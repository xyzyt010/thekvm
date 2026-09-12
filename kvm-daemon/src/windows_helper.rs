//! Windows interactive-session bridge for the LocalSystem service.
//!
//! A service runs in Session 0 and must not try to inject input directly from
//! there. This module keeps the QUIC receiver in the service, then forwards
//! already-authorized events over an authenticated loopback pipe to SYSTEM
//! helpers created in the active console session. The helpers are placed on
//! the Winlogon and Default desktops so the same receiver can cover the
//! password prompt and the normal logged-in desktop.

use anyhow::{bail, Context, Result};
use kvm_core::InputEvent;
use kvm_platform::capture::CaptureBackend;
use kvm_platform::inject::Injector;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

const MAX_IPC_FRAME: usize = 64 * 1024;
const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize)]
enum HelperMessage {
    Input(InputEvent),
    ReleaseAll,
    WarpCursor { x: u32, y: u32 },
    /// Service-to-helper drive-target announce: the entry warp's screen
    /// dims in px. Arms ballistics-proof absolute motion in the helper
    /// (see Win32Injector): without it every injection rides relative
    /// deltas through pointer acceleration and the tracked cursor
    /// desyncs from the visible one. Unknown to pre-absolute helpers,
    /// which drop the frame and stay relative — mixed-version safe.
    SetTargetSize { width: u32, height: u32 },
    SetExclusive(bool),
    /// Helper-to-service reply for WarpCursor: whether this helper
    /// actually moved the visible cursor. Without it a skipped warp
    /// (idle desktop) reads as success and entries land stale.
    WarpDone { placed: bool, detail: String },
    /// Service-to-helper request at input-session teardown: report what
    /// happened to the Input messages since the last request. The
    /// helper's own logs never reach the service journal (stderr is a
    /// black hole for session-0-spawned children), so without this the
    /// service cannot tell injected-ok from SendInput-failed from
    /// gate-skipped — all three read identically green upstream.
    TakeReceipts,
    /// Helper-to-service reply for TakeReceipts. Counters reset on send,
    /// so each report covers exactly one session.
    InputReceipt {
        ok: u64,
        failed: u64,
        skipped: u64,
        last_error: String,
    },
}

/// Summed injection receipts across the helpers that answered. Helpers
/// that stay silent are pre-receipt builds: tolerated (the session
/// census notes them) so upgrades never hang on a mixed fleet.
#[derive(Debug, Default)]
pub struct InjectionReceipts {
    pub ok: u64,
    pub failed: u64,
    pub skipped: u64,
    pub answered: u64,
    pub last_error: String,
}

/// The service-side fan-out connection to the interactive helpers.
pub struct ServiceInputProxy {
    streams: Vec<TcpStream>,
    /// Desktop name per stream, index-aligned with `streams`: fan-out
    /// drop warnings name the departed helper instead of a bare count.
    desktops: Vec<String>,
    session_id: u32,
}

impl ServiceInputProxy {
    pub fn create(lock_screen_enabled: bool) -> Result<Self> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("bind Windows helper loopback listener")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let token = helper_token()?;
        let executable = std::env::current_exe().context("locate kvm-daemon executable")?;
        let session_id = active_console_session_id()?;
        let desktops: &[&str] = if lock_screen_enabled {
            &["winsta0\\winlogon", "winsta0\\default"]
        } else {
            &["winsta0\\default"]
        };
        for desktop in desktops {
            spawn_helper(&executable, port, &token, desktop, false)
                .with_context(|| format!("launch helper on {desktop}"))?;
        }

        let deadline = std::time::Instant::now() + HELPER_CONNECT_TIMEOUT;
        let mut streams = Vec::with_capacity(desktops.len());
        while streams.len() < desktops.len() {
            match listener.accept() {
                Ok((mut stream, address)) => {
                    stream.set_nonblocking(false)?;
                    stream.set_nodelay(true)?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let received =
                        read_ipc_frame(&mut stream).context("read helper authentication frame")?;
                    if received != token.as_bytes() {
                        bail!("rejected unauthenticated helper connection from {address}");
                    }
                    streams.push(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        bail!("interactive helper processes did not connect within 15 seconds");
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error).context("accept Windows helper connection"),
            }
        }

        tracing::info!(
            helpers = streams.len(),
            session_id,
            "Windows interactive input helpers connected"
        );
        Ok(Self {
            streams,
            desktops: desktops.iter().map(|name| name.to_string()).collect(),
            session_id,
        })
    }

    pub fn send(&mut self, event: InputEvent) -> Result<()> {
        self.ensure_session()?;
        let message = serde_json::to_vec(&HelperMessage::Input(event))?;
        fan_out(&mut self.streams, &mut self.desktops, "send event to Windows helper", &message)
            .map(|_| ())
    }

    pub fn ensure_session(&self) -> Result<()> {
        let current_session = active_console_session_id()?;
        if current_session != self.session_id {
            bail!(
                "active Windows session changed from {} to {}; reconnecting helpers",
                self.session_id,
                current_session
            );
        }
        Ok(())
    }

    pub fn release_all(&mut self) -> Result<()> {
        let message = serde_json::to_vec(&HelperMessage::ReleaseAll)?;
        fan_out(&mut self.streams, &mut self.desktops, "release input in Windows helper", &message)
            .map(|_| ())
    }

    pub fn warp_cursor(&mut self, x: u32, y: u32) -> Result<()> {
        self.ensure_session()?;
        let message = serde_json::to_vec(&HelperMessage::WarpCursor { x, y })?;
        fan_out(&mut self.streams, &mut self.desktops, "warp cursor in Windows helper", &message)?;
        collect_warp_acks(&mut self.streams, x, y)
    }

    /// Announce the drive target's dims so helpers can inject absolute
    /// (ballistics-proof) motion. Fire-and-forget: helpers without the
    /// message stay relative, and dead streams are already gone or going
    /// (the warp acks report them).
    pub fn set_target_size(&mut self, width: u32, height: u32) {
        let Ok(message) = serde_json::to_vec(&HelperMessage::SetTargetSize { width, height })
        else {
            return;
        };
        let _ = fan_out(
            &mut self.streams,
            &mut self.desktops,
            "announce drive target size to Windows helper",
            &message,
        );
    }

    /// Ask every helper what happened to its Input messages since the
    /// last request. Best-effort like everything here: dead streams drop
    /// with a named warning, silent streams count as legacy, and the
    /// summed taxpayer-visible numbers go into the session census.
    pub fn take_receipts(&mut self) -> InjectionReceipts {
        let message = serde_json::to_vec(&HelperMessage::TakeReceipts);
        let Ok(message) = message else {
            return InjectionReceipts::default();
        };
        let _ = fan_out(
            &mut self.streams,
            &mut self.desktops,
            "take input receipts from Windows helper",
            &message,
        );
        collect_receipts(&mut self.streams)
    }
}

/// Request/response over the helper command streams: every current
/// helper answers WarpCursor with WarpDone. Fails only when helpers
/// explicitly report the cursor was NOT placed, so the receiver logs a
/// truthful warning (and drives unplaced) instead of a fake success.
/// Silent streams are legacy pre-ack helpers: tolerated as Ok to stay
/// mixed-version compatible during upgrades. Each stream waits at most
/// 500ms; crossings are human-paced, so the stall is bounded and rare.
fn collect_warp_acks(streams: &mut Vec<TcpStream>, x: u32, y: u32) -> Result<()> {
    const ACK_TIMEOUT: Duration = Duration::from_millis(500);
    const STREAM_TIMEOUT: Duration = Duration::from_secs(5);
    let mut placed = false;
    let mut answered = false;
    let mut details: Vec<String> = Vec::new();
    streams.retain_mut(|stream| {
        let _ = stream.set_read_timeout(Some(ACK_TIMEOUT));
        let reply = read_ipc_frame(stream)
            .ok()
            .and_then(|frame| serde_json::from_slice::<HelperMessage>(&frame).ok());
        let _ = stream.set_read_timeout(Some(STREAM_TIMEOUT));
        match reply {
            Some(HelperMessage::WarpDone { placed: ok, detail }) => {
                answered = true;
                placed |= ok;
                details.push(detail);
                true
            }
            _ => {
                details.push("no acknowledgement (legacy helper?)".to_owned());
                true
            }
        }
    });
    if placed || !answered {
        tracing::info!(x, y, placed, details = ?details, "Windows helper entry warp outcome");
        return Ok(());
    }
    bail!(
        "no Windows helper placed the entry warp at ({x}, {y}): {}",
        details.join("; ")
    );
}

/// Bounded receipt collection mirroring collect_warp_acks: every current
/// helper answers TakeReceipts with InputReceipt. Silent streams are
/// legacy pre-receipt helpers: tolerated, counted by absence (answered
/// < live streams at the call site if it cares).
fn collect_receipts(streams: &mut Vec<TcpStream>) -> InjectionReceipts {
    const RECEIPT_TIMEOUT: Duration = Duration::from_millis(250);
    const STREAM_TIMEOUT: Duration = Duration::from_secs(5);
    let mut receipts = InjectionReceipts::default();
    streams.retain_mut(|stream| {
        let _ = stream.set_read_timeout(Some(RECEIPT_TIMEOUT));
        let reply = read_ipc_frame(stream)
            .ok()
            .and_then(|frame| serde_json::from_slice::<HelperMessage>(&frame).ok());
        let _ = stream.set_read_timeout(Some(STREAM_TIMEOUT));
        match reply {
            Some(HelperMessage::InputReceipt {
                ok,
                failed,
                skipped,
                last_error,
            }) => {
                receipts.answered += 1;
                receipts.ok += ok;
                receipts.failed += failed;
                receipts.skipped += skipped;
                if !last_error.is_empty() {
                    receipts.last_error = last_error;
                }
                true
            }
            _ => true,
        }
    });
    receipts
}
/// dropped, never fatal. The old fail-on-first-dead stream turned one
/// departed helper (e.g. the winlogon helper after a desktop switch)
/// into a dead input session even though the other helper was healthy.
/// Drops warn with the desktop name (streams/desktops stay
/// index-aligned): a helper dying mid-drive used to be invisible, and
/// its motion died with it while every counter upstream stayed green.
/// Returns the live helper count so the sender can name total blindness.
fn fan_out(
    streams: &mut Vec<TcpStream>,
    desktops: &mut Vec<String>,
    context: &str,
    payload: &[u8],
) -> Result<usize> {
    let mut dead = Vec::new();
    for (index, stream) in streams.iter_mut().enumerate() {
        if write_ipc_frame(stream, payload).is_err() {
            dead.push(index);
        }
    }
    for index in dead.iter().rev() {
        let name = desktops.get(*index).map(String::as_str).unwrap_or("?");
        tracing::warn!(desktop = name, context, "Windows helper stream failed; dropping it");
        streams.remove(*index);
        if *index < desktops.len() {
            desktops.remove(*index);
        }
    }
    if streams.is_empty() {
        bail!("{context}: all Windows helpers are gone");
    }
    Ok(streams.len())
}

fn active_console_session_id() -> Result<u32> {
    use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;

    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == u32::MAX {
        bail!("there is no active Windows console session");
    }
    Ok(session_id)
}

impl Drop for ServiceInputProxy {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

/// Capture-side bridge used by the optional Windows service controller path.
/// The service owns the network connection while desktop-bound helpers own
/// the low-level hooks. Capture helpers report events upstream and accept only
/// the exclusive-capture control message; they never receive network input.
pub struct ServiceCaptureProxy {
    receiver: tokio::sync::mpsc::Receiver<ServiceCaptureEvent>,
    command_streams: Vec<TcpStream>,
    session_id: u32,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

pub enum ServiceCaptureEvent {
    Input(InputEvent),
    HelpersClosed,
}

impl ServiceCaptureProxy {
    pub fn create(lock_screen_enabled: bool) -> Result<Self> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("bind Windows capture-helper listener")?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        let token = helper_token()?;
        let executable = std::env::current_exe().context("locate kvm-daemon executable")?;
        let session_id = active_console_session_id()?;
        let desktops: &[&str] = if lock_screen_enabled {
            &["winsta0\\winlogon", "winsta0\\default"]
        } else {
            &["winsta0\\default"]
        };
        for desktop in desktops {
            spawn_helper(&executable, port, &token, desktop, true)
                .with_context(|| format!("launch capture helper on {desktop}"))?;
        }

        let deadline = std::time::Instant::now() + HELPER_CONNECT_TIMEOUT;
        let (event_tx, event_rx) = tokio::sync::mpsc::channel(256);
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut command_streams = Vec::with_capacity(desktops.len());
        let mut readers = Vec::with_capacity(desktops.len());
        while command_streams.len() < desktops.len() {
            match listener.accept() {
                Ok((mut stream, address)) => {
                    stream.set_nodelay(true)?;
                    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                    let received = read_ipc_frame(&mut stream)
                        .context("read capture helper authentication")?;
                    if received != token.as_bytes() {
                        bail!("rejected unauthenticated capture helper from {address}");
                    }
                    let mut reader = stream.try_clone()?;
                    reader.set_read_timeout(Some(Duration::from_millis(500)))?;
                    let reader_stop = stop.clone();
                    let reader_tx = event_tx.clone();
                    readers.push(std::thread::spawn(move || {
                        loop {
                            if reader_stop.load(std::sync::atomic::Ordering::Acquire) {
                                break;
                            }
                            match read_ipc_frame_optional(&mut reader) {
                                Ok(Some(frame)) => {
                                    let Ok(HelperMessage::Input(event)) =
                                        serde_json::from_slice::<HelperMessage>(&frame)
                                    else {
                                        continue;
                                    };
                                    if reader_tx
                                        .blocking_send(ServiceCaptureEvent::Input(event))
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(error)
                                    if matches!(
                                        error.kind(),
                                        std::io::ErrorKind::TimedOut
                                            | std::io::ErrorKind::WouldBlock
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                        let _ = reader_tx.blocking_send(ServiceCaptureEvent::HelpersClosed);
                    }));
                    command_streams.push(stream);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        bail!("Windows capture helper processes did not connect within 15 seconds");
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error).context("accept Windows capture helper"),
            }
        }
        drop(event_tx);
        tracing::info!(
            helpers = command_streams.len(),
            session_id,
            "Windows interactive capture helpers connected"
        );
        Ok(Self {
            receiver: event_rx,
            command_streams,
            session_id,
            stop,
            readers,
        })
    }

    pub async fn recv(&mut self) -> Option<ServiceCaptureEvent> {
        self.receiver.recv().await
    }

    /// The helpers are bound to one interactive session. A console switch,
    /// fast-user switch, or RDP handoff must tear down this bridge so the
    /// outer controller loop can create helpers for the new session.
    pub fn session_changed(&self) -> bool {
        active_console_session_id()
            .map(|session_id| session_id != self.session_id)
            .unwrap_or(true)
    }

    pub fn set_exclusive(&mut self, enabled: bool) -> Result<()> {
        let message = serde_json::to_vec(&HelperMessage::SetExclusive(enabled))?;
        for stream in &mut self.command_streams {
            write_ipc_frame(stream, &message).context("set Windows capture exclusivity")?;
        }
        Ok(())
    }
}

impl Drop for ServiceCaptureProxy {
    fn drop(&mut self) {
        let _ = self.set_exclusive(false);
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        use std::net::Shutdown;
        for stream in &self.command_streams {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

/// Per-helper injection receipts: what happened to Input messages since
/// the last TakeReceipts. Single-threaded use (the helper loop is
/// sequential), but statics must be Sync: plain atomics plus one short
/// mutex for the latest error text (bounded, replaced not appended).
struct HelperReceipts {
    ok: std::sync::atomic::AtomicU64,
    failed: std::sync::atomic::AtomicU64,
    skipped: std::sync::atomic::AtomicU64,
    last_error: std::sync::Mutex<String>,
}

static RECEIPTS: HelperReceipts = HelperReceipts {
    ok: std::sync::atomic::AtomicU64::new(0),
    failed: std::sync::atomic::AtomicU64::new(0),
    skipped: std::sync::atomic::AtomicU64::new(0),
    last_error: std::sync::Mutex::new(String::new()),
};

impl HelperReceipts {
    fn ok(&self) -> u64 {
        self.ok.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn failed(&self) -> u64 {
        self.failed.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn skipped(&self) -> u64 {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn take_last_error(&self) -> String {
        self.last_error
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
    fn reset(&self) {
        self.ok.store(0, std::sync::atomic::Ordering::Relaxed);
        self.failed.store(0, std::sync::atomic::Ordering::Relaxed);
        self.skipped.store(0, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut guard) = self.last_error.lock() {
            guard.clear();
        }
    }
}

fn receipt_ok() {
    RECEIPTS.ok.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn receipt_failed(error: String) {
    RECEIPTS
        .failed
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if let Ok(mut guard) = RECEIPTS.last_error.lock() {
        guard.clear();
        guard.push_str(&error.chars().take(256).collect::<String>());
    }
}

fn receipt_skipped() {
    RECEIPTS
        .skipped
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Entry point used by the same executable when SCM starts an interactive
/// helper. The arguments are private service-to-helper IPC credentials.
pub fn run_helper(port: u16, token: &str, desktop: &str) -> Result<()> {
    if !matches!(desktop, "winsta0\\winlogon" | "winsta0\\default") {
        bail!("unsupported helper desktop");
    }

    attach_to_desktop(desktop).context("attach helper thread to target desktop")?;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .context("connect to Windows service helper bridge")?;
    stream.set_nodelay(true)?;
    write_ipc_frame(&mut stream, token.as_bytes()).context("authenticate helper")?;

    let injector = Injector::create().context("create helper input injector")?;
    tracing::info!(desktop, "Windows interactive helper started");
    loop {
        let frame = match read_ipc_frame_optional(&mut stream) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                injector.release_all()?;
                return Ok(());
            }
            Err(error) => {
                // A transient bridge hiccup must not kill the helper (the
                // old `?` turned one bad read into a dead drive with every
                // upstream counter green). Back off briefly and keep
                // reading; a truly dead bridge ends via EOF above.
                tracing::warn!(%error, "helper bridge read failed; continuing");
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        let message: HelperMessage = match serde_json::from_slice(&frame) {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(%error, bytes = frame.len(), "helper dropping undecodable frame; continuing");
                continue;
            }
        };
        match message {
            HelperMessage::Input(event) => {
                // Both helpers stay alive so a desktop transition does not
                // require tearing down the QUIC session. SendInput is a
                // process-global input path, however, so only the helper
                // whose desktop currently owns input may inject. The other
                // helper releases any state it previously held and waits.
                match current_desktop_is_input() {
                    Ok(true) => {
                        // Never die on one bad injection: a transient
                        // SendInput failure used to exit the whole helper,
                        // and every later motion vanished silently into the
                        // dropped pipe while the session looked alive. The
                        // failure itself now logs with its cause, and every
                        // outcome feeds the receipts the service collects
                        // at session teardown (the only channel whose
                        // contents provably reach the journal).
                        match injector.send(event) {
                            Ok(()) => receipt_ok(),
                            Err(error) => {
                                tracing::warn!(%error, "helper input injection failed; continuing");
                                receipt_failed(error.to_string());
                            }
                        }
                    }
                    Ok(false) => {
                        receipt_skipped();
                        injector.release_all()?;
                    }
                    Err(error) => {
                        // Desktop transitions can briefly make the user
                        // object query unavailable. Keep the helper alive,
                        // but fail safe by releasing anything it believes it
                        // owns instead of injecting into an unknown desktop.
                        tracing::debug!(%error, "cannot identify active Windows input desktop");
                        receipt_skipped();
                        injector.release_all()?;
                    }
                }
            }
            HelperMessage::TakeReceipts => {
                let reply = serde_json::to_vec(&HelperMessage::InputReceipt {
                    ok: RECEIPTS.ok(),
                    failed: RECEIPTS.failed(),
                    skipped: RECEIPTS.skipped(),
                    last_error: RECEIPTS.take_last_error(),
                });
                // Take-then-reset keeps each report to exactly one session.
                // Reset even if the reply itself fails: a stale count in
                // the next session is worse than a lost one.
                RECEIPTS.reset();
                if let Ok(reply) = reply {
                    let _ = write_ipc_frame(&mut stream, &reply);
                }
            }
            HelperMessage::ReleaseAll => injector.release_all()?,
            HelperMessage::SetTargetSize { width, height } => {
                injector.set_absolute_target(width, height);
            }
            HelperMessage::WarpCursor { x, y } => {
                // Only the desktop that currently owns input may move the
                // visible cursor. The idle helper (typically winlogon)
                // must REPORT its skip — a silent success here logs fake
                // placement upstream and entries land stale. A failed
                // SetCursorPos must not kill this helper either: the old
                // `?` ended the whole inbound session over one bad warp.
                // Placement is read back, not assumed: SetCursorPos can
                // report success while the cursor stays put.
                let (placed, detail) = match current_desktop_is_input() {
                    Ok(true) => match warp_cursor(x, y) {
                        Ok(()) => {
                            // Re-anchor the absolute accumulator to the
                            // entry both sides integrate from: without
                            // this the first absolute event jumps from a
                            // stale position.
                            injector.note_warp(x, y);
                            match kvm_platform::capture::current_cursor_position() {
                                Ok(Some((actual_x, actual_y)))
                                    if actual_x == x && actual_y == y =>
                                {
                                    (true, format!("warped on {desktop}"))
                                }
                                Ok(actual) => (
                                    false,
                                    format!(
                                        "warp unverified on {desktop}: cursor at {actual:?}"
                                    ),
                                ),
                                Err(error) => (
                                    false,
                                    format!("warp read-back failed on {desktop}: {error:?}"),
                                ),
                            }
                        }
                        Err(error) => (
                            false,
                            format!("SetCursorPos failed on {desktop}: {error:#}"),
                        ),
                    },
                    Ok(false) => (false, format!("skipped: {desktop} does not own input")),
                    Err(error) => (
                        false,
                        format!("cannot identify active Windows input desktop: {error:#}"),
                    ),
                };
                if let Ok(reply) = serde_json::to_vec(&HelperMessage::WarpDone { placed, detail })
                {
                    // Fire-and-forget: if the service is gone the next
                    // read ends this helper anyway.
                    let _ = write_ipc_frame(&mut stream, &reply);
                }
            }
            // Service-to-helper only in reverse: never arrives here.
            HelperMessage::WarpDone { .. } | HelperMessage::InputReceipt { .. } => {}
            HelperMessage::SetExclusive(_) => {}
        }
    }
}

/// Entry point for a SYSTEM helper that captures the active desktop and sends
/// events to the service. The service can toggle local suppression over the
/// same authenticated loopback connection.
pub fn run_capture_helper(port: u16, token: &str, desktop: &str) -> Result<()> {
    if !matches!(desktop, "winsta0\\winlogon" | "winsta0\\default") {
        bail!("unsupported capture helper desktop");
    }

    attach_to_desktop(desktop).context("attach capture helper to target desktop")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .context("connect to Windows service capture bridge")?;
    stream.set_nodelay(true)?;
    write_ipc_frame(&mut stream, token.as_bytes()).context("authenticate capture helper")?;

    let mut command_stream = stream.try_clone()?;
    command_stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let exclusive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release = std::sync::atomic::AtomicBool::new(false);
    let command_stop = stop.clone();
    let command_exclusive = exclusive.clone();
    let command_reader = std::thread::spawn(move || loop {
        if command_stop.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        match read_ipc_frame_optional(&mut command_stream) {
            Ok(Some(frame)) => {
                if let Ok(HelperMessage::SetExclusive(enabled)) =
                    serde_json::from_slice::<HelperMessage>(&frame)
                {
                    command_exclusive.store(enabled, std::sync::atomic::Ordering::Release);
                    kvm_platform::capture::set_exclusive(enabled);
                }
            }
            Ok(None) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => break,
        }
    });

    let mut capture = kvm_platform::capture::DefaultCapture::create()
        .context("create Windows capture helper hooks")?;
    let result = (|| -> Result<()> {
        while !stop.load(std::sync::atomic::Ordering::Acquire) {
            let event = capture
                .next_event(&stop, &exclusive, &release)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            // The helper's thread is attached to one desktop. Only the
            // desktop currently receiving system input may be forwarded; the
            // other helper remains hot but contributes no duplicate events.
            if !current_desktop_is_input().unwrap_or(false) {
                continue;
            }
            let frame = serde_json::to_vec(&HelperMessage::Input(event))?;
            write_ipc_frame(&mut stream, &frame).context("send captured Windows input")?;
        }
        Ok(())
    })();
    stop.store(true, std::sync::atomic::Ordering::Release);
    kvm_platform::capture::set_exclusive(false);
    let _ = command_reader.join();
    result
}

#[cfg(target_os = "windows")]
fn warp_cursor(x: u32, y: u32) -> Result<()> {
    use windows::Win32::UI::WindowsAndMessaging::SetCursorPos;

    unsafe { SetCursorPos(x.min(i32::MAX as u32) as i32, y.min(i32::MAX as u32) as i32) }
        .context("set cursor position on target Windows desktop")
}

/// Desktop access rights the helpers open. SendInput (the entire
/// injection path: motion, buttons, keys, wheel) requires
/// DESKTOP_JOURNALPLAYBACK on the thread desktop — without it every
/// SendInput fails with ERROR_ACCESS_DENIED (5) while SetCursorPos
/// warps keep working, which reads as "entries land, cursor pinned,
/// clicks dead" with every upstream counter green (live-proven).
/// Extracted (not inline) so the requirement is unit-pinned, not lore.
#[cfg(target_os = "windows")]
fn helper_desktop_access() -> u32 {
    use windows::Win32::System::StationsAndDesktops::{
        DESKTOP_CREATEWINDOW, DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK, DESKTOP_READOBJECTS,
        DESKTOP_WRITEOBJECTS,
    };
    DESKTOP_CREATEWINDOW.0
        | DESKTOP_HOOKCONTROL.0
        | DESKTOP_READOBJECTS.0
        | DESKTOP_WRITEOBJECTS.0
        | DESKTOP_JOURNALPLAYBACK.0
}

#[cfg(target_os = "windows")]
fn current_desktop_is_input() -> Result<bool> {
    use windows::Win32::Foundation::{BOOL, HANDLE};
    use windows::Win32::System::StationsAndDesktops::{
        GetThreadDesktop, GetUserObjectInformationW, UOI_IO, UOI_NAME,
    };
    use windows::Win32::System::Threading::GetCurrentThreadId;

    let desktop =
        unsafe { GetThreadDesktop(GetCurrentThreadId()) }.context("get helper desktop")?;
    let mut receives_input = BOOL::default();
    unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_IO,
            Some((&mut receives_input as *mut BOOL).cast()),
            std::mem::size_of::<BOOL>() as u32,
            None,
        )
    }
    .context("query helper desktop input ownership")?;
    let owns = receives_input.as_bool();
    // Name the desktop on first check and on every ownership change: a
    // helper serving the wrong desktop (or losing input mid-drive)
    // explains motion that vanishes past every upstream counter, and the
    // name tells exactly which desktop each helper is parked on.
    let mut name = vec![0u16; 256];
    let desktop_name = if unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            (name.len() * std::mem::size_of::<u16>()) as u32,
            None,
        )
    }
    .is_ok()
    {
        let len = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
        String::from_utf16_lossy(&name[..len])
    } else {
        "<unnamed>".to_owned()
    };
    static LAST: std::sync::Mutex<Option<(String, bool)>> = std::sync::Mutex::new(None);
    if let Ok(mut guard) = LAST.lock() {
        if guard.as_ref().is_none_or(|last| last.0 != desktop_name || last.1 != owns) {
            tracing::info!(desktop = %desktop_name, owns_input = owns, "Windows helper desktop ownership");
            *guard = Some((desktop_name, owns));
        }
    }
    Ok(owns)
}

#[cfg(target_os = "windows")]
fn attach_to_desktop(desktop: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::StationsAndDesktops::{CloseDesktop, OpenDesktopW, SetThreadDesktop};

    let name = desktop
        .rsplit('\\')
        .next()
        .context("invalid Windows desktop name")?;
    let wide = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        OpenDesktopW(
            PCWSTR(wide.as_ptr()),
            Default::default(),
            false,
            helper_desktop_access(),
        )
    }
        .context("open target Windows desktop")?;
    let result = unsafe { SetThreadDesktop(handle) }.context("set helper thread desktop");
    let _ = unsafe { CloseDesktop(handle) };
    result
}

fn helper_token() -> Result<String> {
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| anyhow::anyhow!("generate random Windows helper token: {error}"))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn write_ipc_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    if payload.len() > MAX_IPC_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "helper IPC frame exceeds limit",
        ));
    }
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_ipc_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_IPC_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper IPC frame exceeds limit",
        ));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn read_ipc_frame_optional(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_IPC_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "helper IPC frame exceeds limit",
        ));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    Ok(Some(payload))
}

fn spawn_helper(
    executable: &Path,
    port: u16,
    token: &str,
    desktop: &str,
    capture: bool,
) -> Result<()> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ADJUST_DEFAULT,
        TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, OpenProcess, OpenProcessToken, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
        STARTUPINFOW, STARTF_USESHOWWINDOW,
    };

    let session_id = active_console_session_id()?;

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .context("enumerate Windows processes")?;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut winlogon_pid = None;
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry).is_ok() };
    while has_entry {
        let name_end = entry
            .szExeFile
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(entry.szExeFile.len());
        if String::from_utf16_lossy(&entry.szExeFile[..name_end])
            .eq_ignore_ascii_case("winlogon.exe")
        {
            let mut process_session = 0;
            if unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut process_session) }.is_ok()
                && process_session == session_id
            {
                winlogon_pid = Some(entry.th32ProcessID);
                break;
            }
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry).is_ok() };
    }
    let _ = unsafe { CloseHandle(snapshot) };
    let winlogon_pid = winlogon_pid.context("find winlogon.exe in active console session")?;

    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, winlogon_pid) }
        .context("open active-session winlogon process")?;
    let mut impersonation_token = HANDLE::default();
    let token_result = unsafe {
        OpenProcessToken(
            process,
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut impersonation_token,
        )
    };
    let _ = unsafe { CloseHandle(process) };
    token_result.context("open winlogon process token")?;

    let mut primary_token = HANDLE::default();
    let duplicate_result = unsafe {
        DuplicateTokenEx(
            impersonation_token,
            TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_DUPLICATE
                | TOKEN_QUERY,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        )
    };
    let _ = unsafe { CloseHandle(impersonation_token) };
    duplicate_result.context("duplicate winlogon token as primary token")?;

    let command_flag = if capture {
        "--capture-helper"
    } else {
        "--helper"
    };
    let command = format!(
        "{} {} {} {} {}",
        quote_windows_arg(executable),
        command_flag,
        port,
        token,
        desktop
    );
    let mut command_line = command
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut desktop_wide = desktop
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
        // The helper is a console-subsystem binary spawned onto the
        // interactive desktop: without an explicit hide it flashes a
        // terminal window on the user's screen every time it (re)spawns —
        // exactly the popup reported on every crossing. Belt and braces:
        // no console at creation AND a hidden show-state if one appears.
        dwFlags: STARTF_USESHOWWINDOW,
        wShowWindow: 0, // SW_HIDE
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    let create_result = unsafe {
        CreateProcessAsUserW(
            primary_token,
            None,
            PWSTR(command_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            None,
            None,
            &startup,
            &mut process_info,
        )
    };
    let _ = unsafe { CloseHandle(primary_token) };
    create_result.context("create interactive SYSTEM helper")?;
    let _ = unsafe { CloseHandle(process_info.hThread) };
    let _ = unsafe { CloseHandle(process_info.hProcess) };
    Ok(())
}

fn quote_windows_arg(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("\"{}\"", value.replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn fan_out_delivers_to_every_live_helper() {
        let (left_tx, mut left_rx) = loopback_pair();
        let (right_tx, mut right_rx) = loopback_pair();
        let mut streams = vec![left_tx, right_tx];
        let mut desktops = vec!["winlogon".to_owned(), "default".to_owned()];
        assert_eq!(fan_out(&mut streams, &mut desktops, "test", b"ping").unwrap(), 2);
        assert_eq!(streams.len(), 2);
        assert_eq!(desktops, vec!["winlogon".to_owned(), "default".to_owned()]);
        assert_eq!(read_ipc_frame(&mut left_rx).unwrap(), b"ping");
        assert_eq!(read_ipc_frame(&mut right_rx).unwrap(), b"ping");
    }

    #[test]
    fn fan_out_drops_a_dead_helper_and_keeps_the_live_one() {
        let (dead_tx, _dead_rx) = loopback_pair();
        // A locally shut-down socket fails writes deterministically.
        dead_tx.shutdown(Shutdown::Both).unwrap();
        let (live_tx, mut live_rx) = loopback_pair();
        let mut streams = vec![dead_tx, live_tx];
        let mut desktops = vec!["winlogon".to_owned(), "default".to_owned()];
        assert_eq!(fan_out(&mut streams, &mut desktops, "test", b"ping").unwrap(), 1);
        assert_eq!(streams.len(), 1);
        // Names stay index-aligned with the surviving streams.
        assert_eq!(desktops, vec!["default".to_owned()]);
        assert_eq!(read_ipc_frame(&mut live_rx).unwrap(), b"ping");
    }

    #[test]
    fn fan_out_fails_only_when_no_helper_remains() {
        let mut streams: Vec<TcpStream> = Vec::new();
        let mut desktops: Vec<String> = Vec::new();
        assert!(fan_out(&mut streams, &mut desktops, "test", b"ping").is_err());
    }

    /// Fake helper answering WarpDone: the proxy round-trip reports Ok.
    fn drive_fake_helper(helper_side: &mut TcpStream, placed: bool) {
        let frame = read_ipc_frame(helper_side).unwrap();
        let message: HelperMessage = serde_json::from_slice(&frame).unwrap();
        assert!(matches!(message, HelperMessage::WarpCursor { .. }));
        let reply = serde_json::to_vec(&HelperMessage::WarpDone {
            placed,
            detail: "test helper".to_owned(),
        })
        .unwrap();
        write_ipc_frame(helper_side, &reply).unwrap();
    }

    #[test]
    fn warp_ack_placed_reports_success() {
        let (proxy_side, mut helper_side) = loopback_pair();
        std::thread::spawn(move || drive_fake_helper(&mut helper_side, true));
        let mut streams = vec![proxy_side];
        let message = serde_json::to_vec(&HelperMessage::WarpCursor { x: 10, y: 20 }).unwrap();
        let mut desktops = vec!["default".to_owned()];
        fan_out(&mut streams, &mut desktops, "test", &message).unwrap();
        collect_warp_acks(&mut streams, 10, 20).unwrap();
    }

    #[test]
    fn warp_ack_all_skipped_is_an_error() {
        let (proxy_side, mut helper_side) = loopback_pair();
        std::thread::spawn(move || drive_fake_helper(&mut helper_side, false));
        let mut streams = vec![proxy_side];
        let message = serde_json::to_vec(&HelperMessage::WarpCursor { x: 10, y: 20 }).unwrap();
        let mut desktops = vec!["default".to_owned()];
        fan_out(&mut streams, &mut desktops, "test", &message).unwrap();
        assert!(collect_warp_acks(&mut streams, 10, 20).is_err());
    }

    #[test]
    fn warp_ack_silent_helper_stays_compatible() {
        // No reply at all (legacy pre-ack helper): still Ok after the
        // bounded ack wait, never a hang.
        let (proxy_side, _silent) = loopback_pair();
        let mut streams = vec![proxy_side];
        collect_warp_acks(&mut streams, 1, 2).unwrap();
    }

    /// Fake helper answering TakeReceipts with fixed counts.
    fn drive_receipt_helper(helper_side: &mut TcpStream, ok: u64, failed: u64, skipped: u64) {
        let frame = read_ipc_frame(helper_side).unwrap();
        let message: HelperMessage = serde_json::from_slice(&frame).unwrap();
        assert!(matches!(message, HelperMessage::TakeReceipts));
        let reply = serde_json::to_vec(&HelperMessage::InputReceipt {
            ok,
            failed,
            skipped,
            last_error: if failed > 0 {
                "test injection failure".to_owned()
            } else {
                String::new()
            },
        })
        .unwrap();
        write_ipc_frame(helper_side, &reply).unwrap();
    }

    #[test]
    fn receipts_sum_across_helpers() {
        let (left_proxy, mut left_helper) = loopback_pair();
        let (right_proxy, mut right_helper) = loopback_pair();
        std::thread::spawn(move || drive_receipt_helper(&mut left_helper, 120, 0, 3));
        std::thread::spawn(move || drive_receipt_helper(&mut right_helper, 0, 2, 40));
        let mut proxy = ServiceInputProxy {
            streams: vec![left_proxy, right_proxy],
            desktops: vec!["default".to_owned(), "winlogon".to_owned()],
            session_id: 1,
        };
        let receipts = proxy.take_receipts();
        assert_eq!(receipts.ok, 120);
        assert_eq!(receipts.failed, 2);
        assert_eq!(receipts.skipped, 43);
        assert_eq!(receipts.answered, 2);
        assert_eq!(receipts.last_error, "test injection failure");
    }

    #[test]
    fn receipts_silent_helper_stays_compatible() {
        // No reply at all (legacy pre-receipt helper): zeros, answered=0,
        // never a hang past the bounded wait.
        let (proxy_side, _silent) = loopback_pair();
        let mut proxy = ServiceInputProxy {
            streams: vec![proxy_side],
            desktops: vec!["default".to_owned()],
            session_id: 1,
        };
        let receipts = proxy.take_receipts();
        assert_eq!(receipts.answered, 0);
        assert_eq!(receipts.ok, 0);
        assert_eq!(receipts.failed, 0);
        assert_eq!(receipts.skipped, 0);
    }

    #[test]
    fn receipt_variants_round_trip() {
        let take = serde_json::to_vec(&HelperMessage::TakeReceipts).unwrap();
        assert!(matches!(
            serde_json::from_slice::<HelperMessage>(&take).unwrap(),
            HelperMessage::TakeReceipts
        ));
        let receipt = serde_json::to_vec(&HelperMessage::InputReceipt {
            ok: 7,
            failed: 1,
            skipped: 2,
            last_error: "e".to_owned(),
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_slice::<HelperMessage>(&receipt).unwrap(),
            HelperMessage::InputReceipt { ok: 7, .. }
        ));
    }

    #[test]
    fn target_size_announce_reaches_helper() {
        // The drive-target dims must survive the bridge intact: a wrong
        // size silently maps absolute motion onto the wrong pixels.
        let (mut proxy_side, mut helper_side) = loopback_pair();
        let message = serde_json::to_vec(&HelperMessage::SetTargetSize {
            width: 1536,
            height: 960,
        })
        .unwrap();
        write_ipc_frame(&mut proxy_side, &message).unwrap();
        let frame = read_ipc_frame(&mut helper_side).unwrap();
        assert!(matches!(
            serde_json::from_slice::<HelperMessage>(&frame).unwrap(),
            HelperMessage::SetTargetSize {
                width: 1536,
                height: 960
            }
        ));
    }

    /// The injection path lives or dies on this mask: SendInput demands
    /// DESKTOP_JOURNALPLAYBACK, and without it every injection fails
    /// with ERROR_ACCESS_DENIED while SetCursorPos warps keep working.
    /// If anyone trims this mask, this test names the regression before
    /// a release does.
    #[cfg(target_os = "windows")]
    #[test]
    fn helper_desktop_access_covers_sendinput() {
        use windows::Win32::System::StationsAndDesktops::{
            DESKTOP_CREATEWINDOW, DESKTOP_HOOKCONTROL, DESKTOP_JOURNALPLAYBACK,
            DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS,
        };
        let access = helper_desktop_access();
        assert_ne!(access & DESKTOP_JOURNALPLAYBACK.0, 0);
        assert_ne!(access & DESKTOP_CREATEWINDOW.0, 0);
        assert_ne!(access & DESKTOP_HOOKCONTROL.0, 0);
        assert_ne!(access & DESKTOP_READOBJECTS.0, 0);
        assert_ne!(access & DESKTOP_WRITEOBJECTS.0, 0);
    }
}
