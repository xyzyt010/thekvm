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
    SetExclusive(bool),
}

/// The service-side fan-out connection to the interactive helpers.
pub struct ServiceInputProxy {
    streams: Vec<TcpStream>,
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
            session_id,
        })
    }

    pub fn send(&mut self, event: InputEvent) -> Result<()> {
        self.ensure_session()?;
        let message = serde_json::to_vec(&HelperMessage::Input(event))?;
        for stream in &mut self.streams {
            write_ipc_frame(stream, &message).context("send event to Windows helper")?;
        }
        Ok(())
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
        for stream in &mut self.streams {
            write_ipc_frame(stream, &message).context("release input in Windows helper")?;
        }
        Ok(())
    }

    pub fn warp_cursor(&mut self, x: u32, y: u32) -> Result<()> {
        let message = serde_json::to_vec(&HelperMessage::WarpCursor { x, y })?;
        for stream in &mut self.streams {
            write_ipc_frame(stream, &message).context("warp cursor in Windows helper")?;
        }
        Ok(())
    }
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
        let Some(frame) = read_ipc_frame_optional(&mut stream)? else {
            injector.release_all()?;
            return Ok(());
        };
        let message: HelperMessage = serde_json::from_slice(&frame).context("decode helper IPC")?;
        match message {
            HelperMessage::Input(event) => {
                // Both helpers stay alive so a desktop transition does not
                // require tearing down the QUIC session. SendInput is a
                // process-global input path, however, so only the helper
                // whose desktop currently owns input may inject. The other
                // helper releases any state it previously held and waits.
                match current_desktop_is_input() {
                    Ok(true) => injector.send(event)?,
                    Ok(false) => injector.release_all()?,
                    Err(error) => {
                        // Desktop transitions can briefly make the user
                        // object query unavailable. Keep the helper alive,
                        // but fail safe by releasing anything it believes it
                        // owns instead of injecting into an unknown desktop.
                        tracing::debug!(%error, "cannot identify active Windows input desktop");
                        injector.release_all()?;
                    }
                }
            }
            HelperMessage::ReleaseAll => injector.release_all()?,
            HelperMessage::WarpCursor { x, y } => warp_cursor(x, y)?,
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

#[cfg(target_os = "windows")]
fn current_desktop_is_input() -> Result<bool> {
    use windows::Win32::Foundation::{BOOL, HANDLE};
    use windows::Win32::System::StationsAndDesktops::{
        GetThreadDesktop, GetUserObjectInformationW, UOI_IO,
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
    Ok(receives_input.as_bool())
}

#[cfg(target_os = "windows")]
fn attach_to_desktop(desktop: &str) -> Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::System::StationsAndDesktops::{
        CloseDesktop, OpenDesktopW, SetThreadDesktop, DESKTOP_CREATEWINDOW, DESKTOP_HOOKCONTROL,
        DESKTOP_READOBJECTS, DESKTOP_WRITEOBJECTS,
    };

    let name = desktop
        .rsplit('\\')
        .next()
        .context("invalid Windows desktop name")?;
    let wide = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let access = DESKTOP_CREATEWINDOW.0
        | DESKTOP_HOOKCONTROL.0
        | DESKTOP_READOBJECTS.0
        | DESKTOP_WRITEOBJECTS.0;
    let handle = unsafe { OpenDesktopW(PCWSTR(wide.as_ptr()), Default::default(), false, access) }
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
