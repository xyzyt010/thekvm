//! TheKVM Android controller: Slint UI + the real TheKVM QUIC stack.
//!
//! Android is controller-only: it drives Windows/Linux desktops and can
//! never capture or control another Android device. Pairing is purely
//! Allow/Deny on the desktop (no typed code). Several desktops can stay
//! connected at once; the active one receives all input until switched.

slint::include_modules!();

use slint::android::android_activity::AndroidApp;
use anyhow::{anyhow, bail, Context, Result};
use kvm_core::{ClientKind, InputEvent, InputPacket, InputState, Mode, MouseButton};
use kvm_protocol::discovery::scan;
use kvm_protocol::pairing::Identity;
use kvm_protocol::transport;
use kvm_protocol::wire::{read_frame, write_frame, Hello, MeshConfig, MeshScreen, WireMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slint::{ComponentHandle, Global, Model, ModelRc, SharedString, VecModel, Weak};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const NODE_NAME: &str = "Android controller";
const MAX_DEVICES: usize = 15;
const DEFAULT_PORT: u16 = 42110;
/// Long enough for a human to notice the desktop card and click Allow.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Serialize, Deserialize)]
struct KnownDevice {
    name: String,
    address: String,
    fingerprint: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct GridEntry {
    name: String,
    fingerprint: String,
    col: i32,
    row: i32,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    devices: Vec<KnownDevice>,
    paste_mode: bool,
    horizontal_mode: bool,
    /// Fingerprints explicitly deleted by the user. A deleted pairing is
    /// never restored to the auto-connect list, even after a restart.
    #[serde(default)]
    deleted: Vec<String>,
    #[serde(default = "default_true")]
    dark_mode: bool,
    #[serde(default)]
    multi_node: bool,
    #[serde(default = "default_mesh_mode")]
    mesh_mode: String,
    #[serde(default)]
    mesh_grid: Vec<GridEntry>,
}

fn default_true() -> bool {
    true
}

fn default_mesh_mode() -> String {
    "bidirectional".to_owned()
}

impl Store {
    fn load(dir: &std::path::Path) -> Self {
        std::fs::read_to_string(dir.join("android-devices.json"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }
    fn save(&self, dir: &std::path::Path) {
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(dir.join("android-devices.json"), text);
        }
    }
}

struct Session {
    connection: quinn::Connection,
    /// Every frame for this session (input AND Ping replies) goes through
    /// this one channel to the single writer task that owns the stream.
    /// The old design shared an async mutex between the input pump and
    /// the Ping watcher: one stalled Pong write held the lock forever,
    /// the pump's lock wait had no timeout, and touch frames silently
    /// stopped after the first movement.
    frames: tokio::sync::mpsc::UnboundedSender<WireMessage>,
    /// Set false by the writer/reader the moment the session dies, so
    /// senders fail fast instead of queueing into a dead channel.
    alive: AtomicBool,
}

impl Session {
    /// Close the underlying QUIC connection. Dropping our Arc alone leaves
    /// the peer's inbound link alive, which lets it dial back into us after
    /// a manual Disconnect — the one-way "they can enter, we cannot" state.
    fn close(&self) {
        self.alive.store(false, Ordering::Relaxed);
        self.connection
            .close(quinn::VarInt::from_u32(0), b"manual disconnect");
    }

    /// Queue one input frame. False means the session is dead and the
    /// caller should evict + reconnect instead of dropping the event
    /// into a black hole.
    fn queue(&self, message: WireMessage) -> bool {
        self.alive.load(Ordering::Relaxed) && self.frames.send(message).is_ok()
    }

    /// Push the whole multi-node arrangement to this desktop on its own
    /// stream, so it never interleaves with ordered input frames.
    async fn send_mesh(&self, mesh: MeshConfig) -> Result<()> {
        let (mut send, _recv) = self.connection.open_bi().await?;
        write_frame(&mut send, &WireMessage::MeshConfig(mesh)).await?;
        send.finish()?;
        Ok(())
    }
}

struct ConnectedDevice {
    name: String,
    address: String,
    session: Arc<Session>,
}

#[derive(Default)]
struct TouchState {
    points: HashMap<i32, (f32, f32)>,
    down_at: Option<Instant>,
    moved: f32,
    multi: bool,
    /// True once a long press has turned the gesture into a button drag.
    dragging: bool,
}

struct GestureState {
    active: bool,
    last_center: (f32, f32),
    last_scale: f32,
    started_at: Instant,
    moved: f32,
}

impl Default for GestureState {
    fn default() -> Self {
        Self {
            active: false,
            last_center: (0.0, 0.0),
            last_scale: 1.0,
            started_at: Instant::now(),
            moved: 0.0,
        }
    }
}

struct Controller {
    runtime: tokio::runtime::Runtime,
    data_dir: std::path::PathBuf,
    sessions: Mutex<HashMap<String, ConnectedDevice>>,
    active: Mutex<Option<String>>,
    touch: Mutex<TouchState>,
    gesture: Mutex<GestureState>,
    events: tokio::sync::mpsc::UnboundedSender<InputEvent>,
    paste_mode: Mutex<bool>,
    horizontal_mode: Mutex<bool>,
    /// True while a multi-finger gesture is in progress; suppresses the
    /// stray left click Slint synthesizes when a second finger arrives.
    multi_finger: Arc<AtomicBool>,
    /// Fingerprints whose session died and should reconnect on the next poll.
    retry_now: Mutex<Vec<String>>,
    /// Connect attempts currently in flight (fingerprint, or address for
    /// first contact). Without this, auto-connect respawned a second —
    /// then third — attempt while the first was still waiting for the
    /// desktop Allow click; the sessions replaced each other, the
    /// desktop closed the loser, and the UI flipped between the
    /// trackpad and the device list every few seconds.
    connecting: Mutex<std::collections::HashSet<String>>,
    /// One process-wide input sequence. It must never reset when a
    /// session reconnects: the desktop deduplicates by sequence, so a
    /// restarted counter reads as stale/replayed frames and the new
    /// session's touches are dropped until it catches up.
    next_sequence: AtomicU64,
    /// Current UI phase as last set, so background events (a lost
    /// background session, a discovery refresh) never yank the user
    /// out of the trackpad or settings screen they are looking at.
    phase: Mutex<String>,
    /// Latched by any manual Disconnect/Stop. Cleared only by a fresh app
    /// process (or an explicit Connect by the user). While set, NO automatic
    /// reconnect — outgoing or incoming — is attempted.
    auto_disconnected: AtomicBool,
    /// Fingerprint selected in the grid popup for tap-to-place.
    pending_device: Mutex<String>,
    /// Fingerprint currently being dragged in the grid popup.
    dragging: Mutex<String>,
    /// Last discovery snapshot, used to rebuild the grid popup model.
    discovered_rows: Mutex<Vec<(String, String, String, bool)>>,
    ui: OnceLock<Weak<App>>,
    // Live diagnostics: touch events received vs frames actually written.
    touch_count: AtomicU64,
    frame_count: AtomicU64,
    gesture_count: AtomicU64,
    last_delta: Mutex<(i32, i32)>,
}

impl Controller {
    fn notify_ui(&self, apply: impl FnOnce(&App) + Send + 'static) {
        let Some(ui) = self.ui.get() else { return };
        let ui = ui.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui.upgrade() {
                apply(&ui);
            }
        });
    }

    fn set_phase(&self, phase: &str) {
        *self.phase.lock().unwrap() = phase.to_owned();
        let value = SharedString::from(phase);
        self.notify_ui(move |ui| ui.set_phase(value));
    }

    fn current_phase(&self) -> String {
        self.phase.lock().unwrap().clone()
    }

    fn set_status(&self, status: String) {
        let value = SharedString::from(status);
        self.notify_ui(move |ui| ui.set_status(value));
    }

    fn set_connected_name(&self, name: String) {
        let value = SharedString::from(name);
        self.notify_ui(move |ui| ui.set_connected_name(value));
    }

    fn set_reconnecting(&self, reconnecting: bool) {
        self.notify_ui(move |ui| ui.set_reconnecting(reconnecting));
    }

    fn publish_diag(&self) {
        let touch = self.touch_count.load(Ordering::Relaxed);
        let frames = self.frame_count.load(Ordering::Relaxed);
        let (dx, dy) = *self.last_delta.lock().unwrap();
        let gestures = self.gesture_count.load(Ordering::Relaxed);
        let line = format!("touch {touch} · sent {frames} · gest {gestures} · last {dx},{dy}");
        self.notify_ui(move |ui| ui.set_touch_debug(SharedString::from(line)));
    }

    fn store(&self) -> Store {
        Store::load(&self.data_dir)
    }

    fn active_entry(&self) -> Option<(String, Arc<Session>)> {
        let fingerprint = self.active.lock().unwrap().clone()?;
        let session = self
            .sessions
            .lock()
            .unwrap()
            .get(&fingerprint)
            .map(|device| device.session.clone())?;
        Some((fingerprint, session))
    }

    fn active_session(&self) -> Option<Arc<Session>> {
        self.active_entry().map(|(_, session)| session)
    }

    fn is_connected(&self, fingerprint: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(fingerprint)
    }

    fn connected_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Rebuild the remembered list so connection indicators stay current.
    fn refresh_remembered(&self) {
        let sessions = self.sessions.lock().unwrap();
        let rows: Vec<KnownItem> = self
            .store()
            .devices
            .into_iter()
            .map(|device| KnownItem {
                name: SharedString::from(device.name),
                fingerprint: SharedString::from(device.fingerprint.clone()),
                connected: sessions.contains_key(&device.fingerprint),
            })
            .collect();
        self.notify_ui(move |ui| {
            ui.set_remembered(ModelRc::new(VecModel::from(rows)));
        });
    }

    fn activate(&self, fingerprint: &str) {
        let device = {
            let sessions = self.sessions.lock().unwrap();
            sessions.get(fingerprint).map(|device| device.name.clone())
        };
        let Some(name) = device else { return };
        *self.active.lock().unwrap() = Some(fingerprint.to_owned());
        self.set_reconnecting(false);
        self.set_connected_name(format!("{} · {}", name, short_fp(fingerprint)));
        self.set_phase("control");
        self.set_status(format!("Live · Controlling {} · {} connected", name, self.connected_count()));
    }

    /// Slint TouchArea events -> trackpad input for the ACTIVE desktop.
    ///
    /// These come from Slint's own input pipeline, so they always arrive.
    /// (An android-activity event listener never sees motion events: the
    /// backend's `process_event` drains `input_events_iter()` first.)
    /// Coordinates are already local to the trackpad rectangle.
    /// Rotate a delta 90° when the phone is in "side" (landscape) mode.
    fn rotate(&self, dx: f32, dy: f32) -> (f32, f32) {
        if *self.horizontal_mode.lock().unwrap() {
            (dy, -dx)
        } else {
            (dx, dy)
        }
    }

    /// Emit a click unless a second finger arrived in the meantime. Slint
    /// synthesizes a release for the primary finger when finger 2 lands,
    /// so a short delay is the only reliable way to avoid a stray left click.
    fn click_unless_multi(&self, button: MouseButton) {
        let events = self.events.clone();
        let multi = self.multi_finger.clone();
        self.runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            if !multi.load(Ordering::Relaxed) {
                let _ = events.send(InputEvent::MouseButton { button, pressed: true });
                let _ = events.send(InputEvent::MouseButton { button, pressed: false });
            }
        });
    }

    fn on_trackpad(&self, kind: i32, x: f32, y: f32, finger: i32) {
        let count = self.touch_count.fetch_add(1, Ordering::Relaxed) + 1;
        if self.active_session().is_none() {
            return;
        }
        let mut touch = self.touch.lock().unwrap();
        match kind {
            0 => {
                if touch.points.is_empty() {
                    touch.down_at = Some(Instant::now());
                    touch.moved = 0.0;
                    touch.multi = false;
                    touch.dragging = false;
                } else {
                    // Second finger: mark multi so the synthesized release
                    // of finger 1 does not produce a left click.
                    touch.multi = true;
                    self.multi_finger.store(true, Ordering::Relaxed);
                }
                touch.points.insert(finger, (x, y));
            }
            2 => {
                let old = match touch.points.get(&finger).copied() {
                    Some(pos) => pos,
                    None => {
                        touch.down_at.get_or_insert_with(Instant::now);
                        touch.points.insert(finger, (x, y));
                        return;
                    }
                };
                let dx = x - old.0;
                let dy = y - old.1;
                touch.moved += dx.abs() + dy.abs();
                touch.points.insert(finger, (x, y));

                // One finger only: move the pointer, with optional drag.
                if touch.points.len() == 1 && !self.multi_finger.load(Ordering::Relaxed) {
                    let held = touch
                        .down_at
                        .map(|at| at.elapsed() > Duration::from_millis(260))
                        .unwrap_or(false);
                    if held && !touch.dragging {
                        // Long press + move: hold the left button and drag.
                        touch.dragging = true;
                        let _ = self.events.send(InputEvent::MouseButton {
                            button: MouseButton::Left,
                            pressed: true,
                        });
                    }
                    let (rx, ry) = self.rotate(dx, dy);
                    let out_dx = (rx * 2.0) as i32;
                    let out_dy = (ry * 2.0) as i32;
                    *self.last_delta.lock().unwrap() = (out_dx, out_dy);
                    if out_dx != 0 || out_dy != 0 {
                        let _ = self.events.send(InputEvent::MouseMove { dx: out_dx, dy: out_dy });
                    }
                }
            }
            1 => {
                if touch.dragging {
                    let _ = self.events.send(InputEvent::MouseButton {
                        button: MouseButton::Left,
                        pressed: false,
                    });
                    touch.dragging = false;
                } else {
                    let tap = touch
                        .down_at
                        .map(|at| at.elapsed() < Duration::from_millis(300) && touch.moved < 20.0)
                        .unwrap_or(false);
                    // Right-click is produced by the two-finger gesture end;
                    // here we only handle the single-finger click.
                    if tap && !touch.multi {
                        self.click_unless_multi(MouseButton::Left);
                    }
                }
                touch.points.remove(&finger);
                if touch.points.is_empty() {
                    touch.down_at = None;
                    touch.multi = false;
                    // Let the delayed click check run before clearing the flag.
                    let multi = self.multi_finger.clone();
                    self.runtime.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        multi.store(false, Ordering::Relaxed);
                    });
                }
            }
            _ => {
                if touch.dragging {
                    let _ = self.events.send(InputEvent::MouseButton {
                        button: MouseButton::Left,
                        pressed: false,
                    });
                }
                touch.points.clear();
                touch.down_at = None;
                touch.multi = false;
                touch.dragging = false;
                self.multi_finger.store(false, Ordering::Relaxed);
            }
        }
        if count % 8 == 0 {
            self.publish_diag();
        }
    }

    // ---- Two-finger gestures: centre movement scrolls, scale zooms ----
    fn gesture_start(&self, x: f32, y: f32) {
        let mut g = self.gesture.lock().unwrap();
        g.active = true;
        g.last_center = (x, y);
        g.last_scale = 1.0;
        g.started_at = Instant::now();
        g.moved = 0.0;
        self.multi_finger.store(true, Ordering::Relaxed);
    }

    fn gesture_update(&self, x: f32, y: f32, scale: f32) {
        let count = self.gesture_count.fetch_add(1, Ordering::Relaxed) + 1;
        if count % 6 == 0 {
            self.publish_diag();
        }
        let (dx, dy, zoom) = {
            let mut g = self.gesture.lock().unwrap();
            if !g.active {
                return;
            }
            let dx = x - g.last_center.0;
            let dy = y - g.last_center.1;
            g.moved += dx.abs() + dy.abs();
            g.last_center = (x, y);
            // Slint scale is cumulative; convert the change to 120ths.
            let zoom = (scale - g.last_scale) * 240.0;
            g.last_scale = scale;
            (dx, dy, zoom)
        };
        let (rx, ry) = self.rotate(dx, dy);
        let sx = (-rx * 2.0) as i32;
        let sy = (-ry * 2.0) as i32;
        if sx != 0 || sy != 0 {
            let _ = self.events.send(InputEvent::SmoothWheel { x: sx, y: sy });
        }
        if zoom.abs() >= 1.0 {
            let _ = self.events.send(InputEvent::Pinch { delta: zoom as i32 });
        }
    }

    fn gesture_end(&self) {
        let (short, moved) = {
            let mut g = self.gesture.lock().unwrap();
            if !g.active {
                return;
            }
            g.active = false;
            (
                g.started_at.elapsed() < Duration::from_millis(320),
                g.moved < 16.0,
            )
        };
        // A quick two-finger tap is a right click.
        if short && moved {
            let _ = self.events.send(InputEvent::MouseButton {
                button: MouseButton::Right,
                pressed: true,
            });
            let _ = self.events.send(InputEvent::MouseButton {
                button: MouseButton::Right,
                pressed: false,
            });
        }
        // Always release the synthetic Ctrl held by a pinch expansion.
        let _ = self.events.send(InputEvent::PinchEnd);
        let multi = self.multi_finger.clone();
        self.runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            multi.store(false, Ordering::Relaxed);
        });
    }

    /// Connect to one desktop. `known = None` means first contact: complete
    /// the desktop's Allow/Deny ceremony before opening the input stream.
    fn connect(
        self: Arc<Self>,
        address: String,
        known: Option<KnownDevice>,
        display_name: String,
        auto: bool,
    ) {
        let fingerprint_hint = known.as_ref().map(|device| device.fingerprint.clone());
        // A manual Disconnect latches "no automatic reconnect" for this
        // process. Explicit Connect (auto = false) is the only way to re-arm
        // it short of restarting the app.
        if auto && self.auto_disconnected.load(Ordering::Relaxed) {
            return;
        }
        if let Some(hint) = &fingerprint_hint {
            if auto && self.store().deleted.contains(hint) {
                return;
            }
            if self.is_connected(hint) {
                self.activate(hint);
                return;
            }
        }
        if self.connected_count() >= MAX_DEVICES {
            self.set_status(format!("Error · Already connected to the maximum of {MAX_DEVICES} computers"));
            return;
        }
        // One attempt per computer at a time. A pairing wait can last
        // minutes (a human must click Allow); auto-connect must not
        // spawn parallel attempts that replace each other's sessions.
        let connect_key = fingerprint_hint
            .clone()
            .unwrap_or_else(|| address.clone());
        {
            let mut connecting = self.connecting.lock().unwrap();
            if !connecting.insert(connect_key.clone()) {
                return;
            }
        }
        struct ConnectGuard {
            controller: Arc<Controller>,
            key: String,
        }
        impl Drop for ConnectGuard {
            fn drop(&mut self) {
                self.controller
                    .connecting
                    .lock()
                    .unwrap()
                    .remove(&self.key);
            }
        }
        let _connect_guard = ConnectGuard {
            controller: self.clone(),
            key: connect_key,
        };
        let watcher = self.clone();
        let result: Result<(Arc<Session>, String, String)> = self.runtime.block_on(async {
            let identity = Identity::load_or_create(&self.data_dir)?;
            let endpoint = match known.as_ref() {
                Some(device) => transport::make_pinned_client_endpoint(&identity, &device.fingerprint)?,
                None => transport::make_client_endpoint(&identity)?,
            };
            let addr = normalize_addr(&address)?;
            let connection = tokio::time::timeout(Duration::from_secs(8), endpoint.connect(addr, "thekvm")?)
                .await
                .context("connect timed out")??;

            let mut fingerprint = fingerprint_hint.clone().unwrap_or_default();
            let mut peer_name = display_name.clone();

            if known.is_none() {
                // ---- Allow/Deny ceremony (no typed code anywhere) ----
                let (mut pair_send, mut pair_recv) = connection.open_bi().await?;
                write_frame(
                    &mut pair_send,
                    &WireMessage::PairRequest {
                        node_name: NODE_NAME.into(),
                        fingerprint_hex: identity.fingerprint_hex(),
                        client_kind: ClientKind::Android,
                        pairing_code: None,
                    },
                )
                .await?;

                let challenge = match read_frame(&mut pair_recv).await? {
                    Some(WireMessage::PairChallenge {
                        node_name,
                        fingerprint_hex,
                        ..
                    }) => (node_name, fingerprint_hex),
                    Some(WireMessage::Reject { reason }) => bail!("rejected: {reason}"),
                    _ => bail!("unexpected pairing reply"),
                };
                peer_name = challenge.0;
                fingerprint = challenge.1.to_ascii_lowercase();
                // The challenge fingerprint must be the one in the TLS cert.
                let tls_fingerprint = peer_fingerprint(&connection)?;
                if fingerprint != tls_fingerprint {
                    bail!("the computer's identity changed during pairing");
                }

                // Confirm our side, then wait for the human to click Allow
                // on the desktop. The desktop sends Accepted only after that.
                self.set_status(format!("Connecting · Allow access on {peer_name} to continue…"));
                write_frame(
                    &mut pair_send,
                    &WireMessage::PairConfirm {
                        server_fingerprint_hex: fingerprint.clone(),
                    },
                )
                .await?;
                match tokio::time::timeout(APPROVAL_TIMEOUT, read_frame(&mut pair_recv)).await {
                    Ok(Ok(Some(WireMessage::Accepted { .. }))) => {}
                    Ok(Ok(Some(WireMessage::Reject { reason }))) => {
                        bail!("access denied on the computer: {reason}")
                    }
                    Ok(Ok(_)) => bail!("unexpected pairing answer"),
                    Ok(Err(error)) => bail!("pairing stream failed: {error:#}"),
                    Err(_) => bail!("no one approved the request on the computer (timed out)"),
                }
                let _ = pair_send.finish();
            }

            // ---- Input session on a fresh stream of the same connection ----
            let (mut send, mut recv) = connection.open_bi().await?;
            write_frame(
                &mut send,
                &WireMessage::Hello(Hello {
                    node_name: NODE_NAME.into(),
                    mode: Mode::ServerClient,
                    client_kind: ClientKind::Android,
                    lock_screen_requested: false,
                    clipboard_enabled: false,
                    screen_geometry: None,
                    smooth_scroll: true,
                    pinch_zoom: false,
                    motion_lane: false,
                    link_id: None,
                    udp_motion: false,
                }),
            )
            .await?;
            match read_frame(&mut recv).await? {
                Some(WireMessage::Accepted { .. }) => {}
                Some(WireMessage::Reject { reason }) => bail!("session rejected: {reason}"),
                _ => bail!("unexpected session reply"),
            }
            write_frame(&mut send, &WireMessage::StateSync(InputState::default())).await?;

            // One writer task owns the send stream. Input frames, Ping
            // replies and typed text all queue through `frames`, so no
            // lock can ever be held across a stalled network write.
            let (frame_tx, mut frame_rx) =
                tokio::sync::mpsc::unbounded_channel::<WireMessage>();
            let session = Arc::new(Session {
                connection,
                frames: frame_tx,
                alive: AtomicBool::new(true),
            });
            {
                let writer_session = session.clone();
                let writer_controller = watcher.clone();
                let writer_fp = fingerprint.clone();
                let mut send = send;
                tokio::spawn(async move {
                    while let Some(message) = frame_rx.recv().await {
                        let written = tokio::time::timeout(
                            Duration::from_millis(2000),
                            write_frame(&mut send, &message),
                        )
                        .await;
                        match written {
                            Ok(Ok(())) => {
                                writer_controller.frame_count.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => break,
                        }
                    }
                    writer_session.alive.store(false, Ordering::Relaxed);
                    writer_controller.on_session_lost(&writer_fp, &writer_session);
                });
            }
            let watch = session.clone();
            let watch_fp = fingerprint.clone();
            let watch_controller = watcher.clone();
            tokio::spawn(async move {
                while let Ok(Some(message)) = read_frame(&mut recv).await {
                    if let WireMessage::Ping { nonce } = message {
                        // Queue the Pong through the writer; never write
                        // to the stream from here.
                        let _ = watch.queue(WireMessage::Pong { nonce });
                    }
                }
                // Stream closed: the desktop ended the session. Drop the
                // stale entry so discovery reconnects instead of wedging.
                watch.alive.store(false, Ordering::Relaxed);
                watch_controller.on_session_lost(&watch_fp, &watch);
            });
            Ok((session, fingerprint, peer_name))
        });

        match result {
            Ok((session, fingerprint, peer_name)) => {
                let name = if known.is_some() { display_name } else { peer_name };
                // An in-flight auto-connect may finish after a manual Stop.
                // Never resurrect a session or re-arm auto-connect in that
                // case — close it and leave the Disconnect intact.
                if auto && self.auto_disconnected.load(Ordering::Relaxed) {
                    session.close();
                    return;
                }
                if !auto {
                    // An explicit Connect is fresh user intent: auto-connect
                    // is allowed again from here on.
                    self.auto_disconnected.store(false, Ordering::Relaxed);
                }
                // Replacing a live session (should not happen with the
                // in-flight guard, but belt and braces): close the old
                // connection so the desktop never holds two links from
                // this phone and arbitrates between them.
                let replaced = self.sessions.lock().unwrap().insert(
                    fingerprint.clone(),
                    ConnectedDevice {
                        name: name.clone(),
                        address: address.clone(),
                        session,
                    },
                );
                if let Some(old) = replaced {
                    old.session.close();
                }
                *self.active.lock().unwrap() = Some(fingerprint.clone());
                let mut store = self.store();
                // A deleted pairing can be used manually but is NEVER
                // written back to the auto-connect list.
                if !store.deleted.contains(&fingerprint) {
                    store.devices.retain(|d| d.fingerprint != fingerprint);
                    store.devices.insert(
                        0,
                        KnownDevice { name: name.clone(), address, fingerprint: fingerprint.clone() },
                    );
                    store.devices.truncate(MAX_DEVICES);
                    store.save(&self.data_dir);
                }
                self.set_reconnecting(false);
                self.set_connected_name(format!("{} · {}", name, short_fp(&fingerprint)));
                self.set_phase("control");
                self.set_status(format!("Live · Controlling {name} · {} connected", self.connected_count()));
                self.refresh_remembered();
            }
            Err(error) => self.set_status(format!("Error · {error:#}")),
        }
    }

    /// Stop one device (empty fingerprint = the active one) and either fall
    /// back to another live session or return to the Devices page.
    fn stop(&self, fingerprint: String) {
        // A deliberate Disconnect means: stay disconnected until the user
        // reconnects explicitly or restarts the app. Latch it BEFORE closing
        // anything so watcher-driven reconnects see it.
        self.auto_disconnected.store(true, Ordering::Relaxed);
        self.retry_now.lock().unwrap().clear();
        let targets: Vec<String> = {
            let sessions = self.sessions.lock().unwrap();
            if fingerprint.is_empty() {
                sessions.keys().cloned().collect()
            } else {
                vec![fingerprint]
            }
        };
        // Stopping a background computer must not switch the active one
        // or move the user between screens; only an active stop does.
        let stops_active = self
            .active
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|active| targets.contains(active));
        for target in &targets {
            let removed = self.sessions.lock().unwrap().remove(target);
            if let Some(device) = removed {
                // Dropping our Arc is not enough: close the QUIC connection
                // so the peer cannot dial back into a half-dead link.
                device.session.close();
            }
        }
        self.refresh_remembered();
        if !stops_active {
            return;
        }
        let fallback = {
            let sessions = self.sessions.lock().unwrap();
            sessions.keys().next().cloned()
        };
        *self.active.lock().unwrap() = fallback.clone();
        if let Some(next) = fallback {
            self.activate(&next);
        } else {
            self.set_reconnecting(false);
            self.set_connected_name(String::new());
            self.set_phase("devices");
            self.set_status("Idle · auto-connect resumes after restart or Connect".into());
        }
    }

    /// Called when a session's writer or reader dies.
    /// Only removes the entry if it is still the same session object, so a
    /// reconnect that already happened is never torn down by a stale watcher.
    fn on_session_lost(&self, fingerprint: &str, session: &Arc<Session>) {
        session.alive.store(false, Ordering::Relaxed);
        let removed = {
            let mut sessions = self.sessions.lock().unwrap();
            let same = sessions
                .get(fingerprint)
                .map(|device| Arc::ptr_eq(&device.session, session))
                .unwrap_or(false);
            if same {
                sessions.remove(fingerprint);
                true
            } else {
                false
            }
        };
        if !removed {
            return;
        }
        if !self.auto_disconnected.load(Ordering::Relaxed)
            && !self.store().deleted.iter().any(|fp| fp == fingerprint)
        {
            self.retry_now.lock().unwrap().push(fingerprint.to_owned());
        }
        self.refresh_remembered();
        // A background computer dying must never touch what the user is
        // looking at or which computer is active.
        let was_active = self.active.lock().unwrap().as_deref() == Some(fingerprint);
        if !was_active {
            return;
        }
        let fallback = self.sessions.lock().unwrap().keys().next().cloned();
        *self.active.lock().unwrap() = fallback.clone();
        if let Some(next) = fallback {
            self.activate(&next);
        } else {
            // Stay on the trackpad and say what is happening; discovery
            // retries within a poll and the reconnect restores Live.
            // Throwing the user back to Devices on every transient drop
            // was the visible "glitching between sections" bug.
            self.set_reconnecting(true);
            self.set_status("Reconnecting · connection dropped — retrying…".into());
        }
    }

    /// Delete a pairing permanently. The peer is removed from the
    /// auto-connect list and tombstoned so neither an in-flight connect nor
    /// a session-drop retry can restore it, now or after a restart.
    fn forget(&self, fingerprint: String) {
        let mut store = self.store();
        store.devices.retain(|d| d.fingerprint != fingerprint);
        if !store.deleted.contains(&fingerprint) {
            store.deleted.push(fingerprint.clone());
        }
        store.save(&self.data_dir);
        self.retry_now.lock().unwrap().retain(|fp| fp != &fingerprint);
        if self.is_connected(&fingerprint) {
            self.stop(fingerprint.clone());
        } else {
            self.refresh_remembered();
        }
        self.set_status(format!(
            "Idle · pairing deleted · {} will not auto-connect",
            short_fp(&fingerprint)
        ));
    }

    /// Rebuild the grid popup's machine list from discovery + saved cells.
    fn publish_grid(&self, discovered: &[(String, String, String, bool)]) {
        *self.discovered_rows.lock().unwrap() = discovered.to_vec();
        let store = self.store();
        let mut rows: Vec<GridNode> = Vec::new();
        for (name, _, fingerprint, _) in discovered {
            if rows.iter().any(|row| row.fingerprint.as_str() == fingerprint) {
                continue;
            }
            let cell = store.mesh_grid.iter().find(|entry| entry.fingerprint == *fingerprint);
            rows.push(GridNode {
                name: SharedString::from(name.clone()),
                fingerprint: SharedString::from(fingerprint.clone()),
                col: cell.map(|entry| entry.col).unwrap_or(-1),
                row: cell.map(|entry| entry.row).unwrap_or(-1),
            });
        }
        for entry in &store.mesh_grid {
            if !rows.iter().any(|row| row.fingerprint.as_str() == entry.fingerprint) {
                rows.push(GridNode {
                    name: SharedString::from(entry.name.clone()),
                    fingerprint: SharedString::from(entry.fingerprint.clone()),
                    col: entry.col,
                    row: entry.row,
                });
            }
        }
        self.notify_ui(move |ui| ui.set_grid_nodes(ModelRc::new(VecModel::from(rows))));
    }

    fn refresh_grid(&self) {
        let rows = self.discovered_rows.lock().unwrap().clone();
        self.publish_grid(&rows);
    }

    fn toggle_theme(&self) {
        let mut store = self.store();
        store.dark_mode = !store.dark_mode;
        store.save(&self.data_dir);
        let dark = store.dark_mode;
        self.notify_ui(move |ui| {
            Theme::get(ui).set_dark(dark);
            ui.set_dark_mode(dark);
        });
    }

    fn toggle_multi_node(&self) {
        let mut store = self.store();
        store.multi_node = !store.multi_node;
        store.save(&self.data_dir);
        let enabled = store.multi_node;
        self.notify_ui(move |ui| ui.set_multi_node(enabled));
        self.refresh_grid();
    }

    fn set_mesh_mode(&self, mode: String) {
        if !matches!(mode.as_str(), "bidirectional" | "server_client" | "client_only") {
            return;
        }
        let mut store = self.store();
        store.mesh_mode = mode.clone();
        store.save(&self.data_dir);
        self.notify_ui(move |ui| ui.set_mesh_mode(SharedString::from(mode)));
    }

    fn grid_device_tap(&self, fingerprint: String) {
        let mut pending = self.pending_device.lock().unwrap();
        *pending = if *pending == fingerprint { String::new() } else { fingerprint.clone() };
        let value = pending.clone();
        drop(pending);
        self.notify_ui(move |ui| ui.set_pending_device(SharedString::from(value)));
    }

    fn grid_cell_down(&self, col: i32, row: i32) {
        if !(0..5).contains(&col) || !(0..3).contains(&row) {
            return;
        }
        let store = self.store();
        let occupant = store
            .mesh_grid
            .iter()
            .find(|entry| entry.col == col && entry.row == row)
            .map(|entry| entry.fingerprint.clone());
        if let Some(fingerprint) = occupant {
            *self.dragging.lock().unwrap() = fingerprint.clone();
            let fp = SharedString::from(fingerprint);
            self.notify_ui(move |ui| {
                ui.set_drag_fingerprint(fp);
                ui.set_drag_active(true);
            });
        } else {
            let pending = self.pending_device.lock().unwrap().clone();
            if !pending.is_empty() {
                self.place_node(&pending, col, row);
                *self.pending_device.lock().unwrap() = String::new();
                self.notify_ui(|ui| ui.set_pending_device(SharedString::from("")));
            }
        }
        let (c, r) = (col, row);
        self.notify_ui(move |ui| { ui.set_hover_col(c); ui.set_hover_row(r); });
    }

    fn grid_cell_move(&self, col: i32, row: i32) {
        if self.dragging.lock().unwrap().is_empty() {
            return;
        }
        self.notify_ui(move |ui| { ui.set_hover_col(col); ui.set_hover_row(row); });
    }

    fn grid_cell_up(&self, col: i32, row: i32) {
        let fingerprint = std::mem::take(&mut *self.dragging.lock().unwrap());
        self.notify_ui(|ui| ui.set_drag_active(false));
        if fingerprint.is_empty() || !(0..5).contains(&col) || !(0..3).contains(&row) {
            self.refresh_grid();
            return;
        }
        self.place_node(&fingerprint, col, row);
    }

    /// Place one machine in a cell, evicting whatever occupied it so every
    /// cell holds at most one machine.
    fn place_node(&self, fingerprint: &str, col: i32, row: i32) {
        let mut store = self.store();
        let name = store
            .mesh_grid
            .iter()
            .find(|entry| entry.fingerprint == fingerprint)
            .map(|entry| entry.name.clone())
            .or_else(|| {
                self.discovered_rows
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|row| row.2 == fingerprint)
                    .map(|row| row.0.clone())
            })
            .unwrap_or_else(|| short_fp(fingerprint));
        store.mesh_grid.retain(|entry| {
            !(entry.fingerprint == fingerprint) && !(entry.col == col && entry.row == row)
        });
        if store.mesh_grid.len() >= 15 {
            self.set_status("Error · The grid holds at most 15 computers".into());
            return;
        }
        store.mesh_grid.push(GridEntry {
            name,
            fingerprint: fingerprint.to_owned(),
            col,
            row,
        });
        store.save(&self.data_dir);
        self.refresh_grid();
    }

    fn remove_grid_node(&self, fingerprint: String) {
        let mut store = self.store();
        store.mesh_grid.retain(|entry| entry.fingerprint != fingerprint);
        store.save(&self.data_dir);
        *self.dragging.lock().unwrap() = String::new();
        *self.pending_device.lock().unwrap() = String::new();
        self.notify_ui(|ui| {
            ui.set_drag_active(false);
            ui.set_pending_device(SharedString::from(""));
        });
        self.refresh_grid();
    }

    /// Apply the grid to every connected desktop. Each one rebuilds its
    /// layout from the same placements, so adjacent cells cross into each
    /// other and the right edge wraps to the left edge of its row.
    fn apply_mesh(self: Arc<Self>) {
        let store = self.store();
        let screens: Vec<MeshScreen> = store
            .mesh_grid
            .iter()
            .map(|entry| MeshScreen {
                fingerprint_hex: entry.fingerprint.to_ascii_lowercase(),
                node_name: entry.name.clone(),
                col: entry.col,
                row: entry.row,
            })
            .collect();
        let mesh = MeshConfig {
            mode: store.mesh_mode.clone(),
            screens,
        };
        self.notify_ui(|ui| ui.set_mesh_applying(true));
        let controller = self.clone();
        std::thread::spawn(move || {
            let sessions: Vec<Arc<Session>> = controller
                .sessions
                .lock()
                .unwrap()
                .values()
                .map(|device| device.session.clone())
                .collect();
            let mut applied = 0usize;
            let mut failed = 0usize;
            for session in sessions {
                match controller.runtime.block_on(session.send_mesh(mesh.clone())) {
                    Ok(()) => applied += 1,
                    Err(error) => {
                        failed += 1;
                        tracing::warn!(%error, "mesh config push failed");
                    }
                }
            }
            let status = if applied == 0 {
                "Grid saved locally — connect a computer to apply it everywhere".to_owned()
            } else {
                format!("Grid applied to {applied} computer(s){}, right edge wraps around", if failed > 0 { format!(" · {failed} failed") } else { String::new() })
            };
            controller.set_status(status);
            controller.notify_ui(|ui| ui.set_mesh_applying(false));
        });
    }

    fn send_text(&self, text: String) {
        let paste = *self.paste_mode.lock().unwrap();
        let Some(session) = self.active_session() else { return };
        // Through the session's single writer like every other frame:
        // no second lock holder can ever stall typing or touch.
        session.queue(WireMessage::TextInput { text, paste });
    }
}

fn short_fp(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}

fn normalize_addr(address: &str) -> Result<std::net::SocketAddr> {
    let address = address.trim();
    if let Ok(addr) = address.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    Ok(std::net::SocketAddr::new(address.parse()?, DEFAULT_PORT))
}

/// SHA-256 of the peer's leaf certificate — same fingerprint the desktop uses.
fn peer_fingerprint(conn: &quinn::Connection) -> Result<String> {
    let identity = conn.peer_identity().context("no peer certificate")?;
    let certs = identity
        .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    let leaf = certs.first().context("empty certificate chain")?;
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_ref());
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    let data_dir = app
        .internal_data_path()
        .unwrap_or_else(|| std::path::PathBuf::from("/data/local/tmp/thekvm"));
    let _ = std::fs::create_dir_all(&data_dir);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<InputEvent>();
    let store = Store::load(&data_dir);

    // Slint's backend drives input itself; the trackpad TouchArea in the UI
    // delivers every motion event to `on_trackpad` via the Rust callback.
    slint::android::init(app).expect("Slint Android backend");

    let ui = App::new().expect("create UI");
    let controller = Arc::new(Controller {
        runtime,
        data_dir: data_dir.clone(),
        sessions: Mutex::new(HashMap::new()),
        active: Mutex::new(None),
        touch: Mutex::new(TouchState::default()),
        gesture: Mutex::new(GestureState::default()),
        events: event_tx,
        paste_mode: Mutex::new(store.paste_mode),
        horizontal_mode: Mutex::new(store.horizontal_mode),
        multi_finger: Arc::new(AtomicBool::new(false)),
        retry_now: Mutex::new(Vec::new()),
        connecting: Mutex::new(std::collections::HashSet::new()),
        next_sequence: AtomicU64::new(1),
        phase: Mutex::new("devices".to_string()),
        auto_disconnected: AtomicBool::new(false),
        pending_device: Mutex::new(String::new()),
        dragging: Mutex::new(String::new()),
        discovered_rows: Mutex::new(Vec::new()),
        ui: OnceLock::new(),
        touch_count: AtomicU64::new(0),
        frame_count: AtomicU64::new(0),
        gesture_count: AtomicU64::new(0),
        last_delta: Mutex::new((0, 0)),
    });
    controller.ui.set(ui.as_weak()).ok();

    // Input frames go to the ACTIVE desktop only, queued onto that
    // session's single writer task (which owns the stream and counts
    // frames actually written). The pump itself never touches the
    // network, so it can never stall behind a dead connection: a
    // failed queue means the session is dead — evict and reconnect.
    let pump = controller.clone();
    controller.runtime.spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let Some((fingerprint, session)) = pump.active_entry() else {
                continue;
            };
            let sequence = pump.next_sequence.fetch_add(1, Ordering::Relaxed);
            if !session.queue(WireMessage::Input(InputPacket { sequence, event })) {
                pump.on_session_lost(&fingerprint, &session);
            }
        }
    });

    // The receiver expires an input lease after ~45s of no inbound input.
    // A zero-delta motion frame is harmless to inject and keeps the session
    // alive while the phone is idle (reading the screen, typing, switching).
    let keepalive = controller.clone();
    let keepalive_tx = keepalive.events.clone();
    controller.runtime.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(20)).await;
            if keepalive.active_session().is_some() {
                let _ = keepalive_tx.send(InputEvent::MouseMove { dx: 0, dy: 0 });
            }
        }
    });

    let discovery = controller.clone();
    std::thread::spawn(move || discovery_loop(discovery));

    ui.on_connect_selected({
        let controller = controller.clone();
        move || {
            let view = controller.ui.get().unwrap().upgrade().unwrap();
            let index = view.get_selected();
            let devices = view.get_devices();
            if index < 0 || index as usize >= devices.row_count() {
                return;
            }
            let device = devices.row_data(index as usize).unwrap();
            let address = device.address.to_string();
            let fingerprint = device.fingerprint.to_string();
            let name = device.name.to_string();
            let known = controller
                .store()
                .devices
                .into_iter()
                .find(|entry| entry.fingerprint == fingerprint);
            controller.set_status("Connecting…".into());
            let controller = controller.clone();
            std::thread::spawn(move || controller.connect(address, known, name, false));
        }
    });
    ui.on_toggle_theme({ let c = controller.clone(); move || c.toggle_theme() });
    ui.on_toggle_multi_node({ let c = controller.clone(); move || c.toggle_multi_node() });
    ui.on_set_mesh_mode({ let c = controller.clone(); move |mode| c.set_mesh_mode(mode.to_string()) });
    ui.on_open_mesh_grid({
        let c = controller.clone();
        move || { c.refresh_grid(); c.notify_ui(|ui| ui.set_grid_open(true)); }
    });
    ui.on_close_mesh_grid({
        let c = controller.clone();
        move || c.notify_ui(|ui| ui.set_grid_open(false))
    });
    ui.on_grid_device_tap({ let c = controller.clone(); move |fp| c.grid_device_tap(fp.to_string()) });
    ui.on_grid_cell_down({ let c = controller.clone(); move |col, row| c.grid_cell_down(col, row) });
    ui.on_grid_cell_move({ let c = controller.clone(); move |col, row| c.grid_cell_move(col, row) });
    ui.on_grid_cell_up({ let c = controller.clone(); move |col, row| c.grid_cell_up(col, row) });
    ui.on_apply_mesh({
        let c = controller.clone();
        move || { let c = c.clone(); c.apply_mesh(); }
    });
    ui.on_remove_grid_node({ let c = controller.clone(); move |fp| c.remove_grid_node(fp.to_string()) });
    ui.on_disconnect({ let c = controller.clone(); move || c.stop(String::new()) });
    ui.on_stop_device({ let c = controller.clone(); move |fp| c.stop(fp.to_string()) });
    ui.on_switch_device({ let c = controller.clone(); move |fp| c.activate(&fp.to_string()) });
    ui.on_open_devices({
        let c = controller.clone();
        move || {
            c.set_connected_name(
                c.active
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|fp| c.sessions.lock().unwrap().get(fp).map(|d| d.name.clone()))
                    .unwrap_or_default(),
            );
            c.set_phase("devices");
        }
    });
    ui.on_open_settings({ let c = controller.clone(); move || c.set_phase("settings") });
    ui.on_back({
        let c = controller.clone();
        move || {
            let phase = if c.active_session().is_some() { "control" } else { "devices" };
            c.set_phase(phase);
        }
    });
    ui.on_forget({ let c = controller.clone(); move |fp| c.forget(fp.to_string()) });
    ui.on_toggle_paste({
        let c = controller.clone();
        move || {
            let value = {
                let mut paste = c.paste_mode.lock().unwrap();
                *paste = !*paste;
                *paste
            };
            let mut store = c.store();
            store.paste_mode = value;
            store.save(&c.data_dir);
            c.notify_ui(move |ui| ui.set_paste_mode(value));
        }
    });
    ui.on_send_text({ let c = controller.clone(); move |text| c.send_text(text.to_string()) });
    ui.on_trackpad_event({
        let c = controller.clone();
        move |kind, x, y, finger| c.on_trackpad(kind, x, y, finger)
    });
    ui.on_gesture_start({
        let c = controller.clone();
        move |x, y| c.gesture_start(x, y)
    });
    ui.on_gesture_update({
        let c = controller.clone();
        move |x, y, scale| c.gesture_update(x, y, scale)
    });
    ui.on_gesture_end({ let c = controller.clone(); move || c.gesture_end() });
    ui.on_toggle_horizontal({
        let c = controller.clone();
        move || {
            let value = {
                let mut mode = c.horizontal_mode.lock().unwrap();
                *mode = !*mode;
                *mode
            };
            let mut store = c.store();
            store.horizontal_mode = value;
            store.save(&c.data_dir);
            c.notify_ui(move |ui| ui.set_horizontal_mode(value));
        }
    });

    Theme::get(&ui).set_dark(store.dark_mode);
    ui.set_dark_mode(store.dark_mode);
    ui.set_multi_node(store.multi_node);
    ui.set_mesh_mode(SharedString::from(store.mesh_mode.clone()));
    controller.refresh_grid();
    ui.set_paste_mode(store.paste_mode);
    ui.set_horizontal_mode(store.horizontal_mode);
    ui.set_phase(SharedString::from("devices"));
    ui.set_status("Discovered · scanning for computers…".into());
    controller.refresh_remembered();

    ui.run().expect("run UI");
}

fn discovery_loop(controller: Arc<Controller>) {
    let mut last_auto: HashMap<String, Instant> = HashMap::new();
    let mut discovered: Vec<(String, String, String, bool)> = Vec::new();
    loop {
        // A dropped session should retry immediately, not after the 20s backoff.
        for fingerprint in controller.retry_now.lock().unwrap().drain(..) {
            last_auto.remove(&fingerprint);
        }
        let found = controller
            .runtime
            .block_on(scan(Duration::from_millis(900)))
            .unwrap_or_default();
        let store = controller.store();
        let known: HashMap<String, KnownDevice> = store
            .devices
            .iter()
            .map(|device| (device.fingerprint.clone(), device.clone()))
            .collect();
        discovered.clear();
        for (address, ad) in found {
            if ad.kind == ClientKind::Android {
                continue;
            }
            let remembered = known.contains_key(&ad.fingerprint_hex);
            let name = known
                .get(&ad.fingerprint_hex)
                .map(|device| device.name.clone())
                .unwrap_or_else(|| ad.node_name.clone());
            discovered.push((name, address.to_string(), ad.fingerprint_hex.clone(), remembered));

            if remembered && !controller.is_connected(&ad.fingerprint_hex) {
                let due = last_auto
                    .get(&ad.fingerprint_hex)
                    .map(|at| at.elapsed() > Duration::from_secs(20))
                    .unwrap_or(true);
                if due && controller.connected_count() < MAX_DEVICES {
                    last_auto.insert(ad.fingerprint_hex.clone(), Instant::now());
                    if let Some(device) = known.get(&ad.fingerprint_hex) {
                        let c = controller.clone();
                        let device = device.clone();
                        let name = device.name.clone();
                        // Use the address from THIS discovery, not possibly
                        // stale persisted data (DHCP / network changes).
                        let live_address = address.to_string();
                        std::thread::spawn(move || c.connect(live_address, Some(device), name, true));
                    }
                }
            }
        }

        // Include live sessions whose advertisement has not arrived yet.
        {
            let sessions = controller.sessions.lock().unwrap();
            for (fingerprint, device) in sessions.iter() {
                if !discovered.iter().any(|row| &row.2 == fingerprint) {
                    discovered.push((
                        device.name.clone(),
                        device.address.clone(),
                        fingerprint.clone(),
                        true,
                    ));
                }
            }
        }

        controller.publish_grid(&discovered);
        let count = discovered.len();
        let rows: Vec<(String, String, String, bool)> = discovered.clone();
        let connected: Vec<bool> = rows
            .iter()
            .map(|row| controller.is_connected(&row.2))
            .collect();
        // While the user is on the trackpad, the Live/Reconnecting
        // status owns the line; discovery must not repaint it every
        // couple of seconds (the visible status flicker).
        if controller.current_phase() != "control" {
            let status = if count == 0 {
                "No computers found — make sure TheKVM is running on a Windows or Linux computer".into()
            } else {
                format!(
                    "{count} computer(s) found · {} connected · remembered devices connect automatically",
                    controller.connected_count()
                )
            };
            controller.set_status(status);
        }
        controller.notify_ui(move |ui| {
            let items: Vec<DeviceItem> = rows
                .iter()
                .enumerate()
                .map(|(index, (name, address, fingerprint, remembered))| DeviceItem {
                    name: SharedString::from(name.clone()),
                    address: SharedString::from(address.clone()),
                    fingerprint: SharedString::from(fingerprint.clone()),
                    known: *remembered,
                    connected: connected[index],
                })
                .collect();
            ui.set_devices(ModelRc::new(VecModel::from(items)));
        });
        std::thread::sleep(Duration::from_millis(1200));
    }
}
