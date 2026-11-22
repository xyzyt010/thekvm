//! TheKVM Android controller: Slint UI + the real TheKVM QUIC stack.
//!
//! Android is controller-only: it drives Windows/Linux desktops and can
//! never capture or control another Android device. Pairing is purely
//! Allow/Deny on the desktop (no typed code). Several desktops can stay
//! connected at once; the active one receives all input until switched.

slint::include_modules!();

use slint::android::android_activity;
use android_activity::input::{InputEvent as AndroidInput, MotionAction};
use android_activity::{AndroidApp, InputStatus, MainEvent, PollEvent};
use anyhow::{anyhow, bail, Context, Result};
use kvm_core::{ClientKind, InputEvent, InputPacket, InputState, Mode, MouseButton};
use kvm_protocol::discovery::scan;
use kvm_protocol::pairing::Identity;
use kvm_protocol::transport;
use kvm_protocol::wire::{read_frame, write_frame, Hello, WireMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel, Weak};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Mutex as AsyncMutex;
use std::time::{Duration, Instant};

const NODE_NAME: &str = "Android controller";
const MAX_DEVICES: usize = 10;
const DEFAULT_PORT: u16 = 42110;
/// Long enough for a human to notice the desktop card and click Allow.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone, Serialize, Deserialize)]
struct KnownDevice {
    name: String,
    address: String,
    fingerprint: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    devices: Vec<KnownDevice>,
    paste_mode: bool,
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
    _connection: quinn::Connection,
    send: Arc<AsyncMutex<quinn::SendStream>>,
    sequence: AtomicU64,
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
}

struct Controller {
    runtime: tokio::runtime::Runtime,
    data_dir: std::path::PathBuf,
    sessions: Mutex<HashMap<String, ConnectedDevice>>,
    active: Mutex<Option<String>>,
    touch: Mutex<TouchState>,
    events: tokio::sync::mpsc::UnboundedSender<InputEvent>,
    paste_mode: Mutex<bool>,
    ui: OnceLock<Weak<App>>,
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
        let value = SharedString::from(phase);
        self.notify_ui(move |ui| ui.set_phase(value));
    }

    fn set_status(&self, status: String) {
        let value = SharedString::from(status);
        self.notify_ui(move |ui| ui.set_status(value));
    }

    fn set_connected_name(&self, name: String) {
        let value = SharedString::from(name);
        self.notify_ui(move |ui| ui.set_connected_name(value));
    }

    fn store(&self) -> Store {
        Store::load(&self.data_dir)
    }

    fn active_session(&self) -> Option<Arc<Session>> {
        let fingerprint = self.active.lock().unwrap().clone()?;
        self.sessions
            .lock()
            .unwrap()
            .get(&fingerprint)
            .map(|device| device.session.clone())
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
        self.set_connected_name(format!("{} · {}", name, short_fp(fingerprint)));
        self.set_phase("control");
        self.set_status(format!("Controlling {} · {} connected", name, self.connected_count()));
    }

    /// Android touch -> trackpad input for the ACTIVE desktop only. Touches
    /// inside the status bar / typing bars are ignored so typing never moves
    /// the remote cursor. The reserved heights follow the UI's scale rule.
    fn on_touch(&self, motion: &android_activity::input::MotionEvent<'_>) {
        if self.active_session().is_none() {
            return;
        }
        let (width, height) = APP
            .get()
            .map(|app| app.content_rect())
            .map(|rect| {
                (
                    (rect.right - rect.left) as f32,
                    (rect.bottom - rect.top) as f32,
                )
            })
            .unwrap_or((400.0, 800.0));
        let scale = (width / 400.0).clamp(0.8, 1.7);
        let top_reserve = 62.0 * scale;
        // 5-line typing bar + button row + a little slack.
        let bottom_reserve = (5.0 * 24.0 + 14.0 + 44.0 + 14.0) * scale;

        let mut touch = self.touch.lock().unwrap();
        match motion.action() {
            MotionAction::Down | MotionAction::PointerDown => {
                if motion.action() == MotionAction::Down {
                    touch.points.clear();
                    touch.multi = false;
                    touch.down_at = Some(Instant::now());
                    touch.moved = 0.0;
                } else {
                    touch.multi = true;
                }
                let pointer = motion.pointer_at_index(motion.pointer_index());
                touch.points.insert(pointer.pointer_id(), (pointer.x(), pointer.y()));
            }
            MotionAction::Move => {
                for pointer in motion.pointers() {
                    let Some((old_x, old_y)) = touch.points.get(&pointer.pointer_id()).copied() else {
                        continue;
                    };
                    let dx = pointer.x() - old_x;
                    let dy = pointer.y() - old_y;
                    touch.moved += dx.abs() + dy.abs();
                    touch.points.insert(pointer.pointer_id(), (pointer.x(), pointer.y()));
                    if pointer.y() < top_reserve || pointer.y() > height - bottom_reserve {
                        continue;
                    }
                    let event = if touch.points.len() >= 2 {
                        InputEvent::SmoothWheel {
                            x: (-dx * 3.0) as i32,
                            y: (-dy * 3.0) as i32,
                        }
                    } else {
                        InputEvent::MouseMove {
                            dx: (dx * 1.6) as i32,
                            dy: (dy * 1.6) as i32,
                        }
                    };
                    let _ = self.events.send(event);
                }
            }
            MotionAction::Up | MotionAction::PointerUp | MotionAction::Cancel => {
                let tap = touch
                    .down_at
                    .map(|at| at.elapsed() < Duration::from_millis(230) && touch.moved < 18.0)
                    .unwrap_or(false);
                if tap && motion.action() != MotionAction::Cancel {
                    let button = if touch.multi { MouseButton::Right } else { MouseButton::Left };
                    let _ = self.events.send(InputEvent::MouseButton { button, pressed: true });
                    let _ = self.events.send(InputEvent::MouseButton { button, pressed: false });
                }
                touch.down_at = None;
                touch.multi = false;
                touch.points.clear();
            }
            _ => {}
        }
    }

    /// Connect to one desktop. `known = None` means first contact: complete
    /// the desktop's Allow/Deny ceremony before opening the input stream.
    fn connect(&self, address: String, known: Option<KnownDevice>, display_name: String) {
        let fingerprint_hint = known.as_ref().map(|device| device.fingerprint.clone());
        if let Some(hint) = &fingerprint_hint {
            if self.is_connected(hint) {
                self.activate(hint);
                return;
            }
        }
        if self.connected_count() >= MAX_DEVICES {
            self.set_status(format!("Already connected to the maximum of {MAX_DEVICES} computers"));
            return;
        }
        let result: Result<(Session, String, String)> = self.runtime.block_on(async {
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
                self.set_status(format!("Allow access on {peer_name} to continue…"));
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

            let send = Arc::new(AsyncMutex::new(send));
            let ping_send = send.clone();
            tokio::spawn(async move {
                while let Ok(Some(message)) = read_frame(&mut recv).await {
                    if let WireMessage::Ping { nonce } = message {
                        let mut stream = ping_send.lock().await;
                        let _ = write_frame(&mut *stream, &WireMessage::Pong { nonce }).await;
                    }
                }
            });
            Ok((
                Session { _connection: connection, send, sequence: AtomicU64::new(1) },
                fingerprint,
                peer_name,
            ))
        });

        match result {
            Ok((session, fingerprint, peer_name)) => {
                let name = if known.is_some() { display_name } else { peer_name };
                self.sessions.lock().unwrap().insert(
                    fingerprint.clone(),
                    ConnectedDevice {
                        name: name.clone(),
                        address: address.clone(),
                        session: Arc::new(session),
                    },
                );
                *self.active.lock().unwrap() = Some(fingerprint.clone());
                let mut store = self.store();
                store.devices.retain(|d| d.fingerprint != fingerprint);
                store.devices.insert(
                    0,
                    KnownDevice { name: name.clone(), address, fingerprint: fingerprint.clone() },
                );
                store.devices.truncate(MAX_DEVICES);
                store.save(&self.data_dir);
                self.set_connected_name(format!("{} · {}", name, short_fp(&fingerprint)));
                self.set_phase("control");
                self.set_status(format!("Controlling {name} · {} connected", self.connected_count()));
                self.refresh_remembered();
            }
            Err(error) => self.set_status(format!("{error:#}")),
        }
    }

    /// Stop one device (empty fingerprint = the active one) and either fall
    /// back to another live session or return to the Devices page.
    fn stop(&self, fingerprint: String) {
        let fingerprint = if fingerprint.is_empty() {
            self.active.lock().unwrap().clone().unwrap_or_default()
        } else {
            fingerprint
        };
        self.sessions.lock().unwrap().remove(&fingerprint);
        let fallback = {
            let sessions = self.sessions.lock().unwrap();
            sessions.keys().next().cloned()
        };
        let mut active = self.active.lock().unwrap();
        *active = fallback.clone();
        drop(active);
        self.refresh_remembered();
        if let Some(next) = fallback {
            self.activate(&next);
        } else {
            self.set_connected_name(String::new());
            self.set_phase("devices");
            self.set_status("Disconnected".into());
        }
    }

    fn forget(&self, fingerprint: String) {
        let mut store = self.store();
        store.devices.retain(|d| d.fingerprint != fingerprint);
        store.save(&self.data_dir);
        if self.is_connected(&fingerprint) {
            self.stop(fingerprint);
        } else {
            self.refresh_remembered();
        }
    }

    fn send_text(&self, text: String) {
        let paste = *self.paste_mode.lock().unwrap();
        let Some(session) = self.active_session() else { return };
        let send = session.send.clone();
        self.runtime.spawn(async move {
            let mut stream = send.lock().await;
            let _ = write_frame(&mut *stream, &WireMessage::TextInput { text, paste }).await;
        });
    }
}

static APP: OnceLock<AndroidApp> = OnceLock::new();
thread_local! {
    static TOUCH: std::cell::RefCell<Option<Arc<Controller>>> = const { std::cell::RefCell::new(None) };
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
    APP.set(app.clone()).ok();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let (event_tx, mut event_rx) = tokio::sync::mpsc::unbounded_channel::<InputEvent>();
    let store = Store::load(&data_dir);

    let listener_app = app.clone();
    slint::android::init_with_event_listener(app, move |poll| {
        if matches!(poll, PollEvent::Main(MainEvent::InputAvailable)) {
            let Ok(mut events) = listener_app.input_events_iter() else { return };
            while events.next(|event| {
                if let AndroidInput::MotionEvent(motion) = event {
                    TOUCH.with(|slot| {
                        if let Some(controller) = slot.borrow().as_ref() {
                            controller.on_touch(motion);
                        }
                    });
                }
                InputStatus::Unhandled
            }) {}
        }
    })
    .expect("Slint Android backend");

    let ui = App::new().expect("create UI");
    let controller = Arc::new(Controller {
        runtime,
        data_dir: data_dir.clone(),
        sessions: Mutex::new(HashMap::new()),
        active: Mutex::new(None),
        touch: Mutex::new(TouchState::default()),
        events: event_tx,
        paste_mode: Mutex::new(store.paste_mode),
        ui: OnceLock::new(),
    });
    controller.ui.set(ui.as_weak()).ok();
    TOUCH.with(|slot| *slot.borrow_mut() = Some(controller.clone()));

    // Sequence-numbered input frames go to the ACTIVE desktop only.
    let pump = controller.clone();
    controller.runtime.spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let (send, sequence) = {
                let Some(session) = pump.active_session() else { continue };
                (session.send.clone(), session.sequence.fetch_add(1, Ordering::Relaxed))
            };
            tokio::spawn(async move {
                let mut stream = send.lock().await;
                let _ = write_frame(&mut *stream, &WireMessage::Input(InputPacket { sequence, event })).await;
            });
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
            std::thread::spawn(move || controller.connect(address, known, name));
        }
    });
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

    ui.set_paste_mode(store.paste_mode);
    ui.set_phase(SharedString::from("devices"));
    ui.set_status("Scanning for computers…".into());
    controller.refresh_remembered();

    ui.run().expect("run UI");
}

fn discovery_loop(controller: Arc<Controller>) {
    let mut last_auto: HashMap<String, Instant> = HashMap::new();
    let mut discovered: Vec<(String, String, String, bool)> = Vec::new();
    loop {
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
                        std::thread::spawn(move || c.connect(live_address, Some(device), name));
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

        let count = discovered.len();
        let rows: Vec<(String, String, String, bool)> = discovered.clone();
        let connected: Vec<bool> = rows
            .iter()
            .map(|row| controller.is_connected(&row.2))
            .collect();
        let status = if count == 0 {
            "No computers found — make sure TheKVM is running on a Windows or Linux computer".into()
        } else {
            format!(
                "{count} computer(s) found · {} connected · remembered devices connect automatically",
                controller.connected_count()
            )
        };
        controller.set_status(status);
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
