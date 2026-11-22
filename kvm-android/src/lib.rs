//! TheKVM Android controller: Slint UI + the real TheKVM QUIC stack.
//! Android is controller-only: it drives Windows/Linux desktops and can
//! never capture or control another Android device.

slint::include_modules!();

use slint::android::android_activity;
use android_activity::input::{InputEvent as AndroidInput, MotionAction};
use android_activity::{AndroidApp, InputStatus, MainEvent, PollEvent};
use anyhow::{bail, Context, Result};
use kvm_core::{ClientKind, InputEvent, InputPacket, InputState, Mode, MouseButton};
use kvm_protocol::discovery::scan;
use kvm_protocol::pairing::Identity;
use kvm_protocol::transport;
use kvm_protocol::wire::{read_frame, write_frame, Hello, WireMessage};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel, Weak};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::Mutex as AsyncMutex;
use std::time::{Duration, Instant};

const NODE_NAME: &str = "Android controller";
const MAX_DEVICES: usize = 10;

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
    session: Mutex<Option<Session>>,
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

    fn store(&self) -> Store {
        Store::load(&self.data_dir)
    }

    /// Android touch -> trackpad input. Only while driving and only inside
    /// the trackpad area (between the top status bar and the typing bars).
    fn on_touch(&self, motion: &android_activity::input::MotionEvent<'_>) {
        if self.session.lock().unwrap().is_none() {
            return;
        }
        let height = APP
            .get()
            .map(|app| app.content_rect())
            .map(|rect| (rect.bottom - rect.top) as f32)
            .unwrap_or(800.0);
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
                    if pointer.y() < 64.0 || pointer.y() > height - 150.0 {
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
                    let button = if touch.multi {
                        MouseButton::Right
                    } else {
                        MouseButton::Left
                    };
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

    fn connect(&self, address: String, known: Option<KnownDevice>, pairing_code: Option<String>) {
        if self.session.lock().unwrap().is_some() {
            return;
        }
        let result: Result<(Session, String)> = self.runtime.block_on(async {
            let identity = Identity::load_or_create(&self.data_dir)?;
            let endpoint = match known.as_ref() {
                Some(device) => transport::make_pinned_client_endpoint(&identity, &device.fingerprint)?,
                None => transport::make_client_endpoint(&identity)?,
            };
            let addr = normalize_addr(&address)?;
            let connection = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(addr, "thekvm")?)
                .await
                .context("connect timed out")??;
            let (mut send, mut recv) = connection.open_bi().await?;

            let mut fingerprint = known
                .as_ref()
                .map(|device| device.fingerprint.clone())
                .unwrap_or_default();

            if known.is_none() {
                write_frame(
                    &mut send,
                    &WireMessage::PairRequest {
                        node_name: NODE_NAME.into(),
                        fingerprint_hex: identity.fingerprint_hex(),
                        client_kind: ClientKind::Android,
                        pairing_code,
                    },
                )
                .await?;
                match read_frame(&mut recv).await? {
                    Some(WireMessage::PairChallenge {
                        node_name,
                        fingerprint_hex,
                        verification_code,
                        pre_approved,
                    }) => {
                        fingerprint = fingerprint_hex.to_ascii_lowercase();
                        let _ = (node_name, verification_code);
                        if !pre_approved {
                            bail!("the desktop did not approve this pairing");
                        }
                    }
                    Some(WireMessage::Reject { reason }) => bail!("rejected: {reason}"),
                    _ => bail!("unexpected pairing reply"),
                }
            }

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

            // Keep the association alive by answering pings.
            let ping_send = Arc::new(AsyncMutex::new(send));
            let ping_task = ping_send.clone();
            tokio::spawn(async move {
                while let Ok(Some(message)) = read_frame(&mut recv).await {
                    if let WireMessage::Ping { nonce } = message {
                        let mut stream = ping_task.lock().await;
                        let _ = write_frame(&mut *stream, &WireMessage::Pong { nonce }).await;
                    }
                }
            });
            Ok((Session { _connection: connection, send: ping_send, sequence: AtomicU64::new(1) }, fingerprint))
        });

        match result {
            Ok((session, fingerprint)) => {
                let device = known.unwrap_or(KnownDevice {
                    name: NODE_NAME.into(),
                    address: address.clone(),
                    fingerprint: fingerprint.clone(),
                });
                *self.session.lock().unwrap() = Some(session);
                let mut store = self.store();
                store.devices.retain(|d| d.fingerprint != device.fingerprint);
                store.devices.insert(0, device.clone());
                store.devices.truncate(MAX_DEVICES);
                store.save(&self.data_dir);
                let name = SharedString::from(format!(
                    "{} · {}",
                    device.name,
                    &device.fingerprint[..device.fingerprint.len().min(8)]
                ));
                self.notify_ui(move |ui| {
                    ui.set_connected_name(name);
                    ui.set_phase(SharedString::from("control"));
                    ui.set_status("Connected".into());
                });
            }
            Err(error) => self.set_status(format!("{error:#}")),
        }
    }

    fn disconnect(&self) {
        *self.session.lock().unwrap() = None;
        self.set_phase("devices");
        self.set_status("Disconnected".into());
    }

    fn forget(&self, fingerprint: String) {
        let mut store = self.store();
        store.devices.retain(|d| d.fingerprint != fingerprint);
        store.save(&self.data_dir);
    }

    fn send_text(&self, text: String) {
        let paste = *self.paste_mode.lock().unwrap();
        let send = self
            .session
            .lock()
            .unwrap()
            .as_ref()
            .map(|session| session.send.clone());
        let Some(send) = send else { return };
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

fn normalize_addr(address: &str) -> Result<std::net::SocketAddr> {
    let address = address.trim();
    if let Ok(addr) = address.parse::<std::net::SocketAddr>() {
        return Ok(addr);
    }
    Ok(std::net::SocketAddr::new(address.parse()?, 42110))
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
        session: Mutex::new(None),
        touch: Mutex::new(TouchState::default()),
        events: event_tx,
        paste_mode: Mutex::new(store.paste_mode),
        ui: OnceLock::new(),
    });
    controller.ui.set(ui.as_weak()).ok();
    TOUCH.with(|slot| *slot.borrow_mut() = Some(controller.clone()));

    let pump = controller.clone();
    controller.runtime.spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let (send, sequence) = {
                let guard = pump.session.lock().unwrap();
                let Some(session) = guard.as_ref() else { continue };
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
            let known = controller
                .store()
                .devices
                .into_iter()
                .find(|entry| entry.fingerprint == fingerprint);
            let needs_code = !device.known;
            let code = view.get_draft().to_string();
            view.set_draft("".into());
            controller.set_status("Connecting…".into());
            let controller = controller.clone();
            std::thread::spawn(move || {
                if needs_code {
                    if code.trim().is_empty() {
                        controller.set_status("Type the 6-digit code shown on the computer".into());
                        return;
                    }
                    controller.connect(address, None, Some(code));
                } else {
                    controller.connect(address, known, None);
                }
            });
        }
    });
    ui.on_disconnect({ let c = controller.clone(); move || c.disconnect() });
    ui.on_open_settings({ let c = controller.clone(); move || c.set_phase("settings") });
    ui.on_back({
        let c = controller.clone();
        move || {
            let phase = if c.session.lock().unwrap().is_some() { "control" } else { "devices" };
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
    ui.set_remembered(ModelRc::new(VecModel::from(
        store
            .devices
            .iter()
            .map(|device| KnownItem {
                name: SharedString::from(device.name.clone()),
                fingerprint: SharedString::from(device.fingerprint.clone()),
            })
            .collect::<Vec<_>>(),
    )));

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

            if remembered && controller.session.lock().unwrap().is_none() {
                let due = last_auto
                    .get(&ad.fingerprint_hex)
                    .map(|at| at.elapsed() > Duration::from_secs(20))
                    .unwrap_or(true);
                if due {
                    last_auto.insert(ad.fingerprint_hex.clone(), Instant::now());
                    if let Some(device) = known.get(&ad.fingerprint_hex) {
                        let c = controller.clone();
                        let device = device.clone();
                        std::thread::spawn(move || c.connect(device.address.clone(), Some(device), None));
                    }
                }
            }
        }

        let count = discovered.len();
        let rows: Vec<(String, String, String, bool)> = discovered.clone();
        let status = if count == 0 {
            "No computers found — make sure TheKVM is running on a Windows or Linux computer".into()
        } else {
            format!("{count} computer(s) found · remembered devices connect automatically")
        };
        controller.set_status(status);
        controller.notify_ui(move |ui| {
            let items: Vec<DeviceItem> = rows
                .iter()
                .map(|(name, address, fingerprint, remembered)| DeviceItem {
                    name: SharedString::from(name.clone()),
                    address: SharedString::from(address.clone()),
                    fingerprint: SharedString::from(fingerprint.clone()),
                    known: *remembered,
                })
                .collect();
            ui.set_devices(ModelRc::new(VecModel::from(items)));
        });
        std::thread::sleep(Duration::from_millis(1200));
    }
}
