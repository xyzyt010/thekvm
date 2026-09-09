// GUI subsystem on Windows so double-clicking the app never flashes a
// console window; diagnostics go through the status line and logs.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

slint::include_modules!();

use anyhow::{Context, Result};
use kvm_core::Mode;
use kvm_protocol::control::{
    read_response, write_request, ControlRequest, ControlResponse, DaemonStatus, PendingPairing,
};
use kvm_protocol::pairing::Identity;
use kvm_protocol::transport;
use kvm_protocol::wire::{read_frame, write_frame, WireMessage};
use sha2::{Digest, Sha256};
use slint::{ComponentHandle, SharedString};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

struct PendingPair {
    peer_fingerprint: String,
    peer_node_name: String,
    address: String,
    /// Six-digit code derived from the USER identity (the identity the
    /// controller session dials with) and the peer fingerprint, so both
    /// screens show the same digits. verification_code() is order
    /// independent, matching what the receiver displays for the dialing
    /// fingerprint.
    verification_code: String,
    /// The open pairing channel to the peer. It MUST stay alive between the
    /// code screen and the confirm click: the station registers our request
    /// when the challenge goes out and waits for our PairConfirm on this
    /// exact stream. Dropping it here is what used to make the station-side
    /// popup impossible — the request vanished before it could be shown.
    pairing: Option<PairingChannel>,
    /// Distinguishes successive code checks so a late event (e.g. the
    /// station closing yesterday's request) can never clear today's screen.
    generation: u64,
    /// True when the station's challenge says it already approved this exact
    /// request (we typed its rotating pairing code). The UI must then finish
    /// WITHOUT a compare screen: no station click is outstanding.
    station_pre_approved: bool,
    /// True when a typed code went out with the request but the station did
    /// NOT pre-approve (wrong/stale code): the status text must say so
    /// honestly instead of implying the station is showing a popup for us.
    typed_code_sent: bool,
}

/// One initiator-side pairing conversation, kept open across the two user
/// clicks (code compare, then confirm) so the station's approval and our
/// confirmation can arrive in either order.
struct PairingChannel {
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// A controller session supervised by the UI: `kvm-daemon connect` retries
/// internally forever, so the UI only needs to start it, watch it, and kill
/// it on Disconnect. `verified` is set only when the child reports a live,
/// verified session, so the UI can never again claim "Connected" for a
/// process that merely started.
struct Session {
    child: std::process::Child,
    address: String,
    verified: Arc<std::sync::atomic::AtomicBool>,
    /// True for edge-control mode (`connect` with no address: cursor
    /// crossings drive linked screens) as opposed to fixed-peer takeover
    /// (`connect <address>`: the whole local input drives one peer).
    is_edge: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // One UI per machine. A second window splits attention (an approval can
    // sit unseen in the other one) and doubles daemon traffic. A loopback
    // TCP bind is the lock: the OS holds it while we live and releases it
    // on ANY death, so unlike a pidfile it can never go stale. Port 42109
    // is reserved for this lock (42110 sessions, 42111 discovery).
    // Fail-open: on exotic machines without loopback we run unguarded
    // rather than refuse to start.
    let _instance_lock = match std::net::TcpListener::bind("127.0.0.1:42109") {
        Ok(listener) => Some(listener),
        Err(error) => {
            ui_log(&format!(
                "single-instance lock unavailable ({error}); running unguarded"
            ));
            None
        }
    };
    if _instance_lock.is_none() {
        // Distinguish "no loopback" from "already running": a connect probe
        // answers only when a live instance holds the port.
        if std::net::TcpStream::connect("127.0.0.1:42109").is_ok() {
            ui_log("second UI instance exiting; the running one already shows everything");
            return Ok(());
        }
    }

    let ui = AppWindow::new()?;
    let pending_pair = Arc::new(Mutex::new(None::<PendingPair>));
    let startup_dir = data_dir();
    ui.set_app_version(SharedString::from(format!("v{}", env!("CARGO_PKG_VERSION"))));

    // A GUI-subsystem app has no console: without this hook any panicking
    // background thread dies silently and the UI just looks "dead" (this is
    // how permanently unresponsive buttons happened with zero log evidence).
    // Route every panic into ui.log with its location.
    {
        let panic_log_dir = startup_dir.clone();
        std::panic::set_hook(Box::new(move |info| {
            use std::io::Write as _;
            let dir = panic_log_dir.clone();
            let _ = std::fs::create_dir_all(&dir);
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("ui.log"))
            {
                let millis = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let _ = writeln!(file, "{millis}\tUI thread panicked: {info}");
            }
        }));
    }

    if let Ok(config) = kvm_core::Config::load(&startup_dir.join("config.json")) {
        ui.set_lock_screen_control(config.allow_lock_screen_control);
        ui.set_clipboard_enabled(config.clipboard_enabled);
        ui.set_device_name(SharedString::from(config.device_name.clone()));
        ui.set_auto_connect_address(SharedString::from(
            config.auto_connect_address.unwrap_or_default(),
        ));
        ui.set_mode_index(match config.mode {
            kvm_core::Mode::Bidirectional => 0,
            kvm_core::Mode::ServerClient => 1,
            kvm_core::Mode::ClientOnly => 2,
        });
        // Seed the green "Current role" text from the same file: until the
        // first successful poll it is the only source of truth on screen.
        ui.set_role_text(SharedString::from(role_name(config.mode)));
    }

    let weak = ui.as_weak();
    let last_invite = Arc::new(Mutex::new(String::new()));
    let invite_state = last_invite.clone();
    // Controller session supervised by this UI (at most one).
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
    let session_state = session.clone();
    let session_for_poll = session.clone();
    // Throttle for automatic background-daemon starts: at most one attempt
    // per poll window so a broken install cannot fork-bomb the machine.
    let last_autostart = Arc::new(Mutex::new(None::<std::time::Instant>));
    let autostart_state = last_autostart.clone();
    // Local LAN address is shown even while the daemon is unreachable so the
    // Status tab never reads "unknown" for something the UI can compute
    // itself.
    set_local_address_direct(&weak);
    ui_log(&format!(
        "UI started; user state at {}",
        startup_dir.display()
    ));
    // Throttle for automatic edge starts: at most one attempt per window so
    // a child that dies instantly cannot fork-bomb the machine.
    let last_edge_auto = Arc::new(Mutex::new(None::<std::time::Instant>));
    let last_edge_auto_state = last_edge_auto.clone();
    let pending_for_poll = pending_pair.clone();
    let edge_dir = startup_dir.clone();
    let poll_weak = weak.clone();
    std::thread::spawn(move || {
        let weak = poll_weak;
        let mut tick: u64 = 0;
        let mut consecutive_failures: u32 = 0;
        let mut was_failing = false;
        ui_log("poll thread started");
        loop {
        // NOTE: never gate this loop on weak.upgrade(). Slint component
        // handles live on the event-loop thread: upgrading a Weak from any
        // background thread ALWAYS returns None, so such a check exits the
        // poll on its very first iteration — silently killing every
        // poll-driven display (status, station code, invite, peers,
        // incoming approvals, update counter) on all machines while buttons
        // keep working. The per-update closures below upgrade safely
        // because invoke_from_event_loop runs them ON the UI thread. This
        // thread holds no strong handle, so process exit still ends it.
        // One panicking iteration must never kill the whole poll thread:
        // catch it, log it, count it as a failure, keep polling.
        let iteration = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tick += 1;
        set_poll_count(&weak, tick);
        match control_request(ControlRequest::Status) {
            Ok(ControlResponse::Status(status)) => {
                // Make every success transition provable in ui.log: a poll
                // that works but stays silent is indistinguishable from a
                // dead one, and that ambiguity has cost real debugging days.
                let code_state = if status.pairing_code.is_empty() {
                    "station code unset"
                } else {
                    "station code set"
                };
                if was_failing {
                    was_failing = false;
                    ui_log(&format!(
                        "poll: daemon reachable again after failures ({} peers, {code_state})",
                        status.peer_count
                    ));
                }
                if !POLL_FIRST_OK.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    ui_log(&format!(
                        "poll: first status ok ({} peers, {code_state})",
                        status.peer_count
                    ));
                }
                consecutive_failures = 0;
                // Station-side default arrangement (Machine 2 mirrors: the
                // connector goes on the left) and the Devices arrangement
                // display both refresh here, from live daemon state.
                maybe_mirror_station_arrangement(&status);
                let edge_active = session_for_poll
                    .lock()
                    .ok()
                    .is_some_and(|slot| slot.as_ref().is_some_and(|session| session.is_edge));
                refresh_arrangement(&weak, edge_active);
                // Edge control is always on — no button starts it. The
                // moment the daemon is reachable, no session runs, and no
                // pairing ceremony is in flight, the edge child must be
                // running. This one place restores it after Disconnect,
                // role/settings changes, child crashes, and cold starts
                // alike, so the behavior is deterministic: if this computer
                // may drive, edge is on. Period.
                if should_auto_start_edge(
                    status.mode,
                    session_for_poll.lock().ok().is_some_and(|slot| slot.is_some()),
                    pending_for_poll.lock().ok().is_some_and(|slot| slot.is_some()),
                ) {
                    let mut attempt = false;
                    if let Ok(mut slot) = last_edge_auto_state.lock() {
                        let due = slot
                            .map(|last| last.elapsed() >= std::time::Duration::from_secs(15))
                            .unwrap_or(true);
                        if due {
                            *slot = Some(std::time::Instant::now());
                            attempt = true;
                        }
                    }
                    if attempt {
                        ui_log("edge: auto-starting edge control (always-on)");
                        spawn_edge(&weak, &session_for_poll, &pending_for_poll, &edge_dir);
                    }
                }
                let port = status.listen_port;
                let fingerprint = status.fingerprint_hex.clone();
                set_daemon_status(&weak, status);
                refresh_invite(&weak, &invite_state, port, &fingerprint);
                match control_request(ControlRequest::ListPeers) {
                    Ok(ControlResponse::Peers(peers)) => set_peer_list(&weak, peers),
                    Ok(other) => set_status(&weak, format!("Unexpected peer list: {other:?}")),
                    Err(error) => set_status(&weak, format!("Peer list unavailable: {error}")),
                }
                if let Ok(ControlResponse::PendingPairings(pairings)) =
                    control_request(ControlRequest::ListPendingPairings)
                {
                    // Log arrivals and clears: "UI knew but didn't show" vs
                    // "UI never knew" must always be answerable from ui.log.
                    let count = pairings.len();
                    if LAST_INCOMING_COUNT
                        .swap(count, std::sync::atomic::Ordering::Relaxed)
                        != count
                    {
                        ui_log(&format!("poll: {count} incoming pairing(s) listed"));
                    }
                    set_incoming_pairing(&weak, pairings);
                }
            }
            Ok(other) => {
                consecutive_failures += 1;
                was_failing = true;
                ui_log(&format!("poll: unexpected daemon status: {other:?}"));
                set_daemon_offline(&weak, format!("Unexpected daemon status: {other:?}"));
                clear_invite(&weak, &invite_state);
                set_local_address_direct(&weak);
            }
            Err(error) => {
                consecutive_failures += 1;
                was_failing = true;
                let failure = classify_control_error(&error);
                match failure {
                    ControlFailure::Missing => {
                        // No daemon endpoint at all: start a user-session
                        // daemon next to this app so launching TheKVM always
                        // yields a working app, then keep polling until its
                        // control endpoint appears.
                        let mut attempt = false;
                        if let Ok(mut slot) = autostart_state.lock() {
                            let due = slot
                                .map(|last| last.elapsed() >= std::time::Duration::from_secs(15))
                                .unwrap_or(true);
                            if due {
                                *slot = Some(std::time::Instant::now());
                                attempt = true;
                            }
                        }
                        if attempt {
                            match ensure_user_daemon() {
                                Ok(()) => {
                                    ui_log("poll: no daemon endpoint; started user-session daemon");
                                    set_status(
                                        &weak,
                                        "Background service was not running; started it, connecting…"
                                            .into(),
                                    )
                                }
                                Err(start_error) => {
                                    ui_log(&format!("poll: daemon autostart failed: {start_error}"));
                                    set_daemon_offline(
                                        &weak,
                                        format!("Daemon not started: {start_error}"),
                                    )
                                }
                            }
                        }
                    }
                    ControlFailure::AccessDenied => {
                        // A daemon owns this machine but this session may not
                        // reach it (Linux: desktop session predates the
                        // `thekvm` group). Never spawn a second daemon here:
                        // it would steal port 42110 from the real service.
                        ui_log("poll: access denied to daemon control endpoint");
                        set_daemon_offline(
                            &weak,
                            control_denied_status(&error, "Access denied to the background service"),
                        );
                    }
                    ControlFailure::Other(message) => {
                        ui_log(&format!("poll: daemon control failed: {message}"));
                        set_daemon_offline(&weak, format!("Daemon not started: {message}"));
                    }
                }
                clear_invite(&weak, &invite_state);
                set_local_address_direct(&weak);
            }
        }
        // The supervised `connect` process retries internally, so an exit
        // always means the session ended abnormally (or was disconnected,
        // which clears the slot first). Surface it instead of silently
        // showing a stale "connected" state. The verified flag keeps the
        // message honest: a child that never reported `established` never
        // connected, so say so instead of implying a live session dropped.
        if let Ok(mut slot) = session_for_poll.lock() {
            if let Some(session) = slot.as_mut() {
                match session.child.try_wait() {
                    Ok(Some(status)) => {
                        let address = session.address.clone();
                        let verified =
                            session.verified.load(std::sync::atomic::Ordering::Relaxed);
                        *slot = None;
                        set_session(&weak, None);
                        set_status(
                            &weak,
                            if verified {
                                format!("Connection to {address} ended ({status})")
                            } else {
                                format!(
                                    "Could not establish a connection to {address} ({status}). Check the address and that the other side is waiting, then Connect again."
                                )
                            },
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let address = session.address.clone();
                        *slot = None;
                        set_session(&weak, None);
                        set_status(
                            &weak,
                            format!("Connection to {address} lost: {error}"),
                        );
                    }
                }
            }
        }
        })); // end catch_unwind for one poll iteration
        if iteration.is_err() {
            consecutive_failures += 1;
            was_failing = true;
            ui_log("poll: iteration panicked and was caught; continuing");
        }
        // Status is intentionally polled instead of pushed over the local
        // endpoint so the UI also recovers cleanly when the privileged daemon
        // restarts, upgrades, or changes active sessions. After sustained
        // failure, back off so a dead endpoint cannot churn threads: the
        // Start button and any later poll still retry.
        if consecutive_failures == 10 {
            ui_log("poll: 10 consecutive failures; backing off to 15s intervals");
        }
        std::thread::sleep(std::time::Duration::from_secs(if consecutive_failures >= 10 {
            15
        } else {
            3
        }));
        }
    });

    let weak = ui.as_weak();
    let pending_for_connect = pending_pair.clone();
    let connect_data_dir = startup_dir.clone();
    let connect_session = session_state.clone();
    ui.on_connect_to(move |address, code| {
        let code = code.trim().to_owned();
        start_session_flow(
            &weak,
            &pending_for_connect,
            &connect_data_dir,
            &connect_session,
            address.to_string(),
            (!code.is_empty()).then_some(code),
        );
    });

    let weak = ui.as_weak();
    let role_session = session_state.clone();
    ui.on_set_role(move |role| {
        let weak = weak.clone();
        let role_session = role_session.clone();
        ui_log(&format!("role button pressed: {role}"));
        // Instant local feedback: the press always lands, even if the daemon
        // turns out to be unreachable. The result overwrites this below.
        set_status(&weak, "Applying role…".into());
        std::thread::spawn(move || {
            let requested = match role {
                1 => Mode::ServerClient,
                2 => Mode::ClientOnly,
                _ => Mode::Bidirectional,
            };
            // Read-modify-write against the live daemon config so pressing a
            // role button only ever changes the role, never anything else.
            // Every outcome is logged: a silent press must be impossible.
            let current = match control_request(ControlRequest::GetConfig) {
                Ok(ControlResponse::Config(config)) => config,
                Ok(other) => {
                    ui_log(&format!("role change: cannot read settings: {other:?}"));
                    set_status(&weak, format!("Cannot read settings: {other:?}"));
                    return;
                }
                Err(error) => {
                    ui_log(&format!("role change: settings unreadable: {error:#}"));
                    set_status(&weak, control_denied_status(&error, "Background service unreachable"));
                    return;
                }
            };
            match control_request(ControlRequest::SetConfig {
                device_name: Some(current.device_name.clone()),
                mode: Some(requested),
                allow_lock_screen_control: Some(current.allow_lock_screen_control),
                listen_port: None,
                layout: None,
                auto_connect_address: current.auto_connect_address.clone(),
                clear_auto_connect: current.auto_connect_address.is_none(),
                clipboard_enabled: Some(current.clipboard_enabled),
            }) {
                Ok(ControlResponse::Applied { .. }) => {
                    mirror_user_config(
                        &current.device_name,
                        requested,
                        current.allow_lock_screen_control,
                        current.clipboard_enabled,
                        None,
                    );
                    ui_log(&format!("role applied: {}", role_name(requested)));
                    // Update the green role text from the authoritative
                    // Applied result now; the poll refreshes it again when
                    // healthy.
                    set_role_display(&weak, requested);
                    // Edge control drives under a role contract: a role
                    // change stops it rather than letting it drive under a
                    // stale one (e.g. receiver-only still crossing).
                    if role_session
                        .lock()
                        .ok()
                        .is_some_and(|slot| slot.as_ref().is_some_and(|session| session.is_edge))
                    {
                        ui_log("role changed: stopping edge control; it restarts by itself for the new role");
                        stop_session(&weak, &role_session, "Edge control stopped");
                        set_status(
                            &weak,
                            format!(
                                "Role set: {}. Edge control restarting automatically.",
                                role_name(requested)
                            ),
                        );
                    } else {
                        set_status(
                            &weak,
                            format!("Role set: {}.", role_name(requested)),
                        );
                    }
                }
                Ok(ControlResponse::Error { message }) => {
                    ui_log(&format!("role change refused: {message}"));
                    set_status(&weak, message)
                }
                Ok(other) => {
                    ui_log(&format!("role change unexpected: {other:?}"));
                    set_status(&weak, format!("Unexpected daemon response: {other:?}"))
                }
                Err(error) => {
                    ui_log(&format!("role change failed: {error}"));
                    set_status(&weak, format!("Cannot set role: {error}"))
                }
            }
        });
    });

    let _weak = ui.as_weak();
    ui.on_open_log_folder(move || {
        let dir = data_dir();
        ui_log("log folder opened from Settings");
        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("explorer.exe")
                .arg(dir)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("xdg-open")
                .arg(dir)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    });

    let weak = ui.as_weak();
    let disconnect_session = session_state.clone();
    ui.on_disconnect(move || {
        stop_session(&weak, &disconnect_session, "Disconnected");
    });

    let weak = ui.as_weak();
    ui.on_swap_sides(move || {
        let weak = weak.clone();
        std::thread::spawn(move || {
            arrange_swap(&weak);
        });
    });

    let weak = ui.as_weak();
    let pending_for_invite = pending_pair.clone();
    let invite_data_dir = startup_dir.clone();
    let invite_session = session_state.clone();
    ui.on_pair_from_invite(move |invite| {
        let weak = weak.clone();
        match kvm_protocol::invite::parse(&invite) {
            // An invite is just a trusted address: fill the field and run
            // the same connect flow as a typed IP.
            Ok((target, _)) if !target.trim().is_empty() => {
                set_peer_address_field(&weak, &target);
                start_session_flow(
                    &weak,
                    &pending_for_invite,
                    &invite_data_dir,
                    &invite_session,
                    target,
                    None,
                );
            }
            Ok(_) => set_status(
                &weak,
                "Invite has no address; enter the peer's LAN IP manually".into(),
            ),
            Err(error) => set_status(&weak, format!("Invalid invite: {error}")),
        }
    });

    let weak = ui.as_weak();
    ui.on_discover_lan(move || {
        let weak = weak.clone();
        std::thread::spawn(move || {
            let result = (|| -> Result<(String, Option<String>)> {
                let runtime = runtime();
                let peers = runtime.block_on(kvm_protocol::discovery::scan(
                    std::time::Duration::from_secs(1),
                ))?;
                if peers.is_empty() {
                    return Ok(("No TheKVM receivers found".into(), None));
                }
                let text = peers
                    .iter()
                    .map(|(address, peer)| {
                        format!(
                            "{} · {} · {}",
                            peer.node_name, address, peer.fingerprint_hex
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                let address = (peers.len() == 1).then(|| peers[0].0.to_string());
                Ok((text, address))
            })();
            match result {
                Ok((text, address)) => set_discovery(&weak, text, address),
                Err(error) => set_discovery(&weak, format!("Discovery failed: {error}"), None),
            }
        });
    });

    let weak = ui.as_weak();
    ui.on_start_daemon(move || {
        let weak = weak.clone();
        std::thread::spawn(move || {
            // Explicit button press, so an admin prompt is appropriate:
            // when the packaged system service exists but is stopped,
            // start (and enable) it with one approval instead of making
            // the user open a terminal. The unit check runs first so a
            // machine without the package never sees a password prompt.
            #[cfg(target_os = "linux")]
            if !systemctl_ok("is-active", "thekvmd") && systemctl_unit_present("thekvmd") {
                let elevated = std::process::Command::new("pkexec")
                    .args(["systemctl", "enable", "--now", "thekvmd"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false);
                if elevated {
                    ui_log("background service started from the Start button");
                    set_status(&weak, "Background service started.".into());
                    return;
                }
            }
            match ensure_user_daemon() {
                Ok(()) => set_status(
                    &weak,
                    "Background service started, connecting…".into(),
                ),
                Err(error) => set_status(&weak, format!("Could not start background service: {error}")),
            }
        });
    });

    let weak = ui.as_weak();
    let pending_for_confirm = pending_pair.clone();
    let confirm_data_dir = startup_dir.clone();
    let confirm_session = session_state.clone();
    ui.on_confirm_pairing(move || {
        let pending = pending_for_confirm
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        let Some(pending) = pending else {
            set_status(&weak, "No pending pairing".into());
            return;
        };
        run_pair_confirm(
            &weak,
            confirm_data_dir.clone(),
            &confirm_session,
            &pending_for_confirm,
            pending,
        );
    });

    let weak = ui.as_weak();
    let pending_for_cancel = pending_pair.clone();
    ui.on_cancel_pairing(move || {
        if let Ok(mut slot) = pending_for_cancel.lock() {
            // Dropping the open channel tells the station to withdraw the
            // approval request it is showing.
            *slot = None;
        }
        ui_log("pairing: cancelled by user");
        set_pending(&weak, String::new(), String::new(), String::new());
        set_status(&weak, "Pairing cancelled".into());
    });

    let weak = ui.as_weak();
    ui.on_approve_incoming_pairing(move |fingerprint| {
        decide_incoming_pairing(&weak, fingerprint.to_string(), true);
    });

    let weak = ui.as_weak();
    ui.on_reject_incoming_pairing(move |fingerprint| {
        decide_incoming_pairing(&weak, fingerprint.to_string(), false);
    });

    let weak = ui.as_weak();
    ui.on_revoke_peer(move |fingerprint| {
        let weak = weak.clone();
        let fingerprint = fingerprint.to_string();
        std::thread::spawn(move || {
            match control_request(ControlRequest::Unpair {
                fingerprint_hex: fingerprint.clone(),
            }) {
                Ok(ControlResponse::Unpaired { .. }) => {
                    // Revocation must clear BOTH books: the user book would
                    // otherwise resurrect the trust at the next automatic
                    // setup pass (which mirrors user pins into the daemon).
                    if let Ok(mut book) =
                        kvm_protocol::pairing::PeerBook::load_or_create(&data_dir())
                    {
                        match book.unpin(&fingerprint) {
                            Ok(true) => ui_log("revoke: removed peer from user book too"),
                            Ok(false) => {}
                            Err(error) => {
                                ui_log(&format!("revoke: user book removal failed: {error:#}"))
                            }
                        }
                    }
                    set_status(&weak, format!("Revoked peer {fingerprint}"));
                    if let Ok(ControlResponse::Peers(peers)) =
                        control_request(ControlRequest::ListPeers)
                    {
                        set_peer_list(&weak, peers);
                    }
                }
                Ok(ControlResponse::Error { message }) => set_status(&weak, message),
                Ok(other) => set_status(&weak, format!("Unexpected revoke response: {other:?}")),
                Err(error) => set_status(&weak, format!("Peer revocation failed: {error}")),
            }
        });
    });

    let weak = ui.as_weak();
    ui.on_apply_config(
        move |allow_lock_screen, mode_index, device_name, auto_address, clipboard_enabled| {
            let weak = weak.clone();
            let device_name = device_name.to_string();
            let auto_address = auto_address.to_string();
            let config_session = session_state.clone();
            std::thread::spawn(move || {
                let requested_mode = match mode_index {
                    1 => Mode::ServerClient,
                    2 => Mode::ClientOnly,
                    _ => Mode::Bidirectional,
                };
                // The supervised controller session reads the USER config, so
                // mirror the same choices there (without any boot peer, which
                // the user config must never carry).
                mirror_user_config(
                    &device_name,
                    requested_mode,
                    allow_lock_screen,
                    clipboard_enabled,
                    None,
                );
                let mode = match mode_index {
                    1 => "server-client",
                    2 => "receiver-only",
                    _ => "bidirectional",
                };
                let daemon =
                    std::env::var("THEKVM_DAEMON_PATH").unwrap_or_else(|_| "kvm-daemon".into());
                let mut command = std::process::Command::new(daemon);
                command.args(["configure", "--mode", mode]);
                command.arg("--device-name").arg(&device_name);
                if allow_lock_screen {
                    command.arg("--allow-lock-screen-control");
                } else {
                    command.arg("--disable-lock-screen-control");
                }
                if !auto_address.trim().is_empty() {
                    command.arg("--auto-connect").arg(&auto_address);
                } else {
                    command.arg("--clear-auto-connect");
                }
                if clipboard_enabled {
                    command.arg("--enable-clipboard");
                } else {
                    command.arg("--disable-clipboard");
                }
                match control_request(ControlRequest::SetConfig {
                    device_name: Some(device_name.clone()),
                    mode: Some(requested_mode),
                    allow_lock_screen_control: Some(allow_lock_screen),
                    listen_port: None,
                    layout: None,
                    auto_connect_address: (!auto_address.trim().is_empty())
                        .then_some(auto_address.clone()),
                    clear_auto_connect: auto_address.trim().is_empty(),
                    clipboard_enabled: Some(clipboard_enabled),
                }) {
                    Ok(ControlResponse::Applied { restart_required }) => {
                        // Same truth rule as the role buttons: the green
                        // role text follows the Applied result at once.
                        set_role_display(&weak, requested_mode);
                        // Settings (role included) can invalidate a running
                        // edge contract: stop it rather than drive stale.
                        if config_session
                            .lock()
                            .ok()
                            .is_some_and(|slot| slot.as_ref().is_some_and(|session| session.is_edge))
                        {
                            ui_log("settings saved: stopping edge control; it restarts by itself for the new settings");
                            stop_session(&weak, &config_session, "Edge control stopped");
                        }
                        set_status(
                            &weak,
                            if restart_required {
                                "Configuration saved; restart daemon".into()
                            } else {
                                "Configuration saved".into()
                            },
                        )
                    }
                    Ok(ControlResponse::Error { message }) => {
                        ui_log(&format!("settings save refused: {message}"));
                        set_status(&weak, message)
                    }
                    Ok(other) => {
                        ui_log(&format!("settings save unexpected: {other:?}"));
                        set_status(&weak, format!("Unexpected daemon response: {other:?}"))
                    }
                    Err(control_error) => match command.output() {
                        Ok(output) if output.status.success() => {
                            set_role_display(&weak, requested_mode);
                            set_status(&weak, "Configuration saved (CLI fallback)".into())
                        }
                        Ok(output) => set_status(
                            &weak,
                            format!(
                                "Configuration failed: {}; control: {control_error}",
                                String::from_utf8_lossy(&output.stderr)
                            ),
                        ),
                        Err(error) => set_status(
                            &weak,
                            format!("Cannot start daemon: {error}; control: {control_error}"),
                        ),
                    },
                }
            });
        },
    );

    let weak = ui.as_weak();
    ui.on_import_layout(move |path| {
        let weak = weak.clone();
        let path = PathBuf::from(path.to_string());
        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let raw = std::fs::read_to_string(&path)
                    .with_context(|| format!("read layout {}", path.display()))?;
                let layout: kvm_core::Layout = serde_json::from_str(&raw)
                    .with_context(|| format!("decode layout {}", path.display()))?;
                layout.validate().map_err(anyhow::Error::msg)?;
                match control_request(ControlRequest::GetConfig) {
                    Ok(ControlResponse::Config(current)) => {
                        match control_request(ControlRequest::SetConfig {
                            device_name: Some(current.device_name.clone()),
                            mode: Some(current.mode),
                            allow_lock_screen_control: Some(current.allow_lock_screen_control),
                            listen_port: None,
                            layout: Some(layout),
                            auto_connect_address: None,
                            clear_auto_connect: false,
                            clipboard_enabled: Some(current.clipboard_enabled),
                        })? {
                            ControlResponse::Applied { .. } => Ok(()),
                            ControlResponse::Error { message } => anyhow::bail!(message),
                            other => anyhow::bail!("unexpected daemon response: {other:?}"),
                        }
                    }
                    Ok(other) => anyhow::bail!("unexpected daemon config response: {other:?}"),
                    Err(control_error) => {
                        let daemon = std::env::var("THEKVM_DAEMON_PATH")
                            .unwrap_or_else(|_| "kvm-daemon".into());
                        let output = std::process::Command::new(daemon)
                            .args(["configure", "--layout"])
                            .arg(&path)
                            .output()
                            .with_context(|| {
                                format!("start daemon CLI after control error: {control_error}")
                            })?;
                        if output.status.success() {
                            Ok(())
                        } else {
                            anyhow::bail!(
                                "daemon CLI failed: {}",
                                String::from_utf8_lossy(&output.stderr)
                            )
                        }
                    }
                }
            })();
            match result {
                Ok(()) => set_status(&weak, "Screen topology imported".into()),
                Err(error) => set_status(&weak, format!("Topology import failed: {error}")),
            }
        });
    });

    ui.run()?;
    Ok(())
}

/// Plain-language role names shown next to "Current role:" and in the
/// connect gate message, so selection is never ambiguous.
fn role_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Bidirectional => "Both ways",
        Mode::ServerClient => "Control other",
        Mode::ClientOnly => "Be controlled",
    }
}

/// Show the authoritative role immediately. The green "Current role" text
/// must reflect an applied change at once — not wait for the next
/// successful status poll, which can be failing for unrelated reasons
/// (and then the display would lie until the poll recovers).
fn set_role_display(weak: &slint::Weak<AppWindow>, mode: Mode) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_mode_index(match mode {
                    Mode::Bidirectional => 0,
                    Mode::ServerClient => 1,
                    Mode::ClientOnly => 2,
                });
                ui.set_role_text(SharedString::from(role_name(mode)));
            }
        }
    });
}

/// Status text for a failed control request. A permission problem names its
/// remedy (including the stale-login-session case) instead of a raw OS
/// error, so the user always knows the next step.
fn control_denied_status(error: &anyhow::Error, prefix: &str) -> String {
    let permission_denied = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
    });
    if permission_denied {
        #[cfg(unix)]
        if unix_session_lacks_thekvm_group() {
            return "No permission for the background service: this login started before TheKVM added you to the 'thekvm' group. Log out and back in once (no reinstall needed), then retry.".into();
        }
        return format!(
            "{prefix}: permission denied by the background service. Log out and back in, then relaunch TheKVM."
        );
    }
    format!("{prefix}: {error:#}")
}

/// True when the desktop user is listed in the `thekvm` group in /etc/group
/// (install-time membership) but this process's own login-time groups lack
/// it — proof the session predates the install and a re-login will fix
/// access. No libc dependency: one `id` call, only on permission failures.
#[cfg(unix)]
fn unix_session_lacks_thekvm_group() -> bool {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    if user.is_empty() {
        return false;
    }
    let Ok(groups) = std::fs::read_to_string("/etc/group") else {
        return false;
    };
    let listed = groups.lines().any(|line| {
        let mut fields = line.split(':');
        if fields.next() != Some("thekvm") {
            return false;
        }
        fields.nth(2).is_some_and(|members| {
            members.split(',').any(|member| member.trim() == user)
        })
    });
    if !listed {
        return false;
    }
    std::process::Command::new("id")
        .arg("-Gn")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|names| !names.split_whitespace().any(|name| name == "thekvm"))
        .unwrap_or(false)
}

fn set_daemon_status(weak: &slint::Weak<AppWindow>, status: DaemonStatus) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                // The role buttons apply explicitly through set-role; status
                // polling only displays the daemon's authoritative state and
                // must never write settings back.
                ui.set_connected(true);
                ui.set_status_text(SharedString::from(format!(
                    "Daemon online · {} trusted peer(s) · {} active session(s)",
                    status.peer_count, status.active_session_count
                )));
                ui.set_lock_screen_control(status.allow_lock_screen_control);
                ui.set_clipboard_enabled(status.clipboard_enabled);
                ui.set_device_name(SharedString::from(status.node_name));
                ui.set_auto_connect_address(SharedString::from(
                    status.auto_connect_address.unwrap_or_default(),
                ));
                ui.set_mode_index(match status.mode {
                    Mode::Bidirectional => 0,
                    Mode::ServerClient => 1,
                    Mode::ClientOnly => 2,
                });
                ui.set_fingerprint(SharedString::from(status.fingerprint_hex));
                ui.set_role_text(SharedString::from(role_name(status.mode)));
                ui.set_pairing_code(SharedString::from(status.pairing_code));
            }
        }
    });
}

fn set_daemon_offline(weak: &slint::Weak<AppWindow>, message: String) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_connected(false);
                ui.set_status_text(SharedString::from(message));
                ui.set_incoming_pairing(SharedString::new());
                ui.set_incoming_pairing_fingerprint(SharedString::new());
                ui.set_incoming_verification_code(SharedString::new());
            }
        }
    });
}

fn set_peer_list(weak: &slint::Weak<AppWindow>, peers: Vec<kvm_protocol::pairing::Peer>) {
    let text = if peers.is_empty() {
        "No trusted peers".to_owned()
    } else {
        peers
            .iter()
            .map(|peer| {
                format!(
                    "{} · {} · {}",
                    peer.name,
                    peer.address.as_deref().unwrap_or("address unknown"),
                    peer.fingerprint_hex
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_peer_list(SharedString::from(text));
            }
        }
    });
}

fn set_incoming_pairing(weak: &slint::Weak<AppWindow>, pairings: Vec<PendingPairing>) {
    let (summary, fingerprint, verification_code) = match pairings.first() {
        Some(pairing) => {
            let suffix = if pairings.len() > 1 {
                format!(" (+{} more)", pairings.len() - 1)
            } else {
                String::new()
            };
            (
                format!(
                    "{} · {} · {}{}",
                    pairing.node_name, pairing.address, pairing.fingerprint_hex, suffix
                ),
                pairing.fingerprint_hex.clone(),
                pairing.verification_code.clone(),
            )
        }
        None => (String::new(), String::new(), String::new()),
    };
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                // Taskbar/dock visibility: a minimized window must still
                // announce the request. Restored when the request clears.
                if summary.is_empty() {
                    ui.set_title_alert(SharedString::new());
                } else {
                    ui.set_title_alert(SharedString::from(" — incoming pairing!"));
                }
                ui.set_incoming_pairing(SharedString::from(summary));
                ui.set_incoming_pairing_fingerprint(SharedString::from(fingerprint));
                ui.set_incoming_verification_code(SharedString::from(verification_code));
            }
        }
    });
}

fn decide_incoming_pairing(weak: &slint::Weak<AppWindow>, fingerprint: String, approved: bool) {
    let weak = weak.clone();
    std::thread::spawn(move || {
        let request = if approved {
            ControlRequest::ApprovePairing {
                fingerprint_hex: fingerprint.clone(),
            }
        } else {
            ControlRequest::RejectPairing {
                fingerprint_hex: fingerprint.clone(),
            }
        };
        match control_request(request) {
            Ok(ControlResponse::PairingApproved { .. }) if approved => {
                set_status(&weak, format!("Approved incoming pairing {fingerprint}"));
                set_incoming_pairing(&weak, Vec::new());
            }
            Ok(ControlResponse::PairingRejected { .. }) if !approved => {
                set_status(&weak, format!("Rejected incoming pairing {fingerprint}"));
                set_incoming_pairing(&weak, Vec::new());
            }
            Ok(ControlResponse::Error { message }) => set_status(&weak, message),
            Ok(other) => set_status(&weak, format!("Unexpected pairing decision: {other:?}")),
            Err(error) => set_status(&weak, format!("Pairing decision failed: {error}")),
        }
    });
}

/// Deskflow-simple connect flow: type (or scan) the other computer's
/// address, press Connect. A trusted peer connects immediately; a new peer
/// runs the six-digit ceremony first, then connects. The controller session
/// dials with the USER identity (the same peer book the ceremony pins), so
/// no privileged state is ever needed on the controller side.
///
/// NODE side of the station/node contract: this computer dials out to a
/// waiting station. "Connected" is reported only after the session child
/// confirms a live connection; until then the status says connecting.
fn start_session_flow(
    weak: &slint::Weak<AppWindow>,
    pending: &Arc<Mutex<Option<PendingPair>>>,
    data_dir: &std::path::Path,
    session: &Arc<Mutex<Option<Session>>>,
    address: String,
    pairing_code: Option<String>,
) {
    // Reap a dead previous session first so a stale slot can never wedge
    // reconnect behind a permanent "Already connected".
    if let Ok(mut slot) = session.lock() {
        let dead = slot.as_mut().is_some_and(|session| {
            matches!(session.child.try_wait(), Ok(Some(_)) | Err(_))
        });
        if dead {
            *slot = None;
            set_session(weak, None);
        }
        // Fixed takeover supersedes edge control (and launch_child stops
        // whatever runs), so an active edge session must not wedge Connect
        // behind "Already connected".
        let edge_active = slot.as_ref().is_some_and(|session| session.is_edge);
        let any_active = slot.is_some();
        drop(slot);
        if edge_active {
            ui_log("pairing: fixed connect supersedes edge control; stopping it");
            stop_session(weak, session, "Edge control stopped");
        } else if any_active {
            set_status(weak, "Already connected — Disconnect first".into());
            return;
        }
    }
    let weak = weak.clone();
    let pending = pending.clone();
    let session = session.clone();
    let data_dir = data_dir.to_owned();
    std::thread::spawn(move || {
        // A fresh Connect supersedes any lingering code check: dropping the
        // old pairing channel tells the station to withdraw its popup, so
        // retries never stack duplicate requests there.
        if pending
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .is_some()
        {
            ui_log("pairing: previous code check superseded by a new Connect");
            set_pending(&weak, String::new(), String::new(), String::new());
        }
        // A receiver-only machine must not initiate sessions; the daemon
        // would refuse them. Refuse early with guidance instead of a
        // cryptic failure. When the daemon is unreachable the mode cannot
        // be checked, so the session is attempted anyway and the daemon
        // reports the real error. This check runs here (not on the UI
        // thread) so a wedged control endpoint can never freeze the app.
        if let Ok(ControlResponse::Status(status)) = control_request(ControlRequest::Status) {
            if status.mode == kvm_core::Mode::ClientOnly {
                set_status(
                    &weak,
                    "This computer is set to 'Be controlled', so it cannot dial out. Press 'Control other' or 'Both ways' above, then Connect again.".into(),
                );
                return;
            }
        }
        let node_name = kvm_core::Config::load(&data_dir.join("config.json"))
            .map(|config| config.device_name)
            .unwrap_or_else(|_| fallback_node_name());
        set_peer_address_field(&weak, &address);
        set_status(&weak, format!("Contacting {address}…"));
        match pair_prepare(&address, &data_dir, &node_name, pairing_code) {
            Ok(pair) => {
                // Already trusted: skip the ceremony entirely.
                if is_controller_peer_pinned(&data_dir, &pair.peer_fingerprint) {
                    set_status(&weak, format!("Connecting to {}…", pair.peer_node_name));
                    spawn_session(&weak, &session, &pending, &data_dir, pair.address);
                    return;
                }
                let fingerprint = pair.peer_fingerprint.clone();
                let peer_name = pair.peer_node_name.clone();
                let code = pair.verification_code.clone();
                // Typed-code pairing, approved by the station itself: finish
                // immediately on the held-open channel. No compare screen
                // ever shows (there is nothing left for either human to
                // approve), and the misleading "approve it there too" text
                // must never appear for this path.
                if pair.station_pre_approved {
                    ui_log(&format!(
                        "pairing: station {peer_name} approved via typed code; finishing without a code screen"
                    ));
                    set_status(
                        &weak,
                        format!("{peer_name} approved automatically — finishing pairing…"),
                    );
                    run_pair_confirm(&weak, data_dir, &session, &pending, pair);
                    return;
                }
                let generation = pair.generation;
                let typed_code_sent = pair.typed_code_sent;
                // Hold the pairing channel open (stored in the slot) and
                // watch it: if the station ends the request (expiry,
                // restart, denial-by-closure), the code screen must die
                // with it instead of showing stale digits forever. Only
                // this generation may clear the screen.
                let watch_connection = pair
                    .pairing
                    .as_ref()
                    .map(|channel| channel.connection.clone());
                if let Ok(mut slot) = pending.lock() {
                    *slot = Some(pair);
                }
                if let Some(watch_connection) = watch_connection {
                    let watch_weak = weak.clone();
                    let watch_pending = pending.clone();
                    let watch_address = address.clone();
                    std::thread::spawn(move || {
                        runtime().block_on(async move {
                            watch_connection.closed().await;
                        });
                        let live = watch_pending.lock().ok().is_some_and(|slot| {
                            slot.as_ref()
                                .is_some_and(|current| current.generation == generation)
                        });
                        if live {
                            if let Ok(mut slot) = watch_pending.lock() {
                                *slot = None;
                            }
                            ui_log("pairing: station ended the request; code screen cleared");
                            set_pending(
                                &watch_weak,
                                String::new(),
                                String::new(),
                                String::new(),
                            );
                            set_status(
                                &watch_weak,
                                format!(
                                    "The request on {watch_address} ended before approval — press Connect again for a fresh code."
                                ),
                            );
                        }
                    });
                }
                set_status(&weak, pair_status_text(&peer_name, &code, typed_code_sent));
                set_pending(&weak, fingerprint, code, peer_name);
            }
            Err(error) => set_status(&weak, format!("Cannot reach {address}: {error}")),
        }
    });
}

/// Finish a pairing on the held-open channel: send PairConfirm, wait for the
/// station's answer, pin on Accepted and start the session. Shared by the
/// manual Confirm click (compare-codes path) and the automatic finish
/// (typed-code path: the station already approved, so no code screen ever
/// shows and this runs immediately).
fn run_pair_confirm(
    weak: &slint::Weak<AppWindow>,
    data_dir: std::path::PathBuf,
    session: &Arc<Mutex<Option<Session>>>,
    pending_arc: &Arc<Mutex<Option<PendingPair>>>,
    pending: PendingPair,
) {
    let weak = weak.clone();
    let confirm_data_dir = data_dir;
    let confirm_session = session.clone();
    let confirm_pending = pending_arc.clone();
    std::thread::spawn(move || {
        // The user compared the six-digit code on both screens and
        // approved (or the station pre-approved via the typed code):
        // confirm on the pairing channel we held open, then wait for the
        // station's answer. It may have approved already (answer is
        // instant) or still be deciding (we wait, saying so). Only an
        // Accepted pins the peer locally and starts the session — a
        // one-sided local pin is exactly the trap that used to wedge
        // reconnects forever.
        let mut pending = pending;
        let Some(mut channel) = pending.pairing.take() else {
            ui_log("pairing: confirm without an open channel");
            set_status(&weak, "Pairing channel is gone — press Connect again.".into());
            return;
        };
        let peer_name = pending.peer_node_name.clone();
        set_status(&weak, format!("Waiting for approval on {peer_name}…"));
        ui_log(&format!("pairing: codes approved locally, awaiting {peer_name}"));
        let answer = runtime().block_on(async {
            write_frame(
                &mut channel.send,
                &WireMessage::PairConfirm {
                    server_fingerprint_hex: pending.peer_fingerprint.clone(),
                },
            )
            .await?;
            tokio::time::timeout(
                std::time::Duration::from_secs(150),
                read_frame(&mut channel.recv),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!("timed out waiting for {peer_name} to approve (150s)")
            })?
            .context("peer closed pairing without answering")?
            .context("peer closed pairing without answering")
        });
        match answer {
            Ok(WireMessage::Accepted { .. }) => {
                match pin_controller_peer(&confirm_data_dir, &pending) {
                    Ok(()) => {
                        set_pending(&weak, String::new(), String::new(), String::new());
                        set_status(&weak, format!("Paired with {peer_name}"));
                        ui_log(&format!("pairing: accepted by {peer_name}"));
                        // Mirror the trust into the daemon book (reverse
                        // sessions must open too) and take the Machine-1
                        // default arrangement when none is saved yet.
                        pin_daemon_peer(
                            &pending.peer_fingerprint,
                            &peer_name,
                            Some(&pending.address),
                        );
                        ensure_default_arrangement(&peer_name, &pending.peer_fingerprint);
                        spawn_session(&weak, &confirm_session, &confirm_pending, &confirm_data_dir, pending.address);
                    }
                    Err(error) => {
                        ui_log(&format!("pairing: accepted but pin failed: {error:#}"));
                        set_status(&weak, format!("Pairing failed: {error}"))
                    }
                }
            }
            Ok(WireMessage::Reject { reason }) => {
                ui_log(&format!("pairing: declined by {peer_name}: {reason}"));
                set_status(&weak, format!("{peer_name} declined pairing: {reason}"))
            }
            Ok(other) => {
                ui_log(&format!("pairing: unexpected completion: {other:?}"));
                channel.connection.close(0u32.into(), b"pairing done");
                set_status(&weak, format!("Unexpected pairing answer: {other:?}"))
            }
            Err(error) => {
                ui_log(&format!("pairing: confirm failed: {error:#}"));
                channel.connection.close(0u32.into(), b"pairing done");
                set_status(&weak, format!("{peer_name} did not answer: {error:#}"))
            }
        }
    });
}

/// Status sentence for the compare-code screen. It must never imply the
/// station is showing a popup "for us" when we know it isn't: a typed code
/// that the station rejected (wrong/stale digits) falls back to comparison,
/// and the user must hear that the typed code failed — not wait for an
/// approval that will never come.
fn pair_status_text(peer_name: &str, code: &str, typed_code_sent: bool) -> String {
    if typed_code_sent {
        format!(
            "The typed code was not accepted on {peer_name} (wrong or expired digits) — compare instead: does {peer_name} show the code {code}? Approve it there too, then confirm here."
        )
    } else {
        format!("Does {peer_name} show the code {code}? Approve it there too, then confirm here.")
    }
}

fn is_controller_peer_pinned(data_dir: &std::path::Path, fingerprint: &str) -> bool {
    kvm_protocol::pairing::PeerBook::load_or_create(data_dir)
        .map(|book| book.is_pinned(fingerprint))
        .unwrap_or(false)
}

/// Remove the locally pinned peer(s) for an address — full or host-part
/// match, so `192.168.1.7` and `192.168.1.7:42110` find each other — forcing
/// the next Connect to run the full code ceremony again. Returns true when
/// anything was removed.
fn unpin_peer_by_address(data_dir: &std::path::Path, address: &str) -> bool {
    let mut removed = false;
    if let Ok(mut book) = kvm_protocol::pairing::PeerBook::load_or_create(data_dir) {
        let host = address.split(':').next().unwrap_or(address);
        let fingerprints: Vec<String> = book
            .peers
            .iter()
            .filter(|peer| {
                peer.address.as_deref().is_some_and(|stored| {
                    stored == address || stored.split(':').next() == Some(host)
                })
            })
            .map(|peer| peer.fingerprint_hex.clone())
            .collect();
        for fingerprint in fingerprints {
            match book.unpin(&fingerprint) {
                Ok(true) => {
                    ui_log(&format!("session: removed stale local pin for {address}"));
                    removed = true;
                }
                Ok(false) => {}
                Err(error) => {
                    ui_log(&format!("session: cannot remove stale pin: {error}"));
                }
            }
        }
    }
    removed
}

/// Record the approved peer in the controller (user) book. Mirrors the
/// daemon-side pin: name, lowercase fingerprint, and canonical address so
/// later sessions take the TLS-pinned fast path.
fn pin_controller_peer(data_dir: &std::path::Path, pending: &PendingPair) -> Result<()> {
    let mut book = kvm_protocol::pairing::PeerBook::load_or_create(data_dir)
        .with_context(|| format!("open peer book in {}", data_dir.display()))?;
    let name = if pending.peer_node_name.trim().is_empty() {
        pending.address.clone()
    } else {
        pending.peer_node_name.clone()
    };
    book
        .pin_with_address(name, pending.peer_fingerprint.clone(), Some(pending.address.clone()))
        .with_context(|| format!("pin peer {}", pending.peer_fingerprint))?;
    Ok(())
}

/// Pin a peer into the USER book (the supervised edge child resolves peers
/// from here). Upsert: re-pinning refreshes name/address, never duplicates.
fn ensure_user_pin(fingerprint: &str, name: &str, address: Option<&str>) {
    match kvm_protocol::pairing::PeerBook::load_or_create(&data_dir()) {
        Ok(mut book) => {
            let label = if name.trim().is_empty() {
                address.unwrap_or(fingerprint)
            } else {
                name
            };
            if let Err(error) = book.pin_with_address(
                label,
                fingerprint.to_owned(),
                address.map(str::to_owned),
            ) {
                ui_log(&format!("arrange: user pin failed: {error:#}"));
            }
        }
        Err(error) => ui_log(&format!("arrange: cannot open user peer book: {error:#}")),
    }
}

/// Mirror ceremony trust into the DAEMON book so the reverse direction can
/// open sessions too (edge control drives both ways). Best effort and
/// logged: a mirror failure never fails the pairing itself.
fn pin_daemon_peer(fingerprint: &str, name: &str, address: Option<&str>) {
    match control_request(ControlRequest::PinPeer {
        fingerprint_hex: fingerprint.to_owned(),
        node_name: Some(name.to_owned()),
        address: address.map(str::to_owned),
    }) {
        Ok(ControlResponse::Pinned { .. }) => {
            ui_log("pairing: mirrored trust into daemon peer book")
        }
        Ok(ControlResponse::Error { message }) => {
            ui_log(&format!("pairing: daemon pin refused: {message}"))
        }
        Ok(other) => ui_log(&format!("pairing: daemon pin unexpected: {other:?}")),
        Err(error) => ui_log(&format!("pairing: daemon pin failed: {error:#}")),
    }
}

/// Persist a screen arrangement to BOTH configs the edge child and the
/// daemon read (user config for the supervised child, daemon config for
/// serving and display). Read-modify-write so arranging screens never
/// clobbers any other setting. Saved arrangements are permanent: nothing
/// here ever overwrites one except an explicit arrange action.
fn write_arrangement(layout: kvm_core::Layout) -> Result<kvm_core::Layout> {
    layout.validate().map_err(anyhow::Error::msg)?;
    let current = match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => config,
        Ok(other) => anyhow::bail!("cannot read settings: {other:?}"),
        Err(error) => anyhow::bail!("settings unreadable: {error:#}"),
    };
    match control_request(ControlRequest::SetConfig {
        device_name: Some(current.device_name.clone()),
        mode: Some(current.mode),
        allow_lock_screen_control: Some(current.allow_lock_screen_control),
        listen_port: None,
        layout: Some(layout.clone()),
        auto_connect_address: current.auto_connect_address.clone(),
        clear_auto_connect: current.auto_connect_address.is_none(),
        clipboard_enabled: Some(current.clipboard_enabled),
    }) {
        Ok(ControlResponse::Applied { .. }) => {}
        Ok(ControlResponse::Error { message }) => anyhow::bail!("{message}"),
        Ok(other) => anyhow::bail!("unexpected daemon response: {other:?}"),
        Err(error) => anyhow::bail!("{error:#}"),
    }
    mirror_user_config(
        &current.device_name,
        current.mode,
        current.allow_lock_screen_control,
        current.clipboard_enabled,
        Some(layout.clone()),
    );
    ui_log("arrange: screen arrangement saved");
    Ok(layout)
}

/// Machine-1 default arrangement at pairing time: this machine left, the
/// new peer right (one exit edge). Writes ONLY when no arrangement exists
/// yet — a saved arrangement is never overwritten.
fn ensure_default_arrangement(peer_name: &str, peer_fingerprint: &str) {
    let current = match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => config,
        _ => return,
    };
    if !current.layout.screens.is_empty() {
        return;
    }
    let layout =
        kvm_core::Layout::pair_default(&current.device_name, peer_name, peer_fingerprint);
    match write_arrangement(layout) {
        Ok(_) => ui_log("arrange: default Machine-1 arrangement saved (peer on the right)"),
        Err(error) => ui_log(&format!("arrange: default arrangement failed: {error:#}")),
    }
}

/// Throttle for the automatic arrangement/trust setup check (seconds).
static LAST_MIRROR_CHECK_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Rewrite a 0.2.0 station-mirror layout (self=1, peer=2 on the left) into
/// the global-id convention (self=2, peer=1). 0.2.0 sessions could never
/// open with the old ids — the receiver only accepts its own self screen —
/// so any exact-shape match is provably pre-fix and safe to rewrite.
/// Returns None for anything else (including already-correct layouts).
fn migrate_020_mirror(layout: &kvm_core::Layout) -> Option<kvm_core::Layout> {
    if layout.self_screen != Some(kvm_core::SELF_SCREEN_ID) || layout.screens.len() != 2 {
        return None;
    }
    let me = layout.screen(kvm_core::SELF_SCREEN_ID)?;
    let peer = layout
        .screens
        .iter()
        .find(|screen| screen.id == kvm_core::FIRST_PEER_SCREEN_ID)?;
    let peer_fp = peer.peer_fingerprint.clone()?;
    if peer.x >= me.x || peer.y != me.y {
        return None;
    }
    Some(kvm_core::Layout {
        screens: vec![
            kvm_core::Screen {
                id: kvm_core::MIRROR_SELF_SCREEN_ID,
                name: me.name.clone(),
                x: 0,
                y: 0,
                width: me.width,
                height: me.height,
                peer_fingerprint: None,
            },
            kvm_core::Screen {
                id: kvm_core::MIRROR_PEER_SCREEN_ID,
                name: peer.name.clone(),
                x: -1,
                y: 0,
                width: peer.width,
                height: peer.height,
                peer_fingerprint: Some(peer_fp),
            },
        ],
        self_screen: Some(kvm_core::MIRROR_SELF_SCREEN_ID),
    })
}

/// Automatic first-time setup (at most once a minute, never overwriting):
/// 1. migrate any 0.2.0 mirror layout into global screen ids;
/// 2. station side (daemon trusts peers, nothing arranged): mirror Machine 1
///    onto the left, pin the user book, link the daemon book;
/// 3. initiator side (user book trusts peers, daemon empty, nothing
///    arranged): take the Machine-1 default (peer on the right), link the
///    daemon book so the reverse direction can open sessions too.
fn maybe_mirror_station_arrangement(status: &DaemonStatus) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if LAST_MIRROR_CHECK_SECS.swap(now, std::sync::atomic::Ordering::Relaxed) + 60 > now {
        return;
    }
    let config = match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => config,
        _ => return,
    };
    if !config.layout.screens.is_empty() {
        if let Some(fixed) = migrate_020_mirror(&config.layout) {
            match write_arrangement(fixed) {
                Ok(_) => ui_log("arrange: migrated 0.2.0 mirror layout to shared screen ids"),
                Err(error) => ui_log(&format!("arrange: layout migration failed: {error:#}")),
            }
        }
        return;
    }
    if status.peer_count > 0 {
        let peers = match control_request(ControlRequest::ListPeers) {
            Ok(ControlResponse::Peers(peers)) => peers,
            _ => return,
        };
        let Some(peer) = peers.first() else {
            return;
        };
        let layout = kvm_core::Layout::pair_mirror(
            &config.device_name,
            &peer.name,
            &peer.fingerprint_hex,
        );
        match write_arrangement(layout) {
            Ok(_) => {
                ensure_user_pin(
                    &peer.fingerprint_hex,
                    &peer.name,
                    peer.address.as_deref(),
                );
                ui_log("arrange: station default arrangement saved (peer on the left)");
            }
            Err(error) => ui_log(&format!("arrange: station default failed: {error:#}")),
        }
        return;
    }
    // Initiator side of an older pairing: the user book already trusts the
    // peer (ceremony pin) but the daemon book is empty, so the reverse
    // direction cannot open sessions. Arrange Machine-1 default and link
    // the daemon book — initiation from the other side starts working.
    let user_peers = match kvm_protocol::pairing::PeerBook::load_or_create(&data_dir()) {
        Ok(book) => book.peers,
        Err(_) => return,
    };
    let Some(peer) = user_peers.first() else {
        return;
    };
    let layout = kvm_core::Layout::pair_default(
        &config.device_name,
        &peer.name,
        &peer.fingerprint_hex,
    );
    match write_arrangement(layout) {
        Ok(_) => {
            pin_daemon_peer(
                &peer.fingerprint_hex,
                &peer.name,
                peer.address.as_deref(),
            );
            ui_log("arrange: linked existing pairing for both directions (peer on the right)");
        }
        Err(error) => ui_log(&format!("arrange: existing-pairing setup failed: {error:#}")),
    }
}

/// One linked screen for the Devices arrangement section: the union of the
/// daemon book (both sides pin there after 0.2.0 ceremonies) and the user
/// book (initiator ceremonies pin there), with the arranged side from the
/// daemon layout when present.
struct LinkedPeer {
    name: String,
    fingerprint: String,
    address: Option<String>,
    side: Option<kvm_core::Edge>,
}

fn linked_peers() -> Vec<LinkedPeer> {
    let mut ordered: Vec<(String, String, Option<String>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Ok(ControlResponse::Peers(peers)) = control_request(ControlRequest::ListPeers) {
        for peer in peers {
            if seen.insert(peer.fingerprint_hex.clone()) {
                ordered.push((peer.name, peer.fingerprint_hex, peer.address));
            }
        }
    }
    if let Ok(book) =
        kvm_protocol::pairing::PeerBook::load_or_create(&data_dir())
    {
        for peer in &book.peers {
            if seen.insert(peer.fingerprint_hex.clone()) {
                ordered.push((
                    peer.name.clone(),
                    peer.fingerprint_hex.clone(),
                    peer.address.clone(),
                ));
            }
        }
    }
    let layout = match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => config.layout,
        _ => kvm_core::Layout::default(),
    };
    ordered
        .into_iter()
        .map(|(name, fingerprint, address)| {
            let side = layout.side_of_peer(&fingerprint);
            LinkedPeer {
                name,
                fingerprint,
                address,
                side,
            }
        })
        .collect()
}

fn side_name(side: kvm_core::Edge) -> &'static str {
    match side {
        kvm_core::Edge::Left => "LEFT",
        kvm_core::Edge::Right => "RIGHT",
        kvm_core::Edge::Top => "TOP",
        kvm_core::Edge::Bottom => "BOTTOM",
    }
}

/// True when this machine links exactly one peer screen: any edge crosses
/// (double edge exit), so status text must say "any edge", never one side.
fn any_edge_link() -> bool {
    matches!(
        control_request(ControlRequest::GetConfig),
        Ok(ControlResponse::Config(config)) if config.layout.single_peer_screen().is_some()
    )
}

/// Refresh the Devices arrangement display from live state. Runs on the
/// poll worker; all blocking calls are fine there.
fn refresh_arrangement(weak: &slint::Weak<AppWindow>, edge_active: bool) {
    let peers = linked_peers();
    let any_edge = any_edge_link();
    let (peer_name, text, peer_on_right) = match peers.first() {
        None => (
            String::new(),
            "No linked screens yet — pair a computer first, then place its screen here.".to_owned(),
            true,
        ),
        Some(peer) => {
            let label = if peer.name.trim().is_empty() {
                peer.fingerprint.chars().take(8).collect()
            } else {
                peer.name.clone()
            };
            match peer.side {
                Some(side) if !any_edge => (
                    label.clone(),
                    format!(
                        "{label} is on your {} — push past the {} edge to drive it. Push back past the edge to return.",
                        side_name(side),
                        edge_name(side)
                    ),
                    !matches!(side, kvm_core::Edge::Left),
                ),
                Some(side) => (
                    label.clone(),
                    format!(
                        "{label} is linked — push past ANY edge to drive it, on either computer. Push back past any edge to return."
                    ),
                    !matches!(side, kvm_core::Edge::Left),
                ),
                None => (
                    label.clone(),
                    format!(
                        "{label} is linked but has no screen yet — press Swap sides to place it."
                    ),
                    true,
                ),
            }
        }
    };
    set_arrangement(&weak, peer_name, text, peer_on_right, edge_active);
}

fn set_arrangement(
    weak: &slint::Weak<AppWindow>,
    peer_name: String,
    text: String,
    peer_on_right: bool,
    edge_active: bool,
) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_linked_peer_name(SharedString::from(peer_name));
                ui.set_arrangement_text(SharedString::from(text));
                ui.set_peer_on_right(peer_on_right);
                ui.set_edge_active(edge_active);
            }
        }
    });
}

/// Resolve a peer's display name and address from either book.
fn resolve_peer(fingerprint: &str) -> Option<(String, Option<String>)> {
    for peer in linked_peers() {
        if peer.fingerprint == fingerprint {
            return Some((peer.name, peer.address));
        }
    }
    None
}

/// Place one linked peer on the given side of this machine (the arrangement
/// UI): pins both books (edge child reads the user book, the daemon serves
/// the daemon book) and persists the layout to both configs. Saved
/// arrangements survive restarts; this overwrites only the peer position.
fn arrange_place_peer(weak: &slint::Weak<AppWindow>, fingerprint: &str, side: kvm_core::Edge) {
    let Some((name, address)) = resolve_peer(fingerprint) else {
        set_status(&weak, "Linked computer not found — pair it first.".into());
        return;
    };
    let current = match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => config,
        Ok(other) => {
            set_status(&weak, format!("Cannot read settings: {other:?}"));
            return;
        }
        Err(error) => {
            set_status(&weak, format!("Settings unreadable: {error:#}"));
            return;
        }
    };
    let mut layout = if current.layout.screens.is_empty() {
        kvm_core::Layout::pair_default(&current.device_name, &name, fingerprint)
    } else {
        current.layout.clone()
    };
    // The layout may predate the peer screen (paired before arrangement
    // existed): add it before placing.
    if !layout
        .screens
        .iter()
        .any(|screen| screen.peer_fingerprint.as_deref() == Some(fingerprint))
    {
        let id = layout.next_screen_id();
        layout.screens.push(kvm_core::Screen {
            id,
            name: name.clone(),
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            peer_fingerprint: Some(fingerprint.to_ascii_lowercase()),
        });
    }
    // Repair imports that never named a local screen: prefer a non-peer
    // screen, else the first screen, so placement always has a "me".
    let self_missing = layout
        .self_screen
        .map_or(true, |id| layout.screen(id).is_none());
    if self_missing {
        layout.self_screen = layout
            .screens
            .iter()
            .find(|screen| screen.peer_fingerprint.is_none())
            .or_else(|| layout.screens.first())
            .map(|screen| screen.id);
    }
    if let Err(error) = layout.place_peer(fingerprint, side) {
        set_status(&weak, format!("Cannot place the screen there: {error}"));
        return;
    }
    match write_arrangement(layout) {
        Ok(_) => {
            ensure_user_pin(fingerprint, &name, address.as_deref());
            pin_daemon_peer(fingerprint, &name, address.as_deref());
            ui_log(&format!("arrange: {name} placed on the {}", edge_name(side)));
            refresh_arrangement(&weak, false);
            set_status(
                &weak,
                format!(
                    "{} is on your {} — start edge control and push past the {} edge.",
                    name,
                    side_name(side),
                    edge_name(side)
                ),
            );
        }
        Err(error) => set_status(&weak, format!("Arrangement failed: {error:#}")),
    }
}

/// Swap the first linked peer to the opposite side (Left<->Right,
/// Top<->Bottom). With no placed side yet, this places the peer on the
/// right (Machine-1 default).
fn arrange_swap(weak: &slint::Weak<AppWindow>) {
    let peers = linked_peers();
    let Some(peer) = peers.first() else {
        set_status(&weak, "No linked computer to place — pair one first.".into());
        return;
    };
    let next = match peer.side {
        Some(kvm_core::Edge::Left) => kvm_core::Edge::Right,
        Some(kvm_core::Edge::Right) => kvm_core::Edge::Left,
        Some(kvm_core::Edge::Top) => kvm_core::Edge::Bottom,
        Some(kvm_core::Edge::Bottom) => kvm_core::Edge::Top,
        None => kvm_core::Edge::Right,
    };
    arrange_place_peer(&weak, &peer.fingerprint.clone(), next);
}

/// Start the supervised `connect` session.
///
/// Identity contract (this was the connection bug): the pairing ceremony
/// and the peer book live in THIS UI's user data directory, so the child
/// is pinned to the same directory via THEKVM_DATA_DIR. Inheriting the
/// environment is NOT enough — the daemon defaults to the privileged
/// system directory, which would make the child dial with a different
/// identity than the ceremony approved (and read an empty system peer
/// book), leaving the other side waiting for an approval that never
/// matches, stuck on "Connecting…" forever.
///
/// Honesty contract: spawning the child is NOT connecting. The status stays
/// at "Connecting…" until the child reports THEKVM_STATUS established on
/// its stderr; only then does the UI say "Connected". A child that exits
/// before that is reported as a failed connection, never a live one.
fn spawn_session(
    weak: &slint::Weak<AppWindow>,
    session: &Arc<Mutex<Option<Session>>>,
    pending: &Arc<Mutex<Option<PendingPair>>>,
    data_dir: &std::path::Path,
    address: String,
) {
    launch_child(
        weak,
        session,
        pending,
        data_dir,
        Some(address.clone()),
        address,
        false,
    );
}

/// Always-on edge predicate: edge must be (re)started when this computer
/// may drive (anything but receiver-only), no session runs, and no pairing
/// ceremony is open. Pure so the determinism is unit-tested, not hoped
/// for — the poll loop only adds the 15s spawn throttle around this.
fn should_auto_start_edge(
    mode: kvm_core::Mode,
    session_running: bool,
    ceremony_open: bool,
) -> bool {
    mode != kvm_core::Mode::ClientOnly && !session_running && !ceremony_open
}

/// Start edge control: the supervised `connect` child with no address, which
/// watches the cursor and drives linked screens across the arranged exit
/// edge. Local input stays local until an actual crossing — unlike fixed
/// takeover — so starting it can never trap the local keyboard and mouse.
fn spawn_edge(
    weak: &slint::Weak<AppWindow>,
    session: &Arc<Mutex<Option<Session>>>,
    pending: &Arc<Mutex<Option<PendingPair>>>,
    data_dir: &std::path::Path,
) {
    // A receiver-only machine must not drive others; the daemon would refuse
    // every handoff. Refuse early with guidance instead of a mysterious
    // edge mode that never crosses.
    if let Ok(ControlResponse::Status(status)) = control_request(ControlRequest::Status) {
        if status.mode == kvm_core::Mode::ClientOnly {
            set_status(
                weak,
                "This computer is set to 'Be controlled', so edge control cannot drive others. Press 'Control other' or 'Both ways' above — edge control starts by itself once allowed.".into(),
            );
            return;
        }
    }
    launch_child(
        weak,
        session,
        pending,
        data_dir,
        None,
        "edge mode".to_owned(),
        true,
    );
}

/// Shared supervised-child launcher for fixed takeover (`connect <address>`)
/// and edge control (`connect` with no address). The child reports
/// THEKVM_STATUS progress on stderr; the relay turns it into truthful
/// status. Exactly one supervised child runs at a time: starting one mode
/// stops the other with a log line, so retries can never stack.
fn launch_child(
    weak: &slint::Weak<AppWindow>,
    session: &Arc<Mutex<Option<Session>>>,
    pending: &Arc<Mutex<Option<PendingPair>>>,
    data_dir: &std::path::Path,
    connect_address: Option<String>,
    label: String,
    is_edge: bool,
) {
    if session
        .lock()
        .ok()
        .is_some_and(|slot| slot.as_ref().is_some())
    {
        ui_log(&format!(
            "session: stopping the running {} before starting {label}",
            if is_edge { "takeover" } else { "edge control" }
        ));
        stop_session(weak, session, "Previous session stopped");
    }
    let binary = match daemon_binary() {
        Ok(binary) => binary,
        Err(error) => {
            set_status(&weak, format!("Cannot start connection: {error}"));
            return;
        }
    };
    let mut command = std::process::Command::new(&binary);
    command.arg("connect");
    if let Some(address) = &connect_address {
        command.arg(address);
    }
    command.env("THEKVM_DATA_DIR", data_dir);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    // Piped (not nulled): the child reports dialing/established/waiting
    // progress here and the relay below turns it into truthful status.
    command.stderr(std::process::Stdio::piped());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    match command.spawn() {
        Ok(mut child) => {
            let stderr = child.stderr.take();
            let verified = Arc::new(std::sync::atomic::AtomicBool::new(false));
            if let Ok(mut slot) = session.lock() {
                *slot = Some(Session {
                    child,
                    address: label.clone(),
                    verified: verified.clone(),
                    is_edge,
                });
            }
            set_session(&weak, Some(label.clone()));
            set_status(
                &weak,
                if is_edge {
                    "Starting edge control… arrange the linked screens first if it keeps waiting.".into()
                } else {
                    format!(
                        "Connecting to {label}… verifying the other side (a few seconds). Press Disconnect to stop."
                    )
                },
            );
            if let Some(stderr) = stderr {
                let weak = weak.clone();
                let session = session.clone();
                let pending = pending.clone();
                let data_dir = data_dir.to_owned();
                std::thread::spawn(move || {
                    relay_session_progress(&weak, stderr, &label, &verified, &session, &pending, data_dir, is_edge)
                });
            } else {
                ui_log("session: child stderr unavailable; connection cannot be verified");
            }
        }
        Err(error) => set_status(&weak, format!("Cannot start connection: {error}")),
    }
}

/// Relay the `connect` child's THEKVM_STATUS progress lines into the UI
/// status line. Only `established` flips the session to Connected; anything
/// else is shown as still-connecting. Identical consecutive lines are
/// coalesced so retry loops don't churn the event loop.
///
/// Self-healing trust: when the peer reports "not paired" three times in a
/// row, the local pin is provably one-sided (the ceremony completed here
/// but never there). Instead of retrying forever, the relay removes the
/// stale local pin, stops the hopeless child, and restarts the full code
/// ceremony automatically — the user only watches two code screens match.
/// This is safe: the refusal arrives over the peer's authenticated channel,
/// and the fresh ceremony still needs both sides to approve the codes.
fn relay_session_progress(
    weak: &slint::Weak<AppWindow>,
    stderr: std::process::ChildStderr,
    address: &str,
    verified: &Arc<std::sync::atomic::AtomicBool>,
    session: &Arc<Mutex<Option<Session>>>,
    pending: &Arc<Mutex<Option<PendingPair>>>,
    data_dir: std::path::PathBuf,
    is_edge: bool,
) {
    use std::io::BufRead as _;
    let reader = std::io::BufReader::new(stderr);
    let mut last_shown = String::new();
    let mut not_paired_streak: u32 = 0;
    for line in reader.lines().map_while(Result::ok) {
        let Some(progress) = line.strip_prefix("THEKVM_STATUS ") else {
            continue;
        };
        let (kind, detail) = match progress.find(' ') {
            Some(index) => (&progress[..index], progress[index + 1..].trim()),
            None => (progress, ""),
        };
        // Count refusals before dedup: identical repeats carry no new text
        // but each one is fresh evidence of one-sided trust.
        if kind == "waiting" && detail.contains("peer is not paired") {
            not_paired_streak += 1;
            if not_paired_streak == 3 {
                // Edge mode has no automatic re-pair path: it drives whatever
                // the books trust, so a refusal means the arrangement outlived
                // the trust. Stop honestly instead of looping or hijacking
                // the fixed-takeover ceremony.
                if is_edge {
                    ui_log("edge: peer reports us unknown 3x; stopping edge mode for a fresh pairing");
                    stop_session(weak, session, "Edge mode stopped");
                    set_status(
                        weak,
                        format!("{address} doesn't recognize this computer — repeat the code check under Connect; edge control restarts by itself afterwards."),
                    );
                    return;
                }
                if unpin_peer_by_address(&data_dir, address) {
                    ui_log(
                        "session: peer reports us unknown 3x; restarting pairing automatically",
                    );
                    set_status(
                        weak,
                        format!(
                            "{address} didn't recognize us — restarting the code check automatically…"
                        ),
                    );
                    stop_session(weak, session, "Restarting the code check…");
                    start_session_flow(weak, pending, &data_dir, session, address.to_owned(), None);
                    return;
                }
                // Nothing pinned locally under that address: fall through to
                // the manual recovery text below instead of looping.
            }
        } else if kind == "established" {
            not_paired_streak = 0;
        }
        let text = match kind {
            "established" => {
                verified.store(true, std::sync::atomic::Ordering::Relaxed);
                format!(
                    "Connected to {address} — your whole keyboard and mouse drive it now (this screen is frozen). Disconnect to take it back. It retries automatically until you Disconnect."
                )
            }
            "edge-ready" => {
                verified.store(true, std::sync::atomic::Ordering::Relaxed);
                set_driving(weak, String::new());
                edge_ready_text()
            }
            "driving" => {
                set_driving(weak, detail.to_owned());
                format!("Driving {detail} — push back past the edge to return here.")
            }
            "local" => {
                set_driving(weak, String::new());
                "Edge control is on — this computer. Push past any edge to drive the other screen.".into()
            }
            "locked" => {
                set_driving(weak, String::new());
                "Edge control locked to this computer — press ScrollLock to unlock.".into()
            }
            "waiting" => {
                if detail.contains("peer is not paired") {
                    // Half-finished pairing: this computer pinned the peer
                    // locally, but the peer never approved us, so every dial
                    // skips the ceremony and runs into a refusal. The only
                    // way forward is a fresh code check, which needs the
                    // stale local pin removed first.
                    #[cfg(target_os = "windows")]
                    let fix = "close the app, delete %APPDATA%\\TheKVM\\peers.json, reopen it";
                    #[cfg(not(target_os = "windows"))]
                    let fix = "close the app, delete ~/.config/thekvm/peers.json, reopen it";
                    format!(
                        "{address} does not recognize this computer (pairing was left half-finished). Press Disconnect, {fix}, then Connect again to repeat the code check."
                    )
                } else {
                    format!("Still reaching {address}… ({detail})")
                }
            }
            "dialing" => {
                if detail == "edge" {
                    "Starting edge control…".into()
                } else {
                    format!("Contacting {address}…")
                }
            }
            "ended" => format!("Connection to {address} ended ({detail})"),
            _ => continue,
        };
        if text != last_shown {
            last_shown = text.clone();
            set_status(weak, text);
        }
    }
}

fn stop_session(
    weak: &slint::Weak<AppWindow>,
    session: &Arc<Mutex<Option<Session>>>,
    message: &str,
) {
    let child = session.lock().ok().and_then(|mut slot| slot.take());
    let message = match child {
        Some(mut session) => {
            let address = session.address.clone();
            let _ = session.child.kill();
            // Wait reaps the child; the piped stderr then hits EOF so the
            // relay thread ends on its own. Report what actually happened.
            match session.child.wait() {
                Ok(status) => format!("Disconnected from {address} ({status})"),
                Err(error) => format!("Disconnected from {address} (stop failed: {error})"),
            }
        }
        None => message.to_owned(),
    };
    set_session(&weak, None);
    set_driving(&weak, String::new());
    set_status(&weak, message);
}

fn set_peer_address_field(weak: &slint::Weak<AppWindow>, address: &str) {
    let address = SharedString::from(address);
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_peer_address(address.clone());
            }
        }
    });
}

fn render_invite_qr(invite: &str) -> Result<slint::Image> {
    let code = qrcode::QrCode::new(invite.as_bytes())
        .map_err(|error| anyhow::anyhow!("QR encode failed: {error}"))?;
    let modules = code.width() as u32;
    let quiet = 4u32;
    let scale = 6u32;
    let size = (modules + quiet * 2) * scale;
    let mut buffer = slint::SharedPixelBuffer::<slint::Rgba8Pixel>::new(size, size);
    let dark = slint::Rgba8Pixel {
        r: 10,
        g: 10,
        b: 10,
        a: 255,
    };
    {
        let pixels = buffer.make_mut_slice();
        pixels.fill(slint::Rgba8Pixel {
            r: 255,
            g: 255,
            b: 255,
            a: 255,
        });
        for (index, color) in code.to_colors().iter().enumerate() {
            if matches!(color, qrcode::Color::Dark) {
                let module_x = index as u32 % modules;
                let module_y = index as u32 / modules;
                for dy in 0..scale {
                    for dx in 0..scale {
                        let x = (module_x + quiet) * scale + dx;
                        let y = (module_y + quiet) * scale + dy;
                        pixels[(y * size + x) as usize] = dark;
                    }
                }
            }
        }
    }
    Ok(slint::Image::from_rgba8(buffer))
}

/// Rebuild this machine's invite (and its QR) whenever the daemon identity,
/// port, or LAN address changes. Runs on the status-poll thread; rendering
/// is skipped while the displayed invite is still current.
fn refresh_invite(
    weak: &slint::Weak<AppWindow>,
    last_invite: &Arc<Mutex<String>>,
    listen_port: u16,
    fingerprint_hex: &str,
) {
    let address = match kvm_protocol::invite::lan_address() {
        Some(ip) => format!("{ip}:{listen_port}"),
        None => String::new(),
    };
    let Ok(invite) = kvm_protocol::invite::build(&address, fingerprint_hex) else {
        return;
    };
    match last_invite.lock() {
        Ok(mut slot) => {
            if *slot == invite {
                return;
            }
            *slot = invite.clone();
        }
        Err(_) => return,
    }
    let local_address = if address.is_empty() {
        "address unknown".to_owned()
    } else {
        address
    };
    // The invite string is Send; the QR image is rendered on the UI thread
    // because `slint::Image` must not cross thread boundaries.
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_invite_text(SharedString::from(invite.clone()));
            ui.set_local_address(SharedString::from(local_address));
            ui.set_invite_ready(true);
            if let Ok(qr) = render_invite_qr(&invite) {
                ui.set_invite_qr(qr);
            }
        }
    });
}

fn clear_invite(weak: &slint::Weak<AppWindow>, last_invite: &Arc<Mutex<String>>) {
    if let Ok(mut slot) = last_invite.lock() {
        slot.clear();
    }
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_invite_text(SharedString::new());
                ui.set_local_address(SharedString::new());
                ui.set_invite_ready(false);
            }
        }
    });
}

/// Why a control request failed, so the UI can respond professionally
/// instead of printing a raw OS error: start a missing daemon, or explain a
/// permissions problem without spawning a conflicting second daemon.
enum ControlFailure {
    Missing,
    AccessDenied,
    Other(String),
}

fn classify_control_error(error: &anyhow::Error) -> ControlFailure {
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            return match io.kind() {
                std::io::ErrorKind::PermissionDenied => ControlFailure::AccessDenied,
                std::io::ErrorKind::NotFound
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof => ControlFailure::Missing,
                _ => ControlFailure::Other(io.to_string()),
            };
        }
    }
    ControlFailure::Other(error.to_string())
}

/// Locate the daemon binary shipped next to this UI executable, falling back
/// to THEKVM_DAEMON_PATH for development layouts.
fn daemon_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("THEKVM_DAEMON_PATH") {
        let path = PathBuf::from(&path);
        if path.is_file() {
            return Ok(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let name = if cfg!(target_os = "windows") {
                "kvm-daemon.exe"
            } else {
                "kvm-daemon"
            };
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    anyhow::bail!("no daemon binary found next to this app; reinstall TheKVM")
}

/// Start a user-session daemon so opening TheKVM always yields a working app,
/// even when no system service is installed or running. Refuses when the
/// privileged system daemon already owns this machine (Linux control socket
/// present) so two daemons never fight over port 42110. When the system
/// service is installed but stopped, says exactly how to start it instead
/// of spawning a conflicting user daemon.
fn ensure_user_daemon() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/var/lib/thekvm/control.sock").exists() {
            anyhow::bail!(
                "the system service owns this machine but is unreachable; log out and back in, then relaunch"
            );
        }
        if systemctl_ok("is-active", "thekvmd") {
            anyhow::bail!("the system service is starting; retry in a few seconds");
        }
        if systemctl_ok("is-enabled", "thekvmd") {
            anyhow::bail!(
                "the system service is installed but stopped; start it once with: sudo systemctl start thekvmd (it then starts automatically on later boots)"
            );
        }
        // No system service: fall through and run our own user daemon below.
        // The UI's control path tries the user socket as a fallback, so this
        // daemon is reachable the moment it is up.
    }
    let binary = daemon_binary()?;
    // Pin the child to THIS UI's data directory: without this a user-session
    // daemon would resolve the privileged system directory, fail on
    // permissions, and serve a socket the UI never queries.
    let mut command = std::process::Command::new(&binary);
    command.arg("serve");
    command.env("THEKVM_DATA_DIR", data_dir());
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::null());
    #[cfg(target_os = "windows")]
    {
        // A user-session daemon must never flash a console window.
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
        .spawn()
        .with_context(|| format!("start {}", binary.display()))?;
    Ok(())
}

/// Unprivileged systemd state probe (is-active / is-enabled). Read-only, so
/// it never prompts and is safe to call from the poll path.
#[cfg(target_os = "linux")]
fn systemctl_ok(verb: &str, unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .arg(verb)
        .arg(unit)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// True when the packaged unit file exists at all (enabled, disabled, or
/// failed — anything but absent). Read-only; gates the pkexec path so the
/// Start button never prompts for a password on machines without the
/// package installed.
#[cfg(target_os = "linux")]
fn systemctl_unit_present(unit: &str) -> bool {
    std::process::Command::new("systemctl")
        .arg("cat")
        .arg(format!("{unit}.service"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Show this machine's LAN address even while the daemon is unreachable; it
/// is needed to tell the peer operator what to type.
/// Append a timestamped line to the UI log beside the user state. The UI
/// never shows a console, so this file is the ground truth when something
/// looks dead: every poll failure, role change, and session event lands
/// here with a reason instead of failing silently on screen.
fn ui_log(message: &str) {
    use std::io::Write as _;
    let dir = data_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("ui.log"))
    {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let _ = writeln!(file, "{millis}\t{message}");
    }
}

fn set_poll_count(weak: &slint::Weak<AppWindow>, count: u64) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_poll_count(count as i32);
            }
        }
    });
}

fn set_local_address_direct(weak: &slint::Weak<AppWindow>) {
    let address = kvm_protocol::invite::lan_address()
        .map(|ip| format!("{ip}:42110"))
        .unwrap_or_default();
    let address = SharedString::from(address);
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_local_address(address.clone());
            }
        }
    });
}
/// Monotonic ids for code checks; see PendingPair.generation.
static PAIRING_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Last incoming-pairing count already logged; the poll logs arrivals and
/// clears, so "UI knew but didn't show" vs "UI never knew" is always
/// answerable from ui.log alone.
static LAST_INCOMING_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Whether the poll has ever completed a Status round-trip. First success is
/// logged once with the station-code state, so a healthy-but-silent poll is
/// distinguishable from a dead one in ui.log alone.
static POLL_FIRST_OK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// One shared runtime for every background call (control pipe, pairing
/// preview dials, LAN scans). Creating a fresh Tokio runtime per request
/// churns threads and turns a failed creation into an untraceable call
/// failure; a single long-lived runtime removes that entire class.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Runtime::new().expect("start UI background runtime")
    })
}

fn control_request(request: ControlRequest) -> Result<ControlResponse> {
    let runtime = runtime();
    runtime.block_on(async move {
        #[cfg(unix)]
        let mut stream = {
            // Prefer the privileged system daemon; fall back to a
            // user-session daemon's socket so an automatically started
            // user daemon (the no-system-service case) just works — its
            // identity matches this UI's, so sessions dial with the
            // right peer book. Both attempts are bounded: a wedged
            // endpoint must fail loudly instead of freezing the caller
            // forever with zero log evidence.
            let system = control_data_dir().join("control.sock");
            let system_attempt = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                tokio::net::UnixStream::connect(&system),
            )
            .await;
            match system_attempt {
                Ok(Ok(stream)) => stream,
                system_outcome => {
                    let user = data_dir().join("control.sock");
                    let user_attempt = if user != system {
                        tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            tokio::net::UnixStream::connect(&user),
                        )
                        .await
                        .ok()
                    } else {
                        None
                    };
                    match user_attempt {
                        Some(Ok(stream)) => stream,
                        _ => {
                            return Err(match system_outcome {
                                Ok(Err(error)) => anyhow::Error::new(error)
                                    .context("connect daemon control socket"),
                                Err(_) => anyhow::anyhow!(
                                    "connect daemon control socket timed out after 3s"
                                ),
                                Ok(Ok(_)) => anyhow::anyhow!("unreachable control socket branch"),
                            });
                        }
                    }
                }
            }
        };

        // The synchronous pipe open blocks indefinitely when no server
        // instance is currently accepting. A single wedged open used to
        // freeze the whole status poll forever (buttons stuck disabled with
        // no hover) while one-shot calls kept working, so bound it: the
        // blocking open runs on the pool and gives up after 3 seconds.
        // Next poll retries; see the consecutive-failure backoff below.
        #[cfg(target_os = "windows")]
        let mut stream = {
            let pipe = kvm_protocol::control::windows_control_pipe();
            let opened = tokio::task::spawn_blocking(move || {
                tokio::net::windows::named_pipe::ClientOptions::new().open(&pipe)
            });
            match tokio::time::timeout(std::time::Duration::from_secs(3), opened).await {
                Ok(Ok(Ok(stream))) => stream,
                Ok(Ok(Err(error))) => {
                    return Err(anyhow::Error::new(error).context("connect daemon control pipe"));
                }
                Ok(Err(join_error)) => {
                    return Err(anyhow::anyhow!("control pipe opener failed: {join_error}"));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "control pipe open timed out after 3s (daemon not accepting)"
                    ));
                }
            }
        };

        #[cfg(not(any(unix, target_os = "windows")))]
        anyhow::bail!("local daemon control is not available on this operating system");

        write_request(&mut stream, &request).await?;
        read_response(&mut stream)
            .await?
            .context("daemon closed control connection")
    })
}

/// Preview-dial the peer with the USER identity (the identity the
/// controller session will use), returning its fingerprint, advertised
/// name, and the ceremony code. The receiver shows the identical code for
/// the dialing fingerprint because verification_code() is order
/// independent.
fn pair_prepare(
    address: &str,
    dir: &std::path::Path,
    node_name: &str,
    pairing_code: Option<String>,
) -> Result<PendingPair> {
    let identity = Identity::load_or_create(dir)?;
    let address = normalize_addr(address)?;
    let generation = PAIRING_GENERATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let runtime = runtime();
    runtime.block_on(async move {
        let endpoint = transport::make_client_endpoint(&identity)?;
        // Every network wait here is bounded. Unbounded waits used to leave
        // the UI stuck on "Contacting…" forever (blackholed UDP from a
        // wrong IP, AP isolation, or a firewall) with zero evidence about
        // which stage died. Now each stage fails loudly with its remedy.
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            endpoint.connect(address, "thekvm")?,
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "no answer from {address} after 10s — check the typed IP and that both computers share the same network"
            )
        })?
        .with_context(|| format!("connect to {address}"))?;
        let peer_fingerprint = peer_fingerprint(&conn)?;
        let (mut send, mut recv) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            conn.open_bi(),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{address} connected but opened no pairing stream (10s) — update TheKVM on both computers"
            )
        })?
        .with_context(|| format!("open pairing stream to {address}"))?;
        write_frame(
            &mut send,
            &WireMessage::PairRequest {
                node_name: node_name.to_owned(),
                fingerprint_hex: identity.fingerprint_hex(),
                pairing_code: pairing_code
                    .as_deref()
                    .map(str::trim)
                    .filter(|code| !code.is_empty())
                    .map(str::to_owned),
            },
        )
        .await?;
        let challenge = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            read_frame(&mut recv),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "{address} is not answering pairing (10s) — look at its app window for the incoming request"
            )
        })?
        .with_context(|| format!("read pairing answer from {address}"))?
        .context("peer closed pairing stream")?;
        let (peer_node_name, challenged_fingerprint, station_pre_approved) = match challenge {
            WireMessage::PairChallenge {
                node_name,
                fingerprint_hex,
                pre_approved,
                ..
            } => (node_name, fingerprint_hex, pre_approved),
            WireMessage::Reject { reason } => anyhow::bail!("peer rejected pairing: {reason}"),
            other => anyhow::bail!("unexpected pairing response: {other:?}"),
        };
        if challenged_fingerprint != peer_fingerprint {
            anyhow::bail!("peer fingerprint changed during pairing")
        }
        let verification_code =
            kvm_protocol::pairing::verification_code(&identity.fingerprint_hex(), &peer_fingerprint);
        let typed_code_sent =
            pairing_code.as_deref().is_some_and(|code| !code.trim().is_empty());
        if typed_code_sent {
            ui_log("pairing: typed station code sent with the request");
        }
        if station_pre_approved {
            ui_log("pairing: station pre-approved via typed code; no compare screen will show");
        }
        Ok(PendingPair {
            verification_code,
            peer_fingerprint,
            peer_node_name,
            address: address.to_string(),
            pairing: Some(PairingChannel {
                connection: conn,
                send,
                recv,
            }),
            generation,
            station_pre_approved,
            typed_code_sent,
        })
    })
}

/// Mirror UI choices into the USER config file so the supervised
/// controller session (which reads the user directory, not the privileged
/// daemon state) dials with the right name, mode, and capabilities.
/// Best effort: the daemon-side SetConfig result is authoritative for the
/// user-visible status.
fn mirror_user_config(
    device_name: &str,
    mode: Mode,
    allow_lock_screen: bool,
    clipboard_enabled: bool,
    layout: Option<kvm_core::Layout>,
) {
    let path = data_dir().join("config.json");
    let mut config = kvm_core::Config::load(&path).unwrap_or_default();
    if !device_name.trim().is_empty() {
        config.device_name = device_name.trim().to_owned();
    }
    config.mode = mode;
    config.allow_lock_screen_control = allow_lock_screen;
    config.clipboard_enabled = clipboard_enabled;
    config.auto_connect_address = None;
    // A supplied layout replaces the user's topology (arrangement UI,
    // auto-layout); omission preserves whatever is there so role presses
    // can never wipe the screen arrangement.
    if let Some(layout) = layout {
        config.layout = layout;
    }
    let _ = config.save(&path);
}

fn set_session(weak: &slint::Weak<AppWindow>, address: Option<String>) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                match address {
                    Some(address) => {
                        ui.set_session_active(true);
                        ui.set_session_text(SharedString::from(format!(
                            "Connected to {address}"
                        )));
                    }
                    None => {
                        ui.set_session_active(false);
                        ui.set_session_text(SharedString::from("Not connected"));
                    }
                }
            }
        }
    });
}

/// Plain-language edge direction for status text.
fn edge_name(edge: kvm_core::Edge) -> &'static str {
    match edge {
        kvm_core::Edge::Left => "left",
        kvm_core::Edge::Right => "right",
        kvm_core::Edge::Top => "top",
        kvm_core::Edge::Bottom => "bottom",
    }
}

/// Status sentence when edge control becomes ready, naming the actual exit
/// edge and peer from the live daemon config (this runs on a worker thread,
/// so a blocking control call is fine). Never claims an edge that isn't
/// arranged: without a layout it says exactly that.
fn edge_ready_text() -> String {
    match control_request(ControlRequest::GetConfig) {
        Ok(ControlResponse::Config(config)) => {
            let peer = config
                .layout
                .screens
                .iter()
                .find(|screen| screen.peer_fingerprint.is_some());
            let any_edge = config.layout.single_peer_screen().is_some();
            match (config.layout.peer_exit_edge(), peer) {
                (Some(edge), Some(screen)) if !any_edge => format!(
                    "Edge control is on — push past the {} edge to drive {}. Push back past the edge to return here.",
                    edge_name(edge),
                    screen.name
                ),
                (_, Some(screen)) => format!(
                    "Edge control is on — push past ANY edge to drive {}. Push back past any edge to return here.",
                    screen.name
                ),
                _ => "Edge control is on, but no linked screen is arranged yet — open Devices, place the other screen, and push past an edge.".into(),
            }
        }
        _ => "Edge control is on.".into(),
    }
}

fn set_driving(weak: &slint::Weak<AppWindow>, text: String) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_driving_text(SharedString::from(text));
            }
        }
    });
}

fn set_status(weak: &slint::Weak<AppWindow>, text: String) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_status_text(SharedString::from(text));
            }
        }
    });
}

fn set_pending(
    weak: &slint::Weak<AppWindow>,
    fingerprint: String,
    verification_code: String,
    peer_name: String,
) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_pending_peer_fingerprint(SharedString::from(fingerprint));
                ui.set_pending_verification_code(SharedString::from(verification_code));
                ui.set_pending_peer_name(SharedString::from(peer_name));
            }
        }
    });
}

fn set_discovery(weak: &slint::Weak<AppWindow>, text: String, address: Option<String>) {
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_discovery_text(SharedString::from(text));
                if let Some(address) = address {
                    ui.set_peer_address(SharedString::from(address));
                }
            }
        }
    });
}

fn data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("THEKVM_DATA_DIR") {
        return PathBuf::from(path);
    }
    kvm_core::Config::default_path().unwrap_or_else(|| PathBuf::from("."))
}

/// The UI keeps its temporary discovery identity in the logged-in user's
/// config directory, while the production daemon owns its privileged state in
/// /var/lib/thekvm. Allow a dedicated override for packaged deployments and
/// retain THEKVM_DATA_DIR for single-user development setups.
#[cfg(unix)]
fn control_data_dir() -> PathBuf {
    if let Ok(path) = std::env::var("THEKVM_CONTROL_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("THEKVM_DATA_DIR") {
        return PathBuf::from(path);
    }
    #[cfg(target_os = "linux")]
    return PathBuf::from("/var/lib/thekvm");
    #[cfg(target_os = "freebsd")]
    return PathBuf::from("/var/db/thekvm");
    #[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
    data_dir()
}

fn fallback_node_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "thekvm-ui".into())
}

fn normalize_addr(address: &str) -> Result<SocketAddr> {
    if let Ok(addr) = address.parse() {
        return Ok(addr);
    }
    let address = if address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:42110")
    };
    address
        .to_socket_addrs()?
        .next()
        .context("address resolved to nothing")
}

fn peer_fingerprint(conn: &quinn::Connection) -> Result<String> {
    let identity = conn.peer_identity().context("no peer certificate")?;
    let certs = identity
        .downcast::<Vec<rustls_pki_types::CertificateDer<'static>>>()
        .map_err(|_| anyhow::anyhow!("unexpected peer identity type"))?;
    let leaf = certs.first().context("empty cert chain")?;
    let mut hasher = Sha256::new();
    hasher.update(leaf.as_ref());
    let fingerprint: [u8; 32] = hasher.finalize().into();
    Ok(fingerprint
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::{edge_name, pair_status_text, should_auto_start_edge};

    #[test]
    fn compare_screen_names_peer_and_code() {
        let text = pair_status_text("mint", "862077", false);
        assert!(text.contains("mint"), "{text}");
        assert!(text.contains("862077"), "{text}");
        assert!(!text.contains("not accepted"), "{text}");
    }

    #[test]
    fn rejected_typed_code_says_so_instead_of_implying_a_popup() {
        let text = pair_status_text("mint", "862077", true);
        assert!(text.contains("not accepted"), "{text}");
        assert!(text.contains("862077"), "{text}");
    }

    #[test]
    fn edge_names_are_plain_words() {
        assert_eq!(edge_name(kvm_core::Edge::Left), "left");
        assert_eq!(edge_name(kvm_core::Edge::Right), "right");
        assert_eq!(edge_name(kvm_core::Edge::Top), "top");
        assert_eq!(edge_name(kvm_core::Edge::Bottom), "bottom");
    }

    #[test]
    fn edge_is_always_on_unless_driving_is_forbidden_or_busy() {
        use kvm_core::Mode::{Bidirectional, ClientOnly, ServerClient};
        // May drive + idle + no ceremony: start.
        assert!(should_auto_start_edge(Bidirectional, false, false));
        assert!(should_auto_start_edge(ServerClient, false, false));
        // Receiver-only must never drive.
        assert!(!should_auto_start_edge(ClientOnly, false, false));
        // A running session (takeover or edge) is never disturbed.
        assert!(!should_auto_start_edge(Bidirectional, true, false));
        assert!(!should_auto_start_edge(ServerClient, true, false));
        // An open pairing ceremony is never hijacked.
        assert!(!should_auto_start_edge(Bidirectional, false, true));
        assert!(!should_auto_start_edge(ClientOnly, true, true));
    }

    #[test]
    fn layout_side_reports_peer_position() {
        let fp = "ee".repeat(32);
        let layout = kvm_core::Layout::pair_default("me", "peer", &fp);
        assert_eq!(layout.side_of_peer(&fp), Some(kvm_core::Edge::Right));
        assert_eq!(layout.side_of_peer(&"ff".repeat(32)), None);
        let mirror = kvm_core::Layout::pair_mirror("me", "peer", &fp);
        assert_eq!(mirror.side_of_peer(&fp), Some(kvm_core::Edge::Left));
        let empty = kvm_core::Layout::default();
        assert_eq!(empty.side_of_peer(&fp), None);
    }

    #[test]
    fn migrate_020_mirror_rewrites_ids_only() {
        let fp = "ee".repeat(32);
        // 0.2.0 wrote the mirror with self=1: rebuild that exact shape.
        let old = kvm_core::Layout {
            screens: vec![
                kvm_core::Screen {
                    id: kvm_core::SELF_SCREEN_ID,
                    name: "me".into(),
                    x: 0,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    peer_fingerprint: None,
                },
                kvm_core::Screen {
                    id: kvm_core::FIRST_PEER_SCREEN_ID,
                    name: "peer".into(),
                    x: -1,
                    y: 0,
                    width: 1920,
                    height: 1080,
                    peer_fingerprint: Some(fp.clone()),
                },
            ],
            self_screen: Some(kvm_core::SELF_SCREEN_ID),
        };
        let fixed = super::migrate_020_mirror(&old).expect("exact 0.2.0 shape must migrate");
        assert_eq!(fixed.self_screen, Some(kvm_core::MIRROR_SELF_SCREEN_ID));
        assert_eq!(fixed.side_of_peer(&fp), Some(kvm_core::Edge::Left));
        assert_eq!(fixed.validate(), Ok(()));
        // Anything else is left alone: fresh defaults, empty, multi-screen.
        assert!(super::migrate_020_mirror(
            &kvm_core::Layout::pair_default("me", "peer", &fp)
        )
        .is_none());
        assert!(super::migrate_020_mirror(&kvm_core::Layout::default()).is_none());
    }
}

