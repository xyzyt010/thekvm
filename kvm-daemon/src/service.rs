//! Daemon main loop, pairing flow, and test client.

use anyhow::{bail, Context, Result};
use kvm_core::{
    Config, EdgeRouter, HidUsage, InputEvent, InputPacket, InputState, Mode, MouseButton,
    RoutedEvent, ScreenId, WheelDelta,
};
use kvm_platform::inject::Injector;
use kvm_protocol::pairing::{Identity, PeerBook};
use kvm_protocol::transport;
use kvm_protocol::wire::{
    decode_input_datagram, encode_input_datagram, read_frame, write_frame, DatagramInput, Hello,
    ScreenGeometry, WireMessage,
};
use kvm_protocol::DEFAULT_PORT;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use crate::windows_helper::{ServiceCaptureProxy, ServiceInputProxy};

static SHUTDOWN: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();

pub(crate) fn shutdown_notifier() -> &'static tokio::sync::Notify {
    SHUTDOWN.get_or_init(tokio::sync::Notify::new)
}

/// One live INBOUND input session: a verified peer drives this machine right
/// now. The station-side desktop UI watches this registry (via Status) to
/// arm its own half of a link it never dialed — MWB arming — and to hang
/// the link up again. Keyed by peer fingerprint; the id guards removal so a
/// dying task can never unregister its own successor's fresh session.
#[derive(Debug, Clone)]
pub(crate) struct InboundLink {
    pub id: u64,
    pub fingerprint_hex: String,
    pub node_name: String,
    pub address: String,
    /// Administrative epoch from the dialer's Hello (None for older peers).
    pub link_id: Option<u64>,
}

type LinkRegistry = Arc<std::sync::Mutex<HashMap<String, (InboundLink, tokio::sync::watch::Sender<bool>)>>>;

static INBOUND_LINKS: std::sync::OnceLock<LinkRegistry> = std::sync::OnceLock::new();
static LINK_IDS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn inbound_link_registry() -> LinkRegistry {
    INBOUND_LINKS
        .get_or_init(|| Arc::new(std::sync::Mutex::new(HashMap::new())))
        .clone()
}

/// Record a verified inbound session; returns its registration id and a
/// drop-watch the serve loop selects on. Replaces any stale entry for the
/// same peer (the old task is already gone — only one input session holds
/// the slot at a time).
pub(crate) fn register_inbound_link(
    fingerprint_hex: &str,
    node_name: &str,
    address: &str,
    link_id: Option<u64>,
) -> (u64, tokio::sync::watch::Receiver<bool>) {
    let id = LINK_IDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (drop_tx, drop_rx) = tokio::sync::watch::channel(false);
    if let Ok(mut links) = inbound_link_registry().lock() {
        links.insert(
            fingerprint_hex.to_owned(),
            (
                InboundLink {
                    id,
                    fingerprint_hex: fingerprint_hex.to_owned(),
                    node_name: node_name.to_owned(),
                    address: address.to_owned(),
                    link_id,
                },
                drop_tx,
            ),
        );
    }
    (id, drop_rx)
}

/// Remove a registration, but only when the id still matches — a redialed
/// successor must survive its predecessor's cleanup.
pub(crate) fn remove_inbound_link(fingerprint_hex: &str, id: u64) {
    if let Ok(mut links) = inbound_link_registry().lock() {
        if links
            .get(fingerprint_hex)
            .is_some_and(|(link, _)| link.id == id)
        {
            links.remove(fingerprint_hex);
        }
    }
}

/// Ask the serve loop of one inbound session to end (station hang-up). The
/// dialer's side sees the closed connection and tears down with it, so one
/// Disconnect ends the whole link. Trust is untouched.
pub(crate) fn drop_inbound_link(fingerprint_hex: &str) -> bool {
    if let Ok(links) = inbound_link_registry().lock() {
        if let Some((_, drop_tx)) = links.get(fingerprint_hex) {
            return drop_tx.send(true).is_ok();
        }
    }
    false
}

pub(crate) fn list_inbound_links() -> Vec<kvm_protocol::control::ActiveSession> {
    if let Ok(links) = inbound_link_registry().lock() {
        links
            .values()
            .map(|(link, _)| kvm_protocol::control::ActiveSession {
                fingerprint_hex: link.fingerprint_hex.clone(),
                node_name: link.node_name.clone(),
                address: link.address.clone(),
                link_id: link.link_id,
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// Panic-safe inbound registration: dropping the guard unregisters, so even
/// a panicking session task can never leave a ghost entry behind. A ghost
/// fools the station UI into dialling a dead link (and showing it) forever.
struct InboundLinkGuard {
    fingerprint_hex: String,
    id: u64,
}

impl Drop for InboundLinkGuard {
    fn drop(&mut self) {
        remove_inbound_link(&self.fingerprint_hex, self.id);
    }
}

/// Link epochs the local user ended via Disconnect. A dial carrying a
/// banned epoch is rejected instead of served, so a stale redial can never
/// resurrect a dead link as a zombie. Bounded: past 32 the set resets (a
/// fresh Connect always mints a fresh epoch, so old bans are worthless).
static ENDED_LINKS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<u64>>> =
    std::sync::OnceLock::new();

fn ended_link_ids() -> &'static std::sync::Mutex<std::collections::HashSet<u64>> {
    ENDED_LINKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

pub(crate) fn end_link(link_id: u64) {
    if let Ok(mut ended) = ended_link_ids().lock() {
        if ended.len() >= 32 {
            ended.clear();
        }
        ended.insert(link_id);
    }
}

fn link_ended(link_id: u64) -> bool {
    ended_link_ids()
        .lock()
        .ok()
        .is_some_and(|ended| ended.contains(&link_id))
}

/// True when the dial failed because the peer deliberately ended this link
/// epoch (Disconnect there). Callers exit instead of retrying: a banned
/// link must stay dead. Matches only our own ban wording (lowercase), never
/// the UI's display texts.
fn is_link_ended_rejection(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("link ended"))
}

/// Shared ban-exit status line: `THEKVM_STATUS ended ban <epoch>` so the
/// supervising UI can tell a deliberate remote Disconnect (auto-redial on
/// the peer's fresh epoch) from a crash (report, stay down).
fn ban_ended_status(link_id: Option<u64>) -> String {
    match link_id {
        Some(id) => format!("ended ban {id} (link ended by the other side)"),
        None => "ended ban none (link ended by the other side)".to_owned(),
    }
}

/// Wait for a process-level stop request when the daemon is running outside a
/// service manager. Windows SCM shutdown is delivered through
/// `shutdown_notifier`; Ctrl+C remains useful for foreground development, and
/// Unix SIGTERM is the normal systemd stop path.
async fn process_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGINT handler");
                std::future::pending::<()>().await;
                return;
            }
        };
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::warn!(%error, "cannot install SIGTERM handler");
                std::future::pending::<()>().await;
                return;
            }
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }

    #[cfg(windows)]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "cannot install Ctrl+C handler");
            std::future::pending::<()>().await;
        }
    }

    #[cfg(not(any(unix, windows)))]
    std::future::pending::<()>().await;
}

/// Privileged system state directory, ignoring any THEKVM_DATA_DIR override.
/// Supervised user-session children run with the override pointing at the
/// user directory; station-side edge mode needs to ALSO read the system
/// identity and peer book (same machine, desktop user in the service
/// group), so both paths are available side by side.
fn system_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    return std::env::var("PROGRAMDATA")
        .map(|p| std::path::PathBuf::from(p).join("TheKVM"))
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    #[cfg(target_os = "freebsd")]
    return std::path::PathBuf::from("/var/db/thekvm");
    #[cfg(all(not(target_os = "windows"), not(target_os = "freebsd")))]
    return std::path::PathBuf::from("/var/lib/thekvm");
}

fn data_dir() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("THEKVM_DATA_DIR") {
        return std::path::PathBuf::from(path);
    }
    system_data_dir()
}

/// Record security-relevant session boundaries without recording input data.
/// The file lives beside the daemon identity and peer book so a system service
/// can retain a local trail even when its stderr is not collected by the init
/// system. Failure to write an audit record must not take down the input
/// service, but is surfaced through tracing.
pub(crate) fn audit_event(dir: &std::path::Path, event: &str) {
    let path = dir.join("audit.log");
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true).write(true);
        let mut file = options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let safe_event = event.replace(['\r', '\n'], " ");
        writeln!(file, "{timestamp}\t{safe_event}")?;
        file.flush()
    })();
    if let Err(error) = result {
        tracing::warn!(path = %path.display(), %error, "cannot write TheKVM audit record");
    }
}

/// Append a control-endpoint lifecycle line beside the daemon state. A
/// system service has no visible stderr, so without this file a dead
/// control pipe is invisible from the outside: the UI poll just fails
/// forever and its buttons stay dark with no reason anywhere. This file
/// names the failure (or proves the endpoint is up).
pub(crate) fn control_lifecycle_log(dir: &std::path::Path, event: &str) {
    let path = dir.join("control.log");
    let result = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut options = std::fs::OpenOptions::new();
        options.create(true).append(true).write(true);
        let mut file = options.open(&path)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let safe_event = event.replace(['\r', '\n'], " ");
        writeln!(file, "{timestamp}\t{safe_event}")?;
        file.flush()
    })();
    if let Err(error) = result {
        tracing::warn!(path = %path.display(), %error, "cannot write TheKVM control log");
    }
}

fn load_local_config() -> Result<Config> {
    let path = data_dir().join("config.json");
    if path.exists() {
        Config::load(&path).with_context(|| format!("loading config from {}", path.display()))
    } else {
        Ok(Config::default())
    }
}

pub fn print_fingerprint() -> Result<()> {
    let identity = Identity::load_or_create(&data_dir())?;
    println!("{}", identity.fingerprint_hex());
    Ok(())
}

/// Print this machine's pairing invite: a `thekvm://` URL carrying the LAN
/// address and certificate fingerprint. The operator reads it aloud, sends
/// it, or scans the QR the UI renders from this same value; the other side
/// passes it to `pair` so the peer address never needs typing and the
/// certificate fingerprint is pinned from the start.
pub fn print_invite() -> Result<()> {
    let dir = data_dir();
    let config = load_local_config()?;
    let identity = Identity::load_or_create(&dir)?;
    let address = match kvm_protocol::invite::lan_address() {
        Some(addr) => format!("{addr}:{}", config.listen_port),
        None => {
            eprintln!("warning: no LAN address detected; share the fingerprint instead");
            String::new()
        }
    };
    println!(
        "{}",
        kvm_protocol::invite::build(&address, &identity.fingerprint_hex())?
    );
    Ok(())
}

/// Replace the local certificate/key identity while the daemon is offline.
/// Peers that accept this node must be paired again after the fingerprint
/// changes; peer records are retained because the remote identities remain
/// valid for outbound sessions.
pub async fn rotate_identity(confirmed: bool) -> Result<()> {
    if !confirmed {
        bail!(
            "identity rotation changes the certificate fingerprint; rerun with --yes after stopping the daemon"
        );
    }
    let dir = data_dir();
    if !dir.join("identity.cert").exists() || !dir.join("identity.key").exists() {
        bail!(
            "no existing identity found in {}; use fingerprint first",
            dir.display()
        );
    }
    if crate::control::request(dir.clone(), kvm_protocol::control::ControlRequest::Status)
        .await
        .is_ok()
    {
        bail!("stop the running daemon before rotating its identity");
    }
    let old = Identity::load_or_create(&dir)?;
    let rotated = Identity::rotate(&dir)?;
    println!("identity rotated");
    println!("old fingerprint: {}", old.fingerprint_hex());
    println!("new fingerprint: {}", rotated.fingerprint_hex());
    println!("re-pair peers that accept this machine before reconnecting");
    Ok(())
}

pub fn list_peers() -> Result<()> {
    let peers = PeerBook::load_or_create(&data_dir())?;
    if peers.peers.is_empty() {
        println!("no paired peers");
        return Ok(());
    }
    for peer in peers.peers {
        println!(
            "{}\t{}\t{}",
            peer.name,
            peer.fingerprint_hex,
            peer.address.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

/// Find receiver metadata on the local IPv4 LAN. Discovery is only a
/// convenience for the pairing UI/CLI; the returned fingerprint must still
/// be confirmed through the authenticated QUIC pairing exchange.
pub async fn discover(timeout_ms: u64) -> Result<()> {
    let peers = kvm_protocol::discovery::scan(Duration::from_millis(timeout_ms.max(1)))
        .await
        .context("scan local LAN")?;
    for (address, advertisement) in &peers {
        println!(
            "{}\t{}:{}\t{}",
            advertisement.node_name,
            address.ip(),
            address.port(),
            advertisement.fingerprint_hex
        );
    }
    if peers.is_empty() {
        println!("no TheKVM receivers discovered");
    }
    Ok(())
}

pub async fn unpair(fingerprint: &str) -> Result<()> {
    if !valid_fingerprint(fingerprint) {
        bail!("peer fingerprint must contain 64 hexadecimal characters");
    }
    let fingerprint = fingerprint.to_ascii_lowercase();

    // Prefer the running daemon so its in-memory authorization state is
    // revoked immediately and active sessions receive the cancellation
    // broadcast. Fall back to the state file for an offline daemon.
    match crate::control::request(
        data_dir(),
        kvm_protocol::control::ControlRequest::Unpair {
            fingerprint_hex: fingerprint.clone(),
        },
    )
    .await
    {
        Ok(kvm_protocol::control::ControlResponse::Unpaired { .. }) => {
            println!("revoked {fingerprint}");
            return Ok(());
        }
        Ok(kvm_protocol::control::ControlResponse::Error { message }) => bail!("{message}"),
        Ok(other) => bail!("unexpected daemon revoke response: {other:?}"),
        Err(_) => {}
    }

    let mut peers = PeerBook::load_or_create(&data_dir())?;
    if peers.unpin(&fingerprint)? {
        println!("revoked {fingerprint}");
    } else {
        println!("peer fingerprint was not paired: {fingerprint}");
    }
    Ok(())
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Pin a peer into the running daemon's peer book, mirroring trust the
/// local user established elsewhere (the desktop UI code ceremony). Falls
/// back to the state file when the daemon is offline.
pub async fn pin_peer(
    fingerprint: &str,
    name: Option<&str>,
    address: Option<&str>,
) -> Result<()> {
    if !valid_fingerprint(fingerprint) {
        bail!("peer fingerprint must contain 64 hexadecimal characters");
    }
    let fingerprint_hex = fingerprint.to_ascii_lowercase();
    let clean_name = name.filter(|name| !name.trim().is_empty());
    let clean_address = address.filter(|address| !address.trim().is_empty());
    match crate::control::request(
        data_dir(),
        kvm_protocol::control::ControlRequest::PinPeer {
            fingerprint_hex: fingerprint_hex.clone(),
            node_name: clean_name.map(str::to_owned),
            address: clean_address.map(str::to_owned),
        },
    )
    .await
    {
        Ok(kvm_protocol::control::ControlResponse::Pinned { .. }) => {
            println!("pinned {fingerprint_hex}");
            return Ok(());
        }
        Ok(kvm_protocol::control::ControlResponse::Error { message }) => bail!("{message}"),
        Ok(other) => bail!("unexpected daemon pin response: {other:?}"),
        Err(_) => {}
    }

    let mut peers = PeerBook::load_or_create(&data_dir())?;
    peers.pin_with_address(
        clean_name.unwrap_or(&format!("peer-{}", &fingerprint_hex[..8])),
        fingerprint_hex.clone(),
        clean_address.map(str::to_owned),
    )?;
    println!("pinned {fingerprint_hex}");
    Ok(())
}

pub async fn status() -> Result<()> {
    match crate::control::request(data_dir(), kvm_protocol::control::ControlRequest::Status).await?
    {
        kvm_protocol::control::ControlResponse::Status(status) => {
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        other => bail!("unexpected daemon status response: {other:?}"),
    }
}

/// List pairing requests that have completed the authenticated network
/// exchange and are waiting for this machine's local approval.
pub async fn pending_pairings() -> Result<()> {
    match crate::control::request(
        data_dir(),
        kvm_protocol::control::ControlRequest::ListPendingPairings,
    )
    .await?
    {
        kvm_protocol::control::ControlResponse::PendingPairings(pairings) => {
            println!("{}", serde_json::to_string_pretty(&pairings)?);
            Ok(())
        }
        other => bail!("unexpected pending-pairings response: {other:?}"),
    }
}

/// Approve or reject one incoming pairing request in the running daemon.
pub async fn decide_pairing(fingerprint: &str, approved: bool) -> Result<()> {
    if !valid_fingerprint(fingerprint) {
        bail!("peer fingerprint must contain 64 hexadecimal characters");
    }
    let fingerprint_hex = fingerprint.to_ascii_lowercase();
    let request = if approved {
        kvm_protocol::control::ControlRequest::ApprovePairing {
            fingerprint_hex: fingerprint_hex.clone(),
        }
    } else {
        kvm_protocol::control::ControlRequest::RejectPairing {
            fingerprint_hex: fingerprint_hex.clone(),
        }
    };
    match crate::control::request(data_dir(), request).await? {
        kvm_protocol::control::ControlResponse::PairingApproved { .. } if approved => {
            println!("approved pending pairing {fingerprint_hex}");
            Ok(())
        }
        kvm_protocol::control::ControlResponse::PairingRejected { .. } if !approved => {
            println!("rejected pending pairing {fingerprint_hex}");
            Ok(())
        }
        kvm_protocol::control::ControlResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected pairing decision response: {other:?}"),
    }
}

/// Print read-only platform and desktop-session capability checks.
pub fn doctor() -> Result<()> {
    println!("TheKVM platform diagnostics");
    for check in kvm_platform::diagnostics::checks() {
        println!(
            "[{}] {:<24} {}",
            if check.available { "ok" } else { "missing" },
            check.name,
            check.detail
        );
    }
    Ok(())
}

pub(crate) struct ConfigureOptions<'a> {
    pub(crate) device_name: Option<&'a str>,
    pub(crate) mode: Option<&'a str>,
    pub(crate) allow_lock_screen_control: Option<bool>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) layout_path: Option<&'a std::path::Path>,
    pub(crate) auto_connect_address: Option<&'a str>,
    pub(crate) clear_auto_connect: bool,
    pub(crate) clipboard_enabled: Option<bool>,
}

pub async fn configure(options: ConfigureOptions<'_>) -> Result<()> {
    let ConfigureOptions {
        device_name,
        mode,
        allow_lock_screen_control,
        listen_port,
        layout_path,
        auto_connect_address,
        clear_auto_connect,
        clipboard_enabled,
    } = options;
    let requested_mode = mode
        .map(|mode| match mode.to_ascii_lowercase().as_str() {
            "bidirectional" | "bi" => Ok(Mode::Bidirectional),
            "server-client" | "server_client" | "server" => Ok(Mode::ServerClient),
            "receiver-only" | "receiver_only" | "client-only" | "client_only" | "client" => {
                Ok(Mode::ClientOnly)
            }
            _ => Err(anyhow::anyhow!(
                "invalid mode {mode}; use bidirectional, server-client, or receiver-only"
            )),
        })
        .transpose()?;
    let dir = data_dir();
    let requested_layout = layout_path
        .map(|path| {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading layout {}", path.display()))?;
            serde_json::from_str::<kvm_core::Layout>(&raw)
                .with_context(|| format!("decoding layout {}", path.display()))
        })
        .transpose()?;
    if clear_auto_connect && auto_connect_address.is_some() {
        bail!("auto-connect address cannot be set and cleared together");
    }
    if auto_connect_address.is_some_and(|address| address.trim().is_empty()) {
        bail!("auto-connect address cannot be empty");
    }

    // Prefer the running daemon so its in-memory policy changes together with
    // its persisted config. This is also what the UI uses through its CLI
    // fallback when a direct control connection was unavailable.
    match crate::control::request(
        dir.clone(),
        kvm_protocol::control::ControlRequest::SetConfig {
            device_name: device_name.map(str::to_owned),
            mode: requested_mode,
            allow_lock_screen_control,
            listen_port,
            layout: requested_layout.clone(),
            auto_connect_address: auto_connect_address.map(|address| address.trim().to_owned()),
            clear_auto_connect,
            clipboard_enabled,
            edge_mode: None,
        },
    )
    .await
    {
        Ok(kvm_protocol::control::ControlResponse::Applied { .. }) => {
            println!("configuration applied to running daemon");
            return Ok(());
        }
        Ok(kvm_protocol::control::ControlResponse::Error { message }) => bail!("{message}"),
        Ok(other) => bail!("unexpected daemon configuration response: {other:?}"),
        Err(_) => {}
    }

    let path = dir.join("config.json");
    let mut config = if path.exists() {
        Config::load(&path).context("loading config")?
    } else {
        Config::default()
    };
    let previous_mode = config.mode;
    let previous_name = config.device_name.clone();
    if let Some(mode) = requested_mode {
        config.mode = mode;
    }
    if let Some(device_name) = device_name {
        config.device_name = device_name.trim().to_owned();
    }
    if let Some(allow_lock_screen_control) = allow_lock_screen_control {
        config.allow_lock_screen_control = allow_lock_screen_control;
    }
    if let Some(port) = listen_port {
        if port == 0 {
            bail!("listen port must be non-zero");
        }
        config.listen_port = port;
    }
    if let Some(layout) = requested_layout {
        config.layout = layout;
    }
    if clear_auto_connect {
        config.auto_connect_address = None;
    } else if let Some(address) = auto_connect_address {
        config.auto_connect_address = Some(address.trim().to_owned());
    }
    if let Some(enabled) = clipboard_enabled {
        config.clipboard_enabled = enabled;
    }
    config.save(&path).context("saving config")?;
    if config.mode != previous_mode {
        audit_event(
            &dir,
            &format!("mode {previous_mode:?} -> {:?} via CLI file write", config.mode),
        );
    }
    if config.device_name != previous_name {
        audit_event(
            &dir,
            &format!("device renamed {previous_name:?} -> {:?} via CLI file write", config.device_name),
        );
    }
    println!("saved {}", path.display());
    Ok(())
}

/// Pair with a peer using an explicit human confirmation of its fingerprint.
///
/// `address` accepts either a plain `ip:port` or a `thekvm://` invite. An
/// invite additionally pins the expected certificate fingerprint before any
/// trust is written, so a scanner/transcription error fails loudly instead
/// of pinning the wrong machine.
pub async fn pair(address: &str) -> Result<()> {
    let dir = data_dir();
    let config = load_local_config()?;
    let identity = Identity::load_or_create(&dir)?;
    let mut peers = PeerBook::load_or_create(&dir)?;
    let (target, invited_fingerprint) = match kvm_protocol::invite::parse(address) {
        Ok((invited_address, fingerprint)) if !invited_address.is_empty() => {
            (invited_address, Some(fingerprint))
        }
        Ok(_) => bail!("invite carries no address; enter the peer's LAN IP manually"),
        _ => (address.to_owned(), None),
    };
    let url = normalize_addr(&target)?;

    tracing::info!(peer = %url, local_fingerprint = %identity.fingerprint_hex(), "pairing");
    let endpoint = transport::make_client_endpoint(&identity)?;
    let conn = endpoint
        .connect(url, "thekvm")
        .context("connect")?
        .await
        .context("handshake")?;
    let remote_fingerprint = peer_fingerprint(&conn)?;
    if let Some(expected) = invited_fingerprint {
        if remote_fingerprint != expected {
            audit_event(
                &dir,
                &format!(
                    "pairing-invite-mismatch expected={expected} observed={remote_fingerprint} remote={url}"
                ),
            );
            bail!("peer's certificate does not match the invite fingerprint");
        }
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &WireMessage::PairRequest {
            node_name: local_node_name(&config),
            fingerprint_hex: identity.fingerprint_hex(),
            pairing_code: None,
        },
    )
    .await?;

    let challenge = read_frame(&mut recv)
        .await?
        .context("peer closed pairing stream")?;
    let (peer_name, challenged_fingerprint, challenged_code) = match challenge {
        WireMessage::PairChallenge {
            node_name,
            fingerprint_hex,
            verification_code,
            ..
        } => (node_name, fingerprint_hex, verification_code),
        WireMessage::Reject { reason } => bail!("peer rejected pairing: {reason}"),
        other => bail!("unexpected pairing response: {other:?}"),
    };
    if challenged_fingerprint != remote_fingerprint {
        bail!("peer fingerprint changed during pairing");
    }
    let local_fingerprint = identity.fingerprint_hex();
    let local_code =
        kvm_protocol::pairing::verification_code(&local_fingerprint, &remote_fingerprint);
    if let Some(challenged_code) = challenged_code {
        if challenged_code != local_code {
            audit_event(
                &data_dir(),
                &format!(
                    "pairing-verification-mismatch peer={remote_fingerprint} remote={}",
                    conn.remote_address()
                ),
            );
            bail!("peer's pairing verification code does not match this machine's derivation; the connection may be relayed");
        }
    }

    println!("Peer: {peer_name}");
    println!("Peer fingerprint: {remote_fingerprint}");
    println!("Pairing verification code: {local_code}");
    println!("Compare this code with the one shown on the other machine; they must be identical.");
    if !confirm_pairing()? {
        bail!("pairing cancelled");
    }

    write_frame(
        &mut send,
        &WireMessage::PairConfirm {
            server_fingerprint_hex: remote_fingerprint.clone(),
        },
    )
    .await?;
    match read_frame(&mut recv)
        .await?
        .context("peer closed pairing stream")?
    {
        WireMessage::Accepted { .. } => {
            peers.pin_with_address(peer_name, remote_fingerprint.clone(), Some(url.to_string()))?;
            println!("paired: {remote_fingerprint}");
            Ok(())
        }
        WireMessage::Reject { reason } => bail!("peer rejected pairing: {reason}"),
        other => bail!("unexpected pairing completion: {other:?}"),
    }
}

/// Complete a pairing ceremony on behalf of the logged-in UI. The UI has
/// already shown the certificate fingerprint and obtained explicit user
/// confirmation; the daemon repeats the network exchange with the daemon's
/// own identity so subsequent capture sessions are authorized correctly.
pub async fn pair_for_daemon(
    address: &str,
    expected_fingerprint: &str,
    peers: Arc<tokio::sync::RwLock<PeerBook>>,
) -> Result<String> {
    let dir = data_dir();
    let config = load_local_config()?;
    let identity = Identity::load_or_create(&dir)?;
    let url = normalize_addr(address)?;
    let endpoint = transport::make_client_endpoint(&identity)?;
    let conn = endpoint.connect(url, "thekvm").context("connect")?.await?;
    let remote_fingerprint = peer_fingerprint(&conn)?;
    if remote_fingerprint != expected_fingerprint {
        bail!("peer fingerprint changed before daemon pairing");
    }

    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &WireMessage::PairRequest {
            node_name: local_node_name(&config),
            fingerprint_hex: identity.fingerprint_hex(),
            pairing_code: None,
        },
    )
    .await?;
    let challenge = read_frame(&mut recv)
        .await?
        .context("peer closed pairing stream")?;
    let peer_name = match challenge {
        WireMessage::PairChallenge {
            node_name,
            fingerprint_hex,
            verification_code,
            ..
        } if fingerprint_hex == remote_fingerprint => {
            let local_fingerprint = identity.fingerprint_hex();
            let expected =
                kvm_protocol::pairing::verification_code(&local_fingerprint, &remote_fingerprint);
            if let Some(code) = verification_code {
                if code != expected {
                    audit_event(
                        &data_dir(),
                        &format!(
                            "pairing-verification-mismatch peer={remote_fingerprint} remote={}",
                            conn.remote_address()
                        ),
                    );
                    bail!("peer's pairing verification code does not match this machine's derivation; the connection may be relayed");
                }
            }
            node_name
        }
        WireMessage::Reject { reason } => bail!("peer rejected pairing: {reason}"),
        other => bail!("unexpected pairing response: {other:?}"),
    };
    write_frame(
        &mut send,
        &WireMessage::PairConfirm {
            server_fingerprint_hex: remote_fingerprint.clone(),
        },
    )
    .await?;
    match read_frame(&mut recv)
        .await?
        .context("peer closed pairing stream")?
    {
        WireMessage::Accepted { .. } => {
            peers.write().await.pin_with_address(
                peer_name,
                remote_fingerprint.clone(),
                Some(url.to_string()),
            )?;
            Ok(remote_fingerprint)
        }
        WireMessage::Reject { reason } => bail!("peer rejected pairing: {reason}"),
        other => bail!("unexpected pairing completion: {other:?}"),
    }
}

/// Test client: send a complete key press/release sequence.
pub async fn send_test(address: &str, usage: u16) -> Result<()> {
    let config = load_local_config()?;
    let identity = Identity::load_or_create(&data_dir())?;
    let peers = PeerBook::load_or_create(&data_dir())?;
    let (_conn, mut send, _recv, _capabilities) = connect_input(
        &identity,
        &peers,
        address,
        ConnectPolicy {
            node_name: &config.device_name,
            request_lock_screen: config.allow_lock_screen_control,
            mode: config.mode,
            clipboard_enabled: false,
            screen_geometry: local_screen_geometry(&config.layout),
            link_id: None,
        },
        None,
    )
    .await?;
    write_frame(
        &mut send,
        &WireMessage::Input(InputPacket {
            sequence: 1,
            event: InputEvent::Key(kvm_core::KeyEvent {
                usage,
                pressed: true,
            }),
        }),
    )
    .await?;
    write_frame(
        &mut send,
        &WireMessage::Input(InputPacket {
            sequence: 2,
            event: InputEvent::Key(kvm_core::KeyEvent {
                usage,
                pressed: false,
            }),
        }),
    )
    .await?;
    write_frame(&mut send, &WireMessage::ReleaseAll).await?;
    send.finish()?;
    tracing::info!(peer = %address, usage, "sent key press/release");
    Ok(())
}

/// Capture physical input and stream it to a paired peer.
pub async fn capture(address: &str) -> Result<()> {
    let config = load_local_config()?;
    let identity = Identity::load_or_create(&data_dir())?;
    let peers = PeerBook::load_or_create(&data_dir())?;
    // Do not grab physical devices until the peer has completed the
    // authenticated session handshake. A failed connection must never leave
    // the local desktop temporarily without its keyboard or mouse.
    let (mut priority_rx, mut motion_rx, capture_control) = start_capture(false, false)?;
    let (conn, mut send, recv, capabilities) = dial_session(
        &identity,
        &peers,
        address,
        ConnectPolicy {
            node_name: &config.device_name,
            request_lock_screen: config.allow_lock_screen_control,
            mode: config.mode,
            clipboard_enabled: config.clipboard_enabled,
            screen_geometry: local_screen_geometry(&config.layout),
            link_id: None,
        },
        None,
        &data_dir(),
    )
    .await?;
    let clipboard_enabled = capabilities.clipboard_enabled;
    let mut clipboard = start_clipboard_agent(clipboard_enabled);
    let mut clipboard_revision = 0;
    let snapshot = capture_control.snapshot();
    send_state_sync(&mut send, snapshot.state).await?;
    capture_control.set_exclusive(true)?;
    let result = run_capture_stream(
        conn,
        send,
        recv,
        &mut priority_rx,
        &mut motion_rx,
        snapshot.last_event_id,
        &mut clipboard,
        clipboard_enabled,
        &mut clipboard_revision,
        capabilities.smooth_scroll,
    )
    .await;
    // Keep local input usable after Ctrl+C, peer loss, or any protocol error.
    release_suppression(&capture_control, None);
    result
}

/// Capture physical input while retrying the QUIC session until Ctrl+C. This
/// is the command intended for a user-session startup entry on the controller
/// machine; the target daemon may boot earlier, reboot independently, or be
/// temporarily absent from the LAN.
///
/// MWB node semantics: the upfront dial proves reachability and mutual trust
/// (the status only claims `established` after the handshake accepts), then
/// the child routes topologically — local input stays local until a screen
/// edge is crossed, and crossings drive the linked peer. Nothing ever
/// freezes: both computers stay usable, both directions, one shared cursor
/// each way. Drive episodes dial fresh per crossing over the verified link.
///
/// `link_id` is the administrative epoch both sides share (minted by the UI
/// that the user pressed Connect on; the station side dials back with the
/// same value). A rejection naming a banned epoch ends the child instead of
/// retrying: the other side ended the link on purpose.
/// Read the daemon-owned identity the supervising UI pipes on stdin with
/// `--identity-stdin`: two hex lines (certificate DER, then key DER).
/// Blocking I/O runs off the async runtime; a 15s cap keeps a forgotten
/// pipe from hanging the child forever instead of failing loudly.
async fn read_identity_stdin() -> Result<Identity> {
    let material = tokio::task::spawn_blocking(|| {
        use std::io::Read as _;
        let mut text = String::new();
        std::io::stdin().read_to_string(&mut text).map(|_| text)
    });
    let text = tokio::time::timeout(Duration::from_secs(15), material)
        .await
        .context("identity stdin read timed out (UI must pipe two hex lines)")?
        .context("identity stdin read failed")??;
    let mut lines = text.lines();
    let cert_der = kvm_protocol::pairing::hex_decode(lines.next().unwrap_or_default())
        .context("decode daemon identity certificate")?;
    let key_der = kvm_protocol::pairing::hex_decode(lines.next().unwrap_or_default())
        .context("decode daemon identity key")?;
    Identity::from_der(cert_der, key_der).context("adopt daemon identity")
}

pub async fn connect(
    address: Option<&str>,
    link_id: Option<u64>,
    identity_stdin: bool,
) -> Result<()> {
    let Some(address) = address else {
        let identity = Identity::load_or_create(&data_dir())?;
        return connect_topology(None, identity).await;
    };
    let address = address.to_owned();
    // One face per machine: with `--identity-stdin` the supervising UI
    // hands us the daemon-owned identity (two hex lines on stdin), so this
    // child presents the SAME fingerprint as the service. Read once, before
    // the retry loop — a truncated pipe fails here, never as a mystery TLS
    // error mid-link. Without the flag (manual/legacy use) the local files
    // apply exactly as before.
    let adopted_identity = if identity_stdin {
        Some(read_identity_stdin().await?)
    } else {
        None
    };
    // Machine-readable progress for a supervising UI (which pipes stderr):
    // dialing -> waiting <reason> (retries) -> established <peer>, and ended
    // on a clean shutdown. The UI must only claim "Connected" after
    // `established`; anything earlier is still connecting.
    eprintln!("THEKVM_STATUS dialing {address}");
    loop {
        let identity = match &adopted_identity {
            Some(identity) => identity.clone(),
            None => Identity::load_or_create(&data_dir())?,
        };
        let peers = PeerBook::load_or_create(&data_dir())?;
        let config = load_local_config()?;
        let dial_started = std::time::Instant::now();
        match dial_session(
            &identity,
            &peers,
            &address,
            ConnectPolicy {
                node_name: &config.device_name,
                request_lock_screen: config.allow_lock_screen_control,
                mode: config.mode,
                clipboard_enabled: config.clipboard_enabled,
                screen_geometry: truthful_local_geometry(&config.layout),
                link_id,
            },
            None,
            &data_dir(),
        )
        .await
        {
            Ok((conn, mut send, _recv, _capabilities)) => {
                // Verified logical link: this is the LIVE fingerprint — ghost
                // pins elsewhere can no longer misroute. Episodes dial fresh
                // per crossing, so the handshake connection itself is done.
                let link = TopologyLink {
                    fingerprint: peer_fingerprint(&conn)?.to_ascii_lowercase(),
                    address: address.clone(),
                    link_id,
                };
                tracing::info!(
                    peer = %address,
                    elapsed_ms = dial_started.elapsed().as_millis() as u64,
                    "linked input session",
                );
                // Deskflow-class first crossing: keep the verified QUIC
                // association warm (transport keep-alive holds it across
                // idle) instead of dropping it, so the first edge crossing
                // opens a stream on a live connection — milliseconds, not a
                // cold handshake. The verify stream itself closes gracefully
                // (ReleaseAll + FIN) so the peer's session — and its input
                // permit — ends cleanly instead of lingering into the lease.
                let _ = write_frame(&mut send, &WireMessage::ReleaseAll).await;
                let _ = send.finish();
                store_warm_link(&conn, &link.fingerprint);
                eprintln!("THEKVM_STATUS established {address}");
                return connect_topology(Some(link), identity).await;
            }
            Err(error) => {
                // A banned epoch is a deliberate remote Disconnect, not an
                // outage: exit nonzero instead of retrying forever, or the
                // dead link resurrects as a zombie the moment the peer comes
                // back. The ban status names the dead epoch for the UI's
                // auto-redial.
                if is_link_ended_rejection(&error) {
                    eprintln!("THEKVM_STATUS {}", ban_ended_status(link_id));
                    return Err(error);
                }
                tracing::warn!(%error, peer = %address, "peer unavailable; retrying");
                eprintln!("THEKVM_STATUS waiting {error:#}");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {},
            _ = tokio::signal::ctrl_c() => {
                eprintln!("THEKVM_STATUS ended interrupted");
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(target_os = "windows")]
async fn run_windows_service_controller(
    identity: Identity,
    peers: Arc<tokio::sync::RwLock<PeerBook>>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    address: String,
    node_name: String,
    request_lock_screen: bool,
    mode: Mode,
    screen_geometry: Option<ScreenGeometry>,
) -> Result<()> {
    loop {
        let capture_result =
            tokio::task::spawn_blocking(move || ServiceCaptureProxy::create(request_lock_screen))
                .await;
        let mut capture = match capture_result {
            Ok(Ok(capture)) => capture,
            Ok(Err(error)) => {
                tracing::warn!(%error, "Windows service capture helpers unavailable; retrying");
                tokio::select! {
                    _ = shutdown_notifier().notified() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(2)) => continue,
                }
            }
            Err(error) => {
                tracing::warn!(%error, "Windows capture-helper task failed; retrying");
                tokio::select! {
                    _ = shutdown_notifier().notified() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(2)) => continue,
                }
            }
        };
        let mut state = CapturedState::default();

        loop {
            let peer_book = peers.read().await.clone();
            match connect_input(
                &identity,
                &peer_book,
                &address,
                ConnectPolicy {
                    node_name: &node_name,
                    request_lock_screen,
                    mode,
                    clipboard_enabled: false,
                    screen_geometry,
                    link_id: None,
                },
                None,
            )
            .await
            {
                Ok((connection, mut send, recv, capabilities)) => {
                    let peer_fingerprint = peer_fingerprint(&connection)?;
                    let snapshot = state.snapshot();
                    send_state_sync(&mut send, snapshot.state).await?;
                    capture.set_exclusive(true)?;
                    let result = run_windows_service_capture_stream(
                        connection,
                        send,
                        recv,
                        &mut capture,
                        &mut state,
                        peer_fingerprint,
                        capabilities.smooth_scroll,
                        revoked_peers.clone(),
                    )
                    .await;
                    let _ = capture.set_exclusive(false);
                    let helpers_closed = result.as_ref().err().is_some_and(|error| {
                        matches!(
                            error.to_string().as_str(),
                            "capture helpers closed" | "interactive Windows session changed"
                        )
                    });
                    if helpers_closed {
                        break;
                    }
                    if result.as_ref().err().is_some_and(|error| {
                        error.to_string() == "privileged controller peer was revoked"
                    }) {
                        return Ok(());
                    }
                    if let Err(error) = result {
                        tracing::warn!(%error, peer = %address, "Windows service input session lost; retrying");
                    } else {
                        return Ok(());
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, peer = %address, "Windows service peer unavailable; retrying");
                }
            }

            tokio::select! {
                _ = shutdown_notifier().notified() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            }
        }
    }
}

#[cfg(target_os = "windows")]
async fn run_windows_service_capture_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    capture: &mut ServiceCaptureProxy,
    state: &mut CapturedState,
    peer_fingerprint: String,
    peer_smooth: bool,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
) -> Result<()> {
    let (remote_closed_tx, mut remote_closed_rx) = tokio::sync::oneshot::channel();
    let response_drain = tokio::spawn(async move {
        let mut recv = recv;
        while let Ok(Some(message)) = read_frame(&mut recv).await {
            if matches!(message, WireMessage::Reject { .. }) {
                break;
            }
        }
        let _ = remote_closed_tx.send(());
    });

    let mut sequence = 0u64;
    let mut keep_alive = tokio::time::interval(Duration::from_secs(5));
    keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut session_check = tokio::time::interval(Duration::from_secs(1));
    session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut revoked_rx = revoked_peers.subscribe();
    let mut wheel_debt = WheelDowngrade::default();
    let result: Result<()> = loop {
        tokio::select! {
            biased;
            event = capture.recv() => match event {
                Some(crate::windows_helper::ServiceCaptureEvent::Input(event)) => {
                    state.record(event);
                    let Some(outgoing) =
                        outgoing_wheel_event(event, peer_smooth, &mut wheel_debt)
                    else {
                        // Sub-detent touchpad debt kept, nothing sent.
                        continue;
                    };
                    sequence = sequence.wrapping_add(1);
                    let send_result = match outgoing {
                        InputEvent::MouseMove { .. }
                        | InputEvent::Wheel(_)
                        | InputEvent::SmoothWheel { .. } => {
                            send_input(&connection, &mut send, sequence, outgoing).await
                        }
                        _ => write_frame(
                            &mut send,
                            &WireMessage::Input(InputPacket { sequence, event: outgoing }),
                        )
                        .await
                        .map_err(Into::into),
                    };
                    if let Err(error) = send_result {
                        break Err(error);
                    }
                }
                Some(crate::windows_helper::ServiceCaptureEvent::HelpersClosed) | None => {
                    break Err(anyhow::anyhow!("capture helpers closed"));
                }
            },
            _ = keep_alive.tick() => {
                if let Err(error) = write_frame(&mut send, &WireMessage::Ping { nonce: sequence }).await {
                    break Err(error.into());
                }
            }
            _ = session_check.tick() => {
                if capture.session_changed() {
                    break Err(anyhow::anyhow!("interactive Windows session changed"));
                }
            }
            revoked = revoked_rx.recv() => match revoked {
                Ok(fingerprint) if fingerprint == peer_fingerprint => {
                    break Err(anyhow::anyhow!("privileged controller peer was revoked"));
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
            },
            _ = &mut remote_closed_rx => {
                break Err(anyhow::anyhow!("peer closed the input session"));
            }
            _ = shutdown_notifier().notified() => {
                break Ok(());
            }
        }
    };

    let _ = write_frame(&mut send, &WireMessage::ReleaseAll).await;
    let _ = send.finish();
    response_drain.abort();
    result
}

/// Capture input locally and activate the peer occupying the next configured
/// screen when the logical pointer crosses an edge. This is deliberately a
/// separate path from the fixed-peer diagnostic command: it keeps connection
/// establishment out of the capture backend and makes topology decisions in
/// one stateful router.
///
/// `link` carries a verified logical link (from an upfront dial): the child
/// then drives ONLY that peer — MWB switches solely to connected machines.
/// Without a link the child dials whatever the arrangement names (legacy
/// standalone use; the desktop UI always links).
async fn connect_topology(link: Option<TopologyLink>, identity: Identity) -> Result<()> {
    let dir = data_dir();
    // Machine-readable progress for a supervising UI (which pipes stderr):
    // edge-ready when capture runs, driving <screen> while a peer owns the
    // pointer, local when control is here, waiting <reason> while retrying,
    // ended on shutdown. The UI must only claim edge mode is live after
    // `edge-ready`; anything earlier is still starting.
    eprintln!("THEKVM_STATUS dialing edge");
    // The arrangement may not exist yet (fresh pairing): wait for it instead
    // of exiting, reloading the config every few seconds, so starting edge
    // mode and then arranging the screens just starts working with no
    // restart and no extra click. A linked child additionally waits for the
    // linked peer's screen (the supervisor adopts the live fingerprint on
    // `established`, healing ghost pins with no restart either).
    let (config, mut router) = loop {
        let config = Config::load(&dir.join("config.json"))
            .with_context(|| format!("loading topology config from {}", dir.display()))?;
        let linked = link.as_ref().is_none_or(|link| {
            config.layout.screens.iter().any(|screen| {
                screen.peer_fingerprint.as_deref() == Some(link.fingerprint.as_str())
            })
        });
        match EdgeRouter::new(config.layout.clone()) {
            Ok(router) if linked => break (config, router),
            Ok(_) => {
                let waiting_for = link.as_ref().map(|link| link.address.as_str()).unwrap_or("?");
                tracing::info!(%waiting_for, "topology waiting for the linked screen to be arranged");
                eprintln!(
                    "THEKVM_STATUS waiting linked computer not arranged yet — adopting it…"
                );
            }
            Err(error) => {
                tracing::warn!(%error, "topology has no screen arrangement yet; waiting for one");
                eprintln!(
                    "THEKVM_STATUS waiting no screen arrangement yet — arrange the linked screens first ({error})"
                );
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
            _ = tokio::signal::ctrl_c() => {
                eprintln!("THEKVM_STATUS ended interrupted");
                return Ok(());
            }
        }
    };
    // Real geometry BEFORE the seed (Deskflow getShape parity): the
    // crossing edge must sit on the visible edge. A layout in fallback
    // dims while the pointer lives in physical ones fires crossings the
    // user sees as "far from any edge" — on either computer. Once per
    // process: the per-event truth feed below only re-pins the cursor,
    // never the dims.
    match kvm_platform::capture::screen_size() {
        Ok(Some((width, height))) => {
            match router.adopt_local_screen_size(width, height) {
                Some((w, h)) => {
                    tracing::info!(width = w, height = h, "topology local geometry measured")
                }
                None => tracing::warn!("measured screen size rejected; keeping configured geometry"),
            }
        }
        Ok(None) => tracing::debug!("platform did not expose a screen size; keeping configured geometry"),
        Err(error) => tracing::debug!(%error, "could not query screen size"),
    }
    match kvm_platform::capture::current_cursor_position() {
        Ok(Some((x, y))) => {
            if let Err(error) = router.set_local_cursor_position(x, y) {
                tracing::debug!(%error, "could not seed topology cursor position");
            } else {
                // Proves the first-launch sync: every crossing tracks
                // relative motion from HERE, so a wrong seed puts the
                // first handoff mid-screen while later ones (re-synced by
                // warps) look fine.
                tracing::info!(x, y, "topology cursor seeded from OS position");
            }
        }
        Ok(None) => tracing::debug!("platform did not expose an initial cursor position"),
        Err(error) => tracing::debug!(%error, "could not query initial cursor position"),
    }
    // The Settings edge discipline applies from the first crossing: the
    // router starts in the configured Single/Double mode, and the toggle
    // only affects later handoffs through a fresh child.
    router.set_edge_mode(config.edge_mode);
    tracing::info!(edge_mode = ?config.edge_mode, "topology edge discipline");
    // Episodes advertise the ADOPTED router geometry (real measured dims),
    // never the configured fallback: the peer maps every entry point
    // against this. Plus publish it for the headless daemon sidecar.
    let local_geometry = local_screen_geometry(router.layout());
    publish_local_geometry(&router);
    let peers = PeerBook::load_or_create(&dir)?;
    // The face every episode dial presents. This MUST be the same identity
    // the startup verify used (daemon-owned via --identity-stdin for
    // supervised children): 0.8.0 verified as one face and drove as another,
    // so the peer accepted the link and then rejected every crossing.
    tracing::info!(
        fingerprint = identity.fingerprint_hex(),
        "topology driving identity"
    );
    // Topology mode preserves local input until an edge transition is actually
    // selected. Once a remote screen owns the pointer, the platform backend is
    // switched to exclusive capture until control returns or the session dies.
    // Parked drive stream: the last episode's accepted stream, kept across
    // edge returns so the next push costs one Handoff frame instead of a
    // dial (Deskflow always-ready parity without any protocol change).
    let mut parked: Option<TopologySession> = None;
    // Pre-warm one drive stream BEFORE capture starts (nothing queued yet,
    // so a slow/dead peer cannot stall the hook): the first crossing then
    // costs one Handoff frame instead of a dial plus just-in-time receiver
    // provisioning. Bounded and best effort — a miss just means the first
    // push opens cold like before.
    if let Some(link) = link.as_ref() {
        let prewarm = prewarm_link_stream(
            &identity,
            &peers,
            &config,
            &router,
            link,
            &dir,
            local_geometry,
        );
        parked = match tokio::time::timeout(Duration::from_secs(5), prewarm).await {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                // The peer deliberately ended this epoch: exit now instead
                // of parking at edge-ready as a zombie that rejects every
                // later push. The UI redials on the peer's fresh epoch.
                eprintln!(
                    "THEKVM_STATUS {}",
                    ban_ended_status(link.link_id)
                );
                return Err(error);
            }
            Err(_) => {
                tracing::debug!("pre-warm timed out; first push opens cold");
                None
            }
        };
    }
    let (mut priority_rx, mut motion_rx, capture_control) = start_capture(false, true)?;
    let mut active: Option<TopologySession> = None;
    let mut clipboard = start_clipboard_agent(config.clipboard_enabled);
    let mut clipboard_enabled = config.clipboard_enabled;
    let mut clipboard_revision = 0u64;
    let mut latest_clipboard: Option<String> = None;
    let mut discarded_event_barrier = 0u64;
    let mut last_transfer: Option<std::time::Instant> = None;
    let mut last_failed_episode: Option<std::time::Instant> = None;
    // Last OS-pointer truth resync (see handle_topology_event): throttles
    // the GetCursorPos/query_pointer read to 20Hz so motion stays cheap.
    let mut last_resync: Option<std::time::Instant> = None;
    // Last backend-census journal line (see the keep-alive tick).
    let mut last_census_log: Option<std::time::Instant> = None;
    // Last peer-app heartbeat on the active episode (see Progress): None
    // until the first Pong, so legacy peers that never Pong keep today's
    // behavior instead of tripping the watchdog.
    let mut last_peer_progress: Option<std::time::Instant> = None;
    // Consecutive active-episode Pings with no Pong answer. Clock-free
    // starvation proof: twelve unanswered Pings (~60s) means the peer app
    // is not reading the episode stream — every released version answers
    // Pings since 0.1.0, so this cannot be a healthy old peer. Covers
    // the None-forever hole (Pong never arrives, e.g. drain wedged at
    // drive start) that the timestamp watchdog above cannot see.
    let mut unacked_pings: u32 = 0;
    // Whether local-input suppression is currently requested for a drive.
    // Every release clears it; the keep-alive reaper heals any hold that
    // outlives its drive (the total-freeze class).
    let mut suppression_requested = false;
    let mut local_wheel_dropped = 0u64;
    let mut sequence = 0u64;
    let mut keep_alive = tokio::time::interval(Duration::from_secs(5));
    keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(screen = ?router.current_screen(), "topology capture ready; move to a configured screen edge");
    eprintln!("THEKVM_STATUS edge-ready");
    loop {
        tokio::select! {
            biased;
            signal = async {
                if let Some(session) = active.as_mut() {
                    session.signals.recv().await
                } else {
                    std::future::pending::<Option<RemoteSignal>>().await
                }
            } => {
                match signal {
                    Some(RemoteSignal::Handoff(handoff)) => {
                        if let Some(session) = active.take() {
                            session.finish().await;
                            release_suppression(&capture_control, Some(&mut suppression_requested));
                            discarded_event_barrier = discarded_event_barrier
                                .max(capture_control.snapshot().last_event_id);
                        }
                        let target = ScreenId(handoff.screen_id);
                        // Named routing first: the peer names the screen it
                        // reached, and names agree across machines while local
                        // numbers never do. The bare number is only a
                        // mixed-version fallback. An unknown name stays
                        // local — never drive blind.
                        let target = if handoff.target_name.is_empty() {
                            target
                        } else {
                            match router.layout().screen_by_name(&handoff.target_name) {
                                Some(screen) => screen.id,
                                None => {
                                    tracing::warn!(name = %handoff.target_name, "handoff names an unknown screen; staying local");
                                    eprintln!("THEKVM_STATUS local");
                                    continue;
                                }
                            }
                        };
                        let (handoff_x, handoff_y) = router
                            .screen(target)
                            .map(|screen| {
                                let target_geometry = ScreenGeometry {
                                    screen_id: target.0,
                                    width: screen.width,
                                    height: screen.height,
                                };
                                remap_position(
                                    handoff.x,
                                    handoff.y,
                                    handoff.screen_geometry,
                                    target_geometry,
                                )
                            })
                            .unwrap_or((handoff.x, handoff.y));
                        // A handoff naming this machine's own screen hands
                        // control back: re-enter at the exact pixel
                        // departed (saved local position, Deskflow
                        // jump-position semantics) instead of stale exit
                        // coordinates, so return never jumps somewhere
                        // unexpected.
                        if target == router.local_screen() {
                            let (home_x, home_y) = router.local_cursor_position();
                            router
                                .handoff_to(target, home_x, home_y)
                                .map_err(anyhow::Error::msg)?;
                            capture_control.warp_cursor(home_x, home_y)?;
                            tracing::info!(?target, "topology peer returned control locally");
                            eprintln!("THEKVM_STATUS local");
                            continue;
                        }
                        if !router
                            .handoff_to(target, handoff_x, handoff_y)
                            .map_err(anyhow::Error::msg)?
                        {
                            capture_control.warp_cursor(handoff_x, handoff_y)?;
                            tracing::info!(?target, "topology peer returned control locally");
                            eprintln!("THEKVM_STATUS local");
                            continue;
                        }
                        let snapshot = capture_control.snapshot();
                        let first_event = (handoff.dx != 0 || handoff.dy != 0).then_some(
                            InputEvent::MouseMove {
                                dx: handoff.dx,
                                dy: handoff.dy,
                            },
                        );
                        // A parked stream to this target resumes with one
                        // Handoff frame; otherwise open fresh below.
                        let mut session = match take_parked_for(&mut parked, target).await {
                            Some(parked_session) => {
                                match resume_parked_session(
                                    parked_session,
                                    &router,
                                    target,
                                    handoff_x,
                                    handoff_y,
                                    snapshot.state.clone(),
                                    first_event,
                                    latest_clipboard.clone(),
                                    &mut clipboard_revision,
                                    &mut sequence,
                                    snapshot.last_event_id,
                                )
                                .await
                                {
                                    Ok(resumed) => Some(resumed),
                                    Err(error) => {
                                        tracing::debug!(%error, ?target, "parked drive stream went stale; opening a fresh episode");
                                        None
                                    }
                                }
                            }
                            None => None,
                        };
                        if session.is_none() {
                            match open_topology_session(TopologyOpen {
                                router: &router,
                                identity: &identity,
                                peers: &peers,
                                node_name: &config.device_name,
                                target,
                                target_x: handoff_x,
                                target_y: handoff_y,
                                state: snapshot.state,
                                event_barrier: snapshot.last_event_id,
                                first_event,
                                request_lock_screen: config.allow_lock_screen_control,
                                mode: config.mode,
                                local_geometry,
                                clipboard_enabled,
                                initial_clipboard: latest_clipboard.clone(),
                                sequence: &mut sequence,
                                clipboard_revision: &mut clipboard_revision,
                                dir: &dir,
                                link_id: link.as_ref().and_then(|link| link.link_id),
                            }).await {
                                Ok(opened) => session = Some(opened),
                                Err(error) => {
                                    // A banned epoch ends the child (the peer
                                    // disconnected on purpose); anything else
                                    // just returns control locally.
                                    if is_link_ended_rejection(&error) {
                                        eprintln!(
                                            "THEKVM_STATUS {}",
                                            ban_ended_status(
                                                link.as_ref().and_then(|link| link.link_id)
                                            )
                                        );
                                        return Err(error);
                                    }
                                    let _ = router.restore_local(target);
                                    let (x, y) = router.cursor_position();
                                    let _ = capture_control.warp_cursor(x, y);
                                    tracing::warn!(%error, ?target, "topology handoff target unavailable; returned control locally");
                                    eprintln!("THEKVM_STATUS local");
                                }
                            }
                        }
                        if let Some(session) = session {
                                capture_control.set_exclusive(true)?;
                                suppression_requested = true;
                                // Fresh episode: grace until the first Pong
                                // proves the peer app end (then the watchdog
                                // enforces continued proof).
                                last_peer_progress = None;
                                unacked_pings = 0;
                                active = Some(session);
                                let name = router
                                    .screen(target)
                                    .map(|screen| screen.name.clone())
                                    .unwrap_or_else(|| format!("screen {}", target.0));
                                tracing::info!(?target, "topology handoff continued to next peer");
                                eprintln!("THEKVM_STATUS driving {name}");
                            }
                        }
                    Some(RemoteSignal::Progress) => {
                        // Peer-app heartbeat: the episode stream is alive
                        // end-to-end. The only signal separating a healthy
                        // idle drive from a wedged peer app (transport ACKs
                        // either way).
                        last_peer_progress = Some(Instant::now());
                        unacked_pings = 0;
                    }
                    Some(RemoteSignal::Clipboard { revision, text }) => {                        let Some(session) = active.as_mut() else {
                            continue;
                        };
                        if !session.clipboard_enabled || revision <= session.remote_clipboard_revision {
                            continue;
                        }
                        session.remote_clipboard_revision = revision;
                        if let Some(agent) = clipboard.as_ref() {
                            agent.apply_remote(text.clone())?;
                            latest_clipboard = Some(text);
                        }
                    }
                    Some(RemoteSignal::Closed) | None => {
                        if let Some(session) = active.take() {
                            let target = session.target;
                            session.finish().await;
                            release_suppression(&capture_control, Some(&mut suppression_requested));
                            discarded_event_barrier = discarded_event_barrier
                                .max(capture_control.snapshot().last_event_id);
                            let _ = router.restore_local(target);
                            let (x, y) = router.cursor_position();
                            let _ = capture_control.warp_cursor(x, y);
                            tracing::warn!(?target, "topology peer closed; returned control locally");
                            eprintln!("THEKVM_STATUS local");
                        }
                    }
                }
            }
            event = priority_rx.recv() => {
                let Some(captured) = event else { bail!("priority input capture stopped") };
                if captured.event_id <= discarded_event_barrier
                    || active
                        .as_ref()
                        .is_some_and(|session| captured.event_id <= session.event_barrier)
                {
                    continue;
                }
                handle_topology_event(captured, TopologyEventContext {
                    router: &mut router,
                    identity: &identity,
                    peers: &peers,
                    capture_control: &capture_control,
                    active: &mut active,
                    parked: &mut parked,
                    link: link.as_ref(),
                    last_transfer: &mut last_transfer,
                    last_failed_episode: &mut last_failed_episode,
                    node_name: &config.device_name,
                    sequence: &mut sequence,
                    request_lock_screen: config.allow_lock_screen_control,
                    mode: config.mode,
                    local_geometry,
                    clipboard_enabled,
                    initial_clipboard: latest_clipboard.clone(),
                    clipboard_revision: &mut clipboard_revision,
                    dir: &dir,
                    discarded_event_barrier: &mut discarded_event_barrier,
                    local_wheel_dropped: &mut local_wheel_dropped,
                    last_resync: &mut last_resync,
                    suppression_requested: &mut suppression_requested,
                    last_peer_progress: &mut last_peer_progress,
                    unacked_pings: &mut unacked_pings,
                })
                .await?;
            }
            event = motion_rx.recv() => {
                let Some(captured) = event else { bail!("input capture stopped") };
                if captured.event_id <= discarded_event_barrier
                    || active
                        .as_ref()
                        .is_some_and(|session| captured.event_id <= session.event_barrier)
                {
                    continue;
                }
                handle_topology_event(captured, TopologyEventContext {
                    router: &mut router,
                    identity: &identity,
                    peers: &peers,
                    capture_control: &capture_control,
                    active: &mut active,
                    parked: &mut parked,
                    link: link.as_ref(),
                    last_transfer: &mut last_transfer,
                    last_failed_episode: &mut last_failed_episode,
                    node_name: &config.device_name,
                    sequence: &mut sequence,
                    request_lock_screen: config.allow_lock_screen_control,
                    mode: config.mode,
                    local_geometry,
                    clipboard_enabled,
                    initial_clipboard: latest_clipboard.clone(),
                    clipboard_revision: &mut clipboard_revision,
                    dir: &dir,
                    discarded_event_barrier: &mut discarded_event_barrier,
                    local_wheel_dropped: &mut local_wheel_dropped,
                    last_resync: &mut last_resync,
                    suppression_requested: &mut suppression_requested,
                    last_peer_progress: &mut last_peer_progress,
                    unacked_pings: &mut unacked_pings,
                })
                .await?;
            }
            text = receive_clipboard(&mut clipboard, clipboard_enabled) => match text {
                Some(text) => {
                    latest_clipboard = Some(text.clone());
                    let Some(session) = active.as_mut().filter(|session| session.clipboard_enabled) else {
                        continue;
                    };
                    if text.len() > kvm_protocol::wire::MAX_CLIPBOARD_TEXT_BYTES {
                        tracing::debug!(bytes = text.len(), "skipping oversized clipboard text");
                        continue;
                    }
                    clipboard_revision = clipboard_revision.wrapping_add(1);
                    if let Err(error) = write_frame(
                        &mut session.send,
                        &WireMessage::ClipboardText {
                            revision: clipboard_revision,
                            text,
                        },
                    )
                    .await
                    {
                        // Like a failed input send: the episode ends, the
                        // child lives on for the next crossing.
                        tracing::warn!(%error, "topology clipboard send failed; control is local");
                        let session = active.take().expect("active session exists");
                        let target = session.target;
                        session.finish().await;
                        // The association itself is suspect: drop the park
                        // too, so the next push redials instead of
                        // resuming a dead stream.
                        if let Some(stale) = parked.take() {
                            stale.finish().await;
                        }
                        release_suppression(&capture_control, Some(&mut suppression_requested));
                        discarded_event_barrier = discarded_event_barrier
                            .max(capture_control.snapshot().last_event_id);
                        let _ = router.restore_local(target);
                        let (x, y) = router.cursor_position();
                        let _ = capture_control.warp_cursor(x, y);
                        last_failed_episode = Some(std::time::Instant::now());
                        eprintln!("THEKVM_STATUS local");
                    }
                }
                None => clipboard_enabled = false,
            },
            _ = keep_alive.tick() => {
                if let Some(session) = active.as_mut() {
                    // Bounded keep-alive: an unbounded write pends forever
                    // on a half-dead association and stalls this whole task
                    // (no routing, no release, grabs held) — the persistent
                    // freeze shape. 3s, then the association is dead.
                    let ping = tokio::time::timeout(
                        Duration::from_secs(3),
                        write_frame(&mut session.send, &WireMessage::Ping { nonce: sequence }),
                    )
                    .await;
                    let ping_error: Option<String> = match ping {
                        Ok(Ok(())) => None,
                        Ok(Err(error)) => Some(format!("{error:#}")),
                        Err(_) => Some("keep-alive write timed out after 3s".to_owned()),
                    };
                    // Silent-episode watchdog: Pongs proved the peer app end
                    // before, then stopped — transport ACKs either way, so
                    // only app-level silence proves the wedge. Legacy peers
                    // that never Pong stay on today's behavior (None).
                    // 60s = a dozen missed heartbeats; healthy idle drives
                    // Pong every 5s and never trip it.
                    let episode_silent = last_peer_progress
                        .is_some_and(|when| when.elapsed() > Duration::from_secs(60));
                    if episode_silent {
                        tracing::warn!(
                            "drive peer app silent 60s (heartbeats stopped); ending the episode locally"
                        );
                    }
                    // Clock-free starvation proof: twelve consecutive Pings
                    // with no Pong answer (see unacked_pings) ends the
                    // episode even when no heartbeat ever arrived — the
                    // None-forever hole where a wedged peer app holds the
                    // local grab hostage with the cursor still moving.
                    if ping_error.is_none() {
                        unacked_pings = unacked_pings.saturating_add(1);
                    }
                    let episode_starved = drive_starved(unacked_pings);
                    if episode_starved {
                        tracing::warn!(
                            unacked_pings,
                            "drive peer app never answers keep-alive; ending the episode locally"
                        );
                    }
                    if ping_error.is_some() || episode_silent || episode_starved {
                        if let Some(detail) = ping_error {
                            tracing::warn!(detail, "topology peer keep-alive failed");
                        }
                        let session = active.take().expect("active session exists");
                        let target = session.target;
                        session.finish().await;
                        // The association itself is suspect: drop the park
                        // too, so the next push redials instead of
                        // resuming a dead stream.
                        if let Some(stale) = parked.take() {
                            stale.finish().await;
                        }
                        release_suppression(&capture_control, Some(&mut suppression_requested));
                        discarded_event_barrier = discarded_event_barrier
                            .max(capture_control.snapshot().last_event_id);
                        let _ = router.restore_local(target);
                        let (x, y) = router.cursor_position();
                        let _ = capture_control.warp_cursor(x, y);
                        eprintln!("THEKVM_STATUS local");
                    }
                } else if let Some(session) = parked.as_mut() {
                    // A parked stream still holds the peer's input slot and
                    // provisioned injector: ping it so the lease never
                    // reaps it and a silent death is noticed within seconds
                    // instead of on the next push. Bounded like the active
                    // Ping above: never stall the task on a half-dead peer.
                    let parked_ping = tokio::time::timeout(
                        Duration::from_secs(3),
                        write_frame(&mut session.send, &WireMessage::Ping { nonce: sequence }),
                    )
                    .await;
                    if !matches!(parked_ping, Ok(Ok(()))) {
                        tracing::debug!("parked drive stream died; next push reopens");
                        if let Some(stale) = parked.take() {
                            stale.finish().await;
                        }
                    }
                }
                // Suppression-hold reaper: a held local-suppression with no
                // active drive freezes ALL local input (and injected input
                // too) while the cursor still moves. Any missed or resisted
                // release heals here within seconds, loudly.
                if stale_hold_needs_release(active.is_some(), suppression_requested) {
                    release_suppression(&capture_control, Some(&mut suppression_requested));
                    tracing::info!("suppression reaper: released stale hold with no active drive");
                }
                // Backend receipt census, once a minute: which OS channel
                // speaks (hook vs raw HID vs precision touchpad).
                // Scroll-silence reports end here — hook_wheel/raw_wheel/
                // ptp_scroll name the guilty channel.
                let census_due = last_census_log
                    .map(|when| when.elapsed() >= Duration::from_secs(60))
                    .unwrap_or(true);
                if census_due {
                    last_census_log = Some(Instant::now());
                    let (hook_key, hook_button, hook_move, hook_wheel, raw_move, raw_wheel, ptp_scroll) =
                        kvm_platform::capture::backend_census();
                    // Sender hold snapshot alongside the channel census: the
                    // mystery-freeze triage line — a stuck drive shows here
                    // as drive_active with an ancient peer heartbeat.
                    // peer_progress_age_secs: -1 = no Pong yet this episode
                    // (grace / legacy peer).
                    let peer_progress_age_secs = last_peer_progress
                        .map(|when| when.elapsed().as_secs() as i64)
                        .unwrap_or(-1);
                    tracing::info!(
                        hook_key,
                        hook_button,
                        hook_move,
                        hook_wheel,
                        raw_move,
                        raw_wheel,
                        ptp_scroll,
                        drive_active = active.is_some(),
                        suppression_requested,
                        parked = parked.is_some(),
                        peer_progress_age_secs,
                        unacked_pings,
                        "capture backend census"
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => {
                release_suppression(&capture_control, Some(&mut suppression_requested));
                if let Some(session) = active.take() {
                    session.finish().await;
                }
                if let Some(stale) = parked.take() {
                    stale.finish().await;
                }
                eprintln!("THEKVM_STATUS ended stopped");
                return Ok(());
            }
        }
    }
}

struct TopologySession {
    target: ScreenId,
    connection: quinn::Connection,
    send: quinn::SendStream,
    signals: tokio::sync::mpsc::UnboundedReceiver<RemoteSignal>,
    response_drain: tokio::task::JoinHandle<()>,
    event_barrier: u64,
    clipboard_enabled: bool,
    remote_clipboard_revision: u64,
    /// Whether this peer injects high-resolution touchpad scroll. When it
    /// does not, captured `SmoothWheel` events are downgraded to detent
    /// `Wheel` here (never dropped wholesale, never sent raw).
    peer_smooth: bool,
    wheel_debt: WheelDowngrade,
    /// Sender-side scroll census: captured vs forwarded wheel events. Logged
    /// at teardown next to the receiver's census, so each side's journal
    /// proves where scroll lived or died.
    wheel_captured: u64,
    smooth_captured: u64,
    wheel_forwarded: u64,
    /// Sender-side motion census: captured vs forwarded MouseMove events.
    /// Logged at teardown next to the scroll census, so a silent motion
    /// drop (entry warp lands, cursor never tracks) is diagnosable from
    /// the journal instead of a mystery.
    motion_captured: u64,
    motion_forwarded: u64,
    /// The peer's self-reported geometry (for re-mapping re-entry points
    /// when this stream is reused after parking).
    peer_geometry: Option<ScreenGeometry>,
    /// True once a PointerHandoff has gone out on this stream. Pre-warmed
    /// streams that never drove skip the end-of-episode census line so the
    /// journal never shows a phantom drive.
    handed_off: bool,
}

#[derive(Debug, Clone)]
struct RemoteHandoff {
    screen_id: u32,
    target_name: String,
    x: u32,
    y: u32,
    dx: i32,
    dy: i32,
    screen_geometry: Option<ScreenGeometry>,
}

enum RemoteSignal {
    Handoff(RemoteHandoff),
    Clipboard { revision: u64, text: String },
    Closed,
    /// The peer app answered a keep-alive Ping: the episode stream is
    /// alive end-to-end, not just the QUIC association (which the kernel
    /// ACKs even when the peer app is wedged). Feeds the silent-episode
    /// watchdog below.
    Progress,
}

impl TopologySession {
    async fn finish(self) {
        if self.handed_off {
            tracing::info!(
                target = ?self.target,
                wheel_captured = self.wheel_captured,
                smooth_captured = self.smooth_captured,
                wheel_forwarded = self.wheel_forwarded,
                motion_captured = self.motion_captured,
                motion_forwarded = self.motion_forwarded,
                peer_smooth = self.peer_smooth,
                "topology episode ended",
            );
        }
        let mut send = self.send;
        let _ = write_frame(&mut send, &WireMessage::ReleaseAll).await;
        let _ = send.finish();
        self.response_drain.abort();
    }
}

/// A verified logical link to one peer: the upfront dial proved
/// reachability and mutual trust (and yielded the LIVE fingerprint —
/// ghost pins in the book can no longer misroute). Drive streams persist
/// across crossings (parked on return, pre-warmed at edge-ready) and only
/// ever target this peer: MWB switches solely to connected machines,
/// never to a stranger in a field.
#[derive(Debug, Clone)]
struct TopologyLink {
    fingerprint: String,
    address: String,
    /// Administrative epoch both sides share (None for legacy topology
    /// children: no banning applies to them).
    link_id: Option<u64>,
}

/// One warm, verified QUIC association to the linked peer, kept across
/// drive episodes. A cold dial per screen-edge crossing costs endpoint
/// setup plus a full handshake on EVERY crossing (the visible edge lag);
/// a warm association turns a crossing into one stream plus Hello on an
/// already-live connection — milliseconds on LAN. The transport's 5s
/// keep-alive holds it across idle gaps; a dead association simply falls
/// back to a cold dial and re-warms. One slot per child process is exact:
/// each topology child drives exactly one link.
#[derive(Clone)]
struct WarmLink {
    connection: quinn::Connection,
    fingerprint: String,
}

static WARM_LINK: std::sync::OnceLock<std::sync::Mutex<Option<WarmLink>>> =
    std::sync::OnceLock::new();

fn warm_link_pool() -> &'static std::sync::Mutex<Option<WarmLink>> {
    WARM_LINK.get_or_init(|| std::sync::Mutex::new(None))
}

/// Take the warm association when it is for this peer and still alive.
/// Anything else (wrong peer, closed connection, poisoned lock) means a
/// cold dial. Never blocks: the pool is only ever briefly held.
fn take_warm_link(fingerprint: &str) -> Option<quinn::Connection> {
    let mut pool = warm_link_pool().lock().ok()?;
    let warm = pool.take()?;
    if warm.fingerprint != fingerprint || warm.connection.close_reason().is_some() {
        return None;
    }
    Some(warm.connection)
}

fn store_warm_link(connection: &quinn::Connection, fingerprint: &str) {
    if connection.close_reason().is_some() {
        return;
    }
    if let Ok(mut pool) = warm_link_pool().lock() {
        *pool = Some(WarmLink {
            connection: connection.clone(),
            fingerprint: fingerprint.to_owned(),
        });
    }
}

/// MWB lastJump parity: ignore a new edge transfer within 100ms of the last
/// completed one, so two facing edges can never ping-pong the cursor
/// forever. Pure so the determinism is unit-tested.
fn transfer_debounced(last_transfer: Option<std::time::Instant>) -> bool {
    last_transfer.is_some_and(|when| when.elapsed() < Duration::from_millis(100))
}

/// Best-effort release of local-input suppression. A failed ungrab must
/// NEVER abort drive teardown (or kill the child): the cleanup after it
/// (warp, status, barriers) still has to run. Belief follows reality —
/// the flag clears ONLY on success, so the keep-alive reaper keeps
/// retrying a resisting hold every 5s instead of forgetting it. The old
/// unconditional clear wedged the hold forever: daemon belief false while
/// the platform grab stayed held (keys/clicks dead, cursor moving).
fn release_suppression(
    capture_control: &CaptureGuard,
    requested: Option<&mut bool>,
) {
    if let Err(error) = capture_control.set_exclusive(false) {
        tracing::warn!(%error, "suppression release failed; belief kept, reaper will retry");
        return;
    }
    if let Some(requested) = requested {
        *requested = false;
    }
}

/// Reaper predicate: suppression was requested for a drive, but no drive
/// is active anymore — the hold must be released now. Pure for tests.
fn stale_hold_needs_release(drive_active: bool, suppression_requested: bool) -> bool {
    suppression_requested && !drive_active
}

/// Starvation predicate: this many consecutive active-episode Pings with
/// no Pong answer proves the peer app is not reading the episode stream
/// (twelve Pings at the 5s cadence is ~60s). Pure for tests.
fn drive_starved(unacked_pings: u32) -> bool {
    unacked_pings >= 12
}

/// Cooldown after a FAILED episode dial: the peer is unreachable, busy, or
/// gone, and the cursor sits at the edge pouring motion events in — without
/// a pause every one of them would open a full QUIC handshake (the dial
/// storm that flapped control and stuttered the cursor). Pure so the
/// determinism is unit-tested.
fn episode_cooling_down(last_failed_episode: Option<std::time::Instant>) -> bool {
    last_failed_episode.is_some_and(|when| when.elapsed() < Duration::from_secs(1))
}

/// Step the router cursor a few pixels inside the screen after a refused
/// handoff (Deskflow `avoidJumpZone` parity): without it the cursor rests
/// one pixel from the edge and the very next motion event re-crosses, so a
/// dead peer flaps control local→driving→local at event rate. With it the
/// user simply keeps pushing — a fresh, deliberate crossing retries.
fn park_inside(router: &mut EdgeRouter, edge: kvm_core::Edge) {
    const PARK_PX: u32 = 8;
    let (mut x, mut y) = router.cursor_position();
    match edge {
        kvm_core::Edge::Left => x = x.saturating_add(PARK_PX),
        kvm_core::Edge::Right => x = x.saturating_sub(PARK_PX),
        kvm_core::Edge::Top => y = y.saturating_add(PARK_PX),
        kvm_core::Edge::Bottom => y = y.saturating_sub(PARK_PX),
    }
    // Best effort: a failure here just leaves the cursor where it was.
    let _ = router.set_local_cursor_position(x, y);
}

struct TopologyEventContext<'a> {
    router: &'a mut EdgeRouter,
    identity: &'a Identity,
    peers: &'a PeerBook,
    capture_control: &'a CaptureGuard,
    active: &'a mut Option<TopologySession>,
    parked: &'a mut Option<TopologySession>,
    link: Option<&'a TopologyLink>,
    last_transfer: &'a mut Option<std::time::Instant>,
    last_failed_episode: &'a mut Option<std::time::Instant>,
    node_name: &'a str,
    sequence: &'a mut u64,
    request_lock_screen: bool,
    mode: Mode,
    local_geometry: Option<ScreenGeometry>,
    clipboard_enabled: bool,
    initial_clipboard: Option<String>,
    clipboard_revision: &'a mut u64,
    dir: &'a std::path::Path,
    discarded_event_barrier: &'a mut u64,
    /// Scroll events routed locally while nobody is driven (scroll alone
    /// never opens a crossing). Logged at each handoff: distinguishes a
    /// dead capture hook (zero here too) from scrolling while local.
    local_wheel_dropped: &'a mut u64,
    /// Throttle stamp for the OS-pointer truth resync below.
    last_resync: &'a mut Option<std::time::Instant>,
    /// Belief flag for the suppression-hold reaper: set on drive start,
    /// cleared on every release.
    suppression_requested: &'a mut bool,
    /// Peer-app heartbeat for the silent-episode watchdog: reset to None
    /// on every drive start (grace until the first Pong), stamped by the
    /// Progress signal.
    last_peer_progress: &'a mut Option<std::time::Instant>,
    /// Consecutive unanswered active-episode Pings (see the loop-local):
    /// reset on drive start and on every Pong.
    unacked_pings: &'a mut u32,
}

async fn handle_topology_event(
    captured: CapturedEvent,
    context: TopologyEventContext<'_>,
) -> Result<()> {
    let TopologyEventContext {
        router,
        identity,
        peers,
        capture_control,
        active,
        parked,
        link,
        last_transfer,
        last_failed_episode,
        node_name,
        sequence,
        request_lock_screen,
        mode,
        local_geometry,
        clipboard_enabled,
        initial_clipboard,
        clipboard_revision,
        dir,
        discarded_event_barrier,
        local_wheel_dropped,
        last_resync,
        suppression_requested,
        last_peer_progress,
        unacked_pings,
    } = context;
    // OS-pointer truth resync (Deskflow jump-zone half of the phantom fix):
    // Raw deltas keep flowing after the OS pointer has stopped at the edge,
    // so the integrated virtual cursor runs AHEAD of the visible one and a
    // later push looks like it started "near" the edge. Re-pin to truth at
    // 20Hz while local; the router ignores it while driving remotely, and
    // Wayland (no query) simply skips — the push threshold still guards.
    if matches!(captured.event, InputEvent::MouseMove { .. })
        && router.current_screen() == router.local_screen()
        && router.active_remote().is_none()
    {
        // Near a crossing edge every event re-pins (a 50ms-old virtual
        // position is where phantom crossings are computed from); mid
        // screen the throttle is plenty and keeps motion cheap.
        let near = router.near_crossing_edge(64);
        let due = near
            || last_resync
                .map(|when| when.elapsed() >= Duration::from_millis(50))
                .unwrap_or(true);
        if due {
            *last_resync = Some(Instant::now());
            match kvm_platform::capture::current_cursor_position() {
                Ok(Some((x, y))) => router.resync_if_local(x, y),
                Ok(None) => {}
                Err(error) => {
                    tracing::debug!(%error, "truth resync unavailable");
                }
            }
        }
    }
    // ScrollLock toggles the Deskflow-style screen lock (consumed, never
    // forwarded): locking returns home first so it always means "held
    // locally", never "stranded remotely".
    if is_scroll_lock_press(&captured.event) {
        if router.is_locked() {
            router.set_locked(false);
            tracing::info!("edge control unlocked");
            eprintln!("THEKVM_STATUS local");
        } else {
            if let Some(session) = active.take() {
                let target = session.target;
                session.finish().await;
                release_suppression(&capture_control, Some(&mut *suppression_requested));
                *discarded_event_barrier = (*discarded_event_barrier)
                    .max(capture_control.snapshot().last_event_id);
                let _ = router.restore_local(target);
                let (x, y) = router.cursor_position();
                let _ = capture_control.warp_cursor(x, y);
            }
            // A lock is total: the parked stream goes too, so nothing
            // resumes under the lock.
            if let Some(stale) = parked.take() {
                stale.finish().await;
            }
            router.set_locked(true);
            tracing::info!("edge control locked to this computer");
            eprintln!("THEKVM_STATUS locked");
        }
        return Ok(());
    }
    let routed = router.route(captured.event);
    match routed {
        RoutedEvent::Local(event) => {
            // Scroll that arrives with nobody driven stays local (scroll
            // alone never opens a crossing): count it so the journal
            // distinguishes "hook is dead" from "scrolled while local".
            if matches!(
                event,
                InputEvent::Wheel(_) | InputEvent::SmoothWheel { .. }
            ) {
                *local_wheel_dropped += 1;
            }
            // A compositor portal may have activated a barrier even when the
            // topology has no neighbor on that edge. Release it so the local
            // compositor can continue receiving pointer motion.
            capture_control.release_capture()?;
        }
        RoutedEvent::Forward { target, event } => {
            let Some(session) = active.as_mut() else {
                let _ = router.restore_local(target);
                let (x, y) = router.cursor_position();
                let _ = capture_control.warp_cursor(x, y);
                return Ok(());
            };
            if session.target != target {
                bail!("topology router/session target mismatch");
            }
            // Sub-detent touchpad motion with nothing whole to report yet
            // stays silent (the remainder is kept): an older peer must never
            // see raw 120ths, and sending zeroes would only waste the wire.
            // Census: proves per session what the hook captured vs what the
            // peer accepted, so a silent scroll drop is diagnosable from the
            // journal instead of a mystery (captured counts arrivals here,
            // forwarded counts wire sends).
            match event {
                InputEvent::Wheel(_) => session.wheel_captured += 1,
                InputEvent::SmoothWheel { .. } => session.smooth_captured += 1,
                InputEvent::MouseMove { .. } => session.motion_captured += 1,
                _ => {}
            }
            let Some(outgoing) =
                outgoing_wheel_event(event, session.peer_smooth, &mut session.wheel_debt)
            else {
                return Ok(());
            };
            if matches!(
                outgoing,
                InputEvent::Wheel(_) | InputEvent::SmoothWheel { .. }
            ) {
                session.wheel_forwarded += 1;
            }
            let outgoing_is_motion = matches!(outgoing, InputEvent::MouseMove { .. });
            *sequence = sequence.wrapping_add(1);
            if let Err(error) =
                send_input(&session.connection, &mut session.send, *sequence, outgoing).await
            {
                // A dead episode ends the EPISODE, never the child: the
                // link (and the next crossing) survives a wobbly network.
                // This used to `return Err`, killing the whole child — one
                // dropped datagram ended every future crossing until the
                // UI noticed the exit and redialled.
                tracing::warn!(%error, "topology episode send failed; control is local");
                let session = active.take().expect("active session exists");
                let target = session.target;
                session.finish().await;
                // The association itself is suspect: drop the park too, so
                // the next push redials instead of resuming a dead stream.
                if let Some(stale) = parked.take() {
                    stale.finish().await;
                }
                release_suppression(&capture_control, Some(&mut *suppression_requested));
                *discarded_event_barrier = (*discarded_event_barrier)
                    .max(capture_control.snapshot().last_event_id);
                let _ = router.restore_local(target);
                let (x, y) = router.cursor_position();
                let _ = capture_control.warp_cursor(x, y);
                *last_failed_episode = Some(std::time::Instant::now());
                eprintln!("THEKVM_STATUS local");
            } else if outgoing_is_motion {
                session.motion_forwarded += 1;
            }
        }
        RoutedEvent::ReturnHome { from, edge } => {
            // Deskflow-style edge return: the virtual remote cursor came
            // back past the facing edge, so park the episode and re-enter
            // at the exact saved pixel — no network round trip, no
            // session death, no mid-screen landing. The stream stays open
            // (parked): the next push resumes it with one Handoff frame
            // instead of a dial. The transfer stamp doubles as MWB
            // lastJump debounce against instant re-exit.
            if let Some(session) = active.take() {
                if let Some(stale) = parked.replace(session) {
                    stale.finish().await;
                }
            }
            release_suppression(&capture_control, Some(&mut *suppression_requested));
            *discarded_event_barrier = (*discarded_event_barrier)
                .max(capture_control.snapshot().last_event_id);
            *last_transfer = Some(std::time::Instant::now());
            let (x, y) = router.cursor_position();
            let _ = capture_control.warp_cursor(x, y);
            // Armed-state telemetry: `armed=false` here is always a bug
            // (the router clamps unarmed overflows); `armed=true` means
            // the cursor settled inside and then brushed the boundary —
            // the specified return gesture, however surprising it feels
            // without edge feedback.
            let (entry_edge, armed) = router.return_state();
            tracing::info!(?from, ?edge, ?entry_edge, armed, x, y, "topology edge return; control is local");
            eprintln!("THEKVM_STATUS local");
        }
        RoutedEvent::Handoff {
            target,
            target_x,
            target_y,
            event,
            edge,
            ..
        } => {
            if active.is_some() {
                bail!("topology router attempted a second active handoff");
            }
            // Push-attempt telemetry: the router fired for this edge push.
            // If crossings silently never start, this line (or its absence
            // beside live capture) names the dead layer: no line with
            // motion flowing means the push never reached the router
            // (wrong edge/capture), while guard lines below mean the
            // router refused it (unlinked/debounce/cooldown).
            tracing::info!(?target, ?edge, target_x, target_y, "edge push reaches router; opening crossing");
            // MWB connected-guard: a linked child drives ONLY its verified
            // linked peer. Anything else is a stranger — clamp back local.
            if let Some(link) = link {
                let linked = router
                    .screen(target)
                    .and_then(|screen| screen.peer_fingerprint.as_deref())
                    == Some(link.fingerprint.as_str());
                if !linked {
                    tracing::debug!(?target, "edge faces an unlinked screen; staying local");
                    let _ = router.restore_local(target);
                    park_inside(router, edge);
                    return Ok(());
                }
            }
            // MWB lastJump debounce: let the last transfer settle first.
            if transfer_debounced(*last_transfer) {
                tracing::debug!(?target, ?edge, "edge push debounced after a transfer");
                let _ = router.restore_local(target);
                park_inside(router, edge);
                return Ok(());
            }
            // Cooldown after a failed episode: the cursor sits at the edge
            // pouring motion in, and every event would otherwise open a
            // full QUIC handshake — the dial storm that flapped control.
            // The user simply keeps pushing; a fresh crossing retries.
            if episode_cooling_down(*last_failed_episode) {
                tracing::debug!(?target, ?edge, "edge push in failed-episode cooldown");
                let _ = router.restore_local(target);
                park_inside(router, edge);
                return Ok(());
            }
            let snapshot = capture_control.snapshot();
            let opened_at = std::time::Instant::now();
            // Parked-stream reuse: a crossing on the live drive stream
            // costs one Handoff frame (~0ms on LAN), never a dial. Falls
            // back to a fresh episode when the park is stale or gone.
            let mut resumed = false;
            let mut session = match take_parked_for(parked, target).await {
                Some(parked_session) => {
                    match resume_parked_session(
                        parked_session,
                        router,
                        target,
                        target_x,
                        target_y,
                        snapshot.state.clone(),
                        Some(event),
                        initial_clipboard.clone(),
                        &mut *clipboard_revision,
                        &mut *sequence,
                        snapshot.last_event_id,
                    )
                    .await
                    {
                        Ok(resumed_session) => {
                            resumed = true;
                            Some(resumed_session)
                        }
                        Err(error) => {
                            tracing::debug!(%error, ?target, "parked drive stream went stale; opening a fresh episode");
                            None
                        }
                    }
                }
                None => None,
            };
            if session.is_none() {
                match open_topology_session(TopologyOpen {
                    router,
                    identity,
                    peers,
                    node_name,
                    target,
                    target_x,
                    target_y,
                    state: snapshot.state,
                    event_barrier: snapshot.last_event_id,
                    first_event: Some(event),
                    request_lock_screen,
                    mode,
                    local_geometry,
                    clipboard_enabled,
                    initial_clipboard,
                    clipboard_revision,
                    sequence,
                    dir,
                    link_id: link.and_then(|link| link.link_id),
                })
                .await
                {
                    Ok(opened) => session = Some(opened),
                    Err(error) => {
                        // A banned epoch is a deliberate remote Disconnect: end
                        // the child so the UI reports it, instead of warning
                        // locally and retrying a dead link forever.
                        if is_link_ended_rejection(&error) {
                            eprintln!(
                                "THEKVM_STATUS {}",
                                ban_ended_status(link.and_then(|link| link.link_id))
                            );
                            return Err(error);
                        }
                        *last_failed_episode = Some(std::time::Instant::now());
                        // Single release path (belief-aware): the reaper
                        // heals any hold that outlives this either way.
                        release_suppression(capture_control, Some(&mut *suppression_requested));
                        let _ = router.restore_local(target);
                        park_inside(router, edge);
                        tracing::warn!(%error, ?target, "topology target unavailable; control remains local");
                    }
                }
            }
            if let Some(session) = session {
                capture_control.set_exclusive(true)?;
                *suppression_requested = true;
                // Fresh episode: grace until the first Pong (see the
                // Progress signal); the watchdog enforces continued proof.
                *last_peer_progress = None;
                *unacked_pings = 0;
                *last_transfer = Some(std::time::Instant::now());
                *active = Some(session);
                let name = router
                    .screen(target)
                    .map(|screen| screen.name.clone())
                    .unwrap_or_else(|| format!("screen {}", target.0));
                // open_ms proves the crossing cost (a resumed park reads
                // ~0ms; a cold dial reads handshake + provisioning);
                // local_wheel names scroll that arrived while nobody was
                // driven.
                tracing::info!(?target, open_ms = opened_at.elapsed().as_millis(), resumed, local_wheel = *local_wheel_dropped, "topology handoff activated");
                // Handoff-open diagnostic: how far the OS pointer truth
                // stood from the exit edge at the crossing moment.
                // Near-zero = a genuine sustained push; far = virtual and
                // truth disagree (input scaling), never a feel complaint.
                if let Ok(Some((truth_x, truth_y))) =
                    kvm_platform::capture::current_cursor_position()
                {
                    if let Some(local) = router.layout().screen(router.local_screen()) {
                        let gap = match edge {
                            kvm_core::Edge::Left => truth_x as i64,
                            kvm_core::Edge::Right => {
                                i64::from(local.width.saturating_sub(1)) - truth_x as i64
                            }
                            kvm_core::Edge::Top => truth_y as i64,
                            kvm_core::Edge::Bottom => {
                                i64::from(local.height.saturating_sub(1)) - truth_y as i64
                            }
                        };
                        tracing::info!(?edge, truth_gap_px = gap, "topology handoff opened this far from the edge");
                    }
                }
                eprintln!("THEKVM_STATUS driving {name}");
            }
        }
    }
    Ok(())
}

struct TopologyOpen<'a> {
    router: &'a EdgeRouter,
    identity: &'a Identity,
    peers: &'a PeerBook,
    node_name: &'a str,
    target: ScreenId,
    target_x: u32,
    target_y: u32,
    state: InputState,
    event_barrier: u64,
    first_event: Option<InputEvent>,
    request_lock_screen: bool,
    mode: Mode,
    local_geometry: Option<ScreenGeometry>,
    clipboard_enabled: bool,
    initial_clipboard: Option<String>,
    clipboard_revision: &'a mut u64,
    sequence: &'a mut u64,
    dir: &'a std::path::Path,
    /// Administrative epoch both sides share (None for legacy children).
    link_id: Option<u64>,
}

async fn open_topology_session(request: TopologyOpen<'_>) -> Result<TopologySession> {
    let TopologyOpen {
        router,
        identity,
        peers,
        node_name,
        target,
        target_x,
        target_y,
        state,
        event_barrier,
        first_event,
        request_lock_screen,
        mode,
        local_geometry,
        clipboard_enabled,
        initial_clipboard,
        clipboard_revision,
        sequence,
        dir,
        link_id,
    } = request;
    let screen = router
        .screen(target)
        .context("topology target screen disappeared")?;
    let fingerprint = screen
        .peer_fingerprint
        .as_deref()
        .context("target screen has no paired peer fingerprint")?;
    let peer_name = screen.name.clone();
    let policy = ConnectPolicy {
        node_name,
        request_lock_screen,
        mode,
        clipboard_enabled,
        screen_geometry: local_geometry,
        link_id,
    };
    // Warm first: an episode on the live association skips endpoint setup
    // and the QUIC handshake, so the crossing feels instant. A stale
    // association falls back to a cold dial, which re-warms the pool. Only
    // a cold dial teaches us anything new about the peer's address (it
    // heals the book across DHCP moves); warm episodes skip re-resolving.
    let (conn, mut send, recv, capabilities, dialed_address) = match take_warm_link(fingerprint) {
        Some(warm) => match open_episode_stream(&warm, policy).await {
            Ok((send, recv, capabilities)) => {
                tracing::debug!(?target, "topology episode opened on the warm link");
                (warm, send, recv, capabilities, None)
            }
            Err(error) => {
                tracing::debug!(%error, ?target, "warm link episode failed; re-dialling");
                let (conn, send, recv, capabilities, address) =
                    cold_topology_dial(identity, peers, fingerprint, &peer_name, policy, dir)
                        .await?;
                (conn, send, recv, capabilities, Some(address))
            }
        },
        None => {
            let (conn, send, recv, capabilities, address) =
                cold_topology_dial(identity, peers, fingerprint, &peer_name, policy, dir).await?;
            (conn, send, recv, capabilities, Some(address))
        }
    };
    store_warm_link(&conn, fingerprint);
    if let Some(address) = dialed_address {
        if let Ok(presented) = peer_fingerprint(&conn) {
            note_peer_address(dir, &presented, &address);
        }
    }
    let clipboard_enabled = capabilities.clipboard_enabled;
    let (target_name, target_x, target_y, wire_geometry) = handoff_wire_target(
        router,
        target,
        target_x,
        target_y,
        capabilities
            .screen_geometry
            .filter(|geometry| geometry.screen_id == target.0),
    )?;
    write_frame(
        &mut send,
        &WireMessage::PointerHandoff {
            screen_id: target.0,
            target_name,
            x: target_x,
            y: target_y,
            screen_geometry: wire_geometry,
        },
    )
    .await?;
    send_state_sync(&mut send, state).await?;
    if clipboard_enabled {
        if let Some(text) = initial_clipboard {
            if text.len() <= kvm_protocol::wire::MAX_CLIPBOARD_TEXT_BYTES {
                *clipboard_revision = clipboard_revision.wrapping_add(1);
                write_frame(
                    &mut send,
                    &WireMessage::ClipboardText {
                        revision: *clipboard_revision,
                        text,
                    },
                )
                .await?;
            }
        }
    }
    let mut session = spawn_episode_driver(
        conn,
        send,
        recv,
        capabilities,
        target,
        event_barrier,
    );
    // Normalize the first event for this peer's scroll capability exactly
    // like every later event: an older peer gets detents, never raw 120ths
    // it would misread as hundreds of detents.
    let first_event = first_event
        .and_then(|event| outgoing_wheel_event(event, session.peer_smooth, &mut session.wheel_debt));
    if let Some(event) = first_event {
        *sequence = sequence.wrapping_add(1);
        // Keep the first post-handoff motion on the same ordered stream as
        // PointerHandoff. A datagram could otherwise race the stream frame
        // and be applied before the receiver knows which logical screen it
        // owns.
        write_frame(
            &mut session.send,
            &WireMessage::Input(InputPacket {
                sequence: *sequence,
                event,
            }),
        )
        .await?;
    }
    session.handed_off = true;
    Ok(session)
}

/// Policy every episode dial presents (fresh, reused, or pre-warmed): one
/// constructor so all three prove the same node, mode, clipboard, geometry
/// and link epoch.
fn episode_policy<'a>(
    config: &'a Config,
    link: Option<&'a TopologyLink>,
    local_geometry: Option<ScreenGeometry>,
) -> ConnectPolicy<'a> {
    ConnectPolicy {
        node_name: &config.device_name,
        request_lock_screen: config.allow_lock_screen_control,
        mode: config.mode,
        clipboard_enabled: config.clipboard_enabled,
        screen_geometry: local_geometry,
        link_id: link.and_then(|link| link.link_id),
    }
}

/// Take the parked drive stream when it already targets this screen and its
/// association is still alive. A stale park (wrong target, dead
/// association) is finished here — freeing the peer's input slot — so a
/// fresh episode follows instead of leaking a zombie.
async fn take_parked_for(
    parked: &mut Option<TopologySession>,
    target: ScreenId,
) -> Option<TopologySession> {
    let session = parked.take()?;
    if session.target == target && session.connection.close_reason().is_none() {
        return Some(session);
    }
    session.finish().await;
    None
}

/// Drive on an idle/pre-warmed or parked stream: Handoff + state + first
/// input go out on the ALREADY-ACCEPTED stream, so a crossing costs one
/// frame (~0ms on LAN), never a dial. Our fresh push wins: anything the
/// peer queued while parked is dropped before driving.
#[allow(clippy::too_many_arguments)]
async fn resume_parked_session(
    session: TopologySession,
    router: &EdgeRouter,
    target: ScreenId,
    target_x: u32,
    target_y: u32,
    state: InputState,
    first_event: Option<InputEvent>,
    initial_clipboard: Option<String>,
    clipboard_revision: &mut u64,
    sequence: &mut u64,
    event_barrier: u64,
) -> Result<TopologySession> {
    let mut session = session;
    while session.signals.try_recv().is_ok() {}
    session.event_barrier = event_barrier;
    let (target_name, target_x, target_y, wire_geometry) = handoff_wire_target(
        router,
        target,
        target_x,
        target_y,
        session
            .peer_geometry
            .filter(|geometry| geometry.screen_id == target.0),
    )?;
    write_frame(
        &mut session.send,
        &WireMessage::PointerHandoff {
            screen_id: target.0,
            target_name,
            x: target_x,
            y: target_y,
            screen_geometry: wire_geometry,
        },
    )
    .await?;
    send_state_sync(&mut session.send, state).await?;
    if session.clipboard_enabled {
        if let Some(text) = initial_clipboard {
            if text.len() <= kvm_protocol::wire::MAX_CLIPBOARD_TEXT_BYTES {
                *clipboard_revision = clipboard_revision.wrapping_add(1);
                write_frame(
                    &mut session.send,
                    &WireMessage::ClipboardText {
                        revision: *clipboard_revision,
                        text,
                    },
                )
                .await?;
            }
        }
    }
    let first_event = first_event
        .and_then(|event| outgoing_wheel_event(event, session.peer_smooth, &mut session.wheel_debt));
    if let Some(event) = first_event {
        *sequence = sequence.wrapping_add(1);
        // Same ordering rule as a fresh open: the first post-handoff
        // motion rides the stream, never a datagram.
        write_frame(
            &mut session.send,
            &WireMessage::Input(InputPacket {
                sequence: *sequence,
                event,
            }),
        )
        .await?;
    }
    session.handed_off = true;
    Ok(session)
}

/// Pre-warm the drive stream at edge-ready (always-ready parity): open one
/// episode stream on the live association BEFORE any crossing, so even the
/// first push costs one Handoff frame instead of a dial plus a
/// just-in-time receiver provisioning (uinput create + helpers). Silent on
/// failure — the first real push opens cold exactly as before.
#[allow(clippy::too_many_arguments)]
async fn prewarm_link_stream(
    identity: &Identity,
    peers: &PeerBook,
    config: &Config,
    router: &EdgeRouter,
    link: &TopologyLink,
    dir: &std::path::Path,
    local_geometry: Option<ScreenGeometry>,
) -> Result<Option<TopologySession>> {
    let screen = router.layout().screens.iter().find(|screen| {
        screen.peer_fingerprint.as_deref() == Some(link.fingerprint.as_str())
    });
    let Some(screen) = screen else {
        return Ok(None);
    };
    let target = screen.id;
    let policy = episode_policy(config, Some(link), local_geometry);
    let (conn, send, recv, capabilities) = match take_warm_link(&link.fingerprint) {
        Some(warm) => match open_episode_stream(&warm, policy).await {
            Ok((send, recv, capabilities)) => (warm, send, recv, capabilities),
            Err(error) => {
                // A ban on the warm link is final (peer re-epoch'd): fail
                // the child loudly instead of idling a zombie that can
                // never drive again.
                if is_link_ended_rejection(&error) {
                    return Err(error);
                }
                tracing::debug!(%error, "pre-warm on the warm link failed; dialling cold");
                match cold_topology_dial(identity, peers, &link.fingerprint, &screen.name, policy, dir).await {
                    Ok((conn, send, recv, capabilities, _)) => {
                        store_warm_link(&conn, &link.fingerprint);
                        (conn, send, recv, capabilities)
                    }
                    Err(error) => {
                        if is_link_ended_rejection(&error) {
                            return Err(error);
                        }
                        tracing::debug!(%error, "pre-warm cold dial failed");
                        return Ok(None);
                    }
                }
            }
        },
        None => {
            match cold_topology_dial(identity, peers, &link.fingerprint, &screen.name, policy, dir).await {
                Ok((conn, send, recv, capabilities, _)) => {
                    store_warm_link(&conn, &link.fingerprint);
                    (conn, send, recv, capabilities)
                }
                Err(error) => {
                    if is_link_ended_rejection(&error) {
                        return Err(error);
                    }
                    tracing::debug!(%error, "pre-warm cold dial failed");
                    return Ok(None);
                }
            }
        }
    };
    tracing::info!(?target, "link drive stream pre-warmed; first crossing needs no dial");
    Ok(Some(spawn_episode_driver(conn, send, recv, capabilities, target, 0)))
}

/// Map an edge-entry point into the peer's current geometry and name the
/// target screen. Shared by fresh opens and parked resumes so both land
/// identically — entry at the proportional edge point, never mid-screen.
fn handoff_wire_target(
    router: &EdgeRouter,
    target: ScreenId,
    target_x: u32,
    target_y: u32,
    peer_geometry: Option<ScreenGeometry>,
) -> Result<(String, u32, u32, Option<ScreenGeometry>)> {
    let screen = router
        .screen(target)
        .context("topology target screen disappeared")?;
    let target_geometry = ScreenGeometry {
        screen_id: target.0,
        width: screen.width,
        height: screen.height,
    };
    let (x, y, wire_geometry) = match peer_geometry {
        Some(peer_geometry) => {
            let (x, y) = remap_position(target_x, target_y, Some(target_geometry), peer_geometry);
            (x, y, Some(peer_geometry))
        }
        None => (
            target_x.min(target_geometry.width.saturating_sub(1)),
            target_y.min(target_geometry.height.saturating_sub(1)),
            None,
        ),
    };
    Ok((screen.name.clone(), x, y, wire_geometry))
}

/// Build a drive session around an already-accepted episode stream — a
/// fresh dial and a parked reuse converge here: response drain, capability
/// snapshot, quiet census. Handoff/state/first-input go out next (fresh
/// open sends them inline below; parked reuse sends them in
/// `resume_parked_session`).
fn spawn_episode_driver(
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    capabilities: SessionCapabilities,
    target: ScreenId,
    event_barrier: u64,
) -> TopologySession {
    let (signal_tx, signal_rx) = tokio::sync::mpsc::unbounded_channel();
    let response_drain = tokio::spawn(drain_peer_responses(recv, signal_tx));
    TopologySession {
        target,
        connection,
        send,
        signals: signal_rx,
        response_drain,
        event_barrier,
        clipboard_enabled: capabilities.clipboard_enabled,
        remote_clipboard_revision: 0,
        peer_smooth: capabilities.smooth_scroll,
        peer_geometry: capabilities.screen_geometry,
        handed_off: false,
        wheel_debt: WheelDowngrade::default(),
        wheel_captured: 0,
        smooth_captured: 0,
        wheel_forwarded: 0,
        motion_captured: 0,
        motion_forwarded: 0,
    }
}

/// Cold dial for one topology episode: resolve the peer's daemon address
/// and run the full TLS handshake. Successful episodes re-warm the link
/// pool (see `open_topology_session`); the address also heals the peer
/// book across DHCP moves.
async fn cold_topology_dial(
    identity: &Identity,
    peers: &PeerBook,
    fingerprint: &str,
    peer_name: &str,
    policy: ConnectPolicy<'_>,
    dir: &std::path::Path,
) -> Result<(
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    SessionCapabilities,
    String,
)> {
    let address = resolve_peer_address(peers, fingerprint, peer_name)?;
    let (conn, send, recv, capabilities) = dial_session(
        identity,
        peers,
        &address,
        policy,
        Some(fingerprint),
        dir,
    )
    .await?;
    Ok((conn, send, recv, capabilities, address))
}

async fn drain_peer_responses(
    mut recv: quinn::RecvStream,
    signal: tokio::sync::mpsc::UnboundedSender<RemoteSignal>,
) {
    while let Ok(Some(message)) = read_frame(&mut recv).await {
        match message {
            WireMessage::HandoffRequest {
                screen_id,
                target_name,
                x,
                y,
                dx,
                dy,
                screen_geometry,
            } => {
                let _ = signal.send(RemoteSignal::Handoff(RemoteHandoff {
                    screen_id,
                    target_name,
                    x,
                    y,
                    dx,
                    dy,
                    screen_geometry,
                }));
            }
            WireMessage::ClipboardText { revision, text } => {
                let _ = signal.send(RemoteSignal::Clipboard { revision, text });
            }
            WireMessage::Pong { .. } => {
                let _ = signal.send(RemoteSignal::Progress);
            }
            WireMessage::Reject { .. } => break,
            _ => {}
        }
    }
    let _ = signal.send(RemoteSignal::Closed);
}

fn start_capture(
    exclusive: bool,
    prefer_wayland: bool,
) -> Result<(
    tokio::sync::mpsc::Receiver<CapturedEvent>,
    tokio::sync::mpsc::Receiver<CapturedEvent>,
    CaptureGuard,
)> {
    let mut capture = kvm_platform::capture::create_capture(prefer_wayland, exclusive)?;
    capture
        .set_exclusive(exclusive)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    // Key/button transitions must not be dropped, but an unbounded queue
    // would let a stalled peer consume all memory. A bounded reliable queue
    // applies backpressure only to the capture worker until the receiver is
    // closed; motion remains lossy in its separate bounded channel.
    let (priority_tx, priority_rx) = tokio::sync::mpsc::channel::<CapturedEvent>(256);
    let (motion_tx, motion_rx) = tokio::sync::mpsc::channel::<CapturedEvent>(256);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = stop.clone();
    let requested_exclusive = Arc::new(std::sync::atomic::AtomicBool::new(exclusive));
    let thread_exclusive = requested_exclusive.clone();
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_release = release.clone();
    let state = Arc::new(std::sync::Mutex::new(CapturedState::default()));
    let thread_state = state.clone();
    let thread = std::thread::Builder::new()
        .name("thekvm-input-capture".into())
        .spawn(move || {
            // A capture backend can die mid-link (an X11 grab rejected
            // while a menu holds one, a torn-down hook thread, ...):
            // rebuild it with backoff instead of killing the child, so a
            // transient platform flake costs a beat, not the link. Event
            // ids stay monotonic across rebuilds (shared state), so
            // barriers never discard the resumed stream. Past a burst of
            // consecutive failures the backend is really gone: exit, so
            // the channels close and the child bails for a fresh redial.
            let mut backend = Some(capture);
            let mut failures = 0u32;
            let mut last_warn: Option<std::time::Instant> = None;
            'capture: loop {
                if thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                    break 'capture;
                }
                let Some(active) = backend.as_mut() else {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    match kvm_platform::capture::create_capture(prefer_wayland, false) {
                        Ok(rebuilt) => {
                            backend = Some(rebuilt);
                            continue;
                        }
                        Err(error) => {
                            failures += 1;
                            tracing::debug!(%error, failures, "input capture rebuild failed");
                            if failures > 20 {
                                tracing::warn!(
                                    failures,
                                    "input capture backend keeps failing; stopping capture"
                                );
                                break 'capture;
                            }
                            continue;
                        }
                    }
                };
                let event =
                    match active.next_event(&thread_stop, &thread_exclusive, &thread_release) {
                        Ok(event) => {
                            failures = 0;
                            event
                        }
                        Err(error) => {
                            if thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                                break 'capture;
                            }
                            failures += 1;
                            let due = last_warn.map_or(true, |when| {
                                when.elapsed() > std::time::Duration::from_secs(30)
                            });
                            if due {
                                last_warn = Some(std::time::Instant::now());
                                tracing::warn!(%error, failures, "input capture backend failed; rebuilding");
                            }
                            backend = None;
                            if failures > 20 {
                                tracing::warn!(
                                    failures,
                                    "input capture backend keeps failing; stopping capture"
                                );
                                break 'capture;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(500));
                            continue;
                        }
                    };
                let captured = match thread_state.lock() {
                    Ok(mut state) => {
                        let Some(captured) = state.record(event) else {
                            // Hook backends can repeat a key-down while the
                            // key is held. The receiver's OS performs repeat
                            // itself, so forwarding duplicate transitions
                            // only adds queue pressure and state ambiguity.
                            continue;
                        };
                        captured
                    }
                    Err(_) => CapturedEvent { event, event_id: 0 },
                };
                // Never let a stalled network session block the OS hook or
                // evdev reader indefinitely. Motion/wheel events are safely
                // lossy under backpressure; key and button transitions are
                // reliable within the bounded queue so their state cannot be
                // silently corrupted by a busy network.
                if matches!(event, InputEvent::Key(_) | InputEvent::MouseButton { .. }) {
                    if priority_tx.blocking_send(captured).is_err() {
                        break 'capture;
                    }
                    continue;
                }
                if motion_tx.try_send(captured).is_err() && motion_tx.is_closed() {
                    break 'capture;
                }
            }
            if let Some(active) = backend.as_mut() {
                let _ = active.set_exclusive(false);
            }
        })
        .context("start capture thread")?;
    Ok((
        priority_rx,
        motion_rx,
        CaptureGuard {
            stop,
            exclusive: requested_exclusive,
            release,
            state,
            join: Some(thread),
        },
    ))
}

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
struct ClipboardAgent {
    changes: tokio::sync::watch::Receiver<Option<String>>,
    commands: std::sync::mpsc::Sender<String>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
struct ClipboardAgent;

fn start_clipboard_agent(enabled: bool) -> Option<ClipboardAgent> {
    if !enabled {
        return None;
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
    {
        let (change_tx, changes) = tokio::sync::watch::channel(None::<String>);
        let (command_tx, command_rx) = std::sync::mpsc::channel::<String>();
        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_stop = stop.clone();
        let join = std::thread::Builder::new()
            .name("thekvm-clipboard-agent".into())
            .spawn(move || {
                let mut clipboard = match kvm_platform::clipboard::SystemClipboard::create() {
                    Ok(clipboard) => {
                        let _ = init_tx.send(Ok(()));
                        clipboard
                    }
                    Err(error) => {
                        let message = error.to_string();
                        let _ = init_tx.send(Err(message.clone()));
                        tracing::debug!(error = %message, "normal-session clipboard synchronization unavailable");
                        return;
                    }
                };
                while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                    while let Ok(text) = command_rx.try_recv() {
                        if let Err(error) = clipboard.set_text(text) {
                            tracing::debug!(%error, "cannot apply remote clipboard text");
                        }
                    }
                    match clipboard.poll_changed() {
                        Ok(Some(text)) => {
                            let _ = change_tx.send(Some(text));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            tracing::debug!(%error, "cannot poll system clipboard");
                        }
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            })
            .ok()?;
        match init_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "normal-session clipboard synchronization unavailable");
                let _ = join.join();
                return None;
            }
            Err(_) => {
                let _ = join.join();
                return None;
            }
        }
        Some(ClipboardAgent {
            changes,
            commands: command_tx,
            stop,
            join: Some(join),
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
    {
        let _ = enabled;
        None
    }
}

impl ClipboardAgent {
    async fn recv(&mut self) -> Option<String> {
        if self.changes.changed().await.is_err() {
            return None;
        }
        self.changes.borrow().clone()
    }

    fn apply_remote(&self, text: String) -> Result<()> {
        self.commands
            .send(text)
            .map_err(|error| anyhow::anyhow!("clipboard agent stopped: {error}"))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
impl ClipboardAgent {
    async fn recv(&mut self) -> Option<String> {
        std::future::pending().await
    }

    fn apply_remote(&self, _text: String) -> Result<()> {
        Ok(())
    }
}

impl Drop for ClipboardAgent {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
        {
            self.stop.store(true, std::sync::atomic::Ordering::Release);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }
}

async fn receive_clipboard(
    clipboard: &mut Option<ClipboardAgent>,
    enabled: bool,
) -> Option<String> {
    if !enabled {
        return std::future::pending().await;
    }
    let agent = clipboard.as_mut()?;
    agent.recv().await
}

struct CaptureGuard {
    stop: Arc<std::sync::atomic::AtomicBool>,
    exclusive: Arc<std::sync::atomic::AtomicBool>,
    release: Arc<std::sync::atomic::AtomicBool>,
    state: Arc<std::sync::Mutex<CapturedState>>,
    join: Option<std::thread::JoinHandle<()>>,
}

#[derive(Debug, Clone, Copy)]
struct CapturedEvent {
    event: InputEvent,
    event_id: u64,
}

#[derive(Debug, Clone, Default)]
struct CaptureSnapshot {
    state: InputState,
    last_event_id: u64,
}

#[derive(Default)]
struct CapturedState {
    last_event_id: u64,
    keys: std::collections::BTreeSet<HidUsage>,
    buttons: std::collections::BTreeSet<MouseButton>,
}

impl CapturedState {
    fn record(&mut self, event: InputEvent) -> Option<CapturedEvent> {
        let changed = match event {
            InputEvent::Key(key) => {
                if key.pressed {
                    self.keys.insert(key.usage)
                } else {
                    self.keys.remove(&key.usage)
                }
            }
            InputEvent::MouseButton { button, pressed } => {
                if pressed {
                    self.buttons.insert(button)
                } else {
                    self.buttons.remove(&button)
                }
            }
            InputEvent::MouseMove { .. } | InputEvent::Wheel(_) | InputEvent::SmoothWheel { .. } => true,
        };
        if !changed {
            return None;
        }
        self.last_event_id = self.last_event_id.wrapping_add(1);
        CapturedEvent {
            event,
            event_id: self.last_event_id,
        }
        .into()
    }

    fn snapshot(&self) -> CaptureSnapshot {
        CaptureSnapshot {
            state: InputState {
                pressed_keys: self.keys.iter().copied().collect(),
                pressed_buttons: self.buttons.iter().copied().collect(),
            },
            last_event_id: self.last_event_id,
        }
    }
}

impl CaptureGuard {
    fn set_exclusive(&self, enabled: bool) -> Result<()> {
        self.exclusive
            .store(enabled, std::sync::atomic::Ordering::Release);
        kvm_platform::capture::set_exclusive(enabled);
        Ok(())
    }

    fn release_capture(&self) -> Result<()> {
        self.release
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn warp_cursor(&self, x: u32, y: u32) -> Result<()> {
        kvm_platform::capture::warp_cursor(x, y).map_err(anyhow::Error::from)
    }

    fn snapshot(&self) -> CaptureSnapshot {
        self.state
            .lock()
            .map(|state| state.snapshot())
            .unwrap_or_default()
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.exclusive
            .store(false, std::sync::atomic::Ordering::Release);
        self.release
            .store(true, std::sync::atomic::Ordering::Release);
        kvm_platform::capture::set_exclusive(false);
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_capture_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    priority_rx: &mut tokio::sync::mpsc::Receiver<CapturedEvent>,
    motion_rx: &mut tokio::sync::mpsc::Receiver<CapturedEvent>,
    event_barrier: u64,
    clipboard: &mut Option<ClipboardAgent>,
    clipboard_enabled: bool,
    clipboard_revision: &mut u64,
    peer_smooth: bool,
) -> Result<()> {
    // The receiver replies to pings on the same bidirectional stream. Drain
    // that direction so the QUIC receive window cannot fill during a long
    // capture session.
    let (remote_closed_tx, mut remote_closed_rx) = tokio::sync::oneshot::channel();
    let (remote_message_tx, mut remote_message_rx) =
        tokio::sync::mpsc::unbounded_channel::<WireMessage>();
    let response_drain = tokio::spawn(async move {
        let mut recv = recv;
        while let Ok(Some(message)) = read_frame(&mut recv).await {
            match message {
                WireMessage::ClipboardText { .. } => {
                    if remote_message_tx.send(message).is_err() {
                        break;
                    }
                }
                WireMessage::Reject { .. } => break,
                _ => {}
            }
        }
        let _ = remote_closed_tx.send(());
    });

    tracing::info!("capturing input; press Ctrl+C to stop");
    let mut sequence = 0u64;
    let mut clipboard_enabled = clipboard_enabled;
    let mut remote_clipboard_revision = 0u64;
    let mut wheel_debt = WheelDowngrade::default();
    let mut keep_alive = tokio::time::interval(Duration::from_secs(5));
    keep_alive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result: Result<()> = loop {
        tokio::select! {
            biased;
            event = priority_rx.recv() => match event {
                Some(captured) if captured.event_id <= event_barrier => continue,
                Some(captured) => {
                    // ScrollLock restores local control immediately
                    // (consumed, never forwarded): the only key that can
                    // break a fullscreen takeover from the inside.
                    if is_scroll_lock_press(&captured.event) {
                        tracing::info!("ScrollLock pressed; restoring local control");
                        eprintln!("THEKVM_STATUS ended ScrollLock pressed — local control restored");
                        break Ok(());
                    }
                    sequence = sequence.wrapping_add(1);
                    if let Err(error) = write_frame(&mut send, &WireMessage::Input(InputPacket { sequence, event: captured.event })).await {
                        break Err(error.into());
                    }
                }
                None => break Err(anyhow::anyhow!("priority input capture stopped")),
            },
            event = motion_rx.recv() => match event {
                Some(captured) if captured.event_id <= event_barrier => continue,
                Some(captured) => {
                    let Some(outgoing) =
                        outgoing_wheel_event(captured.event, peer_smooth, &mut wheel_debt)
                    else {
                        continue;
                    };
                    sequence = sequence.wrapping_add(1);
                    if let Err(error) = send_input(&connection, &mut send, sequence, outgoing).await {
                        break Err(error);
                    }
                }
                None => break Err(anyhow::anyhow!("input capture stopped")),
            },
            text = receive_clipboard(clipboard, clipboard_enabled) => match text {
                Some(text) => {
                    if text.len() > kvm_protocol::wire::MAX_CLIPBOARD_TEXT_BYTES {
                        tracing::debug!(bytes = text.len(), "skipping oversized clipboard text");
                        continue;
                    }
                    *clipboard_revision = clipboard_revision.wrapping_add(1);
                    if let Err(error) = write_frame(
                        &mut send,
                        &WireMessage::ClipboardText {
                            revision: *clipboard_revision,
                            text,
                        },
                    )
                    .await
                    {
                        break Err(error.into());
                    }
                }
                None => clipboard_enabled = false,
            },
            remote = remote_message_rx.recv() => match remote {
                Some(WireMessage::ClipboardText { revision, text })
                    if clipboard_enabled && revision > remote_clipboard_revision =>
                {
                    remote_clipboard_revision = revision;
                    if let Some(agent) = clipboard.as_ref() {
                        agent.apply_remote(text)?;
                    }
                }
                Some(_) => {}
                None => break Err(anyhow::anyhow!("peer clipboard stream closed")),
            },
            _ = keep_alive.tick() => {
                if let Err(error) = write_frame(&mut send, &WireMessage::Ping { nonce: sequence }).await {
                    break Err(error.into());
                }
            }
            _ = &mut remote_closed_rx => {
                break Err(anyhow::anyhow!("peer closed the input session"));
            }
            _ = tokio::signal::ctrl_c() => {
                break Ok(());
            }
        }
    };

    // Cleanup is best-effort on a broken transport, but is always attempted
    // before the stream is closed so a normal stop cannot leave held input.
    let release_result = write_frame(&mut send, &WireMessage::ReleaseAll).await;
    let finish_result = send.finish();
    response_drain.abort();
    result?;
    release_result?;
    finish_result?;
    Ok(())
}

pub async fn run() -> Result<()> {
    let dir = data_dir();
    // Station-side edge control runs as the desktop user (same machine,
    // service group): it must READ the system identity and peer book to
    // dial with the identity the peers already trust. Access is only ever
    // ADDED for the group (never removed from anyone): owner keeps full
    // control, the group gains read (+traverse on the directory). Sockets
    // and the audit trail keep their own tighter permissions (handled where
    // created).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(&dir) {
            let mode = metadata.permissions().mode() | 0o050;
            if let Err(error) =
                std::fs::set_permissions(&dir, PermissionsExt::from_mode(mode))
            {
                tracing::warn!(path = %dir.display(), %error, "cannot add daemon directory group access");
            }
        }
        for file in ["identity.key", "peers.json", "config.json"] {
            let path = dir.join(file);
            if let Ok(metadata) = std::fs::metadata(&path) {
                let mode = metadata.permissions().mode() | 0o040;
                if let Err(error) =
                    std::fs::set_permissions(&path, PermissionsExt::from_mode(mode))
                {
                    tracing::warn!(path = %path.display(), %error, "cannot add daemon file group access");
                }
            }
        }
    }
    let config_path = dir.join("config.json");
    let mut config = if config_path.exists() {
        Config::load(&config_path).context("loading config")?
    } else {
        let config = Config::default();
        config
            .save(&config_path)
            .context("writing default config")?;
        config
    };
    // A station that calls itself "unknown" poisons every pairing screen
    // ("Does unknown show the code…?"). Fresh installs that never received
    // an explicit name inherit the OS host name once, persisted, so later
    // role presses (read-modify-write) keep it instead of echoing "unknown".
    if config.device_name.trim().is_empty()
        || config.device_name.trim().eq_ignore_ascii_case("unknown")
    {
        if let Some(host) = os_host_name() {
            tracing::info!(from = %config.device_name, to = %host, "adopting host name as device name");
            config.device_name = host;
            if let Err(error) = config.save(&config_path) {
                tracing::warn!(%error, "cannot persist adopted device name");
            }
        }
    }
    // Real local geometry at startup (Deskflow getShape parity): every
    // Accepted/Hello advertisement and entry remap derives from this
    // layout. Sessionful daemons measure directly; headless ones keep
    // fallback until a child publishes the sidecar (see
    // truthful_local_geometry).
    if let Ok(size) = kvm_platform::capture::screen_size() {
        if let Some((width, height)) = size {
            let local = config
                .layout
                .self_screen
                .or_else(|| config.layout.screens.first().map(|screen| screen.id));
            if let Some(id) = local {
                if config.layout.set_screen_size(id, width, height) {
                    tracing::info!(width, height, "daemon measured local geometry");
                }
            }
        }
    }

    let identity = Identity::load_or_create(&dir).context("creating identity")?;
    let listen_port = config.listen_port;
    let fingerprint = identity.fingerprint_hex();
    tracing::info!(fingerprint = %fingerprint, port = listen_port, "starting daemon");
    tracing::info!(mode = ?config.mode, device = %config.device_name, "loaded daemon config");
    let peers = PeerBook::load_or_create(&dir).context("loading peer book")?;
    let peers = Arc::new(tokio::sync::RwLock::new(peers));
    let configured_node_name = config.device_name.clone();
    let config = Arc::new(tokio::sync::RwLock::new(config));
    let (revoked_peers, _) = tokio::sync::broadcast::channel::<String>(16);
    let pairing_approvals = crate::control::PairingApprovals::default();
    let endpoint = transport::make_server_endpoint(&identity, listen_port)?;
    tracing::info!(port = listen_port, "listening for QUIC connections");
    spawn_discovery_responder(identity.clone(), listen_port, configured_node_name);

    #[cfg(target_os = "windows")]
    if std::env::args().any(|argument| argument == "--service") {
        let controller_config = config.read().await.clone();
        if let Some(address) = controller_config.auto_connect_address {
            let controller_identity = identity.clone();
            let controller_peers = peers.clone();
            let controller_revoked_peers = revoked_peers.clone();
            tokio::spawn(async move {
                if let Err(error) = run_windows_service_controller(
                    controller_identity,
                    controller_peers,
                    controller_revoked_peers,
                    address,
                    controller_config.device_name.clone(),
                    controller_config.allow_lock_screen_control,
                    controller_config.mode,
                    local_screen_geometry(&controller_config.layout),
                )
                .await
                {
                    tracing::warn!(%error, "Windows service controller stopped");
                }
            });
        }
    }

    let control_config = config.clone();
    let control_peers = peers.clone();
    let control_dir = dir.clone();
    let control_fingerprint = fingerprint.clone();
    let started = Arc::new(Instant::now());
    let active_sessions = Arc::new(AtomicUsize::new(0));
    let control_active_sessions = active_sessions.clone();
    let control_started = started.clone();
    let audit_dir = dir.clone();
    // A receiver has one deterministic input owner at a time. Pairing and
    // discovery are still allowed concurrently, but two live controllers must
    // not race key/button state through the same virtual devices.
    let input_session_slot = Arc::new(tokio::sync::Semaphore::new(1));
    let control_revoked_peers = revoked_peers.clone();
    let control_pairing_approvals = pairing_approvals.clone();
    let control_log_dir = dir.clone();
    tokio::spawn(async move {
        control_lifecycle_log(&control_log_dir, "control server starting");
        match crate::control::run_server(
            control_dir,
            control_config,
            control_peers,
            control_active_sessions,
            control_fingerprint,
            control_started,
            control_revoked_peers,
            control_pairing_approvals,
        )
        .await
        {
            Ok(()) => control_lifecycle_log(&control_log_dir, "control server stopped cleanly"),
            Err(error) => {
                tracing::warn!(%error, "local daemon control server stopped");
                control_lifecycle_log(
                    &control_log_dir,
                    &format!("control server FAILED: {error:#}"),
                );
            }
        }
    });

    let process_signal = process_shutdown_signal();
    tokio::pin!(process_signal);
    loop {
        tokio::select! {
            _ = shutdown_notifier().notified() => {
                endpoint.close(0u32.into(), b"daemon shutdown");
                return Ok(());
            }
            _ = &mut process_signal => {
                shutdown_notifier().notify_waiters();
                endpoint.close(0u32.into(), b"daemon shutdown");
                return Ok(());
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { return Ok(()) };
                let peers = peers.clone();
                let config = config.clone();
                let audit_dir = audit_dir.clone();
                let input_session_slot = input_session_slot.clone();
                let revoked_peers = revoked_peers.clone();
                let pairing_approvals = pairing_approvals.clone();
                let active_sessions = active_sessions.clone();
                tokio::spawn(async move {
                    active_sessions.fetch_add(1, Ordering::Relaxed);
                    match incoming.await {
                        Ok(conn) => {
                            let remote = conn.remote_address();
                            if let Err(error) = handle_connection(
                                conn,
                                peers,
                                config,
                                &audit_dir,
                                input_session_slot,
                                revoked_peers,
                                pairing_approvals,
                            )
                            .await
                            {
                                tracing::warn!(%remote, %error, "connection closed with error");
                            }
                        }
                        Err(error) => tracing::warn!(%error, "QUIC handshake failed"),
                    }
                    active_sessions.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }
}

fn spawn_discovery_responder(identity: Identity, listen_port: u16, node_name: String) {
    tokio::spawn(async move {
        let socket = match tokio::net::UdpSocket::bind((
            std::net::Ipv4Addr::UNSPECIFIED,
            kvm_protocol::discovery::DISCOVERY_PORT,
        ))
        .await
        {
            Ok(socket) => socket,
            Err(error) => {
                tracing::warn!(%error, "LAN discovery responder unavailable");
                return;
            }
        };
        let advertisement = match kvm_protocol::discovery::encode_advertisement(
            &kvm_protocol::discovery::Advertisement {
                node_name,
                listen_port,
                fingerprint_hex: identity.fingerprint_hex(),
            },
        ) {
            Ok(advertisement) => advertisement,
            Err(error) => {
                tracing::warn!(%error, "cannot encode LAN discovery advertisement");
                return;
            }
        };
        let mut buffer = [0u8; 128];
        loop {
            let (length, source) = tokio::select! {
                _ = shutdown_notifier().notified() => return,
                received = socket.recv_from(&mut buffer) => match received {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::warn!(%error, "LAN discovery responder stopped");
                        return;
                    }
                },
            };
            if kvm_protocol::discovery::is_request(&buffer[..length]) {
                let _ = socket.send_to(&advertisement, source).await;
            }
        }
    });
}

async fn handle_connection(
    conn: quinn::Connection,
    peers: Arc<tokio::sync::RwLock<PeerBook>>,
    config: Arc<tokio::sync::RwLock<Config>>,
    audit_dir: &std::path::Path,
    input_session_slot: Arc<tokio::sync::Semaphore>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    pairing_approvals: crate::control::PairingApprovals,
) -> Result<()> {
    let peer_fingerprint = peer_fingerprint(&conn)?;
    // One association, many episodes (Deskflow persistent-socket parity):
    // every bidirectional stream on this connection is dispatched on its
    // own — pairing once, then one input episode per stream — so a link
    // costs one handshake and each crossing costs one stream open
    // (milliseconds on LAN), never a cold dial. A bad stream ends that
    // stream, never the association.
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            // The peer went away (child exited, network dropped): nothing
            // left to serve on this association.
            Err(_) => return Ok(()),
        };
        let mut revoked_rx = revoked_peers.subscribe();
        let first = match read_frame(&mut recv).await {
            Ok(Some(frame)) => frame,
            // A stream that dies before saying hello is just gone; the
            // next stream on the live association still gets served.
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(%error, "episode stream died before hello");
                continue;
            }
        };
        let local_config = config.read().await.clone();

        match first {
        WireMessage::PairRequest {
            node_name,
            fingerprint_hex,
            pairing_code,
        } => {
            handle_pairing(
                &conn,
                &mut send,
                &mut recv,
                peers.clone(),
                &peer_fingerprint,
                pairing_approvals.clone(),
                PairingRequest {
                    local_node_name: local_config.device_name.clone(),
                    node_name,
                    claimed_fingerprint: fingerprint_hex,
                    pairing_code,
                },
            )
            .await?;
        }
        WireMessage::Hello(hello) => {
            // Per-stream containment: this async block is a return
            // boundary, so `bail!`, `return` and `?` end THIS episode
            // with a logged reason while the association loop above keeps
            // serving later streams.
            let stream_result: Result<()> = async {
            let config = local_config;
            if !peers.read().await.is_pinned(&peer_fingerprint) {
                reject(&mut send, "peer is not paired").await?;
                bail!("untrusted peer fingerprint {peer_fingerprint}");
            }
            // A banned epoch is a deliberate local Disconnect: reject the
            // stale redial so the dead link stays dead instead of
            // resurrecting as a zombie. The dialer's child exits on this
            // (it never retries a ban).
            if hello.link_id.is_some_and(link_ended) {
                reject(
                    &mut send,
                    "link ended by this computer; press Connect for a fresh link",
                )
                .await?;
                audit_event(
                    audit_dir,
                    &format!(
                        "session-rejected peer={peer_fingerprint} remote={} reason=link_ended",
                        conn.remote_address(),
                    ),
                );
                bail!("peer dialed banned link epoch {:?}", hello.link_id);
            }
            if !mode_allows_incoming(config.mode) {
                reject(&mut send, "this node is configured as controller-only").await?;
                bail!("incoming control is disabled by controller-only mode");
            }
            if !mode_allows_outgoing(hello.mode) {
                reject(&mut send, "peer is configured as receiver-only").await?;
                bail!("peer cannot initiate control from receiver-only mode");
            }
            // Effective grant: requested AND allowed. A downgrade (peer
            // asked, we did not opt in) stays an ordinary desktop session
            // instead of a rejection, so reverse control survives a
            // one-sided checkbox — with an audit line saying exactly that.
            let lock_screen_enabled =
                match validate_input_capability(&config, hello.lock_screen_requested) {
                    Ok(enabled) => enabled,
                    Err(error) => {
                        reject(&mut send, &error.to_string()).await?;
                        audit_event(
                            audit_dir,
                            &format!(
                                "session-rejected peer={peer_fingerprint} remote={} lock_screen_requested={} reason={error}",
                                conn.remote_address(),
                                hello.lock_screen_requested
                            ),
                        );
                        return Err(error);
                    }
                };
            if hello.lock_screen_requested && !lock_screen_enabled {
                audit_event(
                    audit_dir,
                    &format!(
                        "session-downgraded peer={peer_fingerprint} remote={} reason=lock_screen_not_allowed_locally",
                        conn.remote_address(),
                    ),
                );
                tracing::info!(
                    peer = %peer_fingerprint,
                    "peer requested lock-screen input; not allowed here, continuing as ordinary desktop session",
                );
            }

            // The input slot is taken lazily at the first PointerHandoff
            // on this stream (see below), not here: a verify handshake
            // that never drives must not hold the single-driver slot and
            // starve the episode that follows it on this same association.
            let mut input_permit: Option<tokio::sync::OwnedSemaphorePermit> = None;

            let peer_screen_geometry = hello.screen_geometry;
            let local_geometry = truthful_local_geometry(&config.layout);
            let mut clipboard = if config.clipboard_enabled && hello.clipboard_enabled {
                start_clipboard_agent(true)
            } else {
                None
            };
            let mut clipboard_enabled = clipboard.is_some();
            // Provision the native receiver before advertising an accepted
            // session. Otherwise a missing /dev/uinput device or unavailable
            // Windows interactive helper can make the sender believe input is
            // live until the connection fails asynchronously.
            let mut injector = match ReceiverInjector::create(lock_screen_enabled)
                .context("create input injector")
            {
                Ok(injector) => injector,
                Err(error) => {
                    let reason = format!("receiver input unavailable: {error}");
                    let _ = reject(&mut send, &reason).await;
                    audit_event(
                        audit_dir,
                        &format!(
                            "session-rejected peer={peer_fingerprint} remote={} reason=receiver_input_unavailable",
                            conn.remote_address()
                        ),
                    );
                    return Err(error);
                }
            };
            write_frame(
                &mut send,
                &WireMessage::Accepted {
                    lock_screen_enabled,
                    clipboard_enabled,
                    screen_geometry: local_geometry,
                    // This daemon injects high-resolution touchpad scroll.
                    smooth_scroll: true,
                },
            )
            .await?;
            audit_event(
                audit_dir,
                &format!(
                    "session-accepted peer={peer_fingerprint} remote={} lock_screen_requested={} lock_screen_enabled={lock_screen_enabled}",
                    conn.remote_address(),
                    hello.lock_screen_requested
                ),
            );
            // Correlates with the sender's handoff line: an accept with no
            // motion after it means the peer died before driving (or never
            // drove), not that the handshake failed.
            tracing::info!(
                peer = %peer_fingerprint,
                remote = %conn.remote_address(),
                "input session accepted",
            );
            // Publish the live inbound link: the station-side UI arms its
            // own half of the link from here (it never dialed), and hangs
            // the link up from here too. The address MUST be dialable: the
            // socket's remote address is an ephemeral source port that
            // accepts no connections (dialling it back was why Both-ways
            // return control never worked), so prefer the peer book's saved
            // daemon address and otherwise the inbound IP on the standard
            // daemon port.
            let peer_book = peers.read().await;
            let (link_id, mut link_drop) = register_inbound_link(
                &peer_fingerprint,
                &hello.node_name,
                &dialable_peer_address(
                    &peer_book,
                    &peer_fingerprint,
                    &hello.node_name,
                    conn.remote_address(),
                ),
                hello.link_id,
            );
            drop(peer_book);
            // One face per machine: the verified live fingerprint retires
            // same-named ghosts (the service-cert vs user-cert split), so
            // the book converges instead of flapping.
            retire_ghost_identities(
                &peers,
                &data_dir(),
                &hello.node_name,
                &peer_fingerprint,
                audit_dir,
            )
            .await;
            // Panic-safe: the guard unregisters even when the session below
            // dies abnormally, so no ghost entry can fool the station UI.
            let _link_guard = InboundLinkGuard {
                fingerprint_hex: peer_fingerprint.clone(),
                id: link_id,
            };
            // Reverse-path pointer: our half is live, but WE can never dial
            // theirs — their UI must dial back (MWB arming). If the peer
            // never drives, this line plus their ui.log names the gate:
            // peer UI not running, peer in Be-controlled-only mode, or our
            // mode blocking incoming (controller-only).
            tracing::info!(
                peer = %peer_fingerprint,
                node = %hello.node_name,
                "inbound link live; waiting for the peer's dial-back for two-way edge",
            );
            let mut seen_sequences = BTreeSet::new();
            let mut motion_sequence = MotionSequence::default();
            let mut last_activity = Instant::now();
            // Why this session ended, for the census line below: a bare
            // motion/wheel/smooth count cannot tell "peer went away" from
            // "we killed it", and that distinction is the whole reverse-
            // direction diagnosis (Mint driving Windows dies in ms).
            let mut end_reason = "unknown";
            // Per-session input census for the end-of-session journal line:
            // proves what actually arrived (motion vs detent vs smooth).
            let mut motion_count = 0u64;
            let mut wheel_count = 0u64;
            let mut smooth_count = 0u64;
            // Receiver-side drop census: motion datagrams that arrived but
            // were discarded (duplicate sequence vs stale ordering). Logged
            // at session end next to motion_count, so "warp lands, cursor
            // never tracks" names its dropping line instead of guessing.
            let mut dropped_duplicate = 0u64;
            let mut dropped_stale = 0u64;
            let mut remote_screen = None;
            let mut remote_cursor = None;
            // Push-through run for the stateless receiver hop (same
            // EDGE_PUSH_PX the stateful router demands): one stray motion
            // datagram must never end the episode — sustained outward
            // overflow on one edge earns the HandoffRequest. Reset below
            // whenever motion comes back inside.
            let mut hop_edge: Option<kvm_core::Edge> = None;
            let mut hop_accum: i64 = 0;
            let mut clipboard_revision = 0u64;
            let mut remote_clipboard_revision = 0u64;
            let mut lease_check = tokio::time::interval(Duration::from_secs(5));
            lease_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let session_result: Result<()> = loop {
                tokio::select! {
                    message = read_frame(&mut recv) => {
                        let Some(message) = message.map_err(|error| {
                            end_reason = "stream read failed";
                            error
                        })? else {
                            end_reason = "peer finished the stream";
                            break Ok(());
                        };
                        last_activity = Instant::now();
                        injector.ensure_session()?;
                        match message {
                            WireMessage::StateSync(state) => {
                                sync_state(&state)?;
                                injector.sync_state(&state)?;
                            }
                            WireMessage::Input(packet) => {
                                match packet.event {
                                    InputEvent::MouseMove { .. } => motion_count += 1,
                                    InputEvent::Wheel(_) => wheel_count += 1,
                                    InputEvent::SmoothWheel { .. } => smooth_count += 1,
                                    _ => {}
                                }
                                if process_remote_input(
                                    DatagramInput {
                                        sequence: packet.sequence,
                                        event: packet.event,
                                    },
                                    &config,
                                    &mut injector,
                                    &mut send,
                                    &mut remote_screen,
                                    &mut remote_cursor,
                                    &mut seen_sequences,
                                    &mut motion_sequence,
                                    peer_screen_geometry,
                                    &mut hop_edge,
                                    &mut hop_accum,
                                    &mut dropped_duplicate,
                                    &mut dropped_stale,
                                )
                                .await?
                                {
                                    end_reason = "peer requested the session end";
                                    break Ok(());
                                }
                            }
                            WireMessage::PointerHandoff {
                                screen_id,
                                target_name,
                                x,
                                y,
                                screen_geometry,
                            } => {
                                // Lazy single-driver slot: the first handoff
                                // on this stream claims it; a second live
                                // driver is rejected on THIS stream (the
                                // association stays up for the next one).
                                // The permit lives until the stream ends.
                                if input_permit.is_none() {
                                    match input_session_slot.clone().try_acquire_owned() {
                                        Ok(permit) => input_permit = Some(permit),
                                        Err(_) => {
                                            reject(
                                                &mut send,
                                                "another input session already controls this node",
                                            )
                                            .await?;
                                            audit_event(
                                                audit_dir,
                                                &format!(
                                                    "session-rejected peer={peer_fingerprint} remote={} reason=input_session_busy",
                                                    conn.remote_address()
                                                ),
                                            );
                                            bail!("another input session already controls this node");
                                        }
                                    }
                                }
                                // Named acceptance: the sender names THIS
                                // machine, and names agree across machines.
                                // Local screen numbers never cross the wire
                                // as identity (one mirrored config broke
                                // every handoff in both directions).
                                let target = if !target_name.is_empty() {
                                    if target_name != config.device_name {
                                        bail!("peer handed off to '{target_name}', but this node is '{}'", config.device_name);
                                    }
                                    config.layout.self_screen.context(
                                        "handoff accepted by name but no local screen is arranged",
                                    )?
                                } else {
                                    let expected = config.layout.self_screen;
                                    if expected != Some(ScreenId(screen_id)) {
                                        bail!("peer handed off to screen {screen_id}, but this node is {:?}", expected);
                                    }
                                    ScreenId(screen_id)
                                };
                                let target_geometry = screen_geometry_for(&config.layout, target)
                                    .context("local screen geometry is unavailable")?;
                                let (x, y) = remap_position(
                                    x,
                                    y,
                                    screen_geometry,
                                    target_geometry,
                                );
                                remote_screen = Some(target);
                                remote_cursor = Some((x, y));
                                // Proves entry exactness per crossing: the OS
                                // cursor was just placed here, so a later
                                // "exited mid-screen" report can be checked
                                // against this line, not guessed about. A
                                // failed warp warns but never kills the
                                // episode — driving unplaced beats not
                                // driving at all.
                                match injector.warp_cursor(x, y) {
                                    Ok(()) => tracing::info!(x, y, "receiver placed cursor at entry"),
                                    Err(error) => tracing::warn!(%error, x, y, "receiver entry warp failed; cursor starts unplaced"),
                                }
                            }
                            WireMessage::ReleaseAll => injector.release_all()?,
                            WireMessage::Ping { nonce } => {
                                write_frame(&mut send, &WireMessage::Pong { nonce }).await?;
                            }
                            WireMessage::ClipboardText { revision, text }
                                if clipboard_enabled
                                    && revision > remote_clipboard_revision =>
                            {
                                remote_clipboard_revision = revision;
                                if let Some(agent) = clipboard.as_ref() {
                                    agent.apply_remote(text)?;
                                }
                            }
                            WireMessage::Pong { .. } => {}
                            _ => {}
                        }
                    }
                    datagram = conn.read_datagram() => {
                        let payload = datagram.map_err(|error| {
                            end_reason = "datagram read failed";
                            error
                        })?;
                        last_activity = Instant::now();
                        injector.ensure_session()?;
                        // QUIC datagrams are unordered and lossy by design: a
                        // corrupt or future-version datagram is dropped, never
                        // fatal. Killing the whole input session over one bad
                        // packet turned wire noise into visible control snaps.
                        let packet = match decode_input_datagram(&payload) {
                            Ok(packet) => packet,
                            Err(error) => {
                                tracing::debug!(%error, bytes = payload.len(), "dropping undecodable input datagram");
                                continue;
                            }
                        };
                        match packet.event {
                            InputEvent::MouseMove { .. } => motion_count += 1,
                            InputEvent::Wheel(_) => wheel_count += 1,
                            InputEvent::SmoothWheel { .. } => smooth_count += 1,
                            _ => {}
                        }
                        if process_remote_input(
                            packet,
                            &config,
                            &mut injector,
                            &mut send,
                            &mut remote_screen,
                            &mut remote_cursor,
                            &mut seen_sequences,
                            &mut motion_sequence,
                            peer_screen_geometry,
                            &mut hop_edge,
                            &mut hop_accum,
                            &mut dropped_duplicate,
                            &mut dropped_stale,
                        )
                        .await?
                        {
                            break Ok(());
                        }
                    }
                    text = receive_clipboard(&mut clipboard, clipboard_enabled) => match text {
                        Some(text) => {
                            if text.len() > kvm_protocol::wire::MAX_CLIPBOARD_TEXT_BYTES {
                                tracing::debug!(bytes = text.len(), "skipping oversized clipboard text");
                                continue;
                            }
                            clipboard_revision = clipboard_revision.wrapping_add(1);
                            write_frame(
                                &mut send,
                                &WireMessage::ClipboardText {
                                    revision: clipboard_revision,
                                    text,
                                },
                            )
                            .await?;
                        }
                        None => clipboard_enabled = false,
                    },
                    _ = lease_check.tick() => {
                        injector.ensure_session()?;
                        if last_activity.elapsed() > Duration::from_secs(15) {
                            end_reason = "input lease expired without activity";
                            break Err(anyhow::anyhow!(
                                "input session lease expired; released remote input"
                            ));
                        }
                    }
                    revoked = revoked_rx.recv() => {
                        if revoked
                            .as_ref()
                            .is_ok_and(|fingerprint| fingerprint == &peer_fingerprint)
                        {
                            end_reason = "trusted peer revoked mid-session";
                            break Err(anyhow::anyhow!(
                                "trusted peer was revoked during the input session"
                            ));
                        }
                    }
                    _ = async {
                        // Station hang-up: set by DropSession, read here.
                        // (`changed`, not `wait_for`: the watch Ref guard is
                        // not Send and this task is spawned.)
                        loop {
                            if *link_drop.borrow_and_update() {
                                break;
                            }
                            if link_drop.changed().await.is_err() {
                                break;
                            }
                        }
                    } => {
                        end_reason = "station user dropped the session";
                        tracing::info!(peer = %peer_fingerprint, "station user dropped the input session");
                        break Ok(());
                    }
                }
            };
            // The guard below unregisters (panic-safe); the census names
            // what actually arrived over the wire this session, WHY it
            // ended, and the error when it ended badly.
            tracing::info!(
                peer = %peer_fingerprint,
                motion = motion_count,
                wheel = wheel_count,
                smooth = smooth_count,
                dropped_duplicate,
                dropped_stale,
                reason = end_reason,
                error = session_result
                    .as_ref()
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_default(),
                "input session ended",
            );
            drop(_link_guard);
            if let Err(error) = session_result {
                let _ = injector.release_all();
                return Err(error);
            }
            injector.release_all()?;
            Ok(())
            }
            .await;
            if let Err(error) = stream_result {
                tracing::debug!(%error, "episode stream ended");
            }
        }
        other => {
            reject(&mut send, &format!("expected hello, received {other:?}")).await?;
            bail!("invalid first message")
        }
        } // match first: one pairing or one episode per stream
    } // association loop: streams share one handshake
}

#[allow(clippy::too_many_arguments)]
async fn process_remote_input(
    packet: DatagramInput,
    config: &Config,
    injector: &mut ReceiverInjector,
    send: &mut quinn::SendStream,
    remote_screen: &mut Option<ScreenId>,
    remote_cursor: &mut Option<(u32, u32)>,
    seen_sequences: &mut BTreeSet<u64>,
    motion_sequence: &mut MotionSequence,
    peer_screen_geometry: Option<ScreenGeometry>,
    hop_edge: &mut Option<kvm_core::Edge>,
    hop_accum: &mut i64,
    dropped_duplicate: &mut u64,
    dropped_stale: &mut u64,
) -> Result<bool> {
    if !seen_sequences.insert(packet.sequence) {
        *dropped_duplicate += 1;
        return Ok(false);
    }
    if matches!(
        packet.event,
        InputEvent::MouseMove { .. } | InputEvent::Wheel(_) | InputEvent::SmoothWheel { .. }
    ) && !motion_sequence.accept(packet.sequence)
    {
        // QUIC DATAGRAM is intentionally unordered and lossy. Applying an
        // older motion after a newer one can visibly move the cursor backward,
        // especially during a topology handoff, so stale motion is discarded.
        *dropped_stale += 1;
        return Ok(false);
    }
    while seen_sequences.len() > 4096 {
        let Some(oldest) = seen_sequences.first().copied() else {
            break;
        };
        seen_sequences.remove(&oldest);
    }
    if let (Some(screen_id), Some((x, y)), InputEvent::MouseMove { dx, dy }) =
        (*remote_screen, *remote_cursor, packet.event)
    {
        // Push-through parity with the stateful router: the old code asked
        // handoff_for_motion on EVERY motion step, so a single 1px virtual
        // overflow ended the episode — the "Mint exits while visibly far
        // from the edge" flap (virtual edge from wrong dims, echo, or one
        // stray datagram). Now the run must reach EDGE_PUSH_PX on one
        // edge before a HandoffRequest goes out; anything less clamps the
        // tracked cursor and keeps driving.
        let mut hop_ready = false;
        if let Some(screen) = config.layout.screen(screen_id) {
            match kvm_core::edge_overflow(screen.width, screen.height, x, y, dx, dy) {
                Some((edge, overflow)) => {
                    if *hop_edge == Some(edge) {
                        *hop_accum += overflow;
                    } else {
                        *hop_edge = Some(edge);
                        *hop_accum = overflow;
                    }
                    hop_ready = *hop_accum >= kvm_core::EDGE_PUSH_PX;
                }
                None => {
                    *hop_edge = None;
                    *hop_accum = 0;
                }
            }
        }
        if hop_ready {
            *hop_edge = None;
            *hop_accum = 0;
            if let Some(handoff) = config
                .layout
                .handoff_for_motion(screen_id, x, y, dx, dy, config.edge_mode)
            {
            let screen = config
                .layout
                .screen(screen_id)
                .context("remote pointer screen disappeared during handoff")?;
            let next_x = i64::from(x) + i64::from(dx);
            let next_y = i64::from(y) + i64::from(dy);
            let (remainder_dx, remainder_dy) = match handoff.edge {
                kvm_core::Edge::Left => (
                    next_x.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                    0,
                ),
                kvm_core::Edge::Right => (
                    (next_x - i64::from(screen.width - 1))
                        .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                    0,
                ),
                kvm_core::Edge::Top => (
                    0,
                    next_y.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                ),
                kvm_core::Edge::Bottom => (
                    0,
                    (next_y - i64::from(screen.height - 1))
                        .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                ),
            };
            let configured_target_geometry = screen_geometry_for(&config.layout, handoff.target)
                .context("handoff target screen disappeared")?;
            let target_name = config
                .layout
                .screen(handoff.target)
                .map(|screen| screen.name.clone())
                .unwrap_or_default();
            let (target_x, target_y, screen_geometry) = match peer_screen_geometry
                .filter(|geometry| geometry.screen_id == handoff.target.0)
            {
                Some(peer_geometry) => {
                    let (x, y) = remap_position(
                        handoff.target_x,
                        handoff.target_y,
                        Some(configured_target_geometry),
                        peer_geometry,
                    );
                    (x, y, Some(peer_geometry))
                }
                None => (handoff.target_x, handoff.target_y, None),
            };
            write_frame(
                send,
                &WireMessage::HandoffRequest {
                    screen_id: handoff.target.0,
                    target_name,
                    x: target_x,
                    y: target_y,
                    dx: remainder_dx,
                    dy: remainder_dy,
                    screen_geometry,
                },
            )
            .await?;
            return Ok(true);
            }
        }
        // Sub-threshold overflow lands here too: the tracked cursor pins
        // at the border (never past it) and the episode keeps driving.
        if let Some(screen) = config.layout.screen(screen_id) {
            let next_x =
                (i64::from(x) + i64::from(dx)).clamp(0, i64::from(screen.width - 1)) as u32;
            let next_y =
                (i64::from(y) + i64::from(dy)).clamp(0, i64::from(screen.height - 1)) as u32;
            *remote_cursor = Some((next_x, next_y));
        }
    }
    injector.send(packet.event)?;
    Ok(false)
}

/// Per-session 120ths remainder for peers that predate smooth scroll.
/// Touchpad motion below one detent is debt, not waste: it accumulates here
/// until a whole detent exists, so slow two-finger scrolling still arrives
/// (late and steppy) instead of vanishing entirely.
#[derive(Debug, Default)]
struct WheelDowngrade {
    x: i32,
    y: i32,
}

/// Map one captured event onto what this peer can receive. Smooth-capable
/// peers take everything as captured; older peers get `SmoothWheel`
/// downgraded to whole detents, and `None` while nothing whole exists yet
/// (the caller sends nothing and keeps the remainder). Pure so the
/// determinism is unit-tested.
fn outgoing_wheel_event(
    event: InputEvent,
    peer_smooth: bool,
    debt: &mut WheelDowngrade,
) -> Option<InputEvent> {
    if peer_smooth {
        return Some(event);
    }
    let InputEvent::SmoothWheel { x, y } = event else {
        return Some(event);
    };
    // Like the receiver's bank: NET accumulation, never dropped on
    // reversal. Trackpad sensors jitter sign under a slow finger, and
    // dropping the bank on every micro-flip starves legacy peers forever
    // (nothing whole ever exists). A deliberate turn spends the bank back
    // down — the honest physics. (Live peers are smooth and skip this
    // entirely; this is the legacy-detent path.) A zero axis carries no
    // information and must not touch the other axis's bank.
    debt.x = debt.x.saturating_add(x);
    debt.y = debt.y.saturating_add(y);
    // Truncation toward zero: a sub-detent remainder in either direction
    // waits, instead of firing early on one side (as Euclidean division
    // would for negative motion).
    let detents = WheelDelta {
        x: (debt.x / 120)
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        y: (debt.y / 120)
            .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
    };
    debt.x -= i32::from(detents.x) * 120;
    debt.y -= i32::from(detents.y) * 120;
    (detents.x != 0 || detents.y != 0).then_some(InputEvent::Wheel(detents))
}

/// Highest accepted sequence for unreliable pointer/wheel traffic. Reliable
/// key/button frames still use `seen_sequences` for duplicate suppression, but
/// motion needs an ordering check because QUIC DATAGRAM has no ordering
/// guarantee. Serial-number arithmetic keeps the check correct across the
/// eventual u64 sequence wrap.
#[derive(Debug, Default)]
struct MotionSequence {
    latest: Option<u64>,
}

impl MotionSequence {
    fn accept(&mut self, sequence: u64) -> bool {
        let accepted = self.latest.is_none_or(|latest| {
            let distance = sequence.wrapping_sub(latest);
            distance != 0 && distance < (1u64 << 63)
        });
        if accepted {
            self.latest = Some(sequence);
        }
        accepted
    }
}

const MAX_SYNC_KEYS: usize = 256;
const MAX_SYNC_BUTTONS: usize = 5;

fn sync_state(state: &InputState) -> Result<()> {
    if state.pressed_keys.len() > MAX_SYNC_KEYS {
        bail!(
            "state synchronization contains {} keys; maximum is {MAX_SYNC_KEYS}",
            state.pressed_keys.len()
        );
    }
    if state.pressed_buttons.len() > MAX_SYNC_BUTTONS {
        bail!(
            "state synchronization contains {} buttons; maximum is {MAX_SYNC_BUTTONS}",
            state.pressed_buttons.len()
        );
    }
    let keys = state.pressed_keys.iter().collect::<BTreeSet<_>>();
    if keys.len() != state.pressed_keys.len() {
        bail!("state synchronization contains duplicate keys");
    }
    let buttons = state.pressed_buttons.iter().collect::<BTreeSet<_>>();
    if buttons.len() != state.pressed_buttons.len() {
        bail!("state synchronization contains duplicate buttons");
    }
    Ok(())
}

enum ReceiverInjector {
    Native(Injector),
    #[cfg(target_os = "windows")]
    Service(ServiceInputProxy),
}

impl ReceiverInjector {
    fn create(lock_screen_requested: bool) -> Result<Self> {
        #[cfg(target_os = "windows")]
        if std::env::args().any(|argument| argument == "--service") {
            return Ok(Self::Service(ServiceInputProxy::create(
                lock_screen_requested,
            )?));
        }
        #[cfg(not(target_os = "windows"))]
        let _ = lock_screen_requested;
        Ok(Self::Native(Injector::create()?))
    }

    fn send(&mut self, event: InputEvent) -> Result<()> {
        match self {
            Self::Native(injector) => injector.send(event).map_err(Into::into),
            #[cfg(target_os = "windows")]
            Self::Service(proxy) => proxy.send(event),
        }
    }

    fn ensure_session(&self) -> Result<()> {
        match self {
            Self::Native(_) => Ok(()),
            #[cfg(target_os = "windows")]
            Self::Service(proxy) => proxy.ensure_session(),
        }
    }

    fn warp_cursor(&mut self, x: u32, y: u32) -> Result<()> {
        match self {
            Self::Native(_) => {
                // Linux receivers MUST place the OS cursor at the entry
                // point (Deskflow Client::enter parity): without this warp
                // the peer drives a virtual edge cursor while the visible
                // one sits wherever it was — entries land mid-screen and
                // every later exit looks like it fires mid-screen. The
                // headless daemon has no DISPLAY of its own, so it warps
                // through the session-published display (the UI grants
                // access at startup); without one it warns and drives
                // unplaced rather than failing the episode.
                #[cfg(target_os = "linux")]
                {
                    // Cookie first: without it a dead xhost grant fails the
                    // connect below, which used to surface as entries at
                    // the stored position (notably on the lockscreen).
                    seed_session_xauthority();
                    let display = receiver_display().or_else(|| {
                        // Never silently drive unplaced when the ordinary
                        // local display is worth one attempt: a failed
                        // :0 warp warns at the call site and drives
                        // unplaced exactly like before, while a missing
                        // sidecar on a live desktop still gets its warp.
                        tracing::warn!(x, y, "no session display for entry warp; trying :0");
                        Some(":0".to_owned())
                    });
                    // The let-else above always yields Some; keep the shape
                    // total so a future None stays drive-unplaced, not a
                    // panic in the input path.
                    let Some(display) = display else {
                        tracing::debug!(x, y, "no session display for entry warp; driving unplaced");
                        return Ok(());
                    };
                    return kvm_platform::capture::warp_cursor_on(Some(&display), x, y)
                        .map_err(anyhow::Error::from);
                }
                #[cfg(not(any(target_os = "linux", target_os = "windows")))]
                {
                    let _ = (x, y);
                    Ok(())
                }
                // Windows receivers in the interactive session warp exactly
                // like Linux ones (entry edge at the sender's exit height):
                // without this the peer drives relative motion from the
                // stale OS position, so Mint->Windows entries land where
                // the Windows cursor was last parked instead of matching
                // the Mint exit height. The service path above already
                // warped; only the interactive-session Native path no-oped.
                #[cfg(target_os = "windows")]
                {
                    return kvm_platform::capture::warp_cursor(x, y)
                        .map_err(anyhow::Error::from);
                }
            }
            #[cfg(target_os = "windows")]
            Self::Service(proxy) => proxy.warp_cursor(x, y),
        }
    }

    fn release_all(&mut self) -> Result<()> {
        match self {
            Self::Native(injector) => injector.release_all().map_err(Into::into),
            #[cfg(target_os = "windows")]
            Self::Service(proxy) => proxy.release_all(),
        }
    }

    fn sync_state(&mut self, state: &InputState) -> Result<()> {
        self.release_all()?;
        for usage in &state.pressed_keys {
            self.send(InputEvent::Key(kvm_core::KeyEvent {
                usage: *usage,
                pressed: true,
            }))?;
        }
        for button in &state.pressed_buttons {
            self.send(InputEvent::MouseButton {
                button: *button,
                pressed: true,
            })?;
        }
        Ok(())
    }
}

struct PairingRequest {
    local_node_name: String,
    node_name: String,
    claimed_fingerprint: String,
    /// Typed station code from the initiator, if it entered one. Verified
    /// against the rotating station code; a match pre-approves the pairing
    /// with no local click needed.
    pairing_code: Option<String>,
}

async fn handle_pairing(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peers: Arc<tokio::sync::RwLock<PeerBook>>,
    actual_peer_fingerprint: &str,
    pairing_approvals: crate::control::PairingApprovals,
    request: PairingRequest,
) -> Result<()> {
    let PairingRequest {
        local_node_name,
        node_name,
        claimed_fingerprint,
        pairing_code,
    } = request;
    if claimed_fingerprint != actual_peer_fingerprint {
        reject(send, "pairing identity does not match the certificate").await?;
        bail!("pairing identity mismatch");
    }
    let identity = Identity::load_or_create(&data_dir())?;
    let local_fingerprint = identity.fingerprint_hex();
    let verification_code =
        kvm_protocol::pairing::verification_code(&local_fingerprint, actual_peer_fingerprint);
    // Typed-code pairing (MWB security-key model): the initiator typed the
    // digits shown on this machine's screen, proving human presence here
    // without any popup, simultaneity, or second screen-watch. Pre-approve:
    // no pending is registered, no local click is needed, and the decision
    // lands in the audit trail instead of the approval queue. A wrong code
    // simply falls through to the compare-codes flow below.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let typed_code_accepted = pairing_code.as_deref().is_some_and(|code| {
        kvm_protocol::pairing::station_code_valid(&local_fingerprint, code, now_secs)
    });
    if typed_code_accepted {
        audit_event(
            &data_dir(),
            &format!(
                "pairing-code-accepted fingerprint={actual_peer_fingerprint} remote={}",
                conn.remote_address()
            ),
        );
    }
    write_frame(
        send,
        &WireMessage::PairChallenge {
            node_name: local_node_name.clone(),
            fingerprint_hex: local_fingerprint.clone(),
            verification_code: Some(verification_code.clone()),
            // The initiator typed this machine's rotating code: it already
            // approved itself, so its UI must finish without a compare
            // screen and without asking anyone here to click.
            pre_approved: typed_code_accepted,
        },
    )
    .await?;
    // Register the request for local approval RIGHT NOW — while the
    // initiator compares codes — not only after it confirms. Otherwise the
    // station UI can never show the request during the code check, and the
    // ceremony can never complete. The initiator's PairConfirm and the local
    // Allow/Deny race in either order; both must arrive before trust is
    // granted. Whichever side approves first, its decision is held until the
    // other side arrives. (Skipped for typed-code pairings: nobody needs to
    // click anything there.)
    let waiter = if typed_code_accepted {
        None
    } else {
        let pending = kvm_protocol::control::PendingPairing {
            node_name: node_name.clone(),
            fingerprint_hex: actual_peer_fingerprint.to_owned(),
            address: conn.remote_address().to_string(),
            verification_code,
        };
        match pairing_approvals.register(pending).await {
            Ok(waiter) => Some(waiter),
            Err(error) => {
                let _ = reject(send, &format!("{error:#}")).await;
                bail!("pairing not registered: {error:#}");
            }
        }
    };
    // Bound the confirmation wait like the local approval window (30
    // minutes): an initiator that walks away mid-ceremony must not hold a
    // pairing task (and the initiator's open channel) forever. Expiry
    // closes the station side, which tells a lingering initiator to clear
    // its code screen instead of showing stale digits.
    const PAIRING_CONFIRM_TIMEOUT_SECS: u64 = 1800;
    let confirmed = async {
        let incoming = tokio::time::timeout(
            std::time::Duration::from_secs(PAIRING_CONFIRM_TIMEOUT_SECS),
            read_frame(recv),
        )
        .await
        .map_err(|_| anyhow::anyhow!("pairing confirmation timed out"))?
        .map_err(|error| anyhow::anyhow!("pairing stream failed: {error:#}"))?;
        match incoming.context("peer closed pairing stream")? {
            WireMessage::PairConfirm {
                server_fingerprint_hex,
            } if server_fingerprint_hex == identity.fingerprint_hex() => Ok(()),
            WireMessage::Reject { reason } => {
                Err(anyhow::anyhow!("initiator aborted pairing: {reason}"))
            }
            other => Err(anyhow::anyhow!(
                "invalid pairing confirmation: {other:?}"
            )),
        }
    };
    tokio::pin!(confirmed);
    tokio::select! {
        _ = conn.closed() => {
            if let Some(waiter) = &waiter {
                waiter.cancel().await;
            }
            bail!("peer disconnected before pairing completed");
        }
        result = &mut confirmed => {
            if let Err(error) = result {
                if let Some(waiter) = &waiter {
                    waiter.cancel().await;
                }
                let _ = reject(send, &format!("{error:#}")).await;
                return Err(error);
            }
        }
    }
    // The initiator approved the codes; now the LOCAL decision (which may
    // already have been made minutes ago — it was held in the channel).
    // Typed-code pairings skip this: the typed digits were the approval.
    let approved = match waiter {
        Some(waiter) => waiter.wait().await?,
        None => typed_code_accepted,
    };
    if !approved {
        reject(send, "pairing was rejected or timed out locally").await?;
        audit_event(
            &data_dir(),
            &format!(
                "pairing-rejected fingerprint={actual_peer_fingerprint} remote={}",
                conn.remote_address()
            ),
        );
        bail!("pairing was rejected or timed out locally");
    }
    peers
        .write()
        .await
        .pin(node_name, actual_peer_fingerprint.to_owned())?;
    write_frame(
        send,
        &WireMessage::Accepted {
            lock_screen_enabled: false,
            clipboard_enabled: false,
            screen_geometry: None,
            smooth_scroll: true,
        },
    )
    .await?;
    send.finish()?;
    // Keep the QUIC connection alive until the final pairing result
    // has been acknowledged by the peer. Dropping the last
    // Connection handle immediately can turn a valid final frame into
    // a connection close before the initiator's application reads it.
    let _ = tokio::time::timeout(Duration::from_secs(2), send.stopped()).await;
    audit_event(
        &data_dir(),
        &format!(
            "pairing-completed fingerprint={actual_peer_fingerprint} remote={}",
            conn.remote_address()
        ),
    );
    tracing::info!(peer = %actual_peer_fingerprint, remote = %conn.remote_address(), "paired peer");
    Ok(())
}

/// USB HID usage for Scroll Lock. Every capture backend decodes the
/// platform key to this usage (Windows scan 0x46, evdev 70, X11 keycode 78),
/// so hotkey detection below is platform independent. Deskflow parity: the
/// lock key holds the cursor on the current screen; in fixed takeover there
/// is no local screen to hold, so it restores local control by exiting.
const SCROLL_LOCK_USAGE: u16 = 0x47;

fn is_scroll_lock_press(event: &kvm_core::InputEvent) -> bool {
    matches!(
        event,
        kvm_core::InputEvent::Key(kvm_core::KeyEvent { usage, pressed: true })
            if *usage == SCROLL_LOCK_USAGE
    )
}

struct ConnectPolicy<'a> {
    node_name: &'a str,
    request_lock_screen: bool,
    mode: Mode,
    clipboard_enabled: bool,
    screen_geometry: Option<ScreenGeometry>,
    /// Administrative link epoch both sides share (None for the fixed-peer
    /// diagnostic commands and older callers: no banning applies to them).
    link_id: Option<u64>,
}

impl Clone for ConnectPolicy<'_> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for ConnectPolicy<'_> {}

/// True when a dial failed because the peer does not know the identity we
/// presented — locally ("not paired") or remotely ("peer rejected session:
/// ... not paired"). Only this narrow case retries with the alternate local
/// identity; network and policy failures surface immediately.
fn unknown_peer_rejection(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("is not paired"))
}

/// Alternate dial state for the unknown-peer retry: the system identity and
/// a merged peer book (user book plus system entries), used when this
/// process runs as the desktop user but the peer only trusts the identity
/// this machine shows as a pairing station (and vice versa). Returns None
/// when there is no usable alternate (same directory, unreadable key, or
/// identical fingerprint).
fn load_fallback_dial(dir: &std::path::Path, primary_fingerprint: &str) -> Option<(Identity, PeerBook)> {
    let system = system_data_dir();
    if system == dir {
        return None;
    }
    let identity = Identity::load_or_create(&system).ok()?;
    if identity.fingerprint_hex() == primary_fingerprint {
        return None;
    }
    let mut merged = PeerBook::load_or_create(dir).ok()?;
    if let Ok(system_book) = PeerBook::load_or_create(&system) {
        for peer in system_book.peers {
            if !merged.is_pinned(&peer.fingerprint_hex) {
                merged.peers.push(peer);
            }
        }
    }
    tracing::info!("alternate local identity available for unknown-peer retry");
    Some((identity, merged))
}

/// Dial with automatic identity fallback: the primary identity first; when
/// the peer reports us unknown and an alternate local identity exists, one
/// retry with it. Trust never weakens — either identity must be pinned by
/// the peer; this only survives the user-vs-service identity split that
/// pairing ceremonies naturally produce on each machine.
async fn dial_session(
    primary_identity: &Identity,
    peers: &PeerBook,
    address: &str,
    policy: ConnectPolicy<'_>,
    intended_fingerprint: Option<&str>,
    dir: &std::path::Path,
) -> Result<(
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    SessionCapabilities,
)> {
    match connect_input(primary_identity, peers, address, policy, intended_fingerprint).await
    {
        Ok(session) => Ok(session),
        Err(first) if unknown_peer_rejection(&first) => {
            let primary_fp = primary_identity.fingerprint_hex();
            match load_fallback_dial(dir, &primary_fp) {
                Some((identity, merged)) => {
                    tracing::info!(peer = %address, "peer reports this computer unknown; retrying with the alternate local identity");
                    connect_input(&identity, &merged, address, policy, intended_fingerprint).await
                }
                None => Err(first),
            }
        }
        Err(other) => Err(other),
    }
}

/// Address the station side dials back for its half of a link: the peer
/// book's saved daemon address for this fingerprint (exact entry, else a
/// same-named sibling from a re-pairing), else the inbound IP on the
/// standard daemon port. NEVER the socket's remote address verbatim: that
/// is an ephemeral source port, and dialling it back fails forever — the
/// defect that made Both-ways return control impossible. Pure so the
/// determinism is unit-tested.
fn dialable_peer_address(
    peers: &PeerBook,
    fingerprint: &str,
    peer_name: &str,
    inbound_remote: SocketAddr,
) -> String {
    if let Ok(address) = resolve_peer_address(peers, fingerprint, peer_name) {
        return address;
    }
    std::net::SocketAddr::new(inbound_remote.ip(), DEFAULT_PORT).to_string()
}

/// Resolve a dial address for a layout peer fingerprint: the exact entry's
/// address first; otherwise a same-named sibling entry's address (same
/// machine, re-paired identity — the address moved with it). Fingerprint
/// verification at handshake stays strict; an address only decides where
/// to knock.
fn resolve_peer_address(
    peers: &PeerBook,
    fingerprint: &str,
    peer_name: &str,
) -> Result<String> {
    if let Some(address) = peers
        .peers
        .iter()
        .find(|peer| peer.fingerprint_hex == fingerprint)
        .and_then(|peer| peer.address.as_deref())
        .filter(|address| !address.trim().is_empty())
    {
        return Ok(address.to_owned());
    }
    if let Some(address) = peers
        .peers
        .iter()
        .find(|peer| {
            peer.fingerprint_hex != fingerprint
                && !peer.name.trim().is_empty()
                && peer.name == peer_name
        })
        .and_then(|peer| peer.address.as_deref())
        .filter(|address| !address.trim().is_empty())
    {
        tracing::info!("dialling the intended peer via a same-named sibling entry's address");
        return Ok(address.to_owned());
    }
    anyhow::bail!("target screen peer has no saved address")
}

/// Retire ghost identities: same device name, different fingerprint than
/// the peer that just completed a verified session. Two faces for one
/// machine (service cert vs interactive-user cert) used to accumulate here
/// and flap the link — adoption churn, sibling-address redials,
/// input-permit races. The LIVE fingerprint wins; the ghosts lose trust
/// (in-memory and on file) with an audit line. A genuinely re-paired
/// machine presents its new face the same way and retires the old one.
async fn retire_ghost_identities(
    peers: &Arc<tokio::sync::RwLock<PeerBook>>,
    dir: &std::path::Path,
    node_name: &str,
    live_fingerprint: &str,
    audit_dir: &std::path::Path,
) {
    if node_name.trim().is_empty() {
        return;
    }
    let ghosts: Vec<String> = {
        let book = peers.read().await;
        book.peers
            .iter()
            .filter(|peer| {
                peer.name == node_name && peer.fingerprint_hex != live_fingerprint
            })
            .map(|peer| peer.fingerprint_hex.clone())
            .collect()
    };
    if ghosts.is_empty() {
        return;
    }
    let mut retired = 0u32;
    if let Ok(mut file_book) = PeerBook::load_or_create(dir) {
        for ghost in &ghosts {
            match file_book.unpin(ghost) {
                Ok(true) => retired += 1,
                Ok(false) => {}
                Err(error) => tracing::debug!(%error, %ghost, "cannot retire ghost identity from peer book"),
            }
        }
    }
    {
        let mut live_book = peers.write().await;
        for ghost in &ghosts {
            let _ = live_book.unpin(ghost);
        }
    }
    tracing::warn!(
        peer = node_name,
        live = live_fingerprint,
        ghosts = ghosts.len(),
        retired,
        "retired ghost identities for a verified peer; one face per machine from here on"
    );
    audit_event(
        audit_dir,
        &format!(
            "ghost-identities-retired peer={node_name} live={live_fingerprint} ghosts={}",
            ghosts.len()
        ),
    );
}

/// Record a working address for a fingerprint in a peer book (best effort,
/// logged). Keeps dial addresses fresh across DHCP changes and heals
/// entries pinned without one.
fn note_peer_address(dir: &std::path::Path, fingerprint: &str, address: &str) {
    match PeerBook::load_or_create(dir) {
        Ok(mut book) => {
            let current = book
                .peers
                .iter()
                .find(|peer| peer.fingerprint_hex == fingerprint)
                .and_then(|peer| peer.address.clone());
            if current.as_deref() != Some(address) {
                let name = book
                    .peers
                    .iter()
                    .find(|peer| peer.fingerprint_hex == fingerprint)
                    .map(|peer| peer.name.clone())
                    .unwrap_or_else(|| fingerprint.to_owned());
                match book.pin_with_address(name, fingerprint.to_owned(), Some(address.to_owned())) {
                    Ok(()) => tracing::info!("recorded working address for known peer"),
                    Err(error) => tracing::debug!(%error, "cannot record peer address"),
                }
            }
        }
        Err(error) => tracing::debug!(%error, "cannot open peer book to record address"),
    }
}

async fn connect_input(
    identity: &Identity,
    peers: &PeerBook,
    address: &str,
    policy: ConnectPolicy<'_>,
    intended_fingerprint: Option<&str>,
) -> Result<(
    quinn::Connection,
    quinn::SendStream,
    quinn::RecvStream,
    SessionCapabilities,
)> {
    if !mode_allows_outgoing(policy.mode) {
        bail!("receiver-only mode cannot initiate an input session");
    }
    let addr = normalize_addr(address)?;
    // Pin the TLS handshake to the intended peer when the address owner
    // agrees with it (the normal case). When dialling a sibling address for
    // the intended fingerprint — same machine, re-paired identity, address
    // carried by the newer book entry — pinning to the address owner would
    // fail the handshake even though either fingerprint is trusted, so stay
    // unpinned: the fingerprint check below runs against the SAME
    // connection object (no TOCTOU), keeping trust exactly as strict.
    let owner = saved_peer_fingerprint(peers, addr);
    let pin_to = match (intended_fingerprint, owner) {
        (Some(intended), Some(owner)) if owner == intended => Some(intended),
        (Some(intended), None) => Some(intended),
        (Some(_), Some(_)) => {
            tracing::info!(
                peer = %addr,
                "dialling a sibling address for the intended peer; TLS pinning relaxed, peer-book check still enforced"
            );
            None
        }
        (None, Some(owner)) => Some(owner),
        (None, None) => None,
    };
    let endpoint = if let Some(expected_fingerprint) = pin_to {
        transport::make_pinned_client_endpoint(identity, expected_fingerprint)?
    } else {
        // Keep first-run/manual-address compatibility; the application layer
        // still rejects an unpaired certificate before opening an input
        // session. Pairing writes the canonical address, so normal startup
        // connections take the TLS-pinned branch above.
        transport::make_client_endpoint(identity)?
    };
    let conn = endpoint.connect(addr, "thekvm")?.await?;
    let fingerprint = peer_fingerprint(&conn)?;
    if !peers.is_pinned(&fingerprint) {
        bail!("peer {addr} is not paired (fingerprint {fingerprint})");
    }
    let (send, recv, capabilities) = open_episode_stream(&conn, policy).await?;
    Ok((conn, send, recv, capabilities))
}

/// Open one drive episode on a live association: a fresh bidirectional
/// stream plus the Hello/Accepted handshake, without touching TLS. This is
/// the second half of a cold dial AND the whole of every later episode on
/// the warm link association, so screen-edge crossings skip endpoint setup
/// and the QUIC handshake entirely.
async fn open_episode_stream(
    conn: &quinn::Connection,
    policy: ConnectPolicy<'_>,
) -> Result<(
    quinn::SendStream,
    quinn::RecvStream,
    SessionCapabilities,
)> {
    let ConnectPolicy {
        node_name,
        request_lock_screen,
        mode,
        clipboard_enabled,
        screen_geometry,
        link_id,
    } = policy;
    let (mut send, mut recv) = conn.open_bi().await?;
    write_frame(
        &mut send,
        &WireMessage::Hello(Hello {
            node_name: node_name.to_owned(),
            mode,
            lock_screen_requested: request_lock_screen,
            clipboard_enabled,
            screen_geometry,
            // This side captures and understands touchpad smooth scroll.
            smooth_scroll: true,
            link_id,
        }),
    )
    .await?;
    match read_frame(&mut recv)
        .await?
        .context("peer closed before accepting session")?
    {
        WireMessage::Accepted {
            clipboard_enabled,
            screen_geometry,
            smooth_scroll,
            ..
        } => Ok((
            send,
            recv,
            SessionCapabilities {
                clipboard_enabled,
                screen_geometry,
                smooth_scroll,
            },
        )),
        WireMessage::Reject { reason } => bail!("peer rejected session: {reason}"),
        other => bail!("unexpected session response: {other:?}"),
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SessionCapabilities {
    clipboard_enabled: bool,
    screen_geometry: Option<ScreenGeometry>,
    smooth_scroll: bool,
}

fn local_screen_geometry(layout: &kvm_core::Layout) -> Option<ScreenGeometry> {
    let screen_id = layout.self_screen?;
    screen_geometry_for(layout, screen_id)
}

fn screen_geometry_for(layout: &kvm_core::Layout, screen_id: ScreenId) -> Option<ScreenGeometry> {
    let screen = layout.screen(screen_id)?;
    Some(ScreenGeometry {
        screen_id: screen_id.0,
        width: screen.width,
        height: screen.height,
    })
}

/// Session-measured local geometry, published by in-session children for
/// headless daemons (see the connect_topology publish step):
/// `{"width":1536,"height":864}` in the daemon data dir.
const GEOMETRY_SIDECAR: &str = "local-geometry.json";

/// Parse sidecar body into dims. Pure for tests.
fn parse_geometry_sidecar(text: &str) -> Option<(u32, u32)> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let width = value.get("width")?.as_u64()?;
    let height = value.get("height")?.as_u64()?;
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        return None;
    }
    Some((width as u32, height as u32))
}

/// Parse the session display name from the sidecar body (`":0"`).
/// Validated hard: this string selects an X connection, so anything
/// that is not a plain local display id is rejected. Pure for tests.
fn parse_sidecar_display(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let display = value.get("display")?.as_str()?;
    if display.len() > 32
        || !display.starts_with(':')
        || !display
            .chars()
            .all(|cell| cell.is_ascii_alphanumeric() || cell == ':' || cell == '.')
    {
        return None;
    }
    Some(display.to_owned())
}

/// Parse the session X cookie path from the sidecar body. Validated
/// hard: this path is trusted for X authentication, so only absolute
/// paths without NUL bytes pass. Existence is checked at use time, not
/// here, to keep this pure for tests.
fn parse_sidecar_xauthority(text: &str) -> Option<std::path::PathBuf> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let path = value.get("xauthority")?.as_str()?;
    if path.len() > 256
        || !path.starts_with('/')
        || path.contains('\0')
        || path.contains("..")
    {
        return None;
    }
    Some(std::path::PathBuf::from(path))
}

/// Seed XAUTHORITY from the session sidecar when the process has none.
/// Headless daemons (User=thekvm, no session environment) otherwise lean
/// entirely on the UI-startup xhost grant; when that grant stops working
/// — lock greeters, X resets — every entry warp fails closed into
/// drive-unplaced. The cookie file itself survives all of that. Once the
/// environment carries a value this is a no-op, so the process-wide set
/// happens at most once per process lifetime in practice.
#[cfg(target_os = "linux")]
fn seed_session_xauthority() {
    if std::env::var("XAUTHORITY")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }
    let cookie = std::fs::read_to_string(data_dir().join(GEOMETRY_SIDECAR))
        .ok()
        .and_then(|text| parse_sidecar_xauthority(&text))
        .filter(|path| path.is_file());
    if let Some(cookie) = cookie {
        std::env::set_var("XAUTHORITY", &cookie);
        tracing::debug!(path = %cookie.display(), "seeded session X cookie for entry warp");
    }
}

/// Display the receiver should warp on: our own environment first, else
/// the session-published sidecar display (headless daemons have no
/// DISPLAY of their own). None means "no session display known".
fn receiver_display() -> Option<String> {
    if let Ok(display) = std::env::var("DISPLAY") {
        if !display.trim().is_empty() {
            return Some(display);
        }
    }
    std::fs::read_to_string(data_dir().join(GEOMETRY_SIDECAR))
        .ok()
        .and_then(|text| parse_sidecar_display(&text))
}

/// Pick the advertised geometry from best to worst evidence. Pure for
/// tests: session truth (a child measured it inside the live desktop)
/// beats a live platform query beats configured fallback dims.
fn pick_geometry(
    screen_id: u32,
    sidecar: Option<(u32, u32)>,
    measured: Option<(u32, u32)>,
    configured: Option<ScreenGeometry>,
) -> Option<ScreenGeometry> {
    if let Some((width, height)) = sidecar {
        return Some(ScreenGeometry {
            screen_id,
            width,
            height,
        });
    }
    if let Some((width, height)) = measured.filter(|(w, h)| *w != 0 && *h != 0) {
        return Some(ScreenGeometry {
            screen_id,
            width,
            height,
        });
    }
    configured
}

/// Truthful local geometry for advertisements (Deskflow getShape parity).
/// The headless Mint daemon cannot query X11 itself, so without the
/// child-published sidecar it advertises fallback dims and the peer maps
/// every entry point against a screen that does not exist — entries land
/// off-edge and exits look like they fire mid-screen.
fn truthful_local_geometry(layout: &kvm_core::Layout) -> Option<ScreenGeometry> {
    let screen_id = layout
        .self_screen
        .or_else(|| layout.screens.first().map(|screen| screen.id))?;
    let sidecar = std::fs::read_to_string(data_dir().join(GEOMETRY_SIDECAR))
        .ok()
        .and_then(|text| parse_geometry_sidecar(&text));
    let measured = kvm_platform::capture::screen_size()
        .ok()
        .flatten()
        .filter(|(width, height)| *width != 0 && *height != 0);
    pick_geometry(screen_id.0, sidecar, measured, local_screen_geometry(layout))
}

/// Publish session-measured geometry for the headless daemon to
/// advertise (see truthful_local_geometry). Best effort: an unwritable
/// daemon dir just keeps fallback advertisements, today's behavior.
fn publish_local_geometry(router: &EdgeRouter) {
    let Ok(daemon_dir) = std::env::var("THEKVM_DAEMON_DIR") else {
        return;
    };
    let Some(geometry) = local_screen_geometry(router.layout()) else {
        return;
    };
    // The session display travels with the dims: the headless daemon
    // needs it to place the entry warp on the right X server.
    let display = std::env::var("DISPLAY").ok().filter(|name| {
        let name = name.trim();
        !name.is_empty() && name.len() <= 32
    });
    // The session X cookie travels too: the daemon authenticates with the
    // one-shot xhost grant otherwise, and anything that invalidates that
    // grant (lock greeters, X resets) silently unplaces every later entry
    // warp — driving continues from the stale cursor, i.e. entries land
    // at the stored position. Cookie auth survives all of that.
    let xauthority = std::env::var("XAUTHORITY")
        .ok()
        .filter(|path| !path.trim().is_empty() && path.len() <= 256);
    let body = serde_json::json!({ "width": geometry.width, "height": geometry.height, "display": display, "xauthority": xauthority }).to_string();
    if let Err(error) = std::fs::write(
        std::path::Path::new(&daemon_dir).join(GEOMETRY_SIDECAR),
        body,
    ) {
        tracing::debug!(%error, "local geometry sidecar unavailable");
    }
}

/// Map a pointer position between inclusive logical screen coordinate spaces.
/// The edge coordinates are preserved (`0` maps to `0`, the last source pixel
/// maps to the last target pixel), which avoids a one-pixel drift accumulating
/// across repeated topology handoffs. Only the DIMENSIONS participate: the
/// geometry's screen id is a per-machine local number (one side's "screen 1"
/// says nothing about the other's), so comparing ids across the wire only
/// ever forced the unscaled fallback — entry at the raw local pixel instead
/// of the proportional edge point.
fn remap_position(
    x: u32,
    y: u32,
    source: Option<ScreenGeometry>,
    target: ScreenGeometry,
) -> (u32, u32) {
    let Some(source) = source.filter(|geometry| geometry.width > 0 && geometry.height > 0)
    else {
        return (
            x.min(target.width.saturating_sub(1)),
            y.min(target.height.saturating_sub(1)),
        );
    };
    (
        scale_coordinate(x, source.width, target.width),
        scale_coordinate(y, source.height, target.height),
    )
}

fn scale_coordinate(value: u32, source_span: u32, target_span: u32) -> u32 {
    if source_span <= 1 || target_span <= 1 {
        return 0;
    }
    (u64::from(value.min(source_span - 1)) * u64::from(target_span - 1)
        / u64::from(source_span - 1)) as u32
}

async fn send_input(
    connection: &quinn::Connection,
    send: &mut quinn::SendStream,
    sequence: u64,
    event: InputEvent,
) -> Result<()> {
    if matches!(
        event,
        InputEvent::MouseMove { .. } | InputEvent::Wheel(_) | InputEvent::SmoothWheel { .. }
    ) {
        let payload = encode_input_datagram(DatagramInput { sequence, event })?;
        connection
            .send_datagram(payload.into())
            .map_err(|error| anyhow::anyhow!("send input datagram: {error}"))?;
        return Ok(());
    }
    write_frame(
        &mut *send,
        &WireMessage::Input(InputPacket { sequence, event }),
    )
    .await?;
    Ok(())
}

async fn send_state_sync(send: &mut quinn::SendStream, state: InputState) -> Result<()> {
    write_frame(send, &WireMessage::StateSync(state)).await?;
    Ok(())
}

async fn reject(send: &mut quinn::SendStream, reason: &str) -> std::io::Result<()> {
    write_frame(
        send,
        &WireMessage::Reject {
            reason: reason.to_string(),
        },
    )
    .await?;
    // Finish the stream and give the peer a moment to read the reason.
    // Returning immediately drops the connection handle, which QUIC turns
    // into a bare "closed by peer" — the reason dies in flight and the
    // dialing side can never tell "not paired" from a network failure.
    let _ = send.finish();
    let _ = tokio::time::timeout(std::time::Duration::from_millis(500), send.stopped()).await;
    Ok(())
}

fn confirm_pairing() -> Result<bool> {
    if std::env::var("THEKVM_AUTO_CONFIRM").ok().as_deref() == Some("1") {
        return Ok(true);
    }
    print!("Type 'yes' to trust this peer: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

fn local_node_name(config: &Config) -> String {
    config.device_name.clone()
}

/// Best-effort OS host name without new dependencies: environment first,
/// then the platform's canonical source. Returns None when nothing usable
/// is found, so callers keep their existing name.
fn os_host_name() -> Option<String> {
    let from_env = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty());
    if from_env.is_some() {
        return from_env;
    }
    #[cfg(unix)]
    {
        if let Ok(raw) = std::fs::read_to_string("/etc/hostname") {
            let name = raw.trim().trim_matches('.').to_owned();
            if !name.is_empty()
                && name.len() <= 64
                && !name.chars().any(char::is_control)
            {
                return Some(name);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Last resort on Windows when COMPUTERNAME is absent (services
        // normally have it; this is only belt-and-braces).
        if let Ok(output) = std::process::Command::new("hostname").output() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !name.is_empty() && !name.chars().any(char::is_control) {
                return Some(name);
            }
        }
    }
    None
}

fn peer_fingerprint(conn: &quinn::Connection) -> Result<String> {
    use sha2::{Digest, Sha256};
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

fn normalize_addr(address: &str) -> Result<SocketAddr> {
    let with_port = if address.parse::<SocketAddr>().is_ok() || address.contains(':') {
        address.to_string()
    } else {
        format!("{address}:{DEFAULT_PORT}")
    };
    if let Ok(addr) = with_port.parse() {
        return Ok(addr);
    }
    use std::net::ToSocketAddrs;
    with_port
        .to_socket_addrs()
        .context("resolving address")?
        .next()
        .context("address resolved to nothing")
}

fn saved_peer_fingerprint(peers: &PeerBook, address: SocketAddr) -> Option<&str> {
    peers.peers.iter().find_map(|peer| {
        let saved_address = peer.address.as_deref()?;
        (normalize_addr(saved_address).ok()? == address).then_some(peer.fingerprint_hex.as_str())
    })
}

fn validate_input_capability(config: &Config, lock_screen_requested: bool) -> Result<bool> {
    // Returns the EFFECTIVE lock-screen grant (requested AND allowed).
    // MWB-like both-ways rule: a peer that asks for privileged input from
    // a machine that did not opt in is DOWNGRADED to an ordinary desktop
    // session on Windows (the Default-desktop helper isolates it, so this
    // is exactly the "normal paired Windows desktop session" the module
    // below blesses) instead of rejected — a one-sided checkbox must never
    // silently kill reverse control while forward works. The non-Windows
    // evdev/uinput receiver writes below the compositor and can reach a
    // greeter, so its opt-in stays a hard reject in every direction.
    if lock_screen_requested && !config.allow_lock_screen_control {
        if cfg!(target_os = "windows") {
            return Ok(false);
        }
        bail!("privileged remote input is disabled locally");
    }
    // The non-Windows evdev/uinput receiver writes a virtual HID device below
    // the compositor, so it cannot safely promise that an ordinary session is
    // unable to reach a greeter or locker. Windows can isolate an ordinary
    // session to the Default desktop helper. Keep the evdev/uinput path
    // explicitly opted in, while allowing normal paired Windows desktop
    // sessions without Winlogon access.
    if !lock_screen_requested && !config.allow_lock_screen_control && !cfg!(target_os = "windows") {
        bail!("evdev/uinput input injection requires the local lock-screen capability opt-in");
    }
    Ok(lock_screen_requested && config.allow_lock_screen_control)
}

fn mode_allows_incoming(mode: Mode) -> bool {
    matches!(mode, Mode::Bidirectional | Mode::ClientOnly)
}

fn mode_allows_outgoing(mode: Mode) -> bool {
    matches!(mode, Mode::Bidirectional | Mode::ServerClient)
}

#[cfg(target_os = "windows")]
pub fn run_windows_service() -> Result<()> {
    use windows::core::PWSTR;
    use windows::Win32::System::Services::{StartServiceCtrlDispatcherW, SERVICE_TABLE_ENTRYW};

    let mut name = "TheKVM\0".encode_utf16().collect::<Vec<_>>();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(windows_service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
        .map_err(|error| anyhow::anyhow!("StartServiceCtrlDispatcherW failed: {error}"))
}

#[cfg(target_os = "windows")]
static SERVICE_STATUS_HANDLE_VALUE: std::sync::atomic::AtomicIsize =
    std::sync::atomic::AtomicIsize::new(0);

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_service_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    use windows::Win32::System::Services::{
        SetServiceStatus, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_STATUS,
        SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_WIN32_OWN_PROCESS,
    };

    if control == SERVICE_CONTROL_STOP {
        let handle = SERVICE_STATUS_HANDLE(
            SERVICE_STATUS_HANDLE_VALUE.load(std::sync::atomic::Ordering::SeqCst) as *mut _,
        );
        if !handle.is_invalid() {
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: SERVICE_STOP_PENDING,
                dwControlsAccepted: SERVICE_ACCEPT_STOP,
                dwWin32ExitCode: 0,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 1,
                dwWaitHint: 5000,
            };
            let _ = SetServiceStatus(handle, &status);
        }
        shutdown_notifier().notify_waiters();
    }
    0
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn windows_service_main(
    _argument_count: u32,
    _arguments: *mut windows::core::PWSTR,
) {
    use windows::core::w;
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, SERVICE_ACCEPT_STOP, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
    };

    let Ok(handle) =
        RegisterServiceCtrlHandlerExW(w!("TheKVM"), Some(windows_service_handler), None)
    else {
        return;
    };
    SERVICE_STATUS_HANDLE_VALUE.store(handle.0 as isize, std::sync::atomic::Ordering::SeqCst);

    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: 5000,
    };
    let _ = SetServiceStatus(handle, &status);

    status.dwCurrentState = SERVICE_RUNNING;
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    status.dwCheckPoint = 0;
    status.dwWaitHint = 0;
    let _ = SetServiceStatus(handle, &status);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build();
    let result = runtime.and_then(|runtime| {
        runtime
            .block_on(run())
            .map_err(|error| std::io::Error::other(error.to_string()))
    });

    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    status.dwWin32ExitCode = u32::from(result.is_err());
    let _ = SetServiceStatus(handle, &status);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_capability_policy_matches_platform() {
        let locked_off = kvm_core::Config {
            allow_lock_screen_control: false,
            ..kvm_core::Config::default()
        };
        let locked_on = kvm_core::Config {
            allow_lock_screen_control: true,
            ..kvm_core::Config::default()
        };
        if cfg!(target_os = "windows") {
            // Windows isolates ordinary sessions in the Default desktop
            // helper: no opt-in needed, and a privileged request downgrades
            // to ordinary (Ok(false)) instead of killing reverse control.
            assert!(!validate_input_capability(&locked_off, false).unwrap());
            assert!(!validate_input_capability(&locked_off, true).unwrap());
            assert!(!validate_input_capability(&locked_on, false).unwrap());
            assert!(validate_input_capability(&locked_on, true).unwrap());
        } else {
            // evdev/uinput writes below the compositor and can reach a
            // greeter, so every non-Windows session needs the explicit
            // opt-in — ordinary and privileged alike.
            assert!(validate_input_capability(&locked_off, false).is_err());
            assert!(validate_input_capability(&locked_off, true).is_err());
            assert!(!validate_input_capability(&locked_on, false).unwrap());
            assert!(validate_input_capability(&locked_on, true).unwrap());
        }
    }

    #[tokio::test]
    async fn verified_session_retires_same_named_ghost_identities() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("thekvm-ghost-retire-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        let live = "aa".repeat(32);
        let ghost = "bb".repeat(32);
        let other = "cc".repeat(32);
        let mut book = PeerBook::load_or_create(&dir).unwrap();
        book.pin_with_address("mint", live.clone(), Some("192.168.1.7:42110".into()))
            .unwrap();
        book.pin_with_address("mint", ghost.clone(), None).unwrap();
        book.pin_with_address("third", other.clone(), None).unwrap();
        let peers = Arc::new(tokio::sync::RwLock::new(book));
        retire_ghost_identities(&peers, &dir, "mint", &live, &dir).await;
        {
            let book = peers.read().await;
            assert!(book.is_pinned(&live));
            assert!(!book.is_pinned(&ghost));
            assert!(book.is_pinned(&other));
        }
        let file_book = PeerBook::load_or_create(&dir).unwrap();
        assert!(file_book.is_pinned(&live));
        assert!(!file_book.is_pinned(&ghost));
        assert!(file_book.is_pinned(&other));
        // A second verified session with nothing to retire is a no-op.
        retire_ghost_identities(&peers, &dir, "mint", &live, &dir).await;
        assert!(peers.read().await.is_pinned(&live));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ended_link_epochs_are_banned_until_replaced() {
        let id = 0xC0FF_EE00_u64;
        assert!(!link_ended(id));
        end_link(id);
        assert!(link_ended(id));
        assert!(!link_ended(id + 1));
        assert!(is_link_ended_rejection(&anyhow::anyhow!(
            "peer rejected session: link ended by this computer; press Connect for a fresh link"
        )));
        assert!(!is_link_ended_rejection(&anyhow::anyhow!(
            "peer rejected session: peer is not paired"
        )));
        // Display-case text never matches (the matcher is lowercase-only).
        assert!(!is_link_ended_rejection(&anyhow::anyhow!("Link ended")));
    }

    #[test]
    #[test]
    fn stale_hold_reaper_fires_only_without_a_drive() {        // The total-freeze invariant: suppression requested + no active
        // drive = release now. Any other combination leaves the hold
        // alone (an active drive legitimately suppresses).
        assert!(stale_hold_needs_release(false, true));
        assert!(!stale_hold_needs_release(true, true));
        assert!(!stale_hold_needs_release(false, false));
        assert!(!stale_hold_needs_release(true, false));
    }

    #[test]
    fn geometry_sidecar_parses_and_preference_holds() {
        // Sidecar truth beats live measure beats configured fallback;
        // garbage never corrupts an advertisement.
        assert_eq!(parse_geometry_sidecar(r#"{"width":1536,"height":864}"#), Some((1536, 864)));
        assert_eq!(parse_geometry_sidecar(r#"{"width":0,"height":864}"#), None);
        assert_eq!(parse_geometry_sidecar(r#"{"width":99999,"height":864}"#), None);
        assert_eq!(parse_geometry_sidecar("not json"), None);
        assert_eq!(parse_geometry_sidecar(r#"{"width":1536}"#), None);
        let configured = Some(kvm_protocol::wire::ScreenGeometry {
            screen_id: 2,
            width: 1920,
            height: 1080,
        });
        // Sidecar wins over everything.
        assert_eq!(
            pick_geometry(2, Some((1536, 864)), Some((1280, 720)), configured.clone())
                .map(|geometry| (geometry.width, geometry.height)),
            Some((1536, 864))
        );
        // Live measure wins over fallback.
        assert_eq!(
            pick_geometry(2, None, Some((1280, 720)), configured.clone())
                .map(|geometry| (geometry.width, geometry.height)),
            Some((1280, 720))
        );
        // Zero live measure falls through to fallback.
        assert_eq!(
            pick_geometry(2, None, Some((0, 720)), configured.clone())
                .map(|geometry| (geometry.width, geometry.height)),
            Some((1920, 1080))
        );
        // Nothing measured: configured fallback survives.
        assert_eq!(
            pick_geometry(2, None, None, configured)
                .map(|geometry| (geometry.width, geometry.height)),
            Some((1920, 1080))
        );
    }

    #[test]
    fn sidecar_display_parses_strictly() {
        // Plain local display ids pass; anything else (paths, commands,
        // remote specs) is rejected — this string selects an X connection.
        assert_eq!(
            parse_sidecar_display(r#"{"width":1536,"height":864,"display":":0"}"#),
            Some(":0".to_owned())
        );
        assert_eq!(
            parse_sidecar_display(r#"{"width":1536,"height":864,"display":":0.0"}"#),
            Some(":0.0".to_owned())
        );
        assert_eq!(
            parse_sidecar_display(r#"{"width":1536,"height":864}"#),
            None
        );
        assert_eq!(
            parse_sidecar_display(r#"{"display":"/tmp/evil"}"#),
            None
        );
        assert_eq!(
            parse_sidecar_display(r#"{"display":"host:0"}"#),
            None
        );
        assert_eq!(
            parse_sidecar_display(r#"{"display":"; rm -rf ~"}"#),
            None
        );
    }

    #[test]
    fn sidecar_xauthority_parses_strictly() {
        // Absolute cookie paths pass; relative paths, traversal, NUL
        // bytes, and overlong values are rejected — this path is trusted
        // for X authentication.
        assert_eq!(
            parse_sidecar_xauthority(
                r#"{"width":1536,"height":864,"xauthority":"/home/hs01/.Xauthority"}"#
            ),
            Some(std::path::PathBuf::from("/home/hs01/.Xauthority"))
        );
        assert_eq!(
            parse_sidecar_xauthority(r#"{"width":1536,"height":864}"#),
            None
        );
        assert_eq!(
            parse_sidecar_xauthority(r#"{"xauthority":"relative/.Xauthority"}"#),
            None
        );
        assert_eq!(
            parse_sidecar_xauthority(r#"{"xauthority":"/tmp/../etc/passwd"}"#),
            None
        );
        assert_eq!(parse_sidecar_xauthority(r#"{"xauthority":""}"#), None);
    }

    #[test]
    fn ban_exit_status_names_the_dead_epoch() {        // The supervising UI parses this exact shape to auto-redial, so
        // the wording is a contract, not prose.
        assert_eq!(
            ban_ended_status(Some(16824951138575866452)),
            "ended ban 16824951138575866452 (link ended by the other side)"
        );
        assert_eq!(
            ban_ended_status(None),
            "ended ban none (link ended by the other side)"
        );
        assert!(is_link_ended_rejection(&anyhow::anyhow!(
            "peer rejected session: link ended by this computer"
        )));
        assert!(!is_link_ended_rejection(&anyhow::anyhow!(
            "connection refused"
        )));
    }

    #[test]
    fn starved_drives_trip_only_after_a_dozen_silent_pings() {
        // Healthy drives answer every Ping: the counter hovers near zero.
        assert!(!drive_starved(0));
        assert!(!drive_starved(1));
        assert!(!drive_starved(11));
        // Twelve consecutive Pings (~60s) with no Pong is proof, not noise.
        assert!(drive_starved(12));
        assert!(drive_starved(120));
    }

    #[test]
    fn failed_handoff_parks_the_cursor_inside_and_cools_down() {        use kvm_core::{InputEvent, RoutedEvent};
        let mut router = EdgeRouter::new(kvm_core::Layout::pair_default(
            "me",
            "peer",
            &"ab".repeat(32),
        ))
        .unwrap();
        let handoff = router.route(InputEvent::MouseMove { dx: 5000, dy: 0 });
        assert!(matches!(handoff, RoutedEvent::Handoff { .. }));
        let target = router.active_remote().unwrap();
        router.restore_local(target).unwrap();
        let (x_before, y_before) = router.cursor_position();
        park_inside(&mut router, kvm_core::Edge::Right);
        let (x_after, y_after) = router.cursor_position();
        assert_eq!(x_after + 8, x_before);
        assert_eq!(y_after, y_before);
        assert!(!episode_cooling_down(None));
        assert!(episode_cooling_down(Some(std::time::Instant::now())));
        assert!(!episode_cooling_down(Some(
            std::time::Instant::now() - Duration::from_secs(2)
        )));
    }

    #[test]
    fn transfer_debounce_matches_mwb_last_jump() {
        // No transfer yet: drive.
        assert!(!transfer_debounced(None));
        let just = std::time::Instant::now();
        // A transfer that just finished: hold.
        assert!(transfer_debounced(Some(just)));
        // An old transfer: drive again.
        let old = just - Duration::from_secs(1);
        assert!(!transfer_debounced(Some(old)));
    }

    #[test]
    fn inbound_link_registry_tracks_and_drops_live_sessions() {
        let fp = "dd".repeat(32);
        // No session: nothing listed, nothing to drop.
        remove_inbound_link(&fp, 1);
        assert!(!drop_inbound_link(&fp));
        assert!(list_inbound_links().iter().all(|s| s.fingerprint_hex != fp));
        // Register: listed with name and address, droppable.
        let (id, _rx) = register_inbound_link(&fp, "mint", "192.168.1.7:42110", Some(7));
        let listed: Vec<_> = list_inbound_links()
            .into_iter()
            .filter(|s| s.fingerprint_hex == fp)
            .collect();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].node_name, "mint");
        assert_eq!(listed[0].address, "192.168.1.7:42110");
        assert_eq!(listed[0].link_id, Some(7));
        assert!(drop_inbound_link(&fp));
        // Wrong id must not unregister (a redialed successor survives).
        remove_inbound_link(&fp, id + 999);
        assert!(list_inbound_links().iter().any(|s| s.fingerprint_hex == fp));
        // Right id unregisters.
        remove_inbound_link(&fp, id);
        assert!(list_inbound_links().iter().all(|s| s.fingerprint_hex != fp));
    }

    #[test]
    fn scroll_lock_press_detects_only_the_lock_key_down() {
        use kvm_core::{InputEvent, KeyEvent};
        assert!(is_scroll_lock_press(&InputEvent::Key(KeyEvent {
            usage: SCROLL_LOCK_USAGE,
            pressed: true,
        })));
        assert!(!is_scroll_lock_press(&InputEvent::Key(KeyEvent {
            usage: SCROLL_LOCK_USAGE,
            pressed: false,
        })));
        assert!(!is_scroll_lock_press(&InputEvent::Key(KeyEvent {
            usage: 0x04,
            pressed: true,
        })));
        assert!(!is_scroll_lock_press(&InputEvent::MouseMove { dx: 1, dy: 0 }));
    }

    #[test]
    fn unknown_peer_rejection_matches_only_trust_failures() {        assert!(unknown_peer_rejection(&anyhow::anyhow!(
            "peer 192.168.1.7:42110 is not paired (fingerprint {})",
            "ab".repeat(32)
        )));
        assert!(unknown_peer_rejection(&anyhow::anyhow!(
            "peer rejected session: peer is not paired"
        )));
        assert!(!unknown_peer_rejection(&anyhow::anyhow!(
            "peer rejected session: privileged remote input is disabled locally"
        )));
        assert!(!unknown_peer_rejection(&anyhow::anyhow!(
            "connect daemon control socket timed out after 3s"
        )));
        assert!(!unknown_peer_rejection(&anyhow::anyhow!(
            "no answer from 192.168.1.7:42110 after 10s"
        )));
    }

    #[test]
    fn audit_log_sanitizes_multiline_boundary_records() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("thekvm-audit-test-{nonce}"));
        audit_event(&dir, "session-accepted peer=test\nunexpected-line");
        let contents = std::fs::read_to_string(dir.join("audit.log")).unwrap();
        assert!(contents.contains("session-accepted peer=test unexpected-line"));
        assert_eq!(contents.lines().count(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn state_sync_rejects_duplicate_or_oversized_control_sets() {
        assert!(sync_state(&InputState {
            pressed_keys: vec![0x04, 0x04],
            pressed_buttons: Vec::new(),
        })
        .is_err());
        assert!(sync_state(&InputState {
            pressed_keys: vec![0x04; MAX_SYNC_KEYS + 1],
            pressed_buttons: Vec::new(),
        })
        .is_err());
        assert!(sync_state(&InputState {
            pressed_keys: vec![0x04, 0xe0],
            pressed_buttons: vec![MouseButton::Left, MouseButton::Forward],
        })
        .is_ok());
    }

    #[test]
    fn capture_snapshot_barrier_covers_events_already_reflected_in_state() {
        let mut captured = CapturedState::default();
        let pressed = captured
            .record(InputEvent::Key(kvm_core::KeyEvent {
                usage: 0xe0,
                pressed: true,
            }))
            .unwrap();
        let motion = captured
            .record(InputEvent::MouseMove { dx: 4, dy: -2 })
            .unwrap();
        let released = captured
            .record(InputEvent::Key(kvm_core::KeyEvent {
                usage: 0xe0,
                pressed: false,
            }))
            .unwrap();
        let snapshot = captured.snapshot();

        assert_eq!(pressed.event_id, 1);
        assert_eq!(motion.event_id, 2);
        assert_eq!(released.event_id, 3);
        assert_eq!(snapshot.last_event_id, 3);
        assert!(snapshot.state.pressed_keys.is_empty());
    }

    #[test]
    fn capture_state_deduplicates_key_and_button_repeats() {
        let mut captured = CapturedState::default();
        let key = InputEvent::Key(kvm_core::KeyEvent {
            usage: 0x04,
            pressed: true,
        });
        assert!(captured.record(key).is_some());
        assert!(captured.record(key).is_none());
        assert!(captured
            .record(InputEvent::Key(kvm_core::KeyEvent {
                usage: 0x04,
                pressed: false,
            }))
            .is_some());
        assert!(captured
            .record(InputEvent::Key(kvm_core::KeyEvent {
                usage: 0x04,
                pressed: false,
            }))
            .is_none());

        let button = InputEvent::MouseButton {
            button: MouseButton::Left,
            pressed: true,
        };
        assert!(captured.record(button).is_some());
        assert!(captured.record(button).is_none());
    }

    #[test]
    fn motion_sequence_discards_reordered_datagrams_and_handles_wrap() {
        let mut sequence = MotionSequence::default();
        assert!(sequence.accept(10));
        assert!(sequence.accept(11));
        assert!(!sequence.accept(10));
        assert!(!sequence.accept(11));

        let mut wrapped = MotionSequence {
            latest: Some(u64::MAX),
        };
        assert!(wrapped.accept(0));
        assert!(!wrapped.accept(u64::MAX));
    }

    #[test]
    fn fingerprint_validation_rejects_ambiguous_peer_ids() {
        assert!(valid_fingerprint(&"ab".repeat(32)));
        assert!(valid_fingerprint(&"AB".repeat(32)));
        assert!(!valid_fingerprint("ab"));
        assert!(!valid_fingerprint(&format!("{}g", "ab".repeat(31))));
    }

    #[test]
    fn dialback_address_is_dialable_never_ephemeral() {
        use kvm_protocol::pairing::Peer;
        use std::net::{IpAddr, Ipv4Addr};

        let fp = "aa".repeat(32);
        let inbound: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)), 53622);
        // Exact book entry wins, even when the inbound source port differs.
        let mut book = PeerBook::default();
        book.peers.push(Peer {
            name: "mint".into(),
            fingerprint_hex: fp.clone(),
            address: Some("192.168.1.6:42110".into()),
        });
        assert_eq!(
            dialable_peer_address(&book, &fp, "mint", inbound),
            "192.168.1.6:42110"
        );
        // Same-named sibling (same machine, re-paired identity) heals a
        // book entry pinned without an address.
        book.peers[0].address = None;
        book.peers.push(Peer {
            name: "mint".into(),
            fingerprint_hex: "bb".repeat(32),
            address: Some("192.168.1.6:42110".into()),
        });
        assert_eq!(
            dialable_peer_address(&book, &fp, "mint", inbound),
            "192.168.1.6:42110"
        );
        // Unknown peer: inbound IP on the standard daemon port — the
        // ephemeral source port (53622 here) must never come back out.
        book.peers.clear();
        let dialed = dialable_peer_address(&book, &fp, "mint", inbound);
        assert_eq!(dialed, "192.168.1.6:42110");
        assert!(!dialed.contains("53622"));
    }

    #[test]
    fn smooth_wheel_downgrade_keeps_sub_detent_debt() {
        use kvm_core::InputEvent;
        let mut debt = WheelDowngrade::default();
        // Smooth peers take events untouched.
        assert_eq!(
            outgoing_wheel_event(
                InputEvent::SmoothWheel { x: 18, y: -45 },
                true,
                &mut debt
            ),
            Some(InputEvent::SmoothWheel { x: 18, y: -45 })
        );
        // Older peers: sub-detent motion banks debt and sends nothing…
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 18, y: -45 }, false, &mut debt),
            None
        );
        // …until a whole detent exists (truncation toward zero: -90/120
        // total waits, -135/120 fires exactly one).
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 0, y: -45 }, false, &mut debt),
            None
        );
        assert_eq!(
            outgoing_wheel_event(
                InputEvent::SmoothWheel { x: 130, y: -45 },
                false,
                &mut debt
            ),
            Some(InputEvent::Wheel(WheelDelta { x: 1, y: -1 }))
        );
        // Non-wheel events always pass through.
        assert_eq!(
            outgoing_wheel_event(InputEvent::MouseMove { dx: 3, dy: 4 }, false, &mut debt),
            Some(InputEvent::MouseMove { dx: 3, dy: 4 })
        );
    }

    #[test]
    fn smooth_wheel_downgrade_reversal_nets_against_the_bank() {
        use kvm_core::InputEvent;
        let mut debt = WheelDowngrade::default();
        // Bank +100 down, then reverse with -10: net 90 sits waiting —
        // nothing lost to the turn, nothing eaten either.
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 0, y: 100 }, false, &mut debt),
            None
        );
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 0, y: -10 }, false, &mut debt),
            None
        );
        assert_eq!(debt.y, 90);
        // A zero axis never resets the other axis's bank: banking x while
        // a y bank sits untouched must preserve both.
        let mut debt2 = WheelDowngrade::default();
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 0, y: 100 }, false, &mut debt2),
            None
        );
        assert_eq!(
            outgoing_wheel_event(InputEvent::SmoothWheel { x: 50, y: 0 }, false, &mut debt2),
            None
        );
        assert_eq!((debt2.x, debt2.y), (50, 100));
    }

    #[test]
    fn input_roles_are_enforced_in_both_directions() {        assert!(mode_allows_incoming(Mode::Bidirectional));
        assert!(!mode_allows_incoming(Mode::ServerClient));
        assert!(mode_allows_incoming(Mode::ClientOnly));
        assert!(mode_allows_outgoing(Mode::Bidirectional));
        assert!(mode_allows_outgoing(Mode::ServerClient));
        assert!(!mode_allows_outgoing(Mode::ClientOnly));
    }

    #[test]
    fn geometry_remapping_preserves_inclusive_edges() {
        let source = ScreenGeometry {
            screen_id: 7,
            width: 1920,
            height: 1080,
        };
        let target = ScreenGeometry {
            screen_id: 7,
            width: 2560,
            height: 1440,
        };
        assert_eq!(remap_position(0, 0, Some(source), target), (0, 0));
        assert_eq!(
            remap_position(1919, 1079, Some(source), target),
            (2559, 1439)
        );
        assert_eq!(remap_position(960, 540, Some(source), target), (1280, 720));
    }

    #[test]
    fn geometry_remapping_keeps_legacy_handoffs_safe() {
        let target = ScreenGeometry {
            screen_id: 3,
            width: 1280,
            height: 720,
        };
        assert_eq!(remap_position(4000, 4000, None, target), (1279, 719));
        // Degenerate source geometry still clamps instead of dividing.
        assert_eq!(
            remap_position(
                4000,
                4000,
                Some(ScreenGeometry {
                    screen_id: 3,
                    width: 0,
                    height: 0,
                }),
                target,
            ),
            (1279, 719)
        );
    }

    #[test]
    fn geometry_remapping_ignores_cross_machine_screen_numbers() {
        // Screen ids are per-machine local numbers: the sender's id for
        // the peer screen never equals the receiver's id for itself, so
        // the mapping must scale by dimensions anyway. Comparing ids
        // forced the unscaled fallback — entry at the raw local pixel
        // instead of the proportional edge point.
        let source = ScreenGeometry {
            screen_id: 1,
            width: 1920,
            height: 1080,
        };
        let target = ScreenGeometry {
            screen_id: 2,
            width: 2560,
            height: 1440,
        };
        assert_eq!(
            remap_position(1919, 1079, Some(source), target),
            (2559, 1439)
        );
        assert_eq!(remap_position(960, 540, Some(source), target), (1280, 720));
    }

    #[tokio::test]
    async fn receiver_input_session_slot_allows_one_live_controller() {
        let slot = Arc::new(tokio::sync::Semaphore::new(1));
        let first = slot.clone().try_acquire_owned().unwrap();
        assert!(slot.clone().try_acquire_owned().is_err());
        drop(first);
        assert!(slot.try_acquire_owned().is_ok());
    }

    #[test]
    fn lock_screen_requests_require_local_opt_in() {
        // Windows downgrades a privileged request to an ordinary desktop
        // session (MWB-like both-ways); non-Windows uinput keeps the hard
        // reject because it writes below the compositor.
        if cfg!(target_os = "windows") {
            assert!(!validate_input_capability(&Config::default(), true).unwrap());
        } else {
            assert!(validate_input_capability(&Config::default(), true).is_err());
        }
        assert!(validate_input_capability(
            &Config {
                allow_lock_screen_control: true,
                ..Config::default()
            },
            true
        )
        .unwrap());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn ordinary_windows_sessions_do_not_require_lock_screen_opt_in() {
        assert!(validate_input_capability(&Config::default(), false).is_ok());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn ordinary_non_windows_sessions_stay_gated_by_uinput_policy() {
        assert!(validate_input_capability(&Config::default(), false).is_err());
    }
}
