//! Local control server for the logged-in UI.

use anyhow::{bail, Context, Result};
use kvm_core::Config;
use kvm_protocol::control::{
    read_request, write_response, ControlRequest, ControlResponse, DaemonStatus, PendingPairing,
};
use kvm_protocol::pairing::PeerBook;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, RwLock};

pub type SharedConfig = Arc<RwLock<Config>>;
pub type SharedPeers = Arc<RwLock<PeerBook>>;

const MAX_PENDING_PAIRINGS: usize = 16;
// Approval window deliberately generous: pairing is a human rendezvous
// across two screens (find the window, compare digits, click twice), not a
// network handshake. A tight timeout turns slow humans into expired
// requests that look exactly like a broken network on the other side.
const PAIRING_APPROVAL_TIMEOUT: Duration = Duration::from_secs(1800);

/// In-memory approval queue owned by the running daemon. A pairing request is
/// not persisted or trusted until the local user approves it through the
/// control endpoint.
#[derive(Clone, Default)]
pub struct PairingApprovals {
    pending: Arc<tokio::sync::Mutex<BTreeMap<String, PendingEntry>>>,
}

struct PendingEntry {
    request: PendingPairing,
    decision: oneshot::Sender<bool>,
}

/// Handle for a registered pairing request. Registering (listing it for the
/// local approval UI) and waiting for the decision are separate steps so the
/// station can show the request while the initiator is still comparing
/// codes: whichever side approves first, its decision is held in the channel
/// until the other side arrives. Dropping the waiter without waiting leaves
/// the entry listed until it is decided, cancelled, or times out — callers
/// must cancel on early exit.
pub struct DecisionWaiter {
    approvals: PairingApprovals,
    fingerprint: String,
    receiver: Option<oneshot::Receiver<bool>>,
}

impl PairingApprovals {
    /// List the request for local approval immediately. A second request for
    /// the same fingerprint is refused so retries surface as guidance
    /// ("approve or deny it on the other computer") instead of silent
    /// duplicate rows.
    pub async fn register(&self, request: PendingPairing) -> Result<DecisionWaiter> {
        // Opt-in test/integration hook. With it set the request is approved
        // without ever being listed, exactly like the old combined call.
        if std::env::var("THEKVM_AUTO_CONFIRM").ok().as_deref() == Some("1") {
            return Ok(DecisionWaiter {
                approvals: self.clone(),
                fingerprint: request.fingerprint_hex.to_ascii_lowercase(),
                receiver: None,
            });
        }

        let fingerprint = request.fingerprint_hex.to_ascii_lowercase();
        let (decision_tx, decision_rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.len() >= MAX_PENDING_PAIRINGS {
                bail!("too many pending pairing requests");
            }
            if pending.contains_key(&fingerprint) {
                bail!("pairing is already awaiting local approval");
            }
            pending.insert(
                fingerprint.clone(),
                PendingEntry {
                    request,
                    decision: decision_tx,
                },
            );
        }
        Ok(DecisionWaiter {
            approvals: self.clone(),
            fingerprint,
            receiver: Some(decision_rx),
        })
    }

    pub async fn list(&self) -> Vec<PendingPairing> {
        self.pending
            .lock()
            .await
            .values()
            .map(|entry| entry.request.clone())
            .collect()
    }

    pub async fn decide(&self, fingerprint: &str, approved: bool) -> bool {
        let fingerprint = fingerprint.to_ascii_lowercase();
        self.pending
            .lock()
            .await
            .remove(&fingerprint)
            .map(|entry| entry.decision.send(approved).is_ok())
            .unwrap_or(false)
    }

    pub async fn cancel(&self, fingerprint: &str) {
        self.pending
            .lock()
            .await
            .remove(&fingerprint.to_ascii_lowercase());
    }
}

impl DecisionWaiter {
    /// Wait for the local decision (up to the approval timeout). Works no
    /// matter which side approved first: an early local decision is already
    /// sitting in the channel when this runs.
    pub async fn wait(mut self) -> Result<bool> {
        let Some(receiver) = self.receiver.take() else {
            return Ok(true);
        };
        let fingerprint = std::mem::take(&mut self.fingerprint);
        let decision = match tokio::time::timeout(PAIRING_APPROVAL_TIMEOUT, receiver).await {
            Ok(Ok(approved)) => approved,
            Ok(Err(_)) | Err(_) => false,
        };
        self.approvals.pending.lock().await.remove(&fingerprint);
        Ok(decision)
    }

    /// Drop a request that will never complete (initiator vanished, protocol
    /// error) so it stops occupying the approval list.
    pub async fn cancel(&self) {
        self.approvals.cancel(&self.fingerprint).await;
    }
}

pub async fn request(_data_dir: PathBuf, request: ControlRequest) -> Result<ControlResponse> {
    #[cfg(unix)]
    let mut stream = tokio::net::UnixStream::connect(unix_socket_path(&_data_dir))
        .await
        .context("connect daemon control socket")?;

    #[cfg(target_os = "windows")]
    let pipe = kvm_protocol::control::windows_control_pipe();
    #[cfg(target_os = "windows")]
    let mut stream = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&pipe)
        .context("connect daemon control pipe")?;

    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (data_dir, request);
        anyhow::bail!("local daemon control is not available on this operating system");
    }

    kvm_protocol::control::write_request(&mut stream, &request).await?;
    kvm_protocol::control::read_response(&mut stream)
        .await?
        .context("daemon closed control connection")
}

#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    data_dir: PathBuf,
    config: SharedConfig,
    peers: SharedPeers,
    active_sessions: Arc<AtomicUsize>,
    fingerprint: String,
    started: Arc<Instant>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    pairing_approvals: PairingApprovals,
) -> Result<()> {
    #[cfg(unix)]
    {
        run_unix_server(
            data_dir,
            config,
            peers,
            active_sessions,
            fingerprint,
            started,
            revoked_peers.clone(),
            pairing_approvals,
        )
        .await
    }
    #[cfg(target_os = "windows")]
    {
        run_windows_server(
            data_dir,
            config,
            peers,
            active_sessions,
            fingerprint,
            started,
            revoked_peers.clone(),
            pairing_approvals,
        )
        .await
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (
            data_dir,
            config,
            peers,
            active_sessions,
            fingerprint,
            started,
            revoked_peers,
            pairing_approvals,
        );
        tracing::warn!("local daemon control is not available on this operating system");
        crate::service::shutdown_notifier().notified().await;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection<S>(
    mut stream: S,
    data_dir: PathBuf,
    config: SharedConfig,
    peers: SharedPeers,
    active_sessions: Arc<AtomicUsize>,
    fingerprint: String,
    started: Arc<Instant>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    pairing_approvals: PairingApprovals,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(request) = read_request(&mut stream).await? else {
        return Ok(());
    };
    let response = match request {
        ControlRequest::Status => {
            let current = config.read().await.clone();
            let peer_count = peers.read().await.peers.len();
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ControlResponse::Status(DaemonStatus {
                node_name: current.device_name,
                pairing_code: kvm_protocol::pairing::station_pairing_code(
                    &fingerprint,
                    now_secs,
                ),
                fingerprint_hex: fingerprint,
                listen_port: current.listen_port,
                mode: current.mode,
                allow_lock_screen_control: current.allow_lock_screen_control,
                auto_connect_address: current.auto_connect_address,
                clipboard_enabled: current.clipboard_enabled,
                peer_count,
                active_session_count: active_sessions.load(std::sync::atomic::Ordering::Relaxed),
                sessions: crate::service::list_inbound_links(),
                uptime_seconds: started.elapsed().as_secs(),
            })
        }
        ControlRequest::GetConfig => ControlResponse::Config(config.read().await.clone()),
        ControlRequest::Pair {
            address,
            expected_fingerprint_hex,
        } => match crate::service::pair_for_daemon(
            &address,
            &expected_fingerprint_hex,
            peers.clone(),
        )
        .await
        {
            Ok(fingerprint_hex) => ControlResponse::Paired { fingerprint_hex },
            Err(error) => ControlResponse::Error {
                message: format!("pairing failed: {error}"),
            },
        },
        ControlRequest::ListPeers => ControlResponse::Peers(peers.read().await.peers.clone()),
        ControlRequest::ListPendingPairings => {
            ControlResponse::PendingPairings(pairing_approvals.list().await)
        }
        ControlRequest::ApprovePairing { fingerprint_hex } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                if pairing_approvals.decide(&fingerprint_hex, true).await {
                    crate::service::audit_event(
                        &data_dir,
                        &format!("pairing-approved fingerprint={fingerprint_hex}"),
                    );
                    ControlResponse::PairingApproved { fingerprint_hex }
                } else {
                    ControlResponse::Error {
                        message: "pending pairing request was not found".into(),
                    }
                }
            }
        }
        ControlRequest::RejectPairing { fingerprint_hex } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                if pairing_approvals.decide(&fingerprint_hex, false).await {
                    crate::service::audit_event(
                        &data_dir,
                        &format!("pairing-rejected fingerprint={fingerprint_hex}"),
                    );
                    ControlResponse::PairingRejected { fingerprint_hex }
                } else {
                    ControlResponse::Error {
                        message: "pending pairing request was not found".into(),
                    }
                }
            }
        }
        ControlRequest::Unpair { fingerprint_hex } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                match peers.write().await.unpin(&fingerprint_hex) {
                    Ok(true) => {
                        let _ = revoked_peers.send(fingerprint_hex.clone());
                        crate::service::audit_event(
                            &data_dir,
                            &format!("peer-revoked fingerprint={fingerprint_hex}"),
                        );
                        ControlResponse::Unpaired { fingerprint_hex }
                    }
                    Ok(false) => ControlResponse::Error {
                        message: "peer fingerprint was not paired".into(),
                    },
                    Err(error) => ControlResponse::Error {
                        message: format!("revoking peer failed: {error}"),
                    },
                }
            }
        }
        ControlRequest::DropSession { fingerprint_hex } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                if crate::service::drop_inbound_link(&fingerprint_hex) {
                    crate::service::audit_event(
                        &data_dir,
                        &format!("session-dropped fingerprint={fingerprint_hex}"),
                    );
                    ControlResponse::SessionDropped { fingerprint_hex }
                } else {
                    ControlResponse::Error {
                        message: "no live inbound session for that peer".into(),
                    }
                }
            }
        }
        ControlRequest::PinPeer {
            fingerprint_hex,
            node_name,
            address,
        } => {            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                let name = node_name
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or_else(|| format!("peer-{}", &fingerprint_hex[..8]));
                match peers
                    .write()
                    .await
                    .pin_with_address(name, fingerprint_hex.clone(), address)
                {
                    Ok(()) => {
                        crate::service::audit_event(
                            &data_dir,
                            &format!("peer-pinned fingerprint={fingerprint_hex}"),
                        );
                        ControlResponse::Pinned { fingerprint_hex }
                    }
                    Err(error) => ControlResponse::Error {
                        message: format!("pinning peer failed: {error}"),
                    },
                }
            }
        }
        ControlRequest::SetConfig {
            device_name,
            mode,
            allow_lock_screen_control,
            listen_port,
            layout,
            auto_connect_address,
            clear_auto_connect,
            clipboard_enabled,
        } => {
            if listen_port == Some(0) {
                ControlResponse::Error {
                    message: "listen port must be non-zero".into(),
                }
            } else if clear_auto_connect && auto_connect_address.is_some() {
                ControlResponse::Error {
                    message: "auto-connect address cannot be set and cleared together".into(),
                }
            } else {
                let mut current = config.write().await;
                if listen_port.is_some_and(|port| port != current.listen_port) {
                    ControlResponse::Error {
                        message: "changing the listener port requires restarting the daemon".into(),
                    }
                } else {
                    // Persist the candidate before publishing it to the running
                    // daemon. That prevents an I/O failure from leaving the live
                    // policy different from the configuration on disk.
                    let mut updated = current.clone();
                    if let Some(device_name) = device_name {
                        updated.device_name = device_name.trim().to_owned();
                    }
                    if let Some(mode) = mode {
                        updated.mode = mode;
                    }
                    if let Some(allow_lock_screen_control) = allow_lock_screen_control {
                        updated.allow_lock_screen_control = allow_lock_screen_control;
                    }
                    if clear_auto_connect {
                        updated.auto_connect_address = None;
                    } else if let Some(address) = auto_connect_address {
                        if address.trim().is_empty() {
                            return write_response(
                                &mut stream,
                                &ControlResponse::Error {
                                    message: "auto-connect address cannot be empty".into(),
                                },
                            )
                            .await
                            .map_err(Into::into);
                        }
                        updated.auto_connect_address = Some(address.trim().to_owned());
                    }
                    if let Some(enabled) = clipboard_enabled {
                        updated.clipboard_enabled = enabled;
                    }
                    if let Some(layout) = layout {
                        if let Err(error) = layout.validate() {
                            return write_response(
                                &mut stream,
                                &ControlResponse::Error {
                                    message: format!("invalid screen layout: {error}"),
                                },
                            )
                            .await
                            .map_err(Into::into);
                        }
                        updated.layout = layout;
                    }
                    match updated.save(&data_dir.join("config.json")) {
                        Ok(()) => {
                            let windows_controller_configured =
                                current.auto_connect_address.is_some()
                                    || updated.auto_connect_address.is_some();
                            let restart_required = cfg!(target_os = "windows")
                                && (updated.auto_connect_address != current.auto_connect_address
                                    || (windows_controller_configured
                                        && (updated.mode != current.mode
                                            || updated.allow_lock_screen_control
                                                != current.allow_lock_screen_control)));
                            // Audit every applied change with its provenance:
                            // if a mode ever "reverts by itself", this trail
                            // names exactly which writer did it and when.
                            if updated.mode != current.mode {
                                crate::service::audit_event(
                                    &data_dir,
                                    &format!(
                                        "mode {:?} -> {:?} via local control",
                                        current.mode, updated.mode
                                    ),
                                );
                            }
                            if updated.device_name != current.device_name {
                                crate::service::audit_event(
                                    &data_dir,
                                    &format!(
                                        "device renamed {:?} -> {:?} via local control",
                                        current.device_name, updated.device_name
                                    ),
                                );
                            }
                            *current = updated;
                            ControlResponse::Applied { restart_required }
                        }
                        Err(error) => ControlResponse::Error {
                            message: format!("saving configuration: {error}"),
                        },
                    }
                }
            }
        }
    };
    write_response(&mut stream, &response).await?;
    Ok(())
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use super::*;
    use kvm_protocol::control::{read_response, write_request};
    use kvm_protocol::pairing::PeerBook;

    #[tokio::test]
    async fn revoking_peer_persists_and_broadcasts_cancellation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!("thekvm-control-test-{nonce}"));
        let mut peer_book = PeerBook::load_or_create(&data_dir).unwrap();
        let fingerprint = "ab".repeat(32);
        peer_book
            .pin_with_address(
                "test-peer",
                fingerprint.clone(),
                Some("127.0.0.1:42110".into()),
            )
            .unwrap();

        let config = Arc::new(RwLock::new(Config::default()));
        let peers = Arc::new(RwLock::new(peer_book));
        let (revoked_tx, mut revoked_rx) = tokio::sync::broadcast::channel(4);
        let (mut client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(handle_connection(
            server,
            data_dir.clone(),
            config,
            peers.clone(),
            Arc::new(AtomicUsize::new(0)),
            "cd".repeat(32),
            Arc::new(Instant::now()),
            revoked_tx,
            PairingApprovals::default(),
        ));

        write_request(
            &mut client,
            &ControlRequest::Unpair {
                fingerprint_hex: fingerprint.to_ascii_uppercase(),
            },
        )
        .await
        .unwrap();
        let response = read_response(&mut client).await.unwrap().unwrap();
        assert!(matches!(
            response,
            ControlResponse::Unpaired { fingerprint_hex } if fingerprint_hex == fingerprint
        ));
        assert_eq!(revoked_rx.recv().await.unwrap(), fingerprint);
        assert!(peers.read().await.peers.is_empty());
        server_task.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn pending_pairing_can_be_listed_and_decided() {
        let approvals = PairingApprovals::default();
        let pending = PendingPairing {
            node_name: "incoming".into(),
            fingerprint_hex: "ab".repeat(32),
            address: "127.0.0.1:42110".into(),
            verification_code: "123456".into(),
        };
        // Registration alone must list the request (the station UI shows it
        // while the initiator compares codes); the waiter resolves later no
        // matter which side approved first.
        let waiter = approvals.register(pending.clone()).await.unwrap();
        assert_eq!(approvals.list().await.len(), 1);
        assert!(approvals.decide(&pending.fingerprint_hex, true).await);
        assert!(waiter.wait().await.unwrap());
        assert!(approvals.list().await.is_empty());
    }

    #[tokio::test]
    async fn early_local_decision_is_held_for_a_late_waiter() {
        // The station user Allows before the initiator confirms: decide()
        // removes the row but the decision must still reach wait().
        let approvals = PairingApprovals::default();
        let pending = PendingPairing {
            node_name: "early".into(),
            fingerprint_hex: "cd".repeat(32),
            address: "127.0.0.1:42110".into(),
            verification_code: "654321".into(),
        };
        let waiter = approvals.register(pending.clone()).await.unwrap();
        assert_eq!(approvals.list().await.len(), 1);
        assert!(approvals.decide(&pending.fingerprint_hex, true).await);
        assert!(approvals.list().await.is_empty());
        assert!(waiter.wait().await.unwrap());
    }

    #[tokio::test]
    async fn duplicate_pairing_request_is_refused_while_listed() {
        let approvals = PairingApprovals::default();
        let pending = PendingPairing {
            node_name: "dup".into(),
            fingerprint_hex: "ef".repeat(32),
            address: "127.0.0.1:42110".into(),
            verification_code: "111111".into(),
        };
        let _first = approvals.register(pending.clone()).await.unwrap();
        assert!(approvals.register(pending.clone()).await.is_err());
        approvals.cancel(&pending.fingerprint_hex).await;
        assert!(approvals.list().await.is_empty());
    }
}

#[cfg(unix)]
pub fn unix_socket_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("control.sock")
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
async fn run_unix_server(
    data_dir: PathBuf,
    config: SharedConfig,
    peers: SharedPeers,
    active_sessions: Arc<AtomicUsize>,
    fingerprint: String,
    started: Arc<Instant>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    pairing_approvals: PairingApprovals,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let path = unix_socket_path(&data_dir);
    if path.exists() {
        std::fs::remove_file(&path).with_context(|| format!("remove stale {}", path.display()))?;
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind daemon control socket {}", path.display()))?;
    // The deployment can place the desktop user in the service's group. In
    // development, the daemon and UI normally share THEKVM_DATA_DIR and user.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
    tracing::info!(path = %path.display(), "local daemon control ready");

    loop {
        tokio::select! {
            _ = crate::service::shutdown_notifier().notified() => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let config = config.clone();
                let peers = peers.clone();
                let active_sessions = active_sessions.clone();
                let fingerprint = fingerprint.clone();
                let started = started.clone();
                let revoked_peers = revoked_peers.clone();
                let pairing_approvals = pairing_approvals.clone();
                let data_dir = data_dir.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, data_dir, config, peers, active_sessions, fingerprint, started, revoked_peers, pairing_approvals).await {
                        tracing::debug!(%error, "local control connection closed");
                    }
                });
            }
        }
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
async fn run_windows_server(
    data_dir: PathBuf,
    config: SharedConfig,
    peers: SharedPeers,
    active_sessions: Arc<AtomicUsize>,
    fingerprint: String,
    started: Arc<Instant>,
    revoked_peers: tokio::sync::broadcast::Sender<String>,
    pairing_approvals: PairingApprovals,
) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe = kvm_protocol::control::windows_control_pipe();
    tracing::info!(pipe = %pipe, "local daemon control ready");
    loop {
        let mut server_options = ServerOptions::new();
        server_options.max_instances(16);
        server_options.reject_remote_clients(true);
        server_options.write_dac(true);
        let server = server_options
            .create(&pipe)
            .context("create daemon control named pipe")?;
        apply_control_pipe_acl(&server)?;
        tokio::select! {
            _ = crate::service::shutdown_notifier().notified() => break,
            connected = server.connect() => {
                connected.context("connect daemon control named pipe")?;
                let data_dir = data_dir.clone();
                let config = config.clone();
                let peers = peers.clone();
                let active_sessions = active_sessions.clone();
                let fingerprint = fingerprint.clone();
                let started = started.clone();
                let revoked_peers = revoked_peers.clone();
                let pairing_approvals = pairing_approvals.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(server, data_dir, config, peers, active_sessions, fingerprint, started, revoked_peers, pairing_approvals).await {
                        tracing::debug!(%error, "local control connection closed");
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_control_pipe_acl(server: &tokio::net::windows::named_pipe::NamedPipeServer) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, BOOL, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };

    // SYSTEM, local administrators, and users in an interactive logon may
    // operate the UI control endpoint. Remote clients are separately rejected
    // by PIPE_REJECT_REMOTE_CLIENTS. Keep this ACL explicit instead of
    // inheriting an account-dependent default pipe descriptor.
    let sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)\0";
    let wide = sddl.encode_utf16().collect::<Vec<_>>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
        .context("convert control pipe SDDL")?;
    }

    let mut dacl_present = BOOL::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut dacl_defaulted = BOOL::default();
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .context("read control pipe SDDL")?;
    if dacl_present.0 == 0 || dacl.is_null() {
        anyhow::bail!("control pipe SDDL did not contain a DACL");
    }
    let result = unsafe {
        SetSecurityInfo(
            HANDLE(server.as_raw_handle()),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl as *const ACL),
            None,
        )
    };
    let security_result = if result.0 == 0 {
        Ok(())
    } else {
        anyhow::bail!("SetSecurityInfo failed with Win32 error {}", result.0)
    };
    unsafe {
        let _ = LocalFree(HLOCAL(descriptor.0));
    }
    security_result
}
