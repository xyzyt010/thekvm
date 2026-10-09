//! Local control server for the logged-in UI.

use anyhow::{bail, Context, Result};
use kvm_core::Config;
use kvm_protocol::control::{
    read_request, write_response, ControlRequest, ControlResponse, DaemonStatus, PendingLink,
    PendingPairing,
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
// Denial freeze: after this many denials of the same device inside
// REJECT_WINDOW, new pairing requests from it are refused for
// REJECT_FREEZE. A denied initiator auto-retries otherwise, so without
// the freeze one restless peer can ring the station forever. Approving
// clears the count — only sustained denial freezes.
const MAX_PAIRING_REJECTS: u32 = 5;
const REJECT_WINDOW: Duration = Duration::from_secs(10 * 60);
const REJECT_FREEZE: Duration = Duration::from_secs(60);

/// In-memory approval queue owned by the running daemon. A pairing request is
/// not persisted or trusted until the local user approves it through the
/// control endpoint.
#[derive(Clone, Default)]
pub struct PairingApprovals {
    pending: Arc<tokio::sync::Mutex<BTreeMap<String, PendingEntry>>>,
    rejects: Arc<tokio::sync::Mutex<std::collections::HashMap<String, RejectRecord>>>,
}

#[derive(Debug, Clone)]
struct RejectRecord {
    count: u32,
    window_started: Instant,
    frozen_until: Option<Instant>,
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
            // Denial freeze (see MAX_PAIRING_REJECTS): a device denied 5
            // times recently must cool off for a minute instead of ringing
            // the station again immediately.
            {
                let mut rejects = self.rejects.lock().await;
                if let Some(record) = rejects.get(&fingerprint) {
                    if record
                        .frozen_until
                        .is_some_and(|until| Instant::now() < until)
                    {
                        bail!(
                            "pairing attempts from this device are paused for 1 minute after repeated denials"
                        );
                    }
                }
                // Opportunistic janitor: drop cooled-off records so the map
                // cannot grow over months of uptime.
                rejects.retain(|_, record| {
                    record
                        .frozen_until
                        .is_some_and(|until| Instant::now() < until)
                        || record.window_started.elapsed() < REJECT_WINDOW
                });
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
        let removed = self
            .pending
            .lock()
            .await
            .remove(&fingerprint)
            .map(|entry| entry.decision.send(approved).is_ok())
            .unwrap_or(false);
        if removed {
            // Denial accounting (see MAX_PAIRING_REJECTS): approvals clear
            // the count, denials grow it toward the 1-minute freeze.
            let mut rejects = self.rejects.lock().await;
            if approved {
                rejects.remove(&fingerprint);
            } else {
                let now = Instant::now();
                let record = rejects.entry(fingerprint).or_insert(RejectRecord {
                    count: 0,
                    window_started: now,
                    frozen_until: None,
                });
                if record.window_started.elapsed() >= REJECT_WINDOW {
                    record.count = 0;
                    record.window_started = now;
                    record.frozen_until = None;
                }
                record.count += 1;
                if record.count >= MAX_PAIRING_REJECTS {
                    record.frozen_until = Some(now + REJECT_FREEZE);
                }
            }
        }
        removed
    }

    pub async fn cancel(&self, fingerprint: &str) {
        self.pending
            .lock()
            .await
            .remove(&fingerprint.to_ascii_lowercase());
    }
}

/// How long one inbound link waits for the local human: a link is a tap,
/// not a code ceremony, so this is far shorter than pairing — but long
/// enough that a user who stepped away hears "no answer" instead of the
/// initiator hanging forever. Expiry denies loudly.
const LINK_APPROVAL_TIMEOUT: Duration = Duration::from_secs(150);
/// A pairing IS a link approval for the link born right after it: the
/// human approved this exact device seconds ago, so the first link epoch
/// inside this window passes silently instead of popping a second
/// approval for the same decision.
const PAIRING_LINK_GRACE: Duration = Duration::from_secs(120);
/// Approved epochs are remembered (retries and the dial-back on the same
/// epoch never prompt again) but not forever: entries older than a day
/// are pruned, and the set is capped so months of uptime cannot grow it.
const APPROVED_LINK_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const APPROVED_LINK_CAP: usize = 512;

/// In-memory link-approval queue owned by the running daemon. Pairing
/// trust alone never opens a link: every fresh link epoch from a paired
/// peer waits here until the local user allows or denies it, and no
/// input flows before that decision.
#[derive(Clone, Default)]
pub struct LinkApprovals {
    pending: Arc<tokio::sync::Mutex<BTreeMap<(String, u64), PendingLinkEntry>>>,
    approved: Arc<tokio::sync::Mutex<std::collections::HashMap<(String, u64), Instant>>>,
    rejects: Arc<tokio::sync::Mutex<std::collections::HashMap<String, RejectRecord>>>,
    paired_at: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Instant>>>,
}

struct PendingLinkEntry {
    request: PendingLink,
    decision: oneshot::Sender<bool>,
}

/// Process-global link approvals (see [`LinkApprovals`]): the network
/// session task and the local control server must share one queue without
/// re-plumbing every server signature — the same shape as the daemon's
/// other cross-cutting registries.
pub fn link_approvals() -> LinkApprovals {
    static LINKS: std::sync::OnceLock<LinkApprovals> = std::sync::OnceLock::new();
    LINKS.get_or_init(LinkApprovals::default).clone()
}

impl LinkApprovals {
    /// Queue one inbound link for local approval. Epoch-less sessions
    /// never queue (fixed/admin paths carry no epoch to approve).
    /// A repeated denial freezes the device for a minute (same rule as
    /// pairing denials), and a second request for a queued epoch is
    /// refused so retries surface as guidance instead of silent rows.
    pub async fn register(&self, request: PendingLink) -> Result<LinkDecisionWaiter> {
        let fingerprint = request.fingerprint_hex.to_ascii_lowercase();
        let Some(link_id) = request.link_id else {
            bail!("epoch-less links never queue for approval");
        };
        let key = (fingerprint, link_id);
        let (decision_tx, decision_rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            if pending.contains_key(&key) {
                bail!("link is already awaiting local approval");
            }
            {
                let mut rejects = self.rejects.lock().await;
                if let Some(record) = rejects.get(&key.0) {
                    if record
                        .frozen_until
                        .is_some_and(|until| Instant::now() < until)
                    {
                        bail!(
                            "link attempts from this device are paused for 1 minute after repeated denials"
                        );
                    }
                }
                rejects.retain(|_, record| {
                    record
                        .frozen_until
                        .is_some_and(|until| Instant::now() < until)
                        || record.window_started.elapsed() < REJECT_WINDOW
                });
            }
            pending.insert(
                key.clone(),
                PendingLinkEntry {
                    request,
                    decision: decision_tx,
                },
            );
        }
        Ok(LinkDecisionWaiter {
            approvals: self.clone(),
            key,
            receiver: Some(decision_rx),
        })
    }

    pub async fn list(&self) -> Vec<PendingLink> {
        self.pending
            .lock()
            .await
            .values()
            .map(|entry| entry.request.clone())
            .collect()
    }

    /// Decide one queued link. Approvals remember the epoch (retries and
    /// the dial-back pass silently) and clear the denial count; denials
    /// grow it toward the 1-minute freeze.
    pub async fn decide(&self, fingerprint: &str, link_id: u64, approved: bool) -> bool {
        let key = (fingerprint.to_ascii_lowercase(), link_id);
        let removed = self
            .pending
            .lock()
            .await
            .remove(&key)
            .map(|entry| entry.decision.send(approved).is_ok())
            .unwrap_or(false);
        if removed {
            if approved {
                self.approved
                    .lock()
                    .await
                    .insert(key.clone(), Instant::now());
                self.prune_approved().await;
                self.rejects.lock().await.remove(&key.0);
            } else {
                let mut rejects = self.rejects.lock().await;
                let now = Instant::now();
                let record = rejects.entry(key.0).or_insert(RejectRecord {
                    count: 0,
                    window_started: now,
                    frozen_until: None,
                });
                if record.window_started.elapsed() >= REJECT_WINDOW {
                    record.count = 0;
                    record.window_started = now;
                    record.frozen_until = None;
                }
                record.count += 1;
                if record.count >= MAX_PAIRING_REJECTS {
                    record.frozen_until = Some(now + REJECT_FREEZE);
                }
            }
        }
        removed
    }

    /// True when this exact epoch was approved (or auto-passed) before.
    /// Prunes day-old entries on the way so the set stays bounded.
    pub async fn is_approved(&self, fingerprint: &str, link_id: u64) -> bool {
        self.prune_approved().await;
        self.approved
            .lock()
            .await
            .contains_key(&(fingerprint.to_ascii_lowercase(), link_id))
    }

    async fn prune_approved(&self) {
        let mut approved = self.approved.lock().await;
        approved.retain(|_, when| when.elapsed() < APPROVED_LINK_TTL);
        if approved.len() > APPROVED_LINK_CAP {
            approved.clear();
        }
    }

    /// Record a completed pairing: the link born from it inside
    /// PAIRING_LINK_GRACE passes silently (the human approved this exact
    /// device seconds ago — no second popup for the same decision).
    pub async fn note_paired(&self, fingerprint: &str) {
        let mut paired = self.paired_at.lock().await;
        paired.insert(fingerprint.to_ascii_lowercase(), Instant::now());
        paired.retain(|_, when| when.elapsed() < PAIRING_LINK_GRACE);
    }

    pub async fn recently_paired(&self, fingerprint: &str) -> bool {
        self.paired_at
            .lock()
            .await
            .get(&fingerprint.to_ascii_lowercase())
            .is_some_and(|when| when.elapsed() < PAIRING_LINK_GRACE)
    }

    /// Forget every approval for one epoch (Disconnect bans it) or one
    /// device (hang-up / unpair): the next dial prompts again.
    pub async fn revoke_epoch(&self, link_id: u64) {
        self.approved
            .lock()
            .await
            .retain(|(_, epoch), _| *epoch != link_id);
        self.pending
            .lock()
            .await
            .retain(|(_, epoch), _| *epoch != link_id);
    }

    pub async fn revoke_peer(&self, fingerprint: &str) {
        let fingerprint = fingerprint.to_ascii_lowercase();
        self.approved
            .lock()
            .await
            .retain(|(fp, _), _| *fp != fingerprint);
        self.pending
            .lock()
            .await
            .retain(|(fp, _), _| *fp != fingerprint);
    }

    pub async fn cancel(&self, fingerprint: &str, link_id: u64) {
        self.pending
            .lock()
            .await
            .remove(&(fingerprint.to_ascii_lowercase(), link_id));
    }
}

/// Handle for one queued link approval. Registering (listing it for the
/// local approval UI) and waiting for the decision are separate steps so
/// the station can show the request while the initiator still dials.
pub struct LinkDecisionWaiter {
    approvals: LinkApprovals,
    key: (String, u64),
    receiver: Option<oneshot::Receiver<bool>>,
}

impl LinkDecisionWaiter {
    /// Wait for the local decision (up to LINK_APPROVAL_TIMEOUT).
    /// Expiry denies: the initiator hears "no answer" and its child
    /// exits instead of hanging on a silent stream.
    pub async fn wait(mut self) -> Result<bool> {
        let Some(receiver) = self.receiver.take() else {
            return Ok(true);
        };
        let key = std::mem::take(&mut self.key);
        let decision = match tokio::time::timeout(LINK_APPROVAL_TIMEOUT, receiver).await {
            Ok(Ok(approved)) => approved,
            Ok(Err(_)) => false,
            Err(_) => false,
        };
        self.approvals.pending.lock().await.remove(&key);
        Ok(decision)
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
                pairing_code: kvm_protocol::pairing::station_pairing_code(&fingerprint, now_secs),
                fingerprint_hex: fingerprint,
                listen_port: current.listen_port,
                mode: current.mode,
                allow_lock_screen_control: current.allow_lock_screen_control,
                auto_connect_address: current.auto_connect_address,
                clipboard_enabled: current.clipboard_enabled,
                clipboard_max_mb: current.clipboard_max_mb,
                edge_mode: current.edge_mode,
                transport: current.transport,
                reverse_scroll: current.reverse_scroll,
                auto_discover: current.auto_discover,
                double_edge_style: current.double_edge_style,
                peer_count,
                active_session_count: active_sessions.load(std::sync::atomic::Ordering::Relaxed),
                sessions: crate::service::list_inbound_links(),
                peer_ended_links: crate::service::peer_ended_links(),
                recent_inbound: crate::service::recent_inbound_links(),
                uptime_seconds: started.elapsed().as_secs(),
            })
        }
        ControlRequest::GetConfig => ControlResponse::Config(config.read().await.clone()),
        ControlRequest::ClipboardPoll {
            last_seen_revision,
            next_index,
        } => crate::service::poll_inbound_clipboard(last_seen_revision, next_index),
        ControlRequest::ClipboardOffer {
            generation,
            kind,
            total_chunks,
            index,
            data,
            width,
            height,
        } => crate::service::submit_local_clipboard_chunk(
            generation,
            kind,
            total_chunks,
            index,
            data,
            width,
            height,
        ),
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
        ControlRequest::ListPendingLinks => {
            ControlResponse::PendingLinks(link_approvals().list().await)
        }
        ControlRequest::ApproveLink {
            fingerprint_hex,
            link_id,
        } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else if link_id.is_none() {
                ControlResponse::Error {
                    message: "epoch-less links never queue for approval".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                let link_id = link_id.unwrap_or(0);
                if link_approvals()
                    .decide(&fingerprint_hex, link_id, true)
                    .await
                {
                    crate::service::audit_event(
                        &data_dir,
                        &format!("link-approved fingerprint={fingerprint_hex} link_id={link_id}"),
                    );
                    ControlResponse::LinkApproved {
                        fingerprint_hex,
                        link_id: Some(link_id),
                    }
                } else {
                    ControlResponse::Error {
                        message: "pending link request was not found".into(),
                    }
                }
            }
        }
        ControlRequest::RejectLink {
            fingerprint_hex,
            link_id,
        } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else if link_id.is_none() {
                ControlResponse::Error {
                    message: "epoch-less links never queue for approval".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                let link_id = link_id.unwrap_or(0);
                if link_approvals()
                    .decide(&fingerprint_hex, link_id, false)
                    .await
                {
                    crate::service::audit_event(
                        &data_dir,
                        &format!("link-rejected fingerprint={fingerprint_hex} link_id={link_id}"),
                    );
                    ControlResponse::LinkRejected {
                        fingerprint_hex,
                        link_id: Some(link_id),
                    }
                } else {
                    ControlResponse::Error {
                        message: "pending link request was not found".into(),
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
                        // Trust gone means approvals gone too: a revoked
                        // device must prompt again even on a live epoch.
                        link_approvals().revoke_peer(&fingerprint_hex).await;
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
                    // A hung-up link must not silently re-open: forget its
                    // approvals so the next dial prompts again.
                    link_approvals().revoke_peer(&fingerprint_hex).await;
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
        ControlRequest::EndLink { link_id } => {
            crate::service::end_link(link_id);
            // A banned epoch must never ride a stale approval back in.
            link_approvals().revoke_epoch(link_id).await;
            crate::service::persist_ended_links(&data_dir);
            crate::service::audit_event(&data_dir, &format!("link-ended link_id={link_id}"));
            ControlResponse::LinkEnded { link_id }
        }
        ControlRequest::NotifyPeerEnded {
            fingerprint_hex,
            link_id,
        } => {
            if !is_fingerprint(&fingerprint_hex) {
                ControlResponse::Error {
                    message: "peer fingerprint must contain 64 hexadecimal characters".into(),
                }
            } else {
                let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
                let book = peers.read().await;
                match crate::service::notify_peer_ended(&book, &fingerprint_hex, link_id, &data_dir)
                    .await
                {
                    Ok(()) => {
                        crate::service::audit_event(
                            &data_dir,
                            &format!(
                                "link-end-notified peer={fingerprint_hex} link_id={link_id:?}"
                            ),
                        );
                        ControlResponse::PeerNotified { fingerprint_hex }
                    }
                    Err(error) => {
                        crate::service::audit_event(
                            &data_dir,
                            &format!(
                                "link-end-notify-failed peer={fingerprint_hex} link_id={link_id:?} error={error:#}"
                            ),
                        );
                        ControlResponse::Error {
                            message: format!("peer notify failed: {error:#}"),
                        }
                    }
                }
            }
        }
        ControlRequest::ExportIdentity => {
            match kvm_protocol::pairing::Identity::load_or_create(&data_dir) {
                Ok(identity) => ControlResponse::Identity {
                    cert_der_hex: kvm_protocol::pairing::hex_encode(&identity.cert_der),
                    key_der_hex: kvm_protocol::pairing::hex_encode(&identity.key_der),
                },
                Err(error) => ControlResponse::Error {
                    message: format!("reading daemon identity failed: {error}"),
                },
            }
        }
        ControlRequest::PinPeer {
            fingerprint_hex,
            node_name,
            address,
        } => {
            if !is_fingerprint(&fingerprint_hex) {
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
            clipboard_max_mb,
            edge_mode,
            transport,
            reverse_scroll,
            auto_discover,
            double_edge_style,
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
                    if let Some(max_mb) = clipboard_max_mb {
                        if max_mb == 0 || max_mb > kvm_core::config::MAX_CLIPBOARD_MAX_MB {
                            return write_response(
                                &mut stream,
                                &ControlResponse::Error {
                                    message: format!(
                                        "clipboard limit must be 1..={} MB",
                                        kvm_core::config::MAX_CLIPBOARD_MAX_MB
                                    ),
                                },
                            )
                            .await
                            .map_err(Into::into);
                        }
                        updated.clipboard_max_mb = max_mb;
                    }
                    if let Some(edge_mode) = edge_mode {
                        updated.edge_mode = edge_mode;
                    }
                    if let Some(reverse) = reverse_scroll {
                        updated.reverse_scroll = reverse;
                    }
                    if let Some(discover) = auto_discover {
                        updated.auto_discover = discover;
                    }
                    if let Some(style) = double_edge_style {
                        updated.double_edge_style = style;
                    }
                    if transport.is_some() {
                        // Transport is cemented to UDP: a stale client asking
                        // for QUIC is acknowledged but never honored.
                        updated.transport = kvm_core::TransportProtocol::Udp;
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

    #[tokio::test]
    async fn five_denials_freeze_new_requests_for_a_minute() {
        let approvals = PairingApprovals::default();
        let pending = PendingPairing {
            node_name: "restless".into(),
            fingerprint_hex: "aa".repeat(32),
            address: "127.0.0.1:42110".into(),
            verification_code: "222222".into(),
        };
        for _ in 0..5 {
            let _waiter = approvals.register(pending.clone()).await.unwrap();
            assert!(approvals.decide(&pending.fingerprint_hex, false).await);
        }
        // Fifth denial freezes: the next request is refused with the
        // cool-off reason instead of listing.
        let frozen = approvals
            .register(pending.clone())
            .await
            .err()
            .expect("frozen request must fail");
        assert!(
            frozen.to_string().contains("paused for 1 minute"),
            "unexpected freeze error: {frozen:#}"
        );
    }

    #[tokio::test]
    async fn approval_clears_the_denial_count() {
        let approvals = PairingApprovals::default();
        let pending = PendingPairing {
            node_name: "flip".into(),
            fingerprint_hex: "bb".repeat(32),
            address: "127.0.0.1:42110".into(),
            verification_code: "333333".into(),
        };
        for _ in 0..4 {
            let _waiter = approvals.register(pending.clone()).await.unwrap();
            assert!(approvals.decide(&pending.fingerprint_hex, false).await);
        }
        // An approval resets the streak: four more denials still list.
        let _waiter = approvals.register(pending.clone()).await.unwrap();
        assert!(approvals.decide(&pending.fingerprint_hex, true).await);
        let _waiter = approvals.register(pending.clone()).await.unwrap();
        assert!(approvals.decide(&pending.fingerprint_hex, false).await);
        assert!(approvals.register(pending.clone()).await.is_ok());
    }

    fn pending_link(fingerprint: &str, link_id: u64) -> PendingLink {
        PendingLink {
            node_name: "peer".into(),
            fingerprint_hex: fingerprint.to_owned(),
            address: "192.168.1.8:42110".into(),
            link_id: Some(link_id),
        }
    }

    #[tokio::test]
    async fn link_approval_gates_each_fresh_epoch() {
        let approvals = LinkApprovals::default();
        let fp = "cc".repeat(32);
        // Unknown epoch is not approved and nothing is pending.
        assert!(!approvals.is_approved(&fp, 7).await);
        assert!(approvals.list().await.is_empty());
        // Queue + approve: the epoch passes from here on.
        let _waiter = approvals.register(pending_link(&fp, 7)).await.unwrap();
        assert_eq!(approvals.list().await.len(), 1);
        assert!(approvals.decide(&fp, 7, true).await);
        assert!(approvals.is_approved(&fp, 7).await);
        assert!(approvals.list().await.is_empty());
        // A different epoch still prompts.
        assert!(!approvals.is_approved(&fp, 8).await);
    }

    #[tokio::test]
    async fn link_denial_freezes_like_pairing_denial() {
        let approvals = LinkApprovals::default();
        let fp = "dd".repeat(32);
        for epoch in 1..=5 {
            let _waiter = approvals.register(pending_link(&fp, epoch)).await.unwrap();
            assert!(approvals.decide(&fp, epoch, false).await);
        }
        let frozen = approvals
            .register(pending_link(&fp, 6))
            .await
            .err()
            .expect("frozen link must fail");
        assert!(frozen.to_string().contains("paused for 1 minute"));
    }

    #[tokio::test]
    async fn pairing_grace_passes_the_first_link_silently() {
        let approvals = LinkApprovals::default();
        let fp = "ee".repeat(32);
        assert!(!approvals.recently_paired(&fp).await);
        approvals.note_paired(&fp).await;
        assert!(approvals.recently_paired(&fp).await);
    }

    #[tokio::test]
    async fn revoke_forgets_epochs_and_peers() {
        let approvals = LinkApprovals::default();
        let fp = "ff".repeat(32);
        let _waiter = approvals.register(pending_link(&fp, 9)).await.unwrap();
        assert!(approvals.decide(&fp, 9, true).await);
        approvals.revoke_epoch(9).await;
        assert!(!approvals.is_approved(&fp, 9).await);
        let _waiter = approvals.register(pending_link(&fp, 10)).await.unwrap();
        assert!(approvals.decide(&fp, 10, true).await);
        approvals.revoke_peer(&fp).await;
        assert!(!approvals.is_approved(&fp, 10).await);
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
