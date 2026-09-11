//! TheKVM privileged daemon.
//!
//! Runs as:
//! - Windows: LocalSystem service (reaches Winlogon desktop — MWB parity)
//! - Linux:   systemd system unit with `input` group access to /dev/uinput
//!   (reaches GDM/SDDM/LightDM greeters + lock screens)

mod control;
mod service;

#[cfg(target_os = "windows")]
mod windows_helper;

#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kvm-daemon", about = "TheKVM cross-OS KVM privileged daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Default)]
enum Command {
    /// Run the daemon (default when launched by systemd / SCM).
    #[default]
    Serve,
    /// Print this machine's certificate fingerprint.
    Fingerprint,
    /// Replace this machine's certificate/key identity; requires the daemon
    /// to be stopped and explicit confirmation.
    RotateIdentity {
        /// Confirm that every peer accepting this identity must be paired again.
        #[arg(long)]
        yes: bool,
    },
    /// Pair with a peer: connect, exchange fingerprints, pin each other.
    Pair {
        /// Peer address as ip:port, or a `thekvm://` invite from the peer
        address: String,
    },
    /// Print this machine's pairing invite for the peer to scan or paste.
    Invite,
    /// List trusted peers.
    Peers,
    /// Discover TheKVM receivers on the local LAN.
    Discover {
        /// How long to listen for responses, in milliseconds.
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
    },
    /// Query the running daemon's local control endpoint.
    Status,
    /// List incoming pairing requests waiting for local approval.
    PendingPairings,
    /// Approve an incoming pairing request by certificate fingerprint.
    ApprovePairing { fingerprint: String },
    /// Reject an incoming pairing request by certificate fingerprint.
    RejectPairing { fingerprint: String },
    /// Check local platform prerequisites without changing system state.
    Doctor,
    /// Revoke a trusted peer by its certificate fingerprint.
    Unpair { fingerprint: String },
    /// Pin a peer directly into the running daemon's peer book (mirrors
    /// trust established elsewhere, e.g. the desktop UI ceremony).
    PinPeer {
        /// Peer certificate fingerprint (64 hex characters).
        fingerprint: String,
        /// Display name; the existing name is kept when omitted.
        #[arg(long)]
        name: Option<String>,
        /// Last known address; the existing address is kept when omitted.
        #[arg(long)]
        address: Option<String>,
    },
    /// Send a test input event to a peer (for validating the pipeline).
    Send {
        address: String,
        /// USB HID keyboard usage to press (0x04 is A)
        #[arg(default_value_t = 0x04)]
        keycode: u16,
    },
    /// Capture this machine's physical input and stream it to a peer.
    Capture { address: String },
    /// Capture physical input and reconnect to a paired peer until Ctrl+C.
    Connect {
        /// Fixed peer address. Omit it to use the configured screen topology.
        address: Option<String>,
        /// Administrative link epoch both sides share (minted by the UI).
        /// A rejection naming a banned epoch ends the child (the peer
        /// disconnected on purpose) instead of retrying forever.
        #[arg(long)]
        link_id: Option<u64>,
        /// Read the daemon-owned identity from stdin (two hex lines:
        /// certificate DER, then key DER) instead of the local files, so a
        /// UI-supervised child presents the SAME fingerprint as the service.
        /// Without this the child loads the interactive user's identity and
        /// the peer sees two faces for one machine.
        #[arg(long)]
        identity_stdin: bool,
    },
    /// Update persistent daemon configuration.
    Configure {
        /// Friendly node name advertised during LAN discovery and pairing.
        #[arg(long)]
        device_name: Option<String>,
        /// `bidirectional`, `server-client` (controller only), or
        /// `receiver-only` (client/receiver only).
        #[arg(long)]
        mode: Option<String>,
        /// Allow paired peers to request lock-screen-capable injection.
        #[arg(long, conflicts_with = "disable_lock_screen_control")]
        allow_lock_screen_control: bool,
        /// Explicitly disable lock-screen-capable injection.
        #[arg(long, conflicts_with = "allow_lock_screen_control")]
        disable_lock_screen_control: bool,
        /// UDP port for the daemon.
        #[arg(long)]
        listen_port: Option<u16>,
        /// JSON file containing a validated Layout object.
        #[arg(long)]
        layout: Option<std::path::PathBuf>,
        /// Configure a fixed peer for the Windows boot-time controller path.
        #[arg(long)]
        auto_connect: Option<String>,
        /// Disable the configured Windows boot-time controller peer.
        #[arg(long)]
        clear_auto_connect: bool,
        /// Enable normal logged-in text clipboard synchronization.
        #[arg(long, conflicts_with = "disable_clipboard")]
        enable_clipboard: bool,
        /// Disable normal logged-in text clipboard synchronization.
        #[arg(long, conflicts_with = "enable_clipboard")]
        disable_clipboard: bool,
    },
}

fn main() -> Result<()> {
    // The Windows SCM discards service stderr, so the service has always
    // been log-blind: every Mint→Windows receive-side line (warp
    // outcomes, session ends, rejections) vanished at birth. Service mode
    // logs to a capped file instead; every other mode keeps stderr
    // (supervised children rely on it for THEKVM_STATUS progress).
    #[cfg(target_os = "windows")]
    let writer = service_file_writer();
    #[cfg(target_os = "windows")]
    if let Some(writer) = writer {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
            )
            .with_writer(writer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
            )
            // Supervised children run with stdout nulled (the UI pipes stderr
            // for progress): diagnostics must go to stderr or they vanish.
            .with_writer(std::io::stderr)
            .init();
    }
    #[cfg(not(target_os = "windows"))]
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        // Supervised children run with stdout nulled (the UI pipes stderr
        // for progress): diagnostics must go to stderr or they vanish.
        .with_writer(std::io::stderr)
        .init();

    #[cfg(target_os = "windows")]
    {
        let arguments = std::env::args().collect::<Vec<_>>();
        if arguments.iter().any(|argument| argument == "--service") {
            return service::run_windows_service();
        }
        if let Some(index) = arguments.iter().position(|argument| argument == "--helper") {
            let port = arguments
                .get(index + 1)
                .context("missing Windows helper port")?
                .parse::<u16>()
                .context("invalid Windows helper port")?;
            let token = arguments
                .get(index + 2)
                .context("missing Windows helper token")?;
            let desktop = arguments
                .get(index + 3)
                .context("missing Windows helper desktop")?;
            return windows_helper::run_helper(port, token, desktop);
        }
        if let Some(index) = arguments
            .iter()
            .position(|argument| argument == "--capture-helper")
        {
            let port = arguments
                .get(index + 1)
                .context("missing Windows capture helper port")?
                .parse::<u16>()
                .context("invalid Windows capture helper port")?;
            let token = arguments
                .get(index + 2)
                .context("missing Windows capture helper token")?;
            let desktop = arguments
                .get(index + 3)
                .context("missing Windows capture helper desktop")?;
            return windows_helper::run_capture_helper(port, token, desktop);
        }
    }

    async_main()
}

/// SCM-discarded stderr replacement for `--service` mode: an
/// append-only, capped process log at %ProgramData%\TheKVM\daemon.log.
/// std-only (offline builds can't add tracing-appender): an Arc-Mutex
/// file behind MakeWriter. Some(...) only in service mode; foreground
/// modes keep stderr via the None path in main().
#[cfg(target_os = "windows")]
fn service_file_writer() -> Option<ServiceFileWriter> {
    if !std::env::args().any(|argument| argument == "--service") {
        return None;
    }
    let dir = std::env::var("PROGRAMDATA")
        .map(|base| std::path::PathBuf::from(base).join("TheKVM"))
        .ok()?;
    std::fs::create_dir_all(&dir).ok()?;
    let file = open_capped_log(&dir.join("daemon.log"), 8 * 1024 * 1024)?;
    Some(ServiceFileWriter {
        file: std::sync::Arc::new(std::sync::Mutex::new(file)),
    })
}

/// Open an append log, truncating a wedged giant first so a stuck
/// session can never fill the disk. Pure enough for tests (any dir).
#[cfg(target_os = "windows")]
fn open_capped_log(path: &std::path::Path, cap_bytes: u64) -> Option<std::fs::File> {
    if std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) > cap_bytes {
        std::fs::write(path, "").ok()?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

#[cfg(target_os = "windows")]
#[derive(Clone)]
struct ServiceFileWriter {
    file: std::sync::Arc<std::sync::Mutex<std::fs::File>>,
}

#[cfg(target_os = "windows")]
impl std::io::Write for ServiceFileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "service log lock poisoned"))?
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "service log lock poisoned"))?
            .flush()
    }
}

#[cfg(target_os = "windows")]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ServiceFileWriter {
    type Writer = ServiceFileWriter;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn service_log_appends_and_caps() {
        let dir = std::env::temp_dir().join(format!("thekvm-svclog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("daemon.log");
        let file = open_capped_log(&path, 8 * 1024 * 1024).expect("open log");
        let mut writer = ServiceFileWriter {
            file: std::sync::Arc::new(std::sync::Mutex::new(file)),
        };
        writer.write_all(b"warp placed\n").unwrap();
        writer.flush().unwrap();
        // Round-trip through the MakeWriter face the subscriber uses.
        use tracing_subscriber::fmt::MakeWriter as _;
        writer.make_writer().write_all(b"second line\n").unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("warp placed"), "{body}");
        assert!(body.contains("second line"), "{body}");
        // Over the cap: next open truncates.
        std::fs::write(&path, vec![b'x'; 16]).unwrap();
        open_capped_log(&path, 8).expect("reopen capped log");
        assert_eq!(std::fs::read(&path).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[tokio::main]
async fn async_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Fingerprint => service::print_fingerprint(),
        Command::RotateIdentity { yes } => service::rotate_identity(yes).await,
        Command::Pair { address } => service::pair(&address).await,
        Command::Invite => service::print_invite(),
        Command::Peers => service::list_peers(),
        Command::Discover { timeout_ms } => service::discover(timeout_ms).await,
        Command::Status => service::status().await,
        Command::PendingPairings => service::pending_pairings().await,
        Command::ApprovePairing { fingerprint } => {
            service::decide_pairing(&fingerprint, true).await
        }
        Command::RejectPairing { fingerprint } => {
            service::decide_pairing(&fingerprint, false).await
        }
        Command::Doctor => service::doctor(),
        Command::Unpair { fingerprint } => service::unpair(&fingerprint).await,
        Command::PinPeer {
            fingerprint,
            name,
            address,
        } => {
            service::pin_peer(&fingerprint, name.as_deref(), address.as_deref()).await
        }
        Command::Send { address, keycode } => service::send_test(&address, keycode).await,
        Command::Capture { address } => service::capture(&address).await,
        Command::Connect {
            address,
            link_id,
            identity_stdin,
        } => {
            service::connect(address.as_deref(), link_id, identity_stdin).await
        }
        Command::Configure {
            device_name,
            mode,
            allow_lock_screen_control,
            disable_lock_screen_control,
            listen_port,
            layout,
            auto_connect,
            clear_auto_connect,
            enable_clipboard,
            disable_clipboard,
        } => {
            service::configure(service::ConfigureOptions {
                device_name: device_name.as_deref(),
                mode: mode.as_deref(),
                allow_lock_screen_control: if allow_lock_screen_control {
                    Some(true)
                } else if disable_lock_screen_control {
                    Some(false)
                } else {
                    None
                },
                listen_port,
                layout_path: layout.as_deref(),
                auto_connect_address: auto_connect.as_deref(),
                clear_auto_connect,
                clipboard_enabled: if enable_clipboard {
                    Some(true)
                } else if disable_clipboard {
                    Some(false)
                } else {
                    None
                },
            })
            .await
        }
        Command::Serve => service::run().await,
    }
}
