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
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
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
        Command::Connect { address } => service::connect(address.as_deref()).await,
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
