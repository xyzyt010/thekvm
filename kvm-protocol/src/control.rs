//! Local daemon-control protocol shared by the daemon and the desktop UI.

use crate::pairing::Peer;
use kvm_core::{Config, Layout, Mode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_CONTROL_FRAME_SIZE: usize = 64 * 1024;
#[cfg(target_os = "windows")]
pub const WINDOWS_CONTROL_PIPE: &str = r"\\.\pipe\thekvm-control";

/// Return the local Windows control pipe. Production uses the fixed default;
/// the override lets isolated test/service instances coexist on one host.
#[cfg(target_os = "windows")]
pub fn windows_control_pipe() -> String {
    std::env::var("THEKVM_CONTROL_PIPE")
        .ok()
        .filter(|pipe| !pipe.trim().is_empty())
        .unwrap_or_else(|| WINDOWS_CONTROL_PIPE.to_owned())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    GetConfig,
    Pair {
        address: String,
        expected_fingerprint_hex: String,
    },
    /// Return the daemon-owned trusted peer list.
    ListPeers,
    /// Revoke one daemon-owned peer fingerprint.
    Unpair {
        fingerprint_hex: String,
    },
    /// Return incoming network pairing requests waiting for local approval.
    ListPendingPairings,
    /// Approve one incoming pairing request by certificate fingerprint.
    ApprovePairing {
        fingerprint_hex: String,
    },
    /// Reject one incoming pairing request by certificate fingerprint.
    RejectPairing {
        fingerprint_hex: String,
    },
    SetConfig {
        /// Optional for compatibility with older desktop UIs. When supplied,
        /// it becomes the node name advertised and sent in handshakes.
        #[serde(default)]
        device_name: Option<String>,
        /// Replace the operating mode when supplied; omission preserves the
        /// daemon's current mode so partial CLI/UI updates are safe.
        #[serde(default)]
        mode: Option<Mode>,
        /// Replace lock-screen policy when supplied; omission preserves the
        /// current policy. The local CLI exposes explicit enable/disable
        /// switches for this field.
        #[serde(default)]
        allow_lock_screen_control: Option<bool>,
        listen_port: Option<u16>,
        /// Replace the validated screen topology when supplied.
        #[serde(default)]
        layout: Option<Layout>,
        /// Set a fixed boot-time controller peer when supplied. Omit to keep
        /// the existing value; set `clear_auto_connect` to remove it.
        #[serde(default)]
        auto_connect_address: Option<String>,
        #[serde(default)]
        clear_auto_connect: bool,
        /// Set or preserve normal logged-in text clipboard synchronization.
        #[serde(default)]
        clipboard_enabled: Option<bool>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub node_name: String,
    pub fingerprint_hex: String,
    pub listen_port: u16,
    pub mode: Mode,
    pub allow_lock_screen_control: bool,
    pub auto_connect_address: Option<String>,
    pub clipboard_enabled: bool,
    pub peer_count: usize,
    pub active_session_count: usize,
    pub uptime_seconds: u64,
}

/// A remote identity that completed the network half of pairing and is
/// waiting for this machine's explicit local approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPairing {
    pub node_name: String,
    pub fingerprint_hex: String,
    pub address: String,
    /// Six-digit numeric-comparison code derived from both endpoints'
    /// fingerprints. Both machines display the same value so the two users
    /// can compare digits instead of 128 hexadecimal characters.
    #[serde(default)]
    pub verification_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlResponse {
    Status(DaemonStatus),
    Config(Config),
    Paired { fingerprint_hex: String },
    Peers(Vec<Peer>),
    Unpaired { fingerprint_hex: String },
    PendingPairings(Vec<PendingPairing>),
    PairingApproved { fingerprint_hex: String },
    PairingRejected { fingerprint_hex: String },
    Applied { restart_required: bool },
    Error { message: String },
}

pub async fn write_request<W>(writer: &mut W, request: &ControlRequest) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_json_frame(writer, request).await
}

pub async fn read_request<R>(reader: &mut R) -> std::io::Result<Option<ControlRequest>>
where
    R: AsyncRead + Unpin,
{
    read_json_frame(reader).await
}

pub async fn write_response<W>(writer: &mut W, response: &ControlResponse) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_json_frame(writer, response).await
}

pub async fn read_response<R>(reader: &mut R) -> std::io::Result<Option<ControlResponse>>
where
    R: AsyncRead + Unpin,
{
    read_json_frame(reader).await
}

async fn write_json_frame<W, T>(writer: &mut W, value: &T) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if payload.is_empty() || payload.len() > MAX_CONTROL_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control message exceeds maximum frame size",
        ));
    }
    writer
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

async fn read_json_frame<R, T>(reader: &mut R) -> std::io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_CONTROL_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid control frame size: {size}"),
        ));
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn control_frames_round_trip() {
        let (mut left, mut right) = tokio::io::duplex(1024);
        let request = ControlRequest::SetConfig {
            device_name: Some("office-controller".into()),
            mode: Some(Mode::ServerClient),
            allow_lock_screen_control: Some(true),
            listen_port: Some(42110),
            layout: None,
            auto_connect_address: Some("127.0.0.1:42110".into()),
            clear_auto_connect: false,
            clipboard_enabled: Some(true),
        };
        let expected_address = "127.0.0.1:42110".to_owned();
        let sender = tokio::spawn(async move {
            write_request(&mut left, &request).await.unwrap();
        });
        let Some(ControlRequest::SetConfig {
            device_name,
            mode,
            allow_lock_screen_control,
            listen_port,
            layout,
            auto_connect_address,
            clear_auto_connect,
            clipboard_enabled,
        }) = read_request(&mut right).await.unwrap()
        else {
            panic!("expected SetConfig request");
        };
        assert_eq!(device_name.as_deref(), Some("office-controller"));
        assert_eq!(mode, Some(Mode::ServerClient));
        assert_eq!(allow_lock_screen_control, Some(true));
        assert_eq!(listen_port, Some(42110));
        assert!(layout.is_none());
        assert_eq!(
            auto_connect_address.as_deref(),
            Some(expected_address.as_str())
        );
        assert!(!clear_auto_connect);
        assert_eq!(clipboard_enabled, Some(true));
        sender.await.unwrap();
    }

    #[test]
    fn older_set_config_frames_default_device_name_to_preserve() {
        let request: ControlRequest = serde_json::from_str(
            r#"{
                "SetConfig": {
                    "mode": "Bidirectional",
                    "allow_lock_screen_control": false,
                    "listen_port": null,
                    "layout": null,
                    "auto_connect_address": null,
                    "clear_auto_connect": false,
                    "clipboard_enabled": null
                }
            }"#,
        )
        .unwrap();
        let ControlRequest::SetConfig { device_name, .. } = request else {
            panic!("expected SetConfig request");
        };
        assert!(device_name.is_none());
    }

    #[test]
    fn partial_set_config_defaults_policy_fields_to_preserve() {
        let request: ControlRequest = serde_json::from_str(
            r#"{
                "SetConfig": {
                    "device_name": "new-name",
                    "listen_port": null,
                    "layout": null,
                    "auto_connect_address": null,
                    "clear_auto_connect": false,
                    "clipboard_enabled": null
                }
            }"#,
        )
        .unwrap();
        let ControlRequest::SetConfig {
            mode,
            allow_lock_screen_control,
            ..
        } = request
        else {
            panic!("expected SetConfig request");
        };
        assert!(mode.is_none());
        assert!(allow_lock_screen_control.is_none());
    }
}
