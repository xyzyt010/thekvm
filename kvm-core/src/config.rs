use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

pub const MAX_DEVICE_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub device_name: String,
    pub listen_port: u16,
    pub mode: Mode,
    #[serde(default)]
    pub layout: crate::layout::Layout,
    #[serde(default)]
    pub allow_lock_screen_control: bool,
    /// Optional fixed peer for the Windows LocalSystem controller path. This
    /// is deliberately opt-in; an ordinary service installation remains a
    /// receiver until a user configures a paired address.
    #[serde(default)]
    pub auto_connect_address: Option<String>,
    /// Synchronize plain text clipboard contents for ordinary logged-in
    /// sessions. It is opt-in because clipboard data is user content and is
    /// never required for privileged pre-login input.
    #[serde(default)]
    pub clipboard_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Both machines can control each other.
    Bidirectional,
    /// This node is a controller only; it accepts no incoming input sessions.
    ServerClient,
    /// This node is a receiver only; it may not initiate input sessions.
    #[serde(alias = "Client")]
    ClientOnly,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: hostname().unwrap_or_else(|| "unknown".into()),
            listen_port: 42110,
            mode: Mode::Bidirectional,
            layout: Default::default(),
            allow_lock_screen_control: false,
            auto_connect_address: None,
            clipboard_enabled: false,
        }
    }
}

impl Config {
    pub fn default_path() -> Option<PathBuf> {
        dirs_next()
    }

    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&raw)?;
        config.validate().map_err(std::io::Error::other)?;
        Ok(config)
    }

    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.validate().map_err(std::io::Error::other)?;
        atomic_write(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn validate(&self) -> Result<(), String> {
        let device_name = self.device_name.trim();
        if device_name.is_empty() {
            return Err("device name cannot be empty".into());
        }
        if device_name.len() > MAX_DEVICE_NAME_BYTES {
            return Err(format!(
                "device name exceeds {MAX_DEVICE_NAME_BYTES} UTF-8 bytes"
            ));
        }
        if device_name.chars().any(char::is_control) {
            return Err("device name cannot contain control characters".into());
        }
        if self.listen_port == 0 {
            return Err("listen port must be non-zero".into());
        }
        if self
            .auto_connect_address
            .as_deref()
            .is_some_and(|address| address.trim().is_empty())
        {
            return Err("auto-connect address cannot be empty".into());
        }
        if self.mode == Mode::ClientOnly && self.auto_connect_address.is_some() {
            return Err("receiver-only mode cannot have an auto-connect controller peer".into());
        }
        self.layout.validate()
    }
}

/// Replace a small state file through a flushed temporary file. Configuration
/// is read during every daemon start, so a truncated file after a crash would
/// otherwise prevent the service from coming back up.
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
}

fn dirs_next() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    return std::env::var("APPDATA")
        .ok()
        .map(|p| PathBuf::from(p).join("TheKVM"));
    #[cfg(not(target_os = "windows"))]
    return std::env::var("HOME")
        .ok()
        .map(|p| PathBuf::from(p).join(".config/thekvm"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn rejects_zero_port() {
        let config = Config {
            listen_port: 0,
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_empty_auto_connect_address() {
        let config = Config {
            auto_connect_address: Some("  ".into()),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_invalid_device_names() {
        let empty = Config {
            device_name: "  ".into(),
            ..Config::default()
        };
        assert!(empty.validate().is_err());

        let too_long = Config {
            device_name: "x".repeat(MAX_DEVICE_NAME_BYTES + 1),
            ..Config::default()
        };
        assert!(too_long.validate().is_err());

        let control = Config {
            device_name: "office\ncontroller".into(),
            ..Config::default()
        };
        assert!(control.validate().is_err());
    }

    #[test]
    fn receiver_only_mode_cannot_auto_connect() {
        let config = Config {
            mode: Mode::ClientOnly,
            auto_connect_address: Some("127.0.0.1:42110".into()),
            ..Config::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn mode_names_preserve_one_way_role_compatibility() {
        assert_eq!(
            serde_json::from_str::<Mode>(r#""ClientOnly""#).unwrap(),
            Mode::ClientOnly
        );
        assert_eq!(
            serde_json::from_str::<Mode>(r#""Client""#).unwrap(),
            Mode::ClientOnly
        );
        assert_eq!(
            serde_json::to_string(&Mode::ClientOnly).unwrap(),
            r#""ClientOnly""#
        );
    }

    #[test]
    fn loads_pre_topology_config_without_layout() {
        let config: Config = serde_json::from_str(
            r#"{
                "device_name": "old-node",
                "listen_port": 42110,
                "mode": "Bidirectional"
            }"#,
        )
        .unwrap();
        assert!(config.layout.screens.is_empty());
        assert!(!config.allow_lock_screen_control);
        assert!(config.auto_connect_address.is_none());
        assert!(!config.clipboard_enabled);
        assert!(config.validate().is_ok());
    }
}
