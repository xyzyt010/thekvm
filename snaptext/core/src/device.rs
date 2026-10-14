//! Device profiler: OS / arch / CPU / RAM / display server.
use serde::{Deserialize, Serialize};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub cpu: String,
    pub cores_logical: usize,
    pub cores_physical: usize,
    pub ram_gb: f64,
    pub display: String,
    pub supported_v1: bool,
}

pub fn arch_key(machine: &str) -> &'static str {
    match machine.to_lowercase().as_str() {
        "amd64" | "x86_64" | "x86-64" | "x64" => "x86_64",
        "aarch64" | "arm64" => "arm64",
        _ => "unknown",
    }
}

pub fn detect_display() -> String {
    #[cfg(target_os = "windows")]
    return "windows".to_string();
    #[cfg(not(target_os = "windows"))]
    {
        if std::env::var("HYPRLAND_INSTANCE_SIGNATURE").is_ok()
            || std::env::var("HYPRLAND_CMD").is_ok()
        {
            return "hyprland".to_string();
        }
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default().to_lowercase();
        let session = std::env::var("XDG_SESSION_TYPE").unwrap_or_default().to_lowercase();
        if desktop.contains("xfce") {
            return if session == "wayland" {
                "xfce4-wayland".to_string()
            } else {
                "xfce4".to_string()
            };
        }
        if session == "wayland" {
            return "wayland".to_string();
        }
        if std::env::var("WAYLAND_DISPLAY").is_ok() {
            return if desktop.contains("hyprland") {
                "hyprland".to_string()
            } else {
                "wayland".to_string()
            };
        }
        if std::env::var("DISPLAY").is_ok() {
            return "x11".to_string();
        }
        "unknown".to_string()
    }
}

pub fn profile() -> DeviceProfile {
    let mut sys = System::new_all();
    sys.refresh_all();
    let ram_gb = (sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0 * 10.0).round() / 10.0;
    let cores_logical = sys.cpus().len().max(1);
    let cores_physical = sys.physical_core_count().unwrap_or(cores_logical.max(1) / 2).max(1);
    let arch = std::env::consts::ARCH.to_string();
    let os = std::env::consts::OS.to_string();
    let display = detect_display();
    let v1 = matches!(os.as_str(), "windows" | "linux")
        && matches!(arch_key(&arch), "x86_64");
    DeviceProfile {
        os,
        os_version: System::os_version().unwrap_or_default(),
        arch,
        cpu: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        cores_logical,
        cores_physical,
        ram_gb,
        display,
        supported_v1: v1,
    }
}
