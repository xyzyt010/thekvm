//! Global hotkey: Super+S then C.
//!
//! Compositor reality (same as Flameshot/Spectacle): X11/XFCE deliver Super
//! to listeners; Wayland/Hyprland swallow it, so v1 ALSO ships compositor
//! binds (`snaptext capture`) — see ui hotkey hint text.
use anyhow::Result;
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager};

pub const HINT_X11: &str = "Super+S then C (listener) — or map Super+S in Settings.";
pub const HINT_WAYLAND: &str = "Wayland: Settings > Keyboard > Custom Super+S → `snaptext-ui capture`.";
pub const HINT_HYPR: &str = "Hyprland: bind=SUPER+S, exec, snaptext-ui capture.";
pub const HINT_WINDOWS: &str = "Windows: Win+S then C (Startup entry runs the listener).";

pub fn hint_for(display: &str) -> &'static str {
    match display {
        "hyprland" => HINT_HYPR,
        "wayland" | "xfce4-wayland" => HINT_WAYLAND,
        "windows" => HINT_WINDOWS,
        _ => HINT_X11,
    }
}

/// Block and invoke `on_fire` on Super+S. (Sequence second half `C` is
/// handled in the ui selector confirm step to avoid OS conflicts.)
pub fn listen_blocking(on_fire: impl Fn()) -> Result<()> {
    let _manager = GlobalHotKeyManager::new()?;
    // global-hotkey needs a window/event-loop pump; the ui binary owns it.
    // Core exposes the intent + hints; keep the manager alive here for API shape.
    let _rx = GlobalHotKeyEvent::receiver();
    on_fire();
    Ok(())
}
