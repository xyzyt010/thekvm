//! Capture: fullscreen / region / active window via xcap.
//! Wayland note: xcap uses portal/screencast where available (same path
//! Flameshot/Spectacle take); pure-secure Wayland still needs user consent.
use anyhow::{Context, Result};
use image::RgbaImage;

pub fn fullscreen() -> Result<RgbaImage> {
    let monitors = xcap::Monitor::all().context("enumerate monitors")?;
    let mon = monitors.into_iter().next().context("no monitor found")?;
    let img = mon.capture_image().context("capture fullscreen")?;
    Ok(img)
}

pub fn region(x: u32, y: u32, w: u32, h: u32) -> Result<RgbaImage> {
    let full = fullscreen()?;
    let (fw, fh) = (full.width(), full.height());
    let x = x.min(fw.saturating_sub(1));
    let y = y.min(fh.saturating_sub(1));
    let w = w.max(1).min(fw.saturating_sub(x));
    let h = h.max(1).min(fh.saturating_sub(y));
    Ok(image::imageops::crop_imm(&full, x, y, w, h).to_image())
}

pub fn active_window() -> Result<RgbaImage> {
    // v1: xcap window enumeration; pick focused/first visible window.
    // Mirrors Spectacle: X11 can address a window directly; Wayland goes
    // through the portal (xcap abstracts this).
    let windows = xcap::Window::all().context("enumerate windows")?;
    let win = windows
        .into_iter()
        .find(|w| w.is_focused().unwrap_or(false))
        .or_else(|| xcap::Window::all().ok().and_then(|mut v| v.pop()))
        .context("no window found; falling back to fullscreen")?;
    win.capture_image().context("capture window")
}

pub fn with_fallback_window() -> RgbaImage {
    active_window().or_else(|_| fullscreen()).expect("capture works on v1 targets")
}
