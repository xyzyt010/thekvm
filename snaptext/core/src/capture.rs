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

/// Origin (virtual-screen x/y) of the monitor `fullscreen()` captures, so a
/// freeze overlay can be parked exactly over it. Falls back to (0,0).
pub fn fullscreen_origin() -> (i32, i32) {
    xcap::Monitor::all()
        .ok()
        .and_then(|m| m.into_iter().next())
        .map(|m| (m.x().unwrap_or(0), m.y().unwrap_or(0)))
        .unwrap_or((0, 0))
}

/// Map an overlay rect in Slint logical pixels to image pixels.
/// `scale` is the overlay window's scale factor; the window is sized so its
/// physical size equals the image size, so logical×scale lands on pixels.
pub fn map_logical_rect(
    lx: f32,
    ly: f32,
    lw: f32,
    lh: f32,
    scale: f32,
    img_w: u32,
    img_h: u32,
) -> (u32, u32, u32, u32) {
    let s = if scale > 0.0 { scale } else { 1.0 };
    let x = (lx * s).round().clamp(0.0, img_w.saturating_sub(1) as f32) as u32;
    let y = (ly * s).round().clamp(0.0, img_h.saturating_sub(1) as f32) as u32;
    let w = ((lw * s).round() as u32).clamp(1, img_w.saturating_sub(x).max(1));
    let h = ((lh * s).round() as u32).clamp(1, img_h.saturating_sub(y).max(1));
    (x, y, w, h)
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

/// Crop helper kept in core so UI crates never mix `image` versions.
pub fn crop(img: &RgbaImage, x: u32, y: u32, w: u32, h: u32) -> RgbaImage {
    let (fw, fh) = (img.width(), img.height());
    let x = x.min(fw.saturating_sub(1));
    let y = y.min(fh.saturating_sub(1));
    let w = w.max(1).min(fw.saturating_sub(x));
    let h = h.max(1).min(fh.saturating_sub(y));
    image::imageops::crop_imm(img, x, y, w, h).to_image()
}
