//! Platform abstraction: input injection (receiver side) and capture (sender side).
//!
//! The critical property: **injection runs in the privileged daemon**, so on
//! Linux/FreeBSD it goes through `/dev/uinput` (reaches greeters + lock screens) and
//! on Windows through `SendInput` from a LocalSystem service attached to the
//! current input desktop (Default, Winlogon, or Screen-saver).

pub mod capture;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "windows"))]
pub mod clipboard;
pub mod diagnostics;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub mod evdev_capture;
pub mod inject;
#[cfg(target_os = "linux")]
pub mod wayland_capture;
#[cfg(target_os = "linux")]
pub mod x11_capture;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("uinput unavailable: {0}")]
    Uinput(String),
    #[error("win32 error: {0}")]
    Win32(String),
    #[error("capture backend unavailable: {0}")]
    Capture(String),
    #[error("clipboard unavailable: {0}")]
    Clipboard(String),
}
