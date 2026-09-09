//! XInput2 raw capture for logged-in X11 sessions.
//!
//! X11 does not impose Wayland's compositor boundary, so a user-session
//! daemon can subscribe to XI2 raw events without opening `/dev/input`. The
//! backend grabs all master devices only while a topology session is active;
//! in local mode it observes raw input and leaves the normal X11 event path
//! untouched. HID usages use the standard X11 keycode-to-evdev offset, which
//! preserves physical keys rather than translating through the local layout.

use crate::{capture::CaptureBackend, PlatformError};
use kvm_core::{InputEvent, KeyEvent, MouseButton};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use x11rb::connection::Connection;
use x11rb::protocol::xinput::{self, ConnectionExt as XInputConnectionExt};
use x11rb::protocol::xproto;
use x11rb::rust_connection::RustConnection;

const ALL_MASTER_DEVICES: u16 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(4);
const FIXED_POINT_SCALE: f64 = 4_294_967_296.0;

/// Blocking adapter around XInput2's raw event stream.
pub struct X11Capture {
    connection: RustConnection,
    root: xproto::Window,
    exclusive: bool,
    motion_x: f64,
    motion_y: f64,
    /// Slave-device ids owned by our own uinput injector ("TheKVM Virtual
    /// Mouse/Keyboard"). Raw events carry only numeric source ids, so the
    /// set is resolved by device name and refreshed periodically: the
    /// injector creates its devices per receiver session, which can postdate
    /// this capture backend.
    ignored_sources: Vec<xinput::DeviceId>,
    last_source_refresh: std::time::Instant,
}

/// True when an XI device name is one of our own virtual injector devices.
/// Mirrors the evdev backend's name filter: the receiver injects through
/// uinput, the X server attaches that device to the master pointer, and
/// without this filter capture re-reads its own injected input and forwards
/// it back — a phantom second driver.
fn is_own_device_name(name: &[u8]) -> bool {
    String::from_utf8_lossy(name)
        .to_ascii_lowercase()
        .contains("thekvm")
}

/// Resolve our own slave-device ids via XIQueryDevice (0 = all devices).
/// `None` means enumeration failed: the caller keeps its previous set, so
/// capture never degrades because one query hiccuped.
fn query_own_sources(connection: &RustConnection) -> Option<Vec<xinput::DeviceId>> {
    let reply = connection
        // 0 is XIAllDevices: enumerate every slave device on the server.
        .xinput_xi_query_device(0u16)
        .map_err(|error| format!("query XInput2 devices: {error}"))
        .and_then(|cookie| {
            cookie
                .reply()
                .map_err(|error| format!("read XInput2 devices: {error}"))
        });
    match reply {
        Ok(reply) => Some(
            reply
                .infos
                .iter()
                .filter(|info| is_own_device_name(&info.name))
                .map(|info| info.deviceid)
                .collect(),
        ),
        Err(error) => {
            tracing::debug!(%error, "XInput2 device enumeration unavailable; echo filter unchanged");
            None
        }
    }
}

impl X11Capture {
    pub fn create() -> Result<Self, PlatformError> {
        let (connection, screen) = x11rb::connect(None)
            .map_err(|error| PlatformError::Capture(format!("connect to X11: {error}")))?;
        let root = connection
            .setup()
            .roots
            .get(screen)
            .ok_or_else(|| PlatformError::Capture("X11 screen does not exist".into()))?
            .root;

        connection
            .xinput_xi_query_version(2, 0)
            .map_err(|error| PlatformError::Capture(format!("query XInput2 version: {error}")))?
            .reply()
            .map_err(|error| PlatformError::Capture(format!("read XInput2 version: {error}")))?;

        let masks = [xinput::EventMask {
            deviceid: ALL_MASTER_DEVICES,
            mask: vec![xinput::XIEventMask::from(raw_mask())],
        }];
        connection
            .xinput_xi_select_events(root, &masks)
            .map_err(|error| PlatformError::Capture(format!("select XInput2 raw events: {error}")))?
            .check()
            .map_err(|error| {
                PlatformError::Capture(format!("select XInput2 raw events: {error}"))
            })?;
        connection
            .flush()
            .map_err(|error| PlatformError::Capture(format!("flush XInput2 setup: {error}")))?;

        let ignored_sources = query_own_sources(&connection).unwrap_or_default();
        tracing::info!(
            ignored = ignored_sources.len(),
            "X11 capture armed; own injector devices excluded from capture"
        );
        Ok(Self {
            connection,
            root,
            exclusive: false,
            motion_x: 0.0,
            motion_y: 0.0,
            ignored_sources,
            last_source_refresh: std::time::Instant::now(),
        })
    }

    fn translate(&mut self, event: x11rb::protocol::Event) -> Option<InputEvent> {
        match event {
            x11rb::protocol::Event::XinputRawKeyPress(event) => {
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                key_event(event.detail, true)
            }
            x11rb::protocol::Event::XinputRawKeyRelease(event) => {
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                key_event(event.detail, false)
            }
            x11rb::protocol::Event::XinputRawButtonPress(event) => {
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                button_event(event.detail, true)
            }
            x11rb::protocol::Event::XinputRawButtonRelease(event) => {
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                button_event(event.detail, false)
            }
            x11rb::protocol::Event::XinputRawMotion(event) => {
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                let dx = axis_value(&event.valuator_mask, &event.axisvalues_raw, 0)
                    .map(|value| take_integer(&mut self.motion_x, value))
                    .unwrap_or(0);
                let dy = axis_value(&event.valuator_mask, &event.axisvalues_raw, 1)
                    .map(|value| take_integer(&mut self.motion_y, value))
                    .unwrap_or(0);
                (dx != 0 || dy != 0).then_some(InputEvent::MouseMove { dx, dy })
            }
            _ => None,
        }
    }
}

impl CaptureBackend for X11Capture {
    fn next_event(
        &mut self,
        stop: &AtomicBool,
        exclusive: &AtomicBool,
        release: &AtomicBool,
    ) -> Result<InputEvent, PlatformError> {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(PlatformError::Capture("capture stopped".into()));
            }
            // The injector (re)creates its uinput devices per receiver
            // session, which can postdate this backend: re-resolve our own
            // sources every few seconds so freshly injected input is never
            // re-captured. One round trip per interval is negligible next
            // to the 4ms event poll.
            if self.last_source_refresh.elapsed() > std::time::Duration::from_secs(5) {
                self.last_source_refresh = std::time::Instant::now();
                if let Some(refreshed) = query_own_sources(&self.connection) {
                    self.ignored_sources = refreshed;
                }
            }
            if release.swap(false, Ordering::AcqRel) {
                self.release()?;
            }
            let desired_exclusive = exclusive.load(Ordering::Acquire);
            if desired_exclusive != self.exclusive {
                self.set_exclusive(desired_exclusive)?;
            }
            if let Some(event) = self
                .connection
                .poll_for_event()
                .map_err(|error| PlatformError::Capture(format!("poll XInput2 events: {error}")))?
            {
                if let Some(event) = self.translate(event) {
                    return Ok(event);
                }
                continue;
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    fn set_exclusive(&mut self, exclusive: bool) -> Result<(), PlatformError> {
        if exclusive == self.exclusive {
            return Ok(());
        }
        if exclusive {
            let mask = [raw_mask()];
            let status = self
                .connection
                .xinput_xi_grab_device(
                    self.root,
                    0u32,
                    0,
                    ALL_MASTER_DEVICES,
                    xproto::GrabMode::ASYNC,
                    xproto::GrabMode::ASYNC,
                    xinput::GrabOwner::NO_OWNER,
                    &mask,
                )
                .map_err(|error| PlatformError::Capture(format!("grab XInput2 devices: {error}")))?
                .reply()
                .map_err(|error| {
                    PlatformError::Capture(format!("read XInput2 grab status: {error}"))
                })?
                .status;
            if status != xproto::GrabStatus::SUCCESS {
                return Err(PlatformError::Capture(format!(
                    "XInput2 device grab was rejected ({status:?})"
                )));
            }
        } else {
            self.connection
                .xinput_xi_ungrab_device(0u32, ALL_MASTER_DEVICES)
                .map_err(|error| {
                    PlatformError::Capture(format!("ungrab XInput2 devices: {error}"))
                })?
                .check()
                .map_err(|error| {
                    PlatformError::Capture(format!("ungrab XInput2 devices: {error}"))
                })?;
        }
        self.connection.flush().map_err(|error| {
            PlatformError::Capture(format!("flush XInput2 grab state: {error}"))
        })?;
        self.exclusive = exclusive;
        Ok(())
    }

    fn release(&mut self) -> Result<(), PlatformError> {
        if self.exclusive {
            self.set_exclusive(false)?;
        }
        Ok(())
    }
}

impl Drop for X11Capture {
    fn drop(&mut self) {
        let _ = self.set_exclusive(false);
    }
}

fn key_event(detail: u32, pressed: bool) -> Option<InputEvent> {
    let keycode = u8::try_from(detail).ok()?;
    let evdev_code = keycode.checked_sub(8)?;
    crate::evdev_capture::hid_from_evdev(u16::from(evdev_code))
        .map(|usage| InputEvent::Key(KeyEvent { usage, pressed }))
}

fn raw_mask() -> u32 {
    u32::from(xinput::XIEventMask::RAW_KEY_PRESS)
        | u32::from(xinput::XIEventMask::RAW_KEY_RELEASE)
        | u32::from(xinput::XIEventMask::RAW_BUTTON_PRESS)
        | u32::from(xinput::XIEventMask::RAW_BUTTON_RELEASE)
        | u32::from(xinput::XIEventMask::RAW_MOTION)
}

fn button_event(detail: u32, pressed: bool) -> Option<InputEvent> {
    match detail {
        1 => Some(InputEvent::MouseButton {
            button: MouseButton::Left,
            pressed,
        }),
        2 => Some(InputEvent::MouseButton {
            button: MouseButton::Middle,
            pressed,
        }),
        3 => Some(InputEvent::MouseButton {
            button: MouseButton::Right,
            pressed,
        }),
        // X11 reports scroll as detent button clicks: one click is one
        // detent is 120 smooth units, so old peers get their exact detent
        // back through the sender-side downgrade.
        4..=7 if pressed => Some(InputEvent::SmoothWheel {
            x: match detail {
                6 => 120,
                7 => -120,
                _ => 0,
            },
            y: match detail {
                4 => 120,
                5 => -120,
                _ => 0,
            },
        }),
        8 => Some(InputEvent::MouseButton {
            button: MouseButton::Back,
            pressed,
        }),
        9 => Some(InputEvent::MouseButton {
            button: MouseButton::Forward,
            pressed,
        }),
        _ => None,
    }
}

fn axis_value(mask: &[u32], values: &[xinput::Fp3232], axis: usize) -> Option<f64> {
    let word = axis / 32;
    let bit = axis % 32;
    let mask_word = *mask.get(word)?;
    if mask_word & (1 << bit) == 0 {
        return None;
    }
    let index = mask
        .iter()
        .take(word)
        .map(|value| value.count_ones() as usize)
        .sum::<usize>()
        + (mask_word & ((1 << bit) - 1)).count_ones() as usize;
    let value = values.get(index)?;
    Some(value.integral as f64 + f64::from(value.frac) / FIXED_POINT_SCALE)
}

fn take_integer(remainder: &mut f64, value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    let total = (*remainder + value).clamp(-(i32::MAX as f64), i32::MAX as f64);
    let whole = total.trunc();
    *remainder = total - whole;
    whole as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_x11_buttons_and_wheels() {
        assert_eq!(
            button_event(1, true),
            Some(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: true,
            })
        );
        assert_eq!(
            button_event(4, true),
            Some(InputEvent::SmoothWheel { x: 0, y: 120 })
        );
        assert_eq!(button_event(4, false), None);
        assert_eq!(
            button_event(9, false),
            Some(InputEvent::MouseButton {
                button: MouseButton::Forward,
                pressed: false,
            })
        );
    }

    #[test]
    fn maps_standard_x11_keycode_to_physical_hid_usage() {
        assert_eq!(
            key_event(38, true),
            Some(InputEvent::Key(KeyEvent {
                usage: 0x04,
                pressed: true,
            }))
        );
        assert_eq!(key_event(7, true), None);
    }

    #[test]
    fn own_injector_devices_match_case_insensitively() {
        assert!(is_own_device_name(b"TheKVM Virtual Mouse"));
        assert!(is_own_device_name(b"TheKVM Virtual Keyboard"));
        assert!(is_own_device_name(b"thekvm virtual mouse"));
        assert!(!is_own_device_name(b"Logitech USB Receiver"));
        assert!(!is_own_device_name(b"AT Translated Set 2 keyboard"));
        assert!(!is_own_device_name(b""));
    }

    #[test]
    fn finds_axis_values_in_xi2_bitmask_order() {
        let mask = [0b101u32];
        let values = [
            xinput::Fp3232 {
                integral: 3,
                frac: 0,
            },
            xinput::Fp3232 {
                integral: -1,
                frac: 2_147_483_648,
            },
        ];
        assert_eq!(axis_value(&mask, &values, 0), Some(3.0));
        assert_eq!(axis_value(&mask, &values, 2), Some(-0.5));
        assert_eq!(axis_value(&mask, &values, 1), None);
    }
}
