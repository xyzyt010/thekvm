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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;
use x11rb::connection::Connection;
use x11rb::protocol::xfixes::ConnectionExt as XFixesConnectionExt;
use x11rb::protocol::xinput::{self, ConnectionExt as XInputConnectionExt};
use x11rb::protocol::xproto::{self, ConnectionExt as XprotoConnectionExt};
use x11rb::rust_connection::RustConnection;

const ALL_MASTER_DEVICES: u16 = 1;
const POLL_INTERVAL: Duration = Duration::from_millis(4);
const FIXED_POINT_SCALE: f64 = 4_294_967_296.0;

/// Blocking adapter around XInput2's raw event stream.
pub struct X11Capture {
    connection: RustConnection,
    root: xproto::Window,
    exclusive: bool,
    /// Which suppression hold is active while exclusive (see
    /// set_exclusive): the XI2 active grab where servers accept it, else
    /// Deskflow-style core pointer+keyboard grabs.
    grab_kind: GrabKind,
    motion_x: f64,
    motion_y: f64,
    /// Invisible override-redirect input-only window that owns grabbed
    /// core events while driving (see GrabKind::Core): the grab targets
    /// this window so the grabbed stream has somewhere to be read from.
    /// Grabbing root suppresses equally well, but then nobody receives.
    grab_window: xproto::Window,
    /// Last grabbed-core pointer position (root coords): relative steps
    /// derive from successive MotionNotify events. Reset on every grab
    /// engage so a stale anchor can never teleport the cursor.
    core_last: Option<(i16, i16)>,
    /// Slave-device ids owned by our own uinput injector ("TheKVM Virtual
    /// Mouse/Keyboard"). Raw events carry only numeric source ids, so the
    /// set is resolved by device name and refreshed periodically: the
    /// injector creates its devices per receiver session, which can postdate
    /// this capture backend.
    ignored_sources: Vec<xinput::DeviceId>,
    last_source_refresh: std::time::Instant,
    /// Whether the server answered XFixes version negotiation (probed
    /// once at creation): gates cursor hiding, which has no fallback.
    xfixes_cursor: bool,
    /// Whether we currently hold one XFixes hide on the root cursor.
    /// Hide/show counts are strictly paired here (hide only when false,
    /// show only when true) across every engage/release path plus Drop,
    /// so a failed show retries on the next release instead of leaking
    /// an invisible cursor.
    cursor_hidden: bool,
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

/// Backend receipt census for X11: what the server actually delivered
/// past the own-device filter (raw key/button/motion/wheel arrivals).
/// Read by the daemon into the journal: separates "the X server never
/// delivered" (all zero while the user pushes) from "delivered but not
/// routed". The Windows hook/RAW split has no meaning here, so motion
/// fills the move slot and raw slots stay zero.
static XI_KEY: AtomicU64 = AtomicU64::new(0);
static XI_BUTTON: AtomicU64 = AtomicU64::new(0);
static XI_MOTION: AtomicU64 = AtomicU64::new(0);
static XI_WHEEL: AtomicU64 = AtomicU64::new(0);

pub(crate) fn census() -> (u64, u64, u64, u64) {
    (
        XI_KEY.load(Ordering::Relaxed),
        XI_BUTTON.load(Ordering::Relaxed),
        XI_MOTION.load(Ordering::Relaxed),
        XI_WHEEL.load(Ordering::Relaxed),
    )
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

/// Which hold suppresses local delivery while driving remotely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum GrabKind {
    #[default]
    None,
    /// XI2 active grab of all master devices (precise raw-device
    /// semantics) — where the server accepts it.
    Xi,
    /// Core pointer+keyboard grabs, Deskflow X11 parity: proven live
    /// against servers that refuse XIGrabDevice wholesale while
    /// XGrabPointer succeeds. Raw XI event selection is unaffected by
    /// either hold, so capture keeps flowing either way.
    Core,
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

        // XFixes cursor hide/show for drives (best-effort, probed once):
        // grabs redirect EVENTS but the visible cursor keeps roaming, so
        // without hiding every drive shows two live cursors. A server
        // without XFixes simply keeps the visible cursor (fail-open).
        let xfixes_cursor = connection
            .xfixes_query_version(5, 0)
            .map_err(|error| format!("query XFixes version: {error}"))
            .and_then(|cookie| {
                cookie
                    .reply()
                    .map_err(|error| format!("read XFixes version: {error}"))
            })
            .map(|_| true)
            .unwrap_or_else(|error| {
                tracing::debug!(%error, "XFixes unavailable; local cursor stays visible while driving");
                false
            });

        let ignored_sources = query_own_sources(&connection).unwrap_or_default();
        tracing::info!(
            ignored = ignored_sources.len(),
            "X11 capture armed; own injector devices excluded from capture"
        );
        // Invisible grab window (see the field): input-only,
        // override-redirect, mapped but zero pixels on screen.
        let grab_window = connection
            .generate_id()
            .map_err(|error| PlatformError::Capture(format!("allocate grab window id: {error}")))?;
        connection
            .create_window(
                x11rb::COPY_DEPTH_FROM_PARENT,
                grab_window,
                root,
                0,
                0,
                1,
                1,
                0,
                xproto::WindowClass::INPUT_ONLY,
                x11rb::COPY_FROM_PARENT,
                &xproto::CreateWindowAux::new().override_redirect(1),
            )
            .map_err(|error| PlatformError::Capture(format!("create grab window: {error}")))?
            .check()
            .map_err(|error| PlatformError::Capture(format!("create grab window: {error}")))?;
        connection
            .map_window(grab_window)
            .map_err(|error| PlatformError::Capture(format!("map grab window: {error}")))?
            .check()
            .map_err(|error| PlatformError::Capture(format!("map grab window: {error}")))?;
        Ok(Self {
            connection,
            root,
            exclusive: false,
            grab_kind: GrabKind::None,
            motion_x: 0.0,
            motion_y: 0.0,
            grab_window,
            core_last: None,
            ignored_sources,
            last_source_refresh: std::time::Instant::now(),
            xfixes_cursor,
            cursor_hidden: false,
        })
    }

    fn translate(&mut self, event: x11rb::protocol::Event) -> Option<InputEvent> {
        match event {
            x11rb::protocol::Event::XinputRawKeyPress(event) => {
                // Core-grabbed: this server stops XI raw delivery under
                // our own core grab, and the grabbed core stream below is
                // the live tap — reading both would double-deliver where
                // a server provides both.
                if self.grab_kind == GrabKind::Core {
                    return None;
                }
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                XI_KEY.fetch_add(1, Ordering::Relaxed);
                key_event(event.detail, true)
            }
            x11rb::protocol::Event::XinputRawKeyRelease(event) => {
                if self.grab_kind == GrabKind::Core {
                    return None;
                }
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                XI_KEY.fetch_add(1, Ordering::Relaxed);
                key_event(event.detail, false)
            }
            x11rb::protocol::Event::XinputRawButtonPress(event) => {
                if self.grab_kind == GrabKind::Core {
                    return None;
                }
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                count_button_event(button_event(event.detail, true))
            }
            x11rb::protocol::Event::XinputRawButtonRelease(event) => {
                if self.grab_kind == GrabKind::Core {
                    return None;
                }
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                count_button_event(button_event(event.detail, false))
            }
            x11rb::protocol::Event::XinputRawMotion(event) => {
                if self.grab_kind == GrabKind::Core {
                    return None;
                }
                if self.ignored_sources.contains(&event.sourceid) {
                    return None;
                }
                XI_MOTION.fetch_add(1, Ordering::Relaxed);
                let dx = axis_value(&event.valuator_mask, &event.axisvalues_raw, 0)
                    .map(|value| take_integer(&mut self.motion_x, value))
                    .unwrap_or(0);
                let dy = axis_value(&event.valuator_mask, &event.axisvalues_raw, 1)
                    .map(|value| take_integer(&mut self.motion_y, value))
                    .unwrap_or(0);
                (dx != 0 || dy != 0).then_some(InputEvent::MouseMove { dx, dy })
            }
            // Grabbed-core stream (see GrabKind::Core): live ONLY while
            // core-grabbed. Core events carry no source id, so no
            // own-device filter applies — while driving, the receiver
            // injector is idle on this machine, so everything grabbed is
            // physical user input by construction.
            x11rb::protocol::Event::MotionNotify(event) => {
                if self.grab_kind != GrabKind::Core {
                    return None;
                }
                XI_MOTION.fetch_add(1, Ordering::Relaxed);
                let anchor = self.core_last.replace((event.root_x, event.root_y));
                let Some((last_x, last_y)) = anchor else {
                    return None;
                };
                let (dx, dy) = core_motion_step((last_x, last_y), (event.root_x, event.root_y));
                let dx = take_integer(&mut self.motion_x, dx as f64);
                let dy = take_integer(&mut self.motion_y, dy as f64);
                (dx != 0 || dy != 0).then_some(InputEvent::MouseMove { dx, dy })
            }
            x11rb::protocol::Event::ButtonPress(event) => {
                if self.grab_kind != GrabKind::Core {
                    return None;
                }
                count_button_event(button_event(u32::from(event.detail), true))
            }
            x11rb::protocol::Event::ButtonRelease(event) => {
                if self.grab_kind != GrabKind::Core {
                    return None;
                }
                count_button_event(button_event(u32::from(event.detail), false))
            }
            x11rb::protocol::Event::KeyPress(event) => {
                if self.grab_kind != GrabKind::Core {
                    return None;
                }
                XI_KEY.fetch_add(1, Ordering::Relaxed);
                key_event(u32::from(event.detail), true)
            }
            x11rb::protocol::Event::KeyRelease(event) => {
                if self.grab_kind != GrabKind::Core {
                    return None;
                }
                XI_KEY.fetch_add(1, Ordering::Relaxed);
                key_event(u32::from(event.detail), false)
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
            // XI2 active grab first; Deskflow-style core grabs when the
            // server refuses it (live-proven: this Xorg answers every
            // XIGrabDevice with BadValue while XGrabPointer succeeds).
            // Either hold suppresses local delivery; the XI raw selection
            // underneath keeps feeding capture in both cases.
            match xi_grab(&self.connection, self.root) {
                Ok(()) => self.grab_kind = GrabKind::Xi,
                Err(xi_error) => {
                    tracing::info!(%xi_error, "XIGrabDevice refused; falling back to core pointer+keyboard grab");
                    // A failed acquire holds nothing: clear a stale record
                    // so a later kind-matched release cannot skip a real
                    // hold (or chase a phantom one).
                    self.grab_kind = GrabKind::None;
                    core_grab(&self.connection, self.grab_window)?;
                    self.grab_kind = GrabKind::Core;
                }
            }
            // Fresh anchor for grabbed-core relative steps (see
            // translate): without this the first step after engage
            // teleports from a stale position.
            self.core_last = None;
            // The grab suppresses local DELIVERY, not the visible
            // cursor: hide it so the drive shows exactly one pointer
            // (on the peer). Best-effort — a failed hide warns and the
            // drive proceeds with dual cursors rather than no drive.
            self.hide_cursor();
            tracing::info!(grab = ?self.grab_kind, "X11 local suppression engaged");
        } else {
            // Kind-matched release: ungrab ONLY the hold we actually own.
            // The old code attempted BOTH paths unconditionally, but on
            // servers that refuse XIGrabDevice outright (BadValue on every
            // XI grab call, live-proven on Mint Xorg) the XI ungrab fails
            // too — poisoning an otherwise successful core release into a
            // reported failure, which threw capture into rebuild churn with
            // suppression bookkeeping stuck (the freeze-with-visible-cursor
            // shape). Ungrabbing a non-held device is a server-side no-op,
            // so a stale None record is safe by construction.
            let previous = self.grab_kind;
            self.grab_kind = GrabKind::None;
            let released = match previous {
                GrabKind::Xi => self
                    .connection
                    .xinput_xi_ungrab_device(0u32, ALL_MASTER_DEVICES)
                    .map_err(|error| format!("XInput2 ungrab send: {error:?}"))
                    .and_then(|cookie| {
                        cookie
                            .check()
                            .map_err(|error| format!("XInput2 ungrab check: {error:?}"))
                    })
                    .map_err(|error| {
                        PlatformError::Capture(format!(
                            "release XI grab (held {previous:?}): {error}"
                        ))
                    }),
                GrabKind::Core => core_ungrab(&self.connection),
                GrabKind::None => Ok(()),
            };
            if let Err(error) = released {
                return Err(error);
            }
            // Release the drive cursor hide (paired with the engage
            // above): runs on every release path, including Drop via
            // release(), so no path strands an invisible cursor. A
            // failed show keeps the flag set so the next release (or
            // Drop) retries instead of leaking the hide.
            self.show_cursor();
            tracing::debug!(previous = ?previous, "X11 local suppression released");
        }
        self.connection.flush().map_err(|error| {
            PlatformError::Capture(format!("flush XInput2 grab state: {error}"))
        })?;
        self.exclusive = exclusive;
        if exclusive {
            // The peer provisions its injector around handoff time, so a
            // device born seconds ago may not be excluded yet: re-learn
            // own devices NOW instead of inside the 5s window, or the
            // first injected motion is re-captured as a phantom drive.
            self.last_source_refresh = std::time::Instant::now();
            if let Some(refreshed) = query_own_sources(&self.connection) {
                self.ignored_sources = refreshed;
            }
        }
        Ok(())
    }

    /// Hide the local pointer for the drive (see the engage path).
    /// Strictly paired with show_cursor via cursor_hidden: at most one
    /// outstanding hide per backend, so counts can never leak upward.
    fn hide_cursor(&mut self) {
        if self.cursor_hidden || !self.xfixes_cursor {
            return;
        }
        let hidden = self
            .connection
            .xfixes_hide_cursor(self.root)
            .map_err(|error| format!("send XFixes hide cursor: {error}"))
            .and_then(|cookie| {
                cookie
                    .check()
                    .map_err(|error| format!("hide X cursor: {error}"))
            })
            .map(|()| true)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "local cursor stays visible while driving");
                false
            });
        self.cursor_hidden = hidden;
    }

    /// Restore the local pointer after the drive (see the release path).
    /// A failed show keeps the flag so the next release re-tries; every
    /// path (including Drop) funnels here.
    fn show_cursor(&mut self) {
        if !self.cursor_hidden {
            return;
        }
        if self
            .connection
            .xfixes_show_cursor(self.root)
            .map_err(|error| format!("send XFixes show cursor: {error}"))
            .and_then(|cookie| {
                cookie
                    .check()
                    .map_err(|error| format!("show X cursor: {error}"))
            })
            .is_err()
        {
            tracing::warn!("local cursor restore failed; will retry on next release");
            return;
        }
        self.cursor_hidden = false;
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

/// XI2 active grab of all master devices (raw-device semantics). Free
/// function so the capture trait keeps only the backend interface.
fn xi_grab(connection: &RustConnection, root: xproto::Window) -> Result<(), PlatformError> {
    let mask = [raw_mask()];
    let status = connection
        .xinput_xi_grab_device(
            root,
            0u32,
            0u32,
            ALL_MASTER_DEVICES,
            xproto::GrabMode::ASYNC,
            xproto::GrabMode::ASYNC,
            xinput::GrabOwner::NO_OWNER,
            &mask,
        )
        .map_err(|error| PlatformError::Capture(format!("grab XInput2 devices: {error}")))?
        .reply()
        .map_err(|error| PlatformError::Capture(format!("read XInput2 grab status: {error}")))?
        .status;
    if status != xproto::GrabStatus::SUCCESS {
        return Err(PlatformError::Capture(format!(
            "XInput2 device grab was rejected ({status:?})"
        )));
    }
    Ok(())
}

/// Deskflow-parity core grabs (pointer + keyboard), Async/Async with no
/// event owner: local apps receive nothing while held. The grab targets
/// our own invisible window (not root) so the grabbed core stream has a
/// reader: this server stops XI raw delivery under our own core grab,
/// which made XI-only capture go deaf the instant a drive opened (every
/// freeze-with-visible-cursor). The XI raw selection underneath is left
/// in place; translate() reads exactly one source per grab kind, so no
/// server can double-deliver.
fn core_grab(connection: &RustConnection, grab_window: xproto::Window) -> Result<(), PlatformError> {
    let pointer = connection
        .grab_pointer(
            false,
            grab_window,
            xproto::EventMask::BUTTON_PRESS
                | xproto::EventMask::BUTTON_RELEASE
                | xproto::EventMask::POINTER_MOTION,
            xproto::GrabMode::ASYNC,
            xproto::GrabMode::ASYNC,
            0u32,
            0u32,
            0u32,
        )
        .map_err(|error| PlatformError::Capture(format!("grab core pointer: {error}")))?
        .reply()
        .map_err(|error| PlatformError::Capture(format!("read core pointer grab status: {error}")))?
        .status;
    if pointer != xproto::GrabStatus::SUCCESS {
        return Err(PlatformError::Capture(format!(
            "core pointer grab was rejected ({pointer:?})"
        )));
    }
    let keyboard = connection
        .grab_keyboard(false, grab_window, 0u32, xproto::GrabMode::ASYNC, xproto::GrabMode::ASYNC)
        .map_err(|error| PlatformError::Capture(format!("grab core keyboard: {error}")))?
        .reply()
        .map_err(|error| PlatformError::Capture(format!("read core keyboard grab status: {error}")))?
        .status;
    if keyboard != xproto::GrabStatus::SUCCESS {
        let _ = connection.ungrab_pointer(0u32).map(|cookie| cookie.check());
        return Err(PlatformError::Capture(format!(
            "core keyboard grab was rejected ({keyboard:?})"
        )));
    }
    Ok(())
}

/// Release a core hold (pointer first, then keyboard).
fn core_ungrab(connection: &RustConnection) -> Result<(), PlatformError> {    connection
        .ungrab_pointer(0u32)
        .map_err(|error| PlatformError::Capture(format!("ungrab core pointer: {error}")))?
        .check()
        .map_err(|error| PlatformError::Capture(format!("ungrab core pointer: {error}")))?;
    connection
        .ungrab_keyboard(0u32)
        .map_err(|error| PlatformError::Capture(format!("ungrab core keyboard: {error}")))?
        .check()
        .map_err(|error| PlatformError::Capture(format!("ungrab core keyboard: {error}")))?;
    Ok(())
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

/// Census wrapper for translated button arrivals: wheel clicks (4-7)
/// count as wheel, everything else as buttons. Pure counter, no logic.
fn count_button_event(event: Option<InputEvent>) -> Option<InputEvent> {
    match event {
        Some(InputEvent::SmoothWheel { .. }) => {
            XI_WHEEL.fetch_add(1, Ordering::Relaxed);
        }
        Some(_) => {
            XI_BUTTON.fetch_add(1, Ordering::Relaxed);
        }
        None => {}
    }
    event
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

/// Relative step between two grabbed-core pointer positions (root
/// coords, y down). Pure: pins the sign convention the drive router
/// depends on (right/down positive, matching XI raw deltas).
fn core_motion_step(last: (i16, i16), current: (i16, i16)) -> (i32, i32) {
    (
        i32::from(current.0) - i32::from(last.0),
        i32::from(current.1) - i32::from(last.1),
    )
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
    fn grabbed_core_steps_match_xi_raw_signs() {
        // Right/down positive (screen coords, y down), like XI raw deltas.
        assert_eq!(core_motion_step((100, 100), (112, 96)), (12, -4));
        assert_eq!(core_motion_step((100, 100), (100, 100)), (0, 0));
        assert_eq!(core_motion_step((0, 0), (-5, 300)), (-5, 300));
    }

    #[test]
    fn own_injector_devices_match_case_insensitively() {        assert!(is_own_device_name(b"TheKVM Virtual Mouse"));
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
