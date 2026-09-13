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
use std::collections::HashMap;
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
    /// engage so a stale position can never teleport the cursor. Doubles
    /// as the recenter-cage sensor (see maybe_recenter_cage).
    core_last: Option<(i16, i16)>,
    /// Root pixel dims (measured once at creation): the recenter cage
    /// and edge math work in these, never in fallback dims.
    screen_dims: (u16, u16),
    /// Swallowing a cage warp's echo (see maybe_recenter_cage): events
    /// remaining to anchor-but-never-emit. A radius check would eat an
    /// unbounded fling that starts right at the warp; a small count
    /// swallows the warp echo plus in-flight pre-warp positions and
    /// then resumes with a correct anchor either way.
    cage_quiet: u8,
    /// Slave-device ids owned by our own uinput injector ("TheKVM Virtual
    /// Mouse/Keyboard"). Raw events carry only numeric source ids, so the
    /// set is resolved by device name and refreshed periodically: the
    /// injector creates its devices per receiver session, which can postdate
    /// this capture backend.
    ignored_sources: Vec<xinput::DeviceId>,
    last_source_refresh: std::time::Instant,
    /// XI2 smooth-scroll valuators per slave device (axis number +
    /// 120ths per raw unit): trackpads whose scroll classes carry
    /// NO_EMULATION emit no button 4-7 events at all, so without this
    /// map two-finger scroll is uncapturable in every grab kind. Keyed
    /// by source id (valuator layouts differ per device); refreshed
    /// with the own-device set. Empty on servers without scroll
    /// classes — the button path below is untouched.
    scroll_axes: HashMap<xinput::DeviceId, Vec<ScrollAxis>>,
    /// Fractional 120ths remainder per (device, scroll axis): raw
    /// valuator deltas arrive fractional, and truncating each event
    /// would eat slow scrolls whole.
    scroll_bank: HashMap<(xinput::DeviceId, usize), f64>,
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

/// One XI2 smooth-scroll valuator: which raw axis carries it, which
/// direction it scrolls, and how many 120ths one raw unit earns (120 /
/// increment — robust to detent-unit and pixel-distance conventions).
#[derive(Debug, Clone, Copy)]
struct ScrollAxis {
    axis: usize,
    horizontal: bool,
    units_120ths: f64,
}

/// Resolve smooth-scroll valuators via XIQueryDevice (0 = all devices).
/// Devices without scroll classes simply contribute nothing; a failed
/// query keeps the previous map (same contract as query_own_sources).
fn query_scroll_axes(connection: &RustConnection) -> HashMap<xinput::DeviceId, Vec<ScrollAxis>> {
    let mut axes = HashMap::new();
    let Ok(reply) = connection
        .xinput_xi_query_device(0u16)
        .map_err(|error| format!("query XInput2 scroll classes: {error}"))
        .and_then(|cookie| {
            cookie
                .reply()
                .map_err(|error| format!("read XInput2 scroll classes: {error}"))
        })
    else {
        return axes;
    };
    for info in &reply.infos {
        let mut device_axes = Vec::new();
        for class in &info.classes {
            let xinput::DeviceClassData::Scroll(scroll) = &class.data else {
                continue;
            };
            let increment = f64::from(scroll.increment.integral)
                + f64::from(scroll.increment.frac) / FIXED_POINT_SCALE;
            // A zero increment would divide by zero below: fall back to
            // one-detent-per-unit (the common detent convention).
            let units_120ths = if increment > 0.0 { 120.0 / increment } else { 120.0 };
            device_axes.push(ScrollAxis {
                axis: scroll.number as usize,
                horizontal: scroll.scroll_type == xinput::ScrollType::HORIZONTAL,
                units_120ths,
            });
        }
        if !device_axes.is_empty() {
            axes.insert(info.deviceid, device_axes);
        }
    }
    axes
}

/// Derive SmoothWheel 120ths from one raw motion's scroll valuators.
/// Pure apart from the bank map: fractional deltas accumulate across
/// events (slow scrolls survive), whole 120ths emit. Sign convention:
/// XI positive scroll = fingers down/right = legacy buttons 5/7 =
/// negative 120ths (buttons 4/6 are +120). Returns None when no scroll
/// valuator on this device moved a whole unit yet.
fn derive_scroll_wheel(
    sourceid: xinput::DeviceId,
    mask: &[u32],
    values: &[xinput::Fp3232],
    axes: &[ScrollAxis],
    banks: &mut HashMap<(xinput::DeviceId, usize), f64>,
) -> Option<InputEvent> {
    let mut wheel_x = 0i32;
    let mut wheel_y = 0i32;
    for axis in axes {
        let Some(delta) = axis_value(mask, values, axis.axis) else {
            continue;
        };
        if delta == 0.0 {
            continue;
        }
        let bank = banks.entry((sourceid, axis.axis)).or_insert(0.0);
        let whole = take_integer(bank, delta * axis.units_120ths);
        if axis.horizontal {
            wheel_x -= whole;
        } else {
            wheel_y -= whole;
        }
    }
    (wheel_x != 0 || wheel_y != 0).then_some(InputEvent::SmoothWheel {
        x: wheel_x,
        y: wheel_y,
    })
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

/// Recenter target when the grabbed-core cursor crowds an edge: the
/// screen center, or None when comfortably inside. Pure for tests.
/// Core MotionNotify deltas derive from successive POSITIONS, so once
/// the (hidden, still-roaming) local cursor parks at an edge, further
/// physical motion toward that edge reports identical coords — zero
/// deltas — and the driven cursor pins at a phantom border mid-roam
/// (the "cannot move beyond a certain line" stuck shape). Raw XI
/// motion never pins (true device deltas), which is why only the Core
/// hold needs this FPS-style cage.
fn recenter_point_if_near_edge(last: (i16, i16), dims: (u16, u16), margin: i16) -> Option<(i16, i16)> {
    let (width, height) = (dims.0 as i32, dims.1 as i32);
    let (x, y) = (i32::from(last.0), i32::from(last.1));
    let near = x < i32::from(margin)
        || y < i32::from(margin)
        || x > width.saturating_sub(i32::from(margin))
        || y > height.saturating_sub(i32::from(margin));
    near.then(|| {
        (
            (width / 2).clamp(0, i32::from(i16::MAX)) as i16,
            (height / 2).clamp(0, i32::from(i16::MAX)) as i16,
        )
    })
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
        let scroll_axes = query_scroll_axes(&connection);
        tracing::info!(
            devices = scroll_axes.len(),
            axes = scroll_axes.values().map(Vec::len).sum::<usize>(),
            "X11 smooth-scroll valuators resolved (trackpads without button emulation scroll through these)"
        );
        let setup = connection.setup();
        let screen_info = setup.roots.get(screen).ok_or_else(|| {
            PlatformError::Capture("X11 screen does not exist".into())
        })?;
        // Copy out: the setup borrow must end before `connection`
        // moves into Self below.
        let screen_dims = (
            screen_info.width_in_pixels,
            screen_info.height_in_pixels,
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
            scroll_axes,
            scroll_bank: HashMap::new(),
            screen_dims,
            cage_quiet: 0,
            xfixes_cursor,
            cursor_hidden: false,
        })
    }

    /// FPS-style recenter cage for the Core hold (see
    /// recenter_point_if_near_edge): when the hidden local cursor
    /// crowds an edge, warp it back to center, so position-derived
    /// deltas never pin at a phantom border. The warp's own MotionNotify
    /// (plus any in-flight pre-warp events) is swallowed by the quiet
    /// count below — anchoring to the warp point directly would turn
    /// those in-flight edge coords into a giant phantom fling. The
    /// cursor is XFixes-hidden while driving, so the teleport is
    /// invisible. Best-effort: a failed warp just retries next poll —
    /// capture never dies for the cage.
    fn maybe_recenter_cage(&mut self) {
        const CAGE_MARGIN_PX: i16 = 64;
        let Some(last) = self.core_last else {
            return;
        };
        let Some(point) = recenter_point_if_near_edge(last, self.screen_dims, CAGE_MARGIN_PX)
        else {
            return;
        };
        let warped = self
            .connection
            .warp_pointer(x11rb::NONE, self.root, 0, 0, 0, 0, point.0, point.1)
            .map_err(|error| format!("cage warp send: {error}"))
            .and_then(|cookie| {
                cookie
                    .check()
                    .map_err(|error| format!("cage warp check: {error}"))
            })
            .and_then(|()| {
                self.connection
                    .flush()
                    .map_err(|error| format!("cage warp flush: {error}"))
            });
        match warped {
            Ok(()) => {
                // Do NOT re-anchor here (see above): swallow the next
                // few arrivals (warp echo + in-flight pre-warp edge
                // positions) while the anchor keeps tracking, then
                // resume jump-free either way.
                self.cage_quiet = 3;
                tracing::debug!(from = ?last, to = ?point, "core capture cage recentered the hidden cursor");
            }
            Err(error) => {
                tracing::debug!(%error, "core capture cage warp failed; retrying next poll");
            }
        }
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
                // Smooth-scroll valuators FIRST: a scroll gesture carries
                // no pointer motion, and motion below derives nothing —
                // but when both move, the wheel wins (a scroll that also
                // nudges the pointer must still scroll). Disjoint field
                // borrows: the axes map reads while only the bank writes.
                if let Some(axes) = self.scroll_axes.get(&event.sourceid) {
                    if let Some(wheel) = derive_scroll_wheel(
                        event.sourceid,
                        &event.valuator_mask,
                        &event.axisvalues_raw,
                        axes,
                        &mut self.scroll_bank,
                    ) {
                        static FIRST_SMOOTH: std::sync::Once = std::sync::Once::new();
                        FIRST_SMOOTH.call_once(|| {
                            tracing::info!(
                                source = event.sourceid,
                                "x11 smooth-scroll valuator derived into wheel events"
                            );
                        });
                        return count_button_event(Some(wheel));
                    }
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
                // Cage-warp echo swallow (see maybe_recenter_cage):
                // anchor to the warp's own arrival (and any in-flight
                // pre-warp positions), emit nothing, for a few events.
                // Without this the anchor reset turns edge coords into
                // a phantom fling; the count (not a radius) bounds the
                // loss even if the user flings straight out of the warp.
                if self.cage_quiet > 0 {
                    self.core_last = Some((event.root_x, event.root_y));
                    self.cage_quiet -= 1;
                    return None;
                }
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
                // Hot-plugged scroll devices (or a server that grows
                // scroll classes late) join without a restart.
                let refreshed_axes = query_scroll_axes(&self.connection);
                if !refreshed_axes.is_empty() {
                    self.scroll_axes = refreshed_axes;
                }
            }
            if release.swap(false, Ordering::AcqRel) {
                self.release()?;
            }
            let desired_exclusive = exclusive.load(Ordering::Acquire);
            if desired_exclusive != self.exclusive {
                self.set_exclusive(desired_exclusive)?;
            }
            // The cage runs on every poll while core-grabbed (see
            // maybe_recenter_cage): cheap integer compares mid-screen,
            // one warp per edge visit — never per event.
            if self.grab_kind == GrabKind::Core {
                self.maybe_recenter_cage();
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
            // XI2 active grab first, sweeping device selectors: some
            // servers refuse the abstract XIAllDevices/XIAllMasterDevices
            // selectors while accepting the concrete master ids (and vice
            // versa — live-proven: this Xorg answers every XIGrabDevice
            // variant with BadValue while XGrabPointer succeeds). Either
            // XI hold suppresses local delivery with raw XI capture
            // flowing underneath; Deskflow-style core grabs are the last
            // resort, with the recenter cage keeping their
            // position-derived deltas unbounded (see maybe_recenter_cage).
            match xi_grab_sweep(&self.connection, self.grab_window) {
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
            // shape). Ungrabbing a non-held XI selector is a server-side
            // no-op, so the sweep below is safe by construction; the core
            // hold still releases only when actually held.
            let previous = self.grab_kind;
            self.grab_kind = GrabKind::None;
            let released = match previous {
                GrabKind::Xi => xi_ungrab_all(&self.connection),
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
            // INFO, not debug: engage/release pairing is the whole
            // stuck-suppression (click-dead freeze) diagnosis — an
            // engage without a matching release in the journal names
            // the leaked hold instead of another mystery.
            tracing::info!(previous = ?previous, "X11 local suppression released");
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

/// XI2 device selectors tried in order (see xi_grab): XIAllDevices
/// first (the whole tree in one hold), then XIAllMasterDevices (the
/// historical selector), then each concrete master (some servers
/// refuse the abstract selectors while accepting real device ids).
/// Ungrabbing a non-held selector is a server-side no-op, so release
/// sweeps all four unconditionally instead of tracking which armed.
const XI_GRAB_SINGLETONS: [u16; 2] = [0, 1];
const XI_GRAB_MASTER_PAIR: [u16; 2] = [2, 3];
const XI_UNGRAB_SWEEP: [u16; 4] = [0, 1, 2, 3];

/// XI2 active grab of all master devices (raw-device semantics). Free
/// function so the capture trait keeps only the backend interface.
/// The grab targets OUR OWN invisible window, never root: a
/// root-windowed grab is refused outright on strict servers, and raw
/// XI delivery (including smooth-scroll valuators) keeps flowing
/// under an XI hold, which a core hold kills. Core stays the fallback
/// for servers that refuse XI grabs outright.
fn xi_grab(
    connection: &RustConnection,
    grab_window: xproto::Window,
    deviceid: u16,
) -> Result<(), PlatformError> {
    let mask = [raw_mask()];
    let status = connection
        .xinput_xi_grab_device(
            grab_window,
            0u32,
            0u32,
            deviceid,
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

/// Try every XI device selector in order, returning on the first
/// armed hold. A partial concrete-master pair (pointer grabbed,
/// keyboard refused or vice versa) is unwound before the next
/// attempt: a half hold would leak local keys while driving. Errors
/// join into one message so the journal names every refused
/// selector, not just the last.
fn xi_grab_sweep(connection: &RustConnection, grab_window: xproto::Window) -> Result<(), PlatformError> {
    let mut refusals = Vec::new();
    for deviceid in XI_GRAB_SINGLETONS {
        match xi_grab(connection, grab_window, deviceid) {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::debug!(deviceid, %error, "XI grab selector refused");
                refusals.push(format!("{deviceid}: {error}"));
            }
        }
    }
    // Concrete masters last: two holds or none (see above).
    let pair = XI_GRAB_MASTER_PAIR
        .into_iter()
        .map(|deviceid| xi_grab(connection, grab_window, deviceid))
        .collect::<Vec<_>>();
    if pair.iter().all(|result| result.is_ok()) {
        return Ok(());
    }
    for result in &pair {
        if let Err(error) = result {
            tracing::debug!(%error, "XI concrete-master grab refused");
            refusals.push(format!("master-pair: {error}"));
        }
    }
    let _ = xi_ungrab_all(connection);
    Err(PlatformError::Capture(format!(
        "XInput2 device grab was rejected ({})",
        refusals.join("; ")
    )))
}
/// Release every XI selector we may hold (see XI_UNGRAB_SWEEP):
/// best-effort per selector, errors collected into one message so a
/// half-released hold can never strand suppression silently.
fn xi_ungrab_all(connection: &RustConnection) -> Result<(), PlatformError> {
    let mut failures = Vec::new();
    for deviceid in XI_UNGRAB_SWEEP {
        if let Err(error) = connection
            .xinput_xi_ungrab_device(0u32, deviceid)
            .map_err(|error| format!("XInput2 ungrab send: {error:?}"))
            .and_then(|cookie| {
                cookie
                    .check()
                    .map_err(|error| format!("XInput2 ungrab check: {error:?}"))
            })
        {
            failures.push(format!("{deviceid}: {error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(PlatformError::Capture(format!(
            "release XI grab (held selectors): {}",
            failures.join("; ")
        )))
    }
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
    fn smooth_valuator_deltas_derive_signed_wheels() {
        // Trackpads without button emulation scroll purely through XI2
        // scroll valuators: +1 vertical unit is one detent DOWN
        // (button-5 parity, -120), horizontal mirrors on x. Sign and
        // banking pin here so an inversion or a dropped slow scroll
        // fails the gate instead of shipping silently unscrolled.
        use super::{derive_scroll_wheel, ScrollAxis};
        use std::collections::HashMap;
        let vertical = vec![ScrollAxis {
            axis: 2,
            horizontal: false,
            units_120ths: 120.0,
        }];
        let mut banks = HashMap::new();
        let mask = [0b100u32];
        let one = xinput::Fp3232 {
            integral: 1,
            frac: 0,
        };
        assert_eq!(
            derive_scroll_wheel(13, &mask, &[one], &vertical, &mut banks),
            Some(InputEvent::SmoothWheel { x: 0, y: -120 })
        );
        // Sub-detent fractions bank across events (1/256-unit ticks =
        // 0.46875 120ths each: silent, silent, then -1 on the third).
        let tick = xinput::Fp3232 {
            integral: 0,
            frac: 16_777_216,
        };
        let mut banks = HashMap::new();
        assert_eq!(
            derive_scroll_wheel(13, &mask, &[tick], &vertical, &mut banks),
            None
        );
        assert_eq!(
            derive_scroll_wheel(13, &mask, &[tick], &vertical, &mut banks),
            None
        );
        assert_eq!(
            derive_scroll_wheel(13, &mask, &[tick], &vertical, &mut banks),
            Some(InputEvent::SmoothWheel { x: 0, y: -1 })
        );
        // Horizontal valuators drive x with the same right-negative sign.
        let horizontal = vec![ScrollAxis {
            axis: 3,
            horizontal: true,
            units_120ths: 120.0,
        }];
        let mut banks = HashMap::new();
        let hmask = [0b1000u32];
        assert_eq!(
            derive_scroll_wheel(13, &hmask, &[one], &horizontal, &mut banks),
            Some(InputEvent::SmoothWheel { x: -120, y: 0 })
        );
        // Axes the device never advertised contribute nothing.
        assert_eq!(
            derive_scroll_wheel(13, &hmask, &[one], &vertical, &mut banks),
            None
        );
    }

    #[test]
    fn cage_recenter_fires_only_near_edges() {
        // 1536x864 with a 64px margin: corners and edge crowds recenter
        // to the middle; comfortable interior never warps (a mid-screen
        // warp would read as a cursor jump).
        use super::recenter_point_if_near_edge;
        let dims = (1536u16, 864u16);
        assert_eq!(
            recenter_point_if_near_edge((1535, 400), dims, 64),
            Some((768, 432))
        );
        assert_eq!(
            recenter_point_if_near_edge((10, 10), dims, 64),
            Some((768, 432))
        );
        assert_eq!(
            recenter_point_if_near_edge((800, 860), dims, 64),
            Some((768, 432))
        );
        assert_eq!(recenter_point_if_near_edge((800, 400), dims, 64), None);
        assert_eq!(recenter_point_if_near_edge((64, 64), dims, 64), None);
        // Degenerate dims never divide: still centers (0,0).
        assert_eq!(
            recenter_point_if_near_edge((5, 5), (0, 0), 64),
            Some((0, 0))
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
