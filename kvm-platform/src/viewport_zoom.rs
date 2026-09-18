//! OS-level viewport zoom for Linux receivers: a TheKVM-owned magnifier
//! lens (X11 only).
//!
//! Why this exists: on Windows the receiver renders an inbound pinch as a
//! real two-finger touch gesture, so Chrome/Edge perform their *viewport*
//! zoom (optical scale at the cursor, no reflow, no badge). On Linux Mint
//! there is nothing equivalent to drive: the Cinnamon compositor ships the
//! `org.cinnamon.desktop.a11y.magnifier` settings schema but honors none of
//! it (proven live: `mag-factor 4.0` + enable changes zero pixels), and no
//! browser on X11 implements cursor-anchored viewport zoom. So every Linux
//! pinch degraded to Ctrl+wheel *page* zoom (layout reflow + badge).
//!
//! This module renders the missing primitive ourselves: while a pinch
//! gesture is in flight the receiver opens a small always-on-top lens
//! window centered on the local cursor showing a live magnified capture of
//! the desktop around it — the same picture-in-picture contract as the
//! Windows Magnifier lens. No kernel driver, no compositor support, no
//! browser involvement; pure user-mode X11 (capture + scale + present).
//!
//! Behavior contract:
//! - Pinch-out grows the factor 1.0 -> 8.0; pinch-in shrinks it. The lens
//!   opens on the first update past 1.0 and follows the cursor every
//!   update (zoom-to-cursor, like the touch path).
//! - The lens is STICKY: lifting the fingers (PinchEnd) keeps the current
//!   factor so the user can inspect while interacting — exactly how the
//!   browser viewport zoom persists after the gesture. Pinching back to
//!   1.0 closes the lens; so does session teardown (Drop).
//! - The lens is click-through (empty input shape) and never takes focus,
//!   so drive continues underneath it untouched.
//! - Anything missing (Wayland session, no X display, no SHAPE extension,
//!   non-24-bit root, X errors) degrades to `false` and the caller falls
//!   back to the legacy Ctrl+wheel page zoom for the gesture. A gesture
//!   never fails the send.
//! - `THEKVM_LINUX_VIEWPORT_ZOOM=0` forces the old page-zoom path, and the
//!   global `THEKVM_WHEEL_PINCH=1` opt-out keeps forcing it too.
//!
//! Video feedback: the source rect sits under the cursor, which is also
//! where the lens window is — re-capturing with the lens visible would
//! magnify the previous lens frame over and over until the picture melts
//! into a flat blur (proven live: grey mush, then black). Every render
//! therefore unmaps the lens, captures the naked desktop, then re-maps
//! and presents, all inside one flush so the hide never reaches the eye.

/// Minimum/maximum magnification the lens renders.
const MIN_FACTOR: f64 = 1.0;
/// A screen rectangle: `(x, y, width, height)` in pixels.
#[cfg(any(test, target_os = "linux"))]
type Rect = (u32, u32, u32, u32);
/// 8x is the top of the magnifier schema range that stays readable.
#[cfg(any(test, target_os = "linux"))]
const MAX_FACTOR: f64 = 8.0;
/// Per-120th-delta multiplicative gain: one 120 detent is ~x1.10, so a
/// full pinch-out sweep lands near the top without leaping there.
#[cfg(any(test, target_os = "linux"))]
const FACTOR_PER_UNIT: f64 = 0.0008;

/// Next zoom factor after a pinch delta (120ths of finger spread).
/// Pure for tests. Positive deltas (spread) zoom in, negative zoom out,
/// zero is a no-op, and the result clamps to `[1.0, 8.0]`.
#[cfg(any(test, target_os = "linux"))]
fn zoom_factor(current: f64, delta_120ths: i32) -> f64 {
    if delta_120ths == 0 {
        return current.clamp(MIN_FACTOR, MAX_FACTOR);
    }
    (current * (1.0 + f64::from(delta_120ths) * FACTOR_PER_UNIT)).clamp(MIN_FACTOR, MAX_FACTOR)
}

/// Lens + source rectangles for a cursor, screen size and factor. Pure
/// for tests. The lens is a third of the screen (clamped to a usable
/// window), the source is the lens footprint divided by the factor —
/// centered on the cursor and clamped inside the screen so the lens
/// never shows outside pixels. Returns the lens rect and the source
/// rect.
#[cfg(any(test, target_os = "linux"))]
fn lens_geometry(cursor: (u32, u32), screen: (u32, u32), factor: f64) -> (Rect, Rect) {
    fn clamp_box(center: u32, size: u32, bound: u32) -> u32 {
        if size >= bound {
            return 0;
        }
        let half = size / 2;
        center.saturating_sub(half).min(bound - size)
    }
    let lens_w = (screen.0 / 3).clamp(320, 800).min(screen.0.max(1));
    let lens_h = (screen.1 / 3).clamp(240, 600).min(screen.1.max(1));
    let factor = factor.clamp(MIN_FACTOR, MAX_FACTOR);
    let src_w = ((lens_w as f64 / factor).round() as u32)
        .clamp(16, screen.0.max(1))
        .min(lens_w);
    let src_h = ((lens_h as f64 / factor).round() as u32)
        .clamp(16, screen.1.max(1))
        .min(lens_h);
    let src_x = clamp_box(cursor.0, src_w, screen.0);
    let src_y = clamp_box(cursor.1, src_h, screen.1);
    let lens_x = clamp_box(cursor.0, lens_w, screen.0);
    let lens_y = clamp_box(cursor.1, lens_h, screen.1);
    (
        (lens_x, lens_y, lens_w, lens_h),
        (src_x, src_y, src_w, src_h),
    )
}

/// Bilinear upscale of XRGB bytes (B, G, R, pad per pixel; the pad byte
/// is passed through as zero — depth-24 PutImage ignores it). Pure for
/// tests. Edge pixels clamp-sample so the border never reads outside
/// the source.
#[cfg(any(test, target_os = "linux"))]
fn upscale_xrgb(src: &[u8], src_w: u32, src_h: u32, dst_w: u32, dst_h: u32) -> Vec<u8> {
    let src_w = src_w.max(1) as usize;
    let src_h = src_h.max(1) as usize;
    let dst_w = dst_w.max(1) as usize;
    let dst_h = dst_h.max(1) as usize;
    let sample = |x: isize, y: isize, channel: usize| -> f64 {
        let x = x.clamp(0, src_w as isize - 1) as usize;
        let y = y.clamp(0, src_h as isize - 1) as usize;
        src.get((y * src_w + x) * 4 + channel).copied().unwrap_or(0) as f64
    };
    let mut dst = vec![0u8; dst_w * dst_h * 4];
    for y in 0..dst_h {
        // Source-space position of the destination pixel CENTER (the
        // half-pixel offset is what keeps 1:1 output bit-identical).
        let sy = (y as f64 + 0.5) * src_h as f64 / dst_h as f64 - 0.5;
        let y0 = sy.floor() as isize;
        let fy = (sy - y0 as f64).clamp(0.0, 1.0);
        for x in 0..dst_w {
            let sx = (x as f64 + 0.5) * src_w as f64 / dst_w as f64 - 0.5;
            let x0 = sx.floor() as isize;
            let fx = (sx - x0 as f64).clamp(0.0, 1.0);
            for channel in 0..3 {
                let top = sample(x0, y0, channel) * (1.0 - fx) + sample(x0 + 1, y0, channel) * fx;
                let bottom =
                    sample(x0, y0 + 1, channel) * (1.0 - fx) + sample(x0 + 1, y0 + 1, channel) * fx;
                dst[(y * dst_w + x) * 4 + channel] =
                    (top * (1.0 - fy) + bottom * fy).round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    dst
}

/// Gate check with injectable values so tests never touch the process
/// environment. `wheel` is `THEKVM_WHEEL_PINCH`, `gate` is
/// `THEKVM_LINUX_VIEWPORT_ZOOM`.
#[cfg(any(test, target_os = "linux"))]
fn viewport_enabled_with(wheel: Option<&str>, gate: Option<&str>) -> bool {
    if wheel == Some("1") {
        return false;
    }
    gate != Some("0")
}

/// Whether the receiver may render the lens at all. The global wheel
/// opt-out and the Linux-specific kill switch both force page zoom.
/// Off Linux there is no lens, so this is always false there.
#[cfg(any(test, target_os = "linux"))]
fn viewport_enabled() -> bool {
    viewport_enabled_with(
        std::env::var("THEKVM_WHEEL_PINCH").ok().as_deref(),
        std::env::var("THEKVM_LINUX_VIEWPORT_ZOOM").ok().as_deref(),
    )
}

#[cfg(not(any(test, target_os = "linux")))]
fn viewport_enabled() -> bool {
    false
}

/// One receiver-side viewport-zoom gesture driver. Owns the lens window
/// lifetime: sticky across PinchEnd, closed on factor 1.0 or Drop
/// (session teardown never leaves a stuck lens behind).
pub struct ViewportZoom {
    factor: f64,
    /// A failed X session latches the whole gesture driver into the
    /// Ctrl+wheel fallback instead of retrying (and warning) per event.
    #[cfg(target_os = "linux")]
    degraded: bool,
    #[cfg(target_os = "linux")]
    warned: bool,
    #[cfg(target_os = "linux")]
    announced: bool,
    #[cfg(target_os = "linux")]
    session: Option<LensSession>,
}

impl ViewportZoom {
    pub fn new() -> Self {
        Self {
            factor: MIN_FACTOR,
            #[cfg(target_os = "linux")]
            degraded: false,
            #[cfg(target_os = "linux")]
            warned: false,
            #[cfg(target_os = "linux")]
            announced: false,
            #[cfg(target_os = "linux")]
            session: None,
        }
    }

    /// Current factor (1.0 = lens closed). For tests and the journal.
    pub fn factor(&self) -> f64 {
        self.factor
    }

    /// Render one pinch delta as viewport zoom. `display` is the X
    /// display to open (the receiver's session display: a headless
    /// service has none of its own, so the daemon passes its sidecar
    /// truth here — without it the lens fails closed and the caller
    /// falls back to page zoom). Returns true when the event was
    /// consumed (lens open, opening, or closing back to unity); false
    /// when the caller must use the Ctrl+wheel fallback for this event
    /// instead. Never fails the send.
    pub fn update(&mut self, delta: i32, display: Option<&str>) -> bool {
        if !viewport_enabled() {
            return false;
        }
        self.update_platform(delta, display)
    }

    #[cfg(target_os = "linux")]
    fn update_platform(&mut self, delta: i32, display: Option<&str>) -> bool {
        if self.degraded {
            return false;
        }
        let next = zoom_factor(self.factor, delta);
        // Zooming out at unity with no lens open is not a viewport
        // gesture at all: let it fall back so pinch-in at 1.0 still
        // page-zooms out exactly like before.
        if self.session.is_none() && next <= MIN_FACTOR {
            self.factor = MIN_FACTOR;
            return false;
        }
        if self.session.is_none() {
            match LensSession::open(display) {
                Ok(session) => self.session = Some(session),
                Err(error) => {
                    self.degraded = true;
                    self.warn(format!(
                        "viewport lens unavailable ({error}); pinch degrades to Ctrl+wheel"
                    ));
                    return false;
                }
            }
        }
        self.factor = next;
        if self.factor <= MIN_FACTOR {
            // Pinched all the way home: close the lens, swallow the
            // event (the gesture resolved under viewport semantics).
            self.factor = MIN_FACTOR;
            self.session = None;
            return true;
        }
        let rendered = self
            .session
            .as_mut()
            .map(|session| session.render(self.factor))
            .unwrap_or(Ok(()));
        match rendered {
            Ok(()) => {
                if !self.announced {
                    self.announced = true;
                    tracing::info!(factor = %format!("{:.2}", self.factor), "viewport zoom lens engaged (OS-level zoom at cursor)");
                }
                true
            }
            Err(error) => {
                self.session = None;
                self.degraded = true;
                self.warn(format!(
                    "viewport lens render failed ({error}); pinch degrades to Ctrl+wheel"
                ));
                false
            }
        }
    }

    /// Off Linux there is no lens: every gesture falls back (Windows
    /// renders touch injection in its own injector instead).
    #[cfg(not(target_os = "linux"))]
    fn update_platform(&mut self, _delta: i32, _display: Option<&str>) -> bool {
        false
    }

    /// Gesture end. The lens stays open at its factor (sticky, like the
    /// browser zoom persisting after fingers lift); takes one final
    /// follow-refresh so the lens settles on the latest cursor.
    pub fn end(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(session) = self.session.as_mut() {
            if self.factor > MIN_FACTOR {
                if let Err(error) = session.render(self.factor) {
                    self.session = None;
                    self.degraded = true;
                    self.warn(format!(
                        "viewport lens refresh failed ({error}); pinch degrades to Ctrl+wheel"
                    ));
                }
            }
        }
    }

    /// Close the lens now (session teardown also Drops, which closes).
    pub fn close(&mut self) {
        self.factor = MIN_FACTOR;
        #[cfg(target_os = "linux")]
        {
            self.session = None;
        }
    }

    #[cfg(target_os = "linux")]
    fn warn(&mut self, message: String) {
        if !self.warned {
            self.warned = true;
            tracing::warn!("{message}");
        }
    }
}

impl Default for ViewportZoom {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ViewportZoom {
    fn drop(&mut self) {
        self.close();
    }
}

/// The live X11 lens: connection, window, cursor memory. Created lazily
/// on the first pinch update past unity, destroyed when the factor
/// returns to 1.0 or the session ends.
#[cfg(target_os = "linux")]
struct LensSession {
    connection: x11rb::rust_connection::RustConnection,
    root: u32,
    root_depth: u8,
    screen_px: (u32, u32),
    window: u32,
    gc: u32,
    cursor: (u32, u32),
    mapped: bool,
}

#[cfg(target_os = "linux")]
impl LensSession {
    /// Connect to the session X server and raise the lens window.
    /// `display` names the server explicitly (headless services pass
    /// their session sidecar truth; `None` leans on `$DISPLAY`). Fails
    /// closed with a reason whenever the lens cannot be honest:
    /// Wayland (an XWayland root would show the wrong content),
    /// unreachable display, non-LSB image order, non-24-bit root, or a
    /// missing SHAPE extension (without an empty input shape the lens
    /// would swallow clicks landing on it).
    fn open(display: Option<&str>) -> Result<Self, String> {
        use x11rb::connection::{Connection, RequestConnection};
        use x11rb::protocol::shape::ConnectionExt as _;
        use x11rb::protocol::xproto::{ConnectionExt as _, CreateWindowAux, WindowClass};

        if std::env::var("XDG_SESSION_TYPE").as_deref() == Ok("wayland") {
            return Err("Wayland session (lens needs the X11 root)".into());
        }
        let (connection, screen) =
            x11rb::connect(display).map_err(|error| format!("X11 connect: {error}"))?;
        if connection.setup().image_byte_order != x11rb::protocol::xproto::ImageOrder::LSB_FIRST {
            return Err("non-LSB X image order".into());
        }
        let info = connection
            .setup()
            .roots
            .get(screen)
            .ok_or_else(|| "X11 screen does not exist".to_string())?;
        if info.width_in_pixels == 0 || info.height_in_pixels == 0 {
            return Err("zero-size X screen".into());
        }
        if info.root_depth != 24 {
            return Err(format!("root depth {} (lens needs 24)", info.root_depth));
        }
        // Copy the scalars out: `info` borrows the connection, which
        // moves into the session below.
        let root_depth = info.root_depth;
        if connection
            .extension_information(x11rb::protocol::shape::X11_EXTENSION_NAME)
            .map_err(|error| format!("SHAPE probe: {error}"))?
            .is_none()
        {
            return Err("SHAPE extension missing (lens must be click-through)".into());
        }
        let root = info.root;
        let screen_px = (
            u32::from(info.width_in_pixels),
            u32::from(info.height_in_pixels),
        );
        let window: u32 = connection
            .generate_id()
            .map_err(|error| format!("lens window id: {error}"))?;
        let gc: u32 = connection
            .generate_id()
            .map_err(|error| format!("lens gc id: {error}"))?;
        connection
            .create_window(
                x11rb::COPY_FROM_PARENT as u8,
                window,
                root,
                0,
                0,
                320,
                240,
                1,
                WindowClass::INPUT_OUTPUT,
                x11rb::COPY_FROM_PARENT,
                &CreateWindowAux::new()
                    .background_pixel(info.black_pixel)
                    .border_pixel(info.white_pixel)
                    .override_redirect(1),
            )
            .map_err(|error| format!("lens window: {error}"))?
            .check()
            .map_err(|error| format!("lens window: {error}"))?;
        connection
            .create_gc(gc, root, &x11rb::protocol::xproto::CreateGCAux::new())
            .map_err(|error| format!("lens gc: {error}"))?
            .check()
            .map_err(|error| format!("lens gc: {error}"))?;
        // Empty input shape: every click passes through to the windows
        // below, so drive continues underneath the lens untouched.
        connection
            .shape_mask(
                x11rb::protocol::shape::SO::SET,
                x11rb::protocol::shape::SK::INPUT,
                window,
                0,
                0,
                x11rb::NONE,
            )
            .map_err(|error| format!("lens click-through: {error}"))?
            .check()
            .map_err(|error| format!("lens click-through: {error}"))?;
        connection
            .map_window(window)
            .map_err(|error| format!("lens map: {error}"))?
            .check()
            .map_err(|error| format!("lens map: {error}"))?;
        connection
            .flush()
            .map_err(|error| format!("lens flush: {error}"))?;
        tracing::debug!("viewport lens window raised");
        Ok(Self {
            connection,
            root,
            root_depth,
            screen_px,
            window,
            gc,
            cursor: (screen_px.0 / 2, screen_px.1 / 2),
            mapped: true,
        })
    }

    /// One lens frame at the current factor: follow the cursor, capture
    /// the source rect, upscale, present, restack above. The lens unmaps
    /// for the capture (its own old frame sits inside the source rect —
    /// see the module docs) and re-maps for the present; the whole
    /// sequence flushes once so the hide never reaches the eye.
    fn render(&mut self, factor: f64) -> Result<(), String> {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{
            ConfigureWindowAux, ConnectionExt as _, ImageFormat, StackMode,
        };

        let pointer = self
            .connection
            .query_pointer(self.root)
            .map_err(|error| format!("pointer query: {error}"))?
            .reply()
            .map_err(|error| format!("pointer read: {error}"))?;
        if pointer.root_x >= 0 && pointer.root_y >= 0 {
            self.cursor = (pointer.root_x as u32, pointer.root_y as u32);
        }
        let ((lx, ly, lw, lh), (sx, sy, sw, sh)) =
            lens_geometry(self.cursor, self.screen_px, factor);
        if self.mapped {
            self.connection
                .unmap_window(self.window)
                .map_err(|error| format!("lens hide: {error}"))?;
            self.mapped = false;
        }
        let capture = self.connection.get_image(
            ImageFormat::Z_PIXMAP,
            self.root,
            sx as i16,
            sy as i16,
            sw as u16,
            sh as u16,
            u32::MAX,
        );
        let pixels = capture
            .map_err(|error| format!("desktop capture: {error}"))?
            .reply()
            .map_err(|error| format!("capture read: {error}"))?
            .data;
        if pixels.len() < sw as usize * sh as usize * 4 {
            return Err("short capture buffer".into());
        }
        let scaled = upscale_xrgb(&pixels, sw, sh, lw, lh);
        self.connection
            .configure_window(
                self.window,
                &ConfigureWindowAux::new()
                    .x(lx as i32)
                    .y(ly as i32)
                    .width(lw)
                    .height(lh)
                    .stack_mode(StackMode::ABOVE),
            )
            .map_err(|error| format!("lens place: {error}"))?
            .check()
            .map_err(|error| format!("lens place: {error}"))?;
        self.connection
            .map_window(self.window)
            .map_err(|error| format!("lens show: {error}"))?
            .check()
            .map_err(|error| format!("lens show: {error}"))?;
        self.mapped = true;
        self.connection
            .put_image(
                ImageFormat::Z_PIXMAP,
                self.window,
                self.gc,
                lw as u16,
                lh as u16,
                0,
                0,
                0,
                self.root_depth,
                &scaled,
            )
            .map_err(|error| format!("lens present: {error}"))?
            .check()
            .map_err(|error| format!("lens present: {error}"))?;
        self.connection
            .flush()
            .map_err(|error| format!("lens flush: {error}"))?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LensSession {
    fn drop(&mut self) {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::ConnectionExt as _;
        let _ = self.connection.destroy_window(self.window);
        let _ = self.connection.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::{lens_geometry, upscale_xrgb, viewport_enabled_with, zoom_factor};

    #[test]
    fn detent_steps_zoom_smoothly_and_clamp() {
        // One detent in: ~x1.10.
        let after = zoom_factor(1.0, 120);
        assert!(after > 1.09 && after < 1.11, "one detent: {after}");
        // Zero delta is a no-op.
        assert_eq!(zoom_factor(2.5, 0), 2.5);
        // Out clamps at the floor.
        assert_eq!(zoom_factor(1.0, -10_000), 1.0);
        // In clamps at the ceiling.
        assert_eq!(zoom_factor(7.9, 10_000), 8.0);
        // Symmetric: out undoes in (within float dust).
        let up = zoom_factor(1.0, 240);
        let down = zoom_factor(up, -240);
        assert!((down - 1.0).abs() < 0.05, "round trip: {down}");
    }

    #[test]
    fn lens_is_a_third_centered_and_clamped() {
        let ((lx, ly, lw, lh), (sx, sy, sw, sh)) = lens_geometry((960, 540), (1920, 1080), 2.0);
        assert_eq!((lw, lh), (640, 360));
        assert_eq!((sw, sh), (320, 180));
        assert_eq!((sx, sy), (960 - 160, 540 - 90));
        assert_eq!((lx, ly), (960 - 320, 540 - 180));
        // Unity factor: source covers the lens footprint exactly.
        let (_, unity_src) = lens_geometry((960, 540), (1920, 1080), 1.0);
        assert_eq!((unity_src.2, unity_src.3), (lw, lh));
        // Corner cursor: both rects stay inside the screen.
        for cursor in [(0, 0), (1919, 1079), (5, 1000), (1900, 3)] {
            let ((lx, ly, lw, lh), (sx, sy, sw, sh)) = lens_geometry(cursor, (1920, 1080), 4.0);
            assert!(lx + lw <= 1920 && ly + lh <= 1080, "lens in screen");
            assert!(sx + sw <= 1920 && sy + sh <= 1080, "src in screen");
            assert!(sw >= 16 && sh >= 16, "src never degenerates");
        }
        // Small screen: lens clamps to its minimum window.
        let ((_, _, lw, lh), _) = lens_geometry((400, 300), (800, 600), 2.0);
        assert_eq!((lw, lh), (320, 240));
    }

    #[test]
    fn upscale_preserves_solid_and_size() {
        // Solid red 4x4 -> 8x6 stays solid red, exact size.
        let src = (0..16).flat_map(|_| [0u8, 0, 255, 0]).collect::<Vec<_>>();
        let dst = upscale_xrgb(&src, 4, 4, 8, 6);
        assert_eq!(dst.len(), 8 * 6 * 4);
        let (pixels, remainder) = dst.as_chunks::<4>();
        assert!(remainder.is_empty());
        for pixel in pixels {
            assert_eq!(pixel, &[0, 0, 255, 0]);
        }
        // 1:1 is bit-identical on color bytes (the pad byte zeroes).
        let src = (0..12)
            .flat_map(|pixel| [pixel * 3, pixel * 3 + 1, pixel * 3 + 2, 0u8])
            .collect::<Vec<_>>();
        assert_eq!(upscale_xrgb(&src, 4, 3, 4, 3), src);
        // 2x1 black->white to 4x1 interpolates the quarter steps.
        let src = vec![0u8, 0, 0, 0, 255, 255, 255, 0];
        let dst = upscale_xrgb(&src, 2, 1, 4, 1);
        assert_eq!(dst.len(), 16);
        let ramp = [dst[0], dst[4], dst[8], dst[12]];
        assert_eq!(ramp, [0, 64, 191, 255], "quarter-step ramp: {ramp:?}");
    }

    #[test]
    fn gates_force_page_zoom() {
        assert!(viewport_enabled_with(None, None));
        assert!(!viewport_enabled_with(Some("1"), None));
        assert!(!viewport_enabled_with(None, Some("0")));
        assert!(!viewport_enabled_with(Some("1"), Some("0")));
        // Other values are not the opt-outs.
        assert!(viewport_enabled_with(Some("0"), Some("1")));
    }

    #[test]
    fn closed_lens_reports_unity() {
        let zoom = super::ViewportZoom::new();
        assert_eq!(zoom.factor(), 1.0);
    }

    /// Manual end-to-end: opens the REAL lens on the session X server
    /// for ~6s (screenshot window) then closes it. Run on Mint with the
    /// session display visible: `DISPLAY=:0 cargo test -p kvm-platform
    /// --lib -- --ignored lens_smoke`. Fails honestly when no X session
    /// is reachable (that is the fallback path working as designed).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "manual: raises a real lens window on the live desktop for 6s"]
    fn lens_smoke_opens_on_session_x() {
        if std::env::var("DISPLAY").is_err() {
            std::env::set_var("DISPLAY", ":0");
        }
        let mut zoom = super::ViewportZoom::new();
        let mut rendered = false;
        for _ in 0..12 {
            rendered |= zoom.update(120, None);
        }
        assert!(rendered, "lens should render on the session X server");
        assert!(zoom.factor() > 1.5);
        std::thread::sleep(std::time::Duration::from_secs(6));
        zoom.close();
        assert_eq!(zoom.factor(), 1.0);
    }

    /// Debug helper (manual): dumps a full-root GetImage to /tmp/cap.ppm
    /// so we can see exactly what the capture path reads. Run on Mint:
    /// `DISPLAY=:0 cargo test -p kvm-platform --lib -- --ignored
    /// capture_dump --nocapture`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "manual: writes /tmp/cap.ppm from the raw GetImage path"]
    fn capture_dump_writes_root_ppm() {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat};
        if std::env::var("DISPLAY").is_err() {
            std::env::set_var("DISPLAY", ":0");
        }
        let (connection, screen) = x11rb::connect(None).expect("x11 connect");
        let info = connection.setup().roots.get(screen).expect("screen");
        let (width, height) = (
            u32::from(info.width_in_pixels),
            u32::from(info.height_in_pixels),
        );
        eprintln!("root {width}x{height} depth {}", info.root_depth);
        let reply = connection
            .get_image(
                ImageFormat::Z_PIXMAP,
                info.root,
                0,
                0,
                width as u16,
                height as u16,
                u32::MAX,
            )
            .expect("get_image")
            .reply()
            .expect("reply");
        eprintln!("captured {} bytes", reply.data.len());
        let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
        let (pixels, remainder) = reply.data.as_chunks::<4>();
        assert!(remainder.is_empty());
        for pixel in pixels {
            ppm.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        }
        std::fs::write("/tmp/cap.ppm", &ppm).expect("write ppm");
    }
}
