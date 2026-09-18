//! Input capture backends (sender side).

use crate::PlatformError;
use kvm_core::InputEvent;
use std::sync::atomic::AtomicBool;

pub trait CaptureBackend: Send {
    /// Blocking; yields events while this machine is the active controller.
    /// Implementations must periodically observe `stop`, including while no
    /// physical input is arriving, so a grabbed device is released promptly.
    fn next_event(
        &mut self,
        stop: &AtomicBool,
        exclusive: &AtomicBool,
        release: &AtomicBool,
    ) -> Result<InputEvent, PlatformError>;

    /// Release a compositor-mediated capture without changing the desired
    /// exclusivity state. Kernel and hook backends do not need this operation.
    fn release(&mut self) -> Result<(), PlatformError> {
        Ok(())
    }

    /// Make the backend exclusive. Fixed-peer capture uses this to prevent
    /// physical events from being delivered both locally and remotely.
    fn set_exclusive(&mut self, _exclusive: bool) -> Result<(), PlatformError> {
        Ok(())
    }
}

/// Warp the local pointer when a topology handoff returns control. Windows
/// can perform this in the active interactive session, while X11 can perform
/// it through the root window. Wayland intentionally remains a no-op because
/// arbitrary pointer warping is compositor-controlled and not exposed by the
/// input-capture portal.
#[cfg(target_os = "windows")]
pub fn warp_cursor(x: u32, y: u32) -> Result<(), PlatformError> {
    use windows::Win32::UI::WindowsAndMessaging::SetCursorPos;

    unsafe { SetCursorPos(x.min(i32::MAX as u32) as i32, y.min(i32::MAX as u32) as i32) }
        .map_err(|error| PlatformError::Win32(format!("SetCursorPos failed: {error}")))
}

/// Read the current pointer position when the platform exposes it to the
/// controller process. Topology starts from this value instead of assuming
/// the pointer is centered in the configured screen. Wayland intentionally
/// returns `None` because a generic pointer query is not available to an
/// ordinary client.
#[cfg(target_os = "windows")]
pub fn current_cursor_position() -> Result<Option<(u32, u32)>, PlatformError> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    let mut point = POINT::default();
    unsafe { GetCursorPos(&mut point) }
        .map_err(|error| PlatformError::Win32(format!("GetCursorPos failed: {error}")))?;
    if point.x < 0 || point.y < 0 {
        return Ok(None);
    }
    Ok(Some((point.x as u32, point.y as u32)))
}

/// Measured primary-desktop size in pixels (Deskflow `getShape` parity).
/// The crossing edge must sit on the visible edge: a layout working in
/// fallback dims while the pointer lives in physical ones is the whole
/// "exits while visibly far from the edge" class. `None` where the
/// platform exposes no truth (the router keeps its configured dims).
#[cfg(target_os = "windows")]
pub fn screen_size() -> Result<Option<(u32, u32)>, PlatformError> {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    if width <= 0 || height <= 0 {
        return Ok(None);
    }
    Ok(Some((width as u32, height as u32)))
}

/// Update the Windows hook's suppression flag immediately. The capture loop
/// also observes the shared flag, but handoff transitions should not wait for
/// its next input poll before local physical events are blocked or released.
#[cfg(target_os = "windows")]
pub fn set_exclusive(exclusive: bool) {
    win32_hooks::set_exclusive(exclusive);
}

#[cfg(not(target_os = "windows"))]
pub fn set_exclusive(_exclusive: bool) {}

#[cfg(target_os = "linux")]
pub fn warp_cursor(x: u32, y: u32) -> Result<(), PlatformError> {
    warp_cursor_on(None, x, y)
}

/// Warp the pointer on an explicitly named X display. Headless daemons
/// have no DISPLAY of their own: the session side publishes its display
/// name (see the geometry sidecar) and grants access, so the receiver
/// can still place the OS cursor exactly on the entry point.
#[cfg(target_os = "linux")]
pub fn warp_cursor_on(display: Option<&str>, x: u32, y: u32) -> Result<(), PlatformError> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;

    let (connection, screen) = x11rb::connect(display).map_err(|error| {
        PlatformError::Capture(format!("connect to X11 for pointer warp: {error}"))
    })?;
    let root = connection
        .setup()
        .roots
        .get(screen)
        .ok_or_else(|| PlatformError::Capture("X11 screen does not exist".into()))?
        .root;
    connection
        .warp_pointer(
            x11rb::NONE,
            root,
            0,
            0,
            0,
            0,
            x.min(i16::MAX as u32) as i16,
            y.min(i16::MAX as u32) as i16,
        )
        .map_err(|error| PlatformError::Capture(format!("warp X11 pointer: {error}")))?
        .check()
        .map_err(|error| PlatformError::Capture(format!("warp X11 pointer: {error}")))?;
    connection
        .flush()
        .map_err(|error| PlatformError::Capture(format!("flush X11 pointer warp: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn current_cursor_position() -> Result<Option<(u32, u32)>, PlatformError> {
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;

    // This is only a best-effort initialization aid for X11. A negative root
    // coordinate can represent a monitor left/above the X11 origin and
    // cannot safely be interpreted as a single-screen layout coordinate.
    let (connection, screen) = x11rb::connect(None).map_err(|error| {
        PlatformError::Capture(format!("connect to X11 for pointer query: {error}"))
    })?;
    let root = connection
        .setup()
        .roots
        .get(screen)
        .ok_or_else(|| PlatformError::Capture("X11 screen does not exist".into()))?
        .root;
    let reply = connection
        .query_pointer(root)
        .map_err(|error| PlatformError::Capture(format!("query X11 pointer: {error}")))?
        .reply()
        .map_err(|error| PlatformError::Capture(format!("read X11 pointer: {error}")))?;
    if reply.root_x < 0 || reply.root_y < 0 {
        return Ok(None);
    }
    Ok(Some((reply.root_x as u32, reply.root_y as u32)))
}

/// Measured X11 root size in pixels (see the Windows twin above). Reads
/// the same screen the pointer query uses, so seed and dims agree.
#[cfg(target_os = "linux")]
pub fn screen_size() -> Result<Option<(u32, u32)>, PlatformError> {
    use x11rb::connection::Connection;

    let (connection, screen) = x11rb::connect(None).map_err(|error| {
        PlatformError::Capture(format!("connect to X11 for screen size: {error}"))
    })?;
    let info = connection
        .setup()
        .roots
        .get(screen)
        .ok_or_else(|| PlatformError::Capture("X11 screen does not exist".into()))?;
    if info.width_in_pixels == 0 || info.height_in_pixels == 0 {
        return Ok(None);
    }
    Ok(Some((
        info.width_in_pixels as u32,
        info.height_in_pixels as u32,
    )))
}

#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn warp_cursor(_x: u32, _y: u32) -> Result<(), PlatformError> {
    Ok(())
}

/// Platforms without a screen query keep the configured layout dims.
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn screen_size() -> Result<Option<(u32, u32)>, PlatformError> {
    Ok(None)
}

/// Backend receipt census: (hook keys, hook buttons, hook fallback
/// motion, hook wheel, raw motion, raw wheel, precision-touchpad scroll)
/// delivered into our channel since process start. Zeros elsewhere; the
/// daemon logs it once a minute so input-path reports are evidence, not
/// guesses.
#[cfg(target_os = "windows")]
pub fn backend_census() -> (u64, u64, u64, u64, u64, u64, u64) {
    win32_hooks::census()
}

/// Platforms without channel split report no census.
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn backend_census() -> (u64, u64, u64, u64, u64, u64, u64) {
    (0, 0, 0, 0, 0, 0, 0)
}

/// Linux census: X11 translated arrivals fill the key/button/move/wheel
/// slots (raw slots stay zero — no hook/RAW split here).
#[cfg(target_os = "linux")]
pub fn backend_census() -> (u64, u64, u64, u64, u64, u64, u64) {
    let (key, button, motion, wheel) = crate::x11_capture::census();
    (key, button, motion, wheel, 0, 0, 0)
}

/// Inbound-while-driving signal for the topology child's auto-yield:
/// peer-injected arrivals observed while our own drive holds the local
/// suppression. Linux counts own-uinput arrivals diverted by the XI grab;
/// Windows counts ECHO_TAG-tagged hook arrivals (this child injects
/// nothing itself while driving out, and its own warps use the untagged
/// SetCursorPos path, so tagged arrivals are the peer driving us).
/// The child snapshots this when a drive starts and yields the outbound
/// drive when it grows — otherwise the peer cursor stays invisible and
/// its clicks die in our grab until the local mouse returns home.
#[cfg(target_os = "windows")]
pub fn inbound_while_driving_count() -> u64 {
    win32_hooks::inbound_echo_count()
}

/// Linux half of the inbound-while-driving signal (see above).
#[cfg(target_os = "linux")]
pub fn inbound_while_driving_count() -> u64 {
    crate::x11_capture::inbound_diverted_count()
}

/// Platforms without a suppression grab never divert inbound input.
#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn inbound_while_driving_count() -> u64 {
    0
}

#[cfg(all(not(target_os = "windows"), not(target_os = "linux")))]
pub fn current_cursor_position() -> Result<Option<(u32, u32)>, PlatformError> {
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use crate::evdev_capture::EvdevCapture as DefaultCapture;

#[cfg(target_os = "windows")]
pub use win32_hooks::Win32Capture as DefaultCapture;

/// Select the sender-side input backend. A logged-in Linux Wayland topology
/// session can use the compositor's portal/libei API because `/dev/input` is
/// not a valid or safe capture mechanism for ordinary desktop applications.
/// XInput2 is suitable for both topology and fixed-peer X11 sessions, so a
/// logged-in X11 controller does not need privileged evdev access. The evdev
/// backend remains the fallback for headless/pre-login sessions and systems
/// without a working user-session backend.
pub fn create_capture(
    _prefer_wayland: bool,
    _exclusive: bool,
) -> Result<Box<dyn CaptureBackend>, PlatformError> {
    #[cfg(target_os = "linux")]
    if _prefer_wayland {
        match crate::wayland_capture::WaylandCapture::create(_exclusive, true) {
            Ok(capture) => {
                tracing::info!("using Wayland input-capture portal backend");
                return Ok(Box::new(capture));
            }
            Err(error) => {
                tracing::debug!(%error, "Wayland input-capture portal unavailable; trying evdev")
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        match crate::x11_capture::X11Capture::create() {
            Ok(capture) => {
                tracing::info!("using XInput2 raw capture backend");
                return Ok(Box::new(capture));
            }
            Err(error) => {
                tracing::debug!(%error, "XInput2 capture unavailable; trying evdev")
            }
        }
    }

    Ok(Box::new(DefaultCapture::create()?))
}

#[cfg(target_os = "windows")]
mod win32_hooks {
    use super::{CaptureBackend, InputEvent, PlatformError};
    use kvm_core::{KeyEvent, MouseButton};
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Mutex, OnceLock};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::Input::{
        GetRawInputData, RegisterRawInputDevices, HRAWINPUT, MOUSE_MOVE_ABSOLUTE, RAWINPUTDEVICE,
        RAWINPUTHEADER, RAWMOUSE, RIDEV_INPUTSINK, RIDEV_NOLEGACY, RIDEV_REMOVE, RID_INPUT,
        RIM_TYPEHID, RIM_TYPEMOUSE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetCursorPos, GetMessageW, PeekMessageW, PostThreadMessageW, RegisterClassW, SetCursorPos,
        SetWindowPos, SetWindowsHookExW, ShowWindow, TranslateMessage, UnhookWindowsHookEx,
        HC_ACTION, HMENU, HWND_MESSAGE, HWND_TOPMOST, KBDLLHOOKSTRUCT, MSG, MSLLHOOKSTRUCT,
        PM_NOREMOVE, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SW_SHOWNOACTIVATE, WH_KEYBOARD_LL,
        WH_MOUSE_LL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_INPUT, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN,
        WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL,
        WM_QUIT, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDOWN,
        WM_XBUTTONUP, WNDCLASSW, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
        XBUTTON1, XBUTTON2,
    };

    static SENDER: OnceLock<Mutex<Option<Sender<InputEvent>>>> = OnceLock::new();
    static LAST_POINT: OnceLock<Mutex<Option<POINT>>> = OnceLock::new();
    // DUAL-SCROLL CONTRACT — read before touching anything in this
    // module that mentions suppression, NOLEGACY, guard, echo, or dedup.
    // While this machine drives a peer, a trackpad/mouse scroll must reach
    // ONLY the peer. Local delivery leaks through THREE independent OS
    // paths, each closed by its own layer below; removing ANY layer
    // reopens dual scroll (both machines scroll) on some hardware:
    //   1. hook swallow (mouse_hook/keyboard_hook return 1 while
    //      BLOCK_LOCAL): stops legacy wheel the hook sees. Precision
    //      touchpads bypass the hook, so this alone never suffices.
    //   2. RIDEV_NOLEGACY re-registration (apply_raw_legacy_suppression):
    //      stops the OS synthesizing legacy WM_MOUSEWHEEL for our usages.
    //      The PTP digitizer collection bypasses it, so this alone never
    //      suffices either.
    //   3. scroll-guard pixel (scroll_guard_pixel + repark_guard_pixel):
    //      a 1x1 topmost window under the cursor that catches the PTP
    //      stack's direct-to-window translation.
    // Symptom of a broken layer: scroll on the peer ALSO scrolls the
    // local app under the parked cursor, usually "sometimes" (race or
    // hardware dependent). See also the echo oracle + WheelDedup below:
    // they keep our own injected wheel from looping back as a phantom
    // drive, which is the same visible symptom from the opposite side.
    static BLOCK_LOCAL: AtomicBool = AtomicBool::new(false);
    static RAW_INPUT_ACTIVE: AtomicBool = AtomicBool::new(false);
    // Hook-thread rendezvous for the trackpad-scroll suppression toggle:
    // the daemon flips exclusivity from any thread, but RawInput
    // registration belongs to the thread that owns the RawInput window.
    static HOOK_THREAD_ID: AtomicU32 = AtomicU32::new(0);
    static RAW_WINDOW: AtomicIsize = AtomicIsize::new(0);
    static RAW_NOLEGACY: AtomicBool = AtomicBool::new(false);
    static PTP_NOLEGACY: AtomicBool = AtomicBool::new(false);
    /// Scroll-guard pixel window (see scroll_guard_pixel): 0 when absent.
    static GUARD_PIXEL: AtomicIsize = AtomicIsize::new(0);
    /// Cursor park point the guard pixel (and the cursor glue below) hold
    /// while driving: packed x/i32-low + y/i32-high. Written when the
    /// pixel parks, read on every swallowed motion tick. PARK_VALID gates
    /// it: no park yet (or lifted) means no glue.
    static PARK_POINT: AtomicU64 = AtomicU64::new(0);
    static PARK_VALID: AtomicBool = AtomicBool::new(false);
    /// One-shot journal verdicts (see apply_raw_legacy_suppression and
    /// scroll_guard_pixel): deterministic platform refusals log once per
    /// process instead of hiding at debug or spamming per drive.
    static WARNED_PTP_NOLEGACY: AtomicBool = AtomicBool::new(false);
    static WARNED_GUARD_PIXEL: AtomicBool = AtomicBool::new(false);
    /// Private thread message (WM_APP range): wparam != 0 enables RawInput
    /// legacy suppression while driving, 0 restores normal delivery.
    const WM_THEKVM_NOLEGACY: u32 = 0x8000 + 11;

    /// Backend receipt census: what each OS channel actually delivered
    /// into our channel (hook keys/buttons/fallback-motion/wheel, raw
    /// motion/wheel). Read by the daemon once a minute into the journal:
    /// the groundwork that settles "this input never arrives" reports
    /// from evidence instead of by guessing.
    static HOOK_KEY: AtomicU64 = AtomicU64::new(0);
    static HOOK_BUTTON: AtomicU64 = AtomicU64::new(0);
    static HOOK_MOVE: AtomicU64 = AtomicU64::new(0);
    static HOOK_WHEEL: AtomicU64 = AtomicU64::new(0);
    static RAW_MOVE: AtomicU64 = AtomicU64::new(0);
    static RAW_WHEEL: AtomicU64 = AtomicU64::new(0);
    /// Precision-touchpad two-finger scroll ticks derived from the HID
    /// digitizer channel (0x0D/0x05). The third wheel source alongside
    /// hook and raw-mouse: gestures the OS synthesizes straight into
    /// app windows reach neither of those taps.
    static PTP_SCROLL: AtomicU64 = AtomicU64::new(0);
    /// Own-echo arrivals skipped by tag (see keyboard_hook/mouse_hook):
    /// every ECHO_TAG-tagged event the hooks observe. While this child
    /// drives out it injects nothing itself, so tagged arrivals mean
    /// the service/helper is injecting the PEER's drive locally — the
    /// Windows half of the inbound-while-driving signal (see
    /// inbound_while_driving_count): the peer cursor cannot move here
    /// until this drive yields, exactly like the X11 divert shape.
    static INBOUND_ECHO: AtomicU64 = AtomicU64::new(0);

    pub(super) fn census() -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            HOOK_KEY.load(Ordering::Relaxed),
            HOOK_BUTTON.load(Ordering::Relaxed),
            HOOK_MOVE.load(Ordering::Relaxed),
            HOOK_WHEEL.load(Ordering::Relaxed),
            RAW_MOVE.load(Ordering::Relaxed),
            RAW_WHEEL.load(Ordering::Relaxed),
            PTP_SCROLL.load(Ordering::Relaxed),
        )
    }

    pub(super) fn inbound_echo_count() -> u64 {
        INBOUND_ECHO.load(Ordering::Relaxed)
    }

    pub(super) fn set_exclusive(exclusive: bool) {
        BLOCK_LOCAL.store(exclusive, Ordering::Release);
        // Precision-touchpad scroll never produces a hook-visible wheel
        // event, so the hook swallow above cannot stop it reaching local
        // windows. Ask the hook thread (which owns the RawInput window)
        // to toggle legacy suppression; the WM_INPUT channel keeps
        // flowing, so forwarding is unaffected. A lost post (dead hook
        // thread) warns loudly: silent loss here IS dual scroll with no
        // evidence, the worst kind.
        let thread_id = HOOK_THREAD_ID.load(Ordering::Acquire);
        if thread_id != 0 {
            unsafe {
                if PostThreadMessageW(
                    thread_id,
                    WM_THEKVM_NOLEGACY,
                    WPARAM(exclusive as usize),
                    LPARAM(0),
                )
                .is_err()
                {
                    tracing::warn!(
                        exclusive,
                        "suppression toggle lost: hook thread gone; local scroll may apply while driving"
                    );
                }
            }
        }
    }

    fn sender() -> &'static Mutex<Option<Sender<InputEvent>>> {
        SENDER.get_or_init(|| Mutex::new(None))
    }

    fn send(event: InputEvent) {
        if let Ok(guard) = sender().lock() {
            if let Some(tx) = guard.as_ref() {
                let _ = tx.send(event);
            }
        }
    }

    pub struct Win32Capture {
        receiver: Receiver<InputEvent>,
        thread_id: u32,
    }

    impl Win32Capture {
        pub fn create() -> Result<Self, PlatformError> {
            let (tx, receiver) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name("thekvm-windows-hooks".into())
                .spawn(move || hook_thread(tx, ready_tx))
                .map_err(|e| PlatformError::Capture(format!("start Windows hook thread: {e}")))?;
            drop(thread);
            let thread_id = match ready_rx.recv_timeout(std::time::Duration::from_secs(5)) {
                Ok(Ok(thread_id)) => thread_id,
                Ok(Err(error)) => {
                    return Err(PlatformError::Capture(error));
                }
                Err(error) => {
                    return Err(PlatformError::Capture(format!(
                        "Windows hook thread did not initialize: {error}"
                    )));
                }
            };
            // Detaching is intentional: the receiver owns the channel and the
            // hook thread exits when its message loop receives WM_QUIT.
            Ok(Self {
                receiver,
                thread_id,
            })
        }
    }

    impl CaptureBackend for Win32Capture {
        fn next_event(
            &mut self,
            stop: &AtomicBool,
            exclusive: &AtomicBool,
            _release: &AtomicBool,
        ) -> Result<InputEvent, PlatformError> {
            loop {
                BLOCK_LOCAL.store(exclusive.load(Ordering::Acquire), Ordering::Release);
                if stop.load(Ordering::Acquire) {
                    return Err(PlatformError::Capture("capture stopped".into()));
                }
                match self
                    .receiver
                    .recv_timeout(std::time::Duration::from_millis(100))
                {
                    Ok(event) => return Ok(event),
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(PlatformError::Capture("Windows hook stopped".into()))
                    }
                }
            }
        }

        fn set_exclusive(&mut self, exclusive: bool) -> Result<(), PlatformError> {
            set_exclusive(exclusive);
            Ok(())
        }
    }

    impl Drop for Win32Capture {
        fn drop(&mut self) {
            set_exclusive(false);
            unsafe {
                let _ = PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
        }
    }

    fn hook_thread(tx: Sender<InputEvent>, ready: mpsc::SyncSender<Result<u32, String>>) {
        if let Ok(mut guard) = sender().lock() {
            *guard = Some(tx);
        }

        let module = unsafe { GetModuleHandleW(None) }
            .map(|module| HINSTANCE(module.0))
            .unwrap_or_default();
        let keyboard = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), module, 0) };
        let mouse = unsafe { SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), module, 0) };
        let (keyboard, mouse) = match (keyboard, mouse) {
            (Ok(keyboard), Ok(mouse)) => (keyboard, mouse),
            (keyboard, mouse) => {
                if let Ok(keyboard) = keyboard {
                    unsafe {
                        let _ = UnhookWindowsHookEx(keyboard);
                    }
                }
                if let Ok(mouse) = mouse {
                    unsafe {
                        let _ = UnhookWindowsHookEx(mouse);
                    }
                }
                let _ = ready.send(Err("SetWindowsHookExW failed".into()));
                if let Ok(mut guard) = sender().lock() {
                    *guard = None;
                }
                return;
            }
        };
        if let Ok(mut guard) = LAST_POINT.get_or_init(|| Mutex::new(None)).lock() {
            *guard = None;
        }

        // Low-level hooks provide reliable keyboard/buttons/wheel events, but
        // their WM_MOUSEMOVE points are bounded by the local desktop. Raw
        // Input gives us relative mouse deltas, so movement remains available
        // when the pointer is parked at a topology edge. If registration is
        // unavailable, keep the hook-based motion fallback rather than making
        // the whole capture backend unusable.
        let raw_input_window = match create_raw_input_window(module) {
            Ok(window) => {
                RAW_INPUT_ACTIVE.store(true, Ordering::Release);
                Some(window)
            }
            Err(error) => {
                tracing::warn!(%error, "Windows Raw Input unavailable; using hook motion fallback");
                None
            }
        };
        let thread_id = unsafe { GetCurrentThreadId() };
        let mut queue_probe = MSG::default();
        unsafe {
            let _ = PeekMessageW(&mut queue_probe, None, 0, 0, PM_NOREMOVE);
        }
        // Publish the rendezvous only after the queue exists, so a posted
        // WM_THEKVM_NOLEGACY can never land on a queue-less thread.
        HOOK_THREAD_ID.store(thread_id, Ordering::Release);
        if let Some(window) = raw_input_window {
            RAW_WINDOW.store(window.0 as isize, Ordering::Release);
        }
        // A suppress that arrived before the window existed parked the
        // flags un-applied (see apply_raw_legacy_suppression): force the
        // live BLOCK_LOCAL state now, or an early drive start leaks local
        // scroll for the whole session. The pre-reset makes this a real
        // transition even when the flags happen to match already.
        let exclusive = BLOCK_LOCAL.load(Ordering::Acquire);
        RAW_NOLEGACY.store(!exclusive, Ordering::Release);
        PTP_NOLEGACY.store(!exclusive, Ordering::Release);
        apply_raw_legacy_suppression(exclusive);
        let _ = ready.send(Ok(thread_id));

        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
            if result.0 <= 0 {
                break;
            }
            // Thread message from set_exclusive: toggle RawInput legacy
            // suppression on the thread that owns the RawInput window.
            if message.hwnd.0.is_null() && message.message == WM_THEKVM_NOLEGACY {
                apply_raw_legacy_suppression(message.wParam.0 != 0);
                continue;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        unsafe {
            let _ = UnhookWindowsHookEx(keyboard);
            let _ = UnhookWindowsHookEx(mouse);
            // Thread-owned windows die with it, but lift suppression state
            // explicitly so a lingering flag can never outlive the hooks.
            scroll_guard_pixel(false);
            RAW_INPUT_ACTIVE.store(false, Ordering::Release);
            RAW_NOLEGACY.store(false, Ordering::Release);
            PTP_NOLEGACY.store(false, Ordering::Release);
            RAW_WINDOW.store(0, Ordering::Release);
            HOOK_THREAD_ID.store(0, Ordering::Release);
            if let Some(window) = raw_input_window {
                ptp_unsubscribe();
                let removal = RAWINPUTDEVICE {
                    usUsagePage: 0x01,
                    usUsage: 0x02,
                    dwFlags: RIDEV_REMOVE,
                    hwndTarget: HWND::default(),
                };
                let _ = RegisterRawInputDevices(
                    std::slice::from_ref(&removal),
                    std::mem::size_of::<RAWINPUTDEVICE>() as u32,
                );
                let _ = DestroyWindow(window);
            }
        }
        if let Ok(mut guard) = sender().lock() {
            *guard = None;
        }
    }

    unsafe extern "system" fn keyboard_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
            // Echo suppression by magic tag, not by INJECTED flag: our own
            // SendInput events carry ECHO_TAG and are skipped, while input
            // synthesized by vendor drivers (trackpad utilities, hotkey
            // tools) is real user input and must be captured. The old flag
            // check swallowed those. Skipped echoes still count (see
            // INBOUND_ECHO): while driving out, a tagged arrival is the
            // peer driving us.
            if info.dwExtraInfo != crate::ECHO_TAG {
                let message = wparam.0 as u32;
                let pressed = matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN);
                if pressed || matches!(message, WM_KEYUP | WM_SYSKEYUP) {
                    let usage = hid_from_scan_code(info.scanCode as u16, info.flags.0 & 0x01 != 0)
                        .or_else(|| hid_from_vk(info.vkCode as u16));
                    if let Some(usage) = usage {
                        HOOK_KEY.fetch_add(1, Ordering::Relaxed);
                        send(InputEvent::Key(KeyEvent { usage, pressed }));
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                }
            } else {
                INBOUND_ECHO.fetch_add(1, Ordering::Relaxed);
            }
        }
        CallNextHookEx(None, code, wparam, lparam)
    }

    unsafe extern "system" fn mouse_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
            // Own-echo oracle for the tag-less raw channel (see
            // WheelDedup): our SendInput wheel always traverses this hook
            // tagged, while the raw channel carries no tag at all.
            if info.dwExtraInfo == crate::ECHO_TAG {
                INBOUND_ECHO.fetch_add(1, Ordering::Relaxed);
                let own_message = wparam.0 as u32;
                let now = std::time::Instant::now();
                match own_message {
                    WM_MOUSEWHEEL => {
                        wheel_dedup().note_hook(0, (info.mouseData >> 16) as i16 as i32, true, now)
                    }
                    WM_MOUSEHWHEEL => {
                        wheel_dedup().note_hook((info.mouseData >> 16) as i16 as i32, 0, true, now)
                    }
                    _ => {}
                }
            }
            // Same tag rule as the keyboard hook: skip our own echo, keep
            // everything else including vendor-synthesized scroll.
            if info.dwExtraInfo != crate::ECHO_TAG {
                let message = wparam.0 as u32;
                match message {
                    WM_MOUSEMOVE => {
                        if RAW_INPUT_ACTIVE.load(Ordering::Acquire) {
                            if BLOCK_LOCAL.load(Ordering::Acquire) {
                                // Swallowed delivery does not stop the OS
                                // cursor itself from wandering (absolute
                                // devices move it past the hook): keep the
                                // pixel glued and snap the cursor home so
                                // PTP-direct translation cannot escape the
                                // pixel mid-drive (see glue_cursor_to_park).
                                repark_guard_pixel(info.pt);
                                glue_cursor_to_park(info.pt);
                                return LRESULT(1);
                            }
                            return CallNextHookEx(None, code, wparam, lparam);
                        }
                        let point = info.pt;
                        let last = LAST_POINT.get_or_init(|| Mutex::new(None));
                        if let Ok(mut guard) = last.lock() {
                            if let Some(previous) = *guard {
                                let dx = point.x.saturating_sub(previous.x);
                                let dy = point.y.saturating_sub(previous.y);
                                if dx != 0 || dy != 0 {
                                    HOOK_MOVE.fetch_add(1, Ordering::Relaxed);
                                    send(InputEvent::MouseMove { dx, dy });
                                }
                            }
                            *guard = Some(point);
                            if BLOCK_LOCAL.load(Ordering::Acquire) {
                                // Same glue as the RawInput motion arm
                                // above: the fallback path moves the real
                                // cursor too, and must not escape the pixel.
                                repark_guard_pixel(point);
                                glue_cursor_to_park(point);
                                return LRESULT(1);
                            }
                        }
                    }
                    WM_LBUTTONDOWN | WM_LBUTTONUP => {
                        HOOK_BUTTON.fetch_add(1, Ordering::Relaxed);
                        send(InputEvent::MouseButton {
                            button: MouseButton::Left,
                            pressed: message == WM_LBUTTONDOWN,
                        });
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_RBUTTONDOWN | WM_RBUTTONUP => {
                        HOOK_BUTTON.fetch_add(1, Ordering::Relaxed);
                        send(InputEvent::MouseButton {
                            button: MouseButton::Right,
                            pressed: message == WM_RBUTTONDOWN,
                        });
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_MBUTTONDOWN | WM_MBUTTONUP => {
                        HOOK_BUTTON.fetch_add(1, Ordering::Relaxed);
                        send(InputEvent::MouseButton {
                            button: MouseButton::Middle,
                            pressed: message == WM_MBUTTONDOWN,
                        });
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_XBUTTONDOWN | WM_XBUTTONUP => {
                        let button = match (info.mouseData >> 16) as u16 {
                            XBUTTON1 => MouseButton::Back,
                            XBUTTON2 => MouseButton::Forward,
                            _ => return CallNextHookEx(None, code, wparam, lparam),
                        };
                        send(InputEvent::MouseButton {
                            button,
                            pressed: message == WM_XBUTTONDOWN,
                        });
                        HOOK_BUTTON.fetch_add(1, Ordering::Relaxed);
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_MOUSEWHEEL => {
                        // Forward the raw 120ths (one WHEEL_DELTA) untouched:
                        // precision touchpads report smooth sub-detent motion
                        // and the old `/ 120` detent truncation rounded all
                        // of it to zero, so two-finger scroll never arrived
                        // remotely on any legacy KVM. The sender downgrades
                        // to detents for older peers. Filtered against the
                        // raw HID channel (same tick, raw arrived first).
                        let now = std::time::Instant::now();
                        let (_, y) =
                            wheel_dedup().filter_hook(0, (info.mouseData >> 16) as i16 as i32, now);
                        if y != 0 {
                            HOOK_WHEEL.fetch_add(1, Ordering::Relaxed);
                            send(InputEvent::SmoothWheel { x: 0, y });
                        }
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            repark_guard_pixel(info.pt);
                            return LRESULT(1);
                        }
                    }
                    WM_MOUSEHWHEEL => {
                        let now = std::time::Instant::now();
                        let (x, _) =
                            wheel_dedup().filter_hook((info.mouseData >> 16) as i16 as i32, 0, now);
                        if x != 0 {
                            HOOK_WHEEL.fetch_add(1, Ordering::Relaxed);
                            send(InputEvent::SmoothWheel { x, y: 0 });
                        }
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            repark_guard_pixel(info.pt);
                            return LRESULT(1);
                        }
                    }
                    _ => {}
                }
            }
        }
        CallNextHookEx(None, code, wparam, lparam)
    }

    /// Trackpad-scroll local suppression. Precision touchpads report
    /// two-finger scroll only through the raw HID channel (WM_INPUT),
    /// which is observe-only: the OS still delivers the matching legacy
    /// WM_MOUSEWHEEL to the window under the parked cursor, so the local
    /// machine scrolls while we drive the peer. Re-registering our mouse
    /// usage with RIDEV_NOLEGACY stops legacy delivery (the low-level
    /// hook still fires, so buttons/keys keep their hook swallow path,
    /// and WM_INPUT keeps flowing, so remote forwarding is untouched).
    /// The precision-touchpad digitizer collection (0x0D/0x05) is a
    /// separate HID top-level collection whose synthesized scroll bypasses
    /// the mouse-usage flag entirely, so it gets the same NOLEGACY toggle
    /// on the same sink window (WM_INPUT still flows for forwarding).
    /// Runs on the hook thread; idempotent across repeated transitions.
    ///
    /// Belt and braces for the digitizer path: the OS translates PTP pan
    /// straight into app windows (past both the hook and NOLEGACY), so
    /// the drive ALSO parks a 1x1 guard pixel under the held cursor (see
    /// scroll_guard_pixel) to catch that translation. Either layer alone
    /// leaks on some hardware; together they hold. DO NOT remove one
    /// side of this pairing to "simplify": that simplification is dual
    /// scroll (see the DUAL-SCROLL CONTRACT above).
    fn apply_raw_legacy_suppression(suppress: bool) {
        // Park/lift the guard pixel on the same transition (same thread:
        // it owns the window, like the RawInput window above). The pixel
        // is independent of RawInput registration, so it parks even on a
        // RawInput-less machine and the PTP-direct path stays closed
        // there too. Idempotent: parking an existing pixel (or lifting a
        // missing one) is a no-op.
        scroll_guard_pixel(suppress);
        if !RAW_INPUT_ACTIVE.load(Ordering::Acquire) {
            // The RawInput window is not up yet: a suppress request now
            // must NOT consume the flag transition. The swaps below would
            // eat it (armed-but-never-applied) and the drive would scroll
            // locally forever with zero evidence. Park the flags
            // un-applied instead; hook-thread init force-applies the live
            // BLOCK_LOCAL right after creating the window (see
            // hook_thread), so an early drive start still holds.
            RAW_NOLEGACY.store(false, Ordering::Release);
            PTP_NOLEGACY.store(false, Ordering::Release);
            return;
        }
        let mouse_changed = RAW_NOLEGACY.swap(suppress, Ordering::AcqRel) != suppress;
        let ptp_changed = PTP_NOLEGACY.swap(suppress, Ordering::AcqRel) != suppress;
        if !mouse_changed && !ptp_changed {
            return;
        }
        if !RAW_INPUT_ACTIVE.load(Ordering::Acquire) {
            // Window died between the check above and the swaps: un-eat
            // the transitions (see the park-unapplied comment above) so
            // the flags never claim a suppression that is not applied.
            RAW_NOLEGACY.store(false, Ordering::Release);
            PTP_NOLEGACY.store(false, Ordering::Release);
            return;
        }
        let hwnd = HWND(RAW_WINDOW.load(Ordering::Acquire) as *mut std::ffi::c_void);
        if hwnd.0.is_null() {
            // Same strand shape as above (live-proven: the PTP flag sat
            // claimed-but-never-applied and its engage line never logged
            // again): un-eat, loudly, instead of returning claimed.
            RAW_NOLEGACY.store(false, Ordering::Release);
            PTP_NOLEGACY.store(false, Ordering::Release);
            tracing::warn!(
                suppress,
                "suppression window missing at toggle time; flags parked un-applied, init force-applies"
            );
            return;
        }
        let flags = if suppress {
            RIDEV_INPUTSINK | RIDEV_NOLEGACY
        } else {
            RIDEV_INPUTSINK
        };
        if mouse_changed {
            let device = RAWINPUTDEVICE {
                usUsagePage: 0x01,
                usUsage: 0x02,
                dwFlags: flags,
                hwndTarget: hwnd,
            };
            match unsafe {
                RegisterRawInputDevices(
                    std::slice::from_ref(&device),
                    std::mem::size_of::<RAWINPUTDEVICE>() as u32,
                )
            } {
                Ok(_) => tracing::info!(
                    suppress,
                    "RawInput legacy delivery toggled for the drive session"
                ),
                Err(error) => {
                    // A failed registration must not leave the flag
                    // claiming suppression: the drive-start proof line
                    // below reads these flags, and a lie there is dual
                    // scroll with a clean journal — the worst kind.
                    RAW_NOLEGACY.store(false, Ordering::Release);
                    tracing::warn!(
                        %error,
                        suppress,
                        "RawInput legacy toggle failed; trackpad scroll may apply locally while driving"
                    );
                }
            }
        }
        if ptp_changed {
            // Digitizer-only toggle: observe-only WM_INPUT keeps flowing,
            // so the PTP scroll channel still forwards while local legacy
            // synthesis stops. Best effort — desktops without a touchpad
            // simply have nothing to suppress.
            let digitizer = RAWINPUTDEVICE {
                usUsagePage: PTP_USAGE_PAGE,
                usUsage: PTP_USAGE_TOUCHPAD,
                dwFlags: flags,
                hwndTarget: hwnd,
            };
            match unsafe {
                RegisterRawInputDevices(
                    std::slice::from_ref(&digitizer),
                    std::mem::size_of::<RAWINPUTDEVICE>() as u32,
                )
            } {
                Ok(_) => tracing::info!(
                    suppress,
                    "precision-touchpad legacy delivery toggled for the drive session"
                ),
                Err(error) => {
                    // Live-proven deterministic on some stacks (Windows
                    // rejects NOLEGACY for the digitizer collection): the
                    // flag must not claim it, and the refusal must be
                    // VISIBLE (once per process) — a debug here hid the
                    // missing layer for entire releases. The guard pixel
                    // below is then the only PTP-direct layer standing.
                    PTP_NOLEGACY.store(false, Ordering::Release);
                    if !WARNED_PTP_NOLEGACY.swap(true, Ordering::AcqRel) {
                        tracing::warn!(
                            %error,
                            "precision-touchpad NOLEGACY refused by Windows; guard pixel is the only PTP-direct suppression layer"
                        );
                    }
                }
            }
        }
        if suppress {
            // Drive-start suppression proof: one INFO line naming every
            // layer's armed state, so the next dual-scroll report starts
            // from evidence (which layer stood down) instead of guesses.
            tracing::info!(
                block_local = BLOCK_LOCAL.load(Ordering::Acquire),
                raw_nolegacy = RAW_NOLEGACY.load(Ordering::Acquire),
                ptp_nolegacy = PTP_NOLEGACY.load(Ordering::Acquire),
                guard_pixel = GUARD_PIXEL.load(Ordering::Acquire) != 0,
                raw_active = RAW_INPUT_ACTIVE.load(Ordering::Acquire),
                "local suppression armed for the drive session"
            );
        }
    }

    /// Scroll-guard pixel: a 1x1 topmost window parked exactly under the
    /// held cursor while driving. The OS translates precision-touchpad
    /// pan straight into the window under the cursor — past the low-level
    /// hook (which never sees it) and past RIDEV_NOLEGACY (which stops
    /// raw-legacy synthesis, not the PTP stack's own translation). Giving
    /// that translation OUR pixel to land on keeps local apps from
    /// scrolling while we drive the peer. The window ignores everything
    /// (DefWindowProc), never activates, never shows in the taskbar, and
    /// dies with the drive (or the thread): positioned under the cursor
    /// sprite it is invisible in practice. Best-effort creation — a
    /// missing pixel only costs the pre-existing behavior, never the
    /// drive. DO NOT delete this to "simplify" the three suppression
    /// layers: without it, precision-touchpad scroll applies locally on
    /// every drive (dual scroll), because neither the hook nor NOLEGACY
    /// can see that path. Paired with repark_guard_pixel below, which
    /// keeps it glued to a nudged cursor mid-drive.
    fn scroll_guard_pixel(show: bool) {
        unsafe extern "system" fn guard_proc(
            hwnd: HWND,
            message: u32,
            wparam: WPARAM,
            lparam: LPARAM,
        ) -> LRESULT {
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
        unsafe {
            if !show {
                let raw = GUARD_PIXEL.swap(0, Ordering::AcqRel);
                if raw != 0 {
                    let _ = DestroyWindow(HWND(raw as *mut std::ffi::c_void));
                }
                PARK_VALID.store(false, Ordering::Release);
                return;
            }
            if GUARD_PIXEL.load(Ordering::Acquire) != 0 {
                return;
            }
            let mut point = POINT::default();
            if GetCursorPos(&mut point).is_err() {
                return;
            }
            // The park point doubles as the cursor glue below (see
            // glue_cursor_to_park): store it before creating, so a
            // failed create still leaves a valid glue target.
            PARK_POINT.store(
                (point.x as u32 as u64) | ((point.y as u32 as u64) << 32),
                Ordering::Release,
            );
            PARK_VALID.store(true, Ordering::Release);
            let instance: HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();
            const GUARD_CLASS: &[u16] = &[
                'T' as u16, 'h' as u16, 'e' as u16, 'K' as u16, 'v' as u16, 'm' as u16, 'G' as u16,
                'u' as u16, 'a' as u16, 'r' as u16, 'd' as u16, 0,
            ];
            let _ = RegisterClassW(&WNDCLASSW {
                lpfnWndProc: Some(guard_proc),
                hInstance: instance,
                lpszClassName: PCWSTR(GUARD_CLASS.as_ptr()),
                ..Default::default()
            });
            const GUARD_NAME: &[u16] = &[0];
            let hwnd = CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
                PCWSTR(GUARD_CLASS.as_ptr()),
                PCWSTR(GUARD_NAME.as_ptr()),
                WS_POPUP,
                point.x,
                point.y,
                1,
                1,
                HWND::default(),
                HMENU::default(),
                instance,
                None,
            );
            match hwnd {
                Ok(window) => {
                    let _ = SetWindowPos(
                        window,
                        HWND_TOPMOST,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                    );
                    let _ = ShowWindow(window, SW_SHOWNOACTIVATE);
                    GUARD_PIXEL.store(window.0 as isize, Ordering::Release);
                    tracing::debug!("scroll-guard pixel parked under the held cursor");
                }
                Err(error) => {
                    // A missing pixel used to hide at debug while the PTP
                    // NOLEGACY refusal hid beside it — both PTP-direct
                    // layers down with a clean journal. Warn once per
                    // process instead.
                    if !WARNED_GUARD_PIXEL.swap(true, Ordering::AcqRel) {
                        tracing::warn!(%error, "scroll-guard pixel unavailable; precision-touchpad scroll may apply locally while driving");
                    }
                }
            }
        }
    }

    /// Drag the guard pixel back under the live cursor. Parked once at
    /// suppression time, the pixel goes stale the moment a palm brush
    /// nudges the real cursor a pixel or two mid-drive — and the PTP
    /// stack translates into whatever window is under the cursor NOW,
    /// so one nudge reopens dual scroll for the rest of the drive.
    /// Called on every swallowed wheel tick (hook thread, no allocs, one
    /// syscall): the leak window closes after a single tick instead of
    /// staying open. No-op when the pixel was never parked.
    fn repark_guard_pixel(point: POINT) {
        let raw = GUARD_PIXEL.load(Ordering::Acquire);
        if raw == 0 {
            return;
        }
        unsafe {
            let _ = SetWindowPos(
                HWND(raw as *mut std::ffi::c_void),
                HWND_TOPMOST,
                point.x,
                point.y,
                0,
                0,
                SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
    }

    /// Glue the local cursor back onto the park point while driving.
    /// Swallowing a motion event stops its DELIVERY, but absolute-position
    /// devices (and any reposition the hook never sees) still move the OS
    /// cursor itself — and the PTP stack translates into whatever window
    /// is under the cursor NOW, not where the pixel was parked. Snapping
    /// back keeps cursor, pixel, and translation target glued to one
    /// pixel for the whole drive (a parked cursor that cannot wander is
    /// also the honest UX: local input is driving the peer, not here).
    /// No-op unless parked, and a no-op syscall when already home — so
    /// the common case costs one packed-integer compare. Terminates: the
    /// snap-back motion re-enters the hook already home.
    fn glue_cursor_to_park(point: POINT) {
        if !PARK_VALID.load(Ordering::Acquire) {
            return;
        }
        let packed = PARK_POINT.load(Ordering::Acquire);
        let park = POINT {
            x: packed as u32 as i32,
            y: (packed >> 32) as u32 as i32,
        };
        if point.x == park.x && point.y == park.y {
            return;
        }
        unsafe {
            let _ = SetCursorPos(park.x, park.y);
        }
    }

    fn create_raw_input_window(module: HINSTANCE) -> Result<HWND, String> {
        // A message-only window has no visible UI and can receive RIDEV_INPUTSINK
        // messages even while another application owns the foreground window.
        const CLASS_NAME: &[u16] = &[
            'T' as u16, 'h' as u16, 'e' as u16, 'K' as u16, 'v' as u16, 'm' as u16, 'R' as u16,
            'a' as u16, 'w' as u16, 'I' as u16, 'n' as u16, 'p' as u16, 'u' as u16, 't' as u16, 0,
        ];
        const WINDOW_NAME: &[u16] = &[0];

        let class = WNDCLASSW {
            lpfnWndProc: Some(raw_input_window_proc),
            hInstance: module,
            lpszClassName: PCWSTR(CLASS_NAME.as_ptr()),
            ..Default::default()
        };
        unsafe {
            // RegisterClassW returns zero if the class is already registered;
            // CreateWindowExW below is the authoritative success check. This
            // also permits capture to be recreated in the same process.
            let _ = RegisterClassW(&class);
            let window = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(CLASS_NAME.as_ptr()),
                PCWSTR(WINDOW_NAME.as_ptr()),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                HMENU::default(),
                module,
                None,
            )
            .map_err(|error| format!("CreateWindowExW for Raw Input failed: {error}"))?;
            let device = RAWINPUTDEVICE {
                usUsagePage: 0x01,
                usUsage: 0x02,
                dwFlags: RIDEV_INPUTSINK,
                hwndTarget: window,
            };
            if let Err(error) = RegisterRawInputDevices(
                std::slice::from_ref(&device),
                std::mem::size_of::<RAWINPUTDEVICE>() as u32,
            ) {
                let _ = DestroyWindow(window);
                return Err(format!("RegisterRawInputDevices failed: {error}"));
            }
            // Precision-touchpad digitizer tap (best-effort, logged): the
            // third wheel source for gestures the mouse channel never sees.
            // A missing touchpad is normal (desktops); failure here must
            // never fail capture startup.
            ptp_subscribe(window);
            Ok(window)
        }
    }

    unsafe extern "system" fn raw_input_window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if message == WM_INPUT {
            handle_raw_input(lparam);
        }
        DefWindowProcW(hwnd, message, wparam, lparam)
    }

    unsafe fn handle_raw_input(lparam: LPARAM) {
        let raw_input = HRAWINPUT(lparam.0 as *mut std::ffi::c_void);
        let header_size = std::mem::size_of::<RAWINPUTHEADER>() as u32;
        let mut size = 0u32;
        let result = GetRawInputData(raw_input, RID_INPUT, None, &mut size, header_size);
        const MAX_RAW_INPUT_BYTES: usize = 64 * 1024;
        if result == u32::MAX || size == 0 || size as usize > MAX_RAW_INPUT_BYTES {
            return;
        }

        let mut buffer = vec![0u8; size as usize];
        let result = GetRawInputData(
            raw_input,
            RID_INPUT,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            &mut size,
            header_size,
        );
        if result == u32::MAX || result as usize > buffer.len() {
            return;
        }
        // Precision-touchpad digitizer reports (HID, not mouse): route to
        // the PTP scroll channel before the mouse decoders (which reject
        // non-mouse types anyway).
        if buffer.len() >= std::mem::size_of::<RAWINPUTHEADER>() {
            let header = std::ptr::read_unaligned(buffer.as_ptr() as *const RAWINPUTHEADER);
            if header.dwType == RIM_TYPEHID.0 {
                handle_ptp_input(&buffer[..result as usize]);
                return;
            }
        }
        if let Some((dx, dy)) = decode_raw_mouse_motion(&buffer[..result as usize]) {
            RAW_MOVE.fetch_add(1, Ordering::Relaxed);
            send(InputEvent::MouseMove { dx, dy });
        }
        // HID wheel channel (the trackpad fix): precision touchpads report
        // two-finger scroll in the raw HID report (RI_MOUSE_WHEEL), and some
        // drivers never synthesize a hook-visible WM_MOUSEWHEEL for it — the
        // hook then records zero scroll while Windows apps scroll, exactly
        // the reported symptom. Read the raw wheel bits too; the dedup
        // below keeps dual-delivery hardware to a single event.
        let (wheel_x, wheel_y) = decode_raw_mouse_wheel(&buffer[..result as usize]);
        if wheel_x != 0 || wheel_y != 0 {
            let now = std::time::Instant::now();
            let (x, y) = wheel_dedup().filter_raw(wheel_x, wheel_y, now);
            if x != 0 || y != 0 {
                RAW_WHEEL.fetch_add(1, Ordering::Relaxed);
                send(InputEvent::SmoothWheel { x, y });
            }
        }
    }

    fn decode_raw_mouse_motion(data: &[u8]) -> Option<(i32, i32)> {
        let header_size = std::mem::size_of::<RAWINPUTHEADER>();
        let mouse_size = std::mem::size_of::<RAWMOUSE>();
        if data.len() < header_size + mouse_size {
            return None;
        }
        // GetRawInputData writes a native RAWINPUT layout. The Vec<u8> used as
        // its buffer is only byte-aligned, so read_unaligned avoids imposing a
        // stronger alignment requirement on the OS-provided bytes.
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RAWINPUTHEADER) };
        if header.dwType != RIM_TYPEMOUSE.0 {
            return None;
        }
        // NOTE (0.8.1): a NULL device handle does NOT mean synthesized
        // input. Live-traced on real hardware: every raw motion packet from
        // a built-in precision trackpad arrives handle-less, so skipping
        // them drops 100% of motion and kills all crossing. Accept all raw
        // motion exactly like 0.7 did. Echo protection for our own SendInput
        // stays on the hook path (magic echo tag) and on Mint's X11 backend
        // (injector device-name filter); raw motion has no tag channel, and
        // the simultaneous-both-drive loop it could feed is far rarer than
        // a trackpad that must work.
        static ACCEPTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let accepted = ACCEPTED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        if accepted % 500 == 1 {
            tracing::debug!(accepted, "raw motion accepted from physical devices");
        }
        let mouse =
            unsafe { std::ptr::read_unaligned(data.as_ptr().add(header_size) as *const RAWMOUSE) };
        if mouse.usFlags.0 & MOUSE_MOVE_ABSOLUTE.0 != 0 {
            return None;
        }
        (mouse.lLastX != 0 || mouse.lLastY != 0).then_some((mouse.lLastX, mouse.lLastY))
    }

    /// Wheel bits of one raw mouse report, in WHEEL_DELTA 120ths
    /// `(x, y)`. Zero when the report carries no wheel data. Absolute
    /// motion mode does not affect the wheel channel.
    fn decode_raw_mouse_wheel(data: &[u8]) -> (i32, i32) {
        use windows::Win32::UI::WindowsAndMessaging::{RI_MOUSE_HWHEEL, RI_MOUSE_WHEEL};

        let header_size = std::mem::size_of::<RAWINPUTHEADER>();
        let mouse_size = std::mem::size_of::<RAWMOUSE>();
        if data.len() < header_size + mouse_size {
            return (0, 0);
        }
        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const RAWINPUTHEADER) };
        if header.dwType != RIM_TYPEMOUSE.0 {
            return (0, 0);
        }
        let mouse =
            unsafe { std::ptr::read_unaligned(data.as_ptr().add(header_size) as *const RAWMOUSE) };
        // Same unaligned discipline as the motion decoder above.
        let (button_flags, button_data) = unsafe {
            (
                mouse.Anonymous.Anonymous.usButtonFlags,
                mouse.Anonymous.Anonymous.usButtonData,
            )
        };
        let delta = button_data as i16 as i32;
        let flags = u32::from(button_flags);
        let mut x = 0;
        let mut y = 0;
        if flags & RI_MOUSE_WHEEL != 0 {
            y = delta;
        }
        if flags & RI_MOUSE_HWHEEL != 0 {
            x = delta;
        }
        (x, y)
    }

    /// One hook thread owns every wheel receipt, so a plain mutex is
    /// plenty: it serializes the hook proc and the raw window proc.
    fn wheel_dedup() -> std::sync::MutexGuard<'static, WheelDedup> {
        use std::sync::Mutex;

        static DEDUP: Mutex<WheelDedup> = Mutex::new(WheelDedup::new());
        DEDUP
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Our own SendInput echo stays suppressible for this long after the
    /// tagged hook receipt (the raw channel carries no tag of its own).
    const WHEEL_ECHO_WINDOW_MS: u128 = 30;
    /// Same physical tick seen on both channels lands inside this window.
    const WHEEL_DEDUP_WINDOW_MS: u128 = 20;

    /// Cross-source wheel dedup + own-echo oracle. Pure apart from the
    /// clock the caller passes in, so the windows are unit-tested.
    #[derive(Debug, Default)]
    struct WheelDedup {
        last_hook: Option<(std::time::Instant, i8, i8)>,
        last_raw: Option<(std::time::Instant, i8, i8)>,
        last_own: Option<std::time::Instant>,
    }

    impl WheelDedup {
        const fn new() -> Self {
            Self {
                last_hook: None,
                last_raw: None,
                last_own: None,
            }
        }

        /// Record a hook wheel receipt; tagged ones are our own echo and
        /// only arm the echo oracle, never the dedup window.
        fn note_hook(&mut self, x: i32, y: i32, own: bool, now: std::time::Instant) {
            if own {
                self.last_own = Some(now);
                return;
            }
            self.last_hook = Some((now, x.signum() as i8, y.signum() as i8));
        }

        /// Filter a hook tick against a just-seen raw tick (same gesture,
        /// raw arrived first). Returns the surviving axes.
        fn filter_hook(&mut self, x: i32, y: i32, now: std::time::Instant) -> (i32, i32) {
            let x = if self.raw_reported(x, true, now) {
                0
            } else {
                x
            };
            let y = if self.raw_reported(y, false, now) {
                0
            } else {
                y
            };
            if x != 0 || y != 0 {
                self.last_hook = Some((now, x.signum() as i8, y.signum() as i8));
            }
            (x, y)
        }

        /// Filter a raw tick: drop our own echo, then drop per-axis the
        /// tick the hook already reported. Returns the surviving axes.
        fn filter_raw(&mut self, x: i32, y: i32, now: std::time::Instant) -> (i32, i32) {
            if let Some(own) = self.last_own {
                if now.duration_since(own).as_millis() <= WHEEL_ECHO_WINDOW_MS {
                    return (0, 0);
                }
            }
            let x = if self.hook_reported(x, true, now) {
                0
            } else {
                x
            };
            let y = if self.hook_reported(y, false, now) {
                0
            } else {
                y
            };
            if x != 0 || y != 0 {
                self.last_raw = Some((now, x.signum() as i8, y.signum() as i8));
            }
            (x, y)
        }

        fn hook_reported(&self, delta: i32, is_x: bool, now: std::time::Instant) -> bool {
            let Some((at, sx, sy)) = self.last_hook else {
                return false;
            };
            let reported = if is_x { sx } else { sy };
            delta != 0
                && reported == delta.signum() as i8
                && now.duration_since(at).as_millis() <= WHEEL_DEDUP_WINDOW_MS
        }

        fn raw_reported(&self, delta: i32, is_x: bool, now: std::time::Instant) -> bool {
            let Some((at, sx, sy)) = self.last_raw else {
                return false;
            };
            let reported = if is_x { sx } else { sy };
            delta != 0
                && reported == delta.signum() as i8
                && now.duration_since(at).as_millis() <= WHEEL_DEDUP_WINDOW_MS
        }
    }

    /// Precision-touchpad (PTP) scroll channel. Microsoft precision
    /// touchpads report two-finger scroll ONLY through the HID digitizer
    /// collection (usage page 0x0D, usage 0x05): the low-level mouse hook
    /// never fires and the mouse-usage RawInput channel carries no wheel
    /// bits, so both legacy taps read zero while local apps scroll (the
    /// OS synthesizes scroll straight into the target window). This
    /// channel subscribes to the digitizer collection and derives
    /// two-finger pan into SmoothWheel on the shared dedup path, so a
    /// gesture the driver ALSO reports as mouse wheel is still sent once.
    /// Everything here runs on the hook thread (raw window proc) and is
    /// best-effort: any failure degrades to the two legacy channels,
    /// never fatal to capture startup.
    const PTP_USAGE_PAGE: u16 = 0x0D;
    const PTP_USAGE_TOUCHPAD: u16 = 0x05;
    /// Digitizer-page contact usages (HID usage tables).
    const PTP_USAGE_TIP: u16 = 0x42;
    /// Digitizer-page finger-collection usage (MS PTP spec: every
    /// contact lives in a child collection with this usage).
    const PTP_USAGE_FINGER: u16 = 0x22;
    /// Generic-desktop axis usages.
    const PTP_USAGE_X: u16 = 0x30;
    const PTP_USAGE_Y: u16 = 0x31;
    const PTP_GENERIC_PAGE: u16 = 0x01;
    /// Full-span swipe earns this many detents: smooth enough to feel
    /// analog through the 120ths accumulator, coarse enough that sensor
    /// noise never emits. Pinch shares this scale (see ptp_subscribe): 16
    /// full-span detents (~3x calmer than the old 48) so a slight
    /// two-finger slide is a slight zoom, not a full-page leap.
    const PTP_DETENTS_PER_SPAN: i64 = 16;

    struct PtpDevice {
        /// Raw device handle as isize (HWND-style rendezvous precedent:
        /// handles cross threads here only as integers).
        handle: isize,
        /// HidD preparsed data: hook-thread-only, freed on unsubscribe.
        preparsed: windows::Win32::Devices::HumanInterfaceDevice::PHIDP_PREPARSED_DATA,
        /// RIDI-sourced preparsed blob: owns the bytes `preparsed` points
        /// into. Some exactly when the descriptor came from
        /// RIDI_PREPARSEDDATA (no device open): that memory must NOT go
        /// through HidD_FreePreparsedData, which only releases
        /// HidD_GetPreparsedData allocations.
        preparsed_blob: Option<Vec<u8>>,
        report_len: usize,
        /// Link-collection ids of the per-finger digitizer collections.
        fingers: Vec<u16>,
        units_per_detent_x: i64,
        units_per_detent_y: i64,
        /// Negate both scroll axes to match the user's local touchpad
        /// feel (see ptp_scroll_direction): the HID reports carry raw
        /// contact motion, while the felt direction depends on the
        /// Windows ScrollDirection setting.
        scroll_invert: bool,
    }

    fn ptp_device_slot() -> std::sync::MutexGuard<'static, Option<PtpDevice>> {
        static PTP_DEVICE: Mutex<Option<PtpDevice>> = Mutex::new(None);
        PTP_DEVICE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ptp_pan_slot() -> std::sync::MutexGuard<'static, PtpPan> {
        static PAN: Mutex<PtpPan> = Mutex::new(PtpPan::new());
        PAN.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ptp_pinch_slot() -> std::sync::MutexGuard<'static, PtpPinch> {
        static PINCH: Mutex<PtpPinch> = Mutex::new(PtpPinch::new());
        PINCH
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Tip-switch state for one finger collection. The MS PTP spec
    /// exposes Tip (0x42) as a digitizer-page BUTTON, so HidP_GetUsages
    /// is the correct probe: HidP_GetUsageValue only answers value
    /// caps and fails on buttons, which parsed as "no contacts" on
    /// every report and silently held ptp_scroll at zero while the
    /// channel was armed and buffers arrived. A value-style fallback
    /// covers descriptors that expose tip as a value instead.
    fn ptp_tip_down(
        preparsed: windows::Win32::Devices::HumanInterfaceDevice::PHIDP_PREPARSED_DATA,
        collection: u16,
        report: &mut [u8],
    ) -> bool {
        use windows::Win32::Devices::HumanInterfaceDevice as hid;
        let mut usages = [0u16; 16];
        let mut usage_len = usages.len() as u32;
        if unsafe {
            hid::HidP_GetUsages(
                hid::HidP_Input,
                PTP_USAGE_PAGE,
                collection,
                usages.as_mut_ptr(),
                &mut usage_len,
                preparsed,
                report,
            )
        }
        .is_ok()
            && usages
                .iter()
                .take(usage_len as usize)
                .any(|usage| *usage == PTP_USAGE_TIP)
        {
            return true;
        }
        let mut tip = 0u32;
        unsafe {
            hid::HidP_GetUsageValue(
                hid::HidP_Input,
                PTP_USAGE_PAGE,
                collection,
                PTP_USAGE_TIP,
                &mut tip,
                preparsed,
                report,
            )
        }
        .is_ok()
            && tip != 0
    }

    /// Two-finger pan → scroll accumulator. Pure apart from construction,
    /// so the gesture math is unit-tested without HID hardware.
    #[derive(Debug)]
    struct PtpPan {
        prev: Option<(i64, i64)>,
        acc_x: i64,
        acc_y: i64,
        units_per_detent_x: i64,
        units_per_detent_y: i64,
    }

    impl PtpPan {
        const fn new() -> Self {
            Self {
                prev: None,
                acc_x: 0,
                acc_y: 0,
                units_per_detent_x: 64,
                units_per_detent_y: 64,
            }
        }

        /// Feed one report's down-contact positions (logical sensor
        /// units). Returns scroll in WHEEL_DELTA 120ths. Only a steady
        /// two-contact pan scrolls; contact-count changes reset the
        /// anchor and the remainder so lifts never jump.
        fn feed(&mut self, contacts: &[(i32, i32)]) -> (i32, i32) {
            if contacts.len() != 2 {
                self.prev = None;
                self.acc_x = 0;
                self.acc_y = 0;
                return (0, 0);
            }
            let avg = (
                (i64::from(contacts[0].0) + i64::from(contacts[1].0)) / 2,
                (i64::from(contacts[0].1) + i64::from(contacts[1].1)) / 2,
            );
            let Some(prev) = self.prev else {
                self.prev = Some(avg);
                return (0, 0);
            };
            self.prev = Some(avg);
            // Fingers up (sensor y falls) scrolls up (+120ths);
            // fingers right scrolls right (+120ths).
            self.acc_x += avg.0 - prev.0;
            self.acc_y += prev.1 - avg.1;
            // Smooth 120ths, not detent-quantized: one sensor unit earns
            // 120/units 120ths, so slow sub-detent motion still emits small
            // smooth steps instead of waiting for a whole detent (the steppy
            // shape). Truncation toward zero keeps both directions symmetric;
            // the sensor remainder is preserved for the next report.
            let units_x = self.units_per_detent_x.max(1);
            let units_y = self.units_per_detent_y.max(1);
            let out_x = (self.acc_x.saturating_mul(120) / units_x).clamp(-120_000, 120_000);
            let out_y = (self.acc_y.saturating_mul(120) / units_y).clamp(-120_000, 120_000);
            self.acc_x -= out_x.saturating_mul(units_x) / 120;
            self.acc_y -= out_y.saturating_mul(units_y) / 120;
            (out_x as i32, out_y as i32)
        }
    }

    /// Spread changes past this many sensor units own the gesture: below
    /// it two fingers are scrolling (pan keeps them), above it they are
    /// pinching (zoom takes over, pan stays silent for the gesture).
    /// Raised 48 -> 96 -> 128: finger wobble during a real scroll moves
    /// the spread more than the old gates assumed, so a steady vertical
    /// scroll owned a pinch, muted pan, and zoomed the peer instead of
    /// scrolling it. The common-mode guard below is the real
    /// scroll/pinch discriminator; this gate is only the second net.
    const PINCH_ENGAGE_UNITS: i64 = 128;
    /// Common-mode dominance ratio: a frame whose midpoint step exceeds
    /// the spread step by more than this factor is scrolling fingers,
    /// not pinching ones (a one-finger-anchored asymmetric pinch moves
    /// its midpoint at half the spread rate, well under this).
    const SCROLL_DOMINANCE: i64 = 2;
    /// Sub-this midpoint motion is sensor noise, never a scroll verdict.
    const SCROLL_NOISE_FLOOR: i64 = 4;
    /// Sustained scroll-dominated frames while engaged hand the gesture
    /// back to pan (the fingers went back to scrolling mid-pinch).
    const TAKEOVER_FRAMES: u32 = 8;

    /// Two-finger pinch → zoom accumulator. Pure apart from construction,
    /// so the gesture math is unit-tested without HID hardware. Fed the
    /// same per-report contacts as PtpPan: spread (manhattan finger
    /// distance — translation/rotation invariant, only spreading moves
    /// it) past the engage gate emits zoom in WHEEL_DELTA 120ths with
    /// the pan accumulator's remainder discipline. Positive = fingers
    /// spreading = zoom in (matches SmoothWheel's away-positive, so the
    /// daemon renders it as Ctrl+wheel-up).
    #[derive(Debug)]
    struct PtpPinch {
        anchor: Option<i64>,
        prev: Option<i64>,
        prev_mid: Option<(i64, i64)>,
        acc: i64,
        units_per_detent: i64,
        engaged: bool,
        scroll_streak: u32,
    }

    impl PtpPinch {
        const fn new() -> Self {
            Self {
                anchor: None,
                prev: None,
                prev_mid: None,
                acc: 0,
                // Matches the live axis scale (LogicalMax/16): a fresh tap
                // before subscribe is already calm, not 3x eager.
                units_per_detent: 192,
                engaged: false,
                scroll_streak: 0,
            }
        }

        /// Feed one report's down-contact positions. Returns zoom in
        /// 120ths plus whether a gesture just ended (fingers lifted,
        /// count changed, or scrolling took over mid-gesture after
        /// engaging — the daemon's Ctrl-release signal). Only an engaged
        /// pinch scrolls; contact-count changes reset anchor and
        /// remainder so lifts never jump.
        fn feed(&mut self, contacts: &[(i32, i32)]) -> (i32, bool) {
            if contacts.len() != 2 {
                let ended = self.engaged;
                self.anchor = None;
                self.prev = None;
                self.prev_mid = None;
                self.acc = 0;
                self.engaged = false;
                self.scroll_streak = 0;
                return (0, ended);
            }
            let spread = (i64::from(contacts[0].0) - i64::from(contacts[1].0)).abs()
                + (i64::from(contacts[0].1) - i64::from(contacts[1].1)).abs();
            let mid = (
                (i64::from(contacts[0].0) + i64::from(contacts[1].0)) / 2,
                (i64::from(contacts[0].1) + i64::from(contacts[1].1)) / 2,
            );
            let Some(anchor) = self.anchor else {
                self.anchor = Some(spread);
                self.prev = Some(spread);
                self.prev_mid = Some(mid);
                return (0, false);
            };
            let prev = self.prev.unwrap_or(spread);
            let spread_step = spread - prev;
            let (prev_x, prev_y) = self.prev_mid.unwrap_or(mid);
            let mid_step = (mid.0 - prev_x).abs() + (mid.1 - prev_y).abs();
            self.prev = Some(spread);
            self.prev_mid = Some(mid);
            // Scroll-vs-pinch arbitration: a two-finger scroll moves both
            // contacts together (large midpoint step, small spread
            // change); a pinch changes the spread around a near-still
            // midpoint. Scroll-dominated frames slide the anchor, so
            // finger wobble during a scroll can never accumulate to the
            // engage gate and mute pan.
            if mid_step >= SCROLL_NOISE_FLOOR && mid_step > spread_step.abs() * SCROLL_DOMINANCE {
                self.scroll_streak += 1;
                self.anchor = Some(spread);
                if self.engaged && self.scroll_streak >= TAKEOVER_FRAMES {
                    // The fingers went back to scrolling mid-gesture: end
                    // the pinch so pan (which kept feeding underneath)
                    // resumes without a jump, instead of holding zoom
                    // hostage until the fingers lift.
                    self.engaged = false;
                    self.scroll_streak = 0;
                    self.acc = 0;
                    return (0, true);
                }
                return (0, false);
            }
            self.scroll_streak = 0;
            if !self.engaged && (spread - anchor).abs() >= PINCH_ENGAGE_UNITS {
                self.engaged = true;
            }
            let mut zoom = 0;
            if self.engaged {
                self.acc += spread - prev;
                let units = self.units_per_detent.max(1);
                let out = (self.acc.saturating_mul(120) / units).clamp(-120_000, 120_000);
                self.acc -= out.saturating_mul(units) / 120;
                zoom = out as i32;
            }
            (zoom, false)
        }

        /// Whether the fingers currently own a pinch (pan stays silent).
        /// Hysteresis by construction: a contact-count change or a
        /// sustained scroll-takeover disengages, so borderline spread
        /// never flaps pan/zoom.
        fn engaged(&self) -> bool {
            self.engaged
        }
    }

    /// Whether two-finger scroll must be negated to match the user's
    /// local touchpad feel. The HID digitizer reports raw contact
    /// motion, but Windows renders the felt direction through the
    /// PrecisionTouchPad ScrollDirection setting: at the default (0),
    /// upwards contact motion scrolls content downward (and leftwards
    /// motion scrolls content rightwards), which is the opposite of the
    /// raw sensor mapping — forwarding it raw made cross-device scroll
    /// run backwards against the local feel. Missing/unreadable (e.g.
    /// the service profile hive) falls back to the default feel.
    /// Pure apart from the one registry read, read once per subscribe.
    fn ptp_scroll_invert() -> bool {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::ERROR_SUCCESS;
        use windows::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD};
        let subkey: Vec<u16> = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\PrecisionTouchPad\0"
            .encode_utf16()
            .collect();
        let value: Vec<u16> = "ScrollDirection\0".encode_utf16().collect();
        let mut data: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as u32;
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                PCWSTR(value.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some((&mut data as *mut u32).cast()),
                Some(&mut len),
            )
        };
        if status != ERROR_SUCCESS {
            return true;
        }
        data == 0
    }

    /// Subscribe the raw window to the precision-touchpad digitizer
    /// collection. Best-effort with a log line per outcome: desktops
    /// without a touchpad simply keep the two legacy channels.
    /// Fetch HID preparsed data straight from the raw-input device
    /// handle (RIDI_PREPARSEDDATA): no CreateFileW open involved, so
    /// drivers that deny opens (live-proven on precision touchpads:
    /// subscribe died at stage=device-open) still yield their
    /// descriptor. Returns the owned blob plus a preparsed pointer into
    /// it — the caller must keep the blob alive (PtpDevice owns it) and
    /// must never free the pointer with HidD_FreePreparsedData.
    fn ptp_preparsed_via_ridi(
        handle_value: isize,
    ) -> Option<(
        windows::Win32::Devices::HumanInterfaceDevice::PHIDP_PREPARSED_DATA,
        Vec<u8>,
    )> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::UI::Input as raw;
        let handle = HANDLE(handle_value as *mut std::ffi::c_void);
        let mut len = 0u32;
        let _ =
            unsafe { raw::GetRawInputDeviceInfoW(handle, raw::RIDI_PREPARSEDDATA, None, &mut len) };
        if len == 0 || len > 1024 * 1024 {
            return None;
        }
        let mut blob = vec![0u8; len as usize];
        let mut fetch = len;
        let got = unsafe {
            raw::GetRawInputDeviceInfoW(
                handle,
                raw::RIDI_PREPARSEDDATA,
                Some(blob.as_mut_ptr() as *mut std::ffi::c_void),
                &mut fetch,
            )
        };
        if got == 0 || fetch == 0 {
            return None;
        }
        blob.truncate(fetch as usize);
        let preparsed = windows::Win32::Devices::HumanInterfaceDevice::PHIDP_PREPARSED_DATA(
            blob.as_mut_ptr() as isize,
        );
        Some((preparsed, blob))
    }

    fn ptp_subscribe(window: HWND) {
        use windows::Win32::Devices::HumanInterfaceDevice as hid;
        use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows::Win32::Storage::FileSystem as fs;
        use windows::Win32::UI::Input as raw;

        let mut fail_stage = "ok";
        let mut preparsed_source = "ridi";
        let device = (|| -> Option<PtpDevice> {
            // 1. Find the digitizer touchpad collection among raw devices.
            let mut count = 0u32;
            let size = std::mem::size_of::<raw::RAWINPUTDEVICELIST>() as u32;
            if unsafe { raw::GetRawInputDeviceList(None, &mut count, size) } == u32::MAX
                || count == 0
            {
                fail_stage = "device-list";
                return None;
            }
            let mut list = vec![raw::RAWINPUTDEVICELIST::default(); count as usize];
            if unsafe { raw::GetRawInputDeviceList(Some(list.as_mut_ptr()), &mut count, size) }
                == u32::MAX
            {
                fail_stage = "device-list-read";
                return None;
            }
            let mut touchpad: Option<isize> = None;
            for entry in list.iter().take(count as usize) {
                if entry.dwType != raw::RIM_TYPEHID {
                    continue;
                }
                let mut info_size = std::mem::size_of::<raw::RID_DEVICE_INFO>() as u32;
                let mut info = raw::RID_DEVICE_INFO {
                    cbSize: info_size,
                    ..Default::default()
                };
                if unsafe {
                    raw::GetRawInputDeviceInfoW(
                        entry.hDevice,
                        raw::RIDI_DEVICEINFO,
                        Some(&mut info as *mut _ as *mut std::ffi::c_void),
                        &mut info_size,
                    )
                } == 0
                {
                    continue;
                }
                let hid_info = unsafe { info.Anonymous.hid };
                if hid_info.usUsagePage == PTP_USAGE_PAGE && hid_info.usUsage == PTP_USAGE_TOUCHPAD
                {
                    touchpad = Some(entry.hDevice.0 as isize);
                    break;
                }
            }
            let handle_value = touchpad.or_else(|| {
                fail_stage = "no-digitizer-collection";
                None
            })?;
            // 2. Preparsed data: RIDI first (no device open — drivers
            // routinely deny CreateFileW while RIDI answers freely),
            // falling back to the open path below. The open file handle
            // below exists ONLY to feed HidD_GetPreparsedData; it is
            // closed on every exit including success (reports arrive via
            // WM_INPUT, never via this handle).
            let mut preparsed_blob: Option<Vec<u8>> = None;
            let mut open_file: Option<windows::Win32::Foundation::HANDLE> = None;
            let preparsed = match ptp_preparsed_via_ridi(handle_value) {
                Some((parsed, blob)) => {
                    preparsed_blob = Some(blob);
                    parsed
                }
                None => {
                    preparsed_source = "open";
                    // 2b. Open the device path for preparsed-data queries. One
                    // fixed buffer: device paths are always well under this.
                    let mut name = vec![0u16; 512];
                    let mut name_len = name.len() as u32;
                    if unsafe {
                        raw::GetRawInputDeviceInfoW(
                            windows::Win32::Foundation::HANDLE(
                                handle_value as *mut std::ffi::c_void,
                            ),
                            raw::RIDI_DEVICENAME,
                            Some(name.as_mut_ptr() as *mut std::ffi::c_void),
                            &mut name_len,
                        )
                    } == 0
                        || name_len == 0
                    {
                        fail_stage = "device-name";
                        return None;
                    }
                    let handle = unsafe {
                        fs::CreateFileW(
                            windows::core::PCWSTR(name.as_ptr()),
                            (GENERIC_READ | GENERIC_WRITE).0,
                            fs::FILE_SHARE_READ | fs::FILE_SHARE_WRITE,
                            None,
                            fs::OPEN_EXISTING,
                            fs::FILE_FLAGS_AND_ATTRIBUTES(0),
                            None,
                        )
                    }
                    .ok()
                    .or_else(|| {
                        fail_stage = "device-open";
                        None
                    })?;
                    let mut parsed = hid::PHIDP_PREPARSED_DATA::default();
                    if !unsafe { hid::HidD_GetPreparsedData(handle, &mut parsed) }.as_bool() {
                        let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                        fail_stage = "preparsed-data";
                        return None;
                    }
                    open_file = Some(handle);
                    parsed
                }
            };
            // RIDI blobs are borrowed bytes, not HidD allocations: only
            // the open path's pointer may go through HidD_FreePreparsedData.
            // (The open file handle closes alongside on every exit below.)
            let free_preparsed = preparsed_blob.is_none();
            let mut close_open_file = || {
                if let Some(handle) = open_file.take() {
                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
                }
            };
            // 3. Preparsed data + caps: report length, finger collections,
            // per-axis scale from the sensor logical maximum.
            let mut caps = hid::HIDP_CAPS::default();
            if unsafe { hid::HidP_GetCaps(preparsed, &mut caps) }.is_err()
                || caps.InputReportByteLength == 0
            {
                unsafe {
                    if free_preparsed {
                        hid::HidD_FreePreparsedData(preparsed);
                    }
                }
                close_open_file();
                fail_stage = "caps";
                return None;
            }
            let node_len = caps.NumberLinkCollectionNodes as usize;
            // Finger collections, spec-first: the MS PTP spec puts every
            // contact in a digitizer-page collection with the Finger
            // usage (0x22). The old Parent==0 heuristic matched
            // whatever sat at the root (often the touchpad collection
            // itself), so TIP/X/Y lookups failed on every report and
            // two-finger scroll silently never derived — armed, zero
            // scroll, no log naming the miss. Prefer Finger-usage
            // collections; keep the root heuristic ONLY as a fallback
            // for descriptors that hide the usage, and LOG what was
            // picked either way so the next miss is one grep away.
            let mut fingers = Vec::new();
            let mut finger_usages: Vec<u16> = Vec::new();
            if node_len > 1 {
                let mut nodes = vec![hid::HIDP_LINK_COLLECTION_NODE::default(); node_len];
                let mut nodes_len = node_len as u32;
                if unsafe {
                    hid::HidP_GetLinkCollectionNodes(nodes.as_mut_ptr(), &mut nodes_len, preparsed)
                }
                .is_ok()
                {
                    let mut spec_fingers = Vec::new();
                    let mut heuristic_fingers = Vec::new();
                    for (index, node) in nodes.iter().take(nodes_len as usize).enumerate().skip(1) {
                        if node.LinkUsagePage != PTP_USAGE_PAGE {
                            continue;
                        }
                        // CollectionNumber is the node index for
                        // HidP_GetUsageValue's LinkCollection.
                        if node.LinkUsage == PTP_USAGE_FINGER {
                            spec_fingers.push((index as u16, node.LinkUsage));
                        } else if node.Parent == 0 {
                            heuristic_fingers.push((index as u16, node.LinkUsage));
                        }
                    }
                    let picked = if spec_fingers.is_empty() {
                        heuristic_fingers
                    } else {
                        spec_fingers
                    };
                    for (collection, usage) in picked.into_iter().take(10) {
                        fingers.push(collection);
                        finger_usages.push(usage);
                    }
                }
            }
            if fingers.is_empty() {
                unsafe {
                    if free_preparsed {
                        hid::HidD_FreePreparsedData(preparsed);
                    }
                }
                close_open_file();
                fail_stage = "finger-collections";
                return None;
            }
            // Value caps once (bounded by the descriptor's own count):
            // per-axis scroll scale derives from the sensor logical
            // maximum below.
            let mut value_len = caps.NumberInputValueCaps;
            let mut value_caps = vec![hid::HIDP_VALUE_CAPS::default(); value_len.min(512) as usize];
            value_len = value_caps.len() as u16;
            if unsafe {
                hid::HidP_GetValueCaps(
                    hid::HidP_Input,
                    value_caps.as_mut_ptr(),
                    &mut value_len,
                    preparsed,
                )
            }
            .is_err()
            {
                value_len = 0;
            }
            let (units_x, units_y) = ptp_axis_scale(&fingers, &value_caps[..value_len as usize]);
            // 4. Register the digitizer usage on our sink window. Observe
            // only (no NOLEGACY): touchpad delivery to local apps is
            // untouched; we only listen.
            let device_reg = RAWINPUTDEVICE {
                usUsagePage: PTP_USAGE_PAGE,
                usUsage: PTP_USAGE_TOUCHPAD,
                dwFlags: RIDEV_INPUTSINK,
                hwndTarget: window,
            };
            if unsafe {
                RegisterRawInputDevices(
                    std::slice::from_ref(&device_reg),
                    std::mem::size_of::<RAWINPUTDEVICE>() as u32,
                )
            }
            .is_err()
            {
                unsafe {
                    if free_preparsed {
                        hid::HidD_FreePreparsedData(preparsed);
                    }
                }
                close_open_file();
                fail_stage = "register-sink";
                return None;
            }
            // The open path's file handle has served its only purpose
            // (feeding HidD_GetPreparsedData); reports arrive via WM_INPUT.
            close_open_file();
            tracing::info!(
                contacts = fingers.len(),
                usages = ?finger_usages,
                preparsed_source,
                "precision-touchpad finger collections resolved"
            );
            Some(PtpDevice {
                handle: handle_value,
                preparsed,
                preparsed_blob,
                report_len: caps.InputReportByteLength as usize,
                fingers,
                units_per_detent_x: units_x,
                units_per_detent_y: units_y,
                scroll_invert: ptp_scroll_invert(),
            })
        })();
        match device {
            Some(found) => {
                let contacts = found.fingers.len();
                let scroll_invert = found.scroll_invert;
                {
                    let mut pan = ptp_pan_slot();
                    pan.units_per_detent_x = found.units_per_detent_x;
                    pan.units_per_detent_y = found.units_per_detent_y;
                    // Pinch spread moves in the same sensor units: share
                    // the axis scale (mean of both axes).
                    ptp_pinch_slot().units_per_detent =
                        (found.units_per_detent_x + found.units_per_detent_y + 1) / 2;
                }
                *ptp_device_slot() = Some(found);
                tracing::info!(
                    contacts,
                    preparsed_source,
                    scroll_invert,
                    "precision-touchpad scroll channel armed (HID digitizer tap)"
                );
            }
            None => tracing::warn!(stage = fail_stage, "precision-touchpad scroll channel unavailable; trackpad scroll falls back to legacy wheel channels"),
        }
    }

    /// Logical-maximum-derived scroll scale per finger collection axis:
    /// full sensor span earns PTP_DETENTS_PER_SPAN detents. Pure over the
    /// fetched value caps (no HID calls), so scale math stays testable.
    fn ptp_axis_scale(
        fingers: &[u16],
        value_caps: &[windows::Win32::Devices::HumanInterfaceDevice::HIDP_VALUE_CAPS],
    ) -> (i64, i64) {
        let first = fingers.first().copied().unwrap_or(0);
        let scale = |usage: u16| -> i64 {
            for caps in value_caps {
                if caps.UsagePage != PTP_GENERIC_PAGE || caps.LinkCollection != first {
                    continue;
                }
                let covers = if caps.IsRange.as_bool() {
                    let range = unsafe { caps.Anonymous.Range };
                    usage >= range.UsageMin && usage <= range.UsageMax
                } else {
                    unsafe { caps.Anonymous.NotRange }.Usage == usage
                };
                if covers && caps.LogicalMax > 0 {
                    return (i64::from(caps.LogicalMax) / PTP_DETENTS_PER_SPAN).max(1);
                }
            }
            64
        };
        (scale(PTP_USAGE_X), scale(PTP_USAGE_Y))
    }

    /// Stop listening to the digitizer collection (capture teardown).
    fn ptp_unsubscribe() {
        use windows::Win32::Devices::HumanInterfaceDevice as hid;
        let removal = RAWINPUTDEVICE {
            usUsagePage: PTP_USAGE_PAGE,
            usUsage: PTP_USAGE_TOUCHPAD,
            dwFlags: RIDEV_REMOVE,
            hwndTarget: HWND::default(),
        };
        let _ = unsafe {
            RegisterRawInputDevices(
                std::slice::from_ref(&removal),
                std::mem::size_of::<RAWINPUTDEVICE>() as u32,
            )
        };
        if let Some(previous) = ptp_device_slot().take() {
            if previous.preparsed_blob.is_none() {
                unsafe {
                    hid::HidD_FreePreparsedData(previous.preparsed);
                }
            }
        }
    }

    /// One WM_INPUT buffer already known (by header peek) to carry a HID
    /// report from our touchpad device: parse contacts, feed the pan
    /// accumulator, forward surviving scroll on the shared dedup path.
    fn handle_ptp_input(buffer: &[u8]) {
        use windows::Win32::Devices::HumanInterfaceDevice as hid;
        // Delivery-without-contacts watchdog state (see the empty-contacts
        // branch below): buffers arriving while parsing never succeeded.
        static PTP_EVER_PARSED: AtomicBool = AtomicBool::new(false);
        static PTP_EMPTY_BEFORE_PARSE: AtomicU64 = AtomicU64::new(0);
        let header_size = std::mem::size_of::<RAWINPUTHEADER>();
        if buffer.len() < header_size + 8 {
            return;
        }
        let size_hid = u32::from_le_bytes([
            buffer[header_size],
            buffer[header_size + 1],
            buffer[header_size + 2],
            buffer[header_size + 3],
        ]) as usize;
        let count = u32::from_le_bytes([
            buffer[header_size + 4],
            buffer[header_size + 5],
            buffer[header_size + 6],
            buffer[header_size + 7],
        ]) as usize;
        if !(8..=1024).contains(&size_hid) || !(1..=64).contains(&count) {
            return;
        }
        let Some(device) = ptp_device_slot().as_ref().map(|slot| {
            (
                slot.preparsed,
                slot.report_len,
                slot.fingers.clone(),
                slot.handle,
                slot.scroll_invert,
            )
        }) else {
            return;
        };
        // NOTE: the slot lock drops before parsing (HidP calls below take
        // no locks; the gesture accumulator has its own slot).
        let (preparsed, report_len, fingers, _handle, scroll_invert) = device;
        let data_at = header_size + 8;
        for index in 0..count {
            let at = data_at + index * size_hid;
            if at + size_hid > buffer.len() || size_hid < report_len {
                continue;
            }
            // Delivery proof (once per process): armed + silent meant
            // nobody could tell missing reports from failed parsing.
            // Contacts proof lands beside the parse loop below.
            static FIRST_BUFFER_SEEN: std::sync::Once = std::sync::Once::new();
            FIRST_BUFFER_SEEN.call_once(|| {
                tracing::info!("precision-touchpad first HID buffer delivered");
            });
            let report = &buffer[at..at + size_hid];
            // HidP_GetUsages (the tip-button probe below) requires a
            // mutable report buffer: one copy serves every finger
            // collection in this report.
            let mut mutable_report = report.to_vec();
            let mut contacts = Vec::with_capacity(fingers.len().min(10));
            for collection in fingers.iter().take(10) {
                if !ptp_tip_down(preparsed, *collection, &mut mutable_report) {
                    continue;
                }
                let mut x = 0u32;
                let mut y = 0u32;
                let x_ok = unsafe {
                    hid::HidP_GetUsageValue(
                        hid::HidP_Input,
                        PTP_GENERIC_PAGE,
                        *collection,
                        PTP_USAGE_X,
                        &mut x,
                        preparsed,
                        report,
                    )
                }
                .is_ok();
                let y_ok = unsafe {
                    hid::HidP_GetUsageValue(
                        hid::HidP_Input,
                        PTP_GENERIC_PAGE,
                        *collection,
                        PTP_USAGE_Y,
                        &mut y,
                        preparsed,
                        report,
                    )
                }
                .is_ok();
                if x_ok && y_ok {
                    contacts.push((x as i32, y as i32));
                }
            }
            if contacts.is_empty() {
                // All fingers lifted: reset the anchors, no scroll. The
                // pinch tap reports here too — its End releases the
                // daemon's synthetic zoom Ctrl.
                ptp_pan_slot().feed(&[]);
                let (_, pinch_ended) = ptp_pinch_slot().feed(&[]);
                if pinch_ended {
                    send(InputEvent::PinchEnd);
                }
                // Delivery-without-contacts watchdog: buffers arrive but
                // no contact ever parses (wrong collections or tip
                // probe). Fires once, only while parsing never
                // succeeded, so the next miss is one grep away instead
                // of another silent zero-scroll session.
                if !PTP_EVER_PARSED.load(Ordering::Relaxed)
                    && PTP_EMPTY_BEFORE_PARSE.fetch_add(1, Ordering::Relaxed) == 600
                {
                    tracing::warn!(
                        "precision-touchpad HID reports arrive but no contacts parse; tip/collection probe may mismatch this descriptor"
                    );
                }
                continue;
            }
            // Parse proof (once per process): buffers arrive but TIP/X/Y
            // lookups fail = wrong finger collections (the silent miss
            // that held ptp_scroll at zero while "armed").
            static FIRST_CONTACTS_SEEN: std::sync::Once = std::sync::Once::new();
            FIRST_CONTACTS_SEEN.call_once(|| {
                PTP_EVER_PARSED.store(true, Ordering::Relaxed);
                tracing::info!(
                    contacts = contacts.len(),
                    "precision-touchpad first parsed contacts"
                );
            });
            let now = std::time::Instant::now();
            // Pinch owns engaged fingers: zoom instead of scroll (the
            // pan anchor still feeds so a post-pinch scroll never jumps).
            let (zoom, pinch_ended) = ptp_pinch_slot().feed(&contacts);
            let pinching = ptp_pinch_slot().engaged();
            if zoom != 0 {
                static FIRST_PINCH: std::sync::Once = std::sync::Once::new();
                FIRST_PINCH.call_once(|| {
                    tracing::info!(
                        contacts = contacts.len(),
                        zoom,
                        "precision-touchpad first pinch report"
                    );
                });
                send(InputEvent::Pinch { delta: zoom });
            }
            if pinch_ended {
                send(InputEvent::PinchEnd);
            }
            let (x, y) = ptp_pan_slot().feed(&contacts);
            if pinching {
                continue;
            }
            // Match the local touchpad feel (see ptp_scroll_invert):
            // saturating negation is overflow-safe by construction
            // (feed clamps to +-1000 detents before scaling).
            let (x, y) = if scroll_invert {
                (x.saturating_neg(), y.saturating_neg())
            } else {
                (x, y)
            };
            if x != 0 || y != 0 {
                // First live report proves the digitizer tap delivers on
                // THIS hardware (once per process; the census counts on).
                static FIRST_REPORT: std::sync::Once = std::sync::Once::new();
                FIRST_REPORT.call_once(|| {
                    tracing::info!(
                        contacts = contacts.len(),
                        x,
                        y,
                        "precision-touchpad first scroll report"
                    );
                });
                let (fx, fy) = wheel_dedup().filter_raw(x, y, now);
                if fx != 0 || fy != 0 {
                    PTP_SCROLL.fetch_add(1, Ordering::Relaxed);
                    send(InputEvent::SmoothWheel { x: fx, y: fy });
                }
            }
        }
    }

    #[cfg(test)]
    mod raw_input_tests {
        use super::decode_raw_mouse_motion;
        use super::{decode_raw_mouse_wheel, PtpPan, PtpPinch, WheelDedup};
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::UI::Input::{
            MOUSE_MOVE_ABSOLUTE, MOUSE_STATE, RAWINPUT, RAWINPUTHEADER, RAWINPUT_0, RAWMOUSE,
            RAWMOUSE_0, RIM_TYPEMOUSE,
        };
        use windows::Win32::UI::WindowsAndMessaging::{RI_MOUSE_HWHEEL, RI_MOUSE_WHEEL};

        fn raw_mouse(flags: MOUSE_STATE, x: i32, y: i32) -> RAWINPUT {
            RAWINPUT {
                header: RAWINPUTHEADER {
                    dwType: RIM_TYPEMOUSE.0,
                    // A real physical device always presents a handle;
                    // software-synthesized input arrives handle-less.
                    hDevice: HANDLE(0x1_234 as *mut _),
                    ..Default::default()
                },
                data: RAWINPUT_0 {
                    mouse: RAWMOUSE {
                        usFlags: flags,
                        Anonymous: RAWMOUSE_0 { ulButtons: 0 },
                        lLastX: x,
                        lLastY: y,
                        ..Default::default()
                    },
                },
            }
        }

        #[test]
        fn ptp_two_fingers_up_scrolls_up() {
            let mut pan = PtpPan::new();
            pan.units_per_detent_x = 10;
            pan.units_per_detent_y = 10;
            assert_eq!(pan.feed(&[(0, 100), (0, 100)]), (0, 0));
            // Sensor y falls as fingers rise: scroll up is +120ths.
            assert_eq!(pan.feed(&[(0, 90), (0, 90)]), (0, 120));
        }

        #[test]
        fn ptp_two_fingers_right_scrolls_right() {
            let mut pan = PtpPan::new();
            pan.units_per_detent_x = 10;
            pan.units_per_detent_y = 10;
            assert_eq!(pan.feed(&[(100, 0), (100, 0)]), (0, 0));
            assert_eq!(pan.feed(&[(110, 0), (110, 0)]), (120, 0));
        }

        #[test]
        fn ptp_count_changes_reset_without_jumps() {
            let mut pan = PtpPan::new();
            assert_eq!(pan.feed(&[(0, 100), (0, 100)]), (0, 0));
            assert_eq!(pan.feed(&[(0, 0)]), (0, 0));
            // Re-touch anchors anew: no scroll from the gap.
            assert_eq!(pan.feed(&[(0, 0), (0, 0)]), (0, 0));
            assert_eq!(pan.feed(&[]), (0, 0));
        }

        #[test]
        fn ptp_sub_detent_motion_accumulates() {
            let mut pan = PtpPan::new();
            pan.units_per_detent_x = 10;
            pan.units_per_detent_y = 10;
            assert_eq!(pan.feed(&[(0, 100), (0, 100)]), (0, 0));
            // Smooth 120ths: 4 sensor units earn 48 120ths immediately
            // instead of waiting for a whole detent (the steppy shape).
            assert_eq!(pan.feed(&[(0, 96), (0, 96)]), (0, 48));
            assert_eq!(pan.feed(&[(0, 92), (0, 92)]), (0, 48));
            assert_eq!(pan.feed(&[(0, 88), (0, 88)]), (0, 48));
        }

        #[test]
        fn ptp_spread_emits_zoom_in_and_close_emits_zoom_out() {
            let mut pinch = PtpPinch::new();
            pinch.units_per_detent = 10;
            // Anchor: spread 100.
            assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
            assert!(!pinch.engaged());
            // Below the engage gate (128): still scrolling fingers.
            assert_eq!(pinch.feed(&[(0, 0), (120, 0)]), (0, false));
            assert!(!pinch.engaged());
            // Past the gate: engaged, spread change emits zoom-in (+).
            // Anchor 100, prev 120, spread 230: acc 110 => 11 detents.
            assert_eq!(pinch.feed(&[(0, 0), (230, 0)]), (1320, false));
            assert!(pinch.engaged());
            // Fingers close: zoom-out (−).
            assert_eq!(pinch.feed(&[(0, 0), (210, 0)]), (-240, false));
        }

        #[test]
        fn ptp_steady_two_finger_scroll_never_pinches() {
            let mut pinch = PtpPinch::new();
            pinch.units_per_detent = 10;
            assert_eq!(pinch.feed(&[(0, 100), (0, 100)]), (0, false));
            // Pure translation, stable spread: pan's fingers, not a pinch.
            assert_eq!(pinch.feed(&[(0, 90), (0, 90)]), (0, false));
            assert_eq!(pinch.feed(&[(0, 80), (0, 80)]), (0, false));
            assert!(!pinch.engaged());
            // Lift without engaging: no End (nothing held downstream).
            assert_eq!(pinch.feed(&[]), (0, false));
        }

        #[test]
        fn ptp_scroll_with_spread_wobble_never_pinches() {
            // Real brisk scroll: both fingers travel 25 units/frame
            // while the spread jitters ±4 and drifts +2/frame (fingers
            // never stay perfectly parallel). Common-mode dominates
            // every frame, so the anchor slides and the gate never
            // trips — without arbitration the drift alone would pass
            // 128 units by frame ~60, own a pinch, mute pan, and zoom
            // the peer instead of scrolling it.
            let mut pinch = PtpPinch::new();
            pinch.units_per_detent = 10;
            assert_eq!(pinch.feed(&[(0, 200), (100, 205)]), (0, false));
            for step in 1..70 {
                let y = 200 - step * 25;
                let jitter = if step % 2 == 0 { 4 } else { -4 };
                let x1 = 100 + step * 2 + jitter;
                let (zoom, ended) = pinch.feed(&[(0, y), (x1, y + 5)]);
                assert_eq!((zoom, ended), (0, false));
                assert!(!pinch.engaged());
            }
            assert_eq!(pinch.feed(&[]), (0, false));
        }

        #[test]
        fn ptp_scroll_takeover_ends_an_engaged_pinch() {
            // Genuine spread first: engage with a near-still midpoint.
            let mut pinch = PtpPinch::new();
            pinch.units_per_detent = 10;
            assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
            assert_eq!(pinch.feed(&[(0, 0), (240, 0)]), (1680, false));
            assert!(pinch.engaged());
            // Then the fingers go back to scrolling together: after 8
            // sustained scroll-dominated frames the pinch ends (pan kept
            // feeding underneath, so it resumes without a jump).
            for step in 1..8 {
                let y = -step * 20;
                assert_eq!(pinch.feed(&[(0, y), (240, y)]), (0, false));
                assert!(pinch.engaged());
            }
            assert_eq!(pinch.feed(&[(0, -160), (240, -160)]), (0, true));
            assert!(!pinch.engaged());
            // A later lift is silent: nothing held downstream anymore.
            assert_eq!(pinch.feed(&[]), (0, false));
        }

        #[test]
        fn ptp_lift_after_pinch_ends_the_gesture_once() {
            let mut pinch = PtpPinch::new();
            pinch.units_per_detent = 10;
            assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
            // Spread 100 -> 240: net +140 past the 128 gate with a
            // near-still midpoint, so 14 detents of zoom-in.
            assert_eq!(pinch.feed(&[(0, 0), (240, 0)]), (1680, false));
            // Lift: End exactly once, then silence.
            assert_eq!(pinch.feed(&[]), (0, true));
            assert_eq!(pinch.feed(&[]), (0, false));
            // Re-touch anchors anew: no zoom from the gap.
            assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
            assert!(!pinch.engaged());
        }

        #[test]
        fn decodes_relative_mouse_motion() {
            let raw = raw_mouse(MOUSE_STATE(0), 12, -4);
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const RAWINPUT).cast::<u8>(),
                    std::mem::size_of::<RAWINPUT>(),
                )
            };
            assert_eq!(decode_raw_mouse_motion(bytes), Some((12, -4)));
        }

        #[test]
        fn ignores_absolute_mouse_packets() {
            let raw = raw_mouse(MOUSE_MOVE_ABSOLUTE, 12, -4);
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const RAWINPUT).cast::<u8>(),
                    std::mem::size_of::<RAWINPUT>(),
                )
            };
            assert_eq!(decode_raw_mouse_motion(bytes), None);
        }

        #[test]
        fn rejects_truncated_packets() {
            assert_eq!(decode_raw_mouse_motion(&[]), None);
        }

        #[test]
        fn accepts_handle_less_motion_like_builtin_trackpads() {
            // Regression guard for 0.8.0: built-in precision trackpads
            // deliver raw motion with a NULL device handle, so handle-less
            // packets must be accepted, never dropped.
            let mut raw = raw_mouse(MOUSE_STATE(0), 12, -4);
            raw.header.hDevice = HANDLE(std::ptr::null_mut());
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&raw as *const RAWINPUT).cast::<u8>(),
                    std::mem::size_of::<RAWINPUT>(),
                )
            };
            assert_eq!(decode_raw_mouse_motion(bytes), Some((12, -4)));
        }

        fn raw_wheel(flags: u32, data: i16) -> RAWINPUT {
            let mut raw = raw_mouse(MOUSE_STATE(0), 0, 0);
            raw.data.mouse.Anonymous.Anonymous.usButtonFlags = flags as u16;
            raw.data.mouse.Anonymous.Anonymous.usButtonData = data as u16;
            raw
        }

        fn raw_bytes(raw: &RAWINPUT) -> &[u8] {
            unsafe {
                std::slice::from_raw_parts(
                    (raw as *const RAWINPUT).cast::<u8>(),
                    std::mem::size_of::<RAWINPUT>(),
                )
            }
        }

        #[test]
        fn decodes_raw_wheel_reports_in_detent_units() {
            // The HID wheel channel precision touchpads scroll through when
            // no hook-visible WM_MOUSEWHEEL exists.
            let raw = raw_wheel(RI_MOUSE_WHEEL, 120);
            assert_eq!(decode_raw_mouse_wheel(raw_bytes(&raw)), (0, 120));
            let raw = raw_wheel(RI_MOUSE_HWHEEL, -30);
            assert_eq!(decode_raw_mouse_wheel(raw_bytes(&raw)), (-30, 0));
            // Signed data survives the u16 wire field.
            let raw = raw_wheel(RI_MOUSE_WHEEL, -120);
            assert_eq!(decode_raw_mouse_wheel(raw_bytes(&raw)), (0, -120));
            // No wheel bits, no wheel — even with motion present.
            let raw = raw_mouse(MOUSE_STATE(0), 12, -4);
            assert_eq!(decode_raw_mouse_wheel(raw_bytes(&raw)), (0, 0));
            assert_eq!(decode_raw_mouse_wheel(&[]), (0, 0));
        }

        #[test]
        fn wheel_dedup_passes_single_source_traffic() {
            // One channel alone is never suppressed: only the SECOND
            // channel's copy of the same tick dies.
            let now = std::time::Instant::now();
            let mut dedup = WheelDedup::new();
            assert_eq!(dedup.filter_hook(0, 120, now), (0, 120));
            assert_eq!(
                dedup.filter_hook(0, 120, now + std::time::Duration::from_millis(5)),
                (0, 120)
            );
            let mut dedup = WheelDedup::new();
            assert_eq!(dedup.filter_raw(0, 120, now), (0, 120));
            assert_eq!(
                dedup.filter_raw(0, 120, now + std::time::Duration::from_millis(5)),
                (0, 120)
            );
        }

        #[test]
        fn wheel_dedup_drops_the_second_copy_of_one_tick() {
            // Dual-delivery hardware (hook + raw for one tick): whichever
            // arrives second with the same sign inside the window dies.
            let now = std::time::Instant::now();
            let mut dedup = WheelDedup::new();
            dedup.note_hook(0, 120, false, now);
            assert_eq!(dedup.filter_raw(0, 120, now), (0, 0));
            let mut dedup = WheelDedup::new();
            assert_eq!(dedup.filter_raw(0, 120, now), (0, 120));
            assert_eq!(dedup.filter_hook(0, 120, now), (0, 0));
            // Opposite directions are different gestures, never copies.
            let mut dedup = WheelDedup::new();
            dedup.note_hook(0, 120, false, now);
            assert_eq!(dedup.filter_raw(0, -120, now), (0, -120));
            // Outside the window the same tick is new information.
            let mut dedup = WheelDedup::new();
            dedup.note_hook(0, 120, false, now);
            let later = now + std::time::Duration::from_millis(50);
            assert_eq!(dedup.filter_raw(0, 120, later), (0, 120));
        }

        #[test]
        fn wheel_echo_oracle_drops_own_sendinput() {
            // Our injected wheel has no raw tag channel, but it always
            // crosses the hook tagged: raw wheel right after it is echo.
            let now = std::time::Instant::now();
            let mut dedup = WheelDedup::new();
            dedup.note_hook(0, 120, true, now);
            assert_eq!(dedup.filter_raw(0, 120, now), (0, 0));
            // Genuine user scroll after the echo window passes through.
            let later = now + std::time::Duration::from_millis(100);
            assert_eq!(dedup.filter_raw(0, -45, later), (0, -45));
        }
    }

    fn hid_from_scan_code(scan_code: u16, extended: bool) -> Option<u16> {
        if extended {
            return Some(match scan_code {
                0x1c => 0x58,
                0x1d => 0xe4,
                0x35 => 0x54,
                0x37 => 0x46,
                0x38 => 0xe6,
                0x47 => 0x4a,
                0x48 => 0x52,
                0x49 => 0x4b,
                0x4b => 0x50,
                0x4d => 0x4f,
                0x4f => 0x4d,
                0x50 => 0x51,
                0x51 => 0x4e,
                0x52 => 0x49,
                0x53 => 0x4c,
                0x5b => 0xe3,
                0x5c => 0xe7,
                0x5d => 0x65,
                _ => return None,
            });
        }
        Some(match scan_code {
            0x02 => 0x1e,
            0x03 => 0x1f,
            0x04 => 0x20,
            0x05 => 0x21,
            0x06 => 0x22,
            0x07 => 0x23,
            0x08 => 0x24,
            0x09 => 0x25,
            0x0a => 0x26,
            0x0b => 0x27,
            0x0c => 0x2d,
            0x0d => 0x2e,
            0x0e => 0x2a,
            0x0f => 0x2b,
            0x10 => 0x14,
            0x11 => 0x1a,
            0x12 => 0x08,
            0x13 => 0x15,
            0x14 => 0x17,
            0x15 => 0x1c,
            0x16 => 0x18,
            0x17 => 0x0c,
            0x18 => 0x12,
            0x19 => 0x13,
            0x1a => 0x2f,
            0x1b => 0x30,
            0x1c => 0x28,
            0x1d => 0xe0,
            0x1e => 0x04,
            0x1f => 0x16,
            0x20 => 0x07,
            0x21 => 0x09,
            0x22 => 0x0a,
            0x23 => 0x0b,
            0x24 => 0x0d,
            0x25 => 0x0e,
            0x26 => 0x0f,
            0x27 => 0x33,
            0x28 => 0x34,
            0x29 => 0x35,
            0x2a => 0xe1,
            0x2b => 0x31,
            0x2c => 0x1d,
            0x2d => 0x1b,
            0x2e => 0x06,
            0x2f => 0x19,
            0x30 => 0x05,
            0x31 => 0x11,
            0x32 => 0x10,
            0x33 => 0x36,
            0x34 => 0x37,
            0x35 => 0x38,
            0x36 => 0xe5,
            0x37 => 0x46,
            0x38 => 0xe2,
            0x39 => 0x2c,
            0x3a => 0x39,
            0x3b..=0x44 => 0x3a + (scan_code - 0x3b),
            0x45 => 0x53,
            0x46 => 0x47,
            0x57 => 0x44,
            0x58 => 0x45,
            _ => return None,
        })
    }

    fn hid_from_vk(vk: u16) -> Option<u16> {
        Some(match vk {
            0x41..=0x5a => 0x04 + (vk - 0x41),
            0x31..=0x39 => 0x1e + (vk - 0x31),
            0x30 => 0x27,
            0x0d => 0x28,
            0x1b => 0x29,
            0x08 => 0x2a,
            0x09 => 0x2b,
            0x20 => 0x2c,
            0xba => 0x33,
            0xde => 0x34,
            0xc0 => 0x35,
            0xdc => 0x31,
            0xbb => 0x2e,
            0xbd => 0x2d,
            0xbc => 0x36,
            0xbe => 0x37,
            0xbf => 0x38,
            0x14 => 0x39,
            0x13 => 0x48,
            0x90 => 0x53,
            0x2c => 0x46,
            0x60 => 0x62,
            0x61..=0x69 => 0x59 + (vk - 0x61),
            0x6a => 0x55,
            0x6b => 0x57,
            0x6d => 0x56,
            0x6e => 0x63,
            0x6f => 0x54,
            0x70..=0x7b => 0x3a + (vk - 0x70),
            0x7c..=0x87 => 0x68 + (vk - 0x7c),
            0x25 => 0x50,
            0x26 => 0x52,
            0x27 => 0x4f,
            0x28 => 0x51,
            0xa0 => 0xe1,
            0xa1 => 0xe5,
            0xa2 => 0xe0,
            0xa3 => 0xe4,
            0xa4 => 0xe2,
            0xa5 => 0xe6,
            0x5b => 0xe3,
            0x5c => 0xe7,
            0x5d => 0x65,
            // F-row media keys: captured as virtual keys (they carry no
            // useful scan code) and injected back as VK on the peer — the
            // VK -> HID -> VK round trip mirrors key_virtual_key.
            0xAD => 0x7f, // VK_VOLUME_MUTE
            0xAE => 0x81, // VK_VOLUME_DOWN
            0xAF => 0x80, // VK_VOLUME_UP
            _ => return None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::{hid_from_scan_code, hid_from_vk};

        #[test]
        fn distinguishes_keypad_enter_and_numeric_keypad_vk_codes() {
            assert_eq!(hid_from_scan_code(0x1c, true), Some(0x58));
            assert_eq!(hid_from_scan_code(0x35, true), Some(0x54));
            assert_eq!(hid_from_scan_code(0x37, false), Some(0x46)); // print screen
            assert_eq!(hid_from_vk(0x61), Some(0x59)); // keypad 1
            assert_eq!(hid_from_vk(0x60), Some(0x62)); // keypad 0
            assert_eq!(hid_from_vk(0x6a), Some(0x55)); // keypad multiply
            assert_eq!(hid_from_vk(0x87), Some(0x73)); // F24
            assert_eq!(hid_from_vk(0x5d), Some(0x65)); // application
        }

        #[test]
        fn full_letter_rows_and_win_keys_decode_exactly() {
            // (Set 1 scan code, USB HID usage, key) — extended flag matters
            // for the Win keys.
            let pairs: &[(u16, u16, &str)] = &[
                (0x1e, 0x04, "A"),
                (0x30, 0x05, "B"),
                (0x2e, 0x06, "C"),
                (0x20, 0x07, "D"),
                (0x12, 0x08, "E"),
                (0x21, 0x09, "F"),
                (0x22, 0x0a, "G"),
                (0x23, 0x0b, "H"),
                (0x17, 0x0c, "I"),
                (0x24, 0x0d, "J"),
                (0x25, 0x0e, "K"),
                (0x26, 0x0f, "L"),
                (0x32, 0x10, "M"),
                (0x31, 0x11, "N"),
                (0x18, 0x12, "O"),
                (0x19, 0x13, "P"),
                (0x10, 0x14, "Q"),
                (0x13, 0x15, "R"),
                (0x1f, 0x16, "S"),
                (0x14, 0x17, "T"),
                (0x16, 0x18, "U"),
                (0x2f, 0x19, "V"),
                (0x11, 0x1a, "W"),
                (0x2d, 0x1b, "X"),
                (0x15, 0x1c, "Y"),
                (0x2c, 0x1d, "Z"),
                (0x02, 0x1e, "1"),
                (0x0b, 0x27, "0"),
                (0x39, 0x2c, "Space"),
                (0x46, 0x47, "ScrollLock"),
                (0x1d, 0xe0, "LCtrl"),
                (0x2a, 0xe1, "LShift"),
                (0x38, 0xe2, "LAlt"),
            ];
            for (scan, usage, name) in pairs {
                assert_eq!(hid_from_scan_code(*scan, false), Some(*usage), "key {name}");
            }
            assert_eq!(hid_from_scan_code(0x5b, true), Some(0xe3)); // LWin
            assert_eq!(hid_from_scan_code(0x5c, true), Some(0xe7)); // RWin
            assert_eq!(hid_from_scan_code(0x1d, true), Some(0xe4)); // RCtrl
            assert_eq!(hid_from_scan_code(0x38, true), Some(0xe6)); // RAlt
            assert_eq!(hid_from_vk(0x5b), Some(0xe3)); // LWin fallback
            assert_eq!(hid_from_vk(0x5c), Some(0xe7)); // RWin fallback
                                                       // F-row media keys (round trip with key_virtual_key).
            assert_eq!(hid_from_vk(0xAD), Some(0x7f)); // mute
            assert_eq!(hid_from_vk(0xAF), Some(0x80)); // volume up
            assert_eq!(hid_from_vk(0xAE), Some(0x81)); // volume down
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
pub use null_backend::NullCapture as DefaultCapture;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
mod null_backend {
    use super::{CaptureBackend, InputEvent, PlatformError};

    pub struct NullCapture;

    impl NullCapture {
        pub fn create() -> Result<Self, PlatformError> {
            Ok(Self)
        }
    }

    impl CaptureBackend for NullCapture {
        fn next_event(
            &mut self,
            stop: &AtomicBool,
            _exclusive: &AtomicBool,
            _release: &AtomicBool,
        ) -> Result<InputEvent, PlatformError> {
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(PlatformError::Capture(
                "no capture backend for this OS".into(),
            ))
        }
    }
}
