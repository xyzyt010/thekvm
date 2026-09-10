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
    use windows::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
    };

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
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;

    let (connection, screen) = x11rb::connect(None).map_err(|error| {
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::sync::{Mutex, OnceLock};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::Threading::GetCurrentThreadId;
    use windows::Win32::UI::Input::{
        GetRawInputData, RegisterRawInputDevices, HRAWINPUT, MOUSE_MOVE_ABSOLUTE, RAWINPUTDEVICE,
        RAWINPUTHEADER, RAWMOUSE, RIDEV_INPUTSINK, RIDEV_REMOVE, RID_INPUT, RIM_TYPEMOUSE,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
        GetMessageW, PeekMessageW, PostThreadMessageW, RegisterClassW, SetWindowsHookExW,
        TranslateMessage, UnhookWindowsHookEx, HC_ACTION, HMENU, HWND_MESSAGE, KBDLLHOOKSTRUCT,
        MSG, MSLLHOOKSTRUCT, PM_NOREMOVE, WH_KEYBOARD_LL, WH_MOUSE_LL, WINDOW_EX_STYLE,
        WINDOW_STYLE, WM_INPUT, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN,
        WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_QUIT, WM_RBUTTONDOWN,
        WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WM_XBUTTONDOWN, WM_XBUTTONUP, WNDCLASSW,
        XBUTTON1, XBUTTON2,
    };

    static SENDER: OnceLock<Mutex<Option<Sender<InputEvent>>>> = OnceLock::new();
    static LAST_POINT: OnceLock<Mutex<Option<POINT>>> = OnceLock::new();
    static BLOCK_LOCAL: AtomicBool = AtomicBool::new(false);
    static RAW_INPUT_ACTIVE: AtomicBool = AtomicBool::new(false);

    pub(super) fn set_exclusive(exclusive: bool) {
        BLOCK_LOCAL.store(exclusive, Ordering::Release);
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
        let _ = ready.send(Ok(thread_id));

        let mut message = MSG::default();
        loop {
            let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
            if result.0 <= 0 {
                break;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        unsafe {
            let _ = UnhookWindowsHookEx(keyboard);
            let _ = UnhookWindowsHookEx(mouse);
            if let Some(window) = raw_input_window {
                RAW_INPUT_ACTIVE.store(false, Ordering::Release);
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
            // check swallowed those.
            if info.dwExtraInfo != crate::ECHO_TAG {
                let message = wparam.0 as u32;
                let pressed = matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN);
                if pressed || matches!(message, WM_KEYUP | WM_SYSKEYUP) {
                    let usage = hid_from_scan_code(info.scanCode as u16, info.flags.0 & 0x01 != 0)
                        .or_else(|| hid_from_vk(info.vkCode as u16));
                    if let Some(usage) = usage {
                        send(InputEvent::Key(KeyEvent { usage, pressed }));
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                }
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
                let own_message = wparam.0 as u32;
                let now = std::time::Instant::now();
                match own_message {
                    WM_MOUSEWHEEL => wheel_dedup().note_hook(
                        0,
                        (info.mouseData >> 16) as i16 as i32,
                        true,
                        now,
                    ),
                    WM_MOUSEHWHEEL => wheel_dedup().note_hook(
                        (info.mouseData >> 16) as i16 as i32,
                        0,
                        true,
                        now,
                    ),
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
                                    send(InputEvent::MouseMove { dx, dy });
                                }
                            }
                            *guard = Some(point);
                            if BLOCK_LOCAL.load(Ordering::Acquire) {
                                return LRESULT(1);
                            }
                        }
                    }
                    WM_LBUTTONDOWN | WM_LBUTTONUP => {
                        send(InputEvent::MouseButton {
                            button: MouseButton::Left,
                            pressed: message == WM_LBUTTONDOWN,
                        });
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_RBUTTONDOWN | WM_RBUTTONUP => {
                        send(InputEvent::MouseButton {
                            button: MouseButton::Right,
                            pressed: message == WM_RBUTTONDOWN,
                        });
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_MBUTTONDOWN | WM_MBUTTONUP => {
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
                        let (_, y) = wheel_dedup().filter_hook(
                            0,
                            (info.mouseData >> 16) as i16 as i32,
                            now,
                        );
                        if y != 0 {
                            send(InputEvent::SmoothWheel { x: 0, y });
                        }
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    WM_MOUSEHWHEEL => {
                        let now = std::time::Instant::now();
                        let (x, _) = wheel_dedup().filter_hook(
                            (info.mouseData >> 16) as i16 as i32,
                            0,
                            now,
                        );
                        if x != 0 {
                            send(InputEvent::SmoothWheel { x, y: 0 });
                        }
                        if BLOCK_LOCAL.load(Ordering::Acquire) {
                            return LRESULT(1);
                        }
                    }
                    _ => {}
                }
            }
        }
        CallNextHookEx(None, code, wparam, lparam)
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
        if let Some((dx, dy)) = decode_raw_mouse_motion(&buffer[..result as usize]) {
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
        let (button_flags, button_data) =
            unsafe { (mouse.Anonymous.Anonymous.usButtonFlags, mouse.Anonymous.Anonymous.usButtonData) };
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
        DEDUP.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
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
            let x = if self.raw_reported(x, true, now) { 0 } else { x };
            let y = if self.raw_reported(y, false, now) { 0 } else { y };
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
            let x = if self.hook_reported(x, true, now) { 0 } else { x };
            let y = if self.hook_reported(y, false, now) { 0 } else { y };
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

    #[cfg(test)]
    mod raw_input_tests {
        use super::decode_raw_mouse_motion;
        use super::{decode_raw_mouse_wheel, WheelDedup};
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
            unsafe {
                raw.data.mouse.Anonymous.Anonymous.usButtonFlags = flags as u16;
                raw.data.mouse.Anonymous.Anonymous.usButtonData = data as u16;
            }
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
                (0x1e, 0x04, "A"), (0x30, 0x05, "B"), (0x2e, 0x06, "C"),
                (0x20, 0x07, "D"), (0x12, 0x08, "E"), (0x21, 0x09, "F"),
                (0x22, 0x0a, "G"), (0x23, 0x0b, "H"), (0x17, 0x0c, "I"),
                (0x24, 0x0d, "J"), (0x25, 0x0e, "K"), (0x26, 0x0f, "L"),
                (0x32, 0x10, "M"), (0x31, 0x11, "N"), (0x18, 0x12, "O"),
                (0x19, 0x13, "P"), (0x10, 0x14, "Q"), (0x13, 0x15, "R"),
                (0x1f, 0x16, "S"), (0x14, 0x17, "T"), (0x16, 0x18, "U"),
                (0x2f, 0x19, "V"), (0x11, 0x1a, "W"), (0x2d, 0x1b, "X"),
                (0x15, 0x1c, "Y"), (0x2c, 0x1d, "Z"),
                (0x02, 0x1e, "1"), (0x0b, 0x27, "0"),
                (0x39, 0x2c, "Space"), (0x46, 0x47, "ScrollLock"),
                (0x1d, 0xe0, "LCtrl"), (0x2a, 0xe1, "LShift"),
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
