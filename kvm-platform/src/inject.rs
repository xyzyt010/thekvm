//! Native input injection backends.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod linux_uinput {
    #[cfg(target_os = "freebsd")]
    type IoctlRequest = libc::c_ulong;
    #[cfg(not(target_os = "freebsd"))]
    type IoctlRequest = libc::Ioctl;

    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use crate::PlatformError;
    use kvm_core::{HidUsage, InputEvent, KeyEvent, MouseButton};

    const EV_SYN: u16 = 0x00;
    const EV_KEY: u16 = 0x01;
    const EV_REL: u16 = 0x02;
    const SYN_REPORT: i32 = 0;
    const REL_X: u16 = 0x00;
    const REL_Y: u16 = 0x01;
    const REL_HWHEEL: u16 = 0x06;
    const REL_WHEEL: u16 = 0x08;
    const REL_WHEEL_HI_RES: u16 = 0x0b;
    const REL_HWHEEL_HI_RES: u16 = 0x0c;
    const BTN_LEFT: u16 = 0x110;
    const BTN_RIGHT: u16 = 0x111;
    const BTN_MIDDLE: u16 = 0x112;
    const BTN_SIDE: u16 = 0x113;
    const BTN_EXTRA: u16 = 0x114;

    const UI_SET_EVBIT: IoctlRequest = 0x4004_5564;
    const UI_SET_KEYBIT: IoctlRequest = 0x4004_5565;
    const UI_SET_RELBIT: IoctlRequest = 0x4004_5566;
    const UI_DEV_SETUP: IoctlRequest = 0x405c_5503;
    const UI_DEV_CREATE: IoctlRequest = 0x5501;
    const UI_DEV_DESTROY: IoctlRequest = 0x5502;

    fn ioctl_value(file: &File, request: IoctlRequest, value: i32) -> Result<(), PlatformError> {
        let result = unsafe { libc::ioctl(file.as_raw_fd(), request, value) };
        if result < 0 {
            return Err(PlatformError::Uinput(format!(
                "ioctl {request:#x}({value}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn ioctl_ptr(
        file: &File,
        request: IoctlRequest,
        value: *const libc::c_void,
    ) -> Result<(), PlatformError> {
        let result = unsafe { libc::ioctl(file.as_raw_fd(), request, value) };
        if result < 0 {
            return Err(PlatformError::Uinput(format!(
                "ioctl {request:#x} failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// `struct uinput_setup`: input_id (8 bytes), name[80], ff_effects_max.
    fn setup_bytes(name: &str) -> [u8; 92] {
        let mut bytes = [0u8; 92];
        bytes[0..2].copy_from_slice(&0x03u16.to_ne_bytes()); // BUS_USB
        bytes[2..4].copy_from_slice(&0x1u16.to_ne_bytes());
        bytes[4..6].copy_from_slice(&0x1u16.to_ne_bytes());
        bytes[6..8].copy_from_slice(&0x1u16.to_ne_bytes());
        let name = name.as_bytes();
        let length = name.len().min(79);
        bytes[8..8 + length].copy_from_slice(&name[..length]);
        bytes
    }

    fn event_bytes(event_type: u16, code: u16, value: i32) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[16..18].copy_from_slice(&event_type.to_ne_bytes());
        bytes[18..20].copy_from_slice(&code.to_ne_bytes());
        bytes[20..24].copy_from_slice(&value.to_ne_bytes());
        bytes
    }

    pub struct UinputDevice {
        mouse: File,
        keyboard: File,
        pressed_keys: BTreeSet<u16>,
        pressed_buttons: BTreeSet<u16>,
        mouse_created: bool,
        keyboard_created: bool,
        /// Banked 120ths per scroll axis for the legacy detent axis: a
        /// hi-res-only stack scrolls from HI_RES alone, but a legacy-only
        /// stack (no HI_RES support) would see nothing but zeroes for
        /// sub-detent touchpad motion — the debt turns it into whole
        /// detents instead of dropping it.
        wheel_debt_x: i32,
        wheel_debt_y: i32,
    }

    impl UinputDevice {
        pub fn create() -> Result<Self, PlatformError> {
            let open = || {
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/uinput")
                    .map_err(|e| PlatformError::Uinput(format!("open /dev/uinput: {e}")))
            };
            let mouse = open()?;
            let keyboard = open()?;

            for event_type in [EV_KEY, EV_REL, EV_SYN] {
                ioctl_value(&mouse, UI_SET_EVBIT, event_type as i32)?;
            }
            for relative in [
                REL_X,
                REL_Y,
                REL_WHEEL,
                REL_HWHEEL,
                REL_WHEEL_HI_RES,
                REL_HWHEEL_HI_RES,
            ] {
                ioctl_value(&mouse, UI_SET_RELBIT, relative as i32)?;
            }
            for button in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA] {
                ioctl_value(&mouse, UI_SET_KEYBIT, button as i32)?;
            }

            for event_type in [EV_KEY, EV_SYN] {
                ioctl_value(&keyboard, UI_SET_EVBIT, event_type as i32)?;
            }
            // Advertise the complete standard evdev key range. The actual
            // input is restricted by hid_to_evdev below.
            for code in 1..=0x2ffu16 {
                ioctl_value(&keyboard, UI_SET_KEYBIT, code as i32)?;
            }

            let mouse_setup = setup_bytes("TheKVM Virtual Mouse");
            ioctl_ptr(&mouse, UI_DEV_SETUP, mouse_setup.as_ptr().cast())?;
            let keyboard_setup = setup_bytes("TheKVM Virtual Keyboard");
            ioctl_ptr(&keyboard, UI_DEV_SETUP, keyboard_setup.as_ptr().cast())?;
            ioctl_value(&mouse, UI_DEV_CREATE, 0)?;
            let mouse_created = true;
            if let Err(error) = ioctl_value(&keyboard, UI_DEV_CREATE, 0) {
                unsafe { libc::ioctl(mouse.as_raw_fd(), UI_DEV_DESTROY) };
                return Err(error);
            }

            // udev/logind enumeration is asynchronous. This small delay makes
            // the first event reliable on greeters during early boot.
            std::thread::sleep(std::time::Duration::from_millis(50));
            Ok(Self {
                mouse,
                keyboard,
                pressed_keys: BTreeSet::new(),
                pressed_buttons: BTreeSet::new(),
                mouse_created,
                keyboard_created: true,
                wheel_debt_x: 0,
                wheel_debt_y: 0,
            })
        }

        fn emit(file: &mut File, event_type: u16, code: u16, value: i32) -> std::io::Result<()> {
            file.write_all(&event_bytes(event_type, code, value))?;
            file.write_all(&event_bytes(EV_SYN, 0, SYN_REPORT))
        }

        pub fn send(&mut self, event: InputEvent) -> Result<(), PlatformError> {
            match event {
                InputEvent::MouseMove { dx, dy } => {
                    if dx != 0 {
                        Self::emit(&mut self.mouse, EV_REL, REL_X, dx).map_err(io_error)?;
                    }
                    if dy != 0 {
                        Self::emit(&mut self.mouse, EV_REL, REL_Y, dy).map_err(io_error)?;
                    }
                }
                InputEvent::MouseButton { button, pressed } => {
                    let code = button_code(button);
                    Self::emit(&mut self.mouse, EV_KEY, code, i32::from(pressed))
                        .map_err(io_error)?;
                    if pressed {
                        self.pressed_buttons.insert(code);
                    } else {
                        self.pressed_buttons.remove(&code);
                    }
                }
                InputEvent::Wheel(delta) => {
                    // Detent wheel dual-reports legacy + hi-res, exactly like
                    // real high-resolution hardware: modern stacks (libinput)
                    // consume the hi-res axis, legacy-only stacks the detent.
                    if delta.y != 0 {
                        Self::emit(&mut self.mouse, EV_REL, REL_WHEEL, i32::from(delta.y))
                            .map_err(io_error)?;
                        Self::emit(
                            &mut self.mouse,
                            EV_REL,
                            REL_WHEEL_HI_RES,
                            i32::from(delta.y).saturating_mul(120),
                        )
                        .map_err(io_error)?;
                    }
                    if delta.x != 0 {
                        Self::emit(&mut self.mouse, EV_REL, REL_HWHEEL, i32::from(delta.x))
                            .map_err(io_error)?;
                        Self::emit(
                            &mut self.mouse,
                            EV_REL,
                            REL_HWHEEL_HI_RES,
                            i32::from(delta.x).saturating_mul(120),
                        )
                        .map_err(io_error)?;
                    }
                }
                InputEvent::SmoothWheel { x, y } => {
                    // Touchpad smooth scroll in 120ths: hi-res always, plus
                    // whole detents from the banked debt for stacks without
                    // hi-res support. Sub-detent motion reports legacy zero
                    // (no double-scroll anywhere) while hi-res carries it;
                    // slow scrolling still arrives as detents instead of
                    // vanishing. Truncation toward zero keeps both
                    // directions symmetric.
                    if y != 0 {
                        self.wheel_debt_y = self.wheel_debt_y.saturating_add(y);
                        let detents = self.wheel_debt_y / 120;
                        self.wheel_debt_y -= detents.saturating_mul(120);
                        if detents != 0 {
                            Self::emit(&mut self.mouse, EV_REL, REL_WHEEL, detents)
                                .map_err(io_error)?;
                        }
                        Self::emit(&mut self.mouse, EV_REL, REL_WHEEL_HI_RES, y)
                            .map_err(io_error)?;
                    }
                    if x != 0 {
                        self.wheel_debt_x = self.wheel_debt_x.saturating_add(x);
                        let detents = self.wheel_debt_x / 120;
                        self.wheel_debt_x -= detents.saturating_mul(120);
                        if detents != 0 {
                            Self::emit(&mut self.mouse, EV_REL, REL_HWHEEL, detents)
                                .map_err(io_error)?;
                        }
                        Self::emit(&mut self.mouse, EV_REL, REL_HWHEEL_HI_RES, x)
                            .map_err(io_error)?;
                    }
                }
                InputEvent::Key(KeyEvent { usage, pressed }) => {
                    let code = hid_to_evdev(usage).ok_or_else(|| {
                        PlatformError::Uinput(format!("unsupported HID keyboard usage: {usage:#x}"))
                    })?;
                    Self::emit(&mut self.keyboard, EV_KEY, code, i32::from(pressed))
                        .map_err(io_error)?;
                    if pressed {
                        self.pressed_keys.insert(code);
                    } else {
                        self.pressed_keys.remove(&code);
                    }
                }
            }
            Ok(())
        }

        pub fn release_all(&mut self) -> Result<(), PlatformError> {
            let keys = self.pressed_keys.iter().copied().collect::<Vec<_>>();
            for code in keys {
                Self::emit(&mut self.keyboard, EV_KEY, code, 0).map_err(io_error)?;
            }
            let buttons = self.pressed_buttons.iter().copied().collect::<Vec<_>>();
            for code in buttons {
                Self::emit(&mut self.mouse, EV_KEY, code, 0).map_err(io_error)?;
            }
            self.pressed_keys.clear();
            self.pressed_buttons.clear();
            Ok(())
        }
    }

    impl Drop for UinputDevice {
        fn drop(&mut self) {
            let _ = self.release_all();
            if self.mouse_created {
                unsafe { libc::ioctl(self.mouse.as_raw_fd(), UI_DEV_DESTROY) };
            }
            if self.keyboard_created {
                unsafe { libc::ioctl(self.keyboard.as_raw_fd(), UI_DEV_DESTROY) };
            }
        }
    }

    fn io_error(error: std::io::Error) -> PlatformError {
        PlatformError::Uinput(error.to_string())
    }

    fn button_code(button: MouseButton) -> u16 {
        match button {
            MouseButton::Left => BTN_LEFT,
            MouseButton::Right => BTN_RIGHT,
            MouseButton::Middle => BTN_MIDDLE,
            MouseButton::Back => BTN_SIDE,
            MouseButton::Forward => BTN_EXTRA,
        }
    }

    fn hid_to_evdev(usage: HidUsage) -> Option<u16> {
        // Letter rows are explicit, never arithmetic: the HID usage order
        // (QWERTYUIOP...) is not sequential, and a range formula here once
        // scrambled thirteen letters (U pressed as R, and twelve friends).
        Some(match usage {
            0x04 => 30,
            0x05 => 48,
            0x06 => 46,
            0x07 => 32,
            0x08 => 18,
            0x09 => 33,
            0x0a => 34,
            0x0b => 35,
            0x0c => 23,
            0x0d => 36,
            0x0e => 37,
            0x0f => 38,
            0x10 => 50,
            0x11 => 49,
            0x12 => 24,
            0x13 => 25,
            0x14 => 16,
            0x15 => 19,
            0x16 => 31,
            0x17 => 20,
            0x18 => 22,
            0x19 => 47,
            0x1a => 17,
            0x1b => 45,
            0x1c => 21,
            0x1d => 44,
            0x1e..=0x27 => usage - 0x1e + 2,
            0x28 => 28,
            0x29 => 1,
            0x2a => 14,
            0x2b => 15,
            0x2c => 57,
            0x2d => 12,
            0x2e => 13,
            0x2f => 26,
            0x30 => 27,
            0x31 => 43,
            0x33 => 39,
            0x34 => 40,
            0x35 => 41,
            0x36 => 51,
            0x37 => 52,
            0x38 => 53,
            0x39 => 58,
            0x3a..=0x43 => usage - 0x3a + 59,
            0x44 => 87,
            0x45 => 88,
            0x46 => 99,
            0x47 => 70,
            0x48 => 119,
            0x49 => 110,
            0x4a => 102,
            0x4b => 104,
            0x4c => 111,
            0x4d => 107,
            0x4e => 109,
            0x4f => 106,
            0x50 => 105,
            0x51 => 108,
            0x52 => 103,
            0x53 => 69,
            0x54 => 98,
            0x55 => 55,
            0x56 => 74,
            0x57 => 78,
            0x58 => 96,
            0x59..=0x5b => usage - 0x59 + 79,
            0x5c..=0x5e => usage - 0x5c + 75,
            0x5f..=0x61 => usage - 0x5f + 71,
            0x62 => 82,
            0x63 => 83,
            0x64 => 86,
            0x65 => 127,
            0x66 => 116,
            0x67 => 117,
            0x68..=0x73 => usage - 0x68 + 183,
            0x75 => 138,
            0x76 => 139,
            0x77 => 353,
            0x78 => 128,
            0x79 => 129,
            0x7a => 131,
            0x7b => 137,
            0x7c => 133,
            0x7d => 135,
            0x7e => 136,
            0x7f => 113,
            0x80 => 115,
            0x81 => 114,
            0x82 => 58,
            0x83 => 69,
            0x84 => 70,
            0x85 => 121,
            0x86 => 117,
            0xe0 => 29,
            0xe1 => 42,
            0xe2 => 56,
            0xe3 => 125,
            0xe4 => 97,
            0xe5 => 54,
            0xe6 => 100,
            0xe7 => 126,
            _ => return None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::hid_to_evdev;

        #[test]
        fn preserves_non_linear_linux_keypad_codes() {
            assert_eq!(hid_to_evdev(0x59), Some(79)); // keypad 1
            assert_eq!(hid_to_evdev(0x5c), Some(75)); // keypad 4
            assert_eq!(hid_to_evdev(0x5f), Some(71)); // keypad 7
            assert_eq!(hid_to_evdev(0x62), Some(82)); // keypad 0
        }

        #[test]
        fn full_letter_rows_map_to_evdev_exactly() {
            // (USB HID usage, evdev code, key). Every letter, exact —
            // regressions here type the wrong letter on the peer.
            let pairs: &[(u16, u16, &str)] = &[
                (0x04, 30, "A"), (0x05, 48, "B"), (0x06, 46, "C"),
                (0x07, 32, "D"), (0x08, 18, "E"), (0x09, 33, "F"),
                (0x0a, 34, "G"), (0x0b, 35, "H"), (0x0c, 23, "I"),
                (0x0d, 36, "J"), (0x0e, 37, "K"), (0x0f, 38, "L"),
                (0x10, 50, "M"), (0x11, 49, "N"), (0x12, 24, "O"),
                (0x13, 25, "P"), (0x14, 16, "Q"), (0x15, 19, "R"),
                (0x16, 31, "S"), (0x17, 20, "T"), (0x18, 22, "U"),
                (0x19, 47, "V"), (0x1a, 17, "W"), (0x1b, 45, "X"),
                (0x1c, 21, "Y"), (0x1d, 44, "Z"),
            ];
            for (usage, evdev, name) in pairs {
                assert_eq!(hid_to_evdev(*usage), Some(*evdev), "letter {name}");
            }
        }

        #[test]
        fn digits_modifiers_and_win_keys_map_exactly() {
            let pairs: &[(u16, u16, &str)] = &[
                (0x1e, 2, "1"), (0x1f, 3, "2"), (0x20, 4, "3"),
                (0x21, 5, "4"), (0x22, 6, "5"), (0x23, 7, "6"),
                (0x24, 8, "7"), (0x25, 9, "8"), (0x26, 10, "9"),
                (0x27, 11, "0"),
                (0x2c, 57, "Space"), (0x28, 28, "Enter"),
                (0x29, 1, "Esc"), (0x2b, 15, "Tab"),
                (0x2a, 14, "Backspace"),
                (0xe0, 29, "LCtrl"), (0xe1, 42, "LShift"),
                (0xe2, 56, "LAlt"), (0xe3, 125, "LWin"),
                (0xe4, 97, "RCtrl"), (0xe5, 54, "RShift"),
                (0xe6, 100, "RAlt"), (0xe7, 126, "RWin"),
                (0x47, 70, "ScrollLock"), (0x39, 58, "CapsLock"),
                (0x53, 69, "NumLock"),
                (0x4a, 102, "Home"), (0x52, 103, "Up"),
                (0x4b, 104, "PgUp"), (0x50, 105, "Left"),
                (0x4f, 106, "Right"), (0x4d, 107, "End"),
                (0x51, 108, "Down"), (0x4e, 109, "PgDn"),
                (0x49, 110, "Insert"), (0x4c, 111, "Delete"),
                (0x3a, 59, "F1"), (0x43, 68, "F10"),
                (0x44, 87, "F11"), (0x45, 88, "F12"),
            ];
            for (usage, evdev, name) in pairs {
                assert_eq!(hid_to_evdev(*usage), Some(*evdev), "key {name}");
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use linux_uinput::UinputDevice as Injector;

#[cfg(target_os = "windows")]
mod win32_inject {
    use crate::PlatformError;
    use kvm_core::{InputEvent, MouseButton};
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use windows::Win32::Foundation::GetLastError;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYEVENTF_EXTENDEDKEY,
        KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
        MOUSEEVENTF_XUP, MOUSEINPUT, VIRTUAL_KEY,
    };

    pub struct Win32Injector {
        pressed_keys: Mutex<BTreeSet<u16>>,
        pressed_buttons: Mutex<BTreeSet<MouseButton>>,
    }

    impl Win32Injector {
        pub fn create() -> Result<Self, PlatformError> {
            Ok(Self {
                pressed_keys: Mutex::new(BTreeSet::new()),
                pressed_buttons: Mutex::new(BTreeSet::new()),
            })
        }

        pub fn send(&self, event: InputEvent) -> Result<(), PlatformError> {
            // Wheel events fan out to up to two INPUTs (vertical +
            // horizontal): the old code sent only one axis and dropped the
            // other, losing diagonal trackpad scroll.
            let inputs: Vec<INPUT> = match event {
                InputEvent::MouseMove { dx, dy } => vec![INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dx,
                            dy,
                            mouseData: 0,
                            dwFlags: MOUSEEVENTF_MOVE,
                            time: 0,
                            dwExtraInfo: crate::ECHO_TAG,
                        },
                    },
                }],
                InputEvent::MouseButton { button, pressed } => {
                    let (flags, mouse_data) = mouse_button_flags(button, pressed);
                    vec![INPUT {
                        r#type: INPUT_MOUSE,
                        Anonymous: INPUT_0 {
                            mi: MOUSEINPUT {
                                dx: 0,
                                dy: 0,
                                mouseData: mouse_data,
                                dwFlags: flags,
                                time: 0,
                                dwExtraInfo: crate::ECHO_TAG,
                            },
                        },
                    }]
                }
                // Detent wheel: one WHEEL_DELTA (120) per detent, both axes.
                InputEvent::Wheel(delta) => wheel_inputs(
                    delta.y as i32 * 120,
                    delta.x as i32 * 120,
                ),
                // Touchpad smooth scroll: already in 120ths, injected raw so
                // apps receive the same fine motion as local scrolling.
                InputEvent::SmoothWheel { x, y } => wheel_inputs(y, x),
                InputEvent::Key(key) => {
                    // Pause has an E1-prefixed make code that SendInput does
                    // not represent through KEYEVENTF_SCANCODE; VK_PAUSE is
                    // the documented fallback for that one key.
                    let (virtual_key, scan_code, extended) = if key.usage == 0x48 {
                        (0x13, 0, false)
                    } else {
                        let (scan_code, extended) =
                            hid_to_scan_code(key.usage).ok_or_else(|| {
                                PlatformError::Win32(format!(
                                    "unsupported USB HID keyboard usage: {:#x}",
                                    key.usage
                                ))
                            })?;
                        (0, scan_code, extended)
                    };
                    let mut flags = if scan_code == 0 {
                        Default::default()
                    } else {
                        KEYEVENTF_SCANCODE
                    };
                    if !key.pressed {
                        flags |= KEYEVENTF_KEYUP;
                    }
                    if extended {
                        flags |= KEYEVENTF_EXTENDEDKEY;
                    }
                    vec![INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wVk: VIRTUAL_KEY(virtual_key),
                                wScan: scan_code,
                                dwFlags: flags,
                                time: 0,
                                dwExtraInfo: crate::ECHO_TAG,
                            },
                        },
                    }]
                }
            };
            if inputs.is_empty() {
                return Ok(());
            }
            let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            if sent as usize != inputs.len() {
                return Err(PlatformError::Win32(format!(
                    "SendInput failed: {}",
                    unsafe { GetLastError().0 }
                )));
            }
            match event {
                InputEvent::Key(key) => {
                    if let Ok(mut pressed) = self.pressed_keys.lock() {
                        if key.pressed {
                            pressed.insert(key.usage);
                        } else {
                            pressed.remove(&key.usage);
                        }
                    }
                }
                InputEvent::MouseButton {
                    button,
                    pressed: down,
                } => {
                    if let Ok(mut pressed) = self.pressed_buttons.lock() {
                        if down {
                            pressed.insert(button);
                        } else {
                            pressed.remove(&button);
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        }

        pub fn release_all(&self) -> Result<(), PlatformError> {
            let keys = self
                .pressed_keys
                .lock()
                .map_err(|_| PlatformError::Win32("key state lock poisoned".into()))?
                .iter()
                .copied()
                .collect::<Vec<_>>();
            let buttons = self
                .pressed_buttons
                .lock()
                .map_err(|_| PlatformError::Win32("button state lock poisoned".into()))?
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for usage in keys {
                self.send(InputEvent::Key(kvm_core::KeyEvent {
                    usage,
                    pressed: false,
                }))?;
            }
            for button in buttons {
                self.send(InputEvent::MouseButton {
                    button,
                    pressed: false,
                })?;
            }
            Ok(())
        }
    }

    impl Drop for Win32Injector {
        fn drop(&mut self) {
            let _ = self.release_all();
        }
    }

    /// One INPUT per non-zero scroll axis, in 120ths (WHEEL_DELTA units).
    /// A zero axis sends nothing: a zero-amount wheel INPUT is wire noise
    /// that some apps still scroll on.
    fn wheel_inputs(vertical_120ths: i32, horizontal_120ths: i32) -> Vec<INPUT> {
        let mut inputs = Vec::with_capacity(2);
        if vertical_120ths != 0 {
            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: vertical_120ths as u32,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        time: 0,
                        dwExtraInfo: crate::ECHO_TAG,
                    },
                },
            });
        }
        if horizontal_120ths != 0 {
            inputs.push(INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        dx: 0,
                        dy: 0,
                        mouseData: horizontal_120ths as u32,
                        dwFlags: MOUSEEVENTF_HWHEEL,
                        time: 0,
                        dwExtraInfo: crate::ECHO_TAG,
                    },
                },
            });
        }
        inputs
    }

    fn mouse_button_flags(
        button: MouseButton,
        pressed: bool,
    ) -> (
        windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
        u32,
    ) {        match (button, pressed) {
            (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
            (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
            (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
            (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
            (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
            (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
            (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, 1),
            (MouseButton::Back, false) => (MOUSEEVENTF_XUP, 1),
            (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, 2),
            (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, 2),
        }
    }

    /// Convert USB HID usages to Set 1 scan codes. Scan-code injection keeps
    /// the receiver's keyboard layout in charge instead of hard-coding US
    /// virtual-key meanings into the protocol.
    fn hid_to_scan_code(usage: u16) -> Option<(u16, bool)> {
        Some(match usage {
            0x04 => (0x1e, false),
            0x05 => (0x30, false),
            0x06 => (0x2e, false),
            0x07 => (0x20, false),
            0x08 => (0x12, false),
            0x09 => (0x21, false),
            0x0a => (0x22, false),
            0x0b => (0x23, false),
            0x0c => (0x17, false),
            0x0d => (0x24, false),
            0x0e => (0x25, false),
            0x0f => (0x26, false),
            0x10 => (0x32, false),
            0x11 => (0x31, false),
            0x12 => (0x18, false),
            0x13 => (0x19, false),
            0x14 => (0x10, false),
            0x15 => (0x13, false),
            0x16 => (0x1f, false),
            0x17 => (0x14, false),
            0x18 => (0x16, false),
            0x19 => (0x2f, false),
            0x1a => (0x11, false),
            0x1b => (0x2d, false),
            0x1c => (0x15, false),
            0x1d => (0x2c, false),
            0x1e => (0x02, false),
            0x1f => (0x03, false),
            0x20 => (0x04, false),
            0x21 => (0x05, false),
            0x22 => (0x06, false),
            0x23 => (0x07, false),
            0x24 => (0x08, false),
            0x25 => (0x09, false),
            0x26 => (0x0a, false),
            0x27 => (0x0b, false),
            0x28 => (0x1c, false),
            0x29 => (0x01, false),
            0x2a => (0x0e, false),
            0x2b => (0x0f, false),
            0x2c => (0x39, false),
            0x2d => (0x0c, false),
            0x2e => (0x0d, false),
            0x2f => (0x1a, false),
            0x30 => (0x1b, false),
            0x31 => (0x2b, false),
            0x33 => (0x27, false),
            0x34 => (0x28, false),
            0x35 => (0x29, false),
            0x36 => (0x33, false),
            0x37 => (0x34, false),
            0x38 => (0x35, false),
            0x39 => (0x3a, false),
            0x3a..=0x44 => (0x3b + (usage - 0x3a), false),
            0x45 => (0x58, false),
            0x46 => (0x37, true),
            0x47 => (0x46, false),
            0x49 => (0x52, true),
            0x4a => (0x47, true),
            0x4b => (0x4b, true),
            0x4c => (0x53, true),
            0x4d => (0x4d, true),
            0x4e => (0x51, true),
            0x4f => (0x4d, true),
            0x50 => (0x4b, true),
            0x51 => (0x50, true),
            0x52 => (0x48, true),
            0x53 => (0x45, false),
            0x54 => (0x35, true),
            0x55 => (0x37, false),
            0x56 => (0x4a, false),
            0x57 => (0x4e, false),
            0x58 => (0x1c, true),
            0x59 => (0x4f, false),
            0x5a => (0x50, false),
            0x5b => (0x51, false),
            0x5c => (0x4b, false),
            0x5d => (0x4c, false),
            0x5e => (0x4d, false),
            0x5f => (0x47, false),
            0x60 => (0x48, false),
            0x61 => (0x49, false),
            0x62 => (0x52, false),
            0x63 => (0x53, false),
            0x64 => (0x56, false),
            0x65 => (0x5d, true),
            0x68..=0x72 => (0x64 + (usage - 0x68), false),
            0x73 => (0x76, false),
            0xe0 => (0x1d, false),
            0xe1 => (0x2a, false),
            0xe2 => (0x38, false),
            0xe3 => (0x5b, true),
            0xe4 => (0x1d, true),
            0xe5 => (0x36, false),
            0xe6 => (0x38, true),
            0xe7 => (0x5c, true),
            _ => return None,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::hid_to_scan_code;

        #[test]
        fn uses_physical_scan_codes_for_common_keys() {
            assert_eq!(hid_to_scan_code(0x04), Some((0x1e, false))); // A
            assert_eq!(hid_to_scan_code(0x1e), Some((0x02, false))); // 1
            assert_eq!(hid_to_scan_code(0xe4), Some((0x1d, true))); // right Ctrl
            assert_eq!(hid_to_scan_code(0x4f), Some((0x4d, true))); // right arrow
            assert_eq!(hid_to_scan_code(0x59), Some((0x4f, false))); // keypad 1
            assert_eq!(hid_to_scan_code(0x58), Some((0x1c, true))); // keypad Enter
            assert_eq!(hid_to_scan_code(0x73), Some((0x76, false))); // F24
            assert_eq!(hid_to_scan_code(0x65), Some((0x5d, true))); // application
        }

        #[test]
        fn full_letter_rows_and_win_keys_emit_exact_scans() {
            // (USB HID usage, scan code, extended, key). The reverse trip:
            // Mint driving Windows must land the same physical keys.
            let pairs: &[(u16, (u16, bool), &str)] = &[
                (0x04, (0x1e, false), "A"), (0x05, (0x30, false), "B"),
                (0x06, (0x2e, false), "C"), (0x07, (0x20, false), "D"),
                (0x08, (0x12, false), "E"), (0x09, (0x21, false), "F"),
                (0x0a, (0x22, false), "G"), (0x0b, (0x23, false), "H"),
                (0x0c, (0x17, false), "I"), (0x0d, (0x24, false), "J"),
                (0x0e, (0x25, false), "K"), (0x0f, (0x26, false), "L"),
                (0x10, (0x32, false), "M"), (0x11, (0x31, false), "N"),
                (0x12, (0x18, false), "O"), (0x13, (0x19, false), "P"),
                (0x14, (0x10, false), "Q"), (0x15, (0x13, false), "R"),
                (0x16, (0x1f, false), "S"), (0x17, (0x14, false), "T"),
                (0x18, (0x16, false), "U"), (0x19, (0x2f, false), "V"),
                (0x1a, (0x11, false), "W"), (0x1b, (0x2d, false), "X"),
                (0x1c, (0x15, false), "Y"), (0x1d, (0x2c, false), "Z"),
                (0xe3, (0x5b, true), "LWin"), (0xe7, (0x5c, true), "RWin"),
                (0xe0, (0x1d, false), "LCtrl"), (0xe2, (0x38, false), "LAlt"),
                (0x47, (0x46, false), "ScrollLock"),
            ];
            for (usage, scan, name) in pairs {
                assert_eq!(hid_to_scan_code(*usage), Some(*scan), "key {name}");
            }
        }
    }
}

#[cfg(target_os = "windows")]
pub use win32_inject::Win32Injector as Injector;

/// Compile-time fallback for desktop targets without an evdev/uinput or
/// Windows backend. Keeping the type available lets the shared daemon,
/// protocol, and UI build on those targets without pretending that a null
/// backend provides functional KVM input.
#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
pub struct UnsupportedInjector;

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
impl UnsupportedInjector {
    pub fn create() -> Result<Self, PlatformError> {
        Err(PlatformError::Uinput(
            "no native input injector is implemented for this operating system".into(),
        ))
    }

    pub fn send(&self, _event: kvm_core::InputEvent) -> Result<(), PlatformError> {
        Err(PlatformError::Uinput(
            "no native input injector is implemented for this operating system".into(),
        ))
    }

    pub fn release_all(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
pub use UnsupportedInjector as Injector;
