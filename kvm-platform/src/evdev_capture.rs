//! Linux evdev capture backend.
//!
//! The backend deliberately captures physical devices only. TheKVM's own
//! uinput devices are ignored by name so a receiver that also captures input
//! cannot form an event loop.

use crate::{capture::CaptureBackend, PlatformError};
use kvm_core::{InputEvent, KeyEvent, MouseButton};
use std::collections::{BTreeSet, VecDeque};
use std::fs::{read_dir, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "freebsd")]
type IoctlRequest = libc::c_ulong;
#[cfg(not(target_os = "freebsd"))]
type IoctlRequest = libc::Ioctl;

const EV_SYN: u16 = 0x00;
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const SYN_REPORT: u16 = 0;
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
const EVIOCGRAB: IoctlRequest = 0x4004_4590;
const KEY_MAX: usize = 0x2ff;
const REL_MAX: usize = 0x0f;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawInputEvent {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: i32,
}

struct Device {
    path: PathBuf,
    file: File,
    is_keyboard: bool,
    is_mouse: bool,
    dx: i32,
    dy: i32,
    /// Accumulated scroll in 120ths (one REL_WHEEL_HI_RES step), flushed as
    /// one `SmoothWheel` per SYN. Legacy detent ticks count 120 each, so a
    /// notched wheel and a smooth touchpad share one canonical unit.
    scroll_x_120ths: i32,
    scroll_y_120ths: i32,
    queue: VecDeque<InputEvent>,
    pressed_keys: BTreeSet<u16>,
    pressed_buttons: BTreeSet<MouseButton>,
    grabbed: bool,
}

impl Device {
    fn open(path: PathBuf) -> Result<Option<Self>, PlatformError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| PlatformError::Capture(format!("open {}: {e}", path.display())))?;

        let name = device_name(&file).unwrap_or_default();
        if name.to_ascii_lowercase().contains("thekvm") {
            return Ok(None);
        }

        let key_bits = capability_bits(&file, 1, (KEY_MAX + 8) / 8).unwrap_or_default();
        let rel_bits = capability_bits(&file, 2, (REL_MAX + 8) / 8).unwrap_or_default();
        let is_mouse = bit_is_set(&rel_bits, REL_X as usize)
            || bit_is_set(&rel_bits, REL_Y as usize)
            || [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA]
                .iter()
                .any(|code| bit_is_set(&key_bits, *code as usize));
        let is_keyboard = [1u16, 14, 15, 28, 30, 42, 54, 57, 103, 105, 106, 108]
            .iter()
            .any(|code| bit_is_set(&key_bits, *code as usize));

        if !is_keyboard && !is_mouse {
            return Ok(None);
        }

        tracing::debug!(device = %path.display(), name, is_keyboard, is_mouse, "capturing evdev device");
        Ok(Some(Self {
            path,
            file,
            is_keyboard,
            is_mouse,
            dx: 0,
            dy: 0,
            scroll_x_120ths: 0,
            scroll_y_120ths: 0,
            queue: VecDeque::new(),
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            grabbed: false,
        }))
    }

    fn process(&mut self, event: RawInputEvent) -> Vec<InputEvent> {
        let mut output = Vec::new();
        match event.type_ {
            EV_KEY if self.is_mouse => {
                if let Some(button) = mouse_button(event.code) {
                    if let Some(pressed) = key_pressed(event.value) {
                        output.push(InputEvent::MouseButton { button, pressed });
                        if pressed {
                            self.pressed_buttons.insert(button);
                        } else {
                            self.pressed_buttons.remove(&button);
                        }
                    }
                } else if self.is_keyboard {
                    if let Some(event) = self.push_key(event.code, event.value) {
                        output.push(event);
                    }
                }
            }
            EV_KEY if self.is_keyboard => {
                if let Some(event) = self.push_key(event.code, event.value) {
                    output.push(event);
                }
            }
            EV_REL if self.is_mouse => match event.code {
                REL_X => self.dx = self.dx.saturating_add(event.value),
                REL_Y => self.dy = self.dy.saturating_add(event.value),
                REL_WHEEL => {
                    self.scroll_y_120ths = self
                        .scroll_y_120ths
                        .saturating_add(event.value.saturating_mul(120))
                }
                REL_HWHEEL => {
                    self.scroll_x_120ths = self
                        .scroll_x_120ths
                        .saturating_add(event.value.saturating_mul(120))
                }
                REL_WHEEL_HI_RES => {
                    self.scroll_y_120ths = self.scroll_y_120ths.saturating_add(event.value)
                }
                REL_HWHEEL_HI_RES => {
                    self.scroll_x_120ths = self.scroll_x_120ths.saturating_add(event.value)
                }
                _ => {}
            },
            EV_SYN if event.code == SYN_REPORT => {
                if self.dx != 0 || self.dy != 0 {
                    output.push(InputEvent::MouseMove {
                        dx: self.dx,
                        dy: self.dy,
                    });
                }
                if self.scroll_x_120ths != 0 || self.scroll_y_120ths != 0 {
                    output.push(InputEvent::SmoothWheel {
                        x: self.scroll_x_120ths,
                        y: self.scroll_y_120ths,
                    });
                }
                self.dx = 0;
                self.dy = 0;
                self.scroll_x_120ths = 0;
                self.scroll_y_120ths = 0;
            }
            _ => {}
        }
        output
    }

    fn push_key(&mut self, code: u16, value: i32) -> Option<InputEvent> {
        let Some(pressed) = key_pressed(value) else {
            return None;
        };
        let usage = hid_from_evdev(code)?;
        if pressed {
            self.pressed_keys.insert(usage);
        } else {
            self.pressed_keys.remove(&usage);
        }
        Some(InputEvent::Key(KeyEvent { usage, pressed }))
    }
}

fn key_pressed(value: i32) -> Option<bool> {
    // EV_KEY value 2 is an autorepeat notification. The receiver's keyboard
    // stack performs its own repeat; forwarding this as another press creates
    // duplicate make events and can leave state divergent.
    match value {
        0 => Some(false),
        1 => Some(true),
        2 => None,
        other => Some(other != 0),
    }
}

pub struct EvdevCapture {
    devices: Vec<Device>,
    pending_events: VecDeque<InputEvent>,
    pressed_keys: BTreeSet<u16>,
    pressed_buttons: BTreeSet<MouseButton>,
    exclusive: bool,
    last_reload: Instant,
}

impl EvdevCapture {
    pub fn create() -> Result<Self, PlatformError> {
        let mut capture = Self {
            devices: Vec::new(),
            pending_events: VecDeque::new(),
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            exclusive: false,
            last_reload: Instant::now(),
        };
        capture.reload()?;
        if capture.devices.is_empty() {
            return Err(PlatformError::Capture(
                "no keyboard or mouse evdev devices found; grant the daemon access to /dev/input"
                    .into(),
            ));
        }
        Ok(capture)
    }

    fn reload(&mut self) -> Result<(), PlatformError> {
        let mut paths = read_dir("/dev/input")
            .map_err(|e| PlatformError::Capture(format!("read /dev/input: {e}")))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("event"))
            })
            .collect::<Vec<_>>();
        paths.sort();

        for path in paths {
            if self.devices.iter().any(|device| device.path == path) {
                continue;
            }
            if let Ok(Some(device)) = Device::open(path) {
                self.devices.push(device);
            }
        }
        if self.exclusive {
            self.set_devices_exclusive(true)?;
        }
        Ok(())
    }

    fn set_devices_exclusive(&mut self, exclusive: bool) -> Result<(), PlatformError> {
        for device in &mut self.devices {
            if device.grabbed == exclusive {
                continue;
            }
            let value = i32::from(exclusive);
            let result = unsafe { libc::ioctl(device.file.as_raw_fd(), EVIOCGRAB, value) };
            if result < 0 {
                if exclusive {
                    for previous in &mut self.devices {
                        if previous.grabbed {
                            unsafe {
                                let _ = libc::ioctl(previous.file.as_raw_fd(), EVIOCGRAB, 0);
                            }
                            previous.grabbed = false;
                        }
                    }
                }
                self.exclusive = false;
                return Err(PlatformError::Capture(format!(
                    "{} EVIOCGRAB failed: {}",
                    if exclusive { "enable" } else { "disable" },
                    io::Error::last_os_error()
                )));
            }
            device.grabbed = exclusive;
        }
        self.exclusive = exclusive;
        Ok(())
    }

    fn remove_devices(&mut self, mut indexes: Vec<usize>) {
        indexes.sort_unstable();
        indexes.dedup();

        let removed = indexes.iter().copied().collect::<BTreeSet<_>>();
        let remaining_keys = self
            .devices
            .iter()
            .enumerate()
            .filter(|(index, _)| !removed.contains(index))
            .flat_map(|(_, device)| device.pressed_keys.iter().copied())
            .collect::<BTreeSet<_>>();
        let remaining_buttons = self
            .devices
            .iter()
            .enumerate()
            .filter(|(index, _)| !removed.contains(index))
            .flat_map(|(_, device)| device.pressed_buttons.iter().copied())
            .collect::<BTreeSet<_>>();
        let mut removed_keys = BTreeSet::new();
        let mut removed_buttons = BTreeSet::new();
        let devices = std::mem::take(&mut self.devices);
        let mut retained = Vec::with_capacity(devices.len().saturating_sub(removed.len()));
        for (index, mut device) in devices.into_iter().enumerate() {
            if removed.contains(&index) {
                // Preserve events already decoded before the disconnect, then
                // append synthetic releases for controls that the vanished
                // device reported as held. Without this, a pulled keyboard or
                // mouse can leave remote state pressed until the lease timeout.
                self.pending_events.append(&mut device.queue);
                removed_keys.extend(std::mem::take(&mut device.pressed_keys));
                removed_buttons.extend(std::mem::take(&mut device.pressed_buttons));
            } else {
                retained.push(device);
            }
        }
        self.devices = retained;
        for usage in removed_keys.difference(&remaining_keys) {
            if self.pressed_keys.remove(usage) {
                self.pending_events.push_back(InputEvent::Key(KeyEvent {
                    usage: *usage,
                    pressed: false,
                }));
            }
        }
        for button in removed_buttons.difference(&remaining_buttons) {
            if self.pressed_buttons.remove(button) {
                self.pending_events.push_back(InputEvent::MouseButton {
                    button: *button,
                    pressed: false,
                });
            }
        }
    }

    fn accept_event(&mut self, source: usize, event: InputEvent) -> Option<InputEvent> {
        match event {
            InputEvent::Key(KeyEvent { usage, pressed }) => {
                if pressed {
                    self.pressed_keys.insert(usage).then_some(event)
                } else if self
                    .devices
                    .iter()
                    .enumerate()
                    .any(|(index, device)| index != source && device.pressed_keys.contains(&usage))
                {
                    None
                } else {
                    self.pressed_keys.remove(&usage).then_some(event)
                }
            }
            InputEvent::MouseButton { button, pressed } => {
                if pressed {
                    self.pressed_buttons.insert(button).then_some(event)
                } else if self.devices.iter().enumerate().any(|(index, device)| {
                    index != source && device.pressed_buttons.contains(&button)
                }) {
                    None
                } else {
                    self.pressed_buttons.remove(&button).then_some(event)
                }
            }
            _ => Some(event),
        }
    }
}

impl CaptureBackend for EvdevCapture {
    fn next_event(
        &mut self,
        stop: &AtomicBool,
        exclusive: &AtomicBool,
        _release: &AtomicBool,
    ) -> Result<InputEvent, PlatformError> {
        loop {
            if self.last_reload.elapsed() >= Duration::from_secs(1) {
                self.reload()?;
                self.last_reload = Instant::now();
            }
            let desired_exclusive = exclusive.load(Ordering::Acquire);
            if desired_exclusive != self.exclusive {
                self.set_devices_exclusive(desired_exclusive)?;
            }
            if stop.load(Ordering::Acquire) {
                return Err(PlatformError::Capture("capture stopped".into()));
            }
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(event);
            }
            for device in &mut self.devices {
                if let Some(event) = device.queue.pop_front() {
                    return Ok(event);
                }
            }

            if self.devices.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(250));
                self.reload()?;
                continue;
            }

            let mut pollfds = self
                .devices
                .iter()
                .map(|device| libc::pollfd {
                    fd: device.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                })
                .collect::<Vec<_>>();
            let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 250) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(PlatformError::Capture(format!("poll /dev/input: {error}")));
            }
            if result == 0 {
                continue;
            }

            let mut disconnected = Vec::new();
            for (index, pollfd) in pollfds.iter().enumerate() {
                if pollfd.revents & libc::POLLNVAL != 0 {
                    disconnected.push(index);
                    continue;
                }
                if pollfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) == 0 {
                    continue;
                }
                loop {
                    match read_event(&self.devices[index].file) {
                        Ok(Some(event)) => {
                            let produced = self.devices[index].process(event);
                            let accepted = produced
                                .into_iter()
                                .filter_map(|event| self.accept_event(index, event))
                                .collect::<Vec<_>>();
                            self.devices[index].queue.extend(accepted);
                        }
                        Ok(None) => break,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                        Err(error) if device_disconnected(&error) => {
                            disconnected.push(index);
                            break;
                        }
                        Err(error) => {
                            return Err(PlatformError::Capture(format!(
                                "read evdev device: {error}"
                            )))
                        }
                    }
                }
                if pollfd.revents & libc::POLLHUP != 0 {
                    disconnected.push(index);
                }
            }
            if !disconnected.is_empty() {
                self.remove_devices(disconnected);
            }
        }
    }

    fn set_exclusive(&mut self, exclusive: bool) -> Result<(), PlatformError> {
        self.set_devices_exclusive(exclusive)
    }
}

fn device_disconnected(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENODEV | libc::ENXIO | libc::EBADF)
    )
}

impl Drop for Device {
    fn drop(&mut self) {
        if self.grabbed {
            unsafe {
                let _ = libc::ioctl(self.file.as_raw_fd(), EVIOCGRAB, 0);
            }
            self.grabbed = false;
        }
    }
}

fn read_event(file: &File) -> io::Result<Option<RawInputEvent>> {
    let mut event = std::mem::MaybeUninit::<RawInputEvent>::uninit();
    let size = std::mem::size_of::<RawInputEvent>();
    let read = unsafe {
        libc::read(
            file.as_raw_fd(),
            event.as_mut_ptr().cast::<libc::c_void>(),
            size,
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read == 0 {
        return Ok(None);
    }
    if read as usize != size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short evdev event",
        ));
    }
    Ok(Some(unsafe { event.assume_init() }))
}

fn device_name(file: &File) -> io::Result<String> {
    let mut bytes = [0u8; 256];
    let request = eviocgname(bytes.len());
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, bytes.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn capability_bits(file: &File, event_type: u32, length: usize) -> io::Result<Vec<u8>> {
    let mut bits = vec![0u8; length];
    let request = eviocgbit(event_type, length);
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, bits.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(bits)
}

fn bit_is_set(bits: &[u8], bit: usize) -> bool {
    bits.get(bit / 8)
        .is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
}

fn mouse_button(code: u16) -> Option<MouseButton> {
    Some(match code {
        BTN_LEFT => MouseButton::Left,
        BTN_RIGHT => MouseButton::Right,
        BTN_MIDDLE => MouseButton::Middle,
        BTN_SIDE => MouseButton::Back,
        BTN_EXTRA => MouseButton::Forward,
        _ => return None,
    })
}

/// Convert the common Linux evdev keyboard namespace to USB HID usages.
/// The QWERTY row is explicit, never arithmetic: HID usages are not
/// sequential across Q..P, and a range formula here once reported W as R
/// and eight of its neighbours wrong with it.
pub(crate) fn hid_from_evdev(code: u16) -> Option<u16> {
    Some(match code {
        1 => 0x29,
        2..=11 => 0x1e + (code - 2),
        12 => 0x2d,
        13 => 0x2e,
        14 => 0x2a,
        15 => 0x2b,
        16 => 0x14,
        17 => 0x1a,
        18 => 0x08,
        19 => 0x15,
        20 => 0x17,
        21 => 0x1c,
        22 => 0x18,
        23 => 0x0c,
        24 => 0x12,
        25 => 0x13,
        26 => 0x2f,
        27 => 0x30,
        28 => 0x28,
        29 => 0xe0,
        30 => 0x04,
        31 => 0x16,
        32 => 0x07,
        33 => 0x09,
        34 => 0x0a,
        35 => 0x0b,
        36 => 0x0d,
        37 => 0x0e,
        38 => 0x0f,
        39 => 0x33,
        40 => 0x34,
        41 => 0x35,
        42 => 0xe1,
        43 => 0x31,
        44 => 0x1d,
        45 => 0x1b,
        46 => 0x06,
        47 => 0x19,
        48 => 0x05,
        49 => 0x11,
        50 => 0x10,
        51 => 0x36,
        52 => 0x37,
        53 => 0x38,
        54 => 0xe5,
        55 => 0x55,
        56 => 0xe2,
        57 => 0x2c,
        58 => 0x39,
        59..=68 => 0x3a + (code - 59),
        69 => 0x53,
        70 => 0x47,
        71..=73 => 0x5f + (code - 71),
        74 => 0x56,
        75..=77 => 0x5c + (code - 75),
        78 => 0x57,
        79..=81 => 0x59 + (code - 79),
        82 => 0x62,
        83 => 0x63,
        86 => 0x64,
        87 => 0x44,
        88 => 0x45,
        96 => 0x58,
        98 => 0x54,
        99 => 0x46,
        97 => 0xe4,
        100 => 0xe6,
        102 => 0x4a,
        103 => 0x52,
        104 => 0x4b,
        105 => 0x50,
        106 => 0x4f,
        107 => 0x4d,
        108 => 0x51,
        109 => 0x4e,
        110 => 0x49,
        111 => 0x4c,
        113 => 0x7f,
        114 => 0x81,
        115 => 0x80,
        116 => 0x66,
        117 => 0x67,
        128 => 0x78,
        129 => 0x79,
        131 => 0x7a,
        133 => 0x7c,
        135 => 0x7d,
        136 => 0x7e,
        137 => 0x7b,
        138 => 0x75,
        139 => 0x76,
        121 => 0x85,
        122 => 0x90,
        123 => 0x91,
        124 => 0x89,
        119 => 0x48,
        125 => 0xe3,
        126 => 0xe7,
        183..=194 => 0x68 + (code - 183),
        _ => return None,
    })
}

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_READ: u32 = 2;
const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
const IOC_TYPEMASK: u32 = (1 << IOC_TYPEBITS) - 1;
const IOC_SIZEMASK: u32 = (1 << IOC_SIZEBITS) - 1;

const fn ioc(dir: u32, type_: u32, number: u32, size: usize) -> IoctlRequest {
    ((dir << (IOC_NRBITS + IOC_TYPEBITS + IOC_SIZEBITS))
        | ((type_ & IOC_TYPEMASK) << (IOC_NRBITS + IOC_SIZEBITS))
        | ((number & IOC_NRMASK) << IOC_NRBITS)
        | (((size as u32) & IOC_SIZEMASK) << (IOC_NRBITS + IOC_TYPEBITS))) as IoctlRequest
}

const fn eviocgbit(event_type: u32, length: usize) -> IoctlRequest {
    ioc(IOC_READ, b'E' as u32, 0x20 + event_type, length)
}

const fn eviocgname(length: usize) -> IoctlRequest {
    ioc(IOC_READ, b'E' as u32, 0x06, length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device() -> Device {
        Device {
            path: PathBuf::from("/dev/null"),
            file: File::open("/dev/null").unwrap(),
            is_keyboard: true,
            is_mouse: true,
            dx: 0,
            dy: 0,
            scroll_x_120ths: 0,
            scroll_y_120ths: 0,
            queue: VecDeque::new(),
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            grabbed: false,
        }
    }

    #[test]
    fn scroll_reports_smooth_120ths_for_detents_and_hi_res() {
        use super::{REL_HWHEEL, REL_HWHEEL_HI_RES, REL_WHEEL, REL_WHEEL_HI_RES};
        let mut device = test_device();
        let rel = |code, value| RawInputEvent {
            time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            type_: EV_REL,
            code,
            value,
        };
        let syn = RawInputEvent {
            time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            type_: EV_SYN,
            code: SYN_REPORT,
            value: 0,
        };
        // One legacy detent tick plus a sub-detent hi-res touchpad motion.
        assert!(device.process(rel(REL_WHEEL, 1)).is_empty());
        assert!(device.process(rel(REL_WHEEL_HI_RES, 30)).is_empty());
        assert!(device.process(rel(REL_HWHEEL_HI_RES, -15)).is_empty());
        // Legacy horizontal detent counts 120.
        assert!(device.process(rel(REL_HWHEEL, -1)).is_empty());
        assert_eq!(
            device.process(syn),
            vec![InputEvent::SmoothWheel { x: -135, y: 150 }]
        );
    }
    #[test]
    fn filters_kernel_key_autorepeat() {
        assert_eq!(key_pressed(0), Some(false));
        assert_eq!(key_pressed(1), Some(true));
        assert_eq!(key_pressed(2), None);
    }

    #[test]
    fn recognizes_removed_evdev_devices() {
        assert!(device_disconnected(&io::Error::from_raw_os_error(
            libc::ENODEV
        )));
        assert!(device_disconnected(&io::Error::from_raw_os_error(
            libc::ENXIO
        )));
        assert!(!device_disconnected(&io::Error::from_raw_os_error(
            libc::EIO
        )));
    }

    #[test]
    fn maps_extended_keyboard_and_keypad_codes_to_hid() {
        assert_eq!(hid_from_evdev(29), Some(0xe0)); // left Ctrl
        assert_eq!(hid_from_evdev(87), Some(0x44)); // F11
        assert_eq!(hid_from_evdev(88), Some(0x45)); // F12
        assert_eq!(hid_from_evdev(99), Some(0x46)); // Print Screen
        assert_eq!(hid_from_evdev(71), Some(0x5f)); // keypad 7
        assert_eq!(hid_from_evdev(82), Some(0x62)); // keypad 0
        assert_eq!(hid_from_evdev(96), Some(0x58)); // keypad Enter
        assert_eq!(hid_from_evdev(183), Some(0x68)); // F13
    }

    #[test]
    fn full_letter_rows_decode_to_hid_exactly() {
        // (evdev code, USB HID usage, key). Mirror image of the inject
        // table: every letter, exact in both directions.
        let pairs: &[(u16, u16, &str)] = &[
            (30, 0x04, "A"), (48, 0x05, "B"), (46, 0x06, "C"),
            (32, 0x07, "D"), (18, 0x08, "E"), (33, 0x09, "F"),
            (34, 0x0a, "G"), (35, 0x0b, "H"), (23, 0x0c, "I"),
            (36, 0x0d, "J"), (37, 0x0e, "K"), (38, 0x0f, "L"),
            (50, 0x10, "M"), (49, 0x11, "N"), (24, 0x12, "O"),
            (25, 0x13, "P"), (16, 0x14, "Q"), (19, 0x15, "R"),
            (31, 0x16, "S"), (20, 0x17, "T"), (22, 0x18, "U"),
            (47, 0x19, "V"), (17, 0x1a, "W"), (45, 0x1b, "X"),
            (21, 0x1c, "Y"), (44, 0x1d, "Z"),
        ];
        for (code, usage, name) in pairs {
            assert_eq!(hid_from_evdev(*code), Some(*usage), "letter {name}");
        }
    }

    #[test]
    fn win_and_scroll_keys_decode_to_hid_exactly() {
        assert_eq!(hid_from_evdev(125), Some(0xe3)); // left Meta
        assert_eq!(hid_from_evdev(126), Some(0xe7)); // right Meta
        assert_eq!(hid_from_evdev(70), Some(0x47)); // Scroll Lock
        assert_eq!(hid_from_evdev(29), Some(0xe0)); // left Ctrl
        assert_eq!(hid_from_evdev(42), Some(0xe1)); // left Shift
        assert_eq!(hid_from_evdev(56), Some(0xe2)); // left Alt
        assert_eq!(hid_from_evdev(57), Some(0x2c)); // Space
    }

    #[test]
    fn disconnect_cleanup_releases_held_controls() {
        let mut capture = EvdevCapture {
            devices: vec![test_device()],
            pending_events: VecDeque::new(),
            pressed_keys: BTreeSet::from([0x04]),
            pressed_buttons: BTreeSet::from([MouseButton::Left]),
            exclusive: false,
            last_reload: Instant::now(),
        };
        capture.devices[0].pressed_keys.insert(0x04);
        capture.devices[0].pressed_buttons.insert(MouseButton::Left);
        capture.remove_devices(vec![0]);
        assert_eq!(
            capture.pending_events.into_iter().collect::<Vec<_>>(),
            vec![
                InputEvent::Key(KeyEvent {
                    usage: 0x04,
                    pressed: false
                }),
                InputEvent::MouseButton {
                    button: MouseButton::Left,
                    pressed: false
                },
            ]
        );
    }

    #[test]
    fn aggregates_overlapping_controls_across_devices() {
        let mut capture = EvdevCapture {
            devices: vec![test_device(), test_device()],
            pending_events: VecDeque::new(),
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            exclusive: false,
            last_reload: Instant::now(),
        };

        let key = InputEvent::Key(KeyEvent {
            usage: 0x04,
            pressed: true,
        });
        capture.devices[0].pressed_keys.insert(0x04);
        assert_eq!(capture.accept_event(0, key), Some(key));
        capture.devices[1].pressed_keys.insert(0x04);
        assert_eq!(capture.accept_event(1, key), None);

        let release = InputEvent::Key(KeyEvent {
            usage: 0x04,
            pressed: false,
        });
        capture.devices[0].pressed_keys.remove(&0x04);
        assert_eq!(capture.accept_event(0, release), None);
        capture.devices[1].pressed_keys.remove(&0x04);
        assert_eq!(capture.accept_event(1, release), Some(release));

        capture.devices[0].pressed_buttons.insert(MouseButton::Left);
        capture.pressed_buttons.insert(MouseButton::Left);
        capture.remove_devices(vec![0]);
        assert_eq!(
            capture.pending_events.pop_front(),
            Some(InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: false,
            })
        );
        assert_eq!(capture.devices.len(), 1);
    }
}
