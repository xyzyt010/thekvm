//! Gesture-only multitouch tap for trackpad pinch-to-zoom on Linux.
//!
//! X11 reports trackpads as relative pointers (never as touch devices),
//! so a two-finger pinch is invisible to the X11 capture backend. This
//! tap opens the same `/dev/input` nodes read-only WITHOUT grabbing (the
//! X server keeps its reader; no input is stolen or suppressed) and
//! tracks ABS_MT slots purely to derive pinch spread. It emits nothing
//! else — no motion, keys, or buttons — so pointer/keyboard capture stays
//! exactly where it is. Unreadable nodes (permissions) or missing MT axes
//! simply yield an empty tap: pinch unavailable, everything else intact.
//!
//! Gesture math mirrors the Windows precision-touchpad tap (see
//! PtpPinch): same engage gate, same 120ths, same End discipline.

use kvm_core::InputEvent;
use std::collections::BTreeMap;
use std::fs::{read_dir, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

const EV_SYN: u16 = 0x00;
const EV_ABS: u16 = 0x03;
const SYN_REPORT: u16 = 0;
const ABS_MT_SLOT: u16 = 0x2f;
const ABS_MT_POSITION_X: u16 = 0x35;
const ABS_MT_POSITION_Y: u16 = 0x36;
const ABS_MT_TRACKING_ID: u16 = 0x39;
const ABS_BITS_LEN: usize = 8;
/// Same engage gate as the PTP tap: spread must move this far before the
/// fingers own a pinch (a steady two-finger scroll stays pan).
const PINCH_ENGAGE_UNITS: i64 = 48;
/// Full sensor span earns this many detents (PTP parity).
const DETENTS_PER_SPAN: i64 = 48;

type IoctlRequest = libc::c_ulong;

const fn ioc(dir: u32, type_: u32, number: u32, size: usize) -> IoctlRequest {
    const IOC_NRBITS: u32 = 8;
    const IOC_TYPEBITS: u32 = 8;
    const IOC_SIZEBITS: u32 = 14;
    const IOC_READ: u32 = 2;
    ((dir << (IOC_NRBITS + IOC_TYPEBITS + IOC_SIZEBITS))
        | ((type_ & 0xff) << (IOC_NRBITS + IOC_SIZEBITS))
        | ((number & 0xff) << IOC_NRBITS)
        | (((size as u32) & 0x3fff) << (IOC_NRBITS + IOC_TYPEBITS))) as IoctlRequest
}

const fn eviocgbit(event_type: u32, length: usize) -> IoctlRequest {
    ioc(2, b'E' as u32, 0x20 + event_type, length)
}

const fn eviocgname(length: usize) -> IoctlRequest {
    ioc(2, b'E' as u32, 0x06, length)
}

const fn eviocgabs(abs: u32) -> IoctlRequest {
    ioc(2, b'E' as u32, 0x40 + abs, 24)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawEv {
    time: libc::timeval,
    type_: u16,
    code: u16,
    value: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AbsInfo {
    value: i32,
    minimum: i32,
    maximum: i32,
    fuzz: i32,
    flat: i32,
    resolution: i32,
}

fn capability_bits(file: &File, event_type: u32, length: usize) -> Option<Vec<u8>> {
    let mut bits = vec![0u8; length];
    let result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            eviocgbit(event_type, length) as _,
            bits.as_mut_ptr(),
        )
    };
    (result >= 0).then_some(bits)
}

fn bit_is_set(bits: &[u8], bit: usize) -> bool {
    bits.get(bit / 8)
        .is_some_and(|byte| byte & (1 << (bit % 8)) != 0)
}

fn device_name(file: &File) -> Option<String> {
    let mut name = vec![0u8; 256];
    let result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            eviocgname(name.len()) as _,
            name.as_mut_ptr(),
        )
    };
    if result < 0 {
        return None;
    }
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    String::from_utf8(name[..end].to_vec()).ok()
}

fn abs_maximum(file: &File, code: u16) -> Option<i32> {
    let mut info = AbsInfo::default();
    let result = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            eviocgabs(u32::from(code)) as _,
            &mut info as *mut AbsInfo,
        )
    };
    (result >= 0 && info.maximum > 0).then_some(info.maximum)
}

fn read_raw(file: &File) -> io::Result<Option<RawEv>> {
    use std::io::Read as _;
    let mut bytes = [0u8; std::mem::size_of::<RawEv>()];
    let mut file_ref: &File = file;
    match file_ref.read_exact(&mut bytes) {
        Ok(()) => Ok(Some(unsafe {
            std::mem::transmute::<[u8; 24], RawEv>(bytes)
        })),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

/// Pure pinch-spread machine over committed two-contact snapshots.
/// Same contract as the PTP tap: returns zoom in 120ths plus whether a
/// gesture just ended. Only an engaged pinch emits; count changes reset.
#[derive(Debug)]
struct PinchState {
    anchor: Option<i64>,
    prev: Option<i64>,
    acc: i64,
    units_per_detent: i64,
    engaged: bool,
}

impl PinchState {
    fn feed(&mut self, contacts: &[(i32, i32)]) -> (i32, bool) {
        if contacts.len() != 2 {
            let ended = self.engaged;
            self.anchor = None;
            self.prev = None;
            self.acc = 0;
            self.engaged = false;
            return (0, ended);
        }
        let spread = (i64::from(contacts[0].0) - i64::from(contacts[1].0)).abs()
            + (i64::from(contacts[0].1) - i64::from(contacts[1].1)).abs();
        let Some(anchor) = self.anchor else {
            self.anchor = Some(spread);
            self.prev = Some(spread);
            return (0, false);
        };
        if !self.engaged && (spread - anchor).abs() >= PINCH_ENGAGE_UNITS {
            self.engaged = true;
        }
        let mut zoom = 0;
        if self.engaged {
            if let Some(prev) = self.prev {
                self.acc += spread - prev;
                let det = self.acc / self.units_per_detent.max(1);
                self.acc -= det * self.units_per_detent.max(1);
                zoom = det.clamp(-1000, 1000) as i32 * 120;
            }
        }
        self.prev = Some(spread);
        (zoom, false)
    }
}

struct TapDevice {
    file: File,
    /// Live contacts by MT slot (only tracking-id-down slots).
    contacts: BTreeMap<i32, (i32, i32)>,
    slot: i32,
    pinch: PinchState,
    pending: Option<InputEvent>,
}

impl TapDevice {
    fn ingest(&mut self, event: RawEv) {
        if event.type_ == EV_ABS {
            match event.code {
                ABS_MT_SLOT => self.slot = event.value,
                ABS_MT_TRACKING_ID => {
                    if event.value >= 0 {
                        self.contacts.entry(self.slot).or_insert((0, 0));
                    } else {
                        self.contacts.remove(&self.slot);
                    }
                }
                ABS_MT_POSITION_X => {
                    self.contacts.entry(self.slot).or_insert((0, 0)).0 = event.value;
                }
                ABS_MT_POSITION_Y => {
                    self.contacts.entry(self.slot).or_insert((0, 0)).1 = event.value;
                }
                _ => {}
            }
        } else if event.type_ == EV_SYN && event.code == SYN_REPORT {
            let snapshot: Vec<(i32, i32)> = self.contacts.values().copied().collect();
            let (zoom, ended) = self.pinch.feed(&snapshot);
            // First SYN per poll wins: a flurry of frames resolves to at
            // most one gesture event per backend poll either way.
            if self.pending.is_none() {
                if zoom != 0 {
                    self.pending = Some(InputEvent::Pinch { delta: zoom });
                } else if ended {
                    self.pending = Some(InputEvent::PinchEnd);
                }
            }
        }
    }
}

/// Read-only multitouch gesture tap. Empty when no MT node is usable.
pub struct MtPinchTap {
    devices: Vec<TapDevice>,
}

impl MtPinchTap {
    /// Open every usable MT node. Never fails: unusable nodes are
    /// skipped, so construction cannot break capture startup.
    pub fn open() -> Self {
        let mut devices = Vec::new();
        let entries = read_dir("/dev/input").map(|dir| {
            dir.filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("event"))
                })
                .collect::<Vec<_>>()
        });
        let mut count = 0u32;
        for entry in entries.unwrap_or_default() {
            if let Some(device) = Self::open_node(&entry.path()) {
                count += 1;
                devices.push(device);
            }
        }
        if count > 0 {
            tracing::info!(
                devices = count,
                "multitouch pinch tap armed (read-only, no grab)"
            );
        } else {
            tracing::debug!("no multitouch tap node usable; trackpad pinch unavailable");
        }
        Self { devices }
    }

    fn open_node(path: &std::path::Path) -> Option<TapDevice> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        if device_name(&file)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("thekvm")
        {
            return None;
        }
        let abs_bits = capability_bits(&file, u32::from(EV_ABS), ABS_BITS_LEN)?;
        if !(bit_is_set(&abs_bits, ABS_MT_SLOT as usize)
            && bit_is_set(&abs_bits, ABS_MT_POSITION_X as usize))
        {
            return None;
        }
        let span = abs_maximum(&file, ABS_MT_POSITION_X).unwrap_or(3072);
        tracing::debug!(device = %path.display(), span, "multitouch tap node opened read-only");
        Some(TapDevice {
            file,
            contacts: BTreeMap::new(),
            slot: 0,
            pinch: PinchState {
                anchor: None,
                prev: None,
                acc: 0,
                units_per_detent: (span.max(1) / DETENTS_PER_SPAN).max(1),
                engaged: false,
            },
            pending: None,
        })
    }

    /// Drain every node (non-blocking) and return at most one gesture
    /// event. `None` is the common case: no fingers, scrolling fingers,
    /// or an engaged pinch holding still.
    pub fn poll(&mut self) -> Option<InputEvent> {
        for device in &mut self.devices {
            loop {
                match read_raw(&device.file) {
                    Ok(Some(event)) => device.ingest(event),
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%error, "multitouch tap read failed; node skipped this poll");
                        break;
                    }
                }
            }
            if let Some(gesture) = device.pending.take() {
                return Some(gesture);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> PinchState {
        PinchState {
            anchor: None,
            prev: None,
            acc: 0,
            units_per_detent: 10,
            engaged: false,
        }
    }

    #[test]
    fn spread_emits_zoom_in_and_close_emits_zoom_out() {
        let mut pinch = state();
        assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
        assert!(!pinch.engaged);
        assert_eq!(pinch.feed(&[(0, 0), (120, 0)]), (0, false));
        assert_eq!(pinch.feed(&[(0, 0), (160, 0)]), (480, false));
        assert!(pinch.engaged);
        assert_eq!(pinch.feed(&[(0, 0), (140, 0)]), (-240, false));
    }

    #[test]
    fn steady_two_finger_scroll_never_pinches() {
        let mut pinch = state();
        assert_eq!(pinch.feed(&[(0, 100), (0, 100)]), (0, false));
        assert_eq!(pinch.feed(&[(0, 90), (0, 90)]), (0, false));
        assert!(!pinch.engaged);
        assert_eq!(pinch.feed(&[(5, 5)]), (0, false));
    }

    #[test]
    fn lift_after_pinch_ends_once_then_reanchors() {
        let mut pinch = state();
        assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
        assert_eq!(pinch.feed(&[(0, 0), (200, 0)]), (1200, false));
        assert_eq!(pinch.feed(&[]), (0, true));
        assert_eq!(pinch.feed(&[]), (0, false));
        assert_eq!(pinch.feed(&[(0, 0), (100, 0)]), (0, false));
        assert!(!pinch.engaged);
    }

    #[test]
    fn slot_tracking_lift_clears_the_contact() {
        let mut device = TapDevice {
            file: File::open("/dev/null").unwrap(),
            contacts: BTreeMap::new(),
            slot: 0,
            pinch: state(),
            pending: None,
        };
        let ev = |type_: u16, code: u16, value: i32| RawEv {
            time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            type_,
            code,
            value,
        };
        // Two fingers down far apart: engages and zooms.
        device.ingest(ev(EV_ABS, ABS_MT_SLOT, 0));
        device.ingest(ev(EV_ABS, ABS_MT_TRACKING_ID, 7));
        device.ingest(ev(EV_ABS, ABS_MT_POSITION_X, 0));
        device.ingest(ev(EV_ABS, ABS_MT_POSITION_Y, 0));
        device.ingest(ev(EV_ABS, ABS_MT_SLOT, 1));
        device.ingest(ev(EV_ABS, ABS_MT_TRACKING_ID, 8));
        device.ingest(ev(EV_ABS, ABS_MT_POSITION_X, 100));
        device.ingest(ev(EV_ABS, ABS_MT_POSITION_Y, 0));
        device.ingest(ev(EV_SYN, SYN_REPORT, 0));
        assert_eq!(device.pending, None);
        // Spread: slot 1 moves out.
        device.ingest(ev(EV_ABS, ABS_MT_SLOT, 1));
        device.ingest(ev(EV_ABS, ABS_MT_POSITION_X, 200));
        device.ingest(ev(EV_SYN, SYN_REPORT, 0));
        assert_eq!(device.pending, Some(InputEvent::Pinch { delta: 1200 }));
        device.pending = None;
        // Lift slot 1: single contact left, gesture ends.
        device.ingest(ev(EV_ABS, ABS_MT_SLOT, 1));
        device.ingest(ev(EV_ABS, ABS_MT_TRACKING_ID, -1));
        device.ingest(ev(EV_SYN, SYN_REPORT, 0));
        assert_eq!(device.pending, Some(InputEvent::PinchEnd));
    }
}
