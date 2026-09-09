use serde::{Deserialize, Serialize};

/// USB HID keyboard usage IDs are used on the wire. They are stable across
/// Linux, Windows, BSD, and the different native input APIs.
pub type HidUsage = u16;

/// A platform-neutral input event.
///
/// Pointer motion is relative because that is the only representation that is
/// lossless across mixed-DPI, multi-monitor, and lock-screen environments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputEvent {
    Key(KeyEvent),
    MouseMove { dx: i32, dy: i32 },
    MouseButton { button: MouseButton, pressed: bool },
    Wheel(WheelDelta),
    /// High-resolution scroll in 1/120-detent units (one Windows WHEEL_DELTA,
    /// one Linux REL_WHEEL_HI_RES step). Precision touchpads report smooth
    /// sub-detent motion that the detent-only `Wheel` truncates to zero —
    /// which is why two-finger scroll never arrived remotely on any legacy
    /// KVM. New peers negotiate this via Hello/Accepted; capture backends
    /// emit it canonically and the sender downgrades to `Wheel` for older
    /// peers. Sign convention matches `WheelDelta`: positive is away from
    /// the user.
    SmoothWheel { x: i32, y: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEvent {
    /// USB HID usage ID, not a Linux evdev code or a Windows virtual-key code.
    pub usage: HidUsage,
    pub pressed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WheelDelta {
    /// Horizontal wheel detents. Positive means away from the user.
    pub x: i16,
    /// Vertical wheel detents. Positive means away from the user.
    pub y: i16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputPacket {
    pub sequence: u64,
    pub event: InputEvent,
}

/// Snapshot of the physical sender's currently held controls. A reconnecting
/// receiver uses this to reconstruct modifiers/buttons that were already held
/// before the new QUIC stream was established.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputState {
    pub pressed_keys: Vec<HidUsage>,
    pub pressed_buttons: Vec<MouseButton>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trips() {
        let packet = InputPacket {
            sequence: 42,
            event: InputEvent::MouseButton {
                button: MouseButton::Left,
                pressed: false,
            },
        };
        let encoded = serde_json::to_vec(&packet).unwrap();
        assert_eq!(
            serde_json::from_slice::<InputPacket>(&encoded).unwrap(),
            packet
        );
    }

    #[test]
    fn input_state_round_trips() {
        let state = InputState {
            pressed_keys: vec![0xe0, 0x04],
            pressed_buttons: vec![MouseButton::Left],
        };
        let encoded = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            serde_json::from_slice::<InputState>(&encoded).unwrap(),
            state
        );
    }
}
