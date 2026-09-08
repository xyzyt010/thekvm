//! Shared types for TheKVM: event model, config, screen layout.

pub mod config;
pub mod event;
pub mod layout;

pub use config::{Config, Mode, MAX_DEVICE_NAME_BYTES};
pub use event::{HidUsage, InputEvent, InputPacket, InputState, KeyEvent, MouseButton, WheelDelta};
pub use layout::{
    Edge, EdgeHandoff, EdgeRouter, Layout, RoutedEvent, Screen, ScreenId,
    FIRST_PEER_SCREEN_ID, MIRROR_PEER_SCREEN_ID, MIRROR_SELF_SCREEN_ID, SELF_SCREEN_ID,
};
