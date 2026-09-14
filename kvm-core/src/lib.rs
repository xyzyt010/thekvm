//! Shared types for TheKVM: event model, config, screen layout.

pub mod config;
pub mod event;
pub mod layout;

pub use config::{Config, EdgeMode, Mode, MAX_DEVICE_NAME_BYTES};
pub use event::{HidUsage, InputEvent, InputPacket, InputState, KeyEvent, MouseButton, WheelDelta};
pub use layout::{
    edge_overflow, Edge, EdgeHandoff, EdgeRouter, Layout, RoutedEvent, Screen, ScreenId,
    EDGE_PUSH_PX, FIRST_PEER_SCREEN_ID, SELF_SCREEN_ID,
};
