//! Shared types for TheKVM: event model, config, screen layout.

pub mod config;
pub mod event;
pub mod layout;

pub use config::{Config, EdgeMode, Mode, TransportProtocol, MAX_DEVICE_NAME_BYTES};
pub use event::{HidUsage, InputEvent, InputPacket, InputState, KeyEvent, MouseButton, WheelDelta};
pub use layout::{
    edge_overflow, ClampReason, ClampStamp, DoubleEdgeStyle, Edge, EdgeHandoff, EdgeRouter, Layout,
    ResyncReset, RoutedEvent, Screen, ScreenId, EDGE_PUSH_PX, FIRST_PEER_SCREEN_ID, SELF_SCREEN_ID,
};
