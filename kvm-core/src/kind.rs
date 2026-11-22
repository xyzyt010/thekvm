//! What kind of peer a connection comes from.
//!
//! Desktop peers are full bidirectional KVM endpoints. Android peers are
//! controller-only touchpad/text clients: they can drive a desktop but can
//! never capture or control another Android device. The field is carried in
//! discovery advertisements, pairing requests and session hellos so both
//! sides can filter and label peers correctly. All wire fields default to
//! `Desktop`, keeping older peers interoperable.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientKind {
    Desktop,
    Android,
}

impl Default for ClientKind {
    fn default() -> Self {
        Self::Desktop
    }
}

impl ClientKind {
    pub fn is_android(self) -> bool {
        matches!(self, Self::Android)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Desktop => "computer",
            Self::Android => "Android touchpad",
        }
    }
}
