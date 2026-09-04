//! QUIC-based transport with mutual certificate pinning.
//!
//! Design (fixes MWB's plaintext-shared-secret weakness):
//! - Each install generates a self-signed cert + key on first run.
//! - Pairing displays and confirms certificate fingerprints before pinning.
//! - The six-digit numeric pairing code plus a scannable `thekvm://` invite
//!   (see [`pairing::verification_code`] and [`invite`]) make the ceremony
//!   comparable across two machines instead of trusting a displayed hash.
//! - mTLS: both sides present certs; a peer is trusted only if its
//!   fingerprint is pinned. No shared secret ever crosses the wire.

pub mod control;
pub mod discovery;
pub mod invite;
pub mod pairing;
pub mod transport;
pub mod wire;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("transport error: {0}")]
    Transport(#[from] quinn::ConnectionError),
    #[error("crypto config error: {0}")]
    Tls(String),
    #[error("peer not paired")]
    UntrustedPeer,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Default UDP port for TheKVM (avoid MWB's 15100/15101).
pub const DEFAULT_PORT: u16 = 42110;
