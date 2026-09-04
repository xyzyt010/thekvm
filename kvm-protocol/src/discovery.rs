//! Small, metadata-only LAN discovery protocol.
//!
//! Discovery is deliberately separate from QUIC input transport. A response
//! advertises only a node name, QUIC port, and certificate fingerprint; it
//! never authenticates a peer or authorizes input. Pairing must still show and
//! confirm the fingerprint through the normal QUIC ceremony.

use kvm_core::MAX_DEVICE_NAME_BYTES;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

pub const DISCOVERY_PORT: u16 = 42111;
const REQUEST: &[u8] = b"THEKVM-DISCOVER/1";
const RESPONSE_PREFIX: &[u8] = b"THEKVM-ADVERTISE/1\0";
const MAX_RESPONSE_SIZE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advertisement {
    pub node_name: String,
    pub listen_port: u16,
    pub fingerprint_hex: String,
}

pub fn request() -> &'static [u8] {
    REQUEST
}

pub fn encode_advertisement(advertisement: &Advertisement) -> std::io::Result<Vec<u8>> {
    validate(advertisement)?;
    let payload = serde_json::to_vec(advertisement)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let total = RESPONSE_PREFIX.len() + payload.len();
    if total > MAX_RESPONSE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery advertisement exceeds maximum size",
        ));
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(RESPONSE_PREFIX);
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub fn decode_advertisement(payload: &[u8]) -> std::io::Result<Advertisement> {
    if payload.len() <= RESPONSE_PREFIX.len() || payload.len() > MAX_RESPONSE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid discovery advertisement size",
        ));
    }
    let body = payload.strip_prefix(RESPONSE_PREFIX).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid discovery advertisement prefix",
        )
    })?;
    let advertisement: Advertisement = serde_json::from_slice(body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    validate(&advertisement)?;
    Ok(advertisement)
}

pub fn is_request(payload: &[u8]) -> bool {
    payload == REQUEST
}

/// Scan the local IPv4 LAN for metadata-only advertisements. The caller still
/// has to pair through QUIC and confirm the returned certificate fingerprint.
pub async fn scan(timeout: Duration) -> std::io::Result<Vec<(SocketAddr, Advertisement)>> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.set_broadcast(true)?;
    socket
        .send_to(
            REQUEST,
            SocketAddr::from(([255, 255, 255, 255], DISCOVERY_PORT)),
        )
        .await?;

    let deadline = Instant::now() + timeout;
    let mut results = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut buffer = [0u8; 2048];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let received = tokio::time::timeout(remaining, socket.recv_from(&mut buffer)).await;
        let Ok(Ok((length, source))) = received else {
            break;
        };
        let Ok(advertisement) = decode_advertisement(&buffer[..length]) else {
            continue;
        };
        if seen.insert(advertisement.fingerprint_hex.clone()) {
            results.push((
                SocketAddr::from((source.ip(), advertisement.listen_port)),
                advertisement,
            ));
        }
    }
    Ok(results)
}

fn validate(advertisement: &Advertisement) -> std::io::Result<()> {
    if advertisement.node_name.trim().is_empty()
        || advertisement.node_name.len() > MAX_DEVICE_NAME_BYTES
        || advertisement.node_name.chars().any(char::is_control)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery node name is empty or too long",
        ));
    }
    if advertisement.listen_port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery listen port must be non-zero",
        ));
    }
    if advertisement.fingerprint_hex.len() != 64
        || !advertisement
            .fingerprint_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "discovery fingerprint must contain 64 hexadecimal characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisements_round_trip_and_reject_untrusted_shapes() {
        let expected = Advertisement {
            node_name: "desk".into(),
            listen_port: 42110,
            fingerprint_hex: "ab".repeat(32),
        };
        let encoded = encode_advertisement(&expected).unwrap();
        assert_eq!(decode_advertisement(&encoded).unwrap(), expected);
        assert!(decode_advertisement(b"THEKVM-ADVERTISE/1\0{}").is_err());
        assert!(encode_advertisement(&Advertisement {
            node_name: "bad\nname".into(),
            ..expected.clone()
        })
        .is_err());
        assert!(!is_request(b"THEKVM-DISCOVER/0"));
        assert!(is_request(request()));
    }
}
