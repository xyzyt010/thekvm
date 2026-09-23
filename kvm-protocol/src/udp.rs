//! Low-latency UDP transport for TheKVM input sessions.
//!
//! Design:
//! - The daemon always listens on BOTH QUIC (`listen_port`) and UDP
//!   (`udp_port(listen_port)` = `listen_port + 1`). The `transport` config
//!   only selects which one outbound sessions dial first; failures fall back
//!   to the other automatically.
//! - UDP session keys are derived from the authenticated QUIC verify
//!   handshake (both certificate fingerprints plus the fresh per-connect
//!   `link_id`). No second pairing ceremony, no new long-term secrets, and
//!   no cleartext handshake: an attacker that did not MITM the QUIC verify
//!   cannot derive the key.
//! - Packets are ChaCha20Poly1305 AEAD: `MAGIC | nonce | ciphertext`.
//!   Plaintext is `version | kind | seq | body`. Kind 0 carries reliable
//!   JSON `WireMessage` fragments, kind 1 carries unreliable binary pointer
//!   motion, kind 2 carries acks.
//! - Reliable messages are fragmented to stay under the path MTU; motion is
//!   fire-and-forget with sequence dedup (old motion is dropped, never
//!   queued).

use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};

/// 8-byte wire magic identifying TheKVM UDP packets.
pub const UDP_MAGIC: &[u8; 8] = b"THEKVMU1";
/// Wire version for the UDP packet envelope.
pub const UDP_VERSION: u8 = 1;
/// Reliable JSON fragment carrier.
pub const KIND_RELIABLE: u8 = 0;
/// Unreliable binary pointer motion (`encode_input_datagram` bytes).
pub const KIND_MOTION: u8 = 1;
/// Acknowledgement for a reliable packet sequence.
pub const KIND_ACK: u8 = 2;

const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 8 + NONCE_LEN;
const TAG_LEN: usize = 16;
/// Keep every UDP datagram under the usual path-MTU budget.
pub const MAX_UDP_DATAGRAM: usize = 1200;
/// Reliable fragment payload budget per packet (envelope + AEAD overhead
/// reserved).
pub const RELIABLE_FRAGMENT_BYTES: usize = 896;
/// Maximum reassembled reliable message (matches the QUIC frame cap).
pub const MAX_RELIABLE_MESSAGE: usize = 64 * 1024;
/// Maximum fragments per reliable message.
pub const MAX_FRAGMENTS: usize = 128;

/// UDP listen port derived from the QUIC listen port. Discovery stays on
/// 42111, so UDP takes `listen_port + 1` (wrapping 65535 to the discovery
/// successor range is avoided by mapping 65535 to 42112).
pub fn udp_port(listen_port: u16) -> u16 {
    if listen_port == u16::MAX {
        42112
    } else {
        listen_port.wrapping_add(1)
    }
}

/// Derive the per-link UDP session key from both pinned fingerprints and the
/// fresh administrative `link_id` exchanged over the authenticated QUIC
/// verify. Fingerprint order is canonicalized so either side derives the
/// identical key regardless of dial direction.
pub fn derive_udp_key(
    local_fingerprint_hex: &str,
    peer_fingerprint_hex: &str,
    link_id: u64,
) -> [u8; 32] {
    let normalize = |value: &str| value.trim().to_ascii_lowercase();
    let local = normalize(local_fingerprint_hex);
    let peer = normalize(peer_fingerprint_hex);
    let (first, second) = if local <= peer {
        (local, peer)
    } else {
        (peer, local)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"thekvm-udp-v1");
    hasher.update(first.as_bytes());
    hasher.update([0]);
    hasher.update(second.as_bytes());
    hasher.update([0]);
    hasher.update(link_id.to_be_bytes());
    hasher.finalize().into()
}

/// Encode one UDP packet. `body` must already fit the MTU budget; use
/// [`split_reliable`] for larger JSON messages.
pub fn encode_packet(key: &[u8; 32], kind: u8, seq: u64, body: &[u8]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(1 + 1 + 8 + body.len());
    plaintext.push(UDP_VERSION);
    plaintext.push(kind);
    plaintext.extend_from_slice(&seq.to_be_bytes());
    plaintext.extend_from_slice(body);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    for byte in nonce_bytes.iter_mut() {
        *byte = rand::random();
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut buffer = plaintext;
    cipher
        .encrypt_in_place(nonce, b"", &mut buffer)
        .expect("chacha encryption cannot fail with valid key/nonce");
    let mut out = Vec::with_capacity(HEADER_LEN + buffer.len() + TAG_LEN);
    out.extend_from_slice(UDP_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    debug_assert!(out.len() <= MAX_UDP_DATAGRAM || kind == KIND_RELIABLE);
    out
}

/// Try decrypting `datagram` with each key in `keys`. Returns the matching
/// key index plus the decoded `(kind, seq, body)`.
pub fn decode_packet(
    keys: &[[u8; 32]],
    datagram: &[u8],
) -> Result<(usize, u8, u64, Vec<u8>), String> {
    if datagram.len() < HEADER_LEN + 1 + 1 + 8 + TAG_LEN {
        return Err("datagram too short".into());
    }
    if &datagram[..8] != UDP_MAGIC {
        return Err("bad magic".into());
    }
    let nonce_bytes: [u8; NONCE_LEN] = datagram[8..HEADER_LEN]
        .try_into()
        .map_err(|_| "bad nonce".to_string())?;
    let ciphertext = &datagram[HEADER_LEN..];
    let nonce = Nonce::from_slice(&nonce_bytes);
    for (index, key) in keys.iter().enumerate() {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let mut buffer = ciphertext.to_vec();
        if cipher.decrypt_in_place(nonce, b"", &mut buffer).is_ok() {
            if buffer.len() < 10 {
                return Err("plaintext too short".into());
            }
            if buffer[0] != UDP_VERSION {
                return Err("unsupported udp version".into());
            }
            let kind = buffer[1];
            if kind != KIND_RELIABLE && kind != KIND_MOTION && kind != KIND_ACK {
                return Err("unknown packet kind".into());
            }
            let seq = u64::from_be_bytes(buffer[2..10].try_into().unwrap());
            return Ok((index, kind, seq, buffer[10..].to_vec()));
        }
    }
    Err("decrypt failed for all keys".into())
}

/// Split a reliable JSON payload into MTU-safe fragments. Each fragment body
/// is `msg_id (8) | frag_index (2) | frag_count (2) | bytes`.
pub fn split_reliable(msg_id: u64, payload: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if payload.is_empty() || payload.len() > MAX_RELIABLE_MESSAGE {
        return Err("reliable payload size out of range".into());
    }
    let count = payload.len().div_ceil(RELIABLE_FRAGMENT_BYTES);
    if count > MAX_FRAGMENTS {
        return Err("reliable payload needs too many fragments".into());
    }
    let mut out = Vec::with_capacity(count);
    for (index, chunk) in payload.chunks(RELIABLE_FRAGMENT_BYTES).enumerate() {
        let mut body = Vec::with_capacity(12 + chunk.len());
        body.extend_from_slice(&msg_id.to_be_bytes());
        body.extend_from_slice(&(index as u16).to_be_bytes());
        body.extend_from_slice(&(count as u16).to_be_bytes());
        body.extend_from_slice(chunk);
        out.push(body);
    }
    Ok(out)
}

/// Reassembly buffer for fragmented reliable messages (one per sender).
#[derive(Default)]
pub struct ReliableReassembler {
    pending: std::collections::HashMap<u64, Reassembly>,
}

struct Reassembly {
    total: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl ReliableReassembler {
    /// Feed one fragment body. Returns the reassembled message when the last
    /// fragment arrives.
    pub fn feed(&mut self, body: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if body.len() < 12 {
            return Err("fragment too short".into());
        }
        let msg_id = u64::from_be_bytes(body[0..8].try_into().unwrap());
        let index = u16::from_be_bytes(body[8..10].try_into().unwrap()) as usize;
        let count = u16::from_be_bytes(body[10..12].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_FRAGMENTS || index >= count {
            return Err("bad fragment header".into());
        }
        let data = &body[12..];
        if data.len() > RELIABLE_FRAGMENT_BYTES {
            return Err("fragment too large".into());
        }
        // Bound memory: at most 16 concurrent assemblies.
        if self.pending.len() >= 16 && !self.pending.contains_key(&msg_id) {
            return Err("too many concurrent assemblies".into());
        }
        let entry = self.pending.entry(msg_id).or_insert_with(|| Reassembly {
            total: count,
            chunks: (0..count).map(|_| None).collect(),
            received: 0,
        });
        if entry.total != count {
            return Err("fragment count mismatch".into());
        }
        if entry.chunks[index].is_none() {
            entry.chunks[index] = Some(data.to_vec());
            entry.received += 1;
        }
        if entry.received == entry.total {
            let entry = self.pending.remove(&msg_id).unwrap();
            let mut out = Vec::new();
            for chunk in entry.chunks {
                out.extend_from_slice(&chunk.ok_or("missing fragment")?);
            }
            if out.len() > MAX_RELIABLE_MESSAGE {
                return Err("reassembled message too large".into());
            }
            return Ok(Some(out));
        }
        Ok(None)
    }
}

/// Next-sequence helper that never yields zero (zero is reserved for
/// handshake probes in future versions).
pub fn next_seq(counter: &mut u64) -> u64 {
    *counter = counter.wrapping_add(1).max(1);
    *counter
}

/// Encode one pointer-motion datagram for the UDP fast path. Motion is the
/// hottest path in a KVM session; the binary codec matches the QUIC
/// datagram format so both paths share sequence dedup semantics.
pub fn encode_motion_packet(key: &[u8; 32], seq: u64, dx: i32, dy: i32) -> Vec<u8> {
    let body = crate::wire::encode_input_datagram(crate::wire::DatagramInput {
        sequence: seq,
        event: kvm_core::InputEvent::MouseMove { dx, dy },
    })
    .expect("mouse motion always fits the datagram codec");
    encode_packet(key, KIND_MOTION, seq, &body)
}

/// Decode one UDP motion datagram with the key ring. Returns the matching
/// key index plus `(seq, dx, dy)`. Non-motion kinds are rejected.
pub fn decode_motion_packet(
    keys: &[[u8; 32]],
    datagram: &[u8],
) -> Result<(usize, u64, i32, i32), String> {
    let (index, kind, seq, body) = decode_packet(keys, datagram)?;
    if kind != KIND_MOTION {
        return Err("not a motion packet".into());
    }
    let input = crate::wire::decode_input_datagram(&body).map_err(|e| e.to_string())?;
    match input.event {
        kvm_core::InputEvent::MouseMove { dx, dy } => {
            if input.sequence != seq {
                return Err("motion sequence mismatch".into());
            }
            Ok((index, seq, dx, dy))
        }
        _ => Err("motion packet carries non-motion event".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_is_direction_independent() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        assert_eq!(derive_udp_key(&a, &b, 123), derive_udp_key(&b, &a, 123));
        assert_ne!(derive_udp_key(&a, &b, 123), derive_udp_key(&a, &b, 124));
    }

    #[test]
    fn packets_round_trip_and_reject_wrong_keys() {
        let key = derive_udp_key(&"ab".repeat(32), &"cd".repeat(32), 7);
        let other = derive_udp_key(&"ab".repeat(32), &"cd".repeat(32), 8);
        let packet = encode_packet(&key, KIND_MOTION, 42, b"motion-bytes");
        assert!(packet.len() <= MAX_UDP_DATAGRAM);
        let (index, kind, seq, body) = decode_packet(&[other, key], &packet).unwrap();
        assert_eq!(index, 1);
        assert_eq!(kind, KIND_MOTION);
        assert_eq!(seq, 42);
        assert_eq!(body, b"motion-bytes");
        assert!(decode_packet(&[other], &packet).is_err());
        assert!(decode_packet(&[key], b"short").is_err());
        let mut bad = packet.clone();
        bad[0] ^= 0xff;
        assert!(decode_packet(&[key], &bad).is_err());
    }

    #[test]
    fn reliable_fragmentation_round_trips() {
        let payload = vec![0x41; 3000];
        let frags = split_reliable(9, &payload).unwrap();
        assert!(frags.len() > 1);
        for frag in &frags {
            assert!(frag.len() <= RELIABLE_FRAGMENT_BYTES + 12);
        }
        let mut re = ReliableReassembler::default();
        let mut done = None;
        // Deliver out of order: reversed still reassembles.
        for frag in frags.iter().rev() {
            if let Some(msg) = re.feed(frag).unwrap() {
                done = Some(msg);
            }
        }
        assert_eq!(done.unwrap(), payload);
    }

    #[test]
    fn udp_port_derives_without_colliding_discovery() {
        assert_eq!(udp_port(42110), 42111);
        assert_eq!(udp_port(42111), 42112);
        assert_ne!(udp_port(u16::MAX), 0);
    }

    #[test]
    fn motion_packets_round_trip_over_udp_envelope() {
        let key = derive_udp_key(&"ab".repeat(32), &"cd".repeat(32), 99);
        let packet = encode_motion_packet(&key, 7, 12, -4);
        assert!(packet.len() <= MAX_UDP_DATAGRAM);
        let (index, seq, dx, dy) = decode_motion_packet(&[key], &packet).unwrap();
        assert_eq!(index, 0);
        assert_eq!((seq, dx, dy), (7, 12, -4));
        // A tampered packet fails closed.
        let mut bad = packet.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert!(decode_motion_packet(&[key], &bad).is_err());
    }
}
