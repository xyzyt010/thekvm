//! Pairing invite: a small, human-transferable token carrying everything the
//! other machine needs to reach us over QUIC.
//!
//! The invite is a compact `thekvm://v1/<address>#<fingerprint>` URL. It is
//! shown as plain text (copy/paste between machines) and rendered as a QR code
//! on the owning machine so a phone camera or the peer's user can transfer it.
//! It carries the listen address and the certificate fingerprint only; the
//! actual trust decision still goes through the normal QUIC pairing ceremony
//! (fingerprint display, numeric comparison, and explicit mutual approvals).
//! An empty address fragment remains valid so a QR from a machine whose
//! address is not yet known can still be scanned and paired by IP entry.

use crate::pairing;

use std::net::{IpAddr, SocketAddr, UdpSocket};

/// URI scheme prefix for an invite.
pub const INVITE_SCHEME: &str = "thekvm://v1/";

/// Find the local IPv4 address used to reach the LAN, using the standard
/// UDP-socket route lookup (`connect` on a datagram socket selects the local
/// address without sending any packet). Returns `None` when no route or
/// non-IPv4 address is selected, in which case callers fall back to manual
/// address entry.
pub fn lan_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // Link-local documentation address: `connect` on UDP never transmits, it
    // only resolves which local interface the OS would use.
    socket.connect(SocketAddr::from(([192, 0, 2, 1], 9))).ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) => Some(IpAddr::V4(*addr.ip())),
        SocketAddr::V6(_) => None,
    }
}

/// Decode a pairing invite into its address and certificate fingerprint.
///
/// Accepts `thekvm://v1/<address>#<64-hex>` as well as the permissive forms
/// produced by scanning/pasting (`thekvm://<address>#<fingerprint>`, or a bare
/// `<address>#<fingerprint>`). The address may contain a port. The fingerprint
/// is canonicalised to lowercase. Returns `(address, fingerprint_hex)`.
pub fn parse(text: &str) -> std::io::Result<(String, String)> {
    let trimmed = text.trim();
    let lowered = trimmed.to_ascii_lowercase();
    let body = lowered
        .strip_prefix(INVITE_SCHEME)
        .map(|rest| &trimmed[trimmed.len() - rest.len()..])
        .or_else(|| {
            lowered
                .strip_prefix("thekvm://")
                .map(|rest| &trimmed[trimmed.len() - rest.len()..])
        })
        .unwrap_or(trimmed);
    let (address, fingerprint) = body.rsplit_once('#').ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invite must contain '#<certificate fingerprint>'",
        )
    })?;
    let address = address.trim().to_owned();
    let fingerprint = fingerprint.trim().to_ascii_lowercase();
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invite fingerprint must contain 64 hexadecimal characters",
        ));
    }
    if address.chars().any(char::is_control) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invite address contains control characters",
        ));
    }
    Ok((address, fingerprint))
}

/// Encode an invite for the given address and certificate fingerprint.
pub fn build(address: &str, fingerprint_hex: &str) -> std::io::Result<String> {
    let fingerprint = fingerprint_hex.trim().to_ascii_lowercase();
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fingerprint must contain 64 hexadecimal characters",
        ));
    }
    if address.chars().any(char::is_control) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "address contains control characters",
        ));
    }
    Ok(format!("{INVITE_SCHEME}{}#{}", address.trim(), fingerprint))
}

/// Convenience: the invite plus the six-digit numeric pairing code that two
/// already-connected endpoints derive during the QUIC ceremony. Used by the
/// initating UI to show the operator what the other side will display, without
/// another round-trip.
pub fn describe(
    address: &str,
    fingerprint_hex: &str,
    peer_fingerprint_hex: &str,
) -> std::io::Result<(String, String)> {
    let invite = build(address, fingerprint_hex)?;
    let code = pairing::verification_code(fingerprint_hex, peer_fingerprint_hex);
    Ok((invite, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_normalises() {
        let fingerprint = "AB".repeat(32);
        let invite = build("192.168.0.12:42110", &fingerprint).unwrap();
        assert_eq!(
            invite,
            format!(
                "thekvm://v1/192.168.0.12:42110#{}",
                fingerprint.to_ascii_lowercase()
            )
        );
        let (address, parsed) = parse(&invite).unwrap();
        assert_eq!(address, "192.168.0.12:42110");
        assert_eq!(parsed, fingerprint.to_ascii_lowercase());
    }

    #[test]
    fn parse_accepts_legacy_and_pasted_forms() {
        let fingerprint = "cd".repeat(32);
        for text in [
            format!("thekvm://v1/host:42110#{fingerprint}"),
            format!("thekvm://host:42110#{fingerprint}"),
            format!("host:42110#{fingerprint}"),
            format!("  thekvm://v1/host:42110#{fingerprint}  "),
            format!("THEKVM://v1/host:42110#{fingerprint}"),
        ] {
            let (address, parsed) =
                parse(&text).unwrap_or_else(|error| panic!("failed to parse {text:?}: {error}"));
            assert_eq!(address, "host:42110");
            assert_eq!(parsed, fingerprint);
        }
    }

    #[test]
    fn parse_rejects_missing_or_invalid_fingerprints() {
        assert!(parse("thekvm://v1/host:42110").is_err());
        assert!(parse("thekvm://v1/host:42110#not-a-fingerprint").is_err());
        assert!(parse("thekvm://v1/host:42110#ab12").is_err());
        assert!(build("host:42110", "not-a-fingerprint").is_err());
    }

    #[test]
    fn describe_returns_invite_and_shared_numeric_code() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        let (invite, code) = describe("10.0.0.5:42110", &a, &b).unwrap();
        assert!(invite.contains(&a));
        assert_eq!(code, pairing::verification_code(&a, &b));
        assert_eq!(code, pairing::verification_code(&b, &a));
    }

    #[test]
    fn lan_address_lookup_does_not_panic() {
        // Environment-dependent: sandboxes or offline hosts may have no
        // route. The only guarantee is that the lookup never fails loudly.
        if let Some(address) = lan_address() {
            assert!(!address.is_unspecified());
        }
    }
}
