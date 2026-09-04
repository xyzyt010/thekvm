//! QUIC endpoint setup with mutual cert pinning.

use crate::pairing::Identity;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::time::Duration;

const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const DATAGRAM_RECEIVE_BUFFER: usize = 64 * 1024;

fn input_transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // Input sessions must notice a dead peer quickly, while keep-alives keep
    // NAT/firewall state warm during idle periods such as a password prompt.
    transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        MAX_IDLE_TIMEOUT.as_millis() as u32,
    ))));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER));
    transport
}

pub fn make_server_endpoint(
    identity: &Identity,
    port: u16,
) -> Result<quinn::Endpoint, crate::ProtocolError> {
    make_server_endpoint_at(identity, std::net::SocketAddr::from(([0, 0, 0, 0], port)))
}

fn make_server_endpoint_at(
    identity: &Identity,
    addr: std::net::SocketAddr,
) -> Result<quinn::Endpoint, crate::ProtocolError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key_der.clone(),
    ));

    // Require client certificates so we can fingerprint-pin peers.
    let client_verifier = std::sync::Arc::new(AnyClientCertVerifier);
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], key)
        .map_err(|e| crate::ProtocolError::Tls(format!("bad cert: {e}")))?;
    server_crypto.alpn_protocols = vec![b"thekvm/1".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| crate::ProtocolError::Tls(e.to_string()))?,
    ));
    server_config.transport_config(std::sync::Arc::new(input_transport_config()));

    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    Ok(endpoint)
}

/// Build a client endpoint for first-run pairing. The server certificate is
/// authenticated by the QUIC/TLS signature, but its identity is intentionally
/// accepted until the application displays and confirms its fingerprint.
pub fn make_client_endpoint(identity: &Identity) -> Result<quinn::Endpoint, crate::ProtocolError> {
    make_client_endpoint_with_pin(identity, None)
}

/// Build a client endpoint for an already-paired peer. The certificate pin is
/// checked inside the TLS handshake so an untrusted server cannot reach the
/// application protocol. Pairing callers must use `make_client_endpoint`.
pub fn make_pinned_client_endpoint(
    identity: &Identity,
    expected_fingerprint_hex: &str,
) -> Result<quinn::Endpoint, crate::ProtocolError> {
    let expected_fingerprint = parse_fingerprint(expected_fingerprint_hex)?;
    make_client_endpoint_with_pin(identity, Some(expected_fingerprint))
}

fn make_client_endpoint_with_pin(
    identity: &Identity,
    expected_fingerprint: Option<[u8; 32]>,
) -> Result<quinn::Endpoint, crate::ProtocolError> {
    let cert = CertificateDer::from(identity.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        identity.key_der.clone(),
    ));

    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(PinnedVerifier {
            expected_fingerprint,
        }))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| crate::ProtocolError::Tls(format!("bad cert: {e}")))?;
    client_crypto.alpn_protocols = vec![b"thekvm/1".to_vec()];

    // Input events want low latency over throughput.
    let transport = input_transport_config();

    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| crate::ProtocolError::Tls(e.to_string()))?,
    ));
    client_config.transport_config(std::sync::Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn parse_fingerprint(value: &str) -> Result<[u8; 32], crate::ProtocolError> {
    if value.len() != 64 {
        return Err(crate::ProtocolError::Tls(
            "peer fingerprint must contain 64 hexadecimal characters".into(),
        ));
    }
    let mut fingerprint = [0u8; 32];
    for (index, byte) in fingerprint.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| {
            crate::ProtocolError::Tls("peer fingerprint contains non-hexadecimal data".into())
        })?;
    }
    Ok(fingerprint)
}

/// Server-side verifier that accepts any client cert. Actual authorization
/// happens at the session layer: the daemon fingerprints the presented cert
/// and checks it against the PeerBook before doing anything privileged.
#[derive(Debug)]
struct AnyClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for AnyClientCertVerifier {
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

/// Verifier that accepts any cert but records its fingerprint; the caller
/// checks it against the PeerBook before doing anything privileged.
#[derive(Debug)]
struct PinnedVerifier {
    expected_fingerprint: Option<[u8; 32]>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(expected) = self.expected_fingerprint {
            use sha2::{Digest, Sha256};
            let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if actual != expected {
                return Err(rustls::Error::General(
                    "server certificate fingerprint does not match the paired peer".into(),
                ));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::Identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn mutually_authenticated_quic_endpoint_accepts_datagram() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-transport-test-{nonce}"));
        let server_identity = Identity::load_or_create(&root.join("server")).unwrap();
        let client_identity = Identity::load_or_create(&root.join("client")).unwrap();
        let server = make_server_endpoint_at(
            &server_identity,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = make_client_endpoint(&client_identity).unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("server endpoint closed");
            let connection = incoming.await.unwrap();
            let payload = connection.read_datagram().await.unwrap();
            assert_eq!(payload.as_ref(), b"motion");
            connection.close(0u32.into(), b"done");
        });
        let connection = client
            .connect(server_addr, "thekvm")
            .unwrap()
            .await
            .unwrap();
        assert!(connection.peer_identity().is_some());
        connection.send_datagram(b"motion".to_vec().into()).unwrap();
        server_task.await.unwrap();
        client.close(0u32.into(), b"done");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn pinned_client_rejects_a_different_server_certificate() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-pinned-transport-test-{nonce}"));
        let server_identity = Identity::load_or_create(&root.join("server")).unwrap();
        let client_identity = Identity::load_or_create(&root.join("client")).unwrap();
        let wrong_identity = Identity::load_or_create(&root.join("wrong")).unwrap();
        let server = make_server_endpoint_at(
            &server_identity,
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .unwrap();
        let server_addr = server.local_addr().unwrap();
        let client =
            make_pinned_client_endpoint(&client_identity, &wrong_identity.fingerprint_hex())
                .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.connect(server_addr, "thekvm").unwrap(),
        )
        .await;
        assert!(matches!(result, Err(_) | Ok(Err(_))));
        client.close(0u32.into(), b"done");
        server.close(0u32.into(), b"done");
        let _ = std::fs::remove_dir_all(root);
    }
}
