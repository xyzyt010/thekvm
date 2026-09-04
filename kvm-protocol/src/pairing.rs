//! First-run identity generation and pairing state.

use kvm_core::MAX_DEVICE_NAME_BYTES;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::io::Write;
use std::path::PathBuf;

const MAX_TRUSTED_PEERS: usize = 256;
const MAX_PEER_ADDRESS_BYTES: usize = 256;

#[derive(Debug, Clone)]
pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// SHA-256 fingerprint of the DER cert — this is what gets pinned.
    pub fingerprint: [u8; 32],
}

impl Identity {
    /// Load from disk or generate fresh on first run.
    pub fn load_or_create(dir: &std::path::Path) -> std::io::Result<Self> {
        let cert_path = dir.join("identity.cert");
        let key_path = dir.join("identity.key");
        if cert_path.exists() && key_path.exists() {
            let cert_der = std::fs::read(&cert_path)?;
            let stored_key = std::fs::read(&key_path)?;
            #[cfg(target_os = "windows")]
            let key_der = if stored_key.starts_with(windows_dpapi::MAGIC) {
                windows_dpapi::unprotect(&stored_key[windows_dpapi::MAGIC.len()..])?
            } else {
                // Migrate identities created by versions before DPAPI support.
                // The service performs this once under the account that owns
                // the identity, then the raw legacy key is no longer retained.
                let protected = windows_dpapi::protect(&stored_key)?;
                let mut encoded = windows_dpapi::MAGIC.to_vec();
                encoded.extend_from_slice(&protected);
                atomic_write(&key_path, &encoded, true)?;
                stored_key
            };
            #[cfg(not(target_os = "windows"))]
            let key_der = {
                // Older development builds could create the identity before
                // the private-file mode was applied. Repair that state on
                // every load so a pre-existing key cannot remain readable by
                // other Unix users after an upgrade.
                harden_private_key(&key_path)?;
                stored_key
            };
            let fingerprint = sha256(&cert_der);
            return Ok(Self {
                cert_der,
                key_der,
                fingerprint,
            });
        }

        Self::create_and_store(dir)
    }

    /// Generate a replacement certificate/key pair in the existing identity
    /// directory. The caller must stop the daemon first so no listener keeps
    /// using the old certificate while the files are replaced. Trusted peer
    /// records are intentionally left untouched: peers that this node
    /// connects to still have the same identities, while peers that accept
    /// this node must be paired again against the new fingerprint.
    pub fn rotate(dir: &std::path::Path) -> std::io::Result<Self> {
        Self::create_and_store(dir)
    }

    fn create_and_store(dir: &std::path::Path) -> std::io::Result<Self> {
        let (cert_der, key_der) = generate_material()?;
        let cert_path = dir.join("identity.cert");
        let key_path = dir.join("identity.key");
        std::fs::create_dir_all(dir)?;
        atomic_write(&cert_path, &cert_der, false)?;
        let stored_key = stored_key_bytes(&key_der)?;
        atomic_write(&key_path, &stored_key, true)?;
        let fingerprint = sha256(&cert_der);
        Ok(Self {
            cert_der,
            key_der,
            fingerprint,
        })
    }

    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

fn generate_material() -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec![hostname()]).map_err(std::io::Error::other)?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

fn stored_key_bytes(key_der: &[u8]) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        let mut encoded = windows_dpapi::MAGIC.to_vec();
        encoded.extend_from_slice(&windows_dpapi::protect(key_der)?);
        Ok(encoded)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(key_der.to_vec())
    }
}

#[cfg(target_os = "windows")]
mod windows_dpapi {
    use std::ffi::c_void;
    use std::io;
    use std::ptr;

    /// A small file marker makes the on-disk format unambiguous and permits a
    /// one-time migration of pre-DPAPI raw identity keys.
    pub const MAGIC: &[u8] = b"THEKVM-DPAPI\0";
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    // The daemon identity lives in the machine-wide service directory and is
    // intentionally usable by both an elevated CLI and the LocalSystem
    // service. The installer restricts that directory to SYSTEM and local
    // Administrators; DPAPI still prevents the key from being useful off-host.
    const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "Crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            description: *const u16,
            optional_entropy: *const DataBlob,
            reserved: *const c_void,
            prompt: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            description: *const *mut u16,
            optional_entropy: *const DataBlob,
            reserved: *const c_void,
            prompt: *const c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    pub fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
        transform(data, true)
    }

    pub fn unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
        transform(data, false)
    }

    fn transform(data: &[u8], protect: bool) -> io::Result<Vec<u8>> {
        let length = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "identity key is too large")
        })?;
        let input = DataBlob {
            cb_data: length,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut output = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };
        let success = unsafe {
            if protect {
                CryptProtectData(
                    &input,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                    &mut output,
                )
            } else {
                CryptUnprotectData(
                    &input,
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                    &mut output,
                )
            }
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }

        let result = if output.pb_data.is_null() && output.cb_data != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows DPAPI returned an empty key buffer",
            ));
        } else if output.pb_data.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(output.pb_data, output.cb_data as usize) }.to_vec()
        };
        if !output.pb_data.is_null() {
            unsafe {
                let _ = LocalFree(output.pb_data.cast());
            }
        }
        Ok(result)
    }
}

/// Derive the six-digit pairing verification code shared by both endpoints
/// of a pairing ceremony.
///
/// Both endpoints know exactly two certificate fingerprints: their own
/// identity and the TLS-observed peer identity. A short, deterministic code
/// derived from that unordered pair lets a human compare six digits instead
/// of 128 hexadecimal characters, in the same spirit as Bluetooth numeric
/// comparison. The fingerprints are ordered byte-lexicographically before
/// hashing, so either endpoint derives the identical code regardless of which
/// side initiated the pairing, and a domain-separation prefix keeps this
/// derivation from being confused with the plain certificate fingerprint.
/// The result is formatted with leading zeros so it is always six digits.
pub fn verification_code(local_fingerprint_hex: &str, peer_fingerprint_hex: &str) -> String {
    use sha2::{Digest, Sha256};

    const VERIFICATION_CODE_DOMAIN: &[u8] = b"THEKVM-PAIRING-CODE-V1";
    let normalize = |value: &str| value.trim().to_ascii_lowercase();
    let local = normalize(local_fingerprint_hex);
    let peer = normalize(peer_fingerprint_hex);
    let (first, second) = if local <= peer {
        (local, peer)
    } else {
        (peer, local)
    };
    let mut hasher = Sha256::new();
    hasher.update(VERIFICATION_CODE_DOMAIN);
    hasher.update(first.as_bytes());
    hasher.update([0]);
    hasher.update(second.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let value = u64::from_be_bytes([
        0, 0, digest[0], digest[1], digest[2], digest[3], digest[4], digest[5],
    ]);
    format!("{:06}", value % 1_000_000)
}

/// The pinned set of peers we trust.
#[derive(Debug, Default, Clone)]
pub struct PeerBook {
    path: PathBuf,
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Peer {
    pub name: String,
    pub fingerprint_hex: String,
    #[serde(default)]
    pub address: Option<String>,
}

impl PeerBook {
    pub fn load_or_create(dir: &std::path::Path) -> std::io::Result<Self> {
        let path = dir.join("peers.json");
        let mut peers = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?).map_err(std::io::Error::other)?
        } else {
            Vec::new()
        };
        normalize_and_validate_peers(&mut peers, std::io::ErrorKind::InvalidData)?;
        Ok(Self { path, peers })
    }

    pub fn is_pinned(&self, fingerprint_hex: &str) -> bool {
        self.peers
            .iter()
            .any(|p| p.fingerprint_hex == fingerprint_hex)
    }

    pub fn pin(&mut self, name: impl Into<String>, fingerprint_hex: String) -> std::io::Result<()> {
        self.pin_with_address(name, fingerprint_hex, None)
    }

    pub fn pin_with_address(
        &mut self,
        name: impl Into<String>,
        fingerprint_hex: String,
        address: Option<String>,
    ) -> std::io::Result<()> {
        let name = name.into().trim().to_owned();
        let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
        let address = address.map(|address| address.trim().to_owned());
        validate_peer_fields(
            &name,
            &fingerprint_hex,
            address.as_deref(),
            std::io::ErrorKind::InvalidInput,
        )?;
        if !self.is_pinned(&fingerprint_hex) {
            if self.peers.len() >= MAX_TRUSTED_PEERS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("trusted peer limit of {MAX_TRUSTED_PEERS} reached"),
                ));
            }
            self.peers.push(Peer {
                name,
                fingerprint_hex,
                address,
            });
            self.save()?;
        } else if let Some(peer) = self
            .peers
            .iter_mut()
            .find(|peer| peer.fingerprint_hex == fingerprint_hex)
        {
            let mut changed = false;
            if peer.name != name {
                peer.name = name;
                changed = true;
            }
            if address.is_some() && peer.address != address {
                peer.address = address;
                changed = true;
            }
            if changed {
                self.save()?;
            }
        }
        Ok(())
    }

    /// Remove a previously trusted peer. Revocation is deliberately explicit;
    /// deleting a certificate file must not silently repopulate this trust
    /// list on the next connection.
    pub fn unpin(&mut self, fingerprint_hex: &str) -> std::io::Result<bool> {
        let fingerprint_hex = fingerprint_hex.to_ascii_lowercase();
        let original_len = self.peers.len();
        self.peers
            .retain(|peer| peer.fingerprint_hex != fingerprint_hex);
        if self.peers.len() == original_len {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    fn save(&self) -> std::io::Result<()> {
        let mut peers = self.peers.clone();
        normalize_and_validate_peers(&mut peers, std::io::ErrorKind::InvalidData)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&peers)?;
        atomic_write(&self.path, &bytes, false)
    }
}

fn normalize_and_validate_peers(
    peers: &mut [Peer],
    kind: std::io::ErrorKind,
) -> std::io::Result<()> {
    if peers.len() > MAX_TRUSTED_PEERS {
        return Err(std::io::Error::new(
            kind,
            format!("trusted peer list exceeds {MAX_TRUSTED_PEERS} entries"),
        ));
    }
    for peer in peers.iter_mut() {
        peer.name = peer.name.trim().to_owned();
        peer.fingerprint_hex = peer.fingerprint_hex.to_ascii_lowercase();
        peer.address = peer.address.take().map(|address| address.trim().to_owned());
        validate_peer_fields(
            &peer.name,
            &peer.fingerprint_hex,
            peer.address.as_deref(),
            kind,
        )?;
    }
    let mut fingerprints = std::collections::HashSet::with_capacity(peers.len());
    if peers
        .iter()
        .any(|peer| !fingerprints.insert(peer.fingerprint_hex.as_str()))
    {
        return Err(std::io::Error::new(
            kind,
            "trusted peer list contains duplicates",
        ));
    }
    Ok(())
}

fn validate_peer_fields(
    name: &str,
    fingerprint_hex: &str,
    address: Option<&str>,
    kind: std::io::ErrorKind,
) -> std::io::Result<()> {
    if name.is_empty() || name.len() > MAX_DEVICE_NAME_BYTES || name.chars().any(char::is_control) {
        return Err(std::io::Error::new(
            kind,
            "peer name is empty, too long, or contains control characters",
        ));
    }
    if fingerprint_hex.len() != 64 || !fingerprint_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            kind,
            "peer fingerprint must contain 64 hexadecimal characters",
        ));
    }
    if address.is_some_and(|address| {
        address.is_empty()
            || address.len() > MAX_PEER_ADDRESS_BYTES
            || address.chars().any(char::is_control)
    }) {
        return Err(std::io::Error::new(
            kind,
            "peer address is empty, too long, or contains control characters",
        ));
    }
    Ok(())
}

fn atomic_write(path: &std::path::Path, bytes: &[u8], private: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| {
        #[cfg(not(unix))]
        let _ = private;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(source, destination)
}

#[cfg(windows)]
fn replace_file(source: &std::path::Path, destination: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "Kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "thekvm-node".into())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(unix)]
fn harden_private_key(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    #[test]
    fn dpapi_round_trips_identity_key_bytes() {
        let original = b"thekvm-test-private-key";
        let protected = super::windows_dpapi::protect(original).unwrap();
        assert_ne!(protected, original);
        assert_eq!(
            super::windows_dpapi::unprotect(&protected).unwrap(),
            original
        );
    }

    #[test]
    fn identity_file_uses_dpapi_marker_on_windows() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-dpapi-identity-{nonce}"));
        let identity = super::Identity::load_or_create(&root).unwrap();
        let stored = std::fs::read(root.join("identity.key")).unwrap();
        assert!(stored.starts_with(super::windows_dpapi::MAGIC));
        let reloaded = super::Identity::load_or_create(&root).unwrap();
        assert_eq!(identity.fingerprint, reloaded.fingerprint);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn identity_rotation_replaces_the_pinned_fingerprint() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-rotate-identity-{nonce}"));
        let original = super::Identity::load_or_create(&root).unwrap();
        let rotated = super::Identity::rotate(&root).unwrap();
        assert_ne!(original.fingerprint, rotated.fingerprint);
        let reloaded = super::Identity::load_or_create(&root).unwrap();
        assert_eq!(reloaded.fingerprint, rotated.fingerprint);
        let stored = std::fs::read(root.join("identity.key")).unwrap();
        assert!(stored.starts_with(super::windows_dpapi::MAGIC));
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::Identity;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn existing_identity_key_is_restricted_on_load() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-key-permissions-{nonce}"));
        let identity = Identity::load_or_create(&root).unwrap();
        let key_path = root.join("identity.key");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let loaded = Identity::load_or_create(&root).unwrap();
        assert_eq!(loaded.fingerprint, identity.fingerprint);
        assert_eq!(
            std::fs::metadata(key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn identity_rotation_replaces_the_pinned_fingerprint() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-rotate-identity-{nonce}"));
        let original = Identity::load_or_create(&root).unwrap();
        let rotated = Identity::rotate(&root).unwrap();
        assert_ne!(original.fingerprint, rotated.fingerprint);
        let reloaded = Identity::load_or_create(&root).unwrap();
        assert_eq!(reloaded.fingerprint, rotated.fingerprint);
        assert_eq!(
            std::fs::metadata(root.join("identity.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    #[test]
    fn peer_book_normalizes_fingerprints_and_rejects_bad_metadata() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-peer-book-{nonce}"));
        let mut peers = PeerBook::load_or_create(&root).unwrap();
        let fingerprint = "AB".repeat(32);
        peers
            .pin_with_address(
                "  office  ",
                fingerprint,
                Some("  127.0.0.1:42110  ".into()),
            )
            .unwrap();
        assert_eq!(peers.peers[0].name, "office");
        assert_eq!(peers.peers[0].fingerprint_hex, "ab".repeat(32));
        assert_eq!(peers.peers[0].address.as_deref(), Some("127.0.0.1:42110"));
        assert!(peers.unpin(&"AB".repeat(32)).unwrap());

        assert!(peers.pin("bad\nname", "ab".repeat(32)).is_err());
        assert!(peers
            .pin("bad fingerprint", "not-a-fingerprint".into())
            .is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn peer_book_rejects_duplicate_persisted_fingerprints() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("thekvm-peer-duplicate-{nonce}"));
        std::fs::create_dir_all(&root).unwrap();
        let fingerprint = "cd".repeat(32);
        let raw = serde_json::json!([
            {"name":"one","fingerprint_hex":fingerprint,"address":null},
            {"name":"two","fingerprint_hex":fingerprint.to_ascii_uppercase(),"address":null}
        ]);
        std::fs::write(root.join("peers.json"), serde_json::to_vec(&raw).unwrap()).unwrap();
        assert!(PeerBook::load_or_create(&root).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod verification_code_tests {
    use super::verification_code;

    #[test]
    fn code_is_symmetric_in_argument_order() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        assert_eq!(
            verification_code(&a, &b),
            verification_code(&b, &a),
            "either endpoint must derive the identical code"
        );
    }

    #[test]
    fn code_is_case_insensitive_and_trimmed() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        assert_eq!(
            verification_code(&a.to_ascii_uppercase(), &b.to_ascii_uppercase()),
            verification_code(&a, &b)
        );
        assert_eq!(
            verification_code(&format!(" {a} "), &b),
            verification_code(&a, &b)
        );
    }

    #[test]
    fn code_is_exactly_six_digits() {
        for (a, b) in [
            ("ab".repeat(32), "cd".repeat(32)),
            ("00".repeat(32), "ff".repeat(32)),
            ("0a".repeat(32), "0b".repeat(32)),
        ] {
            let code = verification_code(&a, &b);
            assert_eq!(code.len(), 6);
            assert!(code.bytes().all(|byte| byte.is_ascii_digit()));
        }
    }

    #[test]
    fn distinct_fingerprint_pairs_usually_derive_distinct_codes() {
        let base = "ab".repeat(32);
        let codes = [
            verification_code(&base, &"cd".repeat(32)),
            verification_code(&base, &"ce".repeat(32)),
            verification_code(&base, &"dd".repeat(32)),
            verification_code(&base, &"ee".repeat(32)),
        ];
        let unique: std::collections::HashSet<&str> = codes.iter().map(String::as_str).collect();
        assert!(unique.len() > 1);
    }

    #[test]
    fn derivation_is_stable_for_the_same_pair() {
        let a = "ab".repeat(32);
        let b = "cd".repeat(32);
        let first = verification_code(&a, &b);
        assert_eq!(first, verification_code(&a, &b));
    }
}
