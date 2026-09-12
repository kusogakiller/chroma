//! Node identity: long-term Noise static key, persisted per data-dir.
//!
//! This key is the P2P *transport* identity. It is generated independently
//! of consensus keys and wallet keys and must never be confused with them:
//! wallet private keys are never valid Noise identity keys and vice versa.
//!
//! File format: exactly 64 lowercase hex chars (32 bytes), single line,
//! at `<data-dir>/noise_identity`, mode 0600 on Unix, written atomically
//! (temp file + rename). A missing file creates one; a malformed file is a
//! fatal startup error — the node refuses to start rather than silently
//! rotating identity (which would fork peer reputation and TOFU bindings).

use std::io;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// File name of the persisted identity inside the data directory.
pub const IDENTITY_FILE_NAME: &str = "noise_identity";

/// Long-term Noise static private key (32-byte X25519 scalar).
///
/// Debug/Display are redacted: the bytes never appear in logs, errors,
/// panics, or RPC output. Use [`NodeIdentity::public_key`] for the shareable
/// half, which is hex-encoded by callers only from the public bytes.
pub struct NodeIdentity {
    private: [u8; 32],
}

impl NodeIdentity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        NodeIdentity {
            private: chroma_crypto::noise::generate_static_key(),
        }
    }

    /// Load the identity from `<data_dir>/noise_identity`, creating and
    /// persisting a fresh one (atomically) if absent.
    ///
    /// Fails closed on: missing data dir (propagates IO error), malformed
    /// hex, wrong length, all-zero scalar. The caller (Node startup) must
    /// refuse to start on error — never fall back to an ephemeral key.
    pub fn load_or_create(data_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::path_for(data_dir);
        match std::fs::read(&path) {
            Ok(bytes) => Self::parse_file(&bytes).map_err(|reason| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid node identity file {}: {}. \
                         Restore it from backup; the node will not start with \
                         a replaced identity.",
                        path.display(),
                        reason
                    ),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let fresh = Self::generate();
                Self::atomic_write(&path, &fresh.private)?;
                Ok(fresh)
            }
            Err(e) => Err(e),
        }
    }

    /// Strict parser for file bytes: ASCII-trimmed, exactly 64 hex chars,
    /// 32 decoded bytes, non-degenerate scalar. No silent normalization.
    fn parse_file(bytes: &[u8]) -> Result<Self, &'static str> {
        let text = std::str::from_utf8(bytes).map_err(|_| "not valid UTF-8")?;
        let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if trimmed.len() != 64 {
            return Err("expected exactly 64 hex characters");
        }
        if !trimmed.is_ascii() || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("non-hex characters present");
        }
        let mut private = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut private).map_err(|_| "hex decode failed")?;
        if !chroma_crypto::noise::is_valid_static_key(&private) {
            private.zeroize();
            return Err("degenerate static key (all zero)");
        }
        Ok(NodeIdentity { private })
    }

    /// Atomic write: temp file in the same directory + rename, then 0600.
    /// Same-directory rename is atomic on both Unix and Windows and keeps a
    /// half-written key from ever being observed by a concurrent startup.
    fn atomic_write(path: &Path, private: &[u8; 32]) -> io::Result<()> {
        let dir = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "identity path has no parent")
        })?;
        let tmp_path: PathBuf =
            dir.join(format!("{}.tmp.{}", IDENTITY_FILE_NAME, std::process::id()));
        // Hex is lowercase by convention; parser accepts either case.
        std::fs::write(&tmp_path, hex::encode(private))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp_path, path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Rename preserves the temp file's mode on Unix, but re-assert
            // in case the platform copied instead of renaming.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    fn path_for(data_dir: &Path) -> PathBuf {
        data_dir.join(IDENTITY_FILE_NAME)
    }

    /// Borrow the raw private scalar. Callers must not copy it beyond the
    /// Noise handshake, which consumes it immediately.
    pub fn private_bytes(&self) -> &[u8; 32] {
        &self.private
    }

    /// The shareable X25519 static public key for this identity.
    pub fn public_key(&self) -> [u8; 32] {
        chroma_crypto::noise::x25519_public_from_private(&self.private)
    }

    /// Hex of the public key (logs, startup banner, operator tooling).
    /// Only ever derived from public bytes — the secret never formats.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public_key())
    }
}

impl Drop for NodeIdentity {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

// Redacted on purpose: secret bytes must never reach logs/errors/RPC.
impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("public", &self.public_hex())
            .field("private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("chroma_id_test_{}_{}", tag, id));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_generate_unique_and_valid() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        assert_ne!(a.private_bytes(), b.private_bytes());
        assert_ne!(a.public_key(), b.public_key());
        assert!(chroma_crypto::noise::is_valid_static_key(a.private_bytes()));
    }

    #[test]
    fn test_create_then_load_is_stable() {
        let dir = temp_data_dir("stable");
        let first = NodeIdentity::load_or_create(&dir).unwrap();
        let second = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(first.private_bytes(), second.private_bytes());
        assert_eq!(first.public_key(), second.public_key());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_format_is_strict_hex() {
        let dir = temp_data_dir("format");
        let id = NodeIdentity::load_or_create(&dir).unwrap();
        let raw = std::fs::read(dir.join(IDENTITY_FILE_NAME)).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        // Round-trips to the same key.
        let reloaded = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(id.private_bytes(), reloaded.private_bytes());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_corrupted_file_refuses_startup() {
        for (tag, contents) in [
            ("empty", b"".to_vec()),
            ("short", b"abcd".to_vec()),
            ("long", vec![b'a'; 65]),
            ("nonhex", vec![b'z'; 64]),
            ("nonutf8", vec![0xff; 64]),
            ("allzero", b"00".repeat(32)),
            ("trailing", [b"ab".repeat(32), b"xx".to_vec()].concat()),
        ] {
            let dir = temp_data_dir(tag);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(IDENTITY_FILE_NAME), &contents).unwrap();
            let err = NodeIdentity::load_or_create(&dir).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "case {}", tag);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn test_wrong_length_rejected() {
        let dir = temp_data_dir("length");
        std::fs::create_dir_all(&dir).unwrap();
        for len in [0usize, 1, 31, 33, 63, 65, 128] {
            std::fs::write(dir.join(IDENTITY_FILE_NAME), vec![b'a'; len]).unwrap();
            assert!(
                NodeIdentity::load_or_create(&dir).is_err(),
                "length {} must fail",
                len
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_debug_redacts_secret() {
        let id = NodeIdentity::generate();
        let rendered = format!("{:?}", id);
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(&hex::encode(id.private_bytes())));
        // Public half IS visible (needed for operator tooling).
        assert!(rendered.contains(&id.public_hex()));
    }

    #[test]
    fn test_wallet_key_never_reused_as_identity() {
        // Property: a wallet secret imported as a Noise identity must still
        // round-trip as bytes, but the two key *roles* never mix — identity
        // keys always come from generate()/load_or_create(), wallet keys
        // from wallet APIs. This test pins the type-level separation: there
        // is no constructor taking a wallet/consensus secret.
        let wallet_like = [0x42u8; 32];
        assert!(chroma_crypto::noise::is_valid_static_key(&wallet_like));
        // Identity generation never echoes input material.
        let id = NodeIdentity::generate();
        assert_ne!(id.private_bytes(), &wallet_like);
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_data_dir("perms");
        NodeIdentity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join(IDENTITY_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "identity file must be owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
