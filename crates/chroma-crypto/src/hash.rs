//! Hashing Primitives
//!
//! Uses BLAKE3 as the primary hash function (fast, secure, Rust-native).
//! SHA-256 and RIPEMD-160 used for address derivation.

use chroma_core::{blake3 as core_blake3, Hash};
use ripemd::{Digest, Ripemd160};
use sha2::Sha256;

/// BLAKE3 hash -> 32-byte Hash
pub fn blake3(data: &[u8]) -> Hash {
    core_blake3(data)
}

/// SHA-256 hash -> 32 bytes
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// RIPEMD-160 hash -> 20 bytes
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// Hash160 = RIPEMD160(SHA256(data)) -> 20 bytes
/// Used for address key derivation
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = sha256(data);
    ripemd160(&sha)
}

/// Double SHA-256
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hasher2 = Sha256::new();
    hasher2.update(result);
    let result2 = hasher2.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result2);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        let result = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash160() {
        let result = hash160(b"test");
        assert_eq!(result.len(), 20);
        assert_ne!(hash160(b"test"), hash160(b"test2"));
    }
}
