//! Hashing Primitives

use blake3 as blake3_crate;

/// 32-byte hash (BLAKE3 output)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// Zero hash (empty tree root, null hash)
    pub const ZERO: Hash = Hash([0; 32]);

    /// Create from 32-byte array
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create from slice (must be 32 bytes)
    pub fn from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() != 32 {
            return Err("Hash must be 32 bytes");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Hash(bytes))
    }

    /// BLAKE3 hash of data
    pub fn blake3(data: &[u8]) -> Self {
        Hash(*blake3_crate::hash(data).as_bytes())
    }

    /// BLAKE3 keyed hash
    pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> Self {
        Hash(*blake3_crate::keyed_hash(key, data).as_bytes())
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to big-endian hex string (display order)
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from big-endian hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes).map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash({})", &self.to_hex()[..16])
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(h: Hash) -> Self {
        h.0
    }
}

/// RIPEMD160 hash (20 bytes) - used for address hashing
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Hash160(pub [u8; 20]);

impl Hash160 {
    pub const ZERO: Hash160 = Hash160([0; 20]);

    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, &'static str> {
        if slice.len() != 20 {
            return Err("Hash160 must be 20 bytes");
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Hash160(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes).map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}

impl std::fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash160({})", &self.to_hex()[..12])
    }
}

impl std::fmt::Display for Hash160 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for Hash160 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for Hash160 {
    fn from(bytes: [u8; 20]) -> Self {
        Hash160(bytes)
    }
}

impl From<Hash160> for [u8; 20] {
    fn from(h: Hash160) -> Self {
        h.0
    }
}

/// Public BLAKE3 hash function
pub fn blake3(data: &[u8]) -> Hash {
    Hash::blake3(data)
}
