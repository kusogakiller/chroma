//! Bech32m Address Encoding (BIP-350)
//!
//! Chroma addresses use the format: `chr1<data><checksum>`
//! HRP (Human Readable Part): "chr"
//! Checksum: Bech32m
//! Data: witness-style encoding of 20-byte HASH160

use bech32::{self, Bech32m, Hrp};
use chroma_core::{Hash160, ADDRESS_HASH_LEN, ADDRESS_HRP};

/// Chroma address string (e.g., "chr1...")
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddressString(pub String);

impl AddressString {
    /// Encode a HASH160 into a Bech32m address string
    pub fn from_hash160(h: &Hash160, hrp_str: Option<&str>) -> Option<Self> {
        let hrp_val = hrp_str.unwrap_or(ADDRESS_HRP);
        let hrp = Hrp::parse(hrp_val).ok()?;

        let encoded = bech32::encode::<Bech32m>(hrp, &h.0).ok()?;
        Some(AddressString(encoded))
    }

    /// Decode a Bech32m address string into HASH160
    pub fn to_hash160(&self) -> Option<Hash160> {
        let hrp_val = ADDRESS_HRP;
        let (hrp, data) = bech32::decode(&self.0).ok()?;

        if hrp.as_str() != hrp_val {
            return None;
        }

        if data.len() != ADDRESS_HASH_LEN {
            return None;
        }

        let mut hash_bytes = [0u8; 20];
        hash_bytes.copy_from_slice(&data[..20]);
        Some(Hash160(hash_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::Hash160;

    #[test]
    fn test_address_encode_decode() {
        let hash = Hash160::from_bytes([0x42u8; 20]);
        let addr = AddressString::from_hash160(&hash, None).unwrap();
        assert!(addr.0.starts_with("chr1"));

        let decoded = addr.to_hash160().unwrap();
        assert_eq!(decoded, hash);
    }
}
