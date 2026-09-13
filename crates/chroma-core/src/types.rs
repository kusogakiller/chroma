//! Core Protocol Types

use crate::constants::ADDRESS_HRP;
use crate::error::{CoreError, Result};
use crate::hash::Hash160;
use crate::serialize::{CanonicalDecode, CanonicalEncode};
use bech32::{Bech32m, Hrp};

// ============================================================================
// Block Height
// ============================================================================

/// Block height — u32 is sufficient (4 billion blocks at 10s = ~12,000 years)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct BlockHeight(pub u32);

impl BlockHeight {
    pub const GENESIS: BlockHeight = BlockHeight(0);
    pub const MAX: BlockHeight = BlockHeight(u32::MAX);

    pub const fn new(h: u32) -> Self {
        BlockHeight(h)
    }

    pub fn checked_add(self, other: u32) -> Option<Self> {
        self.0.checked_add(other).map(BlockHeight)
    }

    pub fn saturating_sub(self, other: Self) -> Self {
        BlockHeight(self.0.saturating_sub(other.0))
    }
}

impl From<u32> for BlockHeight {
    fn from(h: u32) -> Self {
        BlockHeight(h)
    }
}

impl From<BlockHeight> for u32 {
    fn from(h: BlockHeight) -> Self {
        h.0
    }
}

impl CanonicalEncode for BlockHeight {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl CanonicalDecode for BlockHeight {
    fn decode(data: &[u8]) -> Result<Self> {
        let h = u32::decode(data)?;
        Ok(BlockHeight(h))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let (h, pos) = u32::decode_partial(data)?;
        Ok((BlockHeight(h), pos))
    }
}

// ============================================================================
// Amount (in smallest units, 1 CHR = 1,000,000 units)
// ============================================================================

/// Amount in smallest units (1 CHR = 1,000,000 units)
/// Uses u64 for amounts; max supply = 100,000,000,000,000 units < u64::MAX
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct Amount(pub u64);

impl Amount {
    pub const ZERO: Amount = Amount(0);
    pub const MAX_SUPPLY: Amount = Amount(100_000_000_000_000); // 100M CHR
    pub const BLOCK_REWARD: Amount = Amount(1_000_000); // 1 CHR

    pub fn new(units: u64) -> Self {
        Amount(units)
    }

    /// Checked addition — returns None on overflow
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Checked subtraction — returns None on underflow
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }

    /// Saturating addition (never overflows)
    pub fn saturating_add(self, other: Amount) -> Amount {
        Amount(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction (never underflows)
    pub fn saturating_sub(self, other: Amount) -> Amount {
        Amount(self.0.saturating_sub(other.0))
    }
}

impl From<u64> for Amount {
    fn from(units: u64) -> Self {
        Amount(units)
    }
}

impl From<Amount> for u64 {
    fn from(a: Amount) -> Self {
        a.0
    }
}

impl CanonicalEncode for Amount {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl CanonicalDecode for Amount {
    fn decode(data: &[u8]) -> Result<Self> {
        let a = u64::decode(data)?;
        Ok(Amount(a))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let (a, pos) = u64::decode_partial(data)?;
        Ok((Amount(a), pos))
    }
}

// ============================================================================
// Nonce
// ============================================================================

/// Transaction nonce for replay protection and ordering
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Default)]
pub struct Nonce(pub u64);

impl Nonce {
    pub const ZERO: Nonce = Nonce(0);

    pub fn new(n: u64) -> Self {
        Nonce(n)
    }

    pub fn next(self) -> Option<Nonce> {
        self.0.checked_add(1).map(Nonce)
    }
}

impl From<u64> for Nonce {
    fn from(n: u64) -> Self {
        Nonce(n)
    }
}

impl CanonicalEncode for Nonce {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl CanonicalDecode for Nonce {
    fn decode(data: &[u8]) -> Result<Self> {
        let n = u64::decode(data)?;
        Ok(Nonce(n))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let (n, pos) = u64::decode_partial(data)?;
        Ok((Nonce(n), pos))
    }
}

// ============================================================================
// Network ID
// ============================================================================

/// Network identifier — prevents cross-network replay
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum NetworkId {
    #[default]
    Devnet,
    Testnet,
    Mainnet,
    Unknown,
}

impl NetworkId {
    pub fn as_str(&self) -> &'static str {
        match self {
            NetworkId::Devnet => "chroma-devnet",
            NetworkId::Testnet => "chroma-testnet",
            NetworkId::Mainnet => "chroma-mainnet",
            NetworkId::Unknown => "unknown",
        }
    }
}

impl CanonicalEncode for NetworkId {
    fn encode(&self) -> Vec<u8> {
        match self {
            NetworkId::Devnet => vec![0u8],
            NetworkId::Testnet => vec![1u8],
            NetworkId::Mainnet => vec![2u8],
            NetworkId::Unknown => vec![255u8],
        }
    }
}

impl CanonicalDecode for NetworkId {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(CoreError::InvalidNetworkId("expected 1 byte".to_string()));
        }
        match data[0] {
            0 => Ok(NetworkId::Devnet),
            1 => Ok(NetworkId::Testnet),
            2 => Ok(NetworkId::Mainnet),
            255 => Ok(NetworkId::Unknown),
            _ => Err(CoreError::InvalidNetworkId(format!(
                "unknown network ID: {}",
                data[0]
            ))),
        }
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let n = NetworkId::decode(data)?;
        Ok((n, 1))
    }
}

// ============================================================================
// Address (display format — actual key is Hash160 internally)
// ============================================================================

/// Chroma address in canonical string form.
/// Internally represented as Hash160 (20-byte RIPEMD160(SHA256(pubkey)))
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Address(pub Hash160);

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

impl Address {
    pub const ZERO: Address = Address(Hash160::ZERO);

    pub fn from_hash160(h: Hash160) -> Self {
        Address(h)
    }

    pub fn as_hash160(&self) -> Hash160 {
        self.0
    }

    /// Encode as Bech32m string with the "chr" HRP.
    pub fn to_bech32(&self) -> String {
        let hrp = Hrp::parse(ADDRESS_HRP).expect("valid HRP");
        bech32::encode::<Bech32m>(hrp, self.0.as_ref()).expect("valid bech32m encoding")
    }

    /// Decode a Bech32m address string.
    pub fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s)
            .map_err(|e| CoreError::InvalidFormat(format!("bech32 decode failed: {}", e)))?;

        if hrp.as_str() != ADDRESS_HRP {
            return Err(CoreError::InvalidFormat(format!(
                "invalid HRP: expected '{}', got '{}'",
                ADDRESS_HRP,
                hrp.as_str()
            )));
        }

        if data.len() != 20 {
            return Err(CoreError::InvalidFormat(format!(
                "address must be 20 bytes, got {}",
                data.len()
            )));
        }

        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&data);
        Ok(Address(Hash160(bytes)))
    }
}

impl std::str::FromStr for Address {
    type Err = crate::error::CoreError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.starts_with(ADDRESS_HRP) {
            return Address::from_bech32(s);
        }
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(hex_str)
            .map_err(|e| CoreError::InvalidFormat(format!("invalid hex address: {}", e)))?;
        if bytes.len() != 20 {
            return Err(CoreError::InvalidFormat(format!(
                "address must be 20 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address(Hash160(arr)))
    }
}

impl From<Hash160> for Address {
    fn from(h: Hash160) -> Self {
        Address(h)
    }
}

impl CanonicalEncode for Address {
    fn encode(&self) -> Vec<u8> {
        self.0 .0.to_vec() // 20 bytes, raw
    }
}

impl CanonicalDecode for Address {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 20 {
            return Err(crate::error::CoreError::InvalidFormat(
                "address must be 20 bytes".to_string(),
            ));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(data);
        Ok(Address(Hash160(bytes)))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let addr = Address::decode(data)?;
        Ok((addr, 20))
    }
}

// ============================================================================
// Compact Target ("bits")
// ============================================================================

/// Compact target representation (like Bitcoin "bits").
/// 1-byte exponent + 3-byte mantissa = 4 bytes total.
/// Target = mantissa × 2^(8 × (exponent - 3))
/// Max target (difficulty 1): 0x1d00ffff
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct CompactTarget(pub u32);

impl CompactTarget {
    /// Compact target for difficulty 1
    pub const DIFFICULTY_1: CompactTarget = CompactTarget(0x1d00ffff);

    /// Convert to full 256-bit target
    pub fn to_full_target(&self) -> [u8; 32] {
        let bits = self.0;
        let exponent = bits >> 24;
        let mantissa = bits & 0x00ffffff;

        if exponent <= 3 {
            // Very small target
            let shift = (3 - exponent) * 8;
            let mut result = [0u8; 32];
            let val = mantissa >> shift;
            for i in (0..4).rev() {
                if val >= (1u32 << (i * 8)) {
                    result[31 - i] = ((val >> (i * 8)) & 0xFF) as u8;
                }
            }
            return result;
        }

        let mut result = [0u8; 32];
        let shift_bytes = (exponent - 3) as usize;
        if shift_bytes > 29 {
            return [0xFF; 32];
        }

        // Normal case: mantissa << (8 * (exponent - 3))
        // MSB of mantissa goes to byte position (32 - exponent) in big-endian 32-byte array
        let target_bytes = [
            ((mantissa >> 16) & 0xFF) as u8,
            ((mantissa >> 8) & 0xFF) as u8,
            (mantissa & 0xFF) as u8,
        ];

        let start = 32 - exponent as usize;
        result[start] = target_bytes[0];
        result[start + 1] = target_bytes[1];
        result[start + 2] = target_bytes[2];

        result
    }

    /// Convert from 256-bit target (big-endian byte array) to compact representation.
    ///
    /// Algorithm mirrors Bitcoin Core's GetCompact():
    /// 1. Find bit length of the number
    /// 2. nSize = ceil(bit_length / 8)
    /// 3. Extract top 3 bytes as mantissa
    /// 4. If MSB of mantissa is set, shift right and increment nSize
    pub fn from_full_target(target: &[u8; 32]) -> Self {
        // Find the bit length by locating the first non-zero byte
        let mut first = 0;
        while first < 32 && target[first] == 0 {
            first += 1;
        }
        if first == 32 {
            return CompactTarget(0);
        }

        // bit_length = (31 - first) * 8 + (8 - leading_zeros of first non-zero byte)
        let lz = target[first].leading_zeros() as usize;
        let bit_len = (31 - first) * 8 + (8 - lz);
        let n_size = bit_len.div_ceil(8) as u32;

        // Extract the mantissa: the top 3 bytes of the value starting at byte `first`
        // The mantissa occupies bytes [first..first+3] (padded with zeros if needed)
        let mut mantissa: u32 = 0;
        let end = std::cmp::min(first + 3, 32);
        for byte in &target[first..end] {
            mantissa = (mantissa << 8) | *byte as u32;
        }
        // Pad remaining bytes to fill 24-bit mantissa
        for _ in end..(first + 3) {
            mantissa <<= 8;
        }

        // If MSB of mantissa is set, shift right and increment size
        let mut final_size = n_size;
        if mantissa & 0x00800000 != 0 {
            mantissa >>= 8;
            final_size += 1;
        }

        CompactTarget((final_size << 24) | (mantissa & 0x00ffffff))
    }
}

impl CanonicalEncode for CompactTarget {
    fn encode(&self) -> Vec<u8> {
        self.0.encode()
    }
}

impl CanonicalDecode for CompactTarget {
    fn decode(data: &[u8]) -> Result<Self> {
        let bits = u32::decode(data)?;
        Ok(CompactTarget(bits))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let (bits, pos) = u32::decode_partial(data)?;
        Ok((CompactTarget(bits), pos))
    }
}

// ============================================================================
// Difficulty
// ============================================================================

/// Difficulty as a ratio relative to difficulty-1 target.
/// 1.0 = genesis difficulty. Higher = harder.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct Difficulty(pub u64);

impl Difficulty {
    pub const GENESIS: Difficulty = Difficulty(1);

    /// Compute difficulty from compact target
    pub fn from_bits(bits: CompactTarget) -> Self {
        use crate::u256::U256;

        let cur_target = U256::from_be_bytes(&bits.to_full_target());
        if cur_target.is_zero() {
            return Difficulty(u64::MAX);
        }

        // Difficulty = DIFFICULTY_1_TARGET / current_target
        let max_target = U256::from_be_bytes(&CompactTarget::DIFFICULTY_1.to_full_target());
        let (q, _r) = max_target.div_rem(&cur_target);
        Difficulty(q.to_u64().unwrap_or(u64::MAX))
    }
}
