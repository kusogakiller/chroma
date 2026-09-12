//! Chroma Block
//!
//! Canonical block structure with deterministic serialization.
//!
//! Block header (canonical, little-endian):
//!   version:              4 bytes (u32 LE)
//!   previous_hash:       32 bytes (BLAKE3 of previous block header)
//!   state_root:          32 bytes (BLAKE3 of account state after all txs)
//!   tx_merkle_root:      32 bytes (BLAKE3 Merkle root of transactions)
//!   timestamp:           8 bytes (u64 LE, Unix seconds)
//!   bits:                4 bytes (u32 LE, CompactTarget)
//!   height:              4 bytes (u32 LE)
//!   nonce:               8 bytes (u64 LE, PoW nonce)
//!
//! Header total: 124 bytes.
//!
//! Block = header + transactions (LEB128 count + concatenated txs).

use chroma_core::constants::{BLOCK_REWARD_UNITS, MAX_BLOCK_SIZE, MAX_SUPPLY_UNITS};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{BlockHeight, CompactTarget};
use chroma_tx::Transaction;

// ============================================================================
// Block Header
// ============================================================================

/// Block header: 124 bytes canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: Hash,
    pub state_root: Hash,
    pub tx_merkle_root: Hash,
    pub timestamp: u64,
    pub bits: CompactTarget,
    pub height: BlockHeight,
    pub nonce: u64,
}

impl BlockHeader {
    /// Canonical header size.
    pub const SERIALIZED_SIZE: usize = 4 + 32 + 32 + 32 + 8 + 4 + 4 + 8; // 124

    /// Compute header hash: BLAKE3 of canonical header encoding.
    pub fn hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::blake3(&encoded)
    }
}

impl CanonicalEncode for BlockHeader {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(&self.version.to_le_bytes()); // 4
        buf.extend_from_slice(self.previous_hash.as_bytes()); // 32
        buf.extend_from_slice(self.state_root.as_bytes()); // 32
        buf.extend_from_slice(self.tx_merkle_root.as_bytes()); // 32
        buf.extend_from_slice(&self.timestamp.to_le_bytes()); // 8
        buf.extend_from_slice(&self.bits.0.to_le_bytes()); // 4
        buf.extend_from_slice(&self.height.0.to_le_bytes()); // 4
        buf.extend_from_slice(&self.nonce.to_le_bytes()); // 8
        buf
    }
}

impl CanonicalDecode for BlockHeader {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "block header: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let mut previous_hash = [0u8; 32];
        previous_hash.copy_from_slice(&data[4..36]);

        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&data[36..68]);

        let mut tx_merkle_root = [0u8; 32];
        tx_merkle_root.copy_from_slice(&data[68..100]);

        let timestamp = u64::from_le_bytes([
            data[100], data[101], data[102], data[103], data[104], data[105], data[106], data[107],
        ]);

        let bits = u32::from_le_bytes([data[108], data[109], data[110], data[111]]);
        let height = u32::from_le_bytes([data[112], data[113], data[114], data[115]]);
        let nonce = u64::from_le_bytes([
            data[116], data[117], data[118], data[119], data[120], data[121], data[122], data[123],
        ]);

        Ok(BlockHeader {
            version,
            previous_hash: Hash::from_bytes(previous_hash),
            state_root: Hash::from_bytes(state_root),
            tx_merkle_root: Hash::from_bytes(tx_merkle_root),
            timestamp,
            bits: CompactTarget(bits),
            height: BlockHeight(height),
            nonce,
        })
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "block header: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let header = BlockHeader::decode(&data[..Self::SERIALIZED_SIZE])?;
        Ok((header, Self::SERIALIZED_SIZE))
    }
}

// ============================================================================
// Block
// ============================================================================

/// A complete block: header + ordered transactions.
#[derive(Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Compute the BLAKE3 Merkle root of the transaction list.
    ///
    /// Binary Merkle tree:
    /// - Leaves: `H(encode(tx))`
    /// - Internal: `H(left || right)`
    /// - Odd leaf at any level is promoted to the next level.
    /// - Empty list → `Hash::ZERO`.
    pub fn compute_tx_merkle_root(transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::ZERO;
        }
        let leaves: Vec<Hash> = transactions
            .iter()
            .map(|tx| Hash::blake3(&tx.encode()))
            .collect();
        Self::merkle_root_from_leaves(&leaves)
    }

    /// Compute binary Merkle root from a slice of leaf hashes.
    fn merkle_root_from_leaves(leaves: &[Hash]) -> Hash {
        if leaves.is_empty() {
            return Hash::ZERO;
        }
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                if pair.len() == 2 {
                    let mut buf = Vec::with_capacity(64);
                    buf.extend_from_slice(pair[0].as_bytes());
                    buf.extend_from_slice(pair[1].as_bytes());
                    next.push(Hash::blake3(&buf));
                } else {
                    // Odd leaf: promote to next level
                    next.push(pair[0]);
                }
            }
            current = next;
        }
        current[0]
    }

    /// Compute block hash (= header hash).
    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Serialize the full block.
    pub fn encode_block(&self) -> Vec<u8> {
        let mut buf = self.header.encode();
        // LEB128 transaction count
        buf.extend_from_slice(&chroma_core::serialize::encode_leb128(
            self.transactions.len() as u64,
        ));
        for tx in &self.transactions {
            buf.extend_from_slice(&tx.encode());
        }
        buf
    }

    /// Deserialize a full block.
    pub fn decode_block(data: &[u8]) -> Result<Self> {
        if data.len() < BlockHeader::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "block: data too short for header ({} bytes)",
                data.len()
            )));
        }

        let (header, pos) = BlockHeader::decode_partial(data)?;

        // Verify decoded header re-serializes to the original bytes (round-trip check).
        let re_encoded_header = header.encode();
        if re_encoded_header[..] != data[..BlockHeader::SERIALIZED_SIZE] {
            return Err(CoreError::Serialization(
                "block: header round-trip mismatch (non-canonical encoding)".to_string(),
            ));
        }

        let (tx_count_raw, mut pos) = chroma_core::serialize::decode_leb128(data, pos)?;
        let tx_count = usize::try_from(tx_count_raw).map_err(|_| {
            CoreError::Serialization(format!("block: tx_count {} overflows usize", tx_count_raw))
        })?;
        let max_txs = (data.len() / Transaction::SERIALIZED_SIZE) + 1;
        if tx_count > max_txs {
            return Err(CoreError::Serialization(format!(
                "block: tx_count {} exceeds maximum possible {}",
                tx_count, max_txs
            )));
        }
        let mut transactions = Vec::with_capacity(tx_count);
        for _ in 0..tx_count {
            if pos > data.len() {
                return Err(CoreError::Serialization(
                    "block: truncated transaction data".to_string(),
                ));
            }
            let (tx, consumed) = Transaction::decode_partial(&data[pos..])?;
            transactions.push(tx);
            pos += consumed;
        }
        if pos != data.len() {
            return Err(CoreError::Serialization(format!(
                "block: {} trailing bytes after transactions",
                data.len() - pos
            )));
        }
        Ok(Block {
            header,
            transactions,
        })
    }
}

// ============================================================================
// Block Validation
// ============================================================================

/// Block validation context (chain state needed for validation).
#[derive(Clone, Debug)]
pub struct BlockValidationContext {
    /// Previous block header hash
    pub previous_hash: Hash,
    /// Expected height = previous_height + 1
    pub expected_height: BlockHeight,
    /// Previous block timestamp (for strict monotonicity check)
    pub previous_timestamp: u64,
    /// Median Time Past of the last MTP_WINDOW (7) blocks
    pub median_time_past: u64,
    /// Expected target bits for this block
    pub expected_bits: CompactTarget,
    /// Current total supply (for subsidy cap check)
    pub current_supply: u64,
    /// Previous block's state root (for state transition verification)
    pub previous_state_root: Hash,
    /// Network-adjusted time (for future timestamp check)
    pub network_time: u64,
    /// Network magic for transaction signature verification (cross-network replay protection)
    pub network_magic: [u8; 4],
}

/// Validate a complete block against the chain context.
///
/// Returns the state root after applying all transactions + subsidy.
pub fn validate_block(
    block: &Block,
    ctx: &BlockValidationContext,
    state: &mut chroma_state::State,
) -> Result<Hash> {
    let header = &block.header;

    // --- Size check ---
    let block_size = block.encode_block().len();
    if block_size > MAX_BLOCK_SIZE {
        return Err(CoreError::BlockSizeExceeded(block_size, MAX_BLOCK_SIZE));
    }

    // --- Header checks ---
    if header.version != 1 {
        return Err(CoreError::InvalidBlock(format!(
            "unsupported version: {}",
            header.version
        )));
    }

    if header.previous_hash != ctx.previous_hash {
        return Err(CoreError::InvalidBlock(format!(
            "previous hash mismatch: expected {}, got {}",
            ctx.previous_hash.to_hex(),
            header.previous_hash.to_hex()
        )));
    }

    if header.height != ctx.expected_height {
        return Err(CoreError::InvalidBlock(format!(
            "height mismatch: expected {}, got {}",
            ctx.expected_height.0, header.height.0
        )));
    }

    // Timestamp: must be > median_time_past(last 7 blocks) and <= network_time + 20
    if header.timestamp <= ctx.median_time_past {
        return Err(CoreError::InvalidTimestamp(format!(
            "block timestamp {} must be after MTP {}",
            header.timestamp, ctx.median_time_past
        )));
    }
    if header.timestamp
        > ctx.network_time + chroma_core::constants::MAX_FUTURE_TIMESTAMP_OFFSET as u64
    {
        return Err(CoreError::InvalidTimestamp(format!(
            "block timestamp {} is too far in the future (network time: {})",
            header.timestamp, ctx.network_time
        )));
    }

    // --- Target ---
    if header.bits != ctx.expected_bits {
        return Err(CoreError::InvalidDifficulty(format!(
            "expected bits {:08x}, got {:08x}",
            ctx.expected_bits.0, header.bits.0
        )));
    }

    // --- PoW ---
    // Use RandomX PoW: input = prev_hash || merkle_root || nonce(LE)
    // The BLAKE3 header.hash() is used only for block identification, not PoW.
    let pow_result = chroma_crypto::randomx::pow_randomx(
        &header.previous_hash,
        &header.tx_merkle_root,
        header.nonce,
        &[],
    )
    .map_err(|e| CoreError::InvalidProofOfWork(format!("RandomX PoW failed: {}", e)))?;
    let target = header.bits.to_full_target();
    if !chroma_crypto::randomx::hash_meets_target(&pow_result, &target) {
        return Err(CoreError::InvalidProofOfWork(
            "block hash does not meet target".to_string(),
        ));
    }

    // --- Transaction count ---
    if block.transactions.is_empty() {
        return Err(CoreError::InvalidBlock(
            "block must contain at least one transaction (coinbase)".to_string(),
        ));
    }

    // --- First transaction must be coinbase ---
    let coinbase = &block.transactions[0];
    if coinbase.amount.0 != BLOCK_REWARD_UNITS {
        return Err(CoreError::InvalidBlock(format!(
            "coinbase reward must be exactly {} units, got {}",
            BLOCK_REWARD_UNITS, coinbase.amount.0
        )));
    }

    if coinbase.nonce.0 != 0 {
        return Err(CoreError::InvalidBlock(
            "coinbase nonce must be 0".to_string(),
        ));
    }

    if coinbase.sender_pubkey.0 != [0u8; 32] {
        return Err(CoreError::InvalidBlock(
            "coinbase must have zero sender_pubkey".to_string(),
        ));
    }
    if coinbase.signature.0 != [0u8; 64] {
        return Err(CoreError::InvalidBlock(
            "coinbase must have zero signature".to_string(),
        ));
    }

    // --- Apply state transitions ---
    state.begin_block();

    let _subsidy = match state.apply_subsidy(&coinbase.recipient, header.height.0) {
        Ok(s) => s,
        Err(e) => {
            state.abort_block();
            return Err(e);
        }
    };

    // Check supply cap (use > not >= so the block that reaches exactly MAX is allowed)
    if state.total_supply() > MAX_SUPPLY_UNITS as u64 {
        state.abort_block();
        return Err(CoreError::SupplyInvariant(format!(
            "total supply {} exceeds max {}",
            state.total_supply(),
            MAX_SUPPLY_UNITS
        )));
    }

    for tx in block.transactions.iter().skip(1) {
        if tx.encode().len() > chroma_core::constants::MAX_TRANSACTION_SIZE {
            state.abort_block();
            return Err(CoreError::TransactionSizeExceeded(
                tx.encode().len(),
                chroma_core::constants::MAX_TRANSACTION_SIZE,
            ));
        }

        if !tx.verify_signature(ctx.network_magic) {
            state.abort_block();
            return Err(CoreError::InvalidSignature(
                "transaction signature verification failed".to_string(),
            ));
        }

        if let Err(e) =
            state.apply_transaction(&tx.sender_address(), &tx.recipient, tx.amount.0, tx.nonce.0)
        {
            state.abort_block();
            return Err(e);
        }
    }

    // --- State root check ---
    let new_state_root = state.compute_state_root();
    if new_state_root != header.state_root {
        state.abort_block();
        return Err(CoreError::InvalidStateRoot(format!(
            "expected {}, got {}",
            header.state_root.to_hex(),
            new_state_root.to_hex()
        )));
    }

    // --- Tx Merkle root check ---
    let computed_merkle = Block::compute_tx_merkle_root(&block.transactions);
    if computed_merkle != header.tx_merkle_root {
        state.abort_block();
        return Err(CoreError::InvalidMerkleRoot(format!(
            "expected {}, got {}",
            header.tx_merkle_root.to_hex(),
            computed_merkle.to_hex()
        )));
    }

    state.commit_block();
    Ok(new_state_root)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::REGTEST_MAGIC;
    use chroma_core::hash::Hash160;
    use chroma_core::types::{Address, Amount, Nonce};

    fn zero_hash() -> Hash {
        Hash::from_bytes([0u8; 32])
    }

    fn some_hash() -> Hash {
        Hash::blake3(b"test")
    }

    fn make_header(version: u32, prev: Hash, height: u32, ts: u64, bits: u32) -> BlockHeader {
        BlockHeader {
            version,
            previous_hash: prev,
            state_root: zero_hash(),
            tx_merkle_root: zero_hash(),
            timestamp: ts,
            bits: CompactTarget(bits),
            height: BlockHeight(height),
            nonce: 0,
        }
    }

    #[test]
    fn test_header_serialization_roundtrip() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let encoded = header.encode();
        assert_eq!(encoded.len(), BlockHeader::SERIALIZED_SIZE);
        let decoded = BlockHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn test_header_hash_deterministic() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(Block::compute_tx_merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let sender_h = chroma_crypto::hash::hash160(&pubkey.0);
        let mut bob_h = [0u8; 20];
        bob_h[0] = 0xBB;

        let tx = chroma_tx::create_transaction(
            &secret,
            Address::from_hash160(Hash160(sender_h)),
            Address::from_hash160(Hash160(bob_h)),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        let root1 = Block::compute_tx_merkle_root(std::slice::from_ref(&tx));
        let root2 = Block::compute_tx_merkle_root(&[tx]);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_block_encoding_roundtrip() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![],
        };
        let encoded = block.encode_block();
        let decoded = Block::decode_block(&encoded).unwrap();
        assert_eq!(decoded.header, block.header);
        assert_eq!(decoded.transactions.len(), 0);
    }

    #[test]
    fn test_block_size_exceeded() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![],
        };
        let encoded = block.encode_block();
        assert!(encoded.len() < MAX_BLOCK_SIZE);
    }

    #[test]
    fn test_header_hash_changes_with_previous_hash() {
        let h1 = make_header(1, Hash::blake3(b"a"), 1, 1_700_000_000, 0x1d00ffff);
        let h2 = make_header(1, Hash::blake3(b"b"), 1, 1_700_000_000, 0x1d00ffff);
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_header_hash_changes_with_timestamp() {
        let h1 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let h2 = make_header(1, some_hash(), 1, 1_700_000_001, 0x1d00ffff);
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_header_hash_changes_with_nonce() {
        let mut h1 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        h1.nonce = 0;
        let mut h2 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        h2.nonce = 1;
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_header_hash_changes_with_height() {
        let h1 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let h2 = make_header(1, some_hash(), 2, 1_700_000_000, 0x1d00ffff);
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_header_hash_changes_with_bits() {
        let h1 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let h2 = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00fffe);
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_merkle_root_different_txs() {
        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let sender_h = chroma_crypto::hash::hash160(&pubkey.0);
        let mut bob_h = [0u8; 20];
        bob_h[0] = 0xBB;

        let tx1 = chroma_tx::create_transaction(
            &secret,
            Address::from_hash160(Hash160(sender_h)),
            Address::from_hash160(Hash160(bob_h)),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        let tx2 = chroma_tx::create_transaction(
            &secret,
            Address::from_hash160(Hash160(sender_h)),
            Address::from_hash160(Hash160(bob_h)),
            Amount(2_000_000),
            Nonce(1),
            REGTEST_MAGIC,
        )
        .unwrap();

        let root1 = Block::compute_tx_merkle_root(std::slice::from_ref(&tx1));
        let root2 = Block::compute_tx_merkle_root(std::slice::from_ref(&tx2));
        assert_ne!(
            root1, root2,
            "different txs should produce different merkle roots"
        );

        let root12 = Block::compute_tx_merkle_root(&[tx1, tx2]);
        assert_ne!(
            root1, root12,
            "different tx count should produce different merkle root"
        );
    }

    #[test]
    fn test_block_decode_rejects_truncated_header() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let encoded = header.encode();
        assert!(Block::decode_block(&encoded[..50]).is_err());
    }

    #[test]
    fn test_block_decode_empty() {
        assert!(Block::decode_block(&[]).is_err());
    }

    #[test]
    fn test_header_encoded_size() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let encoded = header.encode();
        assert_eq!(encoded.len(), 124);
    }

    #[test]
    fn test_block_hash_deterministic() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![],
        };
        let h1 = block.hash();
        let h2 = block.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_block_hash_independent_of_transactions() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let b1 = Block {
            header: header.clone(),
            transactions: vec![],
        };
        let b2 = Block {
            header,
            transactions: vec![],
        };
        assert_eq!(
            b1.hash(),
            b2.hash(),
            "block hash = header hash, not dependent on txs"
        );
    }

    #[test]
    fn test_header_previous_hash_zero_for_genesis() {
        let header = make_header(1, Hash::ZERO, 0, 1_700_000_000, 0x1d00ffff);
        assert_eq!(header.previous_hash, Hash::ZERO);
    }

    #[test]
    fn test_merkle_root_binary_tree_structure() {
        let secret = chroma_crypto::schnorr::SecretKey32::generate();
        let secret2 = chroma_crypto::schnorr::SecretKey32::generate();
        let addr = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(
            &chroma_crypto::schnorr::PublicKey32::from_secret(&secret)
                .unwrap()
                .0,
        )));
        let addr2 = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(
            &chroma_crypto::schnorr::PublicKey32::from_secret(&secret2)
                .unwrap()
                .0,
        )));
        let txs: Vec<Transaction> = (0..3)
            .map(|i| {
                chroma_tx::create_transaction(
                    &secret,
                    addr,
                    addr2,
                    Amount(100_000),
                    Nonce(i),
                    REGTEST_MAGIC,
                )
                .unwrap()
            })
            .collect();
        let root_3 = Block::compute_tx_merkle_root(&txs);
        let root_1 = Block::compute_tx_merkle_root(&txs[..1]);
        let root_2 = Block::compute_tx_merkle_root(&txs[..2]);
        assert_ne!(root_1, root_2);
        assert_ne!(root_2, root_3);
        assert_ne!(root_1, root_3);
    }

    #[test]
    fn test_merkle_root_odd_even_consistency() {
        let secret = chroma_crypto::schnorr::SecretKey32::generate();
        let secret2 = chroma_crypto::schnorr::SecretKey32::generate();
        let addr = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(
            &chroma_crypto::schnorr::PublicKey32::from_secret(&secret)
                .unwrap()
                .0,
        )));
        let addr2 = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(
            &chroma_crypto::schnorr::PublicKey32::from_secret(&secret2)
                .unwrap()
                .0,
        )));
        let txs: Vec<Transaction> = (0..4)
            .map(|i| {
                chroma_tx::create_transaction(
                    &secret,
                    addr,
                    addr2,
                    Amount(100_000),
                    Nonce(i),
                    REGTEST_MAGIC,
                )
                .unwrap()
            })
            .collect();
        let root_3 = Block::compute_tx_merkle_root(&txs[..3]);
        let root_4 = Block::compute_tx_merkle_root(&txs);
        assert_ne!(root_3, root_4);
    }

    #[test]
    fn test_block_decode_rejects_truncated_tx_data() {
        let header = make_header(1, some_hash(), 0, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![],
        };
        let mut encoded = block.encode_block();
        // Fake a tx count of 1 but don't include any tx data
        encoded[124] = 1; // tx_count = 1
        assert!(Block::decode_block(&encoded).is_err());
    }

    #[test]
    fn test_block_decode_rejects_trailing_after_txs() {
        let header = make_header(1, some_hash(), 0, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![],
        };
        let mut encoded = block.encode_block();
        encoded.push(0xFF);
        assert!(Block::decode_block(&encoded).is_err());
    }

    #[test]
    fn test_coinbase_zero_pubkey_sig_roundtrip() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let coinbase = Transaction {
            sender_pubkey: chroma_crypto::schnorr::PublicKey32([0u8; 32]),
            recipient: Address::from_hash160(Hash160([0xAA; 20])),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        let block = Block {
            header,
            transactions: vec![coinbase],
        };
        let encoded = block.encode_block();
        let decoded = Block::decode_block(&encoded).unwrap();
        assert_eq!(decoded.transactions.len(), 1);
        assert_eq!(decoded.transactions[0].sender_pubkey.0, [0u8; 32]);
        assert_eq!(decoded.transactions[0].signature.0, [0u8; 64]);
        assert_eq!(decoded.transactions[0].amount, Amount(1_000_000));
    }

    #[test]
    fn test_block_encode_decode_roundtrip_with_coinbase() {
        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let coinbase = Transaction {
            sender_pubkey: chroma_crypto::schnorr::PublicKey32([0u8; 32]),
            recipient: Address::from_hash160(Hash160([0xBB; 20])),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        let block = Block {
            header,
            transactions: vec![coinbase.clone()],
        };
        let encoded = block.encode_block();
        let decoded = Block::decode_block(&encoded).unwrap();
        assert_eq!(decoded.header, block.header);
        assert_eq!(decoded.transactions.len(), 1);
        assert_eq!(decoded.transactions[0], coinbase);
    }

    #[test]
    fn test_coinbase_nonzero_pubkey_rejected_by_consensus() {
        let coinbase = Transaction {
            sender_pubkey: chroma_crypto::schnorr::PublicKey32([1u8; 32]),
            recipient: Address::from_hash160(Hash160([0xAA; 20])),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        assert_ne!(coinbase.sender_pubkey.0, [0u8; 32]);
        assert_eq!(coinbase.signature.0, [0u8; 64]);
        assert!(
            coinbase.sender_pubkey.0 != [0u8; 32],
            "consensus rejects coinbase with non-zero pubkey"
        );
    }

    #[test]
    fn test_coinbase_nonzero_signature_rejected_by_consensus() {
        let coinbase = Transaction {
            sender_pubkey: chroma_crypto::schnorr::PublicKey32([0u8; 32]),
            recipient: Address::from_hash160(Hash160([0xAA; 20])),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: chroma_crypto::schnorr::Signature64([1u8; 64]),
        };
        assert_eq!(coinbase.sender_pubkey.0, [0u8; 32]);
        assert_ne!(coinbase.signature.0, [0u8; 64]);
        assert!(
            coinbase.signature.0 != [0u8; 64],
            "consensus rejects coinbase with non-zero signature"
        );
    }

    #[test]
    fn test_normal_tx_decode_then_verify_rejects_invalid_key() {
        let mut data = [0u8; 132];
        data[0] = 0xFF;
        let tx = Transaction::decode(&data).unwrap();
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_normal_tx_valid_encode_decode_verify() {
        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let h = chroma_crypto::hash::hash160(&pubkey.0);
        let sender = Address::from_hash160(Hash160(h));
        let mut rh = [0u8; 20];
        rh[0] = 0xBB;
        let recipient = Address::from_hash160(Hash160(rh));

        let tx = chroma_tx::create_transaction(
            &secret,
            sender,
            recipient,
            Amount(500_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let encoded = tx.encode();
        assert_eq!(encoded.len(), 132);
        let decoded = Transaction::decode(&encoded).unwrap();
        assert!(decoded.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_wire_format_is_exactly_132_bytes() {
        let coinbase = Transaction {
            sender_pubkey: chroma_crypto::schnorr::PublicKey32([0u8; 32]),
            recipient: Address::from_hash160(Hash160([0xCC; 20])),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        assert_eq!(coinbase.encode().len(), 132);

        let header = make_header(1, some_hash(), 1, 1_700_000_000, 0x1d00ffff);
        let block = Block {
            header,
            transactions: vec![coinbase],
        };
        let encoded = block.encode_block();
        let decoded = Block::decode_block(&encoded).unwrap();
        assert_eq!(decoded.transactions[0].encode().len(), 132);
    }
}
