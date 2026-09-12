//! Block Assembly and Mining
//!
//! Assembles blocks from the mempool, creates coinbase transactions,
//! and performs Proof-of-Work (BLAKE3 placeholder for devnet).

use chroma_block::{Block, BlockHeader};
use chroma_core::constants::{
    BLOCK_REWARD_UNITS, MAX_FUTURE_TIMESTAMP_OFFSET, TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::{Amount, BlockHeight, CompactTarget, Nonce};
use chroma_tx::Transaction;

/// Maximum number of transactions to include in a block.
/// Shared with the P2P miner's selection cap so simulation and assembly
/// agree on how many mempool entries are considered per round.
pub const MAX_BLOCK_TXS: usize = 10_000;

/// Block assembly context needed for mining.
pub struct BlockAssemblyContext {
    pub height: BlockHeight,
    pub previous_hash: Hash,
    pub previous_timestamp: u64,
    pub state_root: Hash,
    pub bits: CompactTarget,
    pub coinbase_recipient: chroma_core::types::Address,
}

/// Assemble a new block from mempool transactions.
///
/// Creates the coinbase transaction and constructs a candidate block.
/// Does NOT perform mining (nonce search) — caller must do that.
pub fn assemble_block(ctx: &BlockAssemblyContext, mempool_txs: &[Transaction]) -> Result<Block> {
    let coinbase = Transaction {
        sender_pubkey: chroma_crypto::schnorr::PublicKey32([0u8; 32]),
        recipient: ctx.coinbase_recipient,
        amount: Amount(BLOCK_REWARD_UNITS),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };

    let mut transactions = Vec::with_capacity(1 + mempool_txs.len());
    transactions.push(coinbase);

    let max_txs = std::cmp::min(mempool_txs.len(), MAX_BLOCK_TXS - 1);
    transactions.extend_from_slice(&mempool_txs[..max_txs]);

    let tx_merkle_root = Block::compute_tx_merkle_root(&transactions);

    let ideal_timestamp = ctx.previous_timestamp + TARGET_BLOCK_TIME_SECS;
    let wall_clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let max_timestamp = wall_clock.saturating_add(MAX_FUTURE_TIMESTAMP_OFFSET as u64);
    let timestamp = std::cmp::min(ideal_timestamp, max_timestamp);

    let header = BlockHeader {
        version: 1,
        previous_hash: ctx.previous_hash,
        state_root: ctx.state_root,
        tx_merkle_root,
        timestamp,
        bits: ctx.bits,
        height: ctx.height,
        nonce: 0,
    };

    Ok(Block {
        header,
        transactions,
    })
}

/// Mine a block by searching for a valid nonce.
///
/// Iterates the nonce field of the block header until the hash meets the target.
/// Returns the block with a valid nonce, or an error if no solution found.
/// Searches up to `u64::MAX` nonces with periodic progress yield points.
///
/// Uses RandomX PoW: input = prev_hash || merkle_root || nonce(LE).
/// Caller must ensure RandomX context is initialized via `ensure_randomx_for_height`.
pub fn mine_block(block: &mut Block) -> Result<()> {
    let target = block.header.bits.to_full_target();

    for nonce in 0..=u64::MAX {
        block.header.nonce = nonce;
        let pow_result = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            nonce,
            &[],
        )
        .map_err(|e| CoreError::InvalidProofOfWork(format!("RandomX PoW failed: {}", e)))?;
        if chroma_crypto::randomx::hash_meets_target(&pow_result, &target) {
            return Ok(());
        }

        if nonce % 10_000_000 == 0 && nonce > 0 {
            // Progress heartbeat — in production, this would yield to the runtime
        }
    }

    Err(CoreError::InvalidProofOfWork(
        "exhausted nonce search space".into(),
    ))
}

/// Mine a block with timeout.
///
/// Searches for at most `max_nonces` nonce values before returning an error.
/// Uses RandomX PoW: input = prev_hash || merkle_root || nonce(LE).
/// Caller must ensure RandomX context is initialized via `ensure_randomx_for_height`.
pub fn mine_block_with_limit(block: &mut Block, max_nonces: u64) -> Result<()> {
    let target = block.header.bits.to_full_target();

    for nonce in 0..max_nonces {
        block.header.nonce = nonce;
        let pow_result = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            nonce,
            &[],
        )
        .map_err(|e| CoreError::InvalidProofOfWork(format!("RandomX PoW failed: {}", e)))?;
        if chroma_crypto::randomx::hash_meets_target(&pow_result, &target) {
            return Ok(());
        }
    }

    Err(CoreError::InvalidProofOfWork(
        "nonce search limit reached without finding solution".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_genesis_block, build_genesis_block_with_bits};
    use chroma_core::constants::REGTEST_MAGIC;
    use chroma_core::hash::Hash160;
    use chroma_core::types::Address;

    fn test_address() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xAA;
        Address::from_hash160(Hash160(h))
    }

    fn easy_bits() -> CompactTarget {
        // Ultra-easy target for RandomX tests: 0x20ffffff
        // With RandomX (~1 hash/sec), we need nearly every nonce to succeed.
        // Target = 0xFFFFFF * 2^232 covers ~99.999% of hash space.
        CompactTarget(0x20ffffff)
    }

    #[test]
    fn test_assemble_block_empty_mempool() {
        let genesis = build_genesis_block();
        let genesis_hash = genesis.hash();

        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis_hash,
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: CompactTarget(0x1d00ffff),
            coinbase_recipient: test_address(),
        };

        let block = assemble_block(&ctx, &[]).unwrap();
        assert_eq!(block.header.height, BlockHeight(1));
        assert_eq!(block.header.previous_hash, genesis_hash);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);
        assert_eq!(block.transactions[0].nonce.0, 0);
        assert_ne!(block.header.tx_merkle_root, Hash::ZERO);
    }

    #[test]
    fn test_assemble_block_with_transactions() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: CompactTarget(0x1d00ffff),
            coinbase_recipient: test_address(),
        };

        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xBB; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let sender_addr = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

        let tx = chroma_tx::create_transaction(
            &secret,
            sender_addr,
            test_address(),
            Amount(100_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        let block = assemble_block(&ctx, &[tx]).unwrap();
        assert_eq!(block.transactions.len(), 2);
        assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);
    }

    #[test]
    fn test_mine_block_easy() {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        use chroma_crypto::randomx::{derive_seed, init_randomx_context};
        // Initialize RandomX with genesis seed for testing
        let seed = derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        init_randomx_context(&seed).unwrap();

        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[]).unwrap();
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let target = block.header.bits.to_full_target();
        let pow_result = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            block.header.nonce,
            &[],
        )
        .unwrap();
        assert!(
            chroma_crypto::randomx::hash_meets_target(&pow_result, &target),
            "mined block should meet target"
        );
    }

    #[test]
    fn test_mine_block_deterministic_per_nonce() {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        use chroma_crypto::randomx::{derive_seed, init_randomx_context};
        let seed = derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        init_randomx_context(&seed).unwrap();

        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[]).unwrap();

        let target = block.header.bits.to_full_target();

        let mut found_nonce = None;
        for nonce in 0..10_000_000u64 {
            block.header.nonce = nonce;
            let pow_result = chroma_crypto::randomx::pow_randomx(
                &block.header.previous_hash,
                &block.header.tx_merkle_root,
                nonce,
                &[],
            )
            .unwrap();
            if chroma_crypto::randomx::hash_meets_target(&pow_result, &target) {
                found_nonce = Some(nonce);
                break;
            }
        }

        let nonce = found_nonce.expect("should find a valid nonce");
        block.header.nonce = nonce;
        let pow_result = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            nonce,
            &[],
        )
        .unwrap();
        assert!(chroma_crypto::randomx::hash_meets_target(
            &pow_result,
            &target
        ));
    }

    #[test]
    fn test_coinbase_has_zero_sender_pubkey() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let block = assemble_block(&ctx, &[]).unwrap();
        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.sender_pubkey.0, [0u8; 32]);
        assert_eq!(coinbase.signature.0, [0u8; 64]);
    }

    #[test]
    fn test_mine_block_valid_pow() {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        use chroma_crypto::randomx::{derive_seed, init_randomx_context};
        let seed = derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        init_randomx_context(&seed).unwrap();

        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[]).unwrap();
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let target = block.header.bits.to_full_target();
        let pow_result = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            block.header.nonce,
            &[],
        )
        .unwrap();
        assert!(chroma_crypto::randomx::hash_meets_target(
            &pow_result,
            &target
        ));
    }

    #[test]
    fn test_mine_block_with_limit_respects_bound() {
        // Use an impossible target (difficulty 0 = maximum difficulty)
        // so no nonce will ever match, proving the limit stops the search.
        // With RandomX (~1 hash/sec), use a small limit to keep the test fast.
        let genesis = build_genesis_block_with_bits(CompactTarget(0x20ffffff));
        let impossible_bits = CompactTarget(0x00000001); // nearly impossible
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            previous_timestamp: genesis.header.timestamp,
            state_root: Hash::ZERO,
            bits: impossible_bits,
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[]).unwrap();
        let start = std::time::Instant::now();

        // With only 5 nonces and an impossible target, this must return Err quickly
        let result = mine_block_with_limit(&mut block, 5);
        let elapsed = start.elapsed();

        assert!(
            result.is_err(),
            "should fail to find solution with impossible target"
        );
        assert!(
            elapsed.as_millis() < 30_000,
            "bounded search with 5 nonces should complete in <30s, took {:?}",
            elapsed
        );
    }
}
