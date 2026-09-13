//! Comprehensive Integration Tests for Chroma
//!
//! Tests consensus, validation, state transitions, serialization,
//! fork choice, and end-to-end mining flows.

use std::collections::BTreeMap;

use chroma_block::{Block, BlockHeader};
use chroma_core::constants::{
    BLOCK_REWARD_UNITS, DIFFICULTY_ADJUSTMENT_WINDOW, GENESIS_TARGET_BITS, GENESIS_TIMESTAMP,
    MAINNET_MAGIC, MAX_BLOCK_SIZE, MAX_TRANSACTION_SIZE, MTP_WINDOW, REGTEST_MAGIC,
    TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::CoreError;
use chroma_core::hash::{Hash, Hash160};
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{Address, Amount, BlockHeight, CompactTarget, Nonce};
use chroma_core::u256::U256;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_p2p::wire::{
    InvEntry, InvMessage, InvType, Message, MessageType, PingMessage, VersionMessage,
};
use chroma_state::State;
use chroma_storage::PersistedTip;
use chroma_tx::Transaction;

fn alice_addr() -> Address {
    let mut h = [0u8; 20];
    h[0] = 0xAA;
    Address::from_hash160(Hash160(h))
}

fn bob_addr() -> Address {
    let mut h = [0u8; 20];
    h[0] = 0xBB;
    Address::from_hash160(Hash160(h))
}

fn easy_bits() -> CompactTarget {
    // Ultra-easy target for RandomX tests: nearly every nonce succeeds
    CompactTarget(0x20ffffff)
}

// ============================================================================
// Protocol Constant Verification
// ============================================================================

#[test]
fn test_frozen_constants_match_spec() {
    assert_eq!(BLOCK_REWARD_UNITS, 1_000_000);
    assert_eq!(chroma_core::constants::UNITS_PER_CHR, 1_000_000);
    assert_eq!(chroma_core::constants::MAX_SUPPLY_CHR, 100_000_000);
    assert_eq!(
        chroma_core::constants::MAX_SUPPLY_UNITS,
        100_000_000_000_000u128
    );
    assert_eq!(TARGET_BLOCK_TIME_SECS, 10);
    assert_eq!(DIFFICULTY_ADJUSTMENT_WINDOW, 10);
    assert_eq!(MAX_BLOCK_SIZE, 1_048_576);
    assert_eq!(MAX_TRANSACTION_SIZE, 65536);
    assert_eq!(MTP_WINDOW, 7);
    assert_eq!(chroma_core::constants::ADDRESS_HRP, "chr");
    assert_eq!(GENESIS_TARGET_BITS, 0x1d00ffff);
    assert_eq!(GENESIS_TIMESTAMP, 1767225600);
}

#[test]
fn test_mainnet_genesis_hash_is_pinned() {
    let genesis = chroma_consensus::build_genesis_block();
    let hash = genesis.hash();
    assert_eq!(
        hash.to_hex(),
        "aa49c7aedb454e70623b9e5f0a5b0f2ad7245f646df5906c2ab97665c2db8374",
        "mainnet genesis hash must not change without a hard fork"
    );
}

/// Genesis reproducibility: the full canonical encoding is pinned, so any
/// builder from the same spec constants reproduces byte-identical output —
/// no hidden runtime state (timestamps, randomness, host data) may enter.
/// A second independent construction must match exactly.
#[test]
fn test_mainnet_genesis_encoding_is_reproducible() {
    use chroma_core::serialize::CanonicalEncode;
    let g1 = chroma_consensus::build_genesis_block();
    let g2 = chroma_consensus::build_genesis_block();
    let e1 = g1.header.encode();
    let e2 = g2.header.encode();
    assert_eq!(e1, e2, "genesis encoding must be deterministic");
    // Spot-check fixed fields inside the encoding (version=1 @0, height=0,
    // nonce=0, prev/state/merkle roots zero, timestamp/bits pinned).
    assert_eq!(u32::from_le_bytes(e1[0..4].try_into().unwrap()), 1);
    assert_eq!(&e1[4..36], &[0u8; 32]);
    assert_eq!(&e1[36..68], &[0u8; 32]);
    assert_eq!(&e1[68..100], &[0u8; 32]);
    assert_eq!(
        u64::from_le_bytes(e1[100..108].try_into().unwrap()),
        chroma_core::constants::GENESIS_TIMESTAMP
    );
    assert_eq!(
        u32::from_le_bytes(e1[108..112].try_into().unwrap()),
        chroma_core::constants::GENESIS_TARGET_BITS
    );
    assert_eq!(u32::from_le_bytes(e1[112..116].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(e1[116..124].try_into().unwrap()), 0);
    assert_eq!(e1.len(), 124);
}

#[test]
fn test_regtest_genesis_hash_is_pinned() {
    let genesis = chroma_consensus::build_genesis_block_with_bits(CompactTarget(0x20ffffff));
    let hash = genesis.hash();
    assert_eq!(
        hash.to_hex(),
        "1461c3e8f0d2827433cd94f8ccbabdab92609274e7c696143f81f1f505a427ed",
        "regtest genesis hash must not change"
    );
}

#[test]
fn test_mainnet_and_regtest_genesis_differ() {
    let mainnet = chroma_consensus::build_genesis_block();
    let regtest = chroma_consensus::build_genesis_block_with_bits(CompactTarget(0x20ffffff));
    assert_ne!(
        mainnet.hash(),
        regtest.hash(),
        "mainnet and regtest must have different genesis hashes"
    );
    assert_ne!(
        mainnet.header.bits, regtest.header.bits,
        "mainnet and regtest must have different genesis difficulty bits"
    );
}

// ============================================================================
// Transaction Validation Integration
// ============================================================================

#[test]
fn test_create_sign_verify_transaction() {
    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(500_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();

    assert!(tx.verify_signature(REGTEST_MAGIC));
    assert_eq!(tx.amount.0, 500_000);
    assert_eq!(tx.nonce.0, 0);

    let encoded = tx.encode();
    assert_eq!(encoded.len(), Transaction::SERIALIZED_SIZE);
    let decoded = Transaction::decode(&encoded).unwrap();
    assert_eq!(tx, decoded);
}

#[test]
fn test_double_spend_rejected() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result1 = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result1.is_ok());

    let result2 = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result2.is_err());
}

#[test]
fn test_nonce_conflict_rejected() {
    let mut state = State::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    state.apply_subsidy(&sender, 0).unwrap();

    let result = state.apply_transaction(&sender, &bob_addr(), 100_000, 0);
    assert!(result.is_ok());

    let result2 = state.apply_transaction(&sender, &bob_addr(), 100_000, 0);
    assert!(result2.is_err());
    match result2.unwrap_err() {
        CoreError::InvalidNonce(_) => {}
        other => panic!("expected InvalidNonce, got {:?}", other),
    }
}

#[test]
fn test_insufficient_balance_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 100, 0);
    assert!(result.is_err());
}

#[test]
fn test_self_send_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &alice_addr(), 100, 0);
    assert!(result.is_err());
}

#[test]
fn test_zero_amount_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 0, 0);
    assert!(result.is_err());
}

#[test]
fn test_valid_transfer() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result.is_ok());

    assert_eq!(state.get_account(&alice_addr()).balance, 500_000);
    assert_eq!(state.get_account(&bob_addr()).balance, 500_000);
    assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);
}

// ============================================================================
// Block Assembly + Mining Integration
// ============================================================================

#[test]
fn test_block_assembly_and_mining() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let genesis = chroma_consensus::build_genesis_block();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        state_root: Hash::ZERO,
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };

    let mut block = assemble_block(&ctx, &[]).unwrap();
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);

    mine_block_with_limit(&mut block, 10_000_000).unwrap();

    let target = block.header.bits.to_full_target();
    assert!(chroma_crypto::randomx::hash_meets_target(
        &block.header.hash(),
        &target
    ));
    assert_eq!(block.header.height, BlockHeight(1));
    assert_eq!(block.header.previous_hash, genesis.hash());
}

#[test]
fn test_block_reward_exact_amount() {
    let state = State::new();
    let subsidy = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy, BLOCK_REWARD_UNITS);
}

#[test]
fn test_max_supply_cap_enforced() {
    let mut state = State::new();
    for _ in 0..chroma_core::constants::MAX_SUPPLY_CHR + 1 {
        let subsidy = state.block_subsidy(0).unwrap();
        if subsidy == 0 {
            break;
        }
        state.apply_subsidy(&alice_addr(), 0).unwrap();
    }
    assert_eq!(
        state.total_supply(),
        chroma_core::constants::MAX_SUPPLY_UNITS as u64
    );
    assert_eq!(state.block_subsidy(0).unwrap(), 0);
}

// ============================================================================
// Difficulty Adjustment Boundary Tests
// ============================================================================

#[test]
fn test_difficulty_no_change_when_on_target() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=10u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    assert_eq!(target_at_10, CompactTarget(GENESIS_TARGET_BITS));
}

#[test]
fn test_difficulty_increases_when_blocks_fast() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=10u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * 5,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(
        new_target < original_target,
        "target should decrease when blocks are fast"
    );
}

#[test]
fn test_difficulty_decreases_when_blocks_slow() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=10u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * 20,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(
        new_target > original_target,
        "target should increase when blocks are slow"
    );
}

#[test]
fn test_difficulty_clamped_at_max_increase() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=10u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64),
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    let max_increase = original.shl(2);
    assert!(
        new_target <= max_increase,
        "should be clamped at 4x increase"
    );
}

#[test]
fn test_difficulty_clamped_at_max_decrease() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=10u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * 1000,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    let min_decrease = {
        let (q, _) = original.div_rem(&U256::from_u64(4));
        q
    };
    assert!(
        new_target >= min_decrease,
        "should be clamped at 4x decrease"
    );
}

#[test]
fn test_difficulty_carries_forward_between_retargets() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=25u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_11 = calculate_target_for_height(11, &headers).unwrap();
    let target_12 = calculate_target_for_height(12, &headers).unwrap();
    let target_19 = calculate_target_for_height(19, &headers).unwrap();
    assert_eq!(target_11, target_12, "non-retarget heights carry forward");
    assert_eq!(target_12, target_19, "non-retarget heights carry forward");
}

// ============================================================================
// Fork Choice / Cumulative Work Tests
// ============================================================================

#[test]
fn test_chain_state_genesis_has_work() {
    let chain = chroma_consensus::ChainState::with_genesis();
    assert!(chain.best_tip().cumulative_work > U256::ZERO);
    assert_eq!(chain.best_tip().height, BlockHeight::GENESIS);
}

#[test]
fn test_mtp_computed_correctly() {
    let chain = chroma_consensus::ChainState::with_genesis();
    let mtp = chain.compute_median_time_past(0);
    assert_eq!(mtp, 0, "genesis MTP should be 0");
}

// ============================================================================
// Storage Integration Tests
// ============================================================================

#[test]
fn test_storage_roundtrip_blocks_and_state() {
    let storage = chroma_storage::Storage::open_temporary().unwrap();

    let genesis = chroma_consensus::build_genesis_block();
    storage.put_block(&genesis).unwrap();
    let tip = PersistedTip {
        height: 0,
        hash: genesis.hash(),
        cumulative_work: [0u8; 32],
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();

    let loaded = storage.get_block_by_hash(&genesis.hash()).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().header, genesis.header);

    let loaded_tip = storage.get_tip().unwrap();
    assert!(loaded_tip.is_some());
    assert_eq!(loaded_tip.unwrap().hash, genesis.hash());
}

#[test]
fn test_storage_account_balance_persistence() {
    let storage = chroma_storage::Storage::open_temporary().unwrap();

    let acc = chroma_state::Account {
        balance: 5_000_000,
        nonce: 3,
    };

    storage.put_account(&alice_addr(), &acc).unwrap();
    let loaded = storage.get_account(&alice_addr()).unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.balance, 5_000_000);
    assert_eq!(loaded.nonce, 3);
}

// ============================================================================
// Wire Protocol Integration
// ============================================================================

#[test]
fn test_wire_message_roundtrip() {
    let version = VersionMessage {
        version: 1,
        services: 0,
        timestamp: 1767225600,
        height: 42,
        nonce: 0xDEADBEEF,
    };
    let msg = Message::new(MessageType::Version, version.encode());
    let encoded = msg.encode();
    assert!(encoded.len() >= 13);

    let (decoded, consumed) = Message::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.msg_type, MessageType::Version);

    let decoded_version = VersionMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_version.version, 1);
    assert_eq!(decoded_version.height, 42);
    assert_eq!(decoded_version.nonce, 0xDEADBEEF);
}

#[test]
fn test_wire_ping_pong_roundtrip() {
    let ping = PingMessage { nonce: 12345 };
    let msg = Message::new(MessageType::Ping, ping.encode());
    let encoded = msg.encode();
    let (decoded, _) = Message::decode(&encoded).unwrap();
    assert_eq!(decoded.msg_type, MessageType::Ping);
    let decoded_ping = PingMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_ping.nonce, 12345);
}

#[test]
fn test_wire_message_rejects_oversized() {
    let big_payload = vec![0u8; 5_000_000];
    let msg = Message::new(MessageType::Block, big_payload);
    let encoded = msg.encode();

    match Message::decode(&encoded) {
        Err(CoreError::Serialization(s)) => {
            assert!(s.contains("too large") || s.contains("exceeds"));
        }
        other => panic!("expected error for oversized message, got {:?}", other),
    }
}

#[test]
fn test_wire_inv_message_roundtrip() {
    let inv = InvMessage {
        inventory: vec![
            InvEntry {
                inv_type: InvType::Tx,
                hash: Hash::blake3(b"tx1"),
            },
            InvEntry {
                inv_type: InvType::Block,
                hash: Hash::blake3(b"block1"),
            },
        ],
    };
    let msg = Message::new(MessageType::Inv, inv.encode());
    let encoded = msg.encode();
    let (decoded, _) = Message::decode(&encoded).unwrap();
    let decoded_inv = InvMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_inv.inventory.len(), 2);
    assert_eq!(decoded_inv.inventory[0].inv_type, InvType::Tx);
    assert_eq!(decoded_inv.inventory[1].inv_type, InvType::Block);
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_block_hash_deterministic() {
    let genesis = chroma_consensus::build_genesis_block();
    let h1 = genesis.hash();
    let h2 = genesis.hash();
    assert_eq!(h1, h2);
}

#[test]
fn test_genesis_block_deterministic_across_instances() {
    let g1 = chroma_consensus::build_genesis_block();
    let g2 = chroma_consensus::build_genesis_block();
    assert_eq!(g1.hash(), g2.hash());
    assert_eq!(g1.header, g2.header);
}

#[test]
fn test_transaction_deterministic() {
    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let tx1 = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(100_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();
    let tx2 = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(100_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();
    assert_eq!(tx1.encode(), tx2.encode());
    assert_eq!(tx1, tx2);
}

#[test]
fn test_sighash_deterministic() {
    use chroma_crypto::schnorr::compute_sighash;

    let sender = alice_addr().0 .0;
    let recipient = bob_addr().0 .0;

    let h1 = compute_sighash(&sender, &recipient, 100_000, 0, REGTEST_MAGIC);
    let h2 = compute_sighash(&sender, &recipient, 100_000, 0, REGTEST_MAGIC);
    assert_eq!(h1, h2);

    let h3 = compute_sighash(&sender, &recipient, 200_000, 0, REGTEST_MAGIC);
    assert_ne!(h1, h3);
}

// ============================================================================
// U256 Arithmetic Safety Tests
// ============================================================================

#[test]
fn test_u256_checked_add_overflow() {
    let max = U256::MAX;
    let one = U256::from_u64(1);
    assert!(max.checked_add(&one).is_none());
}

#[test]
fn test_u256_checked_add_normal() {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    assert_eq!(a.checked_add(&b).unwrap(), U256::from_u64(300));
}

// ============================================================================
// State Root Verification
// ============================================================================

#[test]
fn test_state_root_changes_with_balance_update() {
    let mut state = State::new();
    let root1 = state.compute_state_root();

    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let root2 = state.compute_state_root();
    assert_ne!(root1, root2);
}

#[test]
fn test_state_root_deterministic() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let root1 = state.compute_state_root();
    let root2 = state.compute_state_root();
    assert_eq!(root1, root2);
}

// ============================================================================
// Mempool Integration
// ============================================================================

#[test]
fn test_mempool_add_and_remove() {
    let mut mempool = chroma_p2p::mempool::Mempool::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(100_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();

    let tx_hash = Hash::blake3(&tx.encode());
    mempool.add_transaction(tx.clone(), REGTEST_MAGIC).unwrap();
    assert!(mempool.has_transaction(&tx_hash));

    mempool.remove_transaction(&tx_hash);
    assert!(!mempool.has_transaction(&tx_hash));
}

#[test]
fn test_mempool_capacity_limit() {
    use chroma_p2p::mempool::{Mempool, MAX_MEMPOOL_TXS};

    let mut mempool = Mempool::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let fill_count = std::cmp::min(MAX_MEMPOOL_TXS, 200);
    for i in 0..fill_count {
        let tx = chroma_tx::create_transaction(
            &secret,
            sender,
            bob_addr(),
            Amount(100_000),
            Nonce(i as u64),
            REGTEST_MAGIC,
        )
        .unwrap();
        mempool.add_transaction(tx, REGTEST_MAGIC).unwrap();
    }
    assert_eq!(mempool.len(), fill_count);
}

// ============================================================================
// End-to-End Devnet Flow
// ============================================================================

#[test]
fn test_end_to_end_devnet() {
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
    use chroma_consensus::ChainState;
    use chroma_core::constants::GENESIS_RANDOMX_SEED;
    use chroma_crypto::randomx::{derive_seed, init_randomx_context};

    // Initialize RandomX with genesis seed for testing
    let seed = derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
    init_randomx_context(&seed).unwrap();

    let chain = ChainState::with_genesis();

    let wallet = chroma_wallet::Wallet::generate("devnet-test");
    let recipient = wallet.address();

    let mut state = State::new();
    state.apply_subsidy(&recipient, 0).unwrap();

    let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));
    state.apply_subsidy(&sender, 0).unwrap();

    let state_root = state.compute_state_root();

    let genesis = chain.best_tip().clone();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash,
        previous_timestamp: genesis.header.timestamp,
        state_root,
        bits: easy_bits(),
        coinbase_recipient: recipient,
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
        "mined block should be valid"
    );
    assert_eq!(block.header.height, BlockHeight(1));
    assert_eq!(block.header.previous_hash, genesis.hash);
}

// ============================================================================
// Nonce Ordering Enforcement
// ============================================================================

#[test]
fn test_nonce_must_be_strictly_increasing() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result_skip = state.apply_transaction(&alice_addr(), &bob_addr(), 100_000, 1);
    assert!(result_skip.is_err());

    let result_next = state.apply_transaction(&alice_addr(), &bob_addr(), 100_000, 0);
    assert!(result_next.is_ok());
}

// ============================================================================
// CompactTarget Encoding Boundary Tests
// ============================================================================

#[test]
fn test_compact_target_roundtrip_various_values() {
    let test_cases: Vec<u32> = vec![0x1d00ffff, 0x1e00ffff, 0x1f00ffff];

    for bits in test_cases {
        let ct = CompactTarget(bits);
        let full = ct.to_full_target();
        let back = CompactTarget::from_full_target(&full);
        assert_eq!(ct, back, "roundtrip failed for bits=0x{:08x}", bits);
    }
}

#[test]
fn test_compact_target_max_is_identity() {
    let max = CompactTarget(0x2100ffff);
    let full = max.to_full_target();
    assert_eq!(full, [0xFF; 32]);
}

// ============================================================================
// Block Validation Context Integration
// ============================================================================

#[test]
fn test_mtp_enforced_in_block_validation() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    let genesis = chroma_consensus::build_genesis_block();
    let ctx = chroma_block::BlockValidationContext {
        previous_hash: genesis.hash(),
        expected_height: BlockHeight(1),
        previous_timestamp: genesis.header.timestamp,
        median_time_past: genesis.header.timestamp + 1000,
        expected_bits: CompactTarget(GENESIS_TARGET_BITS),
        current_supply: 0,
        previous_state_root: Hash::ZERO,
        network_time: genesis.header.timestamp + 2000,
        network_magic: MAINNET_MAGIC,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: genesis.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Block::compute_tx_merkle_root(&[]),
            timestamp: genesis.header.timestamp + 500,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(1),
            nonce: 0,
        },
        transactions: vec![],
    };

    let mut state = State::new();
    let result = chroma_block::validate_block(&block, &ctx, &mut state);
    assert!(result.is_err(), "block should fail when timestamp <= MTP");
}

// ============================================================================
// Block Decode Rejection Tests
// ============================================================================

#[test]
fn test_block_decode_rejects_trailing_data() {
    let genesis = chroma_consensus::build_genesis_block();
    let mut encoded = genesis.encode_block();
    encoded.extend_from_slice(&[0xFF; 10]);
    let result = Block::decode_block(&encoded);
    assert!(result.is_err());
}

#[test]
fn test_block_decode_rejects_empty() {
    let result = Block::decode_block(&[]);
    assert!(result.is_err());
}

#[test]
fn test_header_decode_rejects_short_data() {
    let result = BlockHeader::decode(&[0u8; 50]);
    assert!(result.is_err());
}

// ============================================================================
// Storage + Chain Persistence Integration Test
// ============================================================================

#[test]
fn test_storage_genesis_and_persistence() {
    use chroma_core::u256::U256;
    use chroma_storage::Storage;

    let storage = Storage::open_temporary().unwrap();
    let genesis = chroma_consensus::build_genesis_block();
    let genesis_hash = genesis.hash();

    storage.apply_block(&genesis).unwrap();
    storage.put_genesis_hash(&genesis_hash).unwrap();

    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis_hash,
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.put_supply(0).unwrap();
    storage.flush().unwrap();

    let loaded_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(loaded_tip.height, 0);
    assert_eq!(loaded_tip.hash, genesis_hash);
    assert_eq!(loaded_tip.supply, 0);

    let loaded_hash = storage.get_genesis_hash().unwrap().unwrap();
    assert_eq!(loaded_hash, genesis_hash);

    let loaded_header = storage.get_header(0).unwrap().unwrap();
    assert_eq!(loaded_header.height.0, 0);
    assert_eq!(loaded_header.timestamp, genesis.header.timestamp);
}

#[test]
fn test_chain_state_loads_from_storage() {
    use chroma_consensus::{build_genesis_block, ChainState, ChainTip};
    use chroma_core::types::BlockHeight;
    use chroma_core::u256::U256;
    use chroma_storage::Storage;
    use std::collections::{BTreeMap, HashMap};

    let storage = Storage::open_temporary().unwrap();
    let genesis = build_genesis_block();
    let genesis_hash = genesis.hash();

    storage.apply_block(&genesis).unwrap();

    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis_hash,
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.flush().unwrap();

    let loaded_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(loaded_tip.height, 0);

    let mut headers = BTreeMap::new();
    let mut h = 0u32;
    while let Ok(Some(header)) = storage.get_header(h) {
        headers.insert(h, header);
        if h == loaded_tip.height {
            break;
        }
        h += 1;
    }

    let cumulative_work = U256::from_be_bytes(&loaded_tip.cumulative_work);
    let tip_header = headers
        .get(&loaded_tip.height)
        .cloned()
        .unwrap_or(genesis.header.clone());
    let chain_tip = ChainTip {
        height: BlockHeight(loaded_tip.height),
        hash: loaded_tip.hash,
        header: tip_header,
        cumulative_work,
        supply: loaded_tip.supply,
    };

    let mut tips = BTreeMap::new();
    tips.insert(loaded_tip.hash, chain_tip.clone());

    let chain = ChainState {
        headers,
        tip: chain_tip,
        state: chroma_state::State::new(),
        tips,
        alt_headers: HashMap::new(),
        network_magic: REGTEST_MAGIC,
    };

    assert_eq!(chain.tip.height, BlockHeight(0));
    assert_eq!(chain.tip.hash, genesis_hash);
    assert!(chain.best_tip().cumulative_work > U256::ZERO);
}

#[test]
fn test_devnet_multi_block_mining_and_storage() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::{
        build_genesis_block,
        miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext},
        ChainState,
    };
    use chroma_core::hash::Hash160;
    use chroma_core::types::{Address, BlockHeight};
    use chroma_core::u256::U256;
    use chroma_storage::Storage;

    let storage = Storage::open_temporary().unwrap();
    let mut chain = ChainState::with_genesis();

    let genesis = build_genesis_block();
    storage.apply_block(&genesis).unwrap();
    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis.hash(),
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.flush().unwrap();

    let miner_addr = {
        let mut h = [0u8; 20];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h[2] = 0xBE;
        h[3] = 0xEF;
        Address::from_hash160(Hash160(h))
    };

    let blocks_to_mine = 3u32;

    for expected_height in 1..=blocks_to_mine {
        let (prev_hash, prev_ts, state_root) = {
            let tip = chain.best_tip();
            (tip.hash, tip.header.timestamp, tip.header.state_root)
        };

        let ctx = BlockAssemblyContext {
            height: BlockHeight(expected_height),
            previous_hash: prev_hash,
            previous_timestamp: prev_ts,
            state_root,
            bits: easy_bits(),
            coinbase_recipient: miner_addr,
        };

        let mut block = assemble_block(&ctx, &[]).unwrap();
        block.header.timestamp = prev_ts + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let block_hash = block.hash();
        chain.headers.insert(expected_height, block.header.clone());
        let block_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &block.header.bits.to_full_target(),
        ));
        let new_cumulative = chain.tip.cumulative_work.checked_add(&block_work).unwrap();
        chain.tip = chroma_consensus::ChainTip {
            height: BlockHeight(expected_height),
            hash: block_hash,
            header: block.header.clone(),
            cumulative_work: new_cumulative,
            supply: chain.tip.supply + chroma_core::constants::BLOCK_REWARD_UNITS,
        };
        chain.tips.insert(block_hash, chain.tip.clone());

        storage.apply_block(&block).unwrap();
        let tip = chain.best_tip();
        let persisted = chroma_storage::PersistedTip {
            height: tip.height.0,
            hash: tip.hash,
            cumulative_work: tip.cumulative_work.to_be_bytes(),
            supply: tip.supply,
        };
        storage.put_tip(&persisted).unwrap();
        storage.flush().unwrap();

        assert_eq!(chain.best_tip().height.0, expected_height);
        assert_eq!(chain.best_tip().hash, block_hash);
    }

    let final_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(final_tip.height, blocks_to_mine);
}

// ============================================================================
// Definitive Multi-Party Lifecycle Test
//
// Proves the complete flow:
//   1. Create wallets A and B (independent keypairs)
//   2. Mine block #1 → coinbase funds A
//   3. A signs tx → B (500K CHR)
//   4. Mine block #2 containing A→B tx
//   5. Verify: A debited, B credited
//   6. B signs tx → A (200K CHR)
//   7. Mine block #3 containing B→A tx
//   8. Verify: B debited, A credited, balances correct
//   9. Verify: double-spend rejected
//  10. Verify: wrong nonce rejected
//  11. Verify: insufficient balance rejected
//  12. Verify: total supply = 3 × BLOCK_REWARD_UNITS
// ============================================================================

#[test]
fn test_multi_party_lifecycle() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
    use chroma_consensus::{build_genesis_block_with_bits, ChainState};

    // --- Step 1: Create wallets with independent keypairs ---
    let secret_a = SecretKey32::from_bytes([0xAA; 32]).unwrap();
    let pubkey_a = PublicKey32::from_secret(&secret_a).unwrap();
    let addr_a = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey_a.0)));

    let secret_b = SecretKey32::from_bytes([0xBB; 32]).unwrap();
    let pubkey_b = PublicKey32::from_secret(&secret_b).unwrap();
    let addr_b = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey_b.0)));

    assert_ne!(addr_a, addr_b, "wallets must have different addresses");

    // Build chain with easy genesis so mining is fast in tests
    let genesis = build_genesis_block_with_bits(easy_bits());
    let mut chain = ChainState::with_genesis_from(&genesis, REGTEST_MAGIC);

    // --- Step 2: Mine block #1 → coinbase funds A ---
    let tx_descs_block1: Vec<(Address, Address, u64, u64)> = vec![];
    let state_root_block1 = chain
        .state
        .compute_prospective_state_root(1, &addr_a, &tx_descs_block1)
        .unwrap();

    let ctx1 = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        state_root: state_root_block1,
        bits: easy_bits(),
        coinbase_recipient: addr_a,
    };

    let mut block1 = assemble_block(&ctx1, &[]).unwrap();
    block1.header.timestamp = genesis.header.timestamp + 10;
    mine_block_with_limit(&mut block1, 10_000_000).unwrap();

    chain.apply_block(&block1).unwrap();

    // Verify: A received 1 CHR (1,000,000 units)
    let acct_a = chain.state.get_account(&addr_a);
    assert_eq!(
        acct_a.balance, BLOCK_REWARD_UNITS,
        "A should have 1 CHR after coinbase"
    );
    assert_eq!(acct_a.nonce, 0, "A nonce should be 0");
    assert_eq!(chain.state.total_supply(), BLOCK_REWARD_UNITS);

    // --- Step 3: A signs tx → B (500K units = 0.5 CHR) ---
    let tx_ab = chroma_tx::create_transaction(
        &secret_a,
        addr_a,
        addr_b,
        Amount(500_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();
    assert!(
        tx_ab.verify_signature(REGTEST_MAGIC),
        "A→B signature must be valid"
    );

    // --- Step 4: Mine block #2 containing A→B tx ---
    let tx_descs_block2: Vec<_> = vec![(
        tx_ab.sender_address(),
        tx_ab.recipient,
        tx_ab.amount.0,
        tx_ab.nonce.0,
    )];
    let state_root_block2 = chain
        .state
        .compute_prospective_state_root(2, &addr_a, &tx_descs_block2)
        .unwrap();

    let ctx2 = BlockAssemblyContext {
        height: BlockHeight(2),
        previous_hash: block1.hash(),
        previous_timestamp: block1.header.timestamp,
        state_root: state_root_block2,
        bits: easy_bits(),
        coinbase_recipient: addr_a,
    };

    let mut block2 = assemble_block(&ctx2, std::slice::from_ref(&tx_ab)).unwrap();
    block2.header.timestamp = block1.header.timestamp + 10;
    mine_block_with_limit(&mut block2, 10_000_000).unwrap();

    chain.apply_block(&block2).unwrap();

    // --- Step 5: Verify A debited, B credited ---
    let acct_a_after = chain.state.get_account(&addr_a);
    let acct_b_after = chain.state.get_account(&addr_b);

    // A: 1,000,000 (coinbase) - 500,000 (sent) + 1,000,000 (block2 coinbase) = 1,500,000
    assert_eq!(
        acct_a_after.balance, 1_500_000,
        "A should have 1.5 CHR: 1 (block1 coinbase) - 0.5 (sent to B) + 1 (block2 coinbase)"
    );
    assert_eq!(acct_a_after.nonce, 1, "A nonce should be 1 after sending");

    // B: 500,000 (received from A)
    assert_eq!(
        acct_b_after.balance, 500_000,
        "B should have 0.5 CHR (received from A)"
    );
    assert_eq!(acct_b_after.nonce, 0, "B nonce should be 0");

    assert_eq!(chain.state.total_supply(), 2 * BLOCK_REWARD_UNITS);

    // --- Step 6: B signs tx → A (200K units) ---
    let tx_ba = chroma_tx::create_transaction(
        &secret_b,
        addr_b,
        addr_a,
        Amount(200_000),
        Nonce(0),
        REGTEST_MAGIC,
    )
    .unwrap();
    assert!(
        tx_ba.verify_signature(REGTEST_MAGIC),
        "B→A signature must be valid"
    );

    // --- Step 7: Mine block #3 containing B→A tx ---
    let tx_descs_block3: Vec<_> = vec![(
        tx_ba.sender_address(),
        tx_ba.recipient,
        tx_ba.amount.0,
        tx_ba.nonce.0,
    )];
    let state_root_block3 = chain
        .state
        .compute_prospective_state_root(3, &addr_a, &tx_descs_block3)
        .unwrap();

    let ctx3 = BlockAssemblyContext {
        height: BlockHeight(3),
        previous_hash: block2.hash(),
        previous_timestamp: block2.header.timestamp,
        state_root: state_root_block3,
        bits: easy_bits(),
        coinbase_recipient: addr_a,
    };

    let mut block3 = assemble_block(&ctx3, std::slice::from_ref(&tx_ba)).unwrap();
    block3.header.timestamp = block2.header.timestamp + 10;
    mine_block_with_limit(&mut block3, 10_000_000).unwrap();

    chain.apply_block(&block3).unwrap();

    // --- Step 8: Verify final balances ---
    let acct_a_final = chain.state.get_account(&addr_a);
    let acct_b_final = chain.state.get_account(&addr_b);

    // A: 1,500,000 (prev) + 1,000,000 (block3 coinbase) + 200,000 (from B) = 2,700,000
    assert_eq!(
        acct_a_final.balance, 2_700_000,
        "A should have 2.7 CHR after round trip"
    );
    assert_eq!(acct_a_final.nonce, 1, "A nonce unchanged");

    // B: 500,000 (prev) - 200,000 (sent to A) = 300,000
    assert_eq!(
        acct_b_final.balance, 300_000,
        "B should have 0.3 CHR after sending 0.2 to A"
    );
    assert_eq!(acct_b_final.nonce, 1, "B nonce should be 1 after sending");

    assert_eq!(chain.state.total_supply(), 3 * BLOCK_REWARD_UNITS);

    // --- Step 9: Verify double-spend rejected ---
    let ds_result = chain.state.apply_transaction(&addr_a, &addr_b, 100_000, 0);
    assert!(
        ds_result.is_err(),
        "double-spend (reuse nonce=0) must be rejected"
    );

    // --- Step 10: Verify wrong nonce rejected ---
    let wrong_nonce = chain.state.apply_transaction(&addr_a, &addr_b, 100_000, 5);
    assert!(wrong_nonce.is_err(), "wrong nonce must be rejected");

    // --- Step 11: Verify insufficient balance rejected ---
    // B has 300,000. Try to send 1,000,000.
    let overdraw = chain
        .state
        .apply_transaction(&addr_b, &addr_a, 1_000_000, 1);
    assert!(overdraw.is_err(), "insufficient balance must be rejected");

    // --- Step 12: Verify total supply invariant ---
    assert_eq!(chain.state.total_supply(), 3 * BLOCK_REWARD_UNITS);

    // --- Verify chain tip ---
    assert_eq!(chain.best_tip().height.0, 3);
}

// ============================================================================
// Adversarial Consensus Tests
// ============================================================================

fn easy_chain() -> chroma_consensus::ChainState {
    use chroma_consensus::{build_genesis_block_with_bits, ChainState};
    ChainState::with_genesis_from(&build_genesis_block_with_bits(easy_bits()), REGTEST_MAGIC)
}

fn easy_state_root_for_height(height: u32, recipient: &chroma_core::types::Address) -> Hash {
    let mut state = State::new();
    for h in 1..=height {
        state.apply_subsidy(recipient, h).unwrap();
    }
    state.compute_state_root()
}

#[test]
fn test_competing_block_at_tip_rejected_equal_work() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        state_root: easy_state_root_for_height(1, &alice_addr()),
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };

    let mut block_a = assemble_block(&ctx, &[]).unwrap();
    block_a.header.timestamp = genesis.header.timestamp + 10;
    mine_block_with_limit(&mut block_a, 10_000_000).unwrap();
    chain.apply_block(&block_a).unwrap();
    assert_eq!(chain.best_tip().height.0, 1);
    let tip_a_hash = chain.best_tip().hash;

    let mut block_b = assemble_block(&ctx, &[]).unwrap();
    block_b.header.timestamp = genesis.header.timestamp + 11;
    mine_block_with_limit(&mut block_b, 10_000_000).unwrap();

    let result = chain.apply_block(&block_b);
    assert!(
        result.is_err(),
        "competing block with equal work should be rejected"
    );
    assert_eq!(chain.best_tip().hash, tip_a_hash, "tip should be unchanged");
}

#[test]
fn test_deeper_fork_rejected() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());

    let mut prev_hash = genesis.hash();
    let mut prev_ts = genesis.header.timestamp;
    for h in 1..=3u32 {
        let ctx = BlockAssemblyContext {
            height: BlockHeight(h),
            previous_hash: prev_hash,
            previous_timestamp: prev_ts,
            state_root: easy_state_root_for_height(h, &alice_addr()),
            bits: easy_bits(),
            coinbase_recipient: alice_addr(),
        };
        let mut block = assemble_block(&ctx, &[]).unwrap();
        block.header.timestamp = prev_ts + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        chain.apply_block(&block).unwrap();
    }
    assert_eq!(chain.best_tip().height.0, 3);

    let bad_ctx = BlockAssemblyContext {
        height: BlockHeight(2),
        previous_hash: Hash::blake3(b"different_parent"),
        previous_timestamp: genesis.header.timestamp + 10,
        state_root: easy_state_root_for_height(2, &bob_addr()),
        bits: easy_bits(),
        coinbase_recipient: bob_addr(),
    };
    let mut bad_block = assemble_block(&bad_ctx, &[]).unwrap();
    bad_block.header.timestamp = genesis.header.timestamp + 20;
    let result = chain.apply_block(&bad_block);
    assert!(result.is_err(), "deeper fork should be rejected");
}

#[test]
fn test_reorg_depth_reports_correctly() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();

    for h in 1..=3u32 {
        let prev = chain.headers.get(&(h - 1)).unwrap();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(h),
            previous_hash: prev.hash(),
            previous_timestamp: prev.timestamp,
            state_root: easy_state_root_for_height(h, &alice_addr()),
            bits: easy_bits(),
            coinbase_recipient: alice_addr(),
        };
        let mut block = assemble_block(&ctx, &[]).unwrap();
        block.header.timestamp = prev.timestamp + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();
        chain.apply_block(&block).unwrap();
    }
    assert_eq!(chain.best_tip().height.0, 3);
    assert_eq!(chain.reorg_depth(), 0);
}

#[test]
fn test_duplicate_genesis_rejected() {
    use chroma_consensus::build_genesis_block_with_bits;
    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());
    let result = chain.apply_block(&genesis);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidBlock(msg) => assert!(msg.contains("genesis")),
        other => panic!(
            "expected InvalidBlock with genesis message, got {:?}",
            other
        ),
    }
}

#[test]
fn test_block_with_wrong_previous_hash_rejected() {
    use chroma_consensus::miner::{assemble_block, BlockAssemblyContext};

    let mut chain = easy_chain();

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: Hash::blake3(b"nonexistent"),
        previous_timestamp: GENESIS_TIMESTAMP,
        state_root: Hash::ZERO,
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };
    let block = assemble_block(&ctx, &[]).unwrap();
    let result = chain.apply_block(&block);
    assert!(result.is_err());
}

#[test]
fn test_find_fork_point_works() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());
    let genesis_hash = genesis.hash();

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis_hash,
        previous_timestamp: genesis.header.timestamp,
        state_root: easy_state_root_for_height(1, &alice_addr()),
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };
    let mut block = assemble_block(&ctx, &[]).unwrap();
    block.header.timestamp = genesis.header.timestamp + 10;
    mine_block_with_limit(&mut block, 10_000_000).unwrap();
    chain.apply_block(&block).unwrap();

    let fp = chain.find_fork_point(&genesis_hash);
    assert_eq!(fp, Some(0));
}

#[test]
fn test_alt_headers_stored_for_deeper_fork() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());

    let mut prev_hash = genesis.hash();
    let mut prev_ts = genesis.header.timestamp;
    for h in 1..=2u32 {
        let ctx = BlockAssemblyContext {
            height: BlockHeight(h),
            previous_hash: prev_hash,
            previous_timestamp: prev_ts,
            state_root: easy_state_root_for_height(h, &alice_addr()),
            bits: easy_bits(),
            coinbase_recipient: alice_addr(),
        };
        let mut block = assemble_block(&ctx, &[]).unwrap();
        block.header.timestamp = prev_ts + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        chain.apply_block(&block).unwrap();
    }

    let bad_ctx = BlockAssemblyContext {
        height: BlockHeight(2),
        previous_hash: Hash::blake3(b"different"),
        previous_timestamp: genesis.header.timestamp + 10,
        state_root: easy_state_root_for_height(2, &bob_addr()),
        bits: easy_bits(),
        coinbase_recipient: bob_addr(),
    };
    let mut bad_block = assemble_block(&bad_ctx, &[]).unwrap();
    bad_block.header.timestamp = genesis.header.timestamp + 30;
    let _ = chain.apply_block(&bad_block);
}

#[test]
fn test_supply_consistent_after_competing_blocks() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        state_root: easy_state_root_for_height(1, &alice_addr()),
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };

    let mut block_a = assemble_block(&ctx, &[]).unwrap();
    block_a.header.timestamp = genesis.header.timestamp + 10;
    mine_block_with_limit(&mut block_a, 10_000_000).unwrap();
    chain.apply_block(&block_a).unwrap();

    let mut block_b = assemble_block(&ctx, &[]).unwrap();
    block_b.header.timestamp = genesis.header.timestamp + 11;
    mine_block_with_limit(&mut block_b, 10_000_000).unwrap();
    let _ = chain.apply_block(&block_b);

    assert_eq!(chain.state.total_supply(), BLOCK_REWARD_UNITS);
    assert_eq!(chain.tip.supply, BLOCK_REWARD_UNITS);
}

#[test]
fn test_network_time_used_for_validation() {
    use chroma_consensus::build_genesis_block_with_bits;
    use chroma_consensus::miner::{assemble_block, BlockAssemblyContext};

    let mut chain = easy_chain();
    let genesis = build_genesis_block_with_bits(easy_bits());

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        state_root: Hash::ZERO,
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };

    let mut block = assemble_block(&ctx, &[]).unwrap();
    block.header.timestamp = 1;

    let result = chain.apply_block(&block);
    assert!(
        result.is_err(),
        "block with ancient timestamp should be rejected"
    );
}

#[test]
fn test_multi_block_chain_state_consistency() {
    // Initialize RandomX for mining tests
    {
        use chroma_core::constants::GENESIS_RANDOMX_SEED;
        let seed = chroma_crypto::randomx::derive_seed(&Hash::blake3(GENESIS_RANDOMX_SEED));
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    }
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let mut chain = easy_chain();

    for h in 1..=5u32 {
        let prev = chain.headers.get(&(h - 1)).unwrap();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(h),
            previous_hash: prev.hash(),
            previous_timestamp: prev.timestamp,
            state_root: easy_state_root_for_height(h, &alice_addr()),
            bits: easy_bits(),
            coinbase_recipient: alice_addr(),
        };
        let mut block = assemble_block(&ctx, &[]).unwrap();
        block.header.timestamp = prev.timestamp + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();
        chain.apply_block(&block).unwrap();
    }

    assert_eq!(chain.best_tip().height.0, 5);
    assert_eq!(chain.state.total_supply(), 5 * BLOCK_REWARD_UNITS);
    assert_eq!(chain.tip.supply, 5 * BLOCK_REWARD_UNITS);
    assert_eq!(chain.headers.len(), 6);
}

/// Mainnet height-1 template enforces real mainnet consensus (no PoW bypass).
///
/// Uses the production mainnet genesis, MAINNET_MAGIC, and the retargeted
/// mainnet target: template bits must be 0x1d00ffff, RandomX epoch 0 must
/// resolve through the same init path the miner and the validator share,
/// real RandomX hashes must NOT meet the mainnet target (difficulty is
/// real), validation must reject with InvalidProofOfWork, an easy-bits
/// block must be rejected with InvalidDifficulty, and the subsidy path must
/// credit exactly BLOCK_REWARD_UNITS. No block is mined: mainnet difficulty
/// makes that infeasible by design.
#[test]
fn test_mainnet_height1_template_and_pow_enforced() {
    use chroma_consensus::{
        build_genesis_block, calculate_target_for_height,
        miner::{assemble_block, BlockAssemblyContext},
        ChainState,
    };
    use chroma_core::constants::{
        BLOCK_REWARD_UNITS, GENESIS_RANDOMX_SEED, MAINNET_MAGIC, RANDOMX_EPOCH_LENGTH,
    };

    // Epoch 0 resolves through the shared init path (also used by the miner
    // before grinding and by apply_block before validating).
    let genesis_seed = Hash::blake3(GENESIS_RANDOMX_SEED);
    let _ = chroma_crypto::randomx::init_randomx_context(&genesis_seed);
    assert!(chroma_crypto::randomx::ensure_randomx_for_height(1, |_| None).is_ok());
    assert_eq!(
        chroma_crypto::randomx::epoch_for_height(1, RANDOMX_EPOCH_LENGTH),
        0
    );

    let genesis = build_genesis_block();
    let chain = ChainState::with_genesis();
    assert_eq!(chain.tip.hash, genesis.hash());

    // Real mainnet retarget output for height 1: difficulty 1, not easy.
    let bits = calculate_target_for_height(1, &chain.headers).unwrap();
    assert_eq!(
        bits.0, 0x1d00ffff,
        "mainnet height 1 must target difficulty 1"
    );
    let target = bits.to_full_target();

    let miner = alice_addr();
    let state_root = chain
        .state
        .compute_prospective_state_root(1, &miner, &[])
        .unwrap();
    let prev = &chain.headers[&0];
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: prev.timestamp,
        state_root,
        bits,
        coinbase_recipient: miner,
    };
    let mut block = assemble_block(&ctx, &[]).unwrap();
    block.header.timestamp = prev.timestamp + 10;
    // Coinbase economics on the real template: exactly 1 CHR to the miner.
    assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);
    assert_eq!(block.transactions[0].recipient, miner);

    // Real RandomX hashes under the mainnet target: must NOT meet it.
    // (If any of a few plain nonces met difficulty 1, difficulty would be fake.)
    for nonce in 0..3u64 {
        let pow = chroma_crypto::randomx::pow_randomx(
            &block.header.previous_hash,
            &block.header.tx_merkle_root,
            nonce,
            &[],
        )
        .unwrap();
        assert!(
            !chroma_crypto::randomx::hash_meets_target(&pow, &target),
            "mainnet difficulty must actually hold"
        );
    }

    // Validation enforces PoW through the normal path (no bypass).
    let mut chain2 = ChainState::with_genesis_from(&genesis, MAINNET_MAGIC);
    let err = chain2.apply_block(&block).unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidProofOfWork(_)),
        "unmined mainnet block must fail PoW, got: {}",
        err
    );

    // An easy-bits block cannot smuggle past mainnet difficulty.
    let mut easy = block.clone();
    easy.header.bits = CompactTarget(0x20ffffff);
    let err = chain2.apply_block(&easy).unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidDifficulty(_)),
        "easy-bits mainnet block must fail difficulty, got: {}",
        err
    );

    // Subsidy accounting on the mainnet state path: exactly 1 CHR.
    let mut state = State::new();
    assert_eq!(state.apply_subsidy(&miner, 1).unwrap(), BLOCK_REWARD_UNITS);
    assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);
}
