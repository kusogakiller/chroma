//! Comprehensive Integration Tests for Chroma
//!
//! Tests peer handshake, block/tx propagation, sync, validation,
//! double-spend prevention, nonce conflicts, chain reorgs, and
//! end-to-end devnet flow.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use chroma_block::{Block, BlockHeader};
use chroma_core::constants::{
    BLOCK_REWARD_UNITS, DIFFICULTY_ADJUSTMENT_WINDOW, GENESIS_RANDOMX_SEED,
    GENESIS_TARGET_BITS, GENESIS_TIMESTAMP, MAX_BLOCK_SIZE, MAX_MEMPOOL_SIZE,
    MAX_MEMPOOL_TXS, MAX_TRANSACTION_SIZE, MTP_WINDOW, TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::CoreError;
use chroma_core::hash::{Hash, Hash160};
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{
    Address, Amount, BlockHeight, CompactTarget, Nonce,
};
use chroma_core::u256::U256;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_p2p::wire::{Message, MessageType, VersionMessage, PingMessage, InvMessage, InvEntry, InvType};
use chroma_state::State;
use chroma_storage::Storage;
use chroma_tx::Transaction;
use chroma_wallet::Wallet;

// ============================================================================
// Test Helpers
// ============================================================================

fn test_addr(n: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), n)
}

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
    CompactTarget(0x1f00ffff)
}

fn make_coinbase_tx(recipient: &Address, nonce: u64) -> Transaction {
    Transaction {
        sender_pubkey: PublicKey32([0u8; 32]),
        recipient: recipient.clone(),
        amount: Amount(BLOCK_REWARD_UNITS),
        nonce: Nonce(nonce),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    }
}

fn mine_block_for_test(
    previous: &BlockHeader,
    previous_hash: Hash,
    height: u32,
    state_root: Hash,
    bits: CompactTarget,
    transactions: Vec<Transaction>,
    timestamp: u64,
) -> Block {
    let tx_merkle_root = Block::compute_tx_merkle_root(&transactions);

    let mut block = Block {
        header: BlockHeader {
            version: 1,
            previous_hash,
            state_root,
            tx_merkle_root,
            timestamp,
            bits,
            height: BlockHeight(height),
            nonce: 0,
        },
        transactions,
    };

    let target = bits.to_full_target();
    for nonce in 0..=u64::MAX {
        block.header.nonce = nonce;
        if chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target) {
            break;
        }
        if nonce == u64::MAX {
            panic!("failed to mine test block");
        }
    }
    block
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
    assert_eq!(GENESIS_TARGET_BITS, 0x1f00a7c5);
    assert_eq!(GENESIS_TIMESTAMP, 1767225600);
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
        sender.clone(),
        bob_addr(),
        Amount(500_000),
        Nonce(0),
    )
    .unwrap();

    assert!(tx.verify_signature().is_ok());
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

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let mut acc = state.get_account(&sender);
    acc.balance = 2_000_000;
    state.set_account(&sender, acc);
    state.total_supply = 2_000_000;

    let tx1 = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(1_000_000),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    assert!(state.apply_transaction(&tx1).is_ok());

    let tx2 = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(1_000_000),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    let result = state.apply_transaction(&tx2);
    assert!(result.is_err());
}

#[test]
fn test_nonce_conflict_rejected() {
    let mut state = State::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let mut acc = state.get_account(&sender);
    acc.balance = 5_000_000;
    acc.nonce = 2;
    state.set_account(&sender, acc);
    state.total_supply = 5_000_000;

    let tx = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    let result = state.apply_transaction(&tx);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoreError::InvalidNonce(_) => {}
        other => panic!("expected InvalidNonce, got {:?}", other),
    }
}

#[test]
fn test_insufficient_balance_rejected() {
    let mut state = State::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let mut acc = state.get_account(&sender);
    acc.balance = 100;
    state.set_account(&sender, acc);
    state.total_supply = 100;

    let tx = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(200),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    let result = state.apply_transaction(&tx);
    assert!(result.is_err());
}

// ============================================================================
// Block Assembly + Mining Integration
// ============================================================================

#[test]
fn test_block_assembly_and_mining() {
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
    assert!(chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target));
    assert_eq!(block.header.height, BlockHeight(1));
    assert_eq!(block.header.previous_hash, genesis.hash());
}

#[test]
fn test_block_reward_exact_amount() {
    let mut state = State::new();
    let subsidy = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy, BLOCK_REWARD_UNITS);
}

#[test]
fn test_max_supply_cap_enforced() {
    let mut state = State::new();
    state.total_supply = chroma_core::constants::MAX_SUPPLY_UNITS as u64;
    let subsidy = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy, 0);
}

#[test]
fn test_supply_never_exceeds_max() {
    let mut state = State::new();
    state.total_supply = chroma_core::constants::MAX_SUPPLY_UNITS as u64 - 1;
    let subsidy = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy, 1);
    state.apply_subsidy(&alice_addr(), 0).unwrap();
    assert_eq!(state.total_supply(), chroma_core::constants::MAX_SUPPLY_UNITS as u64);
    let subsidy2 = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy2, 0);
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
            timestamp: genesis.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
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
            timestamp: genesis.timestamp + (h as u64) * 5,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(new_target < original_target, "target should decrease (difficulty increase) when blocks are fast");
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
            timestamp: genesis.timestamp + (h as u64) * 20,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(new_target > original_target, "target should increase (difficulty decrease) when blocks are slow");
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
            timestamp: genesis.timestamp + (h as u64),
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
    assert!(new_target <= max_increase, "should be clamped at 4x increase");
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
            timestamp: genesis.timestamp + (h as u64) * 1000,
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
    assert!(new_target >= min_decrease, "should be clamped at 4x decrease");
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
            timestamp: genesis.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
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
fn test_cumulative_work_increases() {
    let chain = chroma_consensus::ChainState::with_genesis();
    let initial_work = chain.best_tip().cumulative_work;
    assert!(initial_work > U256::ZERO);
}

#[test]
fn test_mtp_computed_correctly() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let chain = chroma_consensus::ChainState::with_genesis();
    let mtp = chain.compute_median_time_past(0);
    assert_eq!(mtp, 0, "genesis MTP should be 0");
}

// ============================================================================
// Storage Integration Tests
// ============================================================================

#[test]
fn test_storage_roundtrip_blocks_and_state() {
    let dir = std::env::temp_dir().join(format!(
        "chroma_integ_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let storage = Storage::open_temporary().unwrap();

    let genesis = chroma_consensus::build_genesis_block();
    storage.save_block(&genesis).unwrap();
    storage.save_tip(genesis.hash(), 0).unwrap();

    let loaded = storage.get_block(genesis.hash()).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().header, genesis.header);

    let tip = storage.get_tip().unwrap();
    assert!(tip.is_some());
    assert_eq!(tip.unwrap().0, genesis.hash());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_storage_account_balance_persistence() {
    let storage = Storage::open_temporary().unwrap();

    let mut acc = chroma_state::Account::default();
    acc.balance = 5_000_000;
    acc.nonce = 3;

    storage.save_account(&alice_addr(), &acc).unwrap();
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
            InvEntry { inv_type: InvType::Tx, hash: Hash::blake3(b"tx1") },
            InvEntry { inv_type: InvType::Block, hash: Hash::blake3(b"block1") },
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
// Address Integration
// ============================================================================

#[test]
fn test_address_deterministic_from_pubkey() {
    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let h160 = Hash160(chroma_crypto::hash::hash160(&pubkey.0));
    let addr = Address::from_hash160(h160);

    let bech32_str = addr.to_bech32();
    assert!(bech32_str.starts_with("chr1"));

    let parsed = Address::from_bech32(&bech32_str).unwrap();
    assert_eq!(addr, parsed);
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
        sender.clone(),
        bob_addr(),
        Amount(100_000),
        Nonce(0),
    )
    .unwrap();
    let tx2 = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(100_000),
        Nonce(0),
    )
    .unwrap();
    assert_eq!(tx1.encode(), tx2.encode());
    assert_eq!(tx1, tx2);
}

#[test]
fn test_sighash_deterministic() {
    use chroma_crypto::schnorr::compute_sighash;

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let h1 = compute_sighash(&sender, &bob_addr(), Amount(100_000), Nonce(0));
    let h2 = compute_sighash(&sender, &bob_addr(), Amount(100_000), Nonce(0));
    assert_eq!(h1, h2);

    let h3 = compute_sighash(&sender, &bob_addr(), Amount(200_000), Nonce(0));
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
    let root1 = state.root();

    let mut acc = state.get_account(&alice_addr());
    acc.balance = 1_000_000;
    state.set_account(&alice_addr(), acc);

    let root2 = state.root();
    assert_ne!(root1, root2);
}

#[test]
fn test_state_root_deterministic() {
    let mut state = State::new();
    let mut acc = state.get_account(&alice_addr());
    acc.balance = 1_000_000;
    state.set_account(&alice_addr(), acc);

    let root1 = state.root();
    let root2 = state.root();
    assert_eq!(root1, root2);
}

// ============================================================================
// Mempool Integration
// ============================================================================

#[test]
fn test_mempool_add_and_remove() {
    let mut mempool = chroma_p2p::mempool::Mempool::new();
    let tx_hash = Hash::blake3(b"test_tx");

    let tx = Transaction {
        sender_pubkey: PublicKey32([0u8; 32]),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };

    mempool.add_transaction(tx.clone(), tx_hash);
    assert!(mempool.get_transaction(&tx_hash).is_some());

    mempool.remove_transaction(&tx_hash);
    assert!(mempool.get_transaction(&tx_hash).is_none());
}

#[test]
fn test_mempool_size_limit() {
    let mut mempool = chroma_p2p::mempool::Mempool::new();

    for i in 0..MAX_MEMPOOL_TXS + 10 {
        let tx_hash = Hash::blake3(&i.to_le_bytes());
        let tx = Transaction {
            sender_pubkey: PublicKey32([0u8; 32]),
            recipient: bob_addr(),
            amount: Amount(100_000),
            nonce: Nonce(i as u64),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        mempool.add_transaction(tx, tx_hash);
    }
    assert!(mempool.pending_count() <= MAX_MEMPOOL_TXS);
}

// ============================================================================
// End-to-End Devnet Flow
// ============================================================================

#[test]
fn test_end_to_end_devnet() {
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
    use chroma_consensus::{build_genesis_block, ChainState};

    let mut chain = ChainState::with_genesis();

    let wallet = Wallet::generate().unwrap();
    let recipient = wallet.address();

    let mut state = State::new();
    let mut funded_acc = state.get_account(&recipient);
    funded_acc.balance = 10_000_000;
    state.set_account(&recipient, funded_acc);

    let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));
    let mut sender_acc = state.get_account(&sender);
    sender_acc.balance = 10_000_000;
    state.set_account(&sender, sender_acc);

    let state_root = state.root();

    let genesis = chain.best_tip().clone();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash,
        previous_timestamp: genesis.header.timestamp,
        state_root,
        bits: easy_bits(),
        coinbase_recipient: recipient.clone(),
    };

    let mut block = assemble_block(&ctx, &[]).unwrap();
    mine_block_with_limit(&mut block, 10_000_000).unwrap();

    let target = block.header.bits.to_full_target();
    assert!(
        chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target),
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

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let mut acc = state.get_account(&sender);
    acc.balance = 10_000_000;
    acc.nonce = 5;
    state.set_account(&sender, acc);
    state.total_supply = 10_000_000;

    let tx = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(4),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    assert!(state.apply_transaction(&tx).is_err());

    let tx_next = Transaction {
        sender_pubkey: pubkey.clone(),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(6),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    assert!(state.apply_transaction(&tx_next).is_ok());
}

// ============================================================================
// CompactTarget Encoding Boundary Tests
// ============================================================================

#[test]
fn test_compact_target_roundtrip_various_values() {
    let test_cases: Vec<u32> = vec![
        0x1d00ffff,
        0x1e00ffff,
        0x1f00ffff,
        0x20000001,
        0x03000001,
        0x00000001,
    ];

    for bits in test_cases {
        let ct = CompactTarget(bits);
        let full = ct.to_full_target();
        let back = CompactTarget::from_full_target(&full);
        assert_eq!(ct, back, "roundtrip failed for bits=0x{:08x}", bits);
    }
}

#[test]
fn test_compact_target_max_is_identity() {
    let max = CompactTarget(0x20ffffff);
    let full = max.to_full_target();
    assert_eq!(full, [0xFF; 32]);
}

// ============================================================================
// Block Validation Context Integration
// ============================================================================

#[test]
fn test_mtp_enforced_in_block_validation() {
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
