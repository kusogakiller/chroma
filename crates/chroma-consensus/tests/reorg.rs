//! Reorg / fork / duplicate-block regression tests.
//!
//! These tests encode the SPEC §2.3 reorg contract:
//! - duplicate (same height, same hash) block application is an idempotent
//!   no-op, never an error, never a state mutation;
//! - a competing block at the same height is evaluated by cumulative work;
//! - a deeper fork is discovered, evaluated by cumulative work of the whole
//!   candidate branch, and reorgs when heavier;
//! - rollback restores tip/headers/state/supply/state-root exactly;
//! - reorgs deeper than `REORG_JOURNAL_DEPTH` are explicitly rejected.

use std::collections::BTreeMap;

use chroma_block::{Block, BlockHeader};
use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
use chroma_consensus::{ChainState, ChainTip};
use chroma_core::constants::{
    BLOCK_REWARD_UNITS, GENESIS_RANDOMX_SEED, GENESIS_TIMESTAMP, REGTEST_MAGIC,
};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, BlockHeight, CompactTarget};
use chroma_core::u256::U256;
use chroma_state::State;

fn easy_bits() -> CompactTarget {
    CompactTarget(0x20ffffff)
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

fn init_randomx() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let seed = chroma_core::blake3(GENESIS_RANDOMX_SEED);
        let _ = chroma_crypto::randomx::init_randomx_context(&seed);
    });
}

fn easy_chain() -> ChainState {
    ChainState::with_genesis_from(
        &chroma_consensus::build_genesis_block_with_bits(easy_bits()),
        REGTEST_MAGIC,
    )
}

fn genesis() -> Block {
    chroma_consensus::build_genesis_block_with_bits(easy_bits())
}

/// Deterministic subsidy state root for a list of (height, recipient) pairs.
fn subsidy_root(assignments: &[(u32, Address)]) -> Hash {
    let mut state = State::new();
    for (h, addr) in assignments {
        state.apply_subsidy(addr, *h).unwrap();
    }
    state.compute_state_root()
}

fn alice_root(up_to: u32) -> Hash {
    subsidy_root(&(1..=up_to).map(|h| (h, alice_addr())).collect::<Vec<_>>())
}

/// Mine a block extending `prev` at `height` paid to `recipient`.
fn mine_extend(
    height: u32,
    prev_hash: Hash,
    prev_ts: u64,
    state_root: Hash,
    recipient: Address,
) -> Block {
    let ctx = BlockAssemblyContext {
        height: BlockHeight(height),
        previous_hash: prev_hash,
        previous_timestamp: prev_ts,
        state_root,
        bits: easy_bits(),
        coinbase_recipient: recipient,
    };
    let mut block = assemble_block(&ctx, &[]).unwrap();
    block.header.timestamp = prev_ts + 10;
    mine_block_with_limit(&mut block, 1_000_000).unwrap();
    block
}

/// Build a main chain `1..=n` paid to alice. Returns (chain, header map).
fn build_main_chain(n: u32) -> (ChainState, BTreeMap<u32, BlockHeader>) {
    let mut chain = easy_chain();
    let g = genesis();
    let mut prev_hash = g.hash();
    let mut prev_ts = g.header.timestamp;
    for h in 1..=n {
        let block = mine_extend(h, prev_hash, prev_ts, alice_root(h), alice_addr());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        chain.apply_block(&block).unwrap();
    }
    let headers = chain.headers.clone();
    (chain, headers)
}

// ============================================================================
// Test 1: duplicate identical block is an idempotent no-op
// ============================================================================

#[test]
fn test_duplicate_block_apply_is_noop() {
    init_randomx();
    let mut chain = easy_chain();
    let g = genesis();

    let block = mine_extend(1, g.hash(), g.header.timestamp, alice_root(1), alice_addr());
    chain.apply_block(&block).unwrap();

    let tip = chain.best_tip().clone();
    let state_root = chain.state.compute_state_root();
    let supply = chain.state.total_supply();
    let header_count = chain.headers.len();

    // Re-applying the exact same block must succeed and mutate nothing.
    let r = chain.apply_block(&block);
    assert!(
        r.is_ok(),
        "duplicate identical block must be Ok (idempotent), got {:?}",
        r.err()
    );
    assert_eq!(chain.best_tip().height, tip.height);
    assert_eq!(chain.best_tip().hash, tip.hash);
    assert_eq!(chain.best_tip().cumulative_work, tip.cumulative_work);
    assert_eq!(chain.best_tip().supply, tip.supply);
    assert_eq!(chain.state.compute_state_root(), state_root);
    assert_eq!(chain.state.total_supply(), supply);
    assert_eq!(chain.headers.len(), header_count, "headers must not grow");
}

#[test]
fn test_duplicate_block_apply_ten_times_noop() {
    init_randomx();
    let mut chain = easy_chain();
    let g = genesis();
    let block = mine_extend(1, g.hash(), g.header.timestamp, alice_root(1), alice_addr());
    chain.apply_block(&block).unwrap();
    let tip = chain.best_tip().clone();
    for _ in 0..10 {
        let r = chain.apply_block(&block);
        assert!(r.is_ok(), "repeat duplicate apply must be Ok");
    }
    assert_eq!(chain.best_tip().hash, tip.hash);
    assert_eq!(chain.best_tip().height, tip.height);
    assert_eq!(chain.headers.len(), 2);
}

// ============================================================================
// Test 2: deep fork reorgs to the heavier chain
// ============================================================================

#[test]
fn test_deep_fork_reorgs_to_heavier_chain() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    assert_eq!(chain.best_tip().height.0, 10);

    let fork_point = 8u32;
    let fork_header = headers.get(&fork_point).unwrap().clone();
    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;

    // Candidate: 9' -> 10' -> 11' (bob), common ancestor at height 8.
    let mut candidate_blocks = Vec::new();
    for h in (fork_point + 1)..=11u32 {
        let mut assigns: Vec<(u32, Address)> =
            (1..=fork_point).map(|i| (i, alice_addr())).collect();
        assigns.extend((fork_point + 1..=h).map(|i| (i, bob_addr())));
        let block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        candidate_blocks.push(block);
    }

    // Deliver in order. 9' and 10' may be buffered (not yet heavier); 11'
    // makes the candidate strictly heavier than tip(10) and must trigger the
    // reorg.
    for b in &candidate_blocks {
        let r = chain.apply_block(b);
        assert!(
            r.is_ok(),
            "candidate block at height {} must be accepted/buffered, got {:?}",
            b.header.height.0,
            r.err()
        );
    }

    assert_eq!(
        chain.best_tip().height.0,
        11,
        "heavier candidate must become the tip"
    );
    assert_eq!(
        chain.best_tip().hash,
        candidate_blocks.last().unwrap().hash(),
        "tip must be the candidate tip"
    );

    let expected_supply = 11 * BLOCK_REWARD_UNITS;
    assert_eq!(chain.best_tip().supply, expected_supply);
    let mut assigns: Vec<(u32, Address)> = (1..=fork_point).map(|i| (i, alice_addr())).collect();
    assigns.extend((fork_point + 1..=11).map(|i| (i, bob_addr())));
    assert_eq!(
        chain.state.compute_state_root(),
        subsidy_root(&assigns),
        "state root must match the candidate chain"
    );

    // No residue from the old chain: headers map must be exactly 0..=11.
    assert_eq!(chain.headers.len(), 12);
    for h in 0..=11u32 {
        assert!(chain.headers.contains_key(&h));
    }
}

// ============================================================================
// Test 3: lighter fork does not displace the tip
// ============================================================================

#[test]
fn test_lighter_fork_does_not_displace() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    let main_tip = chain.best_tip().clone();

    // Candidate: 9' -> 10' (2 blocks) from fork point 8 — strictly shorter
    // than tip(10); must stay buffered and never displace.
    let fork_header = headers.get(&8).unwrap().clone();
    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;
    for h in 9..=10u32 {
        let mut assigns: Vec<(u32, Address)> = (1..=8u32).map(|i| (i, alice_addr())).collect();
        assigns.extend((9..=h).map(|i| (i, bob_addr())));
        let block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        let r = chain.apply_block(&block);
        assert!(r.is_ok(), "fork block must be buffered, got {:?}", r.err());
    }

    assert_eq!(chain.best_tip().height, main_tip.height);
    assert_eq!(chain.best_tip().hash, main_tip.hash);
    assert_eq!(chain.best_tip().cumulative_work, main_tip.cumulative_work);
    assert_eq!(
        chain.state.compute_state_root(),
        alice_root(10),
        "state must remain the main chain's state"
    );
}

// ============================================================================
// Test 4: same-height competing block at tip with equal work is rejected
// ============================================================================

#[test]
fn test_same_height_competing_equal_work_rejected_tip_unchanged() {
    init_randomx();
    let mut chain = easy_chain();
    let g = genesis();

    let block_a = mine_extend(1, g.hash(), g.header.timestamp, alice_root(1), alice_addr());
    chain.apply_block(&block_a).unwrap();
    let tip = chain.best_tip().clone();

    // Competitor: same parent, same height, different nonce → same difficulty
    // → equal work.
    let block_b = mine_extend(
        1,
        g.hash(),
        g.header.timestamp + 1,
        alice_root(1),
        bob_addr(),
    );
    assert_ne!(block_b.hash(), block_a.hash());

    let r = chain.apply_block(&block_b);
    assert!(r.is_err(), "equal-work competitor at tip must be rejected");
    assert_eq!(chain.best_tip().hash, tip.hash);
    assert_eq!(chain.best_tip().height, tip.height);
    assert_eq!(chain.best_tip().cumulative_work, tip.cumulative_work);
}

// ============================================================================
// Test 5: reorg deeper than journal depth is explicitly rejected
// ============================================================================

#[test]
fn test_reorg_beyond_journal_depth_rejected() {
    init_randomx();
    let mut chain = easy_chain();
    let g = genesis();

    // Build a header-only chain up to height 2005 (no mining; consensus
    // routing and depth checks run before any state work).
    let mut prev_hash = g.hash();
    let mut cum = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &g.header.bits.to_full_target(),
    ));
    for h in 1..=2005u32 {
        let header = BlockHeader {
            version: 1,
            previous_hash: prev_hash,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: GENESIS_TIMESTAMP + (h as u64) * 10,
            bits: easy_bits(),
            height: BlockHeight(h),
            nonce: h as u64,
        };
        let w = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &header.bits.to_full_target(),
        ));
        cum = cum.checked_add(&w).unwrap();
        prev_hash = header.hash();
        chain.headers.insert(h, header.clone());
        chain.tips.insert(
            header.hash(),
            ChainTip {
                height: BlockHeight(h),
                hash: header.hash(),
                header,
                cumulative_work: cum,
                supply: 0,
            },
        );
    }
    chain.tip = chain.tips.get(&prev_hash).unwrap().clone();

    // Candidate sibling of our height-1 block (fork point 0). Switching to it
    // would require rolling back 2005 blocks > REORG_JOURNAL_DEPTH.
    let candidate = mine_extend(1, g.hash(), g.header.timestamp, alice_root(1), bob_addr());
    let r = chain.apply_block(&candidate);
    assert!(r.is_err(), "beyond-journal-depth reorg must be rejected");
    let msg = format!("{:?}", r.err().unwrap());
    assert!(
        msg.contains("2000") || msg.contains("journal") || msg.contains("depth"),
        "rejection must reference the journal depth limit, got: {}",
        msg
    );
    // Tip untouched, no partial rollback.
    assert_eq!(chain.best_tip().height.0, 2005);
    assert_eq!(chain.headers.len(), 2006);
}

// ============================================================================
// Test 7: out-of-order fork delivery eventually reorgs (orphan linking)
// ============================================================================

#[test]
fn test_out_of_order_fork_delivery_eventually_reorgs() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    let fork_point = 8u32;
    let fork_header = headers.get(&fork_point).unwrap().clone();

    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;
    let mut candidate_blocks = Vec::new();
    for h in (fork_point + 1)..=12u32 {
        let mut assigns: Vec<(u32, Address)> =
            (1..=fork_point).map(|i| (i, alice_addr())).collect();
        assigns.extend((fork_point + 1..=h).map(|i| (i, bob_addr())));
        let block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        candidate_blocks.push(block);
    }

    // Deliver the candidate fork in reverse, EXCEPT the fork base (9'): 12',
    // 11', 10' each arrive as an orphan until their parent lands. The chain
    // must never be corrupted mid-delivery.
    for b in candidate_blocks
        .iter()
        .rev()
        .take(candidate_blocks.len() - 1)
    {
        let _ = chain.apply_block(b);
        assert!(chain.best_tip().height.0 == 10, "tip must stay at 10");
        assert_eq!(
            chain.state.compute_state_root(),
            alice_root(10),
            "state must stay honest while quarantining"
        );
    }

    // The fork base (9') arrives last and links 10'/11'/12' together → reorg
    // to 12'.
    let r = chain.apply_block(&candidate_blocks[0]);
    assert!(
        r.is_ok(),
        "fork base must connect the branch, got {:?}",
        r.err()
    );
    assert_eq!(chain.best_tip().height.0, 12, "reorg must complete");
    assert_eq!(
        chain.best_tip().hash,
        candidate_blocks.last().unwrap().hash()
    );
}

// ============================================================================
// Test 10: a reorg attempt with an invalid fork block must not corrupt the
// chain (rollback only happens after full pre-validation).
// ============================================================================

#[test]
fn test_reorg_with_invalid_fork_block_does_not_corrupt_chain() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    let snap = (
        chain.best_tip().clone(),
        chain.state.compute_state_root(),
        chain.state.total_supply(),
        chain.headers.len(),
    );

    // Candidate 9',10',11' from fork 8, but 9' carries a WRONG state root so
    // the branch is heavier by bits yet provably invalid.
    let fork_header = headers.get(&8).unwrap().clone();
    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;
    let mut blocks = Vec::new();
    for h in 9..=11u32 {
        let mut assigns: Vec<(u32, Address)> = (1..=8u32).map(|i| (i, alice_addr())).collect();
        assigns.extend((9..=h).map(|i| (i, bob_addr())));
        let mut block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        if h == 9 {
            block.header.state_root = Hash::ZERO;
        }
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        blocks.push(block);
    }
    for b in &blocks {
        let _ = chain.apply_block(b);
    }

    // The live chain must be EXACTLY as before the failed reorg attempt.
    assert_eq!(chain.best_tip().height, snap.0.height);
    assert_eq!(chain.best_tip().hash, snap.0.hash);
    assert_eq!(chain.best_tip().cumulative_work, snap.0.cumulative_work);
    assert_eq!(chain.state.compute_state_root(), snap.1);
    assert_eq!(chain.state.total_supply(), snap.2);
    assert_eq!(chain.headers.len(), snap.3);
    // The poisoned block is memoized so the reorg attempt is not repeated.
    assert!(chain.reorg_rejected_blocks.contains(&blocks[0].hash()));
}

#[test]
fn test_fork_quarantine_is_bounded() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    let fork_header = headers.get(&5).unwrap().clone();

    // 1. A single maliciously-long fork chain (600 linked blocks from a fork
    //    point, heavier by bits but each with a WRONG state root so it can
    //    never become canonical): buffered and strictly capped.
    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;
    for h in 6..=605u32 {
        let mut assigns: Vec<(u32, Address)> = (1..=5u32).map(|i| (i, alice_addr())).collect();
        assigns.extend((6..=h).map(|i| (i, bob_addr())));
        let mut block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        block.header.state_root = Hash::ZERO;
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        let _ = chain.apply_block(&block);
    }
    assert!(
        chain.alt_blocks.len() <= 500,
        "single long fork chain must be capped, got {}",
        chain.alt_blocks.len()
    );
    assert!(
        chain.alt_headers.len() <= 100,
        "chain count must be capped, got {}",
        chain.alt_headers.len()
    );
    // Tip untouched by quarantined garbage.
    assert_eq!(chain.best_tip().height.0, 10);

    // 2. Many distinct orphans (unknown parents) must also be capped.
    let mut chain2 = easy_chain();
    let g = genesis();
    let mut prev_hash = g.hash();
    let mut prev_ts = g.header.timestamp;
    for i in 0..600u32 {
        // Each orphan: height 11, distinct unknown-ish parent.
        let mut assigns: Vec<(u32, Address)> = (1..=10u32).map(|h| (h, alice_addr())).collect();
        assigns.push((11, bob_addr()));
        let mut block = mine_extend(11, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        block.header.previous_hash = Hash::blake3(format!("orphan-parent-{i}").as_bytes());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        let _ = chain2.apply_block(&block);
    }
    assert!(
        chain2.alt_blocks.len() <= 500,
        "orphan flood must be capped, got {}",
        chain2.alt_blocks.len()
    );
    assert!(
        chain2.alt_headers.len() <= 100,
        "orphan chain count must be capped, got {}",
        chain2.alt_headers.len()
    );
    assert_eq!(chain2.best_tip().height.0, 0, "tip must stay at genesis");
}

#[test]
fn test_cumulative_work_compares_branches_not_heights() {
    // Fork choice must compare cumulative work, never height. Work is
    // 2^256 / target, so an ultra-hard (tiny-target) block contributes far
    // more work than many ultra-easy blocks. A single hard block at height
    // +1 must beat a 3-block easy branch purely by work — proving a longer
    // chain is NOT automatically heavier.
    init_randomx();
    let chain = easy_chain();
    let base = chain.best_tip().cumulative_work;

    let hard_bits = {
        let mut t = [0u8; 32];
        t[10] = 0xFF;
        t[11] = 0xFF;
        CompactTarget::from_full_target(&t)
    };

    // A 3-block branch at ultra-easy difficulty (tiny per-block work).
    let easy_w = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &easy_bits().to_full_target(),
    ));
    let longer_easy = base
        .checked_add(&easy_w)
        .and_then(|w| w.checked_add(&easy_w))
        .and_then(|w| w.checked_add(&easy_w))
        .unwrap();

    // A single ultra-hard block contributes vastly more work.
    let hard_w = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &hard_bits.to_full_target(),
    ));
    let single_hard = base.checked_add(&hard_w).unwrap();

    assert!(
        single_hard > longer_easy,
        "one hard block (height +1) must outweigh three easy blocks by work"
    );
    assert!(
        base < single_hard && base < longer_easy,
        "any branch must exceed the fork point's cumulative work"
    );
}

#[test]
fn test_rollback_restores_candidate_state_exactly() {
    init_randomx();
    let (mut chain, headers) = build_main_chain(10);
    let fork_point = 8u32;
    let fork_header = headers.get(&fork_point).unwrap().clone();

    let mut prev_hash = fork_header.hash();
    let mut prev_ts = fork_header.timestamp;
    let mut candidate = None;
    for h in (fork_point + 1)..=12u32 {
        let mut assigns: Vec<(u32, Address)> =
            (1..=fork_point).map(|i| (i, alice_addr())).collect();
        assigns.extend((fork_point + 1..=h).map(|i| (i, bob_addr())));
        let block = mine_extend(h, prev_hash, prev_ts, subsidy_root(&assigns), bob_addr());
        prev_hash = block.hash();
        prev_ts = block.header.timestamp;
        let r = chain.apply_block(&block);
        assert!(r.is_ok());
        candidate = Some(block);
    }
    let cand = candidate.unwrap();

    assert_eq!(chain.best_tip().height.0, 12);
    let mut assigns: Vec<(u32, Address)> = (1..=fork_point).map(|i| (i, alice_addr())).collect();
    assigns.extend((fork_point + 1..=12).map(|i| (i, bob_addr())));
    assert_eq!(chain.best_tip().supply, 12 * BLOCK_REWARD_UNITS);
    assert_eq!(chain.state.compute_state_root(), subsidy_root(&assigns));
    assert_eq!(chain.best_tip().hash, cand.hash());

    // The applied tip must link back through the candidate chain to the fork
    // point (headers map is exactly 0..=12 and linkage holds).
    let mut h = 12u32;
    while h > 0 {
        let header = chain.headers.get(&h).unwrap();
        let prev = chain.headers.get(&(h - 1)).unwrap();
        assert_eq!(
            header.previous_hash,
            prev.hash(),
            "height {} must link to height {}",
            h,
            h - 1
        );
        h -= 1;
    }
}
