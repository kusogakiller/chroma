//! Chroma Consensus
//!
//! Deterministic consensus rules: difficulty retarget, chain selection,
//! cumulative work tracking, genesis block.
//!
//! ## Difficulty Retarget Algorithm
//!
//! Retarget every `DIFFICULTY_ADJUSTMENT_WINDOW` (10) blocks.
//!
//! Formula:
//! ```text
//! actual_time = timestamp[height] - timestamp[height - window]
//! target_time = (window - 1) × TARGET_BLOCK_TIME_SECS  (= 90 seconds)
//!
//! new_target = old_target × actual_time / target_time
//!
//! Clamped to: old_target / 4 .. old_target × 4
//! ```
//!
//! Bounds: targets derived from in-bounds currents stay within
//! [MINIMUM_TARGET, MAXIMUM_TARGET]. A current easier than MAXIMUM_TARGET
//! (only possible from an easy-bits genesis: regtest / testnet) is held
//! steady instead of clamped — see `calculate_target_for_height`.
//! At non-retarget heights, the target carries forward unchanged.

pub mod miner;

use std::collections::{BTreeMap, HashMap};

use chroma_block::{Block, BlockHeader, BlockValidationContext};
use chroma_core::constants::{
    DIFFICULTY_ADJUSTMENT_WINDOW, GENESIS_RANDOMX_SEED, GENESIS_TARGET_BITS, GENESIS_TIMESTAMP,
    MAINNET_MAGIC, MAX_DIFFICULTY_DECREASE_FACTOR, MAX_DIFFICULTY_INCREASE_FACTOR, MTP_WINDOW,
    REORG_JOURNAL_DEPTH, TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::{BlockHeight, CompactTarget};
use chroma_core::u256::U256;
use chroma_state::State;

// ============================================================================
// Genesis Block
// ============================================================================

/// Build the deterministic genesis block.
///
/// Genesis is fully determined by protocol constants:
/// - height = 0
/// - previous_hash = Hash::ZERO
/// - timestamp = GENESIS_TIMESTAMP
/// - bits = GENESIS_TARGET_BITS
/// - nonce = 0
/// - state_root = Hash::ZERO (empty state)
/// - tx_merkle_root = Hash::ZERO (no transactions)
pub fn build_genesis_block() -> Block {
    build_genesis_block_with_bits(CompactTarget(GENESIS_TARGET_BITS))
}

pub fn build_genesis_block_with_bits(bits: CompactTarget) -> Block {
    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::ZERO,
        state_root: Hash::ZERO,
        tx_merkle_root: Hash::ZERO,
        timestamp: GENESIS_TIMESTAMP,
        bits,
        height: BlockHeight::GENESIS,
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![],
    }
}

/// Network selector for genesis building.
/// Avoids depending on chroma-p2p just for this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    Mainnet,
    Testnet,
    Regtest,
}

/// Build the genesis block for a given network.
pub fn build_genesis_for_network(network: &NetworkKind) -> Block {
    match network {
        NetworkKind::Mainnet => build_genesis_block(),
        NetworkKind::Testnet => build_testnet_genesis_block(),
        NetworkKind::Regtest => build_genesis_block_with_bits(CompactTarget(0x20ffffff)),
    }
}

/// Build the testnet genesis block with testnet-specific timestamp and RandomX seed.
pub fn build_testnet_genesis_block() -> Block {
    use chroma_core::constants::TESTNET_GENESIS_TIMESTAMP;
    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::ZERO,
        state_root: Hash::ZERO,
        tx_merkle_root: Hash::ZERO,
        timestamp: TESTNET_GENESIS_TIMESTAMP,
        bits: CompactTarget(0x20ffffff), // Easy target for RandomX mining
        height: BlockHeight::GENESIS,
        nonce: 0,
    };
    Block {
        header,
        transactions: vec![],
    }
}

/// Get the genesis block hash.
pub fn genesis_hash() -> Hash {
    build_genesis_block().hash()
}

/// Get the genesis RandomX seed.
pub fn genesis_randomx_seed() -> Hash {
    Hash::blake3(GENESIS_RANDOMX_SEED)
}

// ============================================================================
// Difficulty Retarget
// ============================================================================

/// Minimum target (highest difficulty).
/// 0x00000000000000000000FFFF00000000000000000000000000000000000000000
const MINIMUM_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[10] = 0xFF;
    t[11] = 0xFF;
    t
};

/// Maximum target (lowest difficulty).
/// ~4× genesis target to allow one full difficulty decrease adjustment.
/// Genesis target: CompactTarget 0x1f00a7c5
/// MAXIMUM_TARGET = 4 × genesis = 0x1f029f14
const MAXIMUM_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[1] = 0x02;
    t[2] = 0x9f;
    t[3] = 0x14;
    t
};

/// Determine the target bits for a given block height.
pub fn calculate_target_for_height(
    height: u32,
    headers: &BTreeMap<u32, BlockHeader>,
) -> Result<CompactTarget> {
    if height == 0 {
        return Ok(CompactTarget(GENESIS_TARGET_BITS));
    }

    if !height.is_multiple_of(DIFFICULTY_ADJUSTMENT_WINDOW) {
        let prev = headers.get(&(height - 1)).ok_or_else(|| {
            CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1))
        })?;
        return Ok(prev.bits);
    }

    // Window spans heights [height - window, height - 1], which is `window` blocks
    // but only (window - 1) intervals between them.
    let intervals = (DIFFICULTY_ADJUSTMENT_WINDOW - 1) as u64;
    let target_time = TARGET_BLOCK_TIME_SECS * intervals; // 90 seconds

    let current = headers.get(&(height - 1)).ok_or_else(|| {
        CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1))
    })?;

    let window_start = height.saturating_sub(DIFFICULTY_ADJUSTMENT_WINDOW);
    let start = headers.get(&window_start).ok_or_else(|| {
        CoreError::InvalidDifficulty(format!("missing header for height {}", window_start))
    })?;

    let actual_time = current.timestamp.saturating_sub(start.timestamp);
    // Cap actual_time to prevent overflow in mul_div.
    // Max increase per epoch is 4×, so actual_time should not exceed 4× target_time.
    let max_actual_time = target_time * MAX_DIFFICULTY_INCREASE_FACTOR;
    let actual_time = std::cmp::min(std::cmp::max(actual_time, 1), max_actual_time);

    let old_target = U256::from_be_bytes(&current.bits.to_full_target());

    // Easy-target regime: the current target is easier than the absolute
    // easiest mainnet target (MAXIMUM_TARGET). Absolute clamping would
    // catapult difficulty by orders of magnitude here (easy target
    // 0x20ffffff clamps to mainnet-grade 0x1f03ffff, ~16k× harder), so hold
    // steady instead. Comparison is numeric (U256 full targets), never on
    // the compact encoding.
    //
    // Reachability: mainnet can never present such a current. Its genesis
    // (0x1f00a7c5) is within bounds, every validated retarget lands within
    // [MINIMUM_TARGET, MAXIMUM_TARGET] (absolute clamp below), other heights
    // carry forward unchanged, and validation pins header.bits to the
    // computed expectation at every height — so no valid mainnet chain state
    // reaches this branch. Easy-genesis chains (regtest, and testnet as
    // currently parameterized with 0x20ffffff genesis bits) take this branch
    // at every retarget and keep mineable difficulty.
    let max_abs = U256::from_be_bytes(&MAXIMUM_TARGET);
    if old_target > max_abs {
        return Ok(current.bits);
    }

    let new_target = mul_div(&old_target, actual_time, target_time)
        .ok_or_else(|| CoreError::InvalidDifficulty("difficulty calculation overflow".into()))?;

    let (min_target, _) = old_target.div_rem(&U256::from_u64(MAX_DIFFICULTY_DECREASE_FACTOR));
    let max_target = old_target.shl(2);

    let clamped = if new_target < min_target {
        min_target
    } else if new_target > max_target {
        max_target
    } else {
        new_target
    };

    // Enforce absolute bounds (safety net beyond per-epoch clamping)
    // MINIMUM_TARGET = highest difficulty (smallest target)
    // MAXIMUM_TARGET = lowest difficulty (largest target, ~4× genesis)
    let min_abs = U256::from_be_bytes(&MINIMUM_TARGET);
    let final_target = if clamped < min_abs {
        min_abs
    } else if clamped > max_abs {
        max_abs
    } else {
        clamped
    };

    let target_bytes = final_target.to_be_bytes();
    Ok(CompactTarget::from_full_target(&target_bytes))
}

/// Multiply a U256 by a u64 and divide by a u64: (value * num) / den
/// Returns None on overflow to avoid silent wrapping on consensus-critical values.
fn mul_div(value: &U256, num: u64, den: u64) -> Option<U256> {
    if den == 0 {
        return None;
    }
    if num == 0 {
        return Some(U256::ZERO);
    }

    let (q, r) = value.div_rem(&U256::from_u64(den));

    let part1 = {
        let mut result = U256::ZERO;
        let mut addend = q;
        let mut n = num;
        while n > 0 {
            if n & 1 == 1 {
                result = result.checked_add(&addend)?;
            }
            addend = addend.shl(1);
            n >>= 1;
        }
        result
    };

    let part2 = {
        let mut temp = U256::ZERO;
        let mut addend = r;
        let mut n = num;
        while n > 0 {
            if n & 1 == 1 {
                temp = temp.checked_add(&addend)?;
            }
            addend = addend.shl(1);
            n >>= 1;
        }
        let (q2, _) = temp.div_rem(&U256::from_u64(den));
        q2
    };

    part1.checked_add(&part2)
}

/// Compute Median Time Past from the last MTP_WINDOW (7) block timestamps.
/// For height < MTP_WINDOW, uses timestamps from genesis to height-1.
fn compute_median_time_past_from(headers: &BTreeMap<u32, BlockHeader>, height: u32) -> u64 {
    let mut timestamps: Vec<u64> = Vec::new();
    let count = std::cmp::min(height as usize, MTP_WINDOW);
    for i in 0..count {
        let h = height - 1 - i as u32;
        if let Some(header) = headers.get(&h) {
            timestamps.push(header.timestamp);
        }
    }
    if timestamps.is_empty() {
        return 0;
    }
    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

// ============================================================================
// Chain Tip Context
// ============================================================================

/// Summary of a chain tip needed for block validation.
#[derive(Clone, Debug)]
pub struct ChainTip {
    pub height: BlockHeight,
    pub hash: Hash,
    pub header: BlockHeader,
    pub cumulative_work: U256,
    pub supply: u64,
}

impl ChainTip {
    pub fn new(genesis: &Block) -> Self {
        let work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &genesis.header.bits.to_full_target(),
        ));
        ChainTip {
            height: BlockHeight::GENESIS,
            hash: genesis.hash(),
            header: genesis.header.clone(),
            cumulative_work: work,
            supply: 0,
        }
    }
}

// ============================================================================
// Chain State
// ============================================================================

/// Full chain state for consensus validation.
pub struct ChainState {
    /// All block headers indexed by height.
    pub headers: BTreeMap<u32, BlockHeader>,
    /// Best chain tip.
    pub tip: ChainTip,
    /// Account state at the tip.
    pub state: State,
    /// All known chain tips (for fork choice).
    pub tips: BTreeMap<Hash, ChainTip>,
    /// Alternative chain headers for forks not yet fully resolved.
    /// Capped at 100 entries to prevent memory leaks.
    pub alt_headers: HashMap<Hash, Vec<BlockHeader>>,
    /// Full blocks backing `alt_headers`, keyed by block hash, so a winning
    /// fork can be re-applied with its transactions intact.
    pub alt_blocks: HashMap<Hash, Block>,
    /// Fork blocks proven invalid during a reorg dry-run. Any buffered chain
    /// containing one of these can never become canonical, so reorg attempts
    /// for it are skipped — bounds the CPU cost of an attacker repeatedly
    /// presenting a heavy-but-invalid fork.
    pub reorg_rejected_blocks: std::collections::HashSet<Hash>,
    /// Network magic for transaction signature verification (cross-network replay protection)
    pub network_magic: [u8; 4],
    /// Blocks applied by the most recent successful `apply_block` call (a
    /// plain extension, or every branch block re-applied by a reorg). The
    /// storage layer persists these so restart reconstruction is consistent.
    pub last_applied_blocks: Vec<Block>,
}

impl ChainState {
    /// Create chain state with the mainnet genesis block.
    /// Uses MAINNET_MAGIC so mainnet signatures verify; use
    /// `with_genesis_from` with an explicit magic for testnet/regtest.
    pub fn with_genesis() -> Self {
        Self::with_genesis_from(&build_genesis_block(), MAINNET_MAGIC)
    }

    /// Create chain state from a specific genesis block.
    pub fn with_genesis_from(genesis: &Block, network_magic: [u8; 4]) -> Self {
        let genesis_hash = genesis.hash();
        let tip = ChainTip::new(genesis);

        let mut headers = BTreeMap::new();
        headers.insert(0, genesis.header.clone());

        let mut tips = BTreeMap::new();
        tips.insert(genesis_hash, tip.clone());

        ChainState {
            headers,
            tip: tip.clone(),
            state: State::new(),
            tips,
            alt_headers: HashMap::new(),
            alt_blocks: HashMap::new(),
            reorg_rejected_blocks: std::collections::HashSet::new(),
            network_magic,
            last_applied_blocks: Vec::new(),
        }
    }

    /// Validate and apply a new block to the best chain.
    ///
    /// Classification (SPEC §2.3, fork choice by cumulative work):
    /// 1. A block already on the canonical chain (same height, same hash) is
    ///    an idempotent no-op — wire re-delivery is normal and must never be
    ///    an error, a fork, or peer-misbehavior.
    /// 2. A block whose height already holds a different header is a
    ///    competing block, evaluated by the cumulative work of its whole
    ///    branch (possibly a reorg).
    /// 3. Anything else extends the current chain.
    ///
    /// On success, `last_applied_blocks` records exactly the blocks applied
    /// during this call (a plain extension, or a fork branch re-applied by a
    /// reorg), so the storage layer can persist all of them atomically.
    pub fn apply_block(&mut self, block: &Block) -> Result<()> {
        let height = block.header.height.0;

        // Genesis is trust-by-hash and immutable: it is installed at chain
        // construction, never applied, and can never be replaced.
        if height == 0 {
            return Err(CoreError::InvalidBlock(
                "genesis block already exists, cannot replace".to_string(),
            ));
        }

        let mut applied = Vec::new();

        let result = if let Some(existing) = self.headers.get(&height) {
            if existing.hash() == block.hash() {
                return Ok(());
            }
            self.apply_competing_block(block, &mut applied)
        } else if self.alt_blocks.contains_key(&block.header.previous_hash) {
            // Height not on the canonical chain, but its parent is a buffered
            // fork/orphan block — extend that branch, don't force a main-chain
            // extension (which would fail the parent link).
            self.apply_competing_block(block, &mut applied)
        } else {
            // A clean extension of the canonical chain requires the parent to
            // be the canonical header at height-1. Anything else (unknown
            // parent, gap, future orphan) is a fork/orphan and is buffered
            // through the competing path rather than failing outright.
            let extends_canonical = height == 0
                || self
                    .headers
                    .get(&(height - 1))
                    .map(|h| h.hash() == block.header.previous_hash)
                    .unwrap_or(false);
            if extends_canonical {
                self.apply_block_inner(block, &mut applied)
            } else {
                self.apply_competing_block(block, &mut applied)
            }
        };

        if result.is_ok() {
            // An applied block may connect previously-buffered fork branches.
            self.try_resolve_forks(&mut applied)?;
        }

        if result.is_ok() {
            self.last_applied_blocks = applied;
        }
        result
    }

    /// Core block application logic (validation + state update).
    fn apply_block_inner(&mut self, block: &Block, applied: &mut Vec<Block>) -> Result<()> {
        let height = block.header.height.0;

        if height == 0 && self.headers.contains_key(&0) {
            return Err(CoreError::InvalidBlock(
                "genesis block already exists, cannot replace".to_string(),
            ));
        }

        // Ensure RandomX context is initialized for this block's epoch
        let _ = chroma_crypto::randomx::ensure_randomx_for_height(height, |h| {
            self.headers.get(&h).map(|hdr| hdr.hash())
        });

        let ctx = self.build_validation_ctx(&self.headers, &self.tip, height)?;

        chroma_block::validate_block(block, &ctx, &mut self.state)?;

        let new_hash = block.hash();
        let block_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &block.header.bits.to_full_target(),
        ));
        let new_cumulative_work = self
            .tip
            .cumulative_work
            .checked_add(&block_work)
            .ok_or_else(|| CoreError::Overflow("cumulative work overflow".into()))?;

        self.headers.insert(height, block.header.clone());

        let new_tip = ChainTip {
            height: BlockHeight(height),
            hash: new_hash,
            header: block.header.clone(),
            cumulative_work: new_cumulative_work,
            supply: self.state.total_supply(),
        };

        self.tip = new_tip.clone();
        self.tips.insert(new_hash, new_tip);

        applied.push(block.clone());

        Ok(())
    }

    /// Handle a block at a height that already holds a different header, or
    /// that extends a buffered fork branch.
    ///
    /// The block is buffered into the flat fork store and branches are
    /// linked/evaluated. It is adopted only if its whole branch's cumulative
    /// work strictly exceeds the current tip's. Outcome:
    /// - became canonical (reorg) → Ok;
    /// - buffered below the tip (may still grow heavier) → Ok;
    /// - unknown parent (orphan, quarantined) → Err;
    /// - same-height tie/loss at the tip → Err.
    fn apply_competing_block(&mut self, block: &Block, applied: &mut Vec<Block>) -> Result<()> {
        let height = block.header.height.0;

        if height == 0 {
            return Err(CoreError::InvalidBlock(
                "genesis block already exists, cannot replace".to_string(),
            ));
        }

        // Already-buffered fork block re-delivered → idempotent no-op.
        if self.alt_blocks.contains_key(&block.hash()) {
            return Ok(());
        }

        // The parent is either a canonical header (sibling fork), a buffered
        // fork/orphan block (branch extension), or unknown (orphan).
        let parent_on_main = height > 0
            && self
                .headers
                .get(&(height - 1))
                .map(|h| h.hash() == block.header.previous_hash)
                .unwrap_or(false);
        let parent_on_alt = self.alt_blocks.contains_key(&block.header.previous_hash);

        // Depth guard: a fork from a point older than the journal depth can
        // never be adopted — reject explicitly (SPEC §2.3).
        if parent_on_main {
            let fork_height = height - 1;
            let min_rollback = self.tip.height.0.saturating_sub(fork_height);
            if min_rollback > REORG_JOURNAL_DEPTH {
                return Err(CoreError::InvalidBlock(format!(
                    "deep reorg ({} blocks) exceeds maximum supported depth ({})",
                    min_rollback, REORG_JOURNAL_DEPTH
                )));
            }
        }

        self.buffer_block(block.clone());
        self.link_orphans();
        self.try_resolve_forks(applied)?;

        let became_canonical = self
            .headers
            .get(&height)
            .map(|h| h.hash() == block.hash())
            .unwrap_or(false);
        if became_canonical {
            return Ok(());
        }
        if !parent_on_main && !parent_on_alt {
            return Err(CoreError::InvalidBlock(format!(
                "competing block at height {} with unknown fork point, rejecting",
                height
            )));
        }
        // A same-parent sibling of the tip that is not heavier is a first-seen
        // tie/loss → rejected (pinned behavior). Descendants of a deeper fork
        // at the same height as the tip (parent_on_alt) are simply buffered:
        // their branch may still grow heavier.
        if parent_on_main && height == self.tip.height.0 {
            return Err(CoreError::InvalidBlock(format!(
                "competing block at height {} has less or equal cumulative work, rejecting",
                height
            )));
        }
        Ok(())
    }

    /// Buffer a fork/orphan block into the flat store and start a one-header
    /// branch for it. Branch assembly (linking) happens separately.
    fn buffer_block(&mut self, block: Block) {
        self.alt_headers
            .insert(block.hash(), vec![block.header.clone()]);
        self.alt_blocks.insert(block.hash(), block);
        self.trim_alt_quarantine();
    }

    /// Merge buffered branches whose parent has since been buffered. A child
    /// chain whose first header's `previous_hash` is ANY header of another
    /// buffered chain is spliced onto it at that position — handling chained
    /// orphans where the parent is an interior block, not necessarily a tip.
    fn link_orphans(&mut self) {
        loop {
            let mut merge: Option<(Hash, Hash)> = None; // (parent_chain_tip, child_chain_tip)
            let keys: Vec<Hash> = self.alt_headers.keys().copied().collect();
            'outer: for child_tip in &keys {
                let first_prev = match self.alt_headers.get(child_tip).and_then(|c| c.first()) {
                    Some(h) => h.previous_hash,
                    None => continue,
                };
                for parent_tip in &keys {
                    if parent_tip == child_tip {
                        continue;
                    }
                    let parent_has = self
                        .alt_headers
                        .get(parent_tip)
                        .map(|c| c.iter().any(|h| h.hash() == first_prev))
                        .unwrap_or(false);
                    if parent_has {
                        merge = Some((*parent_tip, *child_tip));
                        break 'outer;
                    }
                }
            }
            match merge {
                Some((parent_tip, child_tip)) => {
                    let parent_chain = self.alt_headers.remove(&parent_tip).unwrap();
                    let child_chain = self.alt_headers.remove(&child_tip).unwrap();
                    let first_prev = child_chain.first().unwrap().previous_hash;
                    let split = parent_chain
                        .iter()
                        .position(|h| h.hash() == first_prev)
                        .expect("parent chain contains parent");
                    let mut merged = parent_chain[..=split].to_vec();
                    merged.extend(child_chain);
                    self.alt_headers.insert(child_tip, merged);
                }
                None => break,
            }
        }
    }

    /// Compute `(fork_height, cumulative_work)` for a buffered alt chain that
    /// connects to the canonical chain, or `None` if it is not yet connected.
    fn alt_chain_cumulative(&self, tip_hash: &Hash) -> Option<(u32, U256)> {
        let chain = self.alt_headers.get(tip_hash)?;
        let first = chain.first()?;
        let parent_height = first.height.0.checked_sub(1)?;
        let parent = self.headers.get(&parent_height)?;
        if parent.hash() != first.previous_hash {
            return None;
        }
        let base = self.tips.get(&parent.hash())?.cumulative_work;
        let mut total = base;
        for hdr in chain {
            let w = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
                &hdr.bits.to_full_target(),
            ));
            total = total.checked_add(&w)?;
        }
        Some((parent_height, total))
    }

    /// After any chain change, adopt the heaviest buffered fork that is
    /// strictly heavier than the current tip and within the journal depth.
    /// Branches are linked (out-of-order assembly) then evaluated; loops
    /// because a reorg can connect further buffered branches.
    fn try_resolve_forks(&mut self, applied: &mut Vec<Block>) -> Result<()> {
        self.link_orphans();
        loop {
            let mut best: Option<(Hash, U256)> = None;
            let keys: Vec<Hash> = self.alt_headers.keys().copied().collect();
            for tip in keys {
                // Skip chains containing a block already proven invalid during
                // a prior reorg dry-run (they can never become canonical).
                let poisoned = self
                    .alt_headers
                    .get(&tip)
                    .map(|c| {
                        c.iter()
                            .any(|h| self.reorg_rejected_blocks.contains(&h.hash()))
                    })
                    .unwrap_or(false);
                if poisoned {
                    continue;
                }
                if let Some((_, cum)) = self.alt_chain_cumulative(&tip) {
                    if cum > self.tip.cumulative_work
                        && best.as_ref().map(|(_, c)| cum > *c).unwrap_or(true)
                    {
                        best = Some((tip, cum));
                    }
                }
            }
            match best {
                Some((tip, _)) => self.reorg_to_alt(&tip, applied)?,
                None => return Ok(()),
            }
        }
    }

    /// Roll back the canonical chain to a fork point and re-apply a buffered
    /// fork branch, advancing tip/headers/tips per height (no stale tip
    /// reuse) and verifying the journal depth before any state mutation.
    fn reorg_to_alt(&mut self, tip_hash: &Hash, applied: &mut Vec<Block>) -> Result<()> {
        let (fork_height, _) = self
            .alt_chain_cumulative(tip_hash)
            .ok_or_else(|| CoreError::InvalidBlock("fork chain no longer connected".to_string()))?;

        let rollback_depth = self.tip.height.0.saturating_sub(fork_height);
        if rollback_depth > REORG_JOURNAL_DEPTH {
            return Err(CoreError::InvalidBlock(format!(
                "deep reorg ({} blocks) exceeds maximum supported depth ({})",
                rollback_depth, REORG_JOURNAL_DEPTH
            )));
        }

        let chain = self
            .alt_headers
            .get(tip_hash)
            .cloned()
            .expect("alt chain present");
        let mut blocks = Vec::with_capacity(chain.len());
        for hdr in &chain {
            let b = self.alt_blocks.get(&hdr.hash()).cloned().ok_or_else(|| {
                CoreError::InvalidBlock("fork chain missing block data".to_string())
            })?;
            blocks.push(b);
        }

        // PRE-VALIDATE the entire candidate branch against a dry-run of the
        // fork-point state BEFORE mutating the live chain. A bad fork block
        // (invalid PoW / state root / merkle / coinbase / …) must never be
        // able to leave the live chain rolled back mid-reorg — the rollback
        // below is only performed once every candidate block is known-valid.
        {
            let fork_point_hash = self
                .headers
                .get(&fork_height)
                .map(|h| h.hash())
                .ok_or_else(|| CoreError::InvalidBlock("fork point missing".to_string()))?;
            let fork_tip = self
                .tips
                .get(&fork_point_hash)
                .cloned()
                .ok_or_else(|| CoreError::InvalidBlock("fork point tip missing".to_string()))?;

            let mut sim_state = self.state.clone();
            for _ in 0..rollback_depth {
                if !sim_state.rollback_block() {
                    return Err(CoreError::InvalidBlock(
                        "failed to rollback state for reorg pre-validation".to_string(),
                    ));
                }
            }
            let mut sim_headers = self.headers.clone();
            for h in (fork_height + 1)..=self.tip.height.0 {
                sim_headers.remove(&h);
            }
            let mut sim_tip = fork_tip;
            for block in &blocks {
                let h = block.header.height.0;
                let _ = chroma_crypto::randomx::ensure_randomx_for_height(h, |x| {
                    sim_headers.get(&x).map(|hdr| hdr.hash())
                });
                let ctx = self.build_validation_ctx(&sim_headers, &sim_tip, h)?;
                if let Err(e) = chroma_block::validate_block(block, &ctx, &mut sim_state) {
                    // This fork block is provably invalid: no chain containing
                    // it can ever become canonical. Memoize so the reorg
                    // attempt is not repeated on every subsequent block.
                    self.reorg_rejected_blocks.insert(block.hash());
                    return Err(CoreError::InvalidBlock(format!(
                        "candidate fork block at height {} failed reorg validation: {}",
                        h, e
                    )));
                }
                let work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
                    &block.header.bits.to_full_target(),
                ));
                sim_tip = ChainTip {
                    height: BlockHeight(h),
                    hash: block.hash(),
                    header: block.header.clone(),
                    cumulative_work: sim_tip
                        .cumulative_work
                        .checked_add(&work)
                        .ok_or_else(|| CoreError::Overflow("cumulative work overflow".into()))?,
                    supply: sim_state.total_supply(),
                };
                sim_headers.insert(h, block.header.clone());
            }
        }

        // Roll back height-by-height, moving the tip to its parent each step
        // so header/tips bookkeeping stays consistent.
        let mut height = self.tip.height.0;
        while height > fork_height {
            if !self.state.rollback_block() {
                return Err(CoreError::InvalidBlock(
                    "failed to rollback state for reorg".to_string(),
                ));
            }
            self.headers.remove(&height);
            let old_hash = self.tip.hash;
            self.tips.remove(&old_hash);
            let parent = self.headers.get(&(height - 1)).ok_or_else(|| {
                CoreError::InvalidBlock(format!("missing parent header at height {}", height - 1))
            })?;
            let parent_tip = self.tips.get(&parent.hash()).cloned().ok_or_else(|| {
                CoreError::InvalidBlock(format!("missing parent tip at height {}", height - 1))
            })?;
            self.tip = parent_tip;
            height -= 1;
        }

        self.alt_headers.remove(tip_hash);
        for b in &blocks {
            self.alt_blocks.remove(&b.hash());
        }

        for b in blocks {
            self.apply_block_inner(&b, applied)?;
        }
        Ok(())
    }

    /// Keep the fork quarantine bounded (mirrors the header cap). Two limits:
    /// a chain-count cap (mirrors the historical 100-entry header cap) and a
    /// TOTAL buffered-block cap so a single maliciously-long fork chain (an
    /// attacker streaming thousands of linked blocks) cannot grow
    /// `alt_blocks` unboundedly. Pruned chains have their full blocks removed
    /// too, so the flat block store stays bounded with the bookkeeping.
    fn trim_alt_quarantine(&mut self) {
        const MAX_ALT_CHAINS: usize = 100;
        const MAX_ALT_BLOCKS: usize = 500;
        let trim = |s: &mut Self| {
            while s.alt_headers.len() > MAX_ALT_CHAINS {
                let oldest: Vec<Hash> = s.alt_headers.keys().take(10).copied().collect();
                for key in oldest {
                    if let Some(chain) = s.alt_headers.remove(&key) {
                        for hdr in chain {
                            s.alt_blocks.remove(&hdr.hash());
                        }
                    }
                }
            }
            while s.alt_blocks.len() > MAX_ALT_BLOCKS {
                let oldest: Vec<Hash> = s.alt_headers.keys().take(1).copied().collect();
                for key in oldest {
                    if let Some(chain) = s.alt_headers.remove(&key) {
                        for hdr in chain {
                            s.alt_blocks.remove(&hdr.hash());
                        }
                    }
                }
            }
        };
        trim(self);
        // The rejected-block memo is only meaningful while the block is still
        // buffered; prune it with the quarantine so it stays bounded too.
        self.reorg_rejected_blocks
            .retain(|h| self.alt_blocks.contains_key(h));
    }

    /// Find the fork point for a known tip hash.
    pub fn find_fork_point(&self, tip_hash: &Hash) -> Option<u32> {
        let tip = self.tips.get(tip_hash)?;
        let height = tip.height.0;

        if height == 0 {
            return Some(0);
        }

        if let Some(alt_chain) = self.alt_headers.get(tip_hash) {
            let mut check_hash = tip.header.previous_hash;
            let mut check_height = height.saturating_sub(1);

            loop {
                if let Some(local_header) = self.headers.get(&check_height) {
                    if local_header.hash() == check_hash {
                        return Some(check_height);
                    }
                }
                if check_height == 0 {
                    break;
                }
                if let Some(alt_header) = alt_chain.iter().find(|h| h.height.0 == check_height) {
                    check_hash = alt_header.previous_hash;
                    check_height -= 1;
                } else {
                    break;
                }
            }
        }

        if let Some(active_header) = self.headers.get(&(height - 1)) {
            if active_header.hash() == tip.header.previous_hash {
                return Some(height - 1);
            }
        }

        None
    }

    /// Blocks to roll back to reach the best competing tip.
    pub fn reorg_depth(&self) -> usize {
        let best = self.tips.values().max_by_key(|t| t.cumulative_work);

        match best {
            Some(best_tip) if best_tip.hash != self.tip.hash => {
                if let Some(fp) = self.find_fork_point(&best_tip.hash) {
                    return (self.tip.height.0.saturating_sub(fp)) as usize;
                }
                0
            }
            _ => 0,
        }
    }

    /// Select the best chain tip (greatest cumulative work).
    pub fn best_tip(&self) -> &ChainTip {
        &self.tip
    }

    /// Return current tip height and hash for reorg detection.
    pub fn tip_info(&self) -> (u32, Hash) {
        (self.tip.height.0, self.tip.hash)
    }

    /// Compute Median Time Past from the last MTP_WINDOW (7) block timestamps.
    /// For height < MTP_WINDOW, uses timestamps from genesis to height-1.
    pub fn compute_median_time_past(&self, height: u32) -> u64 {
        compute_median_time_past_from(&self.headers, height)
    }

    /// Build the validation context for a block at `height` extending
    /// `headers`/`tip`. Used both for live application and for the reorg
    /// dry-run pre-validation (which must not mutate the live chain).
    fn build_validation_ctx(
        &self,
        headers: &BTreeMap<u32, BlockHeader>,
        tip: &ChainTip,
        height: u32,
    ) -> Result<BlockValidationContext> {
        let (previous_hash, previous_timestamp, current_supply) = if height == 0 {
            (Hash::ZERO, 0u64, 0u64)
        } else {
            let prev = headers.get(&(height - 1)).ok_or_else(|| {
                CoreError::InvalidBlock(format!("missing parent header at height {}", height - 1))
            })?;
            (prev.hash(), prev.timestamp, tip.supply)
        };

        let mtp = compute_median_time_past_from(headers, height);
        let expected_bits = calculate_target_for_height(height, headers)?;

        let network_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(BlockValidationContext {
            previous_hash,
            expected_height: BlockHeight(height),
            previous_timestamp,
            median_time_past: mtp,
            expected_bits,
            current_supply,
            previous_state_root: tip.header.state_root,
            network_time,
            network_magic: self.network_magic,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::MAX_DIFFICULTY_INCREASE_FACTOR;

    #[test]
    fn test_genesis_deterministic() {
        let g1 = build_genesis_block();
        let g2 = build_genesis_block();
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_genesis_hash() {
        let genesis = build_genesis_block();
        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.height, BlockHeight::GENESIS);
        assert_eq!(genesis.header.timestamp, GENESIS_TIMESTAMP);
        assert_eq!(genesis.header.bits, CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(genesis.header.nonce, 0);
        assert_eq!(genesis.header.previous_hash, Hash::ZERO);
        assert_eq!(genesis.header.tx_merkle_root, Hash::ZERO);
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn test_genesis_randomx_seed() {
        let seed = genesis_randomx_seed();
        let seed2 = genesis_randomx_seed();
        assert_eq!(seed, seed2);
        assert_ne!(seed, Hash::ZERO);
    }

    #[test]
    fn test_chain_state_genesis() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.tip.height, BlockHeight::GENESIS);
        assert_eq!(chain.tip.supply, 0);
        assert!(chain.best_tip().cumulative_work > U256::ZERO);
    }

    #[test]
    fn test_difficulty_carry_forward() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        let target = calculate_target_for_height(1, &headers).unwrap();
        assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_on_target() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // 10 blocks at exactly 10s intervals → on target
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_blocks_too_fast() {
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
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS / 2),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_before =
            U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        let target_after = U256::from_be_bytes(&target.to_full_target());
        // Blocks 2× too fast → target shrinks (harder).
        assert!(
            target_after < target_before,
            "blocks too fast → target decreases"
        );
    }

    #[test]
    fn test_difficulty_blocks_too_slow() {
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
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS * 4),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_before =
            U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        let target_after = U256::from_be_bytes(&target.to_full_target());
        // Blocks 4× too slow → target grows (easier) or stays.
        assert!(
            target_after >= target_before,
            "blocks too slow → target should not decrease"
        );
    }

    #[test]
    fn test_difficulty_clamped() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // 1 second per block → extremely fast
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_before =
            U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        let target_after = U256::from_be_bytes(&target.to_full_target());

        // Target decreased (harder) but clamped: new_target >= old_target / MAX_DIFFICULTY_INCREASE_FACTOR
        assert!(target_after < target_before);
        let min_allowed = target_before
            .div_rem(&U256::from_u64(MAX_DIFFICULTY_INCREASE_FACTOR))
            .0;
        assert!(
            target_after >= min_allowed,
            "increase clamped to {}x",
            MAX_DIFFICULTY_INCREASE_FACTOR
        );
    }

    #[test]
    fn test_minimum_target_enforced() {
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
                timestamp: GENESIS_TIMESTAMP + (h as u64),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_u256 = U256::from_be_bytes(&target.to_full_target());
        let min = U256::from_be_bytes(&MINIMUM_TARGET);
        assert!(target_u256 >= min, "target must not go below minimum");
    }

    #[test]
    fn test_non_retarget_height() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Insert headers for heights 1-9 so carry-forward can look them up
        for h in 1..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Heights 1-9 should all carry forward genesis target
        for h in 1..=9u32 {
            let target = calculate_target_for_height(h, &headers).unwrap();
            assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS), "height {}", h);
        }
    }

    #[test]
    fn test_mul_div_exact() {
        let a = U256::from_u64(1000);
        assert_eq!(mul_div(&a, 3, 2).unwrap(), U256::from_u64(1500));
        assert_eq!(mul_div(&a, 1, 2).unwrap(), U256::from_u64(500));
        assert_eq!(mul_div(&a, 2, 2).unwrap(), U256::from_u64(1000));
    }

    #[test]
    fn test_mul_div_zero_denominator() {
        let a = U256::from_u64(1000);
        assert!(mul_div(&a, 3, 0).is_none());
    }

    #[test]
    fn test_mul_div_zero_numerator() {
        let a = U256::from_u64(1000);
        assert_eq!(mul_div(&a, 0, 5).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_mul_div_large_values() {
        let a = U256::from_u64(u64::MAX);
        let result = mul_div(&a, 2, 3).unwrap();
        // u64::MAX * 2 / 3 ≈ 12297829382473034410
        let result_u64 = result.to_u64().unwrap();
        let expected = u64::MAX / 3 * 2;
        let diff = result_u64.abs_diff(expected);
        assert!(
            diff < 2,
            "mul_div large: result={} expected={}",
            result_u64,
            expected
        );
    }

    #[test]
    fn test_mul_div_one_to_one() {
        let a = U256::from_u64(42);
        assert_eq!(mul_div(&a, 1, 1).unwrap(), a);
    }

    #[test]
    fn test_difficulty_multiple_retargets() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Build 20 blocks at exactly target pace
        for h in 1..=20u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Both retargets at 10 and 20 should stay at genesis target
        let t10 = calculate_target_for_height(10, &headers).unwrap();
        let t20 = calculate_target_for_height(20, &headers).unwrap();
        assert_eq!(t10, CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(t20, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_accelerating_then_decelerating() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Blocks 1-5: fast (5s each)
        for h in 1..=5u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * 5,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Blocks 6-9: slow (20s each) — relative to block 5
        let block5_ts = GENESIS_TIMESTAMP + 5 * 5;
        for h in 6..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: block5_ts + ((h - 5) as u64) * 20,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // At height 10 retarget: window is heights 0-9
        // actual_time = block9.timestamp - genesis.timestamp
        let block9_ts = headers.get(&9).unwrap().timestamp;
        let actual_time = block9_ts - GENESIS_TIMESTAMP;
        // Expected: 5*5 + 4*20 = 25 + 80 = 105 seconds
        // target_time = 90 seconds
        // new_target = old * 105 / 90 = old * 1.166...
        assert!(
            actual_time > 90,
            "actual_time should be > target_time for slower blocks"
        );

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_before =
            U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        let target_after = U256::from_be_bytes(&target.to_full_target());
        // Blocks slower than target → target grows (easier).
        assert!(
            target_after > target_before,
            "blocks slower than target → target increases"
        );
    }

    #[test]
    fn test_max_target_enforced() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Very slow blocks (100s each) → target tries to increase a lot
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * 100,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_u256 = U256::from_be_bytes(&target.to_full_target());
        let max = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(target_u256 <= max, "target must not exceed maximum");
    }

    #[test]
    fn test_easy_regime_holds_steady_at_retarget() {
        // Regtest easy bits (0x20ffffff) are easier than MAXIMUM_TARGET.
        // Retargeting must hold them steady instead of clamping up to
        // mainnet-grade difficulty (previously 0x1f03ffff: ~16k× harder,
        // unmineable — any chain mining past height 9 stalled forever).
        let easy = CompactTarget(0x20ffffff);
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block_with_bits(easy);
        headers.insert(0, genesis.header.clone());
        for h in 1..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            headers.insert(
                h,
                BlockHeader {
                    version: 1,
                    previous_hash: prev.hash(),
                    state_root: Hash::ZERO,
                    tx_merkle_root: Hash::ZERO,
                    timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                    bits: easy,
                    height: BlockHeight(h),
                    nonce: 0,
                },
            );
        }
        assert_eq!(
            calculate_target_for_height(10, &headers).unwrap(),
            easy,
            "easy-regime retarget must hold steady"
        );
        // Second window too (heights 10..19 carry easy bits forward).
        for h in 10..=19u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            headers.insert(
                h,
                BlockHeader {
                    version: 1,
                    previous_hash: prev.hash(),
                    state_root: Hash::ZERO,
                    tx_merkle_root: Hash::ZERO,
                    timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                    bits: easy,
                    height: BlockHeight(h),
                    nonce: 0,
                },
            );
        }
        assert_eq!(
            calculate_target_for_height(20, &headers).unwrap(),
            easy,
            "easy-regime retarget must hold steady at height 20"
        );
    }

    #[test]
    fn test_mainnet_regime_still_retargets() {
        // Sanity: in-bounds targets (genesis difficulty) still retarget.
        // Fast blocks (5 s each, actual 45 s < 90 s target) → harder.
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());
        for h in 1..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            headers.insert(
                h,
                BlockHeader {
                    version: 1,
                    previous_hash: prev.hash(),
                    state_root: Hash::ZERO,
                    tx_merkle_root: Hash::ZERO,
                    timestamp: GENESIS_TIMESTAMP + (h as u64) * 5,
                    bits: CompactTarget(GENESIS_TARGET_BITS),
                    height: BlockHeight(h),
                    nonce: 0,
                },
            );
        }
        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_before =
            U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        let target_after = U256::from_be_bytes(&target.to_full_target());
        assert!(
            target_after < target_before,
            "fast blocks → target decreases"
        );
    }

    /// Reference implementation of the pre-hold retarget algorithm: the exact
    /// math `calculate_target_for_height` performed before the easy-regime
    /// hold was added. Used to prove bit-exact equivalence on the production
    /// (in-bounds) range. Any intentional divergence from this reference must
    /// be an out-of-bounds current taking the documented hold branch.
    fn reference_retarget_pre_hold(
        height: u32,
        headers: &BTreeMap<u32, BlockHeader>,
    ) -> Result<CompactTarget> {
        if height == 0 {
            return Ok(CompactTarget(GENESIS_TARGET_BITS));
        }
        if !height.is_multiple_of(DIFFICULTY_ADJUSTMENT_WINDOW) {
            let prev = headers.get(&(height - 1)).ok_or_else(|| {
                CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1))
            })?;
            return Ok(prev.bits);
        }
        let intervals = (DIFFICULTY_ADJUSTMENT_WINDOW - 1) as u64;
        let target_time = TARGET_BLOCK_TIME_SECS * intervals;
        let current = headers.get(&(height - 1)).ok_or_else(|| {
            CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1))
        })?;
        let window_start = height.saturating_sub(DIFFICULTY_ADJUSTMENT_WINDOW);
        let start = headers.get(&window_start).ok_or_else(|| {
            CoreError::InvalidDifficulty(format!("missing header for height {}", window_start))
        })?;
        let actual_time = current.timestamp.saturating_sub(start.timestamp);
        let max_actual_time = target_time * MAX_DIFFICULTY_INCREASE_FACTOR;
        let actual_time = std::cmp::min(std::cmp::max(actual_time, 1), max_actual_time);
        let old_target = U256::from_be_bytes(&current.bits.to_full_target());
        let new_target = mul_div(&old_target, actual_time, target_time).ok_or_else(|| {
            CoreError::InvalidDifficulty("difficulty calculation overflow".into())
        })?;
        let (min_target, _) = old_target.div_rem(&U256::from_u64(MAX_DIFFICULTY_DECREASE_FACTOR));
        let max_target = old_target.shl(2);
        let clamped = if new_target < min_target {
            min_target
        } else if new_target > max_target {
            max_target
        } else {
            new_target
        };
        let min_abs = U256::from_be_bytes(&MINIMUM_TARGET);
        let max_abs = U256::from_be_bytes(&MAXIMUM_TARGET);
        let final_target = if clamped < min_abs {
            min_abs
        } else if clamped > max_abs {
            max_abs
        } else {
            clamped
        };
        Ok(CompactTarget::from_full_target(&final_target.to_be_bytes()))
    }

    /// Build a self-consistent header chain 0..=top carrying uniform `bits`;
    /// block `top` gets timestamp `GENESIS_TIMESTAMP + actual_span` so the
    /// retarget at height 10 observes exactly `actual_span` seconds.
    fn chain_with_bits(
        bits: CompactTarget,
        top: u32,
        actual_span: u64,
    ) -> BTreeMap<u32, BlockHeader> {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block_with_bits(bits);
        headers.insert(0, genesis.header.clone());
        for h in 1..=top {
            let prev = headers.get(&(h - 1)).unwrap().clone();
            let ts = if h == top {
                GENESIS_TIMESTAMP.saturating_add(actual_span)
            } else {
                GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS
            };
            headers.insert(
                h,
                BlockHeader {
                    version: 1,
                    previous_hash: prev.hash(),
                    state_root: Hash::ZERO,
                    tx_merkle_root: Hash::ZERO,
                    timestamp: ts,
                    bits,
                    height: BlockHeight(h),
                    nonce: 0,
                },
            );
        }
        headers
    }

    /// Production-regime currents: every compact here denotes a target within
    /// [MINIMUM_TARGET, MAXIMUM_TARGET] (asserted as a test precondition).
    fn production_currents() -> Vec<CompactTarget> {
        vec![
            CompactTarget(GENESIS_TARGET_BITS), // 0x1f00a7c5
            CompactTarget(0x1c00ffff),          // harder, in bounds
            CompactTarget(0x1e00ffff),          // easier, in bounds
            CompactTarget(0x1e0fffff),          // much easier, still in bounds
            CompactTarget(0x1f029f13),          // just below MAXIMUM_TARGET
            CompactTarget(0x1700FFFF),          // near-minimum canonical
            CompactTarget(0x1d00fffe),          // mantissa edge
            CompactTarget(0x1d010000),          // mantissa edge
        ]
    }

    fn actual_spans() -> Vec<u64> {
        vec![
            0,
            1,
            44,
            45,
            89,
            90,
            91,
            135,
            180,
            270,
            359,
            360,
            361,
            720,
            3600,
            86_400,
            u64::MAX,
        ]
    }

    #[test]
    fn test_retarget_reference_equivalence_production_range() {
        // Core audit property: for every in-bounds current and every
        // timespan regime (fast/on-target/slow/clamped/extreme), the
        // implementation must be bit-exact with the pre-hold algorithm.
        let min_abs = U256::from_be_bytes(&MINIMUM_TARGET);
        let max_abs = U256::from_be_bytes(&MAXIMUM_TARGET);
        for bits in production_currents() {
            let old = U256::from_be_bytes(&bits.to_full_target());
            assert!(
                old >= min_abs && old <= max_abs,
                "test setup error: {:08x} is not a production-regime current",
                bits.0
            );
            for actual in actual_spans() {
                let headers = chain_with_bits(bits, 9, actual);
                let got = calculate_target_for_height(10, &headers).unwrap();
                let want = reference_retarget_pre_hold(10, &headers).unwrap();
                assert_eq!(
                    got, want,
                    "equivalence break: bits={:08x} actual={}s got={:08x} want={:08x}",
                    bits.0, actual, got.0, want.0
                );
                // Production invariant: in-bounds current ⇒ in-bounds result.
                let out = U256::from_be_bytes(&got.to_full_target());
                assert!(
                    out >= min_abs && out <= max_abs,
                    "out of bounds: bits={:08x} actual={}s → {:08x}",
                    bits.0,
                    actual,
                    got.0
                );
            }
        }
    }

    #[test]
    fn test_retarget_clamp_regimes_match_reference() {
        // Spot-check the named regimes against independently computed values.
        let bits = CompactTarget(GENESIS_TARGET_BITS);
        // Lower clamp: instant blocks (actual→1s) try old/90, floored at old/4.
        let fast = chain_with_bits(bits, 9, 0);
        let got_fast = calculate_target_for_height(10, &fast).unwrap();
        assert_eq!(got_fast, reference_retarget_pre_hold(10, &fast).unwrap());
        let old_full = U256::from_be_bytes(&bits.to_full_target());
        let (floor, _) = old_full.div_rem(&U256::from_u64(MAX_DIFFICULTY_DECREASE_FACTOR));
        assert_eq!(
            U256::from_be_bytes(&got_fast.to_full_target()),
            U256::from_be_bytes(
                &CompactTarget::from_full_target(&floor.to_be_bytes()).to_full_target()
            ),
            "lower clamp must equal old/4 (up to compact precision)"
        );
        // Upper clamp: glacial blocks (capped at 360s) try old×4.
        let slow = chain_with_bits(bits, 9, 10_000);
        let got_slow = calculate_target_for_height(10, &slow).unwrap();
        assert_eq!(got_slow, reference_retarget_pre_hold(10, &slow).unwrap());
        assert_eq!(
            got_slow,
            CompactTarget::from_full_target(&old_full.shl(2).to_be_bytes()),
            "upper clamp must equal old×4 (up to compact precision)"
        );
        // Exact target time: difficulty unchanged (up to compact precision).
        let exact = chain_with_bits(bits, 9, 90);
        assert_eq!(
            calculate_target_for_height(10, &exact).unwrap(),
            reference_retarget_pre_hold(10, &exact).unwrap()
        );
    }

    #[test]
    fn test_retarget_boundary_currents() {
        // current == just below MAXIMUM_TARGET (0x1f029f13): both
        // algorithms agree and stay in bounds.
        let below = CompactTarget(0x1f029f13);
        assert!(
            U256::from_be_bytes(&below.to_full_target()) <= U256::from_be_bytes(&MAXIMUM_TARGET)
        );
        for actual in actual_spans() {
            let headers = chain_with_bits(below, 9, actual);
            assert_eq!(
                calculate_target_for_height(10, &headers).unwrap(),
                reference_retarget_pre_hold(10, &headers).unwrap(),
                "just-below-max must match reference (actual={}s)",
                actual
            );
        }
        // current just above MAXIMUM_TARGET (0x1f029f15): the ONLY intentional
        // divergence class — hold returns the input bit-exact, while the old
        // algorithm always recomputed (epoch/absolute clamps) and therefore
        // never returned its input unchanged.
        let above = CompactTarget(0x1f029f15);
        let min_abs = U256::from_be_bytes(&MINIMUM_TARGET);
        let max_abs = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(U256::from_be_bytes(&above.to_full_target()) > max_abs);
        for actual in actual_spans() {
            let headers = chain_with_bits(above, 9, actual);
            assert_eq!(
                calculate_target_for_height(10, &headers).unwrap(),
                above,
                "just-above-max must hold bit-exact (actual={}s)",
                actual
            );
            let old = reference_retarget_pre_hold(10, &headers).unwrap();
            assert_ne!(
                old, above,
                "reference must not hold just-above-max (actual={}s)",
                actual
            );
            let v = U256::from_be_bytes(&old.to_full_target());
            assert!(
                v >= min_abs && v <= max_abs,
                "reference just-above-max output {:08x} must stay in bounds",
                old.0
            );
        }
    }

    #[test]
    fn test_retarget_easy_currents_hold_bit_exact() {
        // Out-of-bounds easy currents: hold returns the input unchanged
        // (no canonicalization roundtrip, infallible on this path). The old
        // algorithm never held: it recomputed — clamping toward MAXIMUM on
        // moderate spans, or failing outright with a difficulty-calculation
        // overflow on extreme spans (a chain-stall-by-error). Both old
        // outcomes differ from the hold, confining the behavior change to
        // chains whose genesis was outside production bounds.
        for raw in [0x20ffffffu32, 0x2100FFFF, 0xFFFFFFFF] {
            let easy = CompactTarget(raw);
            assert!(
                U256::from_be_bytes(&easy.to_full_target()) > U256::from_be_bytes(&MAXIMUM_TARGET),
                "test setup error: {:08x} is not above MAXIMUM",
                raw
            );
            for actual in [0u64, 1, 45, 90, 360, 100_000] {
                let headers = chain_with_bits(easy, 9, actual);
                assert_eq!(
                    calculate_target_for_height(10, &headers).unwrap(),
                    easy,
                    "easy current {:08x} must hold bit-exact (actual={}s)",
                    raw,
                    actual
                );
                match reference_retarget_pre_hold(10, &headers) {
                    Ok(old) => assert_ne!(
                        old, easy,
                        "reference must not hold {:08x} (actual={}s)",
                        raw, actual
                    ),
                    Err(CoreError::InvalidDifficulty(_)) => {}
                    Err(e) => panic!("unexpected reference error for {:08x}: {}", raw, e),
                }
            }
        }
        // Anchor the historical shock value: regtest easy bits at ideal
        // cadence used to clamp to mainnet-grade difficulty. Now the reference
        // clamps to MAXIMUM_TARGET instead.
        let headers = chain_with_bits(CompactTarget(0x20ffffff), 9, 90);
        let ref_result = reference_retarget_pre_hold(10, &headers).unwrap();
        let max_target = U256::from_be_bytes(&MAXIMUM_TARGET);
        let ref_u256 = U256::from_be_bytes(&ref_result.to_full_target());
        assert_eq!(
            ref_u256, max_target,
            "reference must clamp to MAXIMUM_TARGET"
        );
    }

    #[test]
    fn test_mainnet_chain_simulation_never_holds() {
        // Constructive unreachability: a valid mainnet-regime chain built
        // block by block (each header carrying the computed expectation,
        // exactly as validation enforces) matches the reference at every
        // height through three retargets — the hold branch never fires.
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());
        for h in 1..=30u32 {
            let prev = headers.get(&(h - 1)).unwrap().clone();
            // Vary cadence per window: fast (5s), exact (10s), slow (20s).
            let step = match h / 10 {
                0 => 5,
                1 => 10,
                _ => 20,
            };
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: prev.timestamp + step,
                bits: prev.bits,
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
            // Heights are filled with carried bits first so the window has
            // the shape validation would have accepted; then check height h
            // against both implementations once its window is complete.
            if h.is_multiple_of(DIFFICULTY_ADJUSTMENT_WINDOW) {
                let got = calculate_target_for_height(h, &headers).unwrap();
                let want = reference_retarget_pre_hold(h, &headers).unwrap();
                assert_eq!(got, want, "mainnet sim diverged at height {}", h);
                let out = U256::from_be_bytes(&got.to_full_target());
                assert!(
                    out >= U256::from_be_bytes(&MINIMUM_TARGET)
                        && out <= U256::from_be_bytes(&MAXIMUM_TARGET),
                    "mainnet sim out of bounds at height {}",
                    h
                );
                headers.get_mut(&h).unwrap().bits = got;
            }
        }
    }

    /// Simulate a valid chain to `top`, each header carrying the computed
    /// expectation (exactly what validation enforces), at ideal 10 s cadence.
    /// Returns (height → bits) for the sampled heights.
    fn simulate_chain(network: NetworkKind, top: u32) -> BTreeMap<u32, CompactTarget> {
        let genesis = build_genesis_for_network(&network);
        let mut headers = BTreeMap::new();
        headers.insert(0, genesis.header.clone());
        let mut sampled = BTreeMap::new();
        sampled.insert(0, genesis.header.bits);
        for h in 1..=top {
            let prev = headers.get(&(h - 1)).unwrap().clone();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: prev.timestamp + TARGET_BLOCK_TIME_SECS,
                bits: calculate_target_for_height(h, &headers).unwrap(),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header.clone());
            if matches!(h, 1 | 9 | 10 | 11 | 20 | 100 | 1000) {
                sampled.insert(h, header.bits);
            }
        }
        sampled
    }

    #[test]
    fn test_testnet_difficulty_evolution_is_frozen_easy() {
        // §1 audit table: testnet (easy genesis 0x20ffffff) at ideal cadence.
        // Every retarget holds — difficulty never evolves.
        let evo = simulate_chain(NetworkKind::Testnet, 1000);
        for h in [0u32, 1, 9, 10, 11, 20, 100, 1000] {
            assert_eq!(
                evo[&h],
                CompactTarget(0x20ffffff),
                "testnet height {} must stay easy (frozen by hold)",
                h
            );
        }
    }

    #[test]
    fn test_mainnet_difficulty_evolution_is_stable() {
        // Contrast: mainnet (difficulty-1 genesis) at ideal cadence keeps
        // production difficulty through all retargets including h=1000.
        let evo = simulate_chain(NetworkKind::Mainnet, 1000);
        for h in [0u32, 1, 9, 10, 11, 20, 100, 1000] {
            let bits = evo[&h];
            let v = U256::from_be_bytes(&bits.to_full_target());
            assert!(
                v >= U256::from_be_bytes(&MINIMUM_TARGET)
                    && v <= U256::from_be_bytes(&MAXIMUM_TARGET),
                "mainnet height {} out of bounds: {:08x}",
                h,
                bits.0
            );
        }
        assert_eq!(evo[&0], CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(evo[&10], CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(evo[&100], CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(evo[&1000], CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_network_genesis_parameters_are_pinned() {
        use chroma_core::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
        // Bits per network.
        assert_eq!(
            build_genesis_for_network(&NetworkKind::Mainnet).header.bits,
            CompactTarget(GENESIS_TARGET_BITS)
        );
        assert_eq!(
            build_genesis_for_network(&NetworkKind::Testnet).header.bits,
            CompactTarget(0x20ffffff)
        );
        assert_eq!(
            build_genesis_for_network(&NetworkKind::Regtest).header.bits,
            CompactTarget(0x20ffffff)
        );
        // Magic bytes per network (wire-level isolation identity).
        assert_eq!(MAINNET_MAGIC, [0xC4, 0x48, 0x52, 0x4F]);
        assert_eq!(TESTNET_MAGIC, [0xC4, 0x54, 0x45, 0x53]);
        assert_eq!(REGTEST_MAGIC, [0xC4, 0x52, 0x54, 0x54]);
        // Genesis hashes are pairwise distinct (chain identity separation).
        let mg = build_genesis_for_network(&NetworkKind::Mainnet).hash();
        let tg = build_genesis_for_network(&NetworkKind::Testnet).hash();
        let rg = build_genesis_for_network(&NetworkKind::Regtest).hash();
        assert_ne!(mg, tg);
        assert_ne!(mg, rg);
        assert_ne!(tg, rg);
        // MAXIMUM_TARGET relation per network genesis (the policy crux).
        let max_abs = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(
            U256::from_be_bytes(
                &build_genesis_for_network(&NetworkKind::Mainnet)
                    .header
                    .bits
                    .to_full_target()
            ) <= max_abs,
            "mainnet genesis must be production-regime"
        );
        for net in [NetworkKind::Testnet, NetworkKind::Regtest] {
            assert!(
                U256::from_be_bytes(&build_genesis_for_network(&net).header.bits.to_full_target())
                    > max_abs,
                "testnet/regtest genesis must be easy-regime"
            );
        }
    }

    #[test]
    fn test_testnet_genesis_hash_is_pinned() {
        let genesis = build_genesis_for_network(&NetworkKind::Testnet);
        assert_eq!(
            genesis.hash().to_hex(),
            "7a127bb73b88c9c4b833bcd24b4ef47111535f01e4bb100f54cd6bc1126c56be",
            "testnet genesis hash must not change without a chain restart"
        );
    }

    #[test]
    fn test_genesis_hash_is_nonzero() {
        let genesis = build_genesis_block();
        let header_hash = genesis.hash();
        assert_ne!(header_hash, Hash::ZERO, "genesis hash must be non-zero");
    }

    #[test]
    fn test_chain_tip_work_increases() {
        let chain = ChainState::with_genesis();
        let work_before = chain.best_tip().cumulative_work;
        assert!(work_before > U256::ZERO);
    }

    #[test]
    fn test_minimum_target_constant() {
        let min = U256::from_be_bytes(&MINIMUM_TARGET);
        assert!(min > U256::ZERO, "MINIMUM_TARGET must be non-zero");
        let max = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(max > min, "MAXIMUM_TARGET must be > MINIMUM_TARGET");
    }

    #[test]
    fn test_difficulty_direction_invariants() {
        // At exactly 90s (target_time for window), difficulty stays same
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
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target_unchanged = calculate_target_for_height(10, &headers).unwrap();
        assert_eq!(
            target_unchanged,
            CompactTarget(GENESIS_TARGET_BITS),
            "at exactly target pace, difficulty unchanged"
        );

        // Test: faster → higher difficulty (lower target)
        let mut headers_fast = headers.clone();
        for h in 1..=10u32 {
            let prev = headers_fast.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS / 2),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers_fast.insert(h, header);
        }
        let target_fast = calculate_target_for_height(10, &headers_fast).unwrap();
        let t_fast = U256::from_be_bytes(&target_fast.to_full_target());
        let t_genesis = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        assert!(
            t_fast < t_genesis,
            "faster blocks → lower target (higher difficulty)"
        );

        // Test: slower → lower difficulty (higher target)
        let mut headers_slow = headers.clone();
        for h in 1..=10u32 {
            let prev = headers_slow.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS * 3),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers_slow.insert(h, header);
        }
        let target_slow = calculate_target_for_height(10, &headers_slow).unwrap();
        let t_slow = U256::from_be_bytes(&target_slow.to_full_target());
        assert!(
            t_slow > t_genesis,
            "slower blocks → higher target (lower difficulty)"
        );
    }

    #[test]
    fn test_calculate_target_missing_header() {
        let headers = BTreeMap::new();
        let result = calculate_target_for_height(5, &headers);
        assert!(result.is_err(), "should fail with missing header");
    }

    #[test]
    fn test_genesis_target_bits_value() {
        assert_eq!(GENESIS_TARGET_BITS, 0x1f00a7c5);
    }

    #[test]
    fn test_chain_state_genesis_supply() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.state.total_supply(), 0);
    }

    #[test]
    fn test_chain_state_genesis_headers() {
        let chain = ChainState::with_genesis();
        assert!(chain.headers.contains_key(&0));
        assert_eq!(chain.headers.len(), 1);
    }

    #[test]
    fn test_chain_state_genesis_tips() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.tips.len(), 1);
        assert!(chain.tips.contains_key(&chain.tip.hash));
    }
}
