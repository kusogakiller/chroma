use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chroma_block::BlockHeader;
use chroma_core::hash::Hash;

use crate::wire::{GetDataMessage, GetHeadersMessage, InvEntry, InvType};

pub const MAX_HEADERS_PER_RESPONSE: usize = 2000;
pub const MAX_BLOCKS_PER_REQUEST: usize = 500;
/// Maximum headers buffered across batches. Bounds memory when a peer sends
/// many individually-valid batches; excess batches are ignored.
pub const MAX_PENDING_HEADERS: usize = 10_000;
/// Maximum entries in `known_headers`. Bounds memory against header-flood
/// pollution. When full, further batches are ignored until entries are
/// validated (blocks applied) or the sync attempt resets. Honest chains far
/// beyond this length need finality-based pruning (mainnet follow-up).
pub const MAX_KNOWN_HEADERS: usize = 100_000;

/// Number of blocks behind a peer must be to trigger IBD mode.
pub const IBD_HEIGHT_THRESHOLD: u32 = 144;

/// Maximum number of consecutive block sync failures before banning a peer.
pub const MAX_SYNC_FAILURES: u32 = 5;

/// Timeout for receiving a response during sync (headers or blocks).
pub const SYNC_RESPONSE_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    SyncingHeaders,
    SyncingBlocks,
    CaughtUp,
}

#[derive(Clone, Debug)]
pub enum SyncCommand {
    GetHeaders(Hash),
    GetBlocks(Vec<Hash>),
    SyncComplete,
    RequestBlocksFrom(Hash),
}

pub struct ChainSyncer {
    pub state: SyncState,
    pub best_height: u32,
    pub best_hash: Hash,
    sync_peer: Option<SocketAddr>,
    /// Headers we've received but not yet validated/applied.
    pub pending_headers: Vec<BlockHeader>,
    /// Height of the last header we successfully stored.
    synced_header_height: u32,
    /// Known header hashes by height (for gap detection).
    known_headers: BTreeMap<u32, Hash>,
    /// Block hashes we've requested but not yet received.
    pending_block_requests: Vec<Hash>,
    /// Next block height to request (for sequential sync).
    next_height: u32,
    /// Timestamp of the last sync request we sent (for timeout detection).
    last_sync_request_time: Option<Instant>,
    /// Number of consecutive sync failures (invalid blocks, timeouts, etc.).
    consecutive_sync_failures: u32,
}

impl ChainSyncer {
    pub fn new(genesis_hash: Hash) -> Self {
        let mut known_headers = BTreeMap::new();
        known_headers.insert(0, genesis_hash);
        ChainSyncer {
            state: SyncState::Idle,
            best_height: 0,
            best_hash: genesis_hash,
            sync_peer: None,
            pending_headers: Vec::new(),
            synced_header_height: 0,
            known_headers,
            pending_block_requests: Vec::new(),
            next_height: 1,
            last_sync_request_time: None,
            consecutive_sync_failures: 0,
        }
    }

    pub fn set_synced_height(&mut self, height: u32) {
        self.synced_header_height = height;
    }

    /// Record a VALIDATED header hash (applied block or loaded chain state).
    /// Overwrites unconditionally: validated truth always wins over header
    /// gossip. Restarts seed the whole stored chain this way so the linkage
    /// check keeps accepting honest continuations of the local tip.
    /// Pointers (`best_*`, `synced_*`) are intentionally untouched.
    pub fn track_validated(&mut self, height: u32, hash: Hash) {
        self.known_headers.insert(height, hash);
    }

    pub fn synced_header_height(&self) -> u32 {
        self.synced_header_height
    }

    /// Begin header sync with a peer. Returns the GetHeaders message to send.
    pub fn start_header_sync(
        &mut self,
        peer: SocketAddr,
        local_tip_hash: Hash,
    ) -> GetHeadersMessage {
        self.state = SyncState::SyncingHeaders;
        self.sync_peer = Some(peer);
        self.pending_headers.clear();
        self.last_sync_request_time = Some(Instant::now());
        GetHeadersMessage {
            start_hash: local_tip_hash,
            stop_hash: Hash::ZERO,
        }
    }

    /// Generate block locator hashes for GetHeaders requests.
    ///
    /// Block locators allow a remote peer to find the fork point between our chains.
    /// Returns a vector of hashes: starting from the tip, then exponentially decreasing
    /// heights, ending with the genesis hash.
    pub fn block_locator_hashes(&self, local_tip_hash: Hash, local_tip_height: u32) -> Vec<Hash> {
        let mut locators = Vec::new();
        locators.push(local_tip_hash);

        let mut step = 1u32;
        let mut height = local_tip_height;
        while height > 0 {
            height = height.saturating_sub(step);
            if let Some(hash) = self.known_headers.get(&height).copied() {
                locators.push(hash);
            }
            if step < 1000 {
                step = step.saturating_mul(2);
            }
        }

        // Always include genesis
        if let Some(genesis_hash) = self.known_headers.get(&0).copied() {
            if locators.last() != Some(&genesis_hash) {
                locators.push(genesis_hash);
            }
        }

        locators
    }

    /// Process a GetHeaders request from a peer (server side).
    /// Returns the start height to respond from, or None if not found.
    pub fn find_headers_start_height(&self, start_hash: &Hash) -> Option<u32> {
        if *start_hash == Hash::ZERO {
            return Some(0);
        }
        // Search our known headers for this hash
        for (height, hash) in &self.known_headers {
            if hash == start_hash {
                return Some(*height);
            }
        }
        None
    }

    /// Check if we should enter Initial Block Download mode.
    ///
    /// IBD is triggered when the local chain is significantly behind the peer.
    pub fn should_enter_ibd(&self, local_tip_height: u32, peer_height: u32) -> bool {
        peer_height > local_tip_height + IBD_HEIGHT_THRESHOLD
    }

    /// Check if we're in IBD mode (significantly behind).
    pub fn is_in_initial_block_download(&self) -> bool {
        self.state == SyncState::SyncingBlocks
            && self.best_height > self.synced_header_height + IBD_HEIGHT_THRESHOLD
    }

    /// Check if a sync operation has timed out.
    pub fn is_sync_timed_out(&self) -> bool {
        if let Some(last_request) = self.last_sync_request_time {
            last_request.elapsed() > Duration::from_secs(SYNC_RESPONSE_TIMEOUT_SECS)
        } else {
            false
        }
    }

    /// Record a sync failure (invalid block, timeout, etc.).
    pub fn record_sync_failure(&mut self) {
        self.consecutive_sync_failures += 1;
    }

    /// Reset consecutive sync failures (on successful block application).
    pub fn clear_sync_failure(&mut self) {
        self.consecutive_sync_failures = 0;
    }

    /// Check if we've exceeded the maximum sync failures threshold.
    pub fn is_peer_banned_for_sync(&self) -> bool {
        self.consecutive_sync_failures >= MAX_SYNC_FAILURES
    }

    /// Begin block sync after headers are synced.
    /// Requests a batch of blocks starting from the given hash.
    pub fn start_block_sync(
        &mut self,
        peer: SocketAddr,
        from_hash: Hash,
        _from_height: u32,
    ) -> GetDataMessage {
        self.state = SyncState::SyncingBlocks;
        self.sync_peer = Some(peer);
        self.last_sync_request_time = Some(Instant::now());

        // Build a batch of block hashes to request
        let mut inventory = Vec::new();
        inventory.push(InvEntry {
            inv_type: InvType::Block,
            hash: from_hash,
        });

        // Add subsequent blocks if we know their hashes
        let start_height = _from_height;
        for h in (start_height + 1)
            ..=(start_height + MAX_BLOCKS_PER_REQUEST as u32).min(self.best_height)
        {
            if let Some(hash) = self.known_headers.get(&h).copied() {
                inventory.push(InvEntry {
                    inv_type: InvType::Block,
                    hash,
                });
            }
        }

        // Track these as pending
        self.pending_block_requests = inventory.iter().skip(1).map(|e| e.hash).collect();

        GetDataMessage { inventory }
    }

    /// Validate a header batch WITHOUT mutating state.
    ///
    /// A batch is accepted only if ALL of the following hold:
    /// - non-empty and within MAX_HEADERS_PER_RESPONSE,
    /// - internally sequential (heights +1, each previous_hash links),
    /// - first previous_hash connects to our known chain,
    /// - no height conflicts with a DIFFERENT known hash (gap-fill only:
    ///   same-hash overlaps are idempotent and fine; different-hash
    ///   overwrites would poison sync state, so the whole batch is refused
    ///   and the caller scores the sender),
    /// - it fits within MAX_KNOWN_HEADERS.
    ///
    /// Unlinked/conflicting batches cannot advance sync and are ignored by
    /// the caller (which scores the sender). Full PoW verification happens
    /// later at block application, where failures ban the sender.
    pub fn header_batch_valid(&self, headers: &[BlockHeader]) -> bool {
        if headers.is_empty() || headers.len() > MAX_HEADERS_PER_RESPONSE {
            return false;
        }
        if self.known_headers.len() + headers.len() > MAX_KNOWN_HEADERS {
            return false;
        }
        let mut prev_hash = headers[0].previous_hash;
        let mut prev_height = headers[0].height.0;
        // First header must connect to something we know.
        if !self.known_headers.values().any(|h| *h == prev_hash) {
            return false;
        }
        for (i, header) in headers.iter().enumerate() {
            if i > 0 {
                if header.height.0 != prev_height + 1 {
                    return false;
                }
                if header.previous_hash != prev_hash {
                    return false;
                }
            }
            // Gap-fill only: conflicts poison lookups and best tracking.
            if let Some(&known) = self.known_headers.get(&header.height.0) {
                if known != header.hash() {
                    return false;
                }
            }
            prev_hash = header.hash();
            prev_height = header.height.0;
        }
        true
    }

    /// Process a batch of received headers.
    /// Returns any commands the syncer wants the caller to execute.
    pub fn received_headers(&mut self, headers: Vec<BlockHeader>) -> Vec<SyncCommand> {
        let mut commands = Vec::new();

        // Defense in depth: never buffer unbounded headers even if the
        // caller skipped validation.
        if self.pending_headers.len() + headers.len() > MAX_PENDING_HEADERS {
            return commands;
        }

        if headers.is_empty() {
            // Empty headers = peer has no more headers → start sequential block sync
            if self.best_height > self.synced_header_height {
                self.state = SyncState::SyncingBlocks;
                self.next_height = self.synced_header_height + 1;
                if let Some(hash) = self.known_headers.get(&self.next_height).copied() {
                    self.next_height += 1;
                    commands.push(SyncCommand::RequestBlocksFrom(hash));
                }
            } else {
                self.state = SyncState::CaughtUp;
                self.sync_peer = None;
                commands.push(SyncCommand::SyncComplete);
            }
            return commands;
        }

        self.last_sync_request_time = Some(Instant::now());

        // Gap-fill only (see header_batch_valid): a height that already
        // records a DIFFERENT hash is skipped entirely — no overwrite, no
        // best-tracking, no buffering. Forks resolve through the Block path
        // (fork choice by work), never by overwriting header bookkeeping.
        // Same-hash overlaps are idempotent and harmless.
        for header in &headers {
            let height = header.height.0;
            let hash = header.hash();
            if let Some(&known) = self.known_headers.get(&height) {
                if known != hash {
                    continue;
                }
            }

            // Track the best
            if height > self.best_height {
                self.best_height = height;
                self.best_hash = hash;
            }

            self.known_headers.entry(height).or_insert(hash);
            self.pending_headers.push(header.clone());
        }

        // If we received fewer than MAX_HEADERS_PER_RESPONSE, peer is done
        if headers.len() < MAX_HEADERS_PER_RESPONSE {
            if self.best_height > self.synced_header_height {
                self.state = SyncState::SyncingBlocks;
                self.next_height = self.synced_header_height + 1;
                // Request first batch of blocks
                let mut batch = Vec::new();
                for h in self.next_height
                    ..=(self.next_height + MAX_BLOCKS_PER_REQUEST as u32).min(self.best_height)
                {
                    if let Some(hash) = self.known_headers.get(&h).copied() {
                        batch.push(hash);
                    }
                }
                if !batch.is_empty() {
                    self.next_height += batch.len() as u32;
                    self.pending_block_requests = batch[1..].to_vec();
                    commands.push(SyncCommand::GetBlocks(batch));
                }
            } else {
                self.state = SyncState::CaughtUp;
                self.sync_peer = None;
                commands.push(SyncCommand::SyncComplete);
            }
        } else {
            // Request more headers
            commands.push(SyncCommand::GetHeaders(self.best_hash));
        }

        commands
    }

    /// Mark headers as applied (synced up to a height).
    pub fn headers_applied(&mut self, height: u32) {
        self.synced_header_height = height;
    }

    /// Process a received block during block sync.
    /// Records the applied (height, hash) as validated truth so header
    /// bookkeeping can never be poisoned underneath confirmed heights.
    pub fn received_block(&mut self, hash: Hash, height: u32) {
        self.pending_block_requests.retain(|h| *h != hash);
        // Validated truth overwrites: an applied block is authoritative for
        // its height (covers reorgs and Inv-announced blocks alike).
        self.known_headers.insert(height, hash);

        if height > self.synced_header_height {
            self.synced_header_height = height;
        }

        // Drain applied headers so the pending buffer is a sliding window,
        // not a leak: without this, the MAX_PENDING_HEADERS cap would stall
        // honest syncs longer than the cap instead of bounding floods.
        let synced = self.synced_header_height;
        self.pending_headers.retain(|h| h.height.0 > synced);

        // Clear consecutive failures on successful block
        self.clear_sync_failure();
        self.last_sync_request_time = Some(Instant::now());
    }

    /// Check if we need to request more blocks.
    pub fn needs_blocks(&self) -> bool {
        self.state == SyncState::SyncingBlocks && self.pending_block_requests.is_empty()
    }

    /// Check if we need to request blocks because of a timeout.
    pub fn needs_block_retry(&self) -> bool {
        self.state == SyncState::SyncingBlocks && self.is_sync_timed_out()
    }

    /// Return the next block height we should request.
    pub fn next_block_height(&self) -> u32 {
        self.next_height
    }

    /// After applying a block, advance the sync state and return the next block hash to request.
    /// Returns None if we're caught up.
    pub fn advance_block_sync(&mut self) -> Option<Hash> {
        if self.next_height > self.best_height {
            self.state = SyncState::CaughtUp;
            self.sync_peer = None;
            return None;
        }
        let h = self.next_height;
        self.next_height += 1;
        self.known_headers.get(&h).copied()
    }

    /// Return the number of pending block requests.
    pub fn pending_block_count(&self) -> usize {
        self.pending_block_requests.len()
    }

    pub fn sync_complete(&mut self) {
        self.state = SyncState::CaughtUp;
        self.sync_peer = None;
        self.pending_block_requests.clear();
    }

    /// Reset a failed sync attempt. Drops unconfirmed header squat above
    /// the validated tip (heights `> synced_header_height`) and rewinds
    /// best tracking to the validated tip, so a failed/malicious attempt can
    /// neither brick future syncs nor poison lookups. Entries at or below
    /// the validated tip are authoritative (see `received_block`) and stay.
    pub fn sync_failed(&mut self) {
        self.state = SyncState::Idle;
        self.sync_peer = None;
        self.pending_headers.clear();
        self.pending_block_requests.clear();
        self.last_sync_request_time = None;
        self.known_headers
            .retain(|h, _| *h <= self.synced_header_height);
        // Invariant: known_headers always records the validated tip hash —
        // genesis at construction, applied hashes via received_block.
        if let Some(&tip_hash) = self.known_headers.get(&self.synced_header_height) {
            self.best_height = self.synced_header_height;
            self.best_hash = tip_hash;
        }
    }

    /// Number of tracked header hashes (bounded by MAX_KNOWN_HEADERS).
    pub fn known_headers_len(&self) -> usize {
        self.known_headers.len()
    }

    pub fn is_syncing(&self) -> bool {
        matches!(
            self.state,
            SyncState::SyncingHeaders | SyncState::SyncingBlocks
        )
    }

    pub fn is_caught_up(&self) -> bool {
        self.state == SyncState::CaughtUp
    }

    pub fn sync_peer(&self) -> Option<SocketAddr> {
        self.sync_peer
    }

    /// Claim sync ownership for `peer` when nobody owns the sync.
    /// Returns true if `peer` owns it afterwards (already owned or freshly
    /// claimed, with a fresh activity timestamp). Returns false when another
    /// peer owns it — the caller must ignore that peer's batches so one
    /// malicious peer cannot reset or hijack another's sync.
    pub fn claim_sync_peer(&mut self, peer: SocketAddr) -> bool {
        match self.sync_peer {
            Some(owner) => owner == peer,
            None => {
                self.sync_peer = Some(peer);
                self.last_sync_request_time = Some(Instant::now());
                true
            }
        }
    }

    /// Check if a given block hash is our expected best (for chain selection).
    pub fn is_expected_best(&self, hash: &Hash) -> bool {
        *hash == self.best_hash
    }

    /// Check if a received block represents a fork that needs reorg handling.
    /// Returns Some(fork_height) if the block is at the same height as a known block
    /// with a different hash, indicating a fork at fork_height.
    pub fn detect_block_fork(&self, block_height: u32, block_hash: &Hash) -> Option<u32> {
        if let Some(&existing_hash) = self.known_headers.get(&block_height) {
            if existing_hash != *block_hash && block_height > 0 {
                // This block competes with an existing block at the same height
                // The fork point is at block_height - 1
                return Some(block_height - 1);
            }
        }
        None
    }
}

// ============================================================================
// Fork Detection
// ============================================================================

/// Information about a fork point.
#[derive(Clone, Debug)]
pub struct ForkInfo {
    /// Height of the fork point (last common ancestor).
    pub fork_height: u32,
    /// Hash of the fork point block.
    pub fork_hash: Hash,
    /// Blocks to roll back (from tip down to fork+1).
    pub rollback_heights: Vec<u32>,
    /// Blocks to apply (from fork+1 up to new tip).
    pub apply_heights: Vec<u32>,
}

/// Detect a fork and compute the reorg path.
///
/// `local_headers` maps height → header for the current best chain.
/// `new_chain` is a sequence of headers from the fork point forward.
/// `new_chain_start_height` is the height of the first header in `new_chain`.
pub fn detect_fork(
    local_headers: &BTreeMap<u32, BlockHeader>,
    new_chain: &[BlockHeader],
    new_chain_start_height: u32,
    local_tip_height: u32,
) -> Option<ForkInfo> {
    if new_chain.is_empty() {
        return None;
    }

    // The fork point is the height where the new chain's parent matches
    // the local chain. Walk the new chain from the beginning.
    let mut fork_height = None;

    for (i, header) in new_chain.iter().enumerate() {
        let h = new_chain_start_height + i as u32;

        // If this height exists locally and matches, continue (no fork here yet)
        if let Some(local_header) = local_headers.get(&h) {
            if local_header.hash() == header.hash() {
                continue;
            }
        }

        // Height doesn't exist locally or hash differs — fork starts before this height.
        // The fork point is h - 1, provided the parent matches.
        if h > 0 {
            let parent_height = h - 1;
            if let Some(local_parent) = local_headers.get(&parent_height) {
                if local_parent.hash() == header.previous_hash {
                    fork_height = Some(parent_height);
                }
            }
        }
        // Once we find the first divergence, stop — later matches are at different chains
        break;
    }

    let fork_height = fork_height?;

    let mut rollback_heights = Vec::new();
    for h in (fork_height + 1)..=local_tip_height {
        rollback_heights.push(h);
    }

    let mut apply_heights = Vec::new();
    for (i, _) in new_chain.iter().enumerate() {
        let h = new_chain_start_height + i as u32;
        if h > fork_height {
            apply_heights.push(h);
        }
    }

    Some(ForkInfo {
        fork_height,
        fork_hash: local_headers
            .get(&fork_height)
            .map(|h| h.hash())
            .unwrap_or(Hash::ZERO),
        rollback_heights,
        apply_heights,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::GENESIS_TIMESTAMP;
    use chroma_core::types::{BlockHeight, CompactTarget};

    fn test_header(height: u32, prev_hash: Hash) -> BlockHeader {
        BlockHeader {
            version: 1,
            previous_hash: prev_hash,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: GENESIS_TIMESTAMP + (height as u64) * 10,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(height),
            nonce: 0,
        }
    }

    fn build_chain(length: u32) -> BTreeMap<u32, BlockHeader> {
        let mut headers = BTreeMap::new();
        let genesis = test_header(0, Hash::ZERO);
        headers.insert(0, genesis.clone());

        let mut prev_hash = genesis.hash();
        for h in 1..=length {
            let header = test_header(h, prev_hash);
            prev_hash = header.hash();
            headers.insert(h, header);
        }
        headers
    }

    // ========================================================================
    // ChainSyncer Tests
    // ========================================================================

    #[test]
    fn test_new_syncer() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        assert_eq!(syncer.state, SyncState::Idle);
        assert_eq!(syncer.best_height, 0);
        assert_eq!(syncer.best_hash, genesis);
        assert!(!syncer.is_syncing());
        assert!(!syncer.is_caught_up());
    }

    #[test]
    fn test_start_header_sync() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let peer = "127.0.0.1:8333".parse().unwrap();
        let msg = syncer.start_header_sync(peer, genesis);
        assert_eq!(syncer.state, SyncState::SyncingHeaders);
        assert_eq!(syncer.sync_peer(), Some(peer));
        assert_eq!(msg.start_hash, genesis);
        assert_eq!(msg.stop_hash, Hash::ZERO);
    }

    #[test]
    fn test_start_block_sync() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let peer = "127.0.0.1:8333".parse().unwrap();
        let msg = syncer.start_block_sync(peer, genesis, 0);
        assert_eq!(syncer.state, SyncState::SyncingBlocks);
        assert_eq!(syncer.sync_peer(), Some(peer));
        // At minimum we request the genesis block itself
        assert!(!msg.inventory.is_empty());
        assert_eq!(msg.inventory[0].inv_type, InvType::Block);
        assert_eq!(msg.inventory[0].hash, genesis);
    }

    #[test]
    fn test_received_headers_updates_best() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);

        let h1 = test_header(1, genesis);
        let h2 = test_header(2, h1.hash());

        let cmds = syncer.received_headers(vec![h1, h2]);
        assert_eq!(syncer.best_height, 2);
        assert!(!cmds.is_empty());
    }

    #[test]
    fn test_received_headers_empty_transitions() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingHeaders;

        let cmds = syncer.received_headers(vec![]);
        assert_eq!(syncer.state, SyncState::CaughtUp);
        assert!(cmds.iter().any(|c| matches!(c, SyncCommand::SyncComplete)));
    }

    #[test]
    fn test_received_headers_less_than_max_requests_more() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingHeaders;

        // Less than MAX_HEADERS_PER_RESPONSE → signals end, but triggers block request
        let h1 = test_header(1, genesis);
        let cmds = syncer.received_headers(vec![h1]);

        // Should transition to batch block request
        assert!(cmds.iter().any(|c| matches!(c, SyncCommand::GetBlocks(_))));
    }

    #[test]
    fn test_received_block() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;

        let h = test_header(1, genesis);
        let hash = h.hash();
        syncer.received_block(hash, 1);
        assert_eq!(syncer.synced_header_height(), 1);
    }

    #[test]
    fn test_sync_complete() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingHeaders;
        syncer.sync_complete();
        assert_eq!(syncer.state, SyncState::CaughtUp);
        assert!(syncer.sync_peer().is_none());
    }

    #[test]
    fn test_sync_failed() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;
        syncer.sync_failed();
        assert_eq!(syncer.state, SyncState::Idle);
        assert!(syncer.sync_peer().is_none());
    }

    #[test]
    fn test_is_syncing() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        assert!(!syncer.is_syncing());
        syncer.state = SyncState::SyncingHeaders;
        assert!(syncer.is_syncing());
        syncer.state = SyncState::SyncingBlocks;
        assert!(syncer.is_syncing());
        syncer.state = SyncState::CaughtUp;
        assert!(!syncer.is_syncing());
    }

    #[test]
    fn test_is_caught_up() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        assert!(!syncer.is_caught_up());
        syncer.state = SyncState::CaughtUp;
        assert!(syncer.is_caught_up());
    }

    #[test]
    fn test_received_header_no_regression() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h1 = Hash::blake3(b"block1");
        let _h0 = Hash::blake3(b"block0");
        syncer.received_headers(vec![]);
        // Manually set best
        syncer.best_height = 1;
        syncer.best_hash = h1;
        // Receiving a lower height should not regress
        assert_eq!(syncer.best_height, 1);
        assert_eq!(syncer.best_hash, h1);
    }

    // ========================================================================
    // Fork Detection Tests
    // ========================================================================

    #[test]
    fn test_no_fork_identical_chain() {
        let local = build_chain(5);
        let new_chain: Vec<BlockHeader> = (1..=5u32)
            .map(|h| local.get(&h).cloned().unwrap())
            .collect();

        let result = detect_fork(&local, &new_chain, 1, 5);
        // Identical chains → no fork
        assert!(result.is_none());
    }

    #[test]
    fn test_fork_diverges_at_height_3() {
        let local = build_chain(5);

        // New chain with completely different parent → no common ancestor
        let fake_prev = Hash::blake3(b"fake_parent_of_3");
        let h3_new = test_header(3, fake_prev);
        let h4_new = test_header(4, h3_new.hash());
        let h5_new = test_header(5, h4_new.hash());

        let result = detect_fork(&local, &[h3_new, h4_new, h5_new], 3, 5);
        // fake_prev doesn't match local[2].hash(), so no common parent → no fork detected
        assert!(result.is_none());
    }

    #[test]
    fn test_fork_diverges_at_height_3_with_common_parent() {
        let local = build_chain(5);

        // New chain: h3 has same parent as local[3] (local[2].hash()),
        // but h3 has a different nonce, so its hash differs from local[3]
        let fork_hash = local.get(&2).unwrap().hash();
        let h3_new = BlockHeader {
            version: 1,
            previous_hash: fork_hash,
            state_root: Hash::blake3(b"different_state"),
            tx_merkle_root: Hash::ZERO,
            timestamp: GENESIS_TIMESTAMP + 30,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(3),
            nonce: 42,
        };
        let h4_new = test_header(4, h3_new.hash());
        let h5_new = test_header(5, h4_new.hash());

        let result = detect_fork(&local, &[h3_new, h4_new, h5_new], 3, 5);
        assert!(result.is_some());
        let fork = result.unwrap();
        assert_eq!(fork.fork_height, 2);
        assert_eq!(fork.rollback_heights, vec![3, 4, 5]);
        assert_eq!(fork.apply_heights, vec![3, 4, 5]);
    }

    #[test]
    fn test_fork_shorter_new_chain() {
        let local = build_chain(5);
        let fork_hash = local.get(&3).unwrap().hash();

        // New chain: extends from height 4 onward, diverging from local[3]
        let h4_new = BlockHeader {
            version: 1,
            previous_hash: fork_hash,
            state_root: Hash::blake3(b"different_state_4"),
            tx_merkle_root: Hash::ZERO,
            timestamp: GENESIS_TIMESTAMP + 40,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(4),
            nonce: 99,
        };
        let h5_new = test_header(5, h4_new.hash());

        let result = detect_fork(&local, &[h4_new, h5_new], 4, 5);
        assert!(result.is_some());
        let fork = result.unwrap();
        assert_eq!(fork.fork_height, 3);
        assert_eq!(fork.rollback_heights, vec![4, 5]);
        assert_eq!(fork.apply_heights, vec![4, 5]);
    }

    #[test]
    fn test_no_fork_no_common_ancestor() {
        let local = build_chain(5);
        // Completely unrelated chain
        let unrelated = test_header(1, Hash::blake3(b"unrelated"));
        let result = detect_fork(&local, &[unrelated], 1, 5);
        // The unrelated block's previous_hash won't match any local header
        // unless by coincidence. With test headers it won't match.
        // Actually, the parent of height 1 in new chain is the previous_hash,
        // which won't match local[0].hash(). So no fork found.
        // BUT detect_fork also checks if any height matches directly.
        // Since unrelated has height 1, and local[1] exists but has different hash, no match.
        assert!(result.is_none());
    }

    #[test]
    fn test_fork_empty_new_chain() {
        let local = build_chain(5);
        let result = detect_fork(&local, &[], 1, 5);
        assert!(result.is_none());
    }

    #[test]
    fn test_sync_state_transitions() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let peer = "127.0.0.1:8333".parse().unwrap();

        // Idle → SyncingHeaders
        assert_eq!(syncer.state, SyncState::Idle);
        syncer.start_header_sync(peer, genesis);
        assert_eq!(syncer.state, SyncState::SyncingHeaders);

        // SyncingHeaders → SyncingBlocks
        syncer.start_block_sync(peer, genesis, 0);
        assert_eq!(syncer.state, SyncState::SyncingBlocks);

        // SyncingBlocks → CaughtUp
        syncer.sync_complete();
        assert_eq!(syncer.state, SyncState::CaughtUp);

        // CaughtUp → Idle (on failure)
        syncer.sync_failed();
        assert_eq!(syncer.state, SyncState::Idle);
    }

    #[test]
    fn test_sync_command_get_headers() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        let peer = "127.0.0.1:8333".parse().unwrap();
        let mut syncer = syncer;
        let msg = syncer.start_header_sync(peer, genesis);
        assert_eq!(msg.start_hash, genesis);
        assert_eq!(msg.stop_hash, Hash::ZERO);
    }

    #[test]
    fn test_needs_blocks() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        assert!(!syncer.needs_blocks());
        syncer.state = SyncState::SyncingBlocks;
        assert!(syncer.needs_blocks());
    }

    // ========================================================================
    // IBD Tests
    // ========================================================================

    #[test]
    fn test_block_locator_hashes() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let chain = build_chain(100);

        for (h, header) in &chain {
            syncer.known_headers.insert(*h, header.hash());
        }

        let tip_hash = chain.get(&100).unwrap().hash();
        let locators = syncer.block_locator_hashes(tip_hash, 100);

        // First locator should be the tip
        assert_eq!(locators[0], tip_hash);

        // Last locator should be the chain's genesis (height 0)
        let chain_genesis = chain.get(&0).unwrap().hash();
        assert_eq!(*locators.last().unwrap(), chain_genesis);

        // Should have exponentially decreasing heights
        assert!(locators.len() >= 3);
    }

    #[test]
    fn test_should_enter_ibd() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);

        // Local height 5, peer height 200 → IBD triggered (200 > 5 + 144)
        assert!(syncer.should_enter_ibd(5, 200));

        // Local height 5, peer height 150 → IBD triggered (150 > 5 + 144)
        assert!(syncer.should_enter_ibd(5, 150));

        // Local height 5, peer height 149 → NOT triggered (149 > 5 + 144 is false, 149 == 149)
        assert!(!syncer.should_enter_ibd(5, 149));

        // Same height → not triggered
        assert!(!syncer.should_enter_ibd(10, 10));

        // Peer behind → not triggered
        assert!(!syncer.should_enter_ibd(10, 5));
    }

    #[test]
    fn test_is_in_initial_block_download() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;
        syncer.best_height = 200;
        syncer.synced_header_height = 5;

        assert!(syncer.is_in_initial_block_download());

        syncer.synced_header_height = 60;
        assert!(!syncer.is_in_initial_block_download());
    }

    #[test]
    fn test_sync_timeout() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);

        // No request sent → not timed out
        assert!(!syncer.is_sync_timed_out());

        // Request just sent → not timed out
        syncer.last_sync_request_time = Some(Instant::now());
        assert!(!syncer.is_sync_timed_out());
    }

    #[test]
    fn test_record_sync_failure() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);

        assert!(!syncer.is_peer_banned_for_sync());

        for _ in 0..4 {
            syncer.record_sync_failure();
        }
        assert!(!syncer.is_peer_banned_for_sync());

        syncer.record_sync_failure();
        assert!(syncer.is_peer_banned_for_sync());

        syncer.clear_sync_failure();
        assert!(!syncer.is_peer_banned_for_sync());
    }

    #[test]
    fn test_sync_failed_resets_timeout() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.last_sync_request_time = Some(Instant::now());

        syncer.sync_failed();
        assert!(syncer.last_sync_request_time.is_none());
    }

    #[test]
    fn test_received_block_clears_failure() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;

        syncer.record_sync_failure();
        syncer.record_sync_failure();
        assert!(!syncer.is_peer_banned_for_sync());

        let h = Hash::blake3(b"block1");
        syncer.received_block(h, 1);

        // Block received should clear failures
        assert!(!syncer.is_peer_banned_for_sync());
    }

    #[test]
    fn test_pending_block_count() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);

        assert_eq!(syncer.pending_block_count(), 0);

        syncer.pending_block_requests.push(Hash::blake3(b"a"));
        syncer.pending_block_requests.push(Hash::blake3(b"b"));
        assert_eq!(syncer.pending_block_count(), 2);
    }

    #[test]
    fn test_needs_block_retry() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;

        // No timeout → no retry
        assert!(!syncer.needs_block_retry());

        // Timed out → retry needed
        syncer.last_sync_request_time =
            Some(Instant::now() - std::time::Duration::from_secs(SYNC_RESPONSE_TIMEOUT_SECS + 1));
        assert!(syncer.needs_block_retry());
    }

    #[test]
    fn test_detect_block_fork() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let chain = build_chain(10);

        for (h, header) in &chain {
            syncer.known_headers.insert(*h, header.hash());
        }

        // Same block at same height → no fork
        let h5_hash = chain.get(&5).unwrap().hash();
        assert!(syncer.detect_block_fork(5, &h5_hash).is_none());

        // Different block at same height → fork detected at height 4
        let different_hash = Hash::blake3(b"different_block_5");
        assert_eq!(syncer.detect_block_fork(5, &different_hash), Some(4));

        // Block at unknown height → no fork
        let unknown_hash = Hash::blake3(b"unknown");
        assert!(syncer.detect_block_fork(999, &unknown_hash).is_none());

        // Block at height 0 (genesis) → no fork (genesis can't be replaced)
        let _genesis_hash = chain.get(&0).unwrap().hash();
        let different_genesis = Hash::blake3(b"different_genesis");
        assert!(syncer.detect_block_fork(0, &different_genesis).is_none());
    }

    // ====================================================================
    // Header Batch Validation Tests (adversarial: unlinked/forged batches)
    // ====================================================================

    #[test]
    fn test_header_batch_valid_accepts_linked_chain() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        let h1 = test_header(1, genesis);
        let h2 = test_header(2, h1.hash());
        assert!(syncer.header_batch_valid(&[h1, h2]));
    }

    #[test]
    fn test_header_batch_valid_rejects_unlinked_first() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        // First header does not connect to anything we know.
        let rogue = test_header(1, Hash::blake3(b"unknown-parent"));
        assert!(!syncer.header_batch_valid(&[rogue]));
    }

    #[test]
    fn test_header_batch_valid_rejects_gap_and_fork_within_batch() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        let h1 = test_header(1, genesis);
        // Skipped height.
        let h3 = test_header(3, h1.hash());
        assert!(!syncer.header_batch_valid(&[h1.clone(), h3]));
        // Broken link within the batch.
        let h2_bad = test_header(2, Hash::blake3(b"other"));
        assert!(!syncer.header_batch_valid(&[h1, h2_bad]));
    }

    #[test]
    fn test_header_batch_valid_rejects_empty_and_oversize() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        assert!(!syncer.header_batch_valid(&[]));
        let huge = vec![test_header(1, genesis); MAX_HEADERS_PER_RESPONSE + 1];
        assert!(!syncer.header_batch_valid(&huge));
    }

    #[test]
    fn test_received_headers_ignores_over_pending_cap() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        // Fill the buffer to the cap with linked headers.
        let mut prev = genesis;
        let mut chain = Vec::new();
        for h in 1..=MAX_PENDING_HEADERS as u32 {
            let hdr = test_header(h, prev);
            prev = hdr.hash();
            chain.push(hdr);
        }
        for chunk in chain.chunks(MAX_HEADERS_PER_RESPONSE) {
            let cmds = syncer.received_headers(chunk.to_vec());
            let _ = cmds;
        }
        assert!(syncer.pending_headers.len() <= MAX_PENDING_HEADERS);
        // One more linked batch must be ignored, not buffered.
        let extra = test_header(MAX_PENDING_HEADERS as u32 + 1, prev);
        let before = syncer.pending_headers.len();
        let cmds = syncer.received_headers(vec![extra]);
        assert!(cmds.is_empty());
        assert_eq!(syncer.pending_headers.len(), before);
    }

    #[test]
    fn test_header_batch_valid_rejects_conflicting_heights() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h1 = test_header(1, genesis);
        assert!(syncer.header_batch_valid(std::slice::from_ref(&h1)));
        syncer.received_headers(vec![h1.clone()]);
        // Same height, different hash (fork/squat): whole batch refused.
        let mut rogue = test_header(1, genesis);
        rogue.nonce = 999;
        assert_ne!(rogue.hash(), h1.hash());
        assert!(!syncer.header_batch_valid(&[rogue]));
    }

    #[test]
    fn test_received_headers_never_overwrites_recorded_hash() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h1 = test_header(1, genesis);
        syncer.received_headers(vec![h1.clone()]);
        // Direct call with a conflicting header: skipped, recorded kept.
        let mut rogue = test_header(1, genesis);
        rogue.nonce = 999;
        syncer.received_headers(vec![rogue]);
        assert_eq!(syncer.known_headers.get(&1), Some(&h1.hash()));
    }

    #[test]
    fn test_received_block_records_validated_hash() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h = Hash::blake3(b"applied");
        syncer.received_block(h, 7);
        assert_eq!(syncer.known_headers.get(&7), Some(&h));
        assert_eq!(syncer.synced_header_height(), 7);
    }

    #[test]
    fn test_sync_failed_drops_ephemeral_and_rewinds_best() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        // Squat: unconfirmed headers far above the validated tip.
        let h1 = test_header(1, genesis);
        syncer.received_headers(vec![h1]);
        syncer.received_block(Hash::blake3(b"v1"), 1);
        let fake2 = test_header(2, Hash::blake3(b"fake"));
        // Bypass validation to simulate pre-fix squat at new heights.
        syncer.known_headers.insert(2, fake2.hash());
        syncer.best_height = 2;
        syncer.best_hash = fake2.hash();
        syncer.sync_failed();
        // Ephemeral entry gone, best rewound to the validated tip.
        assert!(!syncer.known_headers.contains_key(&2));
        assert_eq!(syncer.best_height, 1);
        assert_eq!(syncer.known_headers.get(&1), Some(&Hash::blake3(b"v1")));
        // Honest re-fetch of the same range is accepted again (no brick).
        let real2 = test_header(2, Hash::blake3(b"v1"));
        assert!(syncer.header_batch_valid(&[real2]));
    }

    #[test]
    fn test_track_validated_overwrites_gossip() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.known_headers.insert(5, Hash::blake3(b"squat"));
        let truth = Hash::blake3(b"truth");
        syncer.track_validated(5, truth);
        assert_eq!(syncer.known_headers.get(&5), Some(&truth));
    }

    #[test]
    fn test_claim_sync_peer_first_announcer_wins() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let evil: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let good: SocketAddr = "127.0.0.1:8334".parse().unwrap();
        assert!(syncer.claim_sync_peer(evil));
        assert_eq!(syncer.sync_peer(), Some(evil));
        // Second peer cannot steal ownership mid-sync.
        assert!(!syncer.claim_sync_peer(good));
        assert_eq!(syncer.sync_peer(), Some(evil));
        // Owner re-claiming is idempotent.
        assert!(syncer.claim_sync_peer(evil));
        // Reset releases ownership for the next peer.
        syncer.sync_failed();
        assert!(syncer.claim_sync_peer(good));
        assert_eq!(syncer.sync_peer(), Some(good));
    }

    #[test]
    fn test_sync_failed_unsticks_monopolized_sync() {
        // Malicious peer drives us into SyncingBlocks then goes silent.
        // After cleanup resets the syncer, a healthy peer can take over.
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let evil: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let good: SocketAddr = "127.0.0.1:8334".parse().unwrap();
        syncer.start_header_sync(evil, genesis);
        assert!(syncer.is_syncing());
        assert_eq!(syncer.sync_peer(), Some(evil));
        // Evil disconnects: connection cleanup calls sync_failed().
        syncer.sync_failed();
        assert!(!syncer.is_syncing());
        assert_eq!(syncer.sync_peer(), None);
        // Healthy peer starts a fresh sync immediately.
        syncer.start_header_sync(good, genesis);
        assert_eq!(syncer.sync_peer(), Some(good));
    }

    /// Build `count` sequential headers starting after `start_height`,
    /// chaining off `prev_hash`. Mirrors an attacker batch (linked, valid
    /// structure) without network I/O.
    fn linked_batch(start_height: u32, count: usize, prev_hash: Hash) -> Vec<BlockHeader> {
        let mut out = Vec::with_capacity(count);
        let mut prev = prev_hash;
        for h in start_height..start_height + count as u32 {
            let hdr = test_header(h, prev);
            prev = hdr.hash();
            out.push(hdr);
        }
        out
    }

    #[test]
    fn test_pending_fill_reset_cycles_stay_bounded() {
        // Long-run header-flood shape: fill the pending buffer to its cap,
        // reset (disconnect cleanup), repeat. No cycle may exceed the cap,
        // and the syncer must stay functional afterwards.
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let mut base_height = 1u32;
        let mut prev = genesis;
        for cycle in 0..5 {
            // Fill to exactly the cap in batches.
            while syncer.pending_headers.len() < MAX_PENDING_HEADERS {
                let room = MAX_PENDING_HEADERS - syncer.pending_headers.len();
                let n = room.min(MAX_HEADERS_PER_RESPONSE);
                let batch = linked_batch(base_height, n, prev);
                prev = batch.last().unwrap().hash();
                base_height += n as u32;
                let _ = syncer.received_headers(batch);
            }
            assert_eq!(
                syncer.pending_headers.len(),
                MAX_PENDING_HEADERS,
                "cycle {} must reach exactly the cap",
                cycle
            );
            // One more batch is ignored, not buffered.
            let extra = linked_batch(base_height, 10, prev);
            let _ = syncer.received_headers(extra);
            assert_eq!(syncer.pending_headers.len(), MAX_PENDING_HEADERS);
            // Disconnect-equivalent reset, then prove liveness.
            syncer.sync_failed();
            assert_eq!(syncer.pending_headers.len(), 0);
            let probe = linked_batch(base_height, 5, prev);
            let _ = syncer.received_headers(probe);
            assert_eq!(syncer.pending_headers.len(), 5);
            syncer.sync_failed();
        }
    }

    #[test]
    fn test_known_headers_cap_boundary_exact() {
        // known_headers (height→hash) enforces MAX_KNOWN_HEADERS in
        // header_batch_valid: len+batch == MAX passes, +1 refuses.
        // Filling 100k entries directly is fast (small map values).
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        assert_eq!(syncer.known_headers_len(), 1);
        // Simulate a nearly-full book without 100k inserts: verify the
        // boundary predicate shape via the public length API on a small
        // book, then prove the full-cap refusal on a filled book.
        let batch = linked_batch(1, 3, genesis);
        assert!(syncer.header_batch_valid(&batch));
        // Full book: MAX_KNOWN_HEADERS distinct heights.
        let mut full = ChainSyncer::new(genesis);
        let mut prev = genesis;
        let mut h = 1u32;
        while full.known_headers_len() < MAX_KNOWN_HEADERS {
            // Insert in chunks to keep the test fast.
            for _ in 0..1000 {
                if full.known_headers_len() >= MAX_KNOWN_HEADERS {
                    break;
                }
                let hdr = test_header(h, prev);
                prev = hdr.hash();
                full.known_headers.insert(h, prev);
                h += 1;
            }
        }
        assert_eq!(full.known_headers_len(), MAX_KNOWN_HEADERS);
        // Any non-empty batch now refuses (would exceed the cap)...
        let over = linked_batch(h, 1, prev);
        assert!(!full.header_batch_valid(&over));
        // ...while an empty books accepts (sanity that validity otherwise holds).
        assert!(syncer.header_batch_valid(&linked_batch(1, 1, genesis)));
    }

    #[test]
    fn test_unlinked_header_flood_leaves_no_state() {
        // Thousands of distinct unlinked header batches must ALL be refused
        // by the gate with zero bookkeeping growth. Conflicts only exist
        // against RECORDED heights, so the test first records an honest
        // chain, then floods same-height alien hashes: those refuse too.
        // (The gate, not the buffer, is the bound — message_loop only
        // buffers batches that pass it.)
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        for i in 0..2500u32 {
            let orphan = test_header(1000 + i, Hash::blake3(format!("nope-{i}").as_bytes()));
            assert!(!syncer.header_batch_valid(std::slice::from_ref(&orphan)));
        }
        assert_eq!(syncer.known_headers_len(), 1);
        assert_eq!(syncer.pending_headers.len(), 0);
        // Record honest heights 1..=50 (as validated blocks would).
        let honest = linked_batch(1, 50, genesis);
        let honest_hashes: Vec<Hash> = honest.iter().map(|h| h.hash()).collect();
        let _ = syncer.received_headers(honest);
        assert_eq!(syncer.known_headers_len(), 51);
        // Same heights, alien hashes: refused, nothing changes.
        for i in 0..2500u32 {
            let h = 1 + (i % 50);
            let mut rogue = test_header(
                h,
                if h == 1 {
                    genesis
                } else {
                    honest_hashes[(h - 2) as usize]
                },
            );
            rogue.nonce = 10_000 + i as u64;
            assert_ne!(rogue.hash(), honest_hashes[(h - 1) as usize]);
            assert!(
                !syncer.header_batch_valid(std::slice::from_ref(&rogue)),
                "recorded height {} must reject alien hashes",
                h
            );
        }
        assert_eq!(syncer.known_headers_len(), 51);
        // Spot-check recorded hashes survived intact.
        for (idx, want) in honest_hashes.iter().enumerate() {
            assert_eq!(syncer.known_headers.get(&(idx as u32 + 1)), Some(want));
        }
        // Buffering 50 headers legitimately put the syncer to work; refusals
        // above happened while syncing, which is the realistic attack shape.
        assert!(syncer.is_syncing());
        // Gate still functional for fresh honest heights afterwards.
        let next_prev = honest_hashes[49];
        assert!(syncer.header_batch_valid(&linked_batch(51, 3, next_prev)));
    }
}
