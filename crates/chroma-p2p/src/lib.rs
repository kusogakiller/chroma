pub mod discovery;
pub mod identity;
pub mod mempool;
pub mod noise_transport;
pub mod peer;
pub mod sync;
pub mod wire;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use chroma_core::hash::Hash;
use chroma_core::{CanonicalDecode, CanonicalEncode};
use chroma_crypto::noise::HandshakeRole;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};

use crate::discovery::Discovery;
use crate::mempool::Mempool;
use crate::peer::{
    PeerManager, PeerState, IDLE_EVICT_SECS, PEER_TIMEOUT_SECS, PING_INTERVAL_SECS,
    SCORE_CONNECT_FAIL, SCORE_INVALID_BLOCK, SCORE_INVALID_TX, SCORE_MALFORMED, SCORE_RATE_LIMIT,
    VERSION_TIMEOUT_SECS,
};
use crate::sync::ChainSyncer;
use crate::wire::{
    GetDataMessage, GetHeadersMessage, InvEntry, InvMessage, InvType, Message, MessageType,
    PingMessage, VersionMessage, HEADER_SIZE, MAGIC,
};
use chroma_core::constants::{REGTEST_MAGIC, TESTNET_MAGIC};

pub const PROTOCOL_VERSION: u32 = 1;
pub const SERVICES: u64 = 0;

// ============================================================================
// Network Configuration
// ============================================================================

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub network_name: String,
    pub magic: [u8; 4],
    pub regtest: bool,
    pub testnet: bool,
}

impl NetworkConfig {
    pub fn mainnet() -> Self {
        NetworkConfig {
            network_name: "mainnet".to_string(),
            magic: MAGIC,
            regtest: false,
            testnet: false,
        }
    }

    pub fn testnet() -> Self {
        NetworkConfig {
            network_name: "testnet".to_string(),
            magic: TESTNET_MAGIC,
            regtest: false,
            testnet: true,
        }
    }

    pub fn regtest() -> Self {
        NetworkConfig {
            network_name: "regtest".to_string(),
            magic: REGTEST_MAGIC,
            regtest: true,
            testnet: false,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum P2pError {
    Io(std::io::Error),
    Protocol(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P2pError::Io(e) => write!(f, "io: {}", e),
            P2pError::Protocol(s) => write!(f, "protocol: {}", s),
        }
    }
}

impl std::error::Error for P2pError {}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> Self {
        P2pError::Io(e)
    }
}

impl From<chroma_core::error::CoreError> for P2pError {
    fn from(e: chroma_core::error::CoreError) -> Self {
        P2pError::Protocol(e.to_string())
    }
}

// ============================================================================
// Configuration
// ============================================================================

pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub connect_addrs: Vec<SocketAddr>,
    pub genesis_hash: Hash,
    pub chain_height: Arc<AtomicU32>,
    pub data_dir: PathBuf,
    pub network: NetworkConfig,
    pub mine: bool,
    pub miner_address: Option<chroma_core::types::Address>,
    pub seed_resolver: Option<discovery::SeedResolver>,
    /// DANGEROUS opt-in: speak plaintext instead of Noise XX on peer
    /// connections. Default false (Noise required). Intended for
    /// test/debug inspection only; mainnet must never enable this
    /// (the CLI refuses `--insecure-plaintext-peers` on mainnet).
    /// With no negotiation step, there is no downgrade oracle: a node is
    /// either Noise-only (drops non-Noise bytes) or plaintext-only.
    pub allow_plaintext_peers: bool,
}

impl NodeConfig {
    pub fn new(listen_addr: SocketAddr, genesis_hash: Hash) -> Self {
        NodeConfig {
            listen_addr,
            connect_addrs: Vec::new(),
            genesis_hash,
            chain_height: Arc::new(AtomicU32::new(0)),
            data_dir: PathBuf::from("chroma_data"),
            network: NetworkConfig::mainnet(),
            mine: true,
            miner_address: None,
            seed_resolver: None,
            allow_plaintext_peers: false,
        }
    }

    /// Explicit opt-in to plaintext peer connections (test/debug only).
    /// Never enable on mainnet.
    pub fn with_plaintext_peers_allowed(mut self) -> Self {
        self.allow_plaintext_peers = true;
        self
    }

    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }

    pub fn with_connect_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.connect_addrs = addrs;
        self
    }

    pub fn with_network(mut self, network: NetworkConfig) -> Self {
        self.network = network;
        self
    }

    pub fn with_mine(mut self, mine: bool) -> Self {
        self.mine = mine;
        self
    }

    pub fn with_miner_address(mut self, addr: chroma_core::types::Address) -> Self {
        self.miner_address = Some(addr);
        self
    }

    pub fn with_seed_resolver(mut self, resolver: discovery::SeedResolver) -> Self {
        self.seed_resolver = Some(resolver);
        self
    }
}

// ============================================================================
// Events
// ============================================================================

/// Propagation observability: per-node counters for the relay audit.
/// Behavior-neutral (lock-free increments on message paths only); lets tests
/// and operators quantify GetData demand, Block-response backpressure drops,
/// and duplicate-vs-Byzantine block rejections without changing any logic.
#[derive(Debug, Default)]
pub struct RelayStats {
    /// GetData inventory entries requested by peers (demand side).
    pub getdata_entries: AtomicU64,
    /// Block responses successfully queued toward peers.
    pub block_served: AtomicU64,
    /// Block responses dropped because the peer's bounded (64) write queue
    /// was full — backpressure, not a bug: the requester re-requests.
    pub block_dropped: AtomicU64,
    /// NotFound responses successfully queued.
    pub notfound_served: AtomicU64,
    /// NotFound responses dropped on a full peer queue.
    pub notfound_dropped: AtomicU64,
    /// Blocks received from peers that applied cleanly to the chain.
    pub blocks_applied: AtomicU64,
    /// Received blocks rejected WITHOUT scoring (fork/competition/stale —
    /// duplicates, already-known, same-height losers, orphans).
    pub blocks_rejected_unscored: AtomicU64,
    /// Received blocks rejected WITH Byzantine scoring (bad PoW/roots/sigs).
    pub blocks_rejected_scored: AtomicU64,
}

/// Point-in-time snapshot of [`RelayStats`] for tests and operators.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelaySnapshot {
    pub getdata_entries: u64,
    pub block_served: u64,
    pub block_dropped: u64,
    pub notfound_served: u64,
    pub notfound_dropped: u64,
    pub blocks_applied: u64,
    pub blocks_rejected_unscored: u64,
    pub blocks_rejected_scored: u64,
}

impl RelayStats {
    /// Lock-free snapshot; counters only increase.
    pub fn snapshot(&self) -> RelaySnapshot {
        RelaySnapshot {
            getdata_entries: self.getdata_entries.load(Ordering::Relaxed),
            block_served: self.block_served.load(Ordering::Relaxed),
            block_dropped: self.block_dropped.load(Ordering::Relaxed),
            notfound_served: self.notfound_served.load(Ordering::Relaxed),
            notfound_dropped: self.notfound_dropped.load(Ordering::Relaxed),
            blocks_applied: self.blocks_applied.load(Ordering::Relaxed),
            blocks_rejected_unscored: self.blocks_rejected_unscored.load(Ordering::Relaxed),
            blocks_rejected_scored: self.blocks_rejected_scored.load(Ordering::Relaxed),
        }
    }

    fn note_sent(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a queued-or-dropped write: exactly one of the pair increments.
    fn note_write(sent: &AtomicU64, dropped: &AtomicU64, queued: bool) {
        if queued {
            Self::note_sent(sent);
        } else {
            Self::note_sent(dropped);
        }
    }
}

pub struct Node {
    config: NodeConfig,
    peer_manager: Arc<RwLock<PeerManager>>,
    mempool: Arc<RwLock<Mempool>>,
    discovery: Discovery,
    storage: Arc<chroma_storage::Storage>,
    chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    syncer: Arc<RwLock<ChainSyncer>>,
    relay_stats: Arc<RelayStats>,
    event_tx: mpsc::UnboundedSender<NodeEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<NodeEvent>>,
    outbound_tx: Option<mpsc::UnboundedSender<OutboundCommand>>,
    outbound_rx: Option<mpsc::UnboundedReceiver<OutboundCommand>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    /// Persistent shutdown flag (see `shutdown()`): broadcast alone misses
    /// receivers that subscribe after the send, so every connection task
    /// spawned after shutdown must observe this flag and exit immediately
    /// instead of becoming Ready and orphaning a live socket.
    shutdown_flag: Arc<AtomicBool>,
    /// Long-term Noise static private key (transport identity only — never
    /// a wallet or consensus key). Loaded or created from the data dir.
    noise_identity: identity::NodeIdentity,
}

#[derive(Clone, Debug)]
pub enum NodeEvent {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BlockReceived(Hash, u32),
    BlockMined(Hash, u32),
    Reorg {
        old_height: u32,
        old_hash: Hash,
        new_height: u32,
        new_hash: Hash,
        depth: u32,
    },
    TxReceived(Hash),
    SyncComplete,
    SyncTimeout(SocketAddr),
    Error(String),
}

enum OutboundCommand {
    Send(SocketAddr, Message),
    Connect(SocketAddr),
    #[allow(dead_code)]
    Disconnect(SocketAddr),
}

// ============================================================================
// Node Implementation
// ============================================================================

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _) = broadcast::channel(1);

        let db_path = config.data_dir.clone();
        let storage =
            chroma_storage::Storage::open(&db_path).expect("failed to open storage database");

        // Long-term transport identity: created once per data-dir, stable
        // across restarts. A corrupt file is fatal — the node must not
        // silently rotate identity (restore from backup instead).
        let noise_identity =
            identity::NodeIdentity::load_or_create(&db_path).expect("failed to load node identity");
        tracing::info!(
            "Node Noise static public key: {}",
            noise_identity.public_hex()
        );

        let chain_state = Self::init_chain_state(&storage, config.genesis_hash, &config.network);

        let height = chain_state.tip.height.0;
        config.chain_height.store(height, Ordering::Relaxed);

        let mut syncer = ChainSyncer::new(config.genesis_hash);
        syncer.set_synced_height(height);
        // Seed validated header hashes so post-restart batches chaining off
        // the local tip pass linkage validation (see header_batch_valid).
        for (h, hdr) in &chain_state.headers {
            syncer.track_validated(*h, hdr.hash());
        }

        let discovery = match config.seed_resolver.as_ref() {
            Some(r) => Discovery::with_resolver(r.clone()),
            None => Discovery::new(),
        };

        Node {
            config,
            peer_manager: Arc::new(RwLock::new(PeerManager::new())),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            discovery,
            storage: Arc::new(storage),
            chain_state: Arc::new(RwLock::new(chain_state)),
            syncer: Arc::new(RwLock::new(syncer)),
            relay_stats: Arc::new(RelayStats::default()),
            event_tx,
            event_rx: Some(event_rx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
            shutdown_tx: Some(shutdown_tx),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            noise_identity,
        }
    }

    /// This node's Noise static public key (hex logged at startup).
    /// Exposed for tests and operator tooling; the private half never leaves
    /// the [`identity::NodeIdentity`].
    pub fn noise_public_key(&self) -> [u8; 32] {
        self.noise_identity.public_key()
    }

    fn init_chain_state(
        storage: &chroma_storage::Storage,
        expected_genesis_hash: Hash,
        network: &NetworkConfig,
    ) -> chroma_consensus::ChainState {
        use chroma_consensus::{ChainState, ChainTip};
        use chroma_core::types::BlockHeight;
        use chroma_core::u256::U256;

        let chain = match storage.get_tip() {
            Ok(Some(persisted_tip)) => {
                let mut headers = BTreeMap::new();
                let mut current_height = 0u32;
                while let Ok(Some(header)) = storage.get_header(current_height) {
                    headers.insert(current_height, header);
                    if current_height == persisted_tip.height {
                        break;
                    }
                    current_height += 1;
                }

                let state = storage
                    .load_state()
                    .unwrap_or_else(|_| chroma_state::State::new());

                let cumulative_work = U256::from_be_bytes(&persisted_tip.cumulative_work);
                let tip_header = headers
                    .get(&persisted_tip.height)
                    .cloned()
                    .unwrap_or_else(|| {
                        // Use network-appropriate genesis as fallback
                        let genesis = if network.regtest {
                            chroma_consensus::build_genesis_for_network(
                                &chroma_consensus::NetworkKind::Regtest,
                            )
                        } else if network.testnet {
                            chroma_consensus::build_genesis_for_network(
                                &chroma_consensus::NetworkKind::Testnet,
                            )
                        } else {
                            chroma_consensus::build_genesis_for_network(
                                &chroma_consensus::NetworkKind::Mainnet,
                            )
                        };
                        genesis.header
                    });

                // Chain-identity + coherence checks (fail closed — never
                // operate on a foreign or torn database):
                // 1. Stored genesis record (chain identity) must match this
                //    network's expectation when present.
                if let Some(stored_genesis) = storage.get_genesis_hash().ok().flatten() {
                    if stored_genesis != expected_genesis_hash {
                        panic!(
                            "FATAL: stored genesis {} does not match {} network genesis {}. \
                             Refusing to open a foreign database (resync into a fresh data directory instead).",
                            stored_genesis.to_hex(),
                            network.network_name,
                            expected_genesis_hash.to_hex()
                        );
                    }
                }
                // 2. Height-0 header must be this network's genesis.
                match headers.get(&0) {
                    Some(h) if h.hash() == expected_genesis_hash => {}
                    _ => {
                        panic!(
                            "FATAL: height-0 header is missing or not the {} genesis hash {}. \
                             Database is torn or foreign; resync into a fresh data directory.",
                            network.network_name,
                            expected_genesis_hash.to_hex()
                        );
                    }
                }
                // 3. The persisted tip height must resolve to stored headers
                //    (a tip record pointing at missing history is torn), and
                //    the tip hash must equal that height's header hash (a
                //    stale/aliased tip record must never become the chain).
                if !headers.contains_key(&persisted_tip.height) {
                    panic!(
                        "FATAL: persisted tip height {} has no stored headers. \
                         Database is torn; resync into a fresh data directory.",
                        persisted_tip.height
                    );
                }
                match headers.get(&persisted_tip.height) {
                    Some(h) if h.hash() == persisted_tip.hash => {}
                    _ => {
                        panic!(
                            "FATAL: persisted tip hash {} does not match stored header at height {}. \
                             Database is torn or aliased; resync into a fresh data directory.",
                            persisted_tip.hash.to_hex(),
                            persisted_tip.height
                        );
                    }
                }

                let tip = ChainTip {
                    height: BlockHeight(persisted_tip.height),
                    hash: persisted_tip.hash,
                    header: tip_header,
                    cumulative_work,
                    supply: persisted_tip.supply,
                };

                // 4. Stored money state must reproduce the tip header's state
                //    root, and balances must sum to the recorded supply.
                //    Otherwise the node would operate (RPC serve, P2P relay,
                //    mine) on silently corrupted funds. Single account scan;
                //    recovery is resync (never auto-repair money state).
                {
                    let recomputed_root = state.compute_state_root();
                    if recomputed_root != tip.header.state_root {
                        panic!(
                            "FATAL: stored state root {} does not match tip header state root {} at height {}. \
                             Database state is corrupted; resync into a fresh data directory.",
                            recomputed_root.to_hex(),
                            tip.header.state_root.to_hex(),
                            tip.height.0
                        );
                    }
                    // Exact u128 sum (no saturating mask): supply conservation.
                    let exact_sum: u128 =
                        state.accounts_iter().map(|(_, a)| a.balance as u128).sum();
                    if exact_sum != tip.supply as u128 {
                        panic!(
                            "FATAL: stored balances sum to {} but tip records supply {} at height {}. \
                             Database state is corrupted; resync into a fresh data directory.",
                            exact_sum, tip.supply, tip.height.0
                        );
                    }
                }

                let mut tips = BTreeMap::new();
                tips.insert(persisted_tip.hash, tip.clone());

                println!(
                    "Loaded chain from storage: height={}, supply={} units",
                    persisted_tip.height, persisted_tip.supply
                );

                ChainState {
                    headers,
                    tip,
                    state,
                    tips,
                    alt_headers: HashMap::new(),
                    network_magic: network.magic,
                }
            }
            _ => {
                let genesis = if network.regtest {
                    chroma_consensus::build_genesis_for_network(
                        &chroma_consensus::NetworkKind::Regtest,
                    )
                } else if network.testnet {
                    chroma_consensus::build_genesis_for_network(
                        &chroma_consensus::NetworkKind::Testnet,
                    )
                } else {
                    chroma_consensus::build_genesis_for_network(
                        &chroma_consensus::NetworkKind::Mainnet,
                    )
                };
                let chain = ChainState::with_genesis_from(&genesis, network.magic);
                let genesis_hash = genesis.hash();

                if expected_genesis_hash != genesis_hash {
                    panic!(
                        "FATAL: genesis hash mismatch — expected {}, computed {}. \
                         This indicates a network configuration error.",
                        expected_genesis_hash.to_hex(),
                        genesis_hash.to_hex()
                    );
                }

                storage.apply_block(&genesis).ok();

                let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
                    &genesis.header.bits.to_full_target(),
                ));
                let tip = chroma_storage::PersistedTip {
                    height: 0,
                    hash: genesis_hash,
                    cumulative_work: genesis_work.to_be_bytes(),
                    supply: 0,
                };
                storage.put_tip(&tip).ok();
                storage.put_genesis_hash(&genesis_hash).ok();
                storage.flush().ok();

                println!("Created genesis block: {}", genesis_hash.to_hex());

                chain
            }
        };

        chain
    }

    pub fn storage_arc(&self) -> Arc<chroma_storage::Storage> {
        self.storage.clone()
    }

    pub fn storage(&self) -> &chroma_storage::Storage {
        &self.storage
    }

    pub fn peer_manager(&self) -> &Arc<RwLock<PeerManager>> {
        &self.peer_manager
    }

    pub fn mempool(&self) -> &Arc<RwLock<Mempool>> {
        &self.mempool
    }

    pub fn chain_state(&self) -> &Arc<RwLock<chroma_consensus::ChainState>> {
        &self.chain_state
    }

    /// Soak/chaos observability (read-only sync-state inspection).
    pub fn syncer(&self) -> &Arc<RwLock<ChainSyncer>> {
        &self.syncer
    }

    /// Propagation observability: relay/backpressure counters snapshot.
    pub fn relay_stats(&self) -> &Arc<RelayStats> {
        &self.relay_stats
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn chain_height(&self) -> u32 {
        self.config.chain_height.load(Ordering::Relaxed)
    }

    pub fn event_rx(&mut self) -> Option<mpsc::UnboundedReceiver<NodeEvent>> {
        self.event_rx.take()
    }

    pub fn shutdown_tx_subscriber(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.as_ref().unwrap().subscribe()
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let peer_mgr = self.peer_manager.clone();
        let mempool = self.mempool.clone();
        let genesis_hash = self.config.genesis_hash;

        // Bootstrap: discovered addresses become outbound dial candidates
        // through the SAME Connect queue as explicit `--connect` peers, so
        // every downstream gate (bans, duplicates, caps, backoff, shutdown,
        // Noise/handshake, scoring) applies unchanged.
        let discovered = self
            .discovery
            .discover_peers(
                peer_mgr.clone(),
                &self.config.connect_addrs,
                &self.config.network,
            )
            .await;
        let mut bootstrap_addrs: Vec<SocketAddr> = Vec::new();
        for a in discovered {
            if !self.config.connect_addrs.contains(&a) && !bootstrap_addrs.contains(&a) {
                bootstrap_addrs.push(a);
            }
        }

        let event_tx = self.event_tx.clone();
        let outbound_rx = self.outbound_rx.take().unwrap();
        let shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        let shutdown_flag = self.shutdown_flag.clone();

        let peer_mgr_out = peer_mgr.clone();
        let event_tx_out = event_tx.clone();
        let chain_height_out = self.config.chain_height.clone();
        let storage_out = self.storage.clone();
        let chain_state_out = self.chain_state.clone();
        let syncer_out = self.syncer.clone();
        let mempool_out = mempool.clone();
        let network_out = self.config.network.clone();
        let noise_key_out = *self.noise_identity.private_bytes();
        let noise_public_out = self.noise_identity.public_key();
        let plaintext_out = self.config.allow_plaintext_peers;
        let shutdown_tx_out = self.shutdown_tx.as_ref().unwrap().clone();
        let relay_out = self.relay_stats.clone();
        let shutdown_flag_out = shutdown_flag.clone();
        tokio::spawn(async move {
            Self::run_outbound(
                peer_mgr_out,
                outbound_rx,
                event_tx_out,
                chain_height_out,
                storage_out,
                chain_state_out,
                syncer_out,
                mempool_out,
                network_out,
                noise_key_out,
                noise_public_out,
                plaintext_out,
                shutdown_tx_out,
                shutdown_rx,
                relay_out,
                shutdown_flag_out,
            )
            .await;
        });

        let outbound_tx_ref = self.outbound_tx.as_ref().unwrap();
        for addr in &self.config.connect_addrs {
            let _ = outbound_tx_ref.send(OutboundCommand::Connect(*addr));
        }
        for addr in &bootstrap_addrs {
            let _ = outbound_tx_ref.send(OutboundCommand::Connect(*addr));
        }

        let peer_mgr_in = peer_mgr.clone();
        let mempool_in = mempool.clone();
        let event_tx_in = event_tx.clone();
        let chain_height_in = self.config.chain_height.clone();
        let storage_in = self.storage.clone();
        let chain_state_in = self.chain_state.clone();
        let syncer_in = self.syncer.clone();
        let network_in = self.config.network.clone();
        let noise_key_in = *self.noise_identity.private_bytes();
        let noise_public_in = self.noise_identity.public_key();
        let plaintext_in = self.config.allow_plaintext_peers;
        let shutdown_tx_in = self.shutdown_tx.as_ref().unwrap().clone();
        let shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        let relay_in = self.relay_stats.clone();
        let shutdown_flag_in = shutdown_flag.clone();
        tokio::spawn(async move {
            Self::run_inbound(
                listener,
                peer_mgr_in,
                mempool_in,
                event_tx_in,
                genesis_hash,
                chain_height_in,
                storage_in,
                chain_state_in,
                syncer_in,
                network_in,
                noise_key_in,
                noise_public_in,
                plaintext_in,
                shutdown_tx_in,
                shutdown_rx,
                relay_in,
                shutdown_flag_in,
            )
            .await;
        });

        let peer_mgr_tick = peer_mgr.clone();
        let outbound_tx_tick = self.outbound_tx.as_ref().unwrap().clone();
        let shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        tokio::spawn(async move {
            Self::run_peer_tick(peer_mgr_tick, outbound_tx_tick, shutdown_rx).await;
        });

        // Bounded reconnect for operator-configured AND discovered bootstrap
        // peers (backoff-gated). Discovered peers redial with the same policy
        // as explicit ones so a dropped seed connection is re-established.
        let peer_mgr_reconnect = peer_mgr.clone();
        let outbound_tx_reconnect = self.outbound_tx.as_ref().unwrap().clone();
        let reconnect_addrs = self.config.connect_addrs.clone();
        let bootstrap_reconnect = bootstrap_addrs.clone();
        let shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        tokio::spawn(async move {
            Self::run_reconnect(
                peer_mgr_reconnect,
                outbound_tx_reconnect,
                reconnect_addrs,
                bootstrap_reconnect,
                shutdown_rx,
            )
            .await;
        });

        if (self.config.network.regtest || self.config.network.testnet) && self.config.mine {
            let mining_storage = self.storage.clone();
            let mining_chain_state = self.chain_state.clone();
            let mining_event_tx = self.event_tx.clone();
            let mining_height = self.config.chain_height.clone();
            let mining_mempool = self.mempool.clone();
            let mining_outbound = self.outbound_tx.as_ref().unwrap().clone();
            let mining_peer_manager = self.peer_manager.clone();
            let mining_miner_address = self.config.miner_address;
            let mining_network = self.config.network.clone();
            let shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
            tokio::spawn(async move {
                Self::run_miner(
                    mining_peer_manager,
                    mining_storage,
                    mining_chain_state,
                    mining_event_tx,
                    mining_height,
                    mining_mempool,
                    mining_outbound,
                    shutdown_rx,
                    mining_miner_address,
                    mining_network,
                )
                .await;
            });
        }

        Ok(())
    }

    // ========================================================================
    // Inbound Listener
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn run_inbound(
        listener: TcpListener,
        peer_manager: Arc<RwLock<PeerManager>>,
        mempool: Arc<RwLock<Mempool>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        _genesis_hash: Hash,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        syncer: Arc<RwLock<ChainSyncer>>,
        network: NetworkConfig,
        noise_key: [u8; 32],
        noise_public: [u8; 32],
        allow_plaintext: bool,
        shutdown_tx: broadcast::Sender<()>,
        mut shutdown_rx: broadcast::Receiver<()>,
        relay_stats: Arc<RelayStats>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, addr) = match accept_result {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    // Admission gate BEFORE spawning any task: total cap,
                    // handshake cap, per-IP cap, bans, duplicates. The slot
                    // is reserved synchronously under the same lock so
                    // concurrent accepts cannot overshoot the caps before
                    // their tasks start (handle_connection re-asserts the
                    // same state idempotently).
                    let admitted = {
                        let mut pm = peer_manager.write().await;
                        if !pm.can_accept_inbound(&addr) {
                            false
                        } else {
                            pm.add_peer(addr);
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.state = PeerState::Connecting;
                                peer.connected_at = Some(std::time::Instant::now());
                            }
                            true
                        }
                    };
                    if !admitted {
                        drop(stream);
                        continue;
                    }
                    // Persistent shutdown gate: an accept that raced with
                    // shutdown must not spawn an orphan that misses the
                    // broadcast and lives forever (see shutdown_flag).
                    if shutdown_flag.load(Ordering::SeqCst) {
                        {
                            let mut pm = peer_manager.write().await;
                            pm.remove_peer(&addr);
                        }
                        drop(stream);
                        continue;
                    }

                    let pm = peer_manager.clone();
                    let et = event_tx.clone();
                    let et2 = event_tx.clone();
                    let ch = chain_height.clone();
                    let st = storage.clone();
                    let cs = chain_state.clone();
                    let sy = syncer.clone();
                    let mp = mempool.clone();
                    let net = network.clone();
                    let sdx = shutdown_tx.clone();
                    let rs = relay_stats.clone();
                    let sflag = shutdown_flag.clone();

                    tokio::spawn(async move {
                        match Self::handle_connection(
                            stream, addr, pm, et, ch, st, cs, sy, mp, false, net,
                            noise_key, noise_public, allow_plaintext, sdx, rs, sflag,
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(e) => {
                                let _ = et2.send(NodeEvent::Error(format!("{}: {}", addr, e)));
                            }
                        }
                    });
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    // ========================================================================
    // Outbound Connection Manager
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn run_outbound(
        peer_manager: Arc<RwLock<PeerManager>>,
        mut outbound_rx: mpsc::UnboundedReceiver<OutboundCommand>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        syncer: Arc<RwLock<ChainSyncer>>,
        mempool: Arc<RwLock<Mempool>>,
        network: NetworkConfig,
        noise_key: [u8; 32],
        noise_public: [u8; 32],
        allow_plaintext: bool,
        shutdown_tx: broadcast::Sender<()>,
        mut shutdown_rx: broadcast::Receiver<()>,
        relay_stats: Arc<RelayStats>,
        shutdown_flag: Arc<AtomicBool>,
    ) {
        loop {
            tokio::select! {
                cmd = outbound_rx.recv() => {
                    match cmd {
                        Some(OutboundCommand::Connect(addr)) => {
                            // Dial gate: bans, per-IP/total caps, duplicate
                            // guard, and reconnect backoff — all before I/O.
                            // No slot reservation here: Connect commands are
                            // rare and operator/looper-driven (not attacker
                            // controlled), and reserving would make the
                            // post-dial duplicate check below
                            // indistinguishable from our own reservation.
                            // Inbound floods are capped by reservation on
                            // the accept path instead.
                            // Persistent shutdown gate first: a queued dial
                            // must not start I/O after shutdown.
                            if shutdown_flag.load(Ordering::SeqCst) {
                                continue;
                            }
                            if !peer_manager.write().await.can_dial(&addr) {
                                continue;
                            }

                            match tokio::time::timeout(
                                std::time::Duration::from_secs(PEER_TIMEOUT_SECS),
                                TcpStream::connect(addr),
                            )
                            .await
                            {
                                Ok(Ok(stream)) => {
                                    // Post-dial gates: shutdown first (an
                                    // orphan spawn here would miss the
                                    // broadcast and live forever), then the
                                    // racing-inbound duplicate check.
                                    if shutdown_flag.load(Ordering::SeqCst) {
                                        drop(stream);
                                        continue;
                                    }
                                    // Re-check under lock: a racing inbound
                                    // connection may have claimed the slot.
                                    if peer_manager.read().await.is_tracked_active(&addr) {
                                        drop(stream);
                                        continue;
                                    }

                                    let pm = peer_manager.clone();
                                    let et = event_tx.clone();
                                    let et2 = event_tx.clone();
                                    let ch = chain_height.clone();
                                    let st = storage.clone();
                                    let cs = chain_state.clone();
                                    let sy = syncer.clone();
                                    let mp = mempool.clone();
                                    let net = network.clone();
                                    let sdx = shutdown_tx.clone();
                                    let rs = relay_stats.clone();
                                    let sflag = shutdown_flag.clone();
                                    tokio::spawn(async move {
                                        match Self::handle_connection(
                                            stream, addr, pm, et, ch, st, cs, sy, mp, true, net,
                                            noise_key, noise_public, allow_plaintext, sdx, rs, sflag,
                                        ).await {
                                            Ok(()) => {}
                                            Err(e) => {
                                                let _ = et2.send(NodeEvent::Error(
                                                    format!("{}: {}", addr, e),
                                                ));
                                            }
                                        }
                                    });
                                }
                                _ => {
                                    // Dial failed or timed out: small score
                                    // cost plus exponential backoff stamp.
                                    // Ordinary network errors must not ban.
                                    peer_manager
                                        .write()
                                        .await
                                        .record_connect_failure(&addr);
                                }
                            }
                        }
                        Some(OutboundCommand::Send(addr, msg)) => {
                            let pm = peer_manager.read().await;
                            let sender = pm.get_channel(&addr).cloned();
                            drop(pm);
                            if let Some(tx) = sender {
                                let mut msg = msg;
                                msg.magic = network.magic;
                                let encoded = msg.encode();
                                if tx.try_send(encoded).is_err() {
                                    let mut pm = peer_manager.write().await;
                                    pm.remove_peer(&addr);
                                }
                            }
                        }
                        Some(OutboundCommand::Disconnect(addr)) => {
                            {
                                let mut pm = peer_manager.write().await;
                                pm.remove_peer(&addr);
                            }
                            let _ = event_tx.send(NodeEvent::PeerDisconnected(addr));
                        }
                        None => break,
                    }
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    // ========================================================================
    // Connection Handler — persistent streams with read/write tasks
    // ========================================================================

    /// Perform the Version/VerAck handshake on an established stream.
    /// Sends our Version, then reads until VerAck. Returns the peer's
    /// advertised height. Pure protocol step: no scoring, no peer removal —
    /// the caller funnels ALL failures through one cleanup path so failed
    /// handshakes can neither leak peer slots nor escape scoring.
    async fn do_handshake<R: AsyncRead + Unpin>(
        read_half: &mut R,
        write_tx: &mpsc::Sender<Vec<u8>>,
        peer_manager: &Arc<RwLock<PeerManager>>,
        addr: SocketAddr,
        local_nonce: u64,
        our_height: u32,
        network: &NetworkConfig,
    ) -> Result<u32, P2pError> {
        let version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: SERVICES,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            height: our_height,
            nonce: local_nonce,
        };
        let msg = Message::with_magic(MessageType::Version, version.encode(), network.magic);
        write_tx
            .try_send(msg.encode())
            .map_err(|_| P2pError::Protocol("failed to send version".into()))?;

        let mut peer_height = 0u32;
        let mut buf = Vec::with_capacity(65536);
        let mut sent_verack = false;
        let handshake_timeout = std::time::Duration::from_secs(VERSION_TIMEOUT_SECS);
        let handshake_deadline = tokio::time::Instant::now() + handshake_timeout;

        loop {
            let remaining = handshake_deadline
                .checked_duration_since(tokio::time::Instant::now())
                .unwrap_or_default();
            if remaining.is_zero() {
                return Err(P2pError::Protocol("handshake timeout".into()));
            }

            match tokio::time::timeout(remaining, read_frame(read_half, &mut buf, network.magic))
                .await
            {
                Ok(Ok((msg_type, payload))) => match msg_type {
                    MessageType::Version => {
                        let ver = VersionMessage::decode(&payload).map_err(P2pError::from)?;
                        if ver.version != PROTOCOL_VERSION {
                            return Err(P2pError::Protocol(format!(
                                "unsupported version: {}",
                                ver.version
                            )));
                        }
                        if ver.nonce == local_nonce {
                            return Err(P2pError::Protocol("self-connection detected".into()));
                        }
                        peer_height = ver.height;
                        {
                            let mut pm = peer_manager.write().await;
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.version = ver.version;
                                peer.height = ver.height;
                                peer.services = ver.services;
                                peer.state = PeerState::Handshaking;
                            }
                        }

                        if !sent_verack {
                            let verack =
                                Message::with_magic(MessageType::VerAck, vec![], network.magic);
                            let _ = write_tx.try_send(verack.encode());
                            sent_verack = true;
                        }
                    }
                    MessageType::VerAck => {
                        return Ok(peer_height);
                    }
                    _ => {
                        return Err(P2pError::Protocol(format!(
                            "unexpected message during handshake: {:?}",
                            msg_type
                        )));
                    }
                },
                Ok(Err(e)) => {
                    return Err(e);
                }
                Err(_) => {
                    return Err(P2pError::Protocol("handshake timeout".into()));
                }
            }
        }
    }

    /// Spawn the per-connection write task. It owns the writer (plaintext
    /// or encrypted) and a bounded 64-slot queue; overflow drops the peer
    /// without affecting others. Ends when all senders are gone or a send
    /// fails. Shared cleanup in the caller handles peer removal.
    fn spawn_write_task(
        writer: noise_transport::NetWriter,
        mut write_rx: mpsc::Receiver<Vec<u8>>,
        peer_manager: Arc<RwLock<PeerManager>>,
        addr: SocketAddr,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut writer = writer;
            while let Some(data) = write_rx.recv().await {
                if writer.send(&data).await.is_err() {
                    break;
                }
            }
            let mut pm = peer_manager.write().await;
            pm.remove_peer(&addr);
        })
    }

    /// Classify a block-application failure for peer scoring.
    ///
    /// Only EXACT judgments score: proof-of-work, state/merkle roots,
    /// coinbase structure, sizes, and tx signatures are deterministic —
    /// an honest peer never produces them. Fork/competition artifacts
    /// (previous-hash or height mismatch, timestamps/clock skew, stale
    /// difficulty, raced nonces/balances) are NORMAL multi-miner operation:
    /// orphans happen on mainnet too, and scoring them would ban honest
    /// miners for losing races and split the network. Those return 0
    /// (still rejected for consensus, still logged, still counted in the
    /// global sync-failure tracker — just never a ban).
    /// Scoring is deliberately fail-open: an unrecognized failure mode
    /// costs no points. Bans are the dangerous action, so they require
    /// positive evidence of Byzantine behavior, never ambiguity.
    fn block_rejection_score(err: &chroma_core::error::CoreError) -> i32 {
        use chroma_core::error::CoreError;
        match err {
            CoreError::InvalidProofOfWork(_)
            | CoreError::InvalidStateRoot(_)
            | CoreError::InvalidMerkleRoot(_)
            | CoreError::BlockSizeExceeded(..)
            | CoreError::TransactionSizeExceeded(..)
            | CoreError::SupplyInvariant(_)
            | CoreError::Overflow(_)
            | CoreError::InvalidSignature(_) => SCORE_INVALID_BLOCK,
            CoreError::InvalidBlock(msg) => {
                let m = msg.as_str();
                if m.contains("coinbase")
                    || m.contains("subsidy")
                    || m.contains("reward")
                    || m.contains("zero sender")
                    || m.contains("zero signature")
                    || m.contains("at least one transaction")
                    || m.contains("nonce must be 0")
                {
                    SCORE_INVALID_BLOCK
                } else {
                    // Fork/competition/staleness markers ("previous hash",
                    // "height", "competing", "reorg", "missing parent",
                    // "less or equal work", "timestamp", ...) and anything
                    // unrecognized: normal operation, no score.
                    0
                }
            }
            _ => 0,
        }
    }

    /// Shared connection teardown: free the slot (preserving live bans),
    /// unstick sync if this peer was the sync source, announce disconnect.
    /// Every exit path of `handle_connection` funnels through here exactly
    /// once (plus the idempotent write-task tail).
    async fn cleanup_connection(
        peer_manager: &Arc<RwLock<PeerManager>>,
        syncer: &Arc<RwLock<ChainSyncer>>,
        event_tx: &mpsc::UnboundedSender<NodeEvent>,
        addr: SocketAddr,
    ) {
        {
            let mut pm = peer_manager.write().await;
            pm.remove_peer(&addr);
        }
        {
            let mut s = syncer.write().await;
            if s.sync_peer() == Some(addr) {
                s.sync_failed();
            }
        }
        let _ = event_tx.send(NodeEvent::PeerDisconnected(addr));
    }

    /// Application session over an established transport (plaintext or
    /// Noise-encrypted — the bytes are identical either way): Version/VerAck
    /// handshake, Ready marking, sync initiation, then the message loop.
    /// Transport-agnostic via `R: AsyncRead`; writes go through the shared
    /// bounded channel. No cleanup here — the caller aborts the writer and
    /// runs `cleanup_connection` on every exit path.
    #[allow(clippy::too_many_arguments)]
    async fn run_session<R: AsyncRead + Unpin>(
        read_half: &mut R,
        write_tx: &mpsc::Sender<Vec<u8>>,
        addr: SocketAddr,
        peer_manager: &Arc<RwLock<PeerManager>>,
        event_tx: &mpsc::UnboundedSender<NodeEvent>,
        chain_height: &Arc<AtomicU32>,
        storage: &Arc<chroma_storage::Storage>,
        chain_state: &Arc<RwLock<chroma_consensus::ChainState>>,
        syncer: &Arc<RwLock<ChainSyncer>>,
        mempool: &Arc<RwLock<Mempool>>,
        outbound: bool,
        local_nonce: u64,
        our_height: u32,
        network: &NetworkConfig,
        relay_stats: &Arc<RelayStats>,
    ) -> Result<(), P2pError> {
        // Application handshake: failures score the peer and return;
        // the caller frees the slot.
        let peer_height = match Self::do_handshake(
            read_half,
            write_tx,
            peer_manager,
            addr,
            local_nonce,
            our_height,
            network,
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                let mut pm = peer_manager.write().await;
                pm.note_handshake_failure(&addr);
                pm.remove_peer(&addr);
                return Err(e);
            }
        };

        // Handshake complete
        {
            let mut pm = peer_manager.write().await;
            pm.clear_connect_failures(&addr);
            if let Some(peer) = pm.get_peer_mut(&addr) {
                peer.state = PeerState::Ready;
                peer.last_seen = Some(std::time::Instant::now());
                peer.height = peer_height;
            }
        }
        let _ = event_tx.send(NodeEvent::PeerConnected(addr));

        // If we're behind, initiate header sync with this peer
        if outbound {
            let mut s = syncer.write().await;
            if !s.is_syncing() && !s.is_caught_up() {
                let cs = chain_state.read().await;
                let tip_hash = cs.tip.hash;
                let tip_height = cs.tip.height.0;
                drop(cs);

                // Check if we should enter IBD mode
                if s.should_enter_ibd(tip_height, peer_height) {
                    let _ = event_tx.send(NodeEvent::Error(format!(
                        "IBD: local height {} vs peer height {}, starting sync",
                        tip_height, peer_height
                    )));
                }

                // Send GetHeaders for each locator hash until peer responds.
                // The first locator that the peer recognizes will cause it to
                // send back headers from the fork point onward.
                let locator_hashes = s.block_locator_hashes(tip_hash, tip_height);
                for locator in &locator_hashes {
                    let getheaders = s.start_header_sync(addr, *locator);
                    let msg = Message::with_magic(
                        MessageType::GetHeaders,
                        getheaders.encode(),
                        network.magic,
                    );
                    let _ = write_tx.try_send(msg.encode());
                }
            }
        }

        // Main message loop
        let mut main_buf = Vec::with_capacity(65536);
        Self::message_loop(
            read_half,
            write_tx,
            addr,
            peer_manager,
            event_tx,
            chain_height,
            storage,
            chain_state,
            syncer,
            mempool,
            network,
            relay_stats,
            &mut main_buf,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        addr: SocketAddr,
        peer_manager: Arc<RwLock<PeerManager>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        syncer: Arc<RwLock<ChainSyncer>>,
        mempool: Arc<RwLock<Mempool>>,
        outbound: bool,
        network: NetworkConfig,
        noise_key: [u8; 32],
        noise_public: [u8; 32],
        allow_plaintext: bool,
        shutdown_tx: broadcast::Sender<()>,
        relay_stats: Arc<RelayStats>,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<(), P2pError> {
        // Persistent shutdown gate: a task spawned after shutdown missed the
        // broadcast and must not become Ready. Remove any slot the accept
        // gate reserved and exit before any I/O.
        if shutdown_flag.load(Ordering::SeqCst) {
            {
                let mut pm = peer_manager.write().await;
                pm.remove_peer(&addr);
            }
            return Ok(());
        }
        let local_nonce = rand_u64();
        let mut shutdown_rx = shutdown_tx.subscribe();

        {
            let mut pm = peer_manager.write().await;
            pm.add_peer(addr);
            if let Some(peer) = pm.get_peer_mut(&addr) {
                peer.state = PeerState::Connecting;
                peer.connected_at = Some(std::time::Instant::now());
            }
        }

        let (mut read_half, mut write_half) = stream.into_split();

        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);

        {
            let mut pm = peer_manager.write().await;
            pm.set_channel(addr, write_tx.clone());
        }

        // --- Transport security: Noise XX first, unless explicit plaintext
        // opt-in (test/debug only). There is deliberately no negotiation and
        // no fallback: any Noise failure drops the connection right here.
        // This runs inside the slot reserved by the accept/dial gate and is
        // bounded by the handshake deadline, so limits are never bypassed.
        let noise_session = if allow_plaintext {
            None
        } else {
            let role = if outbound {
                HandshakeRole::Initiator
            } else {
                HandshakeRole::Responder
            };
            let deadline = std::time::Instant::now() + noise_transport::NOISE_HANDSHAKE_TIMEOUT;
            let hs = tokio::select! {
                r = noise_transport::do_noise_handshake(
                    &mut read_half,
                    &mut write_half,
                    role,
                    &noise_key,
                    deadline,
                ) => Some(r),
                _ = shutdown_rx.recv() => None,
            };
            match hs {
                None => {
                    // Shutdown during Noise handshake: quiet teardown.
                    Self::cleanup_connection(&peer_manager, &syncer, &event_tx, addr).await;
                    return Ok(());
                }
                Some(Err(e)) => {
                    let mut pm = peer_manager.write().await;
                    pm.note_handshake_failure(&addr);
                    pm.remove_peer(&addr);
                    return Err(P2pError::Protocol(format!("noise handshake: {}", e)));
                }
                Some(Ok((session, remote_static))) => {
                    // Static-key self-connection: stronger than the app
                    // nonce check below (kept as defense in depth).
                    if remote_static == noise_public {
                        Self::cleanup_connection(&peer_manager, &syncer, &event_tx, addr).await;
                        return Err(P2pError::Protocol("self-connection detected".into()));
                    }
                    // TOFU binding: first-seen key per address. A change
                    // warns loudly but keeps availability (see SPEC §10.5);
                    // first-contact MITM is NOT prevented (no trust anchor).
                    {
                        let mut pm = peer_manager.write().await;
                        if let Some(peer) = pm.get_peer_mut(&addr) {
                            match peer.remote_static {
                                Some(prev) if prev != remote_static => {
                                    let _ = event_tx.send(NodeEvent::Error(format!(
                                        "peer {} identity changed; possible MITM or key rotation",
                                        addr
                                    )));
                                    peer.remote_static = Some(remote_static);
                                }
                                _ => {
                                    peer.remote_static = Some(remote_static);
                                }
                            }
                        }
                    }
                    Some(session)
                }
            }
        };

        // Application session over the established transport. Both arms run
        // the identical session logic; only the byte stream differs, so a
        // Noise failure can never silently become plaintext (and vice versa).
        // Shutdown ends the session promptly; every exit funnels through the
        // shared cleanup below.
        // Second shutdown gate: shutdown may have fired during the (blocking)
        // Noise handshake; the broadcast select above catches pre-subscribed
        // tasks, but a flag check closes any remaining window before the
        // connection can become Ready.
        if shutdown_flag.load(Ordering::SeqCst) {
            Self::cleanup_connection(&peer_manager, &syncer, &event_tx, addr).await;
            return Ok(());
        }
        let our_height = chain_height.load(Ordering::Relaxed);
        let result = if let Some(session) = noise_session {
            let mut secure_reader = noise_transport::NoiseReader::new(read_half, session.clone());
            let net_writer = noise_transport::NetWriter::Secure(noise_transport::NoiseWriter::new(
                write_half, session,
            ));
            let write_handle =
                Self::spawn_write_task(net_writer, write_rx, peer_manager.clone(), addr);
            let r = tokio::select! {
                r = Self::run_session(
                    &mut secure_reader,
                    &write_tx,
                    addr,
                    &peer_manager,
                    &event_tx,
                    &chain_height,
                    &storage,
                    &chain_state,
                    &syncer,
                    &mempool,
                    outbound,
                    local_nonce,
                    our_height,
                    &network,
                    &relay_stats,
                ) => r,
                _ = shutdown_rx.recv() => Ok::<(), P2pError>(()),
            };
            write_handle.abort();
            r
        } else {
            let net_writer = noise_transport::NetWriter::Plain(write_half);
            let write_handle =
                Self::spawn_write_task(net_writer, write_rx, peer_manager.clone(), addr);
            let r = tokio::select! {
                r = Self::run_session(
                    &mut read_half,
                    &write_tx,
                    addr,
                    &peer_manager,
                    &event_tx,
                    &chain_height,
                    &storage,
                    &chain_state,
                    &syncer,
                    &mempool,
                    outbound,
                    local_nonce,
                    our_height,
                    &network,
                    &relay_stats,
                ) => r,
                _ = shutdown_rx.recv() => Ok::<(), P2pError>(()),
            };
            write_handle.abort();
            r
        };

        Self::cleanup_connection(&peer_manager, &syncer, &event_tx, addr).await;
        result
    }

    // ========================================================================
    // Message Loop — processes frames on a persistent connection
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn message_loop<R: AsyncRead + Unpin>(
        read_half: &mut R,
        write_tx: &mpsc::Sender<Vec<u8>>,
        addr: SocketAddr,
        peer_manager: &Arc<RwLock<PeerManager>>,
        event_tx: &mpsc::UnboundedSender<NodeEvent>,
        chain_height: &Arc<AtomicU32>,
        storage: &Arc<chroma_storage::Storage>,
        chain_state: &Arc<RwLock<chroma_consensus::ChainState>>,
        syncer: &Arc<RwLock<ChainSyncer>>,
        mempool: &Arc<RwLock<Mempool>>,
        network: &NetworkConfig,
        relay_stats: &Arc<RelayStats>,
        buf: &mut Vec<u8>,
    ) -> Result<(), P2pError> {
        loop {
            // Enforce bans mid-connection: a peer that crossed the ban
            // threshold through THIS connection's offenses is dropped now
            // instead of being served indefinitely. Ban records survive in
            // the peer book (and at IP level), so reconnects stay rejected.
            {
                let pm = peer_manager.read().await;
                if pm.get_peer(&addr).map(|p| p.is_banned()).unwrap_or(false) {
                    return Err(P2pError::Protocol("peer banned".into()));
                }
            }
            // Check for sync timeout before reading
            {
                let s = syncer.read().await;
                if s.is_syncing() && s.is_sync_timed_out() {
                    let responsible = s.sync_peer() == Some(addr);
                    drop(s);
                    if !responsible {
                        // Bystander during someone else's stall: idle
                        // briefly instead of busy-spinning the timeout
                        // check, then re-evaluate (the state may have
                        // reset once the sync peer disconnects).
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                    let _ = event_tx.send(NodeEvent::SyncTimeout(addr));
                    // Network-error tier: chronic stallers accumulate toward
                    // a ban slowly (40 timeouts); honest slow peers recover
                    // via decay. Never bans on its own quickly.
                    peer_manager
                        .write()
                        .await
                        .note_invalid_object(&addr, SCORE_CONNECT_FAIL);
                    return Err(P2pError::Protocol("sync timeout".into()));
                }
            }

            // Idle read deadline: a connection that delivers no frames for
            // IDLE_EVICT_SECS is dead (half-open / blackholed) and must
            // self-terminate. This is the same bound the peer-tick uses for
            // idle eviction (SPEC §10), enforced here so a lost FIN cannot
            // leave a zombie read task + socket behind forever: the
            // tick-level Disconnect only removes bookkeeping. Honest peers
            // are pinged every PING_INTERVAL_SECS (30 s < 90 s) and pong in
            // reply, so any live link resets this deadline continuously.
            // Expiry funnels through the shared cleanup path below.
            let idle_deadline = std::time::Duration::from_secs(IDLE_EVICT_SECS);
            match tokio::time::timeout(idle_deadline, read_frame(read_half, buf, network.magic))
                .await
            {
                Err(_) => {
                    return Err(P2pError::Protocol("idle timeout: no frames".into()));
                }
                Ok(Ok((msg_type, payload))) => {
                    // Rate limit check
                    {
                        let mut pm = peer_manager.write().await;
                        if let Some(peer) = pm.get_peer_mut(&addr) {
                            if !peer.check_msg_rate() {
                                peer.score_bad(SCORE_RATE_LIMIT);
                                return Err(P2pError::Protocol("rate limited".into()));
                            }
                            peer.last_seen = Some(std::time::Instant::now());
                        }
                    }

                    match msg_type {
                        MessageType::Ping => {
                            let ping = PingMessage::decode(&payload)?;
                            let pong = Message::with_magic(
                                MessageType::Pong,
                                PingMessage { nonce: ping.nonce }.encode(),
                                network.magic,
                            );
                            let _ = write_tx.try_send(pong.encode());
                            let mut pm = peer_manager.write().await;
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.last_seen = Some(std::time::Instant::now());
                                peer.score_tick();
                            }
                        }
                        MessageType::Pong => {
                            let mut pm = peer_manager.write().await;
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.last_seen = Some(std::time::Instant::now());
                            }
                        }
                        MessageType::GetHeaders => {
                            let getheaders = GetHeadersMessage::decode(&payload)?;
                            let cs = chain_state.read().await;
                            let tip_height = cs.tip.height.0;
                            drop(cs);

                            let mut headers_buf = Vec::new();
                            let mut count = 0u32;

                            // Find the start height from the requested start_hash
                            let start_height = if getheaders.start_hash != Hash::ZERO {
                                // Use the syncer's locator lookup for better accuracy
                                let s = syncer.read().await;
                                s.find_headers_start_height(&getheaders.start_hash)
                                    .unwrap_or_else(|| {
                                        // Fallback to storage lookup
                                        storage
                                            .get_height_for_hash(&getheaders.start_hash)
                                            .ok()
                                            .flatten()
                                            .unwrap_or(0)
                                    })
                            } else {
                                0
                            };

                            // Send up to MAX_HEADERS_PER_RESPONSE headers starting after start_height
                            for h in (start_height + 1)..=(start_height + 2000).min(tip_height) {
                                if let Ok(Some(header)) = storage.get_header(h) {
                                    let encoded = header.encode();
                                    headers_buf.extend_from_slice(&encoded);
                                    count += 1;
                                } else {
                                    break;
                                }
                            }

                            let mut response = Vec::with_capacity(4 + headers_buf.len());
                            response.extend_from_slice(&count.to_le_bytes());
                            response.extend_from_slice(&headers_buf);
                            let msg =
                                Message::with_magic(MessageType::Headers, response, network.magic);
                            let _ = write_tx.try_send(msg.encode());
                        }
                        MessageType::Headers => {
                            if payload.len() < 4 {
                                continue;
                            }
                            let count = u32::from_le_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]) as usize;
                            // Cap BEFORE allocating/looping: a claimed count
                            // larger than one response batch is abusive.
                            if count > crate::sync::MAX_HEADERS_PER_RESPONSE {
                                peer_manager
                                    .write()
                                    .await
                                    .note_invalid_object(&addr, SCORE_MALFORMED);
                                continue;
                            }
                            if count == 0 {
                                // Empty batch terminates sync ("no more
                                // headers"). Ownership is claimed atomically
                                // like data batches, so the terminator is
                                // always attributable for timeout purposes;
                                // a stranger's terminator mid-sync is
                                // silently ignored (never scored — it may be
                                // a confused honest peer).
                                let mut s = syncer.write().await;
                                if !s.claim_sync_peer(addr) {
                                    continue;
                                }
                                let cmds = s.received_headers(vec![]);
                                for cmd in cmds {
                                    Self::execute_sync_command(
                                        cmd,
                                        write_tx,
                                        peer_manager,
                                        chain_state,
                                        storage,
                                        syncer,
                                        network.magic,
                                    )
                                    .await;
                                }
                                continue;
                            }

                            let mut headers = Vec::new();
                            let mut pos = 4;
                            for _ in 0..count {
                                if pos + 124 > payload.len() {
                                    break;
                                }
                                match chroma_block::BlockHeader::decode(&payload[pos..pos + 124]) {
                                    Ok(header) => {
                                        headers.push(header);
                                        pos += 124;
                                    }
                                    Err(_) => break,
                                }
                            }

                            if !headers.is_empty() {
                                // Structural validation first (pure check).
                                // Unlinked/conflicting batches are SILENTLY
                                // ignored, never scored: at header layer a
                                // conflict is ambiguous (honest forks announce
                                // competing heights; our own view may be the
                                // stale one). Exact Byzantine judgments happen
                                // at block application, where PoW/state roots
                                // decide and scoring applies. Only the
                                // unambiguous oversize-count violation scores.
                                let valid = { syncer.read().await.header_batch_valid(&headers) };
                                if !valid {
                                    continue;
                                }
                                // Single-owner gate, atomically with
                                // processing: while one peer owns the sync,
                                // other peers' batches are silently ignored
                                // (no score — could be an honest competing
                                // view), so nobody can reset, hijack, or
                                // monopolize the sync. Stuck owners are
                                // evicted by timeout and cleanup resets.
                                let mut s = syncer.write().await;
                                if !s.claim_sync_peer(addr) {
                                    continue;
                                }
                                let cmds = s.received_headers(headers);
                                drop(s);
                                for cmd in cmds {
                                    Self::execute_sync_command(
                                        cmd,
                                        write_tx,
                                        peer_manager,
                                        chain_state,
                                        storage,
                                        syncer,
                                        network.magic,
                                    )
                                    .await;
                                }
                            }
                        }
                        MessageType::Inv => {
                            let inv = match InvMessage::decode(&payload) {
                                Ok(inv) => inv,
                                Err(_) => {
                                    peer_manager
                                        .write()
                                        .await
                                        .note_invalid_object(&addr, SCORE_MALFORMED);
                                    continue;
                                }
                            };
                            // Cap follow-up work: even a max-size Inv only
                            // triggers bounded lookups + one bounded GetData.
                            if inv.inventory.len() > crate::wire::MAX_INV_FOLLOW {
                                peer_manager
                                    .write()
                                    .await
                                    .note_invalid_object(&addr, SCORE_MALFORMED);
                            }
                            let mut getdata_items = Vec::new();

                            for entry in inv.inventory.iter().take(crate::wire::MAX_INV_FOLLOW) {
                                match entry.inv_type {
                                    InvType::Block => {
                                        // Check if we have this block
                                        let have = storage
                                            .get_block_by_hash(&entry.hash)
                                            .ok()
                                            .flatten()
                                            .is_some();
                                        if !have {
                                            getdata_items.push(entry.clone());
                                        }
                                    }
                                    InvType::Tx => {
                                        let have = {
                                            let mp = mempool.read().await;
                                            mp.has_transaction(&entry.hash)
                                        };
                                        if !have {
                                            getdata_items.push(entry.clone());
                                        }
                                    }
                                }
                            }

                            if !getdata_items.is_empty() {
                                let getdata = GetDataMessage {
                                    inventory: getdata_items,
                                };
                                let msg = Message::with_magic(
                                    MessageType::GetData,
                                    getdata.encode(),
                                    network.magic,
                                );
                                let _ = write_tx.try_send(msg.encode());
                            }
                        }
                        MessageType::GetData => {
                            let getdata = match GetDataMessage::decode(&payload) {
                                Ok(gd) => gd,
                                Err(_) => {
                                    peer_manager
                                        .write()
                                        .await
                                        .note_invalid_object(&addr, SCORE_MALFORMED);
                                    continue;
                                }
                            };
                            // Cap served entries per message so one peer
                            // cannot force unlimited disk reads / bandwidth.
                            if getdata.inventory.len() > crate::wire::MAX_INV_FOLLOW {
                                peer_manager
                                    .write()
                                    .await
                                    .note_invalid_object(&addr, SCORE_MALFORMED);
                            }
                            relay_stats
                                .getdata_entries
                                .fetch_add(getdata.inventory.len() as u64, Ordering::Relaxed);
                            for entry in getdata.inventory.iter().take(crate::wire::MAX_INV_FOLLOW)
                            {
                                match entry.inv_type {
                                    InvType::Block => {
                                        if let Ok(Some(block)) =
                                            storage.get_block_by_hash(&entry.hash)
                                        {
                                            let msg = Message::with_magic(
                                                MessageType::Block,
                                                block.encode_block(),
                                                network.magic,
                                            );
                                            RelayStats::note_write(
                                                &relay_stats.block_served,
                                                &relay_stats.block_dropped,
                                                write_tx.try_send(msg.encode()).is_ok(),
                                            );
                                        } else {
                                            let notfound = Message::with_magic(
                                                MessageType::NotFound,
                                                InvMessage {
                                                    inventory: vec![entry.clone()],
                                                }
                                                .encode(),
                                                network.magic,
                                            );
                                            RelayStats::note_write(
                                                &relay_stats.notfound_served,
                                                &relay_stats.notfound_dropped,
                                                write_tx.try_send(notfound.encode()).is_ok(),
                                            );
                                        }
                                    }
                                    InvType::Tx => {
                                        let tx_data = {
                                            let mp = mempool.read().await;
                                            mp.get_transaction(&entry.hash).map(|tx| tx.encode())
                                        };
                                        if let Some(encoded) = tx_data {
                                            let msg = Message::with_magic(
                                                MessageType::Tx,
                                                encoded,
                                                network.magic,
                                            );
                                            let _ = write_tx.try_send(msg.encode());
                                        } else {
                                            let notfound = Message::with_magic(
                                                MessageType::NotFound,
                                                InvMessage {
                                                    inventory: vec![entry.clone()],
                                                }
                                                .encode(),
                                                network.magic,
                                            );
                                            RelayStats::note_write(
                                                &relay_stats.notfound_served,
                                                &relay_stats.notfound_dropped,
                                                write_tx.try_send(notfound.encode()).is_ok(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        MessageType::Block => {
                            let block_result = chroma_block::Block::decode_block(&payload);
                            match block_result {
                                Ok(block) => {
                                    let block_hash = block.hash();
                                    let block_height = block.header.height.0;

                                    // Capture old tip before apply for reorg detection
                                    let (old_tip_height, old_tip_hash) = {
                                        let cs = chain_state.read().await;
                                        cs.tip_info()
                                    };

                                    let mut cs = chain_state.write().await;
                                    if let Err(e) = cs.apply_block(&block) {
                                        let _ = event_tx.send(NodeEvent::Error(format!(
                                            "block validation failed: {}",
                                            e
                                        )));
                                        // Record sync failure for invalid blocks
                                        drop(cs);
                                        let mut s = syncer.write().await;
                                        s.record_sync_failure();
                                        if s.is_peer_banned_for_sync() {
                                            let _ = event_tx.send(NodeEvent::Error(format!(
                                                "peer {} banned for repeated sync failures",
                                                addr
                                            )));
                                        }
                                        drop(s);
                                        // Score ONLY exact Byzantine judgments
                                        // (bad PoW/roots/coinbase/sizes/sigs).
                                        // Fork/orphan/stale rejections score 0:
                                        // punishing those would ban honest
                                        // miners for losing races and split
                                        // the network (see block_rejection_score).
                                        eprintln!("DIAGX block rejected from {}: {}", addr, e);
                                        let points = Self::block_rejection_score(&e);
                                        if points > 0 {
                                            RelayStats::note_sent(
                                                &relay_stats.blocks_rejected_scored,
                                            );
                                            peer_manager
                                                .write()
                                                .await
                                                .note_invalid_object(&addr, points);
                                        } else {
                                            RelayStats::note_sent(
                                                &relay_stats.blocks_rejected_unscored,
                                            );
                                        }
                                    } else {
                                        let tip = &cs.tip;
                                        let persisted = chroma_storage::PersistedTip {
                                            height: tip.height.0,
                                            hash: tip.hash,
                                            cumulative_work: tip.cumulative_work.to_be_bytes(),
                                            supply: tip.supply,
                                        };
                                        let _ = storage.commit_block(&block, &persisted, &cs.state);
                                        let _ = storage.flush();
                                        drop(cs);

                                        chain_height.store(block_height, Ordering::Relaxed);
                                        RelayStats::note_sent(&relay_stats.blocks_applied);
                                        let _ = event_tx.send(NodeEvent::BlockReceived(
                                            block_hash,
                                            block_height,
                                        ));

                                        if block_height < old_tip_height {
                                            let depth = old_tip_height - block_height;
                                            let _ = event_tx.send(NodeEvent::Reorg {
                                                old_height: old_tip_height,
                                                old_hash: old_tip_hash,
                                                new_height: block_height,
                                                new_hash: block_hash,
                                                depth,
                                            });
                                        }

                                        // Clean mined transactions from mempool
                                        {
                                            let mut mp = mempool.write().await;
                                            for tx in &block.transactions {
                                                let encoded = tx.encode();
                                                let h = Hash::blake3(&encoded);
                                                mp.remove_transaction(&h);
                                            }
                                        }

                                        // Update syncer and request next block if syncing
                                        {
                                            let mut s = syncer.write().await;
                                            s.received_block(block_hash, block_height);
                                            if s.needs_blocks() {
                                                if let Some(next_hash) = s.advance_block_sync() {
                                                    let msg = Message::with_magic(
                                                        MessageType::GetData,
                                                        GetDataMessage {
                                                            inventory: vec![InvEntry {
                                                                inv_type: InvType::Block,
                                                                hash: next_hash,
                                                            }],
                                                        }
                                                        .encode(),
                                                        network.magic,
                                                    );
                                                    let _ = write_tx.try_send(msg.encode());
                                                }
                                            }
                                        }

                                        // Only broadcast during steady-state sync (not IBD)
                                        {
                                            let s = syncer.read().await;
                                            if !s.is_in_initial_block_download() {
                                                let inv_entry = InvEntry {
                                                    inv_type: InvType::Block,
                                                    hash: block_hash,
                                                };
                                                let inv_msg = Message::new(
                                                    MessageType::Inv,
                                                    InvMessage {
                                                        inventory: vec![inv_entry],
                                                    }
                                                    .encode(),
                                                );
                                                Self::broadcast_to_peers(
                                                    peer_manager,
                                                    inv_msg,
                                                    network.magic,
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = event_tx.send(NodeEvent::Error(format!(
                                        "block decode failed from {}: {}",
                                        addr, e
                                    )));
                                    // Record sync failure for corrupt blocks
                                    let mut s = syncer.write().await;
                                    s.record_sync_failure();
                                    drop(s);
                                    // Undecodable block bytes: malformed.
                                    peer_manager
                                        .write()
                                        .await
                                        .note_invalid_object(&addr, SCORE_MALFORMED);
                                }
                            }
                        }
                        MessageType::Tx => {
                            let tx = chroma_tx::Transaction::decode(&payload);
                            match tx {
                                Ok(tx) => {
                                    // Check transaction rate limit
                                    {
                                        let mut pm = peer_manager.write().await;
                                        if let Some(peer) = pm.get_peer_mut(&addr) {
                                            if !peer.check_tx_rate() {
                                                peer.score_bad(SCORE_RATE_LIMIT);
                                                let _ = event_tx.send(NodeEvent::Error(format!(
                                                    "tx rate limited from {}",
                                                    addr
                                                )));
                                                continue;
                                            }
                                        }
                                    }

                                    // Validate signature before adding to mempool
                                    if let Err(e) =
                                        Mempool::validate_transaction(&tx, network.magic)
                                    {
                                        let _ = event_tx.send(NodeEvent::Error(format!(
                                            "invalid tx from {}: {}",
                                            addr, e
                                        )));
                                        peer_manager
                                            .write()
                                            .await
                                            .note_invalid_object(&addr, SCORE_INVALID_TX);
                                        let notfound = Message::with_magic(
                                            MessageType::NotFound,
                                            InvMessage {
                                                inventory: vec![InvEntry {
                                                    inv_type: InvType::Tx,
                                                    hash: Hash::blake3(&payload),
                                                }],
                                            }
                                            .encode(),
                                            network.magic,
                                        );
                                        RelayStats::note_write(
                                            &relay_stats.notfound_served,
                                            &relay_stats.notfound_dropped,
                                            write_tx.try_send(notfound.encode()).is_ok(),
                                        );
                                        continue;
                                    }

                                    let encoded = tx.encode();
                                    let tx_hash = Hash::blake3(&encoded);
                                    let _ = event_tx.send(NodeEvent::TxReceived(tx_hash));

                                    // Add to local mempool
                                    {
                                        let mut mp = mempool.write().await;
                                        let _ = mp.add_transaction(tx, network.magic);
                                    }

                                    // Relay to other peers
                                    let inv_entry = InvEntry {
                                        inv_type: InvType::Tx,
                                        hash: tx_hash,
                                    };
                                    let inv_msg = Message::new(
                                        MessageType::Inv,
                                        InvMessage {
                                            inventory: vec![inv_entry],
                                        }
                                        .encode(),
                                    );
                                    Self::broadcast_to_peers(peer_manager, inv_msg, network.magic)
                                        .await;
                                }
                                Err(e) => {
                                    let _ = event_tx.send(NodeEvent::Error(format!(
                                        "tx decode failed from {}: {}",
                                        addr, e
                                    )));
                                    // Undecodable 132-byte payload: malformed.
                                    peer_manager
                                        .write()
                                        .await
                                        .note_invalid_object(&addr, SCORE_MALFORMED);
                                }
                            }
                        }
                        MessageType::NotFound => {}
                        MessageType::Reject => {}
                        MessageType::Addr | MessageType::GetAddr => {}
                        MessageType::Version | MessageType::VerAck => {
                            // Duplicate during established connection — ignore or ban
                        }
                    }
                }
                Ok(Err(P2pError::Protocol(ref e))) if e.contains("bad magic") => {
                    // Wrong-network (or garbage) app frame inside an
                    // established session: same tier as handshake magic
                    // failures. A persistent wrong-network peer bans
                    // itself after 10 strikes.
                    peer_manager
                        .write()
                        .await
                        .note_invalid_object(&addr, SCORE_MALFORMED);
                    return Err(P2pError::Protocol("bad magic".into()));
                }
                Ok(Err(P2pError::Io(ref e))) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Ok(Err(P2pError::Io(_))) => {
                    return Ok(());
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
            }
        }
    }

    // ========================================================================
    // Peer Tick — periodic pings and reconnection
    // ========================================================================

    async fn run_peer_tick(
        peer_manager: Arc<RwLock<PeerManager>>,
        outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECS));
        let mut decay_interval = tokio::time::interval(std::time::Duration::from_secs(300)); // score decay every 5 min
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let pm = peer_manager.read().await;
                    let addrs: Vec<SocketAddr> = pm.peers_for_announcement();
                    drop(pm);

                    for addr in addrs {
                        let ping = PingMessage { nonce: rand_u64() };
                        let msg = Message::new(MessageType::Ping, ping.encode());
                        let _ = outbound_tx.send(OutboundCommand::Send(addr, msg));
                    }

                    // Idle eviction: Ready peers silent for IDLE_EVICT_SECS
                    // hold a slot, task, and buffers forever otherwise.
                    // Pings keep honest peers alive; only truly dead links
                    // are cut, and only while we still need the capacity.
                    let idle: Vec<SocketAddr> = {
                        let pm = peer_manager.read().await;
                        let cutoff = std::time::Duration::from_secs(IDLE_EVICT_SECS);
                        pm.idle_peers(cutoff)
                    };
                    for addr in idle {
                        let _ = outbound_tx.send(OutboundCommand::Disconnect(addr));
                    }
                }
                _ = decay_interval.tick() => {
                    let mut pm = peer_manager.write().await;
                    pm.decay_all_scores(1);
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    /// Bounded reconnect loop for operator-configured peers only.
    ///
    /// Runs every RECONNECT_TICK_SECS (plus jitter). For each configured
    /// address that is neither tracked nor banned nor in backoff, and only
    /// while the node still wants more peers, queues one dial. No storms:
    /// at most one dial per address per tick, gated by exponential backoff.
    /// Shutdown stops the loop; no new dials are queued afterwards.
    async fn run_reconnect(
        peer_manager: Arc<RwLock<PeerManager>>,
        outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
        connect_addrs: Vec<SocketAddr>,
        bootstrap_addrs: Vec<SocketAddr>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        const RECONNECT_TICK_SECS: u64 = 15;
        // Initial delay so startup dials (sent by run()) settle first.
        tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_TICK_SECS)).await;
        loop {
            // Small jitter so restarted nodes do not dial in lockstep.
            let jitter = rand_u64() % 5;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(
                    RECONNECT_TICK_SECS + jitter,
                )) => {
                    // Snapshot candidates without holding the lock across I/O.
                    // Reap dead entries first so failed-dial records do not
                    // accumulate (backoff history lives in a separate map
                    // and survives pruning; live bans are kept).
                    let candidates: Vec<SocketAddr> = {
                        let mut pm = peer_manager.write().await;
                        pm.prune_disconnected();
                        if !pm.need_more_peers() {
                            Vec::new()
                        } else {
                            // Explicit and discovered bootstrap peers share one
                            // candidate set (deduped); every address still
                            // passes the same dial gates below. No storms:
                            // at most one dial per address per tick.
                            let mut out = Vec::new();
                            for a in connect_addrs
                                .iter()
                                .copied()
                                .chain(bootstrap_addrs.iter().copied())
                            {
                                if !out.contains(&a) && pm.can_dial(&a) {
                                    out.push(a);
                                }
                            }
                            out
                        }
                    };
                    for addr in candidates {
                        let _ = outbound_tx.send(OutboundCommand::Connect(addr));
                    }
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    // ========================================================================
    // Miner
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn run_miner(
        peer_manager: Arc<RwLock<PeerManager>>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        mempool: Arc<RwLock<Mempool>>,
        _outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
        mut shutdown_rx: broadcast::Receiver<()>,
        miner_address: Option<chroma_core::types::Address>,
        network: NetworkConfig,
    ) {
        use chroma_consensus::miner::{
            assemble_block, mine_block_with_limit, BlockAssemblyContext,
        };
        use chroma_core::constants::TARGET_BLOCK_TIME_SECS;
        use chroma_core::hash::Hash160;
        use chroma_core::types::BlockHeight;

        let miner_address = miner_address.unwrap_or_else(|| {
            let mut addr = [0u8; 20];
            addr[0] = 0xDE;
            addr[1] = 0xAD;
            addr[2] = 0xBE;
            addr[3] = 0xEF;
            chroma_core::types::Address::from_hash160(Hash160(addr))
        });

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                    let network_time = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let (height, previous_hash, previous_timestamp, bits, state_root, txs) = {
                        let cs = chain_state.read().await;
                        let tip = &cs.tip;
                        let height = tip.height.0 + 1;
                        let previous_hash = tip.hash;
                        let previous_timestamp = tip.header.timestamp;
                        let bits = chroma_consensus::calculate_target_for_height(
                            height,
                            &cs.headers,
                        ).unwrap_or(tip.header.bits);

                        // Select only state-valid txs (see select_for_block):
                        // unfiltered mempool contents would poison the
                        // prospective root and stall mining on invalid blocks.
                        // No lock-order risk: every other path takes the
                        // mempool lock without holding chain_state.
                        let mp = mempool.read().await;
                        let txs = mp.select_for_block(
                            &cs.state,
                            chroma_consensus::miner::MAX_BLOCK_TXS - 1,
                        );
                        drop(mp);

                        let tx_descs: Vec<_> = txs.iter().map(|tx| {
                            (tx.sender_address(), tx.recipient, tx.amount.0, tx.nonce.0)
                        }).collect();

                        let state_root = cs.state
                            .compute_prospective_state_root(height, &miner_address, &tx_descs)
                            .unwrap_or(Hash::ZERO);

                        (height, previous_hash, previous_timestamp, bits, state_root, txs)
                    };

                    let timestamp = std::cmp::min(
                        previous_timestamp + TARGET_BLOCK_TIME_SECS,
                        network_time + 20,
                    );

                    let ctx = BlockAssemblyContext {
                        height: BlockHeight(height),
                        previous_hash,
                        previous_timestamp: timestamp.saturating_sub(TARGET_BLOCK_TIME_SECS),
                        state_root,
                        bits,
                        coinbase_recipient: miner_address,
                    };

                    match assemble_block(&ctx, &txs) {
                        Ok(mut block) => {
                            block.header.timestamp = timestamp;
                            // Initialize RandomX context for this block height
                            let _ = chroma_crypto::randomx::ensure_randomx_for_height(
                                height,
                                |h| {
                                    storage.get_canonical_hash_at_height(h).ok().flatten()
                                },
                            );
                            // Heavy synchronous RandomX PoW must not block a
                            // tokio async worker: handshake/accept/message
                            // tasks share the worker pool, and starving them
                            // causes spurious handshake timeouts under load.
                            // Consensus logic is unchanged; only the thread
                            // the nonce loop runs on moves to the blocking
                            // pool.
                            let mined = tokio::task::spawn_blocking(move || {
                                let mut b = block;
                                let r = mine_block_with_limit(&mut b, 10_000_000);
                                (b, r)
                            })
                            .await;
                            let (block, mine_res) = match mined {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            if let Ok(()) = mine_res {
                                let mut cs = chain_state.write().await;
                                if let Ok(()) = cs.apply_block(&block) {
                                    let block_hash = block.hash();
                                    let tip = &cs.tip;
                                    let persisted = chroma_storage::PersistedTip {
                                        height: tip.height.0,
                                        hash: tip.hash,
                                        cumulative_work: tip.cumulative_work.to_be_bytes(),
                                        supply: tip.supply,
                                    };
                                    let _ = storage.commit_block(&block, &persisted, &cs.state);
                                    let _ = storage.flush();

                                    chain_height.store(height, Ordering::Relaxed);
                                    let _ = event_tx.send(NodeEvent::BlockMined(block_hash, height));

                                    // Broadcast block to peers
                                    let inv_entry = InvEntry {
                                        inv_type: InvType::Block,
                                        hash: block_hash,
                                    };
                                    let inv_msg = Message::new(
                                        MessageType::Inv,
                                        InvMessage { inventory: vec![inv_entry] }.encode(),
                                    );
                                    Self::broadcast_to_peers(&peer_manager, inv_msg, network.magic).await;

                                    // Remove mined txs from mempool
                                    let mut mp = mempool.write().await;
                                    for tx in &block.transactions {
                                        let encoded = tx.encode();
                                        let h = Hash::blake3(&encoded);
                                        mp.remove_transaction(&h);
                                    }
                                } else {
                                    eprintln!("Mined block rejected: block validation failed");
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Block assembly failed: {}", e);
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // Sync Command Executor
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    async fn execute_sync_command(
        cmd: sync::SyncCommand,
        write_tx: &mpsc::Sender<Vec<u8>>,
        peer_manager: &Arc<RwLock<PeerManager>>,
        _chain_state: &Arc<RwLock<chroma_consensus::ChainState>>,
        _storage: &Arc<chroma_storage::Storage>,
        _syncer: &Arc<RwLock<ChainSyncer>>,
        magic: [u8; 4],
    ) {
        match cmd {
            sync::SyncCommand::GetHeaders(from_hash) => {
                let msg = Message::with_magic(
                    MessageType::GetHeaders,
                    GetHeadersMessage {
                        start_hash: from_hash,
                        stop_hash: Hash::ZERO,
                    }
                    .encode(),
                    magic,
                );
                let _ = write_tx.try_send(msg.encode());
            }
            sync::SyncCommand::RequestBlocksFrom(from_hash) => {
                let msg = Message::with_magic(
                    MessageType::GetData,
                    GetDataMessage {
                        inventory: vec![InvEntry {
                            inv_type: InvType::Block,
                            hash: from_hash,
                        }],
                    }
                    .encode(),
                    magic,
                );
                let _ = write_tx.try_send(msg.encode());
            }
            sync::SyncCommand::GetBlocks(hashes) => {
                if hashes.is_empty() {
                    return;
                }

                // Split into batches of MAX_BLOCKS_PER_REQUEST
                for chunk in hashes.chunks(sync::MAX_BLOCKS_PER_REQUEST) {
                    let entries: Vec<InvEntry> = chunk
                        .iter()
                        .map(|h| InvEntry {
                            inv_type: InvType::Block,
                            hash: *h,
                        })
                        .collect();
                    let msg = Message::with_magic(
                        MessageType::GetData,
                        GetDataMessage { inventory: entries }.encode(),
                        magic,
                    );
                    let _ = write_tx.try_send(msg.encode());
                }
            }
            sync::SyncCommand::SyncComplete => {
                let _ = peer_manager.read().await;
                // Sync is complete — node will continue normal operation
            }
        }
    }

    // ========================================================================
    // Public API
    // ========================================================================

    pub fn connect(&self, addr: SocketAddr) {
        if let Some(tx) = &self.outbound_tx {
            let _ = tx.send(OutboundCommand::Connect(addr));
        }
    }

    pub fn send_message(&self, addr: SocketAddr, msg: Message) {
        if let Some(tx) = &self.outbound_tx {
            let _ = tx.send(OutboundCommand::Send(addr, msg));
        }
    }

    pub fn broadcast_message(&self, msg: Message) {
        let peers = self.peer_manager.clone();
        let magic = self.config.network.magic;
        tokio::spawn(async move {
            Self::broadcast_to_peers(&peers, msg, magic).await;
        });
    }

    async fn broadcast_to_peers(
        peer_manager: &Arc<RwLock<PeerManager>>,
        msg: Message,
        magic: [u8; 4],
    ) {
        // Ready peers ONLY: relay traffic (INV announcements) must never
        // precede the Version handshake on a fresh connection. Sending it
        // earlier breaks strict peers (their handshake expects Version
        // first) and leaks nothing useful — the peer syncs via the
        // post-handshake locator flow instead.
        let pm = peer_manager.read().await;
        let addrs: Vec<SocketAddr> = pm.ready_peers().into_iter().map(|p| p.addr).collect();
        let mut msg = msg;
        msg.magic = magic;
        let encoded = msg.encode();
        for addr in &addrs {
            if let Some(sender) = pm.get_channel(addr) {
                let _ = sender.try_send(encoded.clone());
            }
        }
    }

    pub fn broadcast_transaction(&self, tx_hash: Hash) {
        let entry = InvEntry {
            inv_type: InvType::Tx,
            hash: tx_hash,
        };
        let inv = InvMessage {
            inventory: vec![entry],
        };
        self.broadcast_message(Message::new(MessageType::Inv, inv.encode()));
    }

    pub fn broadcast_block(&self, block_hash: Hash, _height: u32) {
        let entry = InvEntry {
            inv_type: InvType::Block,
            hash: block_hash,
        };
        let inv = InvMessage {
            inventory: vec![entry],
        };
        self.broadcast_message(Message::new(MessageType::Inv, inv.encode()));
    }

    pub fn shutdown(&self) {
        // Set the persistent flag BEFORE the broadcast so tasks spawned
        // after this point observe shutdown even though they miss the
        // broadcast message (new broadcast subscribers only see future
        // sends). Existing tasks still use the broadcast for prompt wake.
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(());
        }
    }
}

// ============================================================================
// Frame Reading — reads one complete message frame from the stream
// ============================================================================

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    expected_magic: [u8; 4],
) -> Result<(MessageType, Vec<u8>), P2pError> {
    // Read header (13 bytes: 4 magic + 1 type + 4 len + 4 checksum)
    while buf.len() < HEADER_SIZE {
        let n = reader.read_buf(buf).await.map_err(P2pError::Io)?;
        if n == 0 {
            return Err(P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            )));
        }
    }

    // Validate magic
    if buf[0..4] != expected_magic {
        return Err(P2pError::Protocol("bad magic".into()));
    }

    let msg_type = MessageType::from_u8(buf[4])?;
    let len = u32::from_le_bytes([buf[5], buf[6], buf[7], buf[8]]) as usize;

    if len > crate::wire::MAX_MESSAGE_SIZE {
        return Err(P2pError::Protocol(format!("payload too large: {}", len)));
    }

    let expected_checksum = [buf[9], buf[10], buf[11], buf[12]];

    // Ensure we have enough data for the payload
    while buf.len() < HEADER_SIZE + len {
        let n = reader.read_buf(buf).await.map_err(P2pError::Io)?;
        if n == 0 {
            return Err(P2pError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed during payload",
            )));
        }
    }

    // Extract payload
    let payload = buf[HEADER_SIZE..HEADER_SIZE + len].to_vec();
    let consumed = HEADER_SIZE + len;
    buf.drain(..consumed);

    // Verify checksum
    let actual = blake3::hash(&payload);
    if expected_checksum != actual.as_bytes()[..4] {
        return Err(P2pError::Protocol("checksum mismatch".into()));
    }

    Ok((msg_type, payload))
}

// ============================================================================
// Helpers
// ============================================================================

/// Generate a random u64 for nonces and handshakes.
/// Not cryptographically secure — acceptable for protocol nonces
/// where collision resistance is sufficient.
fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::SystemTime;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let s = RandomState::new();
    let mut h = s.build_hasher();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    h.write_u64(nanos);
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.finish()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_addr(n: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), n)
    }

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("chroma_test_{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_node_config() {
        let addr = test_addr(8333);
        let genesis = Hash::blake3(b"genesis");
        let config = NodeConfig::new(addr, genesis);
        assert_eq!(config.listen_addr, addr);
        assert_eq!(config.genesis_hash, genesis);
        assert!(config.connect_addrs.is_empty());
    }

    #[test]
    fn test_relay_stats_default_zero_and_snapshot() {
        // Observability must start at zero and reflect exactly the increments
        // made (single choke point for sent/dropped accounting).
        let stats = RelayStats::default();
        assert_eq!(stats.snapshot(), RelaySnapshot::default());
        RelayStats::note_sent(&stats.blocks_applied);
        RelayStats::note_write(&stats.block_served, &stats.block_dropped, true);
        RelayStats::note_write(&stats.block_served, &stats.block_dropped, false);
        RelayStats::note_write(&stats.notfound_served, &stats.notfound_dropped, false);
        let snap = stats.snapshot();
        assert_eq!(snap.blocks_applied, 1);
        assert_eq!(snap.block_served, 1);
        assert_eq!(snap.block_dropped, 1);
        assert_eq!(snap.notfound_served, 0);
        assert_eq!(snap.notfound_dropped, 1);
        assert_eq!(snap.getdata_entries, 0);
        assert_eq!(snap.blocks_rejected_unscored, 0);
        assert_eq!(snap.blocks_rejected_scored, 0);
    }

    #[test]
    fn test_node_creation() {
        let addr = test_addr(8333);
        let genesis = chroma_consensus::build_genesis_block();
        let genesis_hash = genesis.hash();
        let dir = temp_dir();
        let config = NodeConfig::new(addr, genesis_hash).with_data_dir(dir.clone());
        let node = Node::new(config);
        assert!(node.event_rx.is_some());
        assert!(node.outbound_rx.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rand_u64() {
        let a = rand_u64();
        let b = rand_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn test_p2p_error_display() {
        let err = P2pError::Protocol("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_network_config_mainnet() {
        let cfg = NetworkConfig::mainnet();
        assert_eq!(cfg.network_name, "mainnet");
        assert!(!cfg.regtest);
        assert_eq!(cfg.magic, MAGIC);
    }

    #[test]
    fn test_network_config_regtest() {
        let cfg = NetworkConfig::regtest();
        assert_eq!(cfg.network_name, "regtest");
        assert!(cfg.regtest);
        assert!(!cfg.testnet);
        assert_ne!(cfg.magic, MAGIC);
    }

    #[test]
    fn test_network_config_testnet() {
        let cfg = NetworkConfig::testnet();
        assert_eq!(cfg.network_name, "testnet");
        assert!(cfg.testnet);
        assert!(!cfg.regtest);
        assert_ne!(cfg.magic, MAGIC);
        assert_eq!(cfg.magic, TESTNET_MAGIC);
    }

    #[test]
    fn test_node_config_with_network() {
        let addr = test_addr(8333);
        let genesis = Hash::blake3(b"genesis");
        let config = NodeConfig::new(addr, genesis).with_network(NetworkConfig::regtest());
        assert!(config.network.regtest);
    }

    /// Crafted empty-state chain 0..=top in `dir` (no PoW: reload checks
    /// coherence, never re-validates PoW). Returns tip hash per height.
    fn craft_empty_chain(dir: &std::path::Path, top: u32) -> std::collections::BTreeMap<u32, Hash> {
        use chroma_core::types::{BlockHeight, CompactTarget};
        let storage = chroma_storage::Storage::open(dir).unwrap();
        let mut hashes = std::collections::BTreeMap::new();
        let mut prev = Hash::ZERO;
        let mut prev_ts = chroma_core::constants::GENESIS_TIMESTAMP;
        for h in 0..=top {
            let header = chroma_block::BlockHeader {
                version: 1,
                previous_hash: prev,
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: prev_ts + if h == 0 { 0 } else { 10 },
                bits: CompactTarget(0x20ffffff),
                height: BlockHeight(h),
                nonce: h as u64,
            };
            let block = chroma_block::Block {
                header,
                transactions: vec![],
            };
            let state = chroma_state::State::new();
            let tip = chroma_storage::PersistedTip {
                height: h,
                hash: block.hash(),
                cumulative_work: [0u8; 32],
                supply: 0,
            };
            if h == 0 {
                storage.apply_block(&block).unwrap();
                storage.put_tip(&tip).unwrap();
                storage.put_genesis_hash(&block.hash()).unwrap();
                storage.flush().unwrap();
            } else {
                storage.commit_block(&block, &tip, &state).unwrap();
            }
            prev = block.hash();
            prev_ts = block.header.timestamp;
            hashes.insert(h, prev);
        }
        storage.flush().unwrap();
        hashes
    }

    fn reload_node(dir: &std::path::Path, genesis_hash: Hash, port: u16) -> Node {
        let config = NodeConfig::new(test_addr(port), genesis_hash)
            .with_data_dir(dir.to_path_buf())
            .with_network(NetworkConfig::regtest());
        Node::new(config)
    }

    #[test]
    fn test_reload_consistent_chain_verifies() {
        // Happy path: coherent DB reloads with identical tip/root/supply.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 3);
        let node = reload_node(&dir, hashes[&0], 8341);
        let tip = node.storage().get_tip().unwrap().unwrap();
        assert_eq!((tip.height, tip.hash), (3, hashes[&3]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload_reverse_network_db_refused() {
        // Mainnet-genesis DB opened as testnet must also refuse (both
        // directions pinned; chain identity is symmetric).
        let dir = temp_dir();
        let genesis = chroma_consensus::build_genesis_block();
        let storage = chroma_storage::Storage::open(&dir).unwrap();
        storage.apply_block(&genesis).unwrap();
        let tip = chroma_storage::PersistedTip {
            height: 0,
            hash: genesis.hash(),
            cumulative_work: [0u8; 32],
            supply: 0,
        };
        storage.put_tip(&tip).unwrap();
        storage.put_genesis_hash(&genesis.hash()).unwrap();
        storage.flush().unwrap();
        drop(storage);
        let testnet_genesis =
            chroma_consensus::build_genesis_for_network(&chroma_consensus::NetworkKind::Testnet)
                .hash();
        let config = NodeConfig::new(test_addr(8348), testnet_genesis)
            .with_data_dir(dir.clone())
            .with_network(NetworkConfig::testnet());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = Node::new(config);
        }));
        assert!(result.is_err(), "mainnet DB as testnet must refuse");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_node_restart_burst_preserves_tip() {
        // Five rapid restarts (no mining, no network): tip, headers, and
        // state verification must hold every time; mempool stays empty.
        // Fast because no PoW or sockets are involved.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 4);
        for round in 0..5 {
            let node = reload_node(&dir, hashes[&0], 8350 + round as u16);
            let tip = node.storage().get_tip().unwrap().unwrap();
            assert_eq!((tip.height, tip.hash), (4, hashes[&4]), "round {}", round);
            assert!(node.mempool().try_read().unwrap().is_empty());
            drop(node);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[should_panic(expected = "stored genesis")]
    fn test_reload_wrong_network_db_refused() {
        // Testnet-genesis DB opened as mainnet: chain-identity refusal.
        // (Crafted with the testnet genesis; expectation is mainnet's.)
        let dir = temp_dir();
        let genesis =
            chroma_consensus::build_genesis_for_network(&chroma_consensus::NetworkKind::Testnet);
        let storage = chroma_storage::Storage::open(&dir).unwrap();
        storage.apply_block(&genesis).unwrap();
        let tip = chroma_storage::PersistedTip {
            height: 0,
            hash: genesis.hash(),
            cumulative_work: [0u8; 32],
            supply: 0,
        };
        storage.put_tip(&tip).unwrap();
        storage.put_genesis_hash(&genesis.hash()).unwrap();
        storage.flush().unwrap();
        drop(storage);
        let mainnet_genesis = chroma_consensus::build_genesis_block().hash();
        let config = NodeConfig::new(test_addr(8342), mainnet_genesis)
            .with_data_dir(dir.clone())
            .with_network(NetworkConfig::mainnet());
        let _ = Node::new(config);
    }

    #[test]
    #[should_panic(expected = "no stored headers")]
    fn test_reload_torn_tip_refused() {
        // Tip record points past stored history: torn database refusal.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 2);
        let storage = chroma_storage::Storage::open(&dir).unwrap();
        let tip = chroma_storage::PersistedTip {
            height: 5,
            hash: Hash::blake3(b"phantom"),
            cumulative_work: [0u8; 32],
            supply: 0,
        };
        storage.put_tip(&tip).unwrap();
        storage.flush().unwrap();
        drop(storage);
        let _ = reload_node(&dir, hashes[&0], 8343);
    }

    #[test]
    #[should_panic(expected = "does not match stored header")]
    fn test_reload_aliased_tip_refused() {
        // Tip hash disagrees with the stored header at its height.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 3);
        let storage = chroma_storage::Storage::open(&dir).unwrap();
        let tip = chroma_storage::PersistedTip {
            height: 3,
            hash: Hash::blake3(b"impostor"),
            cumulative_work: [0u8; 32],
            supply: 0,
        };
        storage.put_tip(&tip).unwrap();
        storage.flush().unwrap();
        drop(storage);
        let _ = reload_node(&dir, hashes[&0], 8344);
    }

    #[test]
    #[should_panic(expected = "state root")]
    fn test_reload_tampered_balance_refused() {
        // Valid-length but wrong-value account record: the getter cannot see
        // it, but startup state-root verification refuses to boot on it.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 2);
        let storage = chroma_storage::Storage::open(&dir).unwrap();
        let mut h = [0u8; 20];
        h[0] = 0xEF;
        let addr = chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(h));
        storage
            .put_account(
                &addr,
                &chroma_state::Account {
                    balance: 999,
                    nonce: 0,
                },
            )
            .unwrap();
        storage.flush().unwrap();
        drop(storage);
        let _ = reload_node(&dir, hashes[&0], 8345);
    }

    #[test]
    fn test_mempool_does_not_persist_restart() {
        // Mempool policy pin: unconfirmed txs evaporate on restart (no
        // mempool journal); the chain tip itself is preserved.
        let dir = temp_dir();
        let hashes = craft_empty_chain(&dir, 2);
        let config = NodeConfig::new(test_addr(8346), hashes[&0])
            .with_data_dir(dir.clone())
            .with_network(NetworkConfig::regtest());
        let node = Node::new(config);
        assert!(node.mempool().try_read().is_ok());
        {
            use chroma_core::constants::REGTEST_MAGIC;
            use chroma_core::types::{Amount, Nonce};
            use chroma_crypto::hash::hash160;
            use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
            let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
            let pubkey = PublicKey32::from_secret(&secret).unwrap();
            let sender = chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(
                hash160(&pubkey.0),
            ));
            let mut h = [0u8; 20];
            h[0] = 0xBB;
            let recipient =
                chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(h));
            let tx = chroma_tx::create_transaction(
                &secret,
                sender,
                recipient,
                Amount(1_000),
                Nonce(0),
                REGTEST_MAGIC,
            )
            .unwrap();
            // `mempool` is behind an async RwLock; this is a sync test, so
            // use try_write (uncontended — deterministic, never blocks).
            node.mempool()
                .try_write()
                .unwrap()
                .add_transaction(tx, REGTEST_MAGIC)
                .unwrap();
            assert_eq!(node.mempool().try_read().unwrap().len(), 1);
        }
        drop(node);
        let node2 = reload_node(&dir, hashes[&0], 8347);
        assert!(
            node2.mempool().try_read().unwrap().is_empty(),
            "restart must drop unconfirmed transactions"
        );
        let tip = node2.storage().get_tip().unwrap().unwrap();
        assert_eq!((tip.height, tip.hash), (2, hashes[&2]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
