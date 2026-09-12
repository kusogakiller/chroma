use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, UNIX_EPOCH};

use tokio::sync::mpsc;

use chroma_core::constants::{PEER_MSG_RATE_LIMIT, PEER_TX_RATE_LIMIT};

pub const PEER_SCORE_GOOD: i32 = 10;
pub const PEER_SCORE_BAD: i32 = -100;
pub const BAN_SCORE_THRESHOLD: i32 = -200;
pub const MAX_OUTBOUND_PEERS: usize = 8;
pub const MAX_INBOUND_PEERS: usize = 16;
/// Total connection slots (inbound + outbound). Enforced across ALL
/// connection states (Connecting/Handshaking/Connected/Ready), not just Ready,
/// so handshake-flooding cannot exceed the cap.
pub const MAX_TOTAL_PEERS: usize = MAX_OUTBOUND_PEERS + MAX_INBOUND_PEERS;
/// Maximum concurrent connections from a single IP address (anti-Sybil).
/// Applies to inbound and outbound combined. Rotating source ports does not
/// bypass this because accounting is keyed by IP, not SocketAddr.
pub const MAX_PER_IP_PEERS: usize = 3;
/// Maximum concurrent handshakes (Connecting + Handshaking states).
/// Bounds task/memory growth from handshake flooding.
pub const MAX_HANDSHAKE_CONCURRENT: usize = 8;
pub const PEER_TIMEOUT_SECS: u64 = 30;
pub const PING_INTERVAL_SECS: u64 = 30;
pub const VERSION_TIMEOUT_SECS: u64 = 10;
/// Idle eviction: Ready peers silent for longer than this are disconnected.
pub const IDLE_EVICT_SECS: u64 = 90;
/// Ban duration for misbehaving peers/IPs.
pub const BAN_DURATION_SECS: u64 = 3600;
/// Maximum retained ban records (peer + IP). Bounds memory when an attacker
/// rotates addresses. Oldest expiries are evicted first.
pub const MAX_BANNED_RECORDS: usize = 1024;

// --- Deterministic scoring tiers -------------------------------------------
// Network errors (timeouts, refused connections) cost little; protocol
// violations cost more; invalid consensus objects cost the most. Four
// malformed handshakes (4x20), four invalid txs (4x50), or two invalid
// blocks (2x100) each reach the -200 ban threshold.
/// Score cost: failed dial / connect timeout (ordinary network error).
pub const SCORE_CONNECT_FAIL: i32 = 5;
/// Score cost: rate-limit violation.
pub const SCORE_RATE_LIMIT: i32 = 10;
/// Score cost: malformed handshake / undecodable message / protocol violation.
pub const SCORE_MALFORMED: i32 = 20;
/// Score cost: well-formed but invalid transaction (bad signature, etc.).
pub const SCORE_INVALID_TX: i32 = 50;
/// Score cost: well-formed but invalid block/header batch.
pub const SCORE_INVALID_BLOCK: i32 = 100;

// --- Reconnect backoff -------------------------------------------------------
// Base backoff after a failed dial (seconds). Doubles per consecutive
// failure: 5, 10, 20, ... capped at MAX_RECONNECT_BACKOFF_SECS.
pub const RECONNECT_BASE_SECS: u64 = 5;
/// Maximum reconnect backoff (seconds).
pub const MAX_RECONNECT_BACKOFF_SECS: u64 = 300;

// --- Inbound accept rate limiting --------------------------------------------
// Bounds handshake-attempt floods (task spawns + event generation) at the
// source. Legitimate peers connect rarely (once per session, redials spaced
// by backoff), so 32 accepts/minute/IP is generous; excess is dropped
// silently WITHOUT scoring (a busy NAT gateway must not get banned).
// Concurrent resource use stays bounded independently by MAX_TOTAL_PEERS
// and MAX_HANDSHAKE_CONCURRENT regardless of this rate.
/// Sliding window for inbound accept accounting.
pub const ACCEPT_WINDOW_SECS: u64 = 60;
/// Max inbound accepts per IP per window.
pub const ACCEPT_BURST_PER_IP: usize = 32;
/// Max tracked IPs in the accept log / connect-failure map. Oldest-idle
/// entries are reaped; bounds memory under address rotation.
pub const MAX_TRACKED_ADDRS: usize = 2048;

// ============================================================================
// Token Bucket Rate Limiter (SPEC §10)
// ============================================================================

/// Sliding-window token bucket for per-peer rate limiting.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    /// Maximum tokens per second.
    rate: u32,
    /// Current token count.
    tokens: f64,
    /// Maximum burst size (= rate).
    max_tokens: f64,
    /// Last refill time.
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given tokens-per-second rate.
    pub fn new(rate: u32) -> Self {
        RateLimiter {
            rate,
            tokens: rate as f64,
            max_tokens: rate as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.rate as f64;
        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
        self.last_refill = now;
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Connected,
    Handshaking,
    Ready,
    Disconnected,
    Banned,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub state: PeerState,
    pub score: i32,
    pub connected_at: Option<Instant>,
    pub last_seen: Option<Instant>,
    pub last_ping_nonce: Option<u64>,
    pub height: u32,
    pub version: u32,
    pub services: u64,
    pub ban_until: Option<Instant>,
    /// Peer's Noise static public key from the handshake (TOFU binding).
    /// None until a Noise handshake completes; always None on plaintext
    /// (opt-in) connections.
    pub remote_static: Option<[u8; 32]>,
    /// Rate limiter for incoming messages (msg/s).
    pub msg_limiter: RateLimiter,
    /// Rate limiter for incoming transactions (tx/s).
    pub tx_limiter: RateLimiter,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        PeerInfo {
            addr,
            state: PeerState::Disconnected,
            score: 0,
            connected_at: None,
            last_seen: None,
            last_ping_nonce: None,
            height: 0,
            version: 0,
            services: 0,
            ban_until: None,
            remote_static: None,
            msg_limiter: RateLimiter::new(PEER_MSG_RATE_LIMIT as u32),
            tx_limiter: RateLimiter::new(PEER_TX_RATE_LIMIT as u32),
        }
    }

    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.ban_until {
            if Instant::now() < until {
                return true;
            }
        }
        self.score <= BAN_SCORE_THRESHOLD
    }

    pub fn score_tick(&mut self) {
        self.score = self.score.saturating_add(1);
    }

    /// Decay score toward zero by the given amount.
    /// Peers that stop misbehaving gradually recover their reputation.
    /// Also clears expired bans so peers can rejoin.
    pub fn score_decay(&mut self, amount: i32) {
        if self.score > 0 {
            self.score = self.score.saturating_sub(amount).max(0);
        } else if self.score < 0 {
            self.score = self.score.saturating_add(amount).min(0);
        }
        if let Some(until) = self.ban_until {
            if Instant::now() >= until {
                self.ban_until = None;
            }
        }
    }

    pub fn score_bad(&mut self, points: i32) {
        self.score = self.score.saturating_sub(points);
        if self.score <= BAN_SCORE_THRESHOLD {
            self.ban_until = Some(Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
            self.state = PeerState::Banned;
        }
    }

    /// Try to consume a message rate-limit token. Returns false if rate-limited.
    pub fn check_msg_rate(&mut self) -> bool {
        self.msg_limiter.try_consume()
    }

    /// Try to consume a transaction rate-limit token. Returns false if rate-limited.
    pub fn check_tx_rate(&mut self) -> bool {
        self.tx_limiter.try_consume()
    }
}
pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
    channels: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
    /// IP-level bans (ban bypass resistance: rotating source ports does not
    /// escape a ban). Entries expire after BAN_DURATION_SECS.
    banned_ips: HashMap<IpAddr, Instant>,
    /// Consecutive outbound dial failures per address with the last-failure
    /// timestamp, for exponential reconnect backoff.
    connect_failures: HashMap<SocketAddr, (u32, Instant)>,
    /// Recent inbound accept timestamps per IP (sliding-window rate limit).
    accept_log: HashMap<IpAddr, VecDeque<Instant>>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
            channels: HashMap::new(),
            banned_ips: HashMap::new(),
            connect_failures: HashMap::new(),
            accept_log: HashMap::new(),
        }
    }

    /// Raw peer-entry count (all states). Test/soak observability.
    pub fn peer_entry_count(&self) -> usize {
        self.peers.len()
    }

    /// Live IP bans. Test/soak observability.
    pub fn ip_ban_count(&self) -> usize {
        self.banned_ips.len()
    }

    /// Tracked dial-failure records. Test/soak observability.
    pub fn connect_failure_count(&self) -> usize {
        self.connect_failures.len()
    }

    /// Number of tracked connections in any non-terminal state.
    /// Used for the global cap so handshake floods cannot exceed it.
    pub fn total_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| !matches!(p.state, PeerState::Disconnected | PeerState::Banned))
            .count()
    }

    /// Number of connections currently handshaking.
    pub fn handshake_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| matches!(p.state, PeerState::Connecting | PeerState::Handshaking))
            .count()
    }

    /// Connections from one IP in any non-terminal state (anti-Sybil).
    pub fn count_by_ip(&self, ip: &IpAddr) -> usize {
        self.peers
            .values()
            .filter(|p| {
                &p.addr.ip() == ip
                    && !matches!(p.state, PeerState::Disconnected | PeerState::Banned)
            })
            .count()
    }

    /// True if the address is tracked in an active state
    /// (duplicate-connection guard).
    pub fn is_tracked_active(&self, addr: &SocketAddr) -> bool {
        matches!(
            self.peers.get(addr).map(|p| &p.state),
            Some(PeerState::Connecting)
                | Some(PeerState::Connected)
                | Some(PeerState::Handshaking)
                | Some(PeerState::Ready)
        )
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        self.peers
            .entry(addr)
            .or_insert_with(|| PeerInfo::new(addr));
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        // Preserve ban records: a banned peer keeps its entry (marked Banned)
        // so reconnect attempts are still rejected. The channel is always
        // dropped. Expired bans are reaped by prune_disconnected.
        let keep_ban = self.peers.get(addr).map(|p| p.is_banned()).unwrap_or(false);
        self.channels.remove(addr);
        if keep_ban {
            if let Some(peer) = self.peers.get_mut(addr) {
                peer.state = PeerState::Banned;
                peer.connected_at = None;
                peer.last_ping_nonce = None;
            }
        } else {
            self.peers.remove(addr);
        }
    }

    pub fn get_peer(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    pub fn get_peer_mut(&mut self, addr: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(addr)
    }

    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| matches!(p.state, PeerState::Ready))
            .count()
    }

    pub fn ready_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Ready && !p.is_banned())
            .collect()
    }

    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| !matches!(p.state, PeerState::Disconnected) && !p.is_banned())
            .collect()
    }

    pub fn need_more_peers(&self) -> bool {
        self.connected_count() < MAX_OUTBOUND_PEERS
    }

    pub fn random_peer(&self) -> Option<&PeerInfo> {
        let ready: Vec<&PeerInfo> = self.ready_peers();
        if ready.is_empty() {
            return None;
        }
        let idx = (std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize)
            % ready.len();
        ready.into_iter().nth(idx)
    }

    pub fn set_channel(&mut self, addr: SocketAddr, tx: mpsc::Sender<Vec<u8>>) {
        self.channels.insert(addr, tx);
    }

    pub fn get_channel(&self, addr: &SocketAddr) -> Option<&mpsc::Sender<Vec<u8>>> {
        self.channels.get(addr)
    }

    pub fn ban_peer(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.score = BAN_SCORE_THRESHOLD - 1;
            peer.ban_until = Some(Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
            peer.state = PeerState::Banned;
        }
        self.ban_ip(addr.ip());
        self.evict_old_bans_if_needed();
    }

    /// IP ban check with lazy expiry. True while the ban is live.
    pub fn is_ip_banned(&mut self, ip: &IpAddr) -> bool {
        match self.banned_ips.get(ip) {
            Some(until) if Instant::now() < *until => true,
            Some(_) => {
                self.banned_ips.remove(ip);
                false
            }
            None => false,
        }
    }

    /// Ban an IP for BAN_DURATION_SECS (bypass resistance across ports).
    pub fn ban_ip(&mut self, ip: IpAddr) {
        if self.banned_ips.len() >= MAX_BANNED_RECORDS {
            // Evict the oldest expiry to bound memory under address rotation.
            if let Some(oldest) = self
                .banned_ips
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(ip, _)| *ip)
            {
                self.banned_ips.remove(&oldest);
            }
        }
        self.banned_ips
            .insert(ip, Instant::now() + Duration::from_secs(BAN_DURATION_SECS));
    }

    /// Gate for inbound connections. Cheap: no allocation, no I/O.
    /// Enforced BEFORE spawning a connection task.
    pub fn can_accept_inbound(&mut self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        if self.is_ip_banned(&ip) {
            return false;
        }
        if let Some(p) = self.peers.get(addr) {
            if p.is_banned() {
                return false;
            }
        }
        if self.is_tracked_active(addr) {
            return false;
        }
        if self.total_count() >= MAX_TOTAL_PEERS {
            return false;
        }
        if self.handshake_count() >= MAX_HANDSHAKE_CONCURRENT {
            return false;
        }
        if self.count_by_ip(&ip) >= MAX_PER_IP_PEERS {
            return false;
        }
        // Rate gate LAST: only admitted attempts consume budget, so the
        // budget measures spawned handshakes (the expensive part).
        if !self.check_accept_rate(&ip, Instant::now()) {
            return false;
        }
        true
    }

    /// Sliding-window inbound accept accounting. Returns false when this IP
    /// already used its burst within the window. Passing calls record a
    /// timestamp; rejections are silent (no score — busy NATs must not ban).
    /// Testable core takes an explicit `now`.
    pub fn check_accept_rate(&mut self, ip: &IpAddr, now: Instant) -> bool {
        if self.accept_log.len() >= MAX_TRACKED_ADDRS {
            // Reap idle IPs (no accepts within 2 windows) to bound memory,
            // then oldest-first so an all-fresh flood still cannot grow the
            // map (evicted IPs simply restart their budget on next attempt;
            // global concurrency caps contain the actual resource use).
            let cutoff = Duration::from_secs(ACCEPT_WINDOW_SECS * 2);
            self.accept_log.retain(|_, log| {
                log.back()
                    .map(|t| now.duration_since(*t) < cutoff)
                    .unwrap_or(false)
            });
            while self.accept_log.len() >= MAX_TRACKED_ADDRS {
                let oldest = self
                    .accept_log
                    .iter()
                    .min_by_key(|(_, log)| log.back().cloned())
                    .map(|(ip, _)| *ip);
                match oldest {
                    Some(ip) => {
                        self.accept_log.remove(&ip);
                    }
                    None => break,
                }
            }
        }
        let log = self.accept_log.entry(*ip).or_default();
        while log
            .front()
            .map(|t| now.duration_since(*t).as_secs() >= ACCEPT_WINDOW_SECS)
            .unwrap_or(false)
        {
            log.pop_front();
        }
        if log.len() >= ACCEPT_BURST_PER_IP {
            return false;
        }
        log.push_back(now);
        true
    }

    /// Gate for outbound dials. Cheap: no allocation, no I/O.
    pub fn can_dial(&mut self, addr: &SocketAddr) -> bool {
        let ip = addr.ip();
        if self.is_ip_banned(&ip) {
            return false;
        }
        if let Some(p) = self.peers.get(addr) {
            if p.is_banned() {
                return false;
            }
        }
        if self.is_tracked_active(addr) {
            return false;
        }
        if self.total_count() >= MAX_TOTAL_PEERS {
            return false;
        }
        if self.count_by_ip(&ip) >= MAX_PER_IP_PEERS {
            return false;
        }
        if !self.can_retry(addr) {
            return false;
        }
        true
    }

    /// Record a failed outbound dial. Small score cost plus a timestamp
    /// for exponential backoff. Releases the reserved slot (Disconnected)
    /// while keeping the failure history so backoff still applies.
    pub fn record_connect_failure(&mut self, addr: &SocketAddr) {
        if self.connect_failures.len() >= MAX_TRACKED_ADDRS {
            // Reap stale records (backoff long expired) to bound memory,
            // then oldest-first so an all-fresh flood still cannot grow it.
            // Operator-configured peer sets are tiny; this only triggers
            // under address-rotation abuse of the public connect() API.
            let cutoff = Duration::from_secs(MAX_RECONNECT_BACKOFF_SECS * 2);
            self.connect_failures
                .retain(|_, (_, t)| t.elapsed() < cutoff);
            while self.connect_failures.len() >= MAX_TRACKED_ADDRS {
                let oldest = self
                    .connect_failures
                    .iter()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(a, _)| *a);
                match oldest {
                    Some(a) => {
                        self.connect_failures.remove(&a);
                    }
                    None => break,
                }
            }
        }
        let entry = self
            .connect_failures
            .entry(*addr)
            .or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = Instant::now();
        self.add_peer(*addr);
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.score = peer.score.saturating_sub(SCORE_CONNECT_FAIL);
            if !peer.is_banned() {
                peer.state = PeerState::Disconnected;
            }
        }
    }

    /// Clear dial-failure history after a successful handshake.
    pub fn clear_connect_failures(&mut self, addr: &SocketAddr) {
        self.connect_failures.remove(addr);
    }

    /// Backoff for one address: `min(300, 5 * 2^(failures-1))` seconds must
    /// have elapsed since the last failure. Deterministic (no jitter) so the
    /// behavior is testable; callers add jitter if desired.
    pub fn backoff_secs(failures: u32) -> u64 {
        if failures == 0 {
            return 0;
        }
        let shift = failures.saturating_sub(1).min(6);
        (RECONNECT_BASE_SECS << shift).min(MAX_RECONNECT_BACKOFF_SECS)
    }

    /// True if enough time has passed to retry a failed dial.
    pub fn can_retry(&self, addr: &SocketAddr) -> bool {
        match self.connect_failures.get(addr) {
            None => true,
            Some((failures, last)) => last.elapsed().as_secs() >= Self::backoff_secs(*failures),
        }
    }

    /// Score a handshake/protocol failure; mirrors bans to the IP level so
    /// the offender cannot reconnect from a new source port.
    pub fn note_handshake_failure(&mut self, addr: &SocketAddr) {
        self.add_peer(*addr);
        let banned = if let Some(peer) = self.peers.get_mut(addr) {
            peer.score_bad(SCORE_MALFORMED);
            peer.is_banned()
        } else {
            false
        };
        if banned {
            self.ban_ip(addr.ip());
            self.evict_old_bans_if_needed();
        }
    }

    /// Score an invalid consensus object from a peer; mirrors bans to IP.
    pub fn note_invalid_object(&mut self, addr: &SocketAddr, points: i32) {
        self.add_peer(*addr);
        let banned = if let Some(peer) = self.peers.get_mut(addr) {
            peer.score_bad(points);
            peer.is_banned()
        } else {
            false
        };
        if banned {
            self.ban_ip(addr.ip());
            self.evict_old_bans_if_needed();
        }
    }

    fn evict_old_bans_if_needed(&mut self) {
        let banned_count =
            self.peers.values().filter(|p| p.is_banned()).count() + self.banned_ips.len();
        if banned_count <= MAX_BANNED_RECORDS {
            return;
        }
        let mut with_expiry: Vec<(SocketAddr, Instant)> = self
            .peers
            .iter()
            .filter_map(|(a, p)| p.ban_until.map(|u| (*a, u)))
            .collect();
        with_expiry.sort_by_key(|(_, u)| *u);
        for (a, _) in with_expiry.into_iter().take(16) {
            self.peers.remove(&a);
            self.channels.remove(&a);
        }
    }

    pub fn prune_disconnected(&mut self) {
        // Reaps Disconnected entries, but never live bans (they must survive
        // reconnect attempts until expiry).
        let addrs: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Disconnected && !p.is_banned())
            .map(|(a, _)| *a)
            .collect();
        for addr in addrs {
            self.peers.remove(&addr);
            self.channels.remove(&addr);
        }
    }

    pub fn peers_for_announcement(&self) -> Vec<SocketAddr> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Ready && !p.is_banned())
            .map(|p| p.addr)
            .collect()
    }

    /// Decay scores for all connected peers toward zero.
    pub fn decay_all_scores(&mut self, amount: i32) {
        for peer in self.peers.values_mut() {
            peer.score_decay(amount);
        }
    }

    /// Ready peers silent for longer than `idle_for` (liveness check for
    /// idle eviction). Banned peers are never returned.
    pub fn idle_peers(&self, idle_for: Duration) -> Vec<SocketAddr> {
        let now = Instant::now();
        self.peers
            .values()
            .filter(|p| {
                p.state == PeerState::Ready
                    && !p.is_banned()
                    && p.last_seen
                        .map(|t| now.duration_since(t) > idle_for)
                        .unwrap_or(false)
            })
            .map(|p| p.addr)
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_addr(n: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), n)
    }

    #[test]
    fn test_add_and_get_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        assert!(pm.get_peer(&addr).is_some());
    }

    #[test]
    fn test_remove_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.remove_peer(&addr);
        assert!(pm.get_peer(&addr).is_none());
    }

    #[test]
    fn test_connected_count() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        pm.add_peer(a1);
        pm.add_peer(a2);
        assert_eq!(pm.connected_count(), 0);

        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        assert_eq!(pm.connected_count(), 1);
    }

    #[test]
    fn test_need_more_peers() {
        let mut pm = PeerManager::new();
        assert!(pm.need_more_peers());

        for i in 0..MAX_OUTBOUND_PEERS {
            let addr = test_addr((8333 + i) as u16);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
        }
        assert!(!pm.need_more_peers());
    }

    #[test]
    fn test_peer_scoring() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);

        for _ in 0..5 {
            pm.get_peer_mut(&addr).unwrap().score_tick();
        }
        assert_eq!(pm.get_peer(&addr).unwrap().score, 5);

        pm.get_peer_mut(&addr).unwrap().score_bad(210);
        assert!(pm.get_peer(&addr).unwrap().is_banned());
    }

    #[test]
    fn test_ban_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);
        assert!(pm.get_peer(&addr).unwrap().is_banned());
        assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Banned);
    }

    #[test]
    fn test_peer_info_new() {
        let addr = test_addr(9000);
        let info = PeerInfo::new(addr);
        assert_eq!(info.addr, addr);
        assert_eq!(info.state, PeerState::Disconnected);
        assert_eq!(info.score, 0);
        assert!(!info.is_banned());
    }

    #[test]
    fn test_prune_disconnected() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        pm.add_peer(a1);
        pm.add_peer(a2);
        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        pm.prune_disconnected();
        assert!(pm.get_peer(&a1).is_some());
        assert!(pm.get_peer(&a2).is_none());
    }

    #[test]
    fn test_ready_peers() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        let a3 = test_addr(8335);
        pm.add_peer(a1);
        pm.add_peer(a2);
        pm.add_peer(a3);
        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        pm.get_peer_mut(&a2).unwrap().state = PeerState::Connected;
        pm.ban_peer(&a3);

        let ready = pm.ready_peers();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].addr, a1);
    }

    // ========================================================================
    // Rate Limiter Tests
    // ========================================================================

    #[test]
    fn test_rate_limiter_allows_burst() {
        let mut limiter = RateLimiter::new(100);
        // Should allow the full burst (100 tokens)
        for _ in 0..100 {
            assert!(limiter.try_consume());
        }
        // 101st should fail
        assert!(!limiter.try_consume());
    }

    #[test]
    fn test_rate_limiter_refills() {
        let mut limiter = RateLimiter::new(100);
        // Consume all tokens
        for _ in 0..100 {
            limiter.try_consume();
        }
        assert!(!limiter.try_consume());
        // Simulate time passing (1 second)
        limiter.last_refill = Instant::now() - Duration::from_secs(1);
        assert!(limiter.try_consume());
    }

    #[test]
    fn test_peer_rate_limit_enforced() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;

        // Consume all message tokens
        let peer = pm.get_peer_mut(&addr).unwrap();
        for _ in 0..PEER_MSG_RATE_LIMIT {
            assert!(peer.check_msg_rate());
        }
        assert!(!peer.check_msg_rate());
    }

    #[test]
    fn test_peer_tx_rate_limit_separate() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);

        let peer = pm.get_peer_mut(&addr).unwrap();
        // Consume all tx tokens
        for _ in 0..PEER_TX_RATE_LIMIT {
            assert!(peer.check_tx_rate());
        }
        assert!(!peer.check_tx_rate());
        // Message rate still works (separate limiter)
        assert!(peer.check_msg_rate());
    }

    // ========================================================================
    // Connection Limit Tests (adversarial)
    // ========================================================================

    fn test_ip(n: u8) -> IpAddr {
        IpAddr::V4([10, 0, 0, n].into())
    }

    fn test_sock(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    fn ready_peer(pm: &mut PeerManager, addr: SocketAddr) {
        pm.add_peer(addr);
        let peer = pm.get_peer_mut(&addr).unwrap();
        peer.state = PeerState::Ready;
        peer.last_seen = Some(Instant::now());
    }

    #[test]
    fn test_total_count_ignores_terminal_states() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        pm.add_peer(a1);
        pm.add_peer(a2);
        // Both Disconnected → not counted.
        assert_eq!(pm.total_count(), 0);
        pm.get_peer_mut(&a1).unwrap().state = PeerState::Handshaking;
        pm.get_peer_mut(&a2).unwrap().state = PeerState::Ready;
        assert_eq!(pm.total_count(), 2);
        // Handshake states count toward the cap (flood resistance).
        assert_eq!(pm.handshake_count(), 1);
    }

    #[test]
    fn test_count_by_ip_keyed_by_ip_not_port() {
        let mut pm = PeerManager::new();
        let ip = test_ip(7);
        for port in [8333u16, 8334, 8335] {
            let addr = test_sock(ip, port);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
        }
        // Same IP, three source ports → counted together.
        assert_eq!(pm.count_by_ip(&ip), 3);
        assert_eq!(pm.count_by_ip(&test_ip(8)), 0);
    }

    #[test]
    fn test_accept_rejects_duplicate_active() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.get_peer_mut(&addr).unwrap().state = PeerState::Connecting;
        assert!(!pm.can_accept_inbound(&addr));
        assert!(!pm.can_dial(&addr));
    }

    #[test]
    fn test_accept_enforces_total_cap() {
        let mut pm = PeerManager::new();
        // Fill every slot with distinct IPs (avoids the per-IP cap).
        for i in 0..MAX_TOTAL_PEERS {
            let addr = test_sock(test_ip(i as u8 + 1), 10000 + i as u16);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
        }
        assert_eq!(pm.total_count(), MAX_TOTAL_PEERS);
        let extra = test_sock(test_ip(200), 9999);
        assert!(!pm.can_accept_inbound(&extra));
        assert!(!pm.can_dial(&extra));
    }

    #[test]
    fn test_accept_enforces_per_ip_cap() {
        let mut pm = PeerManager::new();
        let ip = test_ip(9);
        for port in 0..MAX_PER_IP_PEERS {
            let addr = test_sock(ip, 9000 + port as u16);
            assert!(pm.can_accept_inbound(&addr), "slot {} should admit", port);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
        }
        // One IP cannot take a fourth slot by rotating source ports.
        let fourth = test_sock(ip, 9999);
        assert!(!pm.can_accept_inbound(&fourth));
        assert!(!pm.can_dial(&fourth));
        // A different IP is unaffected.
        assert!(pm.can_accept_inbound(&test_sock(test_ip(10), 9999)));
    }

    #[test]
    fn test_accept_enforces_handshake_cap() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_HANDSHAKE_CONCURRENT {
            let addr = test_sock(test_ip(20 + i as u8), 9000 + i as u16);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Handshaking;
        }
        assert_eq!(pm.handshake_count(), MAX_HANDSHAKE_CONCURRENT);
        let extra = test_sock(test_ip(100), 9999);
        assert!(!pm.can_accept_inbound(&extra));
    }

    // ========================================================================
    // Scoring / Ban Tests (adversarial)
    // ========================================================================

    #[test]
    fn test_scoring_tiers_reach_ban_deterministically() {
        // Malformed (20): ten strikes ban (200/20).
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        for _ in 0..9 {
            pm.note_handshake_failure(&addr);
            assert!(!pm.get_peer(&addr).unwrap().is_banned());
        }
        pm.note_handshake_failure(&addr);
        assert!(pm.get_peer(&addr).unwrap().is_banned());

        // Invalid tx (50): four strikes ban.
        let mut pm = PeerManager::new();
        let addr = test_addr(8334);
        for _ in 0..4 {
            pm.note_invalid_object(&addr, SCORE_INVALID_TX);
        }
        assert!(pm.get_peer(&addr).unwrap().is_banned());

        // Invalid block (100): two strikes ban.
        let mut pm = PeerManager::new();
        let addr = test_addr(8335);
        for _ in 0..2 {
            pm.note_invalid_object(&addr, SCORE_INVALID_BLOCK);
        }
        assert!(pm.get_peer(&addr).unwrap().is_banned());

        // Ordinary connect failures (5) never ban on their own.
        let mut pm = PeerManager::new();
        let addr = test_addr(8336);
        for _ in 0..10 {
            pm.record_connect_failure(&addr);
        }
        assert!(!pm.get_peer(&addr).unwrap().is_banned());
    }

    #[test]
    fn test_ip_ban_blocks_port_rotation() {
        let mut pm = PeerManager::new();
        let ip = test_ip(30);
        let first = test_sock(ip, 8333);
        // Ban via repeated handshake failures.
        for _ in 0..10 {
            pm.note_handshake_failure(&first);
        }
        assert!(pm.get_peer(&first).unwrap().is_banned());
        // Same IP, fresh source port: still rejected (bypass resistance).
        let rotated = test_sock(ip, 4444);
        assert!(!pm.can_accept_inbound(&rotated));
        assert!(!pm.can_dial(&rotated));
        // Unrelated IP unaffected.
        assert!(pm.can_accept_inbound(&test_sock(test_ip(31), 4444)));
    }

    #[test]
    fn test_remove_peer_preserves_live_bans() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);
        // Disconnect cleanup must not erase the ban record.
        pm.remove_peer(&addr);
        assert!(pm.get_peer(&addr).is_some());
        assert!(pm.get_peer(&addr).unwrap().is_banned());
        assert!(!pm.can_accept_inbound(&addr));
        // Channels are always dropped.
        assert!(pm.get_channel(&addr).is_none());
    }

    #[test]
    fn test_prune_keeps_live_bans_drops_clean() {
        let mut pm = PeerManager::new();
        let banned = test_addr(8333);
        let clean = test_addr(8334);
        pm.add_peer(banned);
        pm.add_peer(clean);
        pm.ban_peer(&banned);
        pm.get_peer_mut(&banned).unwrap().state = PeerState::Disconnected;
        pm.prune_disconnected();
        assert!(pm.get_peer(&banned).is_some());
        assert!(pm.get_peer(&clean).is_none());
    }

    // ========================================================================
    // Backoff / Idle / Concurrency Tests (adversarial)
    // ========================================================================

    #[test]
    fn test_backoff_secs_doubles_to_cap() {
        assert_eq!(PeerManager::backoff_secs(0), 0);
        assert_eq!(PeerManager::backoff_secs(1), 5);
        assert_eq!(PeerManager::backoff_secs(2), 10);
        assert_eq!(PeerManager::backoff_secs(3), 20);
        assert_eq!(PeerManager::backoff_secs(4), 40);
        assert_eq!(PeerManager::backoff_secs(7), 300);
        assert_eq!(PeerManager::backoff_secs(100), 300);
        assert_eq!(PeerManager::backoff_secs(u32::MAX), 300);
    }

    #[test]
    fn test_can_retry_gates_reconnect() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        // No history: free to dial.
        assert!(pm.can_retry(&addr));
        pm.record_connect_failure(&addr);
        // Immediate retry refused (5s backoff).
        assert!(!pm.can_retry(&addr));
        assert!(!pm.can_dial(&addr));
        // Failure in the past beyond backoff: allowed again.
        pm.connect_failures
            .insert(addr, (1, Instant::now() - Duration::from_secs(6)));
        assert!(pm.can_retry(&addr));
        // Success clears history.
        pm.clear_connect_failures(&addr);
        assert!(pm.can_retry(&addr));
    }

    #[test]
    fn test_idle_peers_lists_only_stale_ready() {
        let mut pm = PeerManager::new();
        let stale = test_addr(8333);
        let fresh = test_addr(8334);
        let handshaking = test_addr(8335);
        ready_peer(&mut pm, stale);
        ready_peer(&mut pm, fresh);
        pm.add_peer(handshaking);
        pm.get_peer_mut(&handshaking).unwrap().state = PeerState::Handshaking;
        // Age only one peer past the eviction horizon.
        pm.get_peer_mut(&stale).unwrap().last_seen =
            Some(Instant::now() - Duration::from_secs(IDLE_EVICT_SECS + 1));
        let idle = pm.idle_peers(Duration::from_secs(IDLE_EVICT_SECS));
        assert_eq!(idle, vec![stale]);
    }

    #[test]
    fn test_accept_rate_burst_then_rejects() {
        let mut pm = PeerManager::new();
        let ip = test_ip(50);
        let now = Instant::now();
        for _ in 0..ACCEPT_BURST_PER_IP {
            assert!(pm.check_accept_rate(&ip, now));
        }
        // Burst exhausted within the window.
        assert!(!pm.check_accept_rate(&ip, now));
        // Other IPs unaffected.
        assert!(pm.check_accept_rate(&test_ip(51), now));
    }

    #[test]
    fn test_accept_rate_refills_after_window() {
        let mut pm = PeerManager::new();
        let ip = test_ip(52);
        let then = Instant::now() - Duration::from_secs(ACCEPT_WINDOW_SECS + 1);
        for _ in 0..ACCEPT_BURST_PER_IP {
            assert!(pm.check_accept_rate(&ip, then));
        }
        // Old entries aged out of the window: budget restored.
        assert!(pm.check_accept_rate(&ip, Instant::now()));
    }

    #[test]
    fn test_accept_log_bounded_under_ip_rotation() {
        let mut pm = PeerManager::new();
        let now = Instant::now();
        // Far more distinct IPs than the cap: map must stay bounded and
        // the newest IP must still be admittable.
        for i in 0..(MAX_TRACKED_ADDRS + 100) {
            let ip = IpAddr::V4([10, (i >> 8) as u8, (i & 0xFF) as u8, 1].into());
            assert!(pm.check_accept_rate(&ip, now));
        }
        assert!(pm.accept_log.len() <= MAX_TRACKED_ADDRS);
    }

    #[test]
    fn test_connect_failures_bounded() {
        let mut pm = PeerManager::new();
        // Fill with stale records, then one fresh failure must prune.
        for i in 0..(MAX_TRACKED_ADDRS + 10) {
            let addr = test_sock(
                IpAddr::V4([10, (i >> 8) as u8, (i & 0xFF) as u8, 2].into()),
                8333,
            );
            pm.record_connect_failure(&addr);
            // Backdate everything so the next insert reaps.
            if let Some(entry) = pm.connect_failures.get_mut(&addr) {
                entry.1 = Instant::now() - Duration::from_secs(3600);
            }
        }
        let fresh = test_sock(test_ip(60), 8333);
        pm.record_connect_failure(&fresh);
        assert!(pm.connect_failure_count() <= MAX_TRACKED_ADDRS);
        // Fresh record survived pruning.
        assert!(pm.connect_failures.contains_key(&fresh));
    }

    #[test]
    fn test_observability_getters() {
        let mut pm = PeerManager::new();
        assert_eq!(pm.peer_entry_count(), 0);
        assert_eq!(pm.ip_ban_count(), 0);
        assert_eq!(pm.connect_failure_count(), 0);
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);
        pm.record_connect_failure(&test_addr(8334));
        assert_eq!(pm.peer_entry_count(), 2);
        assert_eq!(pm.ip_ban_count(), 1);
        assert_eq!(pm.connect_failure_count(), 1);
    }

    #[test]
    fn test_concurrent_gate_act_check_stays_capped() {
        use std::sync::{Arc, Mutex};
        // Simulate N racing acceptors doing gate+reserve under one lock,
        // exactly as run_inbound does. Final state must respect the per-IP
        // cap no matter the interleaving.
        let pm = Arc::new(Mutex::new(PeerManager::new()));
        let ip = test_ip(40);
        let mut handles = Vec::new();
        for t in 0..8u16 {
            let pm = pm.clone();
            handles.push(std::thread::spawn(move || {
                for p in 0..4u16 {
                    let addr = test_sock(ip, 9000 + t * 4 + p);
                    let mut pm = pm.lock().unwrap();
                    if pm.can_accept_inbound(&addr) {
                        pm.add_peer(addr);
                        pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let pm = pm.lock().unwrap();
        assert!(pm.count_by_ip(&ip) <= MAX_PER_IP_PEERS);
        assert!(pm.total_count() <= MAX_TOTAL_PEERS);
    }

    #[test]
    fn test_disconnect_cycles_leave_no_entries() {
        // Long-run churn shape: hundreds of connect/disconnect cycles from
        // rotating source ports must not accumulate peer entries, channels,
        // or handshake slots. Non-banned disconnects are removed outright.
        let mut pm = PeerManager::new();
        for i in 0..500u16 {
            let addr = test_addr(20000 + i);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
            pm.remove_peer(&addr);
            assert!(pm.get_peer(&addr).is_none());
        }
        assert_eq!(pm.peer_entry_count(), 0);
        assert_eq!(pm.total_count(), 0);
        assert_eq!(pm.handshake_count(), 0);
    }

    #[test]
    fn test_subthreshold_scores_never_ban_across_addrs() {
        // Scoring is per-SocketAddr: one invalid tx (-50) per connection from
        // rotating ports never reaches the -200 threshold, so no peer ban and
        // no IP ban may result. This pins the exact threshold semantics: bans
        // require sustained abuse WITHIN one connection (proven by the ban
        // e2e), while caps/rate-limits contain the sub-threshold case.
        let mut pm = PeerManager::new();
        for i in 0..20u16 {
            pm.note_invalid_object(&test_addr(30000 + i), SCORE_INVALID_TX);
        }
        assert_eq!(
            pm.ip_ban_count(),
            0,
            "rotating ports must not trigger IP ban"
        );
        assert!(
            pm.peers.values().all(|p| !p.is_banned()),
            "no single -50 strike may ban"
        );
        // Same offender, one connection, four strikes: banned + IP mirrored.
        let addr = test_addr(31000);
        for _ in 0..4 {
            pm.note_invalid_object(&addr, SCORE_INVALID_TX);
        }
        assert!(pm.get_peer(&addr).unwrap().is_banned());
        assert_eq!(pm.ip_ban_count(), 1);
        // Redial gate: new ports from the banned IP are refused everywhere.
        assert!(!pm.can_accept_inbound(&test_addr(31001)));
        assert!(!pm.can_dial(&test_addr(31001)));
    }
}
