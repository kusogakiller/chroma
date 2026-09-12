use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::peer::PeerManager;

pub const SEED_NODES: &[&str] = &["seed.chroma.network:8333"];
pub const DNS_SEEDS: &[&str] = &["seed.chroma.network"];
pub const TESTNET_SEED_NODES: &[&str] = &["seed-testnet.chroma.network:18333"];
pub const TESTNET_DNS_SEEDS: &[&str] = &["seed-testnet.chroma.network"];
pub const MAX_SEED_FAILURES: usize = 3;
const DNS_TIMEOUT_SECS: u64 = 3;

pub type SeedResolver = Arc<dyn Fn(&str) -> Vec<SocketAddr> + Send + Sync>;

pub struct Discovery {
    seed_failures: usize,
    resolver: Option<SeedResolver>,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Discovery {
            seed_failures: 0,
            resolver: None,
        }
    }

    pub fn with_resolver(resolver: SeedResolver) -> Self {
        Discovery {
            seed_failures: 0,
            resolver: Some(resolver),
        }
    }

    async fn resolve(&self, seed: &str) -> std::io::Result<Vec<SocketAddr>> {
        if let Some(ref resolver) = self.resolver {
            return Ok(resolver(seed));
        }
        resolve_seed(seed).await
    }

    pub async fn discover_peers(
        &mut self,
        peer_manager: Arc<RwLock<PeerManager>>,
        connect_addrs: &[SocketAddr],
        network: &crate::NetworkConfig,
    ) -> Vec<SocketAddr> {
        let mut found = Vec::new();

        // Operator-configured addresses are trusted as-is (regtest loopback
        // included) and never filtered.
        for &addr in connect_addrs {
            let mut pm = peer_manager.write().await;
            if !pm.get_peer(&addr).is_some() {
                pm.add_peer(addr);
                found.push(addr);
            }
        }

        if network.regtest {
            return found;
        }

        // Trust boundary: an injected resolver is explicit operator
        // configuration (same class as `--connect`, which bypasses filtering
        // entirely). Raw DNS answers stay untrusted and filtered.
        let trusted = self.resolver.is_some();

        let (seeds, dns) = if network.testnet {
            (TESTNET_SEED_NODES, TESTNET_DNS_SEEDS)
        } else {
            (SEED_NODES, DNS_SEEDS)
        };

        for seed in seeds {
            match self.resolve(seed).await {
                Ok(addrs) => {
                    for a in addrs {
                        // DNS results are untrusted: drop non-routable
                        // addresses (DNS rebinding / poisoning defense).
                        if !trusted && !is_routable_peer_addr(&a) {
                            continue;
                        }
                        let mut pm = peer_manager.write().await;
                        if pm.get_peer(&a).is_none() {
                            pm.add_peer(a);
                            found.push(a);
                        }
                    }
                    self.seed_failures = 0;
                }
                Err(_) => {
                    self.seed_failures += 1;
                    if self.seed_failures >= MAX_SEED_FAILURES {
                        break;
                    }
                }
            }
        }

        for seed in dns {
            match self.resolve(seed).await {
                Ok(addrs) => {
                    for a in addrs {
                        if !trusted && !is_routable_peer_addr(&a) {
                            continue;
                        }
                        let mut pm = peer_manager.write().await;
                        if pm.get_peer(&a).is_none() {
                            pm.add_peer(a);
                            found.push(a);
                        }
                    }
                    self.seed_failures = 0;
                }
                Err(_) => {
                    self.seed_failures += 1;
                    if self.seed_failures >= MAX_SEED_FAILURES {
                        break;
                    }
                }
            }
        }

        found
    }
}

/// True for addresses we will dial from DNS discovery results.
/// Rejects loopback, unspecified, multicast, and other non-routable
/// addresses that indicate DNS poisoning/rebinding. Private (RFC1918)
/// addresses are allowed: operators run nodes behind NAT and seeds may
/// legitimately serve them. Explicit `--connect` addresses bypass this
/// filter entirely.
pub fn is_routable_peer_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_link_local())
        }
        std::net::IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()),
    }
}

async fn resolve_seed(seed: &str) -> std::io::Result<Vec<SocketAddr>> {
    let seed = seed.to_string();
    tokio::time::timeout(
        std::time::Duration::from_secs(DNS_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || {
            seed.to_socket_addrs().map(|iter| iter.collect::<Vec<_>>())
        }),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS resolution timed out"))?
    .map_err(std::io::Error::other)
    .and_then(|r| r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_discovery() {
        let d = Discovery::new();
        assert_eq!(d.seed_failures, 0);
    }

    #[test]
    fn test_routable_filter_rejects_loopback_and_special() {
        // DNS rebinding defense: never dial these from discovery results.
        for addr in [
            "127.0.0.1:8333",
            "0.0.0.0:8333",
            "224.0.0.1:8333",
            "255.255.255.255:8333",
            "192.0.2.1:8333",
            "[::1]:8333",
            "[::]:8333",
            "[ff02::1]:8333",
        ] {
            let a: SocketAddr = addr.parse().unwrap();
            assert!(!is_routable_peer_addr(&a), "must reject {}", addr);
        }
    }

    #[test]
    fn test_routable_filter_allows_public_and_private() {
        // Public IPs and operator-NAT private IPs are dialable.
        for addr in ["8.8.4.4:8333", "10.0.0.5:8333", "192.168.1.20:8333"] {
            let a: SocketAddr = addr.parse().unwrap();
            assert!(is_routable_peer_addr(&a), "must allow {}", addr);
        }
    }
}
