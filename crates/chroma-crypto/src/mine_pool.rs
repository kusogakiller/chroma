//! Parallel RandomX nonce search over worker-local VMs.
//!
//! The process-global RandomX worker (`randomx.rs`) serializes every hash
//! through ONE thread, so mining through it is single-threaded no matter how
//! many Tokio blocking threads wait on it. This pool gives each mining worker
//! its own cache + VM (`1 worker = 1 RandomXVM`; the reference types are
//! `!Send`, so sharing one VM across threads is not an option) and splits
//! the nonce range into disjoint lanes. Validation keeps using the global
//! worker untouched.

use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};

use randomx_rs::{RandomXFlag, RandomXVM};

use crate::randomx::{build_vm, hash_meets_target};
use chroma_core::hash::Hash;

/// Sentinel for "no lane has won this search yet".
const NO_WINNER: u64 = u64::MAX;

/// A mining job: every input is fixed except the nonce range.
#[derive(Clone, Debug)]
pub struct MineJob {
    /// Canonical seed for the block height (see `seed_for_height`).
    pub seed: [u8; 32],
    /// Block previous-hash (PoW input prefix).
    pub prev: Hash,
    /// Block tx-merkle-root (PoW input prefix).
    pub merkle: Hash,
    /// First nonce, inclusive.
    pub start: u64,
    /// Nonce count: the searched range is `start..start.saturating_add(count)`.
    pub count: u64,
    /// Full 256-bit target, big-endian (see `hash_meets_target`).
    pub target: [u8; 32],
}

/// A winning nonce together with the hash that met the target, as computed
/// by the winning worker's own VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoundNonce {
    pub nonce: u64,
    pub hash: [u8; 32],
}

enum Cmd {
    Search {
        job: MineJob,
        done: mpsc::Sender<Option<FoundNonce>>,
        /// First winner slot (`NO_WINNER` while open), fresh per search.
        found: Arc<AtomicU64>,
        /// External abort (shutdown). Long-lived; never set by the pool.
        quit: Arc<AtomicBool>,
    },
}

/// Nonce lane for `worker` of `workers` over `start..end` (exclusive end):
/// `start + worker`, stepping by `workers`. Lanes are disjoint by
/// construction and their union is the whole range.
fn lane_iter(start: u64, end: u64, workers: u64, worker: u64) -> impl Iterator<Item = u64> {
    let mut n = start.saturating_add(worker);
    std::iter::from_fn(move || {
        if n >= end {
            return None;
        }
        let cur = n;
        n = n.saturating_add(workers);
        Some(cur)
    })
}

fn pow_input(prev: &Hash, merkle: &Hash, nonce: u64) -> Vec<u8> {
    let mut input = Vec::with_capacity(72);
    input.extend_from_slice(prev.as_bytes());
    input.extend_from_slice(merkle.as_bytes());
    input.extend_from_slice(&nonce.to_le_bytes());
    input
}

fn worker_main(id: u64, workers: u64, rx: mpsc::Receiver<Cmd>) {
    // The VM owns its linked cache (see `RandomXVM::new`), so keeping the
    // VM alive keeps the cache alive — same ownership as the global worker.
    let mut vm: Option<([u8; 32], RandomXVM)> = None;
    let flags = RandomXFlag::get_recommended_flags();
    // Channel close (pool drop) is the only exit path.
    while let Ok(Cmd::Search {
        job,
        done,
        found,
        quit,
    }) = rx.recv()
    {
        let end = job.start.saturating_add(job.count);
        // (Re)build the worker-local VM only when the seed changed.
        let seeded = vm.as_ref().map(|(s, _)| s) == Some(&job.seed);
        if !seeded {
            match build_vm(flags, &job.seed) {
                Ok(v) => vm = Some((job.seed, v)),
                Err(_) => {
                    let _ = done.send(None);
                    continue;
                }
            }
        }
        let vm_ref = match vm.as_ref() {
            Some((_, v)) => v,
            None => {
                let _ = done.send(None);
                continue;
            }
        };
        let mut win = None;
        for nonce in lane_iter(job.start, end, workers, id) {
            if found.load(Ordering::Relaxed) != NO_WINNER || quit.load(Ordering::Relaxed) {
                break;
            }
            match vm_ref.calculate_hash(&pow_input(&job.prev, &job.merkle, nonce)) {
                Ok(h) => {
                    let mut out = [0u8; 32];
                    let n = h.len().min(32);
                    out[..n].copy_from_slice(&h[..n]);
                    if hash_meets_target(&Hash::from_bytes(out), &job.target) {
                        // First claim wins; losers observe `found` and quit.
                        if found
                            .compare_exchange(NO_WINNER, nonce, Ordering::SeqCst, Ordering::Relaxed)
                            .is_ok()
                        {
                            win = Some(FoundNonce { nonce, hash: out });
                        }
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = done.send(win);
    }
}

/// Parallel RandomX miner: `workers` OS threads, each with its own VM.
///
/// Created once and reused across block templates; per-search state (first
/// winner, external stop) is scoped to a single `search` call. Dropping the
/// pool closes the job channels and joins every worker: no orphaned threads.
pub struct MiningPool {
    txs: Vec<mpsc::Sender<Cmd>>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl MiningPool {
    /// Spawn `workers` hashing threads (`workers == 0` means 1).
    pub fn new(workers: usize) -> Self {
        let n = workers.max(1) as u64;
        let mut txs = Vec::with_capacity(n as usize);
        let mut handles = Vec::with_capacity(n as usize);
        for id in 0..n {
            let (tx, rx) = mpsc::channel::<Cmd>();
            txs.push(tx);
            handles.push(
                std::thread::Builder::new()
                    .name(format!("chroma-miner-{id}"))
                    .spawn(move || worker_main(id, n, rx))
                    .expect("mining worker thread must spawn"),
            );
        }
        MiningPool { txs, handles }
    }

    /// Active hashing threads.
    pub fn worker_count(&self) -> usize {
        self.txs.len()
    }

    /// Search `job` across all lanes. Returns the winning nonce with the
    /// hash that met the target, or `None` when the range is exhausted,
    /// every worker errors, or `quit` is set (shutdown/epoch abort). All
    /// workers are idle again on return.
    ///
    /// `quit` is caller-owned and long-lived: the pool only reads it, never
    /// sets it, so the same flag is safe to reuse across searches. The
    /// first-winner slot is created fresh per call.
    pub fn search(&self, job: &MineJob, quit: &Arc<AtomicBool>) -> Option<FoundNonce> {
        if job.count == 0 {
            return None;
        }
        let found = Arc::new(AtomicU64::new(NO_WINNER));
        let mut rxs = Vec::with_capacity(self.txs.len());
        for tx in &self.txs {
            let (done_tx, done_rx) = mpsc::channel();
            // A disconnected worker (impossible: threads outlive the pool)
            // counts as a failed lane.
            if tx
                .send(Cmd::Search {
                    job: job.clone(),
                    done: done_tx,
                    found: Arc::clone(&found),
                    quit: Arc::clone(quit),
                })
                .is_err()
            {
                continue;
            }
            rxs.push(done_rx);
        }
        if rxs.is_empty() {
            return None;
        }
        let mut winner = None;
        for rx in rxs {
            // A hung-up lane contributes nothing; remaining lanes decide.
            // Every reply is a genuinely valid (nonce, hash) pair claimed
            // via `found`.
            if let Ok(Some(found)) = rx.recv() {
                if winner.is_none() {
                    winner = Some(found);
                }
            }
        }
        winner
    }
}

impl Drop for MiningPool {
    fn drop(&mut self) {
        // Close every job channel first so blocked workers observe EOF.
        self.txs.clear();
        while let Some(h) = self.handles.pop() {
            let _ = h.join();
        }
    }
}

/// Default mining threads: parallelism capped for RandomX cache cost
/// (~256 MiB Argon2 cache per worker-local VM).
pub fn default_mine_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(1, 4))
        .unwrap_or(2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn covered(start: u64, count: u64, workers: usize) -> Vec<u64> {
        let mut all = Vec::new();
        for w in 0..workers {
            all.extend(lane_iter(
                start,
                start.saturating_add(count),
                workers as u64,
                w as u64,
            ));
        }
        all.sort_unstable();
        all
    }

    #[test]
    fn test_nonce_lanes_cover_range_without_overlap() {
        for workers in [1usize, 2, 4, 8] {
            for (start, count) in [(0u64, 10_000u64), (7, 10_007), (999_999, 3)] {
                let all = covered(start, count, workers);
                assert_eq!(all.len() as u64, count, "workers={workers}");
                let uniq: HashSet<u64> = all.iter().copied().collect();
                assert_eq!(uniq.len() as u64, count, "no duplicates");
                assert_eq!(all[0], start);
                assert_eq!(*all.last().unwrap(), start + count - 1);
            }
        }
    }

    #[test]
    fn test_pool_zero_workers_is_single_lane() {
        assert_eq!(MiningPool::new(0).worker_count(), 1);
    }

    /// Independent worker-local VMs must agree byte-for-byte: a winner found
    /// by a 4-worker pool, re-hashed alone by a 1-worker pool, yields the
    /// identical nonce AND identical hash. Hermetic (no global worker), so
    /// parallel test threads cannot interfere.
    #[test]
    fn test_pool_winners_agree_across_worker_counts() {
        use crate::randomx::hash_meets_target as meets;
        let seed = [0x5Au8; 32];
        let prev = Hash::from_bytes([0x11u8; 32]);
        let merkle = Hash::from_bytes([0x22u8; 32]);
        // First-byte target: ~1/16 of nonces win, exercising real lanes.
        let mut target = [0xFFu8; 32];
        target[0] = 0x0F;
        let job = MineJob {
            seed,
            prev,
            merkle,
            start: 0,
            count: 50_000,
            target,
        };
        let pool4 = MiningPool::new(4);
        let w4 = pool4
            .search(&job, &Arc::new(AtomicBool::new(false)))
            .expect("range must yield");
        assert!(
            w4.nonce < 50_000,
            "winner must come from the searched range"
        );
        assert!(meets(&Hash::from_bytes(w4.hash), &target));

        // The same nonce, hashed alone on a different pool instance: same bytes.
        let pool1 = MiningPool::new(1);
        let solo = MineJob {
            start: w4.nonce,
            count: 1,
            ..job.clone()
        };
        let w1 = pool1
            .search(&solo, &Arc::new(AtomicBool::new(false)))
            .expect("winning nonce re-hashes valid");
        assert_eq!(w1, w4, "independent VMs must agree byte-for-byte");
    }

    #[test]
    fn test_preset_stop_aborts_search() {
        let seed = [0x5Bu8; 32];
        let pool = MiningPool::new(2);
        let stop = Arc::new(AtomicBool::new(true));
        let job = MineJob {
            seed,
            prev: Hash::from_bytes([0x11u8; 32]),
            merkle: Hash::from_bytes([0x22u8; 32]),
            start: 0,
            count: 1_000_000,
            target: [0xFFu8; 32],
        };
        assert_eq!(pool.search(&job, &stop), None);
    }

    #[test]
    fn test_empty_range_returns_none_without_hashing() {
        let pool = MiningPool::new(2);
        let stop = Arc::new(AtomicBool::new(false));
        let job = MineJob {
            seed: [0x77u8; 32],
            prev: Hash::from_bytes([0x11u8; 32]),
            merkle: Hash::from_bytes([0x22u8; 32]),
            start: 0,
            count: 0,
            target: [0xFFu8; 32],
        };
        assert_eq!(pool.search(&job, &stop), None);
    }
}
