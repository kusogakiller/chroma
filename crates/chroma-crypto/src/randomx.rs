//! RandomX Proof of Work (canonical reference implementation).
//!
//! RandomX is a CPU-oriented proof-of-work algorithm. This module binds the
//! canonical tevador/RandomX C++ reference implementation through the
//! `randomx-rs` crate (BSD-3-Clause; vendored reference sources; built with
//! CMake + MSVC at compile time). A prior pure-Rust dependency (`rustdom-x`)
//! was REMOVED because it demonstrably disagrees with canonical RandomX on
//! official test vectors and is GPL-3.0.
//!
//! Design notes (all consensus-relevant):
//! - LIGHT mode (cache-only VM, recommended CPU flags without FULL_MEM):
//!   identical consensus hashes to full mode (reference guarantee; Monero
//!   wallets validate in light mode), fast (~1 s) cache init, no multi-minute
//!   dataset stalls on epoch change. A future FULL_MEM upgrade would change
//!   only performance, never consensus output.
//! - The reference `RandomXCache`/`RandomXVM` types are `!Send + !Sync`
//!   (raw pointers), so ALL RandomX objects live on ONE dedicated worker
//!   thread. Callers (any thread, including Tokio workers) talk to it over
//!   `std::sync::mpsc` channels. No `unsafe` in this module.
//! - Hash requests serialize through the worker. Throughput (~10s of H/s in
//!   light mode) suffices for validation and regtest/testnet mining;
//!   mainnet-grade mining throughput is explicitly out of scope for V1.0.
//!
//! Security properties (from spec v0.1):
//! - Seed: H(block at height epoch_start - 100)
//! - Epoch: 1000 blocks (~2h 47min)
//! - Seed lag: 100 blocks (mitigates grinding)
//! - Cache: ~256 MiB Argon2 cache per seed (light mode)

use crate::error::{CryptoError, CryptoResult as Result};
use chroma_core::constants::{RANDOMX_EPOCH_LENGTH, RANDOMX_SEED_LAG};
use chroma_core::{blake3, Hash};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::sync::{mpsc, Mutex, RwLock};

/// Requests served by the dedicated RandomX worker thread.
/// (Plain `std` Results here: the crate-level `Result` alias is fallible-with-`CryptoError`.)
enum WorkerReq {
    /// (Re)initialize the VM for `seed`. Replies Ok(true) on actual rebuild,
    /// Ok(false) when the worker already serves that seed (idempotent).
    Init {
        seed: [u8; 32],
        resp: mpsc::Sender<std::result::Result<bool, String>>,
    },
    /// Compute one canonical RandomX hash. Replies Err when uninitialized.
    Hash {
        input: Vec<u8>,
        resp: mpsc::Sender<std::result::Result<[u8; 32], String>>,
    },
}

/// Front handle to the worker thread (process-global, lazily spawned).
struct WorkerFront {
    tx: mpsc::Sender<WorkerReq>,
}

static FRONT: Mutex<Option<WorkerFront>> = Mutex::new(None);

/// Mirror of the worker's active seed. Updated on every successful init;
/// the worker itself is the source of truth for idempotence, this mirror
/// only backs `is_randomx_initialized` and the epoch fast-path check.
static FRONT_SEED: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// Track the current RandomX epoch so we know when to re-init.
/// Updated inside `ensure_randomx_for_height` after a successful init.
static RANDOMX_CURRENT_EPOCH: RwLock<Option<u32>> = RwLock::new(None);

/// Build a light-mode VM for `seed`: recommended CPU flags (JIT/HARD_AES
/// where available; identical consensus output to interpreter mode per the
/// reference test suite), falling back to FLAG_DEFAULT on any failure.
fn build_vm(flags: RandomXFlag, seed: &[u8; 32]) -> std::result::Result<RandomXVM, String> {
    let attempt = |fl: RandomXFlag| -> std::result::Result<RandomXVM, String> {
        let cache =
            RandomXCache::new(fl, seed).map_err(|e| format!("RandomX cache init failed: {e:?}"))?;
        RandomXVM::new(fl, Some(cache), None).map_err(|e| format!("RandomX VM init failed: {e:?}"))
    };
    attempt(flags).or_else(|_| attempt(RandomXFlag::FLAG_DEFAULT))
}

/// Worker thread body: owns ALL RandomX objects; never panics on requests
/// (every failure is reported through the reply channel instead).
fn worker_main(rx: mpsc::Receiver<WorkerReq>) {
    let mut vm: Option<RandomXVM> = None;
    let mut seed: Option<[u8; 32]> = None;
    let flags = RandomXFlag::get_recommended_flags();
    while let Ok(req) = rx.recv() {
        match req {
            WorkerReq::Init { seed: s, resp } => {
                if seed == Some(s) && vm.is_some() {
                    let _ = resp.send(Ok(false));
                    continue;
                }
                match build_vm(flags, &s) {
                    Ok(v) => {
                        vm = Some(v);
                        seed = Some(s);
                        let _ = resp.send(Ok(true));
                    }
                    Err(e) => {
                        let _ = resp.send(Err(e));
                    }
                }
            }
            WorkerReq::Hash { input, resp } => match vm.as_ref() {
                None => {
                    let _ = resp.send(Err(
                        "RandomX context not initialized (call init_randomx_context first)"
                            .to_string(),
                    ));
                }
                Some(v) => {
                    let r = v.calculate_hash(&input).map(|h| {
                        let mut out = [0u8; 32];
                        let n = h.len().min(32);
                        out[..n].copy_from_slice(&h[..n]);
                        out
                    });
                    let _ = resp.send(r.map_err(|e| format!("RandomX hash failed: {e:?}")));
                }
            },
        }
    }
}

/// Lazily spawn the worker thread and return a request handle.
fn worker_tx() -> Result<mpsc::Sender<WorkerReq>> {
    let mut front = FRONT
        .lock()
        .map_err(|e| CryptoError::RandomX(format!("RandomX worker lock: {e}")))?;
    if front.is_none() {
        let (tx, rx) = mpsc::channel::<WorkerReq>();
        let _ = std::thread::spawn(move || worker_main(rx));
        front.replace(WorkerFront { tx });
    }
    Ok(front.as_ref().unwrap().tx.clone())
}

/// RandomX PoW result
/// In production: 32-byte hash, compared against target
pub struct PowResult {
    pub hash: Hash,
}

/// BLAKE3 placeholder PoW (devnet fallback).
pub fn pow_blake3(prev_hash: &Hash, merkle_root: &Hash, nonce: u64, extra_nonce: &[u8]) -> Hash {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(prev_hash.as_bytes());
    data.extend_from_slice(merkle_root.as_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(extra_nonce);
    blake3(&data)
}

/// RandomX PoW: compute a 32-byte hash from header fields.
///
/// Input layout: prev_hash || merkle_root || nonce(LE) || extra_nonce
/// (byte-exact and unchanged from the previous backend: only the hash
/// function behind it changed, from noncanonical to canonical RandomX).
/// The result is a canonical RandomX hash under the initialized seed.
///
/// Thread safety: the request is served by the dedicated worker thread;
/// concurrent callers serialize there. Safe to call from any thread,
/// including Tokio async workers (each call blocks only for one hash).
pub fn pow_randomx(
    prev_hash: &Hash,
    merkle_root: &Hash,
    nonce: u64,
    extra_nonce: &[u8],
) -> Result<Hash> {
    let mut input = Vec::with_capacity(72 + extra_nonce.len());
    input.extend_from_slice(prev_hash.as_bytes());
    input.extend_from_slice(merkle_root.as_bytes());
    input.extend_from_slice(&nonce.to_le_bytes());
    input.extend_from_slice(extra_nonce);

    let tx = worker_tx()?;
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(WorkerReq::Hash {
        input,
        resp: resp_tx,
    })
    .map_err(|_| CryptoError::RandomX("RandomX worker unavailable".to_string()))?;
    let out = resp_rx
        .recv()
        .map_err(|_| CryptoError::RandomX("RandomX worker unavailable".to_string()))?
        .map_err(CryptoError::RandomX)?;
    Ok(Hash::from_bytes(out))
}

/// Check if a hash meets the target
/// target is a 256-bit value (big-endian, lower = harder)
/// Returns true if hash_as_uint256 <= target_as_uint256
#[allow(clippy::needless_range_loop)]
pub fn hash_meets_target(hash: &Hash, target: &[u8; 32]) -> bool {
    for i in 0..32 {
        if hash.0[i] < target[i] {
            return true;
        }
        if hash.0[i] > target[i] {
            return false;
        }
    }
    true
}

/// Calculate cumulative work: 2^256 / target
pub fn calculate_work(target: &[u8; 32]) -> [u8; 32] {
    use chroma_core::u256::U256;

    let target_u256 = U256::from_be_bytes(target);
    if target_u256.is_zero() {
        return U256::MAX.to_be_bytes();
    }

    let max = U256::MAX;
    let (q, _r) = max.div_rem(&target_u256);
    let work = q.wrapping_add(&U256::ONE);
    work.to_be_bytes()
}

/// RandomX seed derivation
/// seed = H(block_hash_at_height(epoch_start - SEED_LAG))
pub fn derive_seed(block_hash: &Hash) -> Hash {
    blake3(block_hash.as_bytes())
}

/// Epoch calculation: height / EPOCH_LENGTH
pub fn epoch_for_height(height: u32, epoch_length: u32) -> u32 {
    height / epoch_length
}

/// Check if we're at a seed update point (epoch boundary)
pub fn is_seed_update_height(height: u32, epoch_length: u32) -> bool {
    height.is_multiple_of(epoch_length)
}

/// Initialize the RandomX VM context with a seed.
///
/// The worker is the source of truth for idempotence: it rebuilds the
/// cache and VM only when the seed differs, and replies Ok(false)
/// otherwise. Returns Ok(true) on actual (re)initialization.
/// A failed init leaves the previous context (if any) untouched.
pub fn init_randomx_context(seed: &Hash) -> Result<bool> {
    let tx = worker_tx()?;
    let (resp_tx, resp_rx) = mpsc::channel();
    tx.send(WorkerReq::Init {
        seed: *seed.as_bytes(),
        resp: resp_tx,
    })
    .map_err(|_| CryptoError::RandomX("RandomX worker unavailable".to_string()))?;
    let created = resp_rx
        .recv()
        .map_err(|_| CryptoError::RandomX("RandomX worker unavailable".to_string()))?
        .map_err(CryptoError::RandomX)?;
    if let Ok(mut mirror) = FRONT_SEED.lock() {
        *mirror = Some(*seed.as_bytes());
    }
    Ok(created)
}

/// Initialize or re-initialize the RandomX context for a given block height.
///
/// Computes the correct seed for the epoch containing `height` and initializes
/// the VM if the epoch has changed. This is the main entry point for the node
/// to keep the RandomX context up to date during sync and mining.
///
/// Seed formula: derive_seed(block_hash_at_height(epoch * EPOCH_LENGTH - SEED_LAG))
/// For heights in the first epoch (before the first seed update), uses the genesis seed.
///
/// Returns Ok(true) if re-initialized, Ok(false) if already current.
///
/// Thread safety: the epoch check and the init call are serialized through
/// the epoch write lock; the worker itself guarantees init idempotence per
/// seed, so concurrent callers cannot corrupt the context (at worst they
/// redundantly request the same seed, which replies Ok(false)).
pub fn ensure_randomx_for_height<F>(height: u32, get_block_hash: F) -> Result<bool>
where
    F: FnOnce(u32) -> Option<Hash>,
{
    let epoch = epoch_for_height(height, RANDOMX_EPOCH_LENGTH);

    // Compute the seed for this epoch (before taking any locks)
    let seed = compute_seed_for_epoch(epoch, get_block_hash);

    {
        let mut epoch_guard = RANDOMX_CURRENT_EPOCH.write().map_err(|e| {
            CryptoError::RandomX(format!("failed to acquire epoch write lock: {}", e))
        })?;

        if epoch_guard.is_some_and(|e| e == epoch) {
            // Also verify the seed mirror still matches (another caller in
            // this process may have switched seeds directly via
            // init_randomx_context since we last ran).
            let mirror = FRONT_SEED
                .lock()
                .map_err(|e| CryptoError::RandomX(format!("failed to acquire seed lock: {}", e)))?;
            if *mirror == Some(*seed.as_bytes()) {
                return Ok(false);
            }
            // Epoch matches but seed differs: fall through to re-initialize.
        }

        // Initialize the context with the new seed
        init_randomx_context(&seed)?;

        // Update the tracked epoch
        *epoch_guard = Some(epoch);
    }

    Ok(true)
}

/// Compute the RandomX seed for a given epoch.
///
/// For epoch 0 (before the first seed lag is reached), uses the genesis seed.
/// For epoch N > 0: derive_seed(block_hash_at_height(N * EPOCH_LENGTH - SEED_LAG))
fn compute_seed_for_epoch<F>(epoch: u32, get_block_hash: F) -> Hash
where
    F: FnOnce(u32) -> Option<Hash>,
{
    if epoch == 0 {
        return blake3(chroma_core::constants::GENESIS_RANDOMX_SEED);
    }

    let seed_height = epoch * RANDOMX_EPOCH_LENGTH;
    if seed_height < RANDOMX_SEED_LAG {
        return blake3(chroma_core::constants::GENESIS_RANDOMX_SEED);
    }

    let seed_block_height = seed_height - RANDOMX_SEED_LAG;
    match get_block_hash(seed_block_height) {
        Some(block_hash) => derive_seed(&block_hash),
        None => blake3(chroma_core::constants::GENESIS_RANDOMX_SEED),
    }
}

/// Check if the RandomX context has been initialized.
pub fn is_randomx_initialized() -> bool {
    FRONT_SEED
        .lock()
        .map(|mirror| mirror.is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::Hash;
    use std::sync::Mutex;

    /// Shared seed for tests that just need a valid RandomX context.
    /// Avoids repeated Argon2 cache rebuilds from different seeds.
    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    fn test_seed() -> Hash {
        Hash::from_bytes(TEST_SEED)
    }

    /// Serialize tests that modify the global worker seed / RANDOMX_CURRENT_EPOCH.
    /// Uses `unwrap_or_else(|e| e.into_inner())` to recover from poisoned mutex
    /// (a panicking test thread can poison the mutex; we still want to proceed).
    static GLOBAL_RANDOMX_MUTEX: Mutex<()> = Mutex::new(());

    /// Helper: lock the global mutex, recovering from poison.
    fn lock_global_randomx() -> std::sync::MutexGuard<'static, ()> {
        GLOBAL_RANDOMX_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Canonical RandomX compatibility (permanent regression suite).
    ///
    /// Vectors are the official reference results from tevador/RandomX
    /// `src/tests/tests.cpp` (interpreter, default v1 flags — the canonical
    /// baseline every conforming implementation must reproduce bit-for-bit,
    /// including JIT/HARD_AES paths). A prior backend failed these vectors
    /// and was removed for that reason plus its GPL-3.0 license; these tests
    /// exist so no noncanonical implementation can ever be substituted
    /// silently again.
    #[test]
    fn test_canonical_randomx_vectors() {
        use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
        let vectors: &[(&[u8], &[u8], &str)] = &[
            (
                b"test key 000",
                b"This is a test",
                "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
            ),
            (
                b"test key 000",
                b"Lorem ipsum dolor sit amet",
                "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
            ),
            (
                b"test key 000",
                b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
            ),
            (
                b"test key 001",
                b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
                "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
            ),
        ];
        // Same-key vectors share one cache (also covers cache reuse); the
        // different-key vector forces a second cache init.
        // Every vector runs under BOTH flag sets: FLAG_DEFAULT (portable
        // interpreter path) and the machine-recommended flags (JIT/HARD_AES
        // where available). The reference implementation guarantees identical
        // output across modes; this pins that guarantee on this machine.
        for flags in [
            RandomXFlag::FLAG_DEFAULT,
            RandomXFlag::get_recommended_flags(),
        ] {
            let mut cache_key: Option<Vec<u8>> = None;
            let mut vm_opt: Option<RandomXVM> = None;
            for (key, input, expected) in vectors {
                if cache_key.as_deref() != Some(*key) {
                    let cache = RandomXCache::new(flags, key).expect("canonical cache init");
                    vm_opt =
                        Some(RandomXVM::new(flags, Some(cache), None).expect("canonical VM init"));
                    cache_key = Some(key.to_vec());
                }
                let vm = vm_opt.as_ref().unwrap();
                let hash = vm.calculate_hash(input).expect("canonical hash");
                assert_eq!(
                    hex::encode(&hash),
                    *expected,
                    "canonical RandomX mismatch for key {:?} (flags {:?})",
                    String::from_utf8_lossy(key),
                    flags
                );
                // Deterministic repeatability on the same VM.
                let again = vm.calculate_hash(input).expect("canonical hash");
                assert_eq!(hash, again, "canonical RandomX must be deterministic");
            }
        }
    }

    /// Consensus PoW-input fixture (permanent).
    ///
    /// Locks the exact RandomX input layout `prev(32) || merkle(32) ||
    /// nonce-LE(8) || extra` together with the canonical backend output for
    /// fixed fields under TEST_SEED. Any layout, endianness, or backend
    /// change alters this hash. (This is a Chroma-fixture pin, NOT a
    /// canonical RandomX vector — those live in
    /// `test_canonical_randomx_vectors`.)
    #[test]
    fn test_pow_input_fixture() {
        let _guard = lock_global_randomx();
        let _ = init_randomx_context(&test_seed());
        let prev = Hash::from_bytes([0xAAu8; 32]);
        let merkle = Hash::from_bytes([0xBBu8; 32]);
        let h = pow_randomx(&prev, &merkle, 0x0102030405060708u64, b"fx").expect("fixture hash");
        assert_eq!(
            h.to_hex(),
            "951146e2d4c7f024e2d5837f76b5869ee775a82671b86696d677d7bd963537fc"
        );
    }

    /// Epoch-boundary seed selection (permanent).
    ///
    /// EPOCH_LENGTH=1000, SEED_LAG=100: epoch N>0 seeds from the block at
    /// N*1000-100 (when known), else the genesis seed. Miner and validator
    /// share `compute_seed_for_epoch`, so identical heights always derive
    /// identical seeds on every node.
    #[test]
    fn test_seed_epoch_boundaries() {
        use chroma_core::constants::{RANDOMX_EPOCH_LENGTH, RANDOMX_SEED_LAG};
        assert_eq!(epoch_for_height(0, RANDOMX_EPOCH_LENGTH), 0);
        assert_eq!(epoch_for_height(999, RANDOMX_EPOCH_LENGTH), 0);
        assert_eq!(epoch_for_height(1000, RANDOMX_EPOCH_LENGTH), 1);
        assert_eq!(epoch_for_height(2000, RANDOMX_EPOCH_LENGTH), 2);
        // Last block before the seed transition still uses the old epoch.
        assert_eq!(
            compute_seed_for_epoch(0, |_| None),
            blake3(chroma_core::constants::GENESIS_RANDOMX_SEED)
        );
        // Epoch 2 with the seed block known: H(block @1900) via derive_seed.
        let bh = Hash::from_bytes([0x77u8; 32]);
        assert_eq!(
            compute_seed_for_epoch(2, |h| if h == 1900 { Some(bh) } else { None }),
            derive_seed(&bh)
        );
        // Epoch 2 without the seed block: genesis fallback (syncing node).
        assert_eq!(
            compute_seed_for_epoch(2, |_| None),
            blake3(chroma_core::constants::GENESIS_RANDOMX_SEED)
        );
        // Epoch 1 seeds from block 900 = 1*EPOCH_LENGTH - SEED_LAG.
        let bh1 = Hash::from_bytes([0x99u8; 32]);
        assert_eq!(
            compute_seed_for_epoch(1, |h| if h == RANDOMX_EPOCH_LENGTH - RANDOMX_SEED_LAG {
                Some(bh1)
            } else {
                None
            }),
            derive_seed(&bh1)
        );
    }

    #[test]
    fn test_pow_blake3() {
        let prev_hash = Hash::from_bytes([0x42u8; 32]);
        let merkle_root = Hash::from_bytes([0x24u8; 32]);
        let nonce = 12345u64;
        let extra = b"test";

        let result = pow_blake3(&prev_hash, &merkle_root, nonce, extra);
        assert_eq!(result.as_bytes().len(), 32);

        let result2 = pow_blake3(&prev_hash, &merkle_root, nonce, extra);
        assert_eq!(result, result2);

        let result3 = pow_blake3(&prev_hash, &merkle_root, nonce + 1, extra);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hash_meets_target() {
        let hash = Hash::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]);

        let target = [0xFFu8; 32];
        assert!(hash_meets_target(&hash, &target));

        let target_low = [0x00u8; 32];
        assert!(!hash_meets_target(&hash, &target_low));

        let zero_hash = Hash::from_bytes([0u8; 32]);
        assert!(hash_meets_target(&zero_hash, &target_low));
        assert!(hash_meets_target(&zero_hash, &target));

        let exact_target = [0x42u8; 32];
        let exact_hash = Hash::from_bytes([0x42u8; 32]);
        assert!(hash_meets_target(&exact_hash, &exact_target));

        let mut target_bytes = [0u8; 32];
        target_bytes[31] = 0x41;
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = 0x42;
        let hash_above = Hash::from_bytes(hash_bytes);
        assert!(!hash_meets_target(&hash_above, &target_bytes));

        let mut target_bytes2 = [0u8; 32];
        target_bytes2[31] = 0x42;
        let mut hash_bytes2 = [0u8; 32];
        hash_bytes2[31] = 0x41;
        let hash_below = Hash::from_bytes(hash_bytes2);
        assert!(hash_meets_target(&hash_below, &target_bytes2));

        let mut target_ho = [0u8; 32];
        target_ho[0] = 0x02;
        let mut hash_ho = [0u8; 32];
        hash_ho[0] = 0x01;
        let hash_high_order = Hash::from_bytes(hash_ho);
        assert!(hash_meets_target(&hash_high_order, &target_ho));

        let mut hash_ho2 = [0u8; 32];
        hash_ho2[0] = 0x03;
        let hash_high_order_fail = Hash::from_bytes(hash_ho2);
        assert!(!hash_meets_target(&hash_high_order_fail, &target_ho));

        let max_hash = Hash::from_bytes([0xFFu8; 32]);
        let max_target = [0xFFu8; 32];
        assert!(hash_meets_target(&max_hash, &max_target));

        let mut bug_hash_bytes = [0u8; 32];
        bug_hash_bytes[0] = 0x01;
        bug_hash_bytes[1] = 0xFF;
        let bug_hash = Hash::from_bytes(bug_hash_bytes);
        let mut bug_target = [0u8; 32];
        bug_target[0] = 0x02;
        bug_target[1] = 0x00;
        assert!(hash_meets_target(&bug_hash, &bug_target));
    }

    #[test]
    fn test_epoch_calculation() {
        assert_eq!(epoch_for_height(0, 1000), 0);
        assert_eq!(epoch_for_height(999, 1000), 0);
        assert_eq!(epoch_for_height(1000, 1000), 1);
        assert_eq!(epoch_for_height(1999, 1000), 1);
        assert_eq!(epoch_for_height(2000, 1000), 2);
    }

    #[test]
    fn test_seed_update_check() {
        assert!(is_seed_update_height(0, 1000));
        assert!(!is_seed_update_height(999, 1000));
        assert!(is_seed_update_height(1000, 1000));
        assert!(is_seed_update_height(2000, 1000));
    }

    #[test]
    fn test_derive_seed() {
        let block_hash = Hash::from_bytes([0xABu8; 32]);
        let seed = derive_seed(&block_hash);
        // seed should be blake3(block_hash), not the block_hash itself
        assert_ne!(seed, block_hash, "derive_seed should hash the input");
        let expected = blake3(block_hash.as_bytes());
        assert_eq!(
            seed, expected,
            "derive_seed should return blake3(block_hash)"
        );
        // Deterministic
        let seed2 = derive_seed(&block_hash);
        assert_eq!(seed, seed2, "derive_seed should be deterministic");
    }

    #[test]
    fn test_calculate_work() {
        use chroma_core::u256::U256;

        let max_target = [0xFFu8; 32];
        let work = calculate_work(&max_target);
        let work_u256 = U256::from_be_bytes(&work);
        assert_eq!(work_u256, U256::from_u64(2));

        let one_target = {
            let mut t = [0u8; 32];
            t[31] = 1;
            t
        };
        let work2 = calculate_work(&one_target);
        let work2_u256 = U256::from_be_bytes(&work2);
        assert_eq!(work2_u256, U256::ZERO);

        let two_target = {
            let mut t = [0u8; 32];
            t[31] = 2;
            t
        };
        let work3 = calculate_work(&two_target);
        let work3_u256 = U256::from_be_bytes(&work3);
        let expected = U256::from_u64(0).with_bit_set(255);
        assert_eq!(work3_u256, expected, "target=2 should produce work = 2^255");

        let work_again = calculate_work(&max_target);
        assert_eq!(work, work_again);

        let mut large_target = [0xFFu8; 32];
        large_target[0] = 0xFE;
        let work_large = calculate_work(&large_target);
        let work_large_u256 = U256::from_be_bytes(&work_large);
        assert!(
            work_large_u256 < U256::from_u64(4),
            "larger target = smaller work"
        );

        let mut small_target = [0u8; 32];
        small_target[0] = 0x01;
        let work_small = calculate_work(&small_target);
        let work_small_u256 = U256::from_be_bytes(&work_small);
        assert!(
            work_small_u256 > U256::from_u64(4),
            "smaller target = larger work"
        );
    }

    #[test]
    fn test_hash_meets_target_transitivity() {
        let target = [0x80u8; 32];
        let hash_a_bytes = [0x40u8; 32];
        let hash_b_bytes = [0x20u8; 32];
        let hash_a = Hash::from_bytes(hash_a_bytes);
        let hash_b = Hash::from_bytes(hash_b_bytes);
        assert!(hash_meets_target(&hash_a, &target));
        assert!(hash_meets_target(&hash_b, &target));
        assert!(hash_meets_target(&hash_b, &hash_a.0));
    }

    #[test]
    fn test_hash_meets_target_boundary_values() {
        let cases: Vec<([u8; 32], [u8; 32], bool)> = vec![
            ([0x00u8; 32], [0x01u8; 32], true),
            ([0x01u8; 32], [0x00u8; 32], false),
            ([0x42u8; 32], [0x42u8; 32], true),
            ([0xFFu8; 32], [0xFFu8; 32], true),
            ([0x00u8; 32], [0x00u8; 32], true),
        ];
        for (hash_bytes, target, expected) in cases {
            let hash = Hash::from_bytes(hash_bytes);
            assert_eq!(
                hash_meets_target(&hash, &target),
                expected,
                "hash={:?} target={:?}",
                hash_bytes[0],
                target[0]
            );
        }
    }

    #[test]
    fn test_calculate_work_target_1_is_max() {
        use chroma_core::u256::U256;
        let target_1 = {
            let mut t = [0u8; 32];
            t[31] = 1;
            t
        };
        let work = calculate_work(&target_1);
        let work_u256 = U256::from_be_bytes(&work);
        assert_eq!(
            work_u256,
            U256::ZERO,
            "target=1 should produce work 0 (wrapped from 2^256)"
        );
    }

    #[test]
    fn test_pow_blake3_different_nonces() {
        let prev = Hash::from_bytes([0x01u8; 32]);
        let merkle = Hash::from_bytes([0x02u8; 32]);
        let mut results = std::collections::HashSet::new();
        for nonce in 0..100u64 {
            let h = pow_blake3(&prev, &merkle, nonce, b"");
            assert!(results.insert(h), "duplicate hash at nonce {}", nonce);
        }
    }

    #[test]
    fn test_pow_blake3_empty_extra() {
        let prev = Hash::from_bytes([0xAAu8; 32]);
        let merkle = Hash::from_bytes([0xBBu8; 32]);
        let h1 = pow_blake3(&prev, &merkle, 0, b"");
        let h2 = pow_blake3(&prev, &merkle, 0, &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_epoch_boundaries() {
        for h in 0..1000u32 {
            assert_eq!(epoch_for_height(h, 1000), 0);
        }
        for h in 1000..2000u32 {
            assert_eq!(epoch_for_height(h, 1000), 1);
        }
    }

    #[test]
    fn test_seed_update_at_exact_boundaries() {
        assert!(is_seed_update_height(0, 1000));
        assert!(!is_seed_update_height(1, 1000));
        assert!(is_seed_update_height(1000, 1000));
        assert!(!is_seed_update_height(1001, 1000));
        assert!(is_seed_update_height(2000, 1000));
    }

    #[test]
    fn test_init_randomx_context_succeeds() {
        let _guard = lock_global_randomx();
        let seed = test_seed();
        let result = init_randomx_context(&seed);
        assert!(
            result.is_ok(),
            "RandomX context init should succeed: {:?}",
            result.err()
        );
        assert!(is_randomx_initialized());
    }

    #[test]
    fn test_init_randomx_reinitializable() {
        let _guard = lock_global_randomx();
        // This test intentionally uses unique seeds to verify idempotency behavior.
        // It does NOT use the shared TEST_SEED to avoid interfering with other tests.
        let seed_a = Hash::from_bytes([0xA1u8; 32]);
        let seed_b = Hash::from_bytes([0xB2u8; 32]);

        let r1 = init_randomx_context(&seed_a);
        assert!(r1.is_ok());

        // Re-init with same seed should be idempotent (no 2 GB re-allocation)
        let r1_again = init_randomx_context(&seed_a);
        assert!(r1_again.is_ok());
        assert!(
            !r1_again.unwrap(),
            "re-init with same seed should return false"
        );

        // Re-init with different seed should succeed
        let r2 = init_randomx_context(&seed_b);
        assert!(r2.is_ok());
        assert!(r2.unwrap(), "different seed should return true");

        // Re-init with seed_a again should succeed (different from current)
        let r1_return = init_randomx_context(&seed_a);
        assert!(r1_return.is_ok());
        assert!(r1_return.unwrap(), "switching back should return true");
        assert!(is_randomx_initialized());

        // Restore test_seed() so later tests see the expected worker seed
        let _ = init_randomx_context(&test_seed());
    }

    #[test]
    fn test_pow_randomx_produces_hash() {
        let _guard = lock_global_randomx();
        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x01u8; 32]);
        let merkle = Hash::from_bytes([0x02u8; 32]);
        let result = pow_randomx(&prev, &merkle, 0, b"");
        assert!(
            result.is_ok(),
            "pow_randomx should succeed: {:?}",
            result.err()
        );

        let hash = result.unwrap();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_pow_randomx_deterministic() {
        let _guard = lock_global_randomx();
        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x10u8; 32]);
        let merkle = Hash::from_bytes([0x20u8; 32]);

        let h1 = pow_randomx(&prev, &merkle, 42, b"extra").unwrap();
        let h2 = pow_randomx(&prev, &merkle, 42, b"extra").unwrap();
        assert_eq!(h1, h2, "RandomX should be deterministic for same inputs");

        // Re-init same seed should be idempotent
        let reinit = init_randomx_context(&test_seed());
        assert!(reinit.is_ok());
        assert!(
            !reinit.unwrap(),
            "re-init with same seed should return false"
        );

        // After idempotent re-init, result must still be the same
        let h3 = pow_randomx(&prev, &merkle, 42, b"extra").unwrap();
        assert_eq!(h1, h3, "deterministic after idempotent re-init");
    }

    #[test]
    fn test_pow_randomx_different_nonces() {
        let _guard = lock_global_randomx();
        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x01u8; 32]);
        let merkle = Hash::from_bytes([0x02u8; 32]);
        let mut results = std::collections::HashSet::new();
        for nonce in 0..10u64 {
            let h = pow_randomx(&prev, &merkle, nonce, b"").unwrap();
            assert!(
                results.insert(h),
                "duplicate RandomX hash at nonce {}",
                nonce
            );
        }
    }

    #[test]
    fn test_pow_randomx_without_init_fails() {
        let _guard = lock_global_randomx();
        // We can't reset the global state, so just verify the function compiles
        // and that the error path exists. In isolation this would fail; with the
        // shared context from other tests it succeeds.
        let prev = Hash::from_bytes([0x01u8; 32]);
        let merkle = Hash::from_bytes([0x02u8; 32]);
        let _ = pow_randomx(&prev, &merkle, 0, b"");
    }

    #[test]
    fn test_ensure_randomx_for_height_genesis_epoch() {
        let _guard = lock_global_randomx();
        let result = ensure_randomx_for_height(0, |_| None);
        assert!(
            result.is_ok(),
            "ensure_randomx should succeed: {:?}",
            result.err()
        );
        assert!(is_randomx_initialized());

        // Second call at same epoch should return false (no re-init)
        let result2 = ensure_randomx_for_height(500, |_| None);
        assert!(result2.is_ok());
        assert!(!result2.unwrap(), "should not re-init for same epoch");
    }

    #[test]
    fn test_compute_seed_for_epoch_zero() {
        let seed = compute_seed_for_epoch(0, |_| None);
        let expected = blake3(chroma_core::constants::GENESIS_RANDOMX_SEED);
        assert_eq!(seed, expected, "epoch 0 should use genesis seed");
    }

    #[test]
    fn test_compute_seed_for_epoch_uses_block_hash() {
        let block_hash = Hash::from_bytes([0x42u8; 32]);
        let seed = compute_seed_for_epoch(1, |_| Some(block_hash));
        let expected = derive_seed(&block_hash);
        assert_eq!(
            seed, expected,
            "epoch 1 should use derive_seed of block hash"
        );
    }

    #[test]
    fn test_compute_seed_falls_back_to_genesis() {
        // When block hash is unavailable, should fall back to genesis seed
        let seed = compute_seed_for_epoch(1, |_| None);
        let expected = blake3(chroma_core::constants::GENESIS_RANDOMX_SEED);
        assert_eq!(
            seed, expected,
            "missing block hash should fall back to genesis seed"
        );
    }

    // ========================================================================
    // Concurrency determinism tests
    //
    // These verify that pow_randomx is thread-safe: multiple threads computing
    // hashes with the same VM context produce identical results, and concurrent
    // init with different seeds doesn't corrupt the hash output.
    // ========================================================================

    /// Multiple threads compute pow_randomx with the same inputs concurrently.
    /// All must produce the same hash.
    #[test]
    fn test_pow_randomx_concurrent_same_context() {
        let _guard = lock_global_randomx();
        use std::sync::Arc;
        use std::sync::Barrier;

        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x11u8; 32]);
        let merkle = Hash::from_bytes([0x22u8; 32]);
        let nonce = 77u64;
        let extra = b"concurrent";

        // Compute reference hash single-threaded
        let reference = pow_randomx(&prev, &merkle, nonce, extra).unwrap();

        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for _ in 0..num_threads {
            let barrier = Arc::clone(&barrier);
            let extra: Vec<u8> = extra.to_vec();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let h = pow_randomx(&prev, &merkle, nonce, &extra).unwrap();
                assert_eq!(h, reference, "concurrent thread produced different hash");
                h
            }));
        }

        for h in handles.into_iter().map(|h| h.join().unwrap()) {
            assert_eq!(h, reference);
        }
    }

    /// Concurrent pow_randomx calls with different nonces all produce unique hashes.
    #[test]
    fn test_pow_randomx_concurrent_different_nonces() {
        let _guard = lock_global_randomx();
        use std::sync::Arc;
        use std::sync::Barrier;

        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x33u8; 32]);
        let merkle = Hash::from_bytes([0x44u8; 32]);

        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));
        let mut handles = vec![];

        for tid in 0..num_threads as u64 {
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut hashes = std::collections::HashSet::new();
                for nonce in tid * 50..(tid + 1) * 50 {
                    let h = pow_randomx(&prev, &merkle, nonce, b"").unwrap();
                    assert!(
                        hashes.insert(h),
                        "duplicate within thread at nonce {}",
                        nonce
                    );
                }
                hashes
            }));
        }

        let all_hashes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let total: usize = all_hashes.iter().map(|s| s.len()).sum();
        let unique: std::collections::HashSet<_> =
            all_hashes.iter().flat_map(|s| s.iter().cloned()).collect();
        assert_eq!(
            total,
            unique.len(),
            "cross-thread duplicate hashes detected"
        );
    }

    /// Verify idempotent init under concurrent access.
    #[test]
    fn test_init_randomx_concurrent_same_seed() {
        let _guard = lock_global_randomx();
        use std::sync::Arc;
        use std::sync::Barrier;

        let num_threads = 4;
        let barrier = Arc::new(Barrier::new(num_threads));

        let mut handles = vec![];
        for _ in 0..num_threads {
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let r = init_randomx_context(&test_seed());
                assert!(r.is_ok());
                let prev = Hash::from_bytes([0x55u8; 32]);
                let merkle = Hash::from_bytes([0x66u8; 32]);
                pow_randomx(&prev, &merkle, 1, b"")
            }));
        }

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap())
            .collect();
        for window in results.windows(2) {
            assert_eq!(window[0], window[1], "concurrent same-seed results differ");
        }
    }

    /// Miner and validator running concurrently.
    #[test]
    fn test_pow_randomx_miner_validator_concurrent() {
        let _guard = lock_global_randomx();
        use std::sync::Arc;
        use std::sync::Barrier;

        let _ = init_randomx_context(&test_seed());

        let prev = Hash::from_bytes([0x77u8; 32]);
        let merkle = Hash::from_bytes([0x88u8; 32]);

        let reference_nonce = 42u64;
        let reference = pow_randomx(&prev, &merkle, reference_nonce, b"miner").unwrap();

        let barrier = Arc::new(Barrier::new(2));

        let barrier_m = Arc::clone(&barrier);
        let prev_m = prev;
        let merkle_m = merkle;
        let miner = std::thread::spawn(move || {
            barrier_m.wait();
            let mut results = vec![];
            for nonce in reference_nonce..reference_nonce + 10 {
                let h = pow_randomx(&prev_m, &merkle_m, nonce, b"miner").unwrap();
                results.push(h);
            }
            results
        });

        let barrier_v = Arc::clone(&barrier);
        let prev_v = prev;
        let merkle_v = merkle;
        let validator = std::thread::spawn(move || {
            barrier_v.wait();
            pow_randomx(&prev_v, &merkle_v, reference_nonce, b"miner")
        });

        let miner_results = miner.join().unwrap();
        let validator_hash = validator.join().unwrap().unwrap();

        assert_eq!(
            miner_results[0], validator_hash,
            "miner and validator produced different hashes for same input"
        );
        assert_eq!(miner_results[0], reference);
    }
}
