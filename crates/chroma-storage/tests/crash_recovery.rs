//! Storage crash-consistency, corruption-classification, and idempotency tests.
//!
//! Strategy: storage commits need no PoW (no validation at this layer), so
//! crafted blocks exercise the REAL persistence paths fast and
//! deterministically. Real OS-level kills use a self-spawned child (the test
//! binary re-executed with a filter + env gate): `child.kill()` is
//! TerminateProcess-equivalent, strictly stronger than graceful shutdown.
//!
//! What each test proves is stated above it; none depend on timing races.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chroma_block::{Block, BlockHeader};
use chroma_core::hash::Hash;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{Address, BlockHeight, CompactTarget};
use chroma_state::{Account, State};
use chroma_storage::{PersistedTip, Storage, CURRENT_SCHEMA_VERSION, SCHEMA_VERSION_KEY};

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_dir(name: &str) -> PathBuf {
    let id = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("chroma_storage_crash_{}_{}", name, id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_address(n: u8) -> Address {
    let mut h = [0u8; 20];
    h[0] = n;
    Address::from_hash160(chroma_core::hash::Hash160(h))
}

/// Deterministic chain content: height h pays 1000*h units to addr 0x01.
/// State after prefix 0..=h: balance(h) = 1000*sum(1..=h), supply likewise.
fn state_for_prefix(top: u32) -> State {
    let mut st = State::new();
    for h in 1..=top {
        let mut acc = st.get_account(&test_address(1));
        acc.balance += 1000 * h as u64;
        st.set_account_direct(&test_address(1), acc);
        st.set_total_supply(st.total_supply() + 1000 * h as u64);
    }
    st
}

fn header_for(height: u32, prev: Hash) -> BlockHeader {
    BlockHeader {
        version: 1,
        previous_hash: prev,
        state_root: Hash::blake3(format!("state-{height}").as_bytes()),
        tx_merkle_root: Hash::ZERO,
        timestamp: 1_700_000_000 + height as u64 * 10,
        bits: CompactTarget::DIFFICULTY_1,
        height: BlockHeight(height),
        nonce: height as u64,
    }
}

/// Commit a crafted linear chain 0..=top (genesis + blocks), each with its
/// tip record, WITHOUT flushing. Returns (tip_hash_per_height, final_tip).
fn commit_prefix(storage: &Storage, top: u32) -> (BTreeMap<u32, Hash>, PersistedTip) {
    let genesis_header = header_for(0, Hash::ZERO);
    let genesis = Block {
        header: genesis_header.clone(),
        transactions: vec![],
    };
    storage.apply_block(&genesis).unwrap();
    let mut hashes = BTreeMap::new();
    hashes.insert(0, genesis.hash());
    let mut prev = genesis.hash();
    let mut tip = PersistedTip {
        height: 0,
        hash: genesis.hash(),
        cumulative_work: [0u8; 32],
        supply: 0,
    };
    for h in 1..=top {
        let header = header_for(h, prev);
        let block = Block {
            header,
            transactions: vec![],
        };
        let st = state_for_prefix(h);
        tip = PersistedTip {
            height: h,
            hash: block.hash(),
            cumulative_work: [h as u8; 32],
            supply: st.total_supply(),
        };
        storage.commit_block(&block, &tip, &st).unwrap();
        prev = block.hash();
        hashes.insert(h, prev);
    }
    (hashes, tip)
}

/// Assert the FULL canonical prefix 0..=top is coherent: tip record, every
/// header, every block, both indexes, supply, and account balance.
fn assert_prefix_coherent(storage: &Storage, hashes: &BTreeMap<u32, Hash>, top: u32) {
    let tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(tip.height, top, "tip height must be exactly {}", top);
    assert_eq!(tip.hash, hashes[&top], "tip hash must match");
    let mut expect_supply = 0u64;
    for h in 0..=top {
        let header = storage.get_header(h).unwrap().unwrap_or_else(|| {
            panic!("header {} missing", h);
        });
        assert_eq!(header.hash(), hashes[&h], "header {} hash mismatch", h);
        let block = storage
            .get_block_by_hash(&hashes[&h])
            .unwrap()
            .unwrap_or_else(|| {
                panic!("block {} missing", h);
            });
        assert_eq!(block.header.hash(), hashes[&h]);
        assert_eq!(
            storage.get_height_for_hash(&hashes[&h]).unwrap(),
            Some(h),
            "hash→height index broken at {}",
            h
        );
        assert_eq!(
            storage.get_canonical_hash_at_height(h).unwrap(),
            Some(hashes[&h]),
            "height→hash index broken at {}",
            h
        );
        if h > 0 {
            expect_supply += 1000 * h as u64;
        }
    }
    assert_eq!(storage.get_supply().unwrap(), expect_supply);
    let acc = storage
        .get_account(&test_address(1))
        .unwrap()
        .unwrap_or(Account {
            balance: 0,
            nonce: 0,
        });
    assert_eq!(acc.balance, expect_supply);
    // Loaded state reproduces the committed state root shape (supply side).
    let loaded = storage.load_state().unwrap();
    assert_eq!(loaded.total_supply(), expect_supply);
}

/// Drop WITHOUT flush or ceremony (≈ unclean shutdown for durability
/// purposes: whatever sled recovered is what a kill would leave, minus a
/// possible torn WAL tail — torn tails are covered by the real-kill tests).
fn drop_reopen(dir: &Path) -> Storage {
    Storage::open(dir).unwrap()
}

#[test]
fn crash_drop_reopen_exact_prefix_repeated_100() {
    // 100 unclean restarts: every reopen must show the EXACT committed tip
    // (all commits were WAL-acknowledged before the drop).
    let dir = test_dir("drop100");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, _) = commit_prefix(&storage, 4);
    drop(storage);
    for round in 0..100u32 {
        let storage = drop_reopen(&dir);
        let tip = storage.get_tip().unwrap().unwrap();
        assert_eq!(
            tip.height, 4,
            "round {}: tip must survive unclean drop",
            round
        );
        assert_eq!(tip.hash, hashes[&4]);
        assert_prefix_coherent(&storage, &hashes, 4);
        drop(storage);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crash_no_flush_recovery_is_prefix_coherent() {
    // Commits WITHOUT any flush, then drop: recovery must be a coherent
    // prefix (possibly shorter than committed if the tail never reached
    // durable storage — never torn). Documents the flush-necessity boundary.
    let dir = test_dir("noflush");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, _) = commit_prefix(&storage, 10);
    drop(storage);
    let storage = Storage::open(&dir).unwrap();
    let tip = storage.get_tip().unwrap().unwrap();
    assert!(tip.height <= 10, "tip cannot exceed committed prefix");
    let mut expect = BTreeMap::new();
    for h in 0..=tip.height {
        expect.insert(h, hashes[&h]);
    }
    assert_prefix_coherent(&storage, &expect, tip.height);
    eprintln!(
        "no-flush recovery: committed 10, recovered tip height {}",
        tip.height
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crash_duplicate_commits_are_idempotent() {
    // Same block committed 100× (as redelivered after restarts would be):
    // records stay exact, indexes unambiguous.
    let dir = test_dir("dup100");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, tip) = commit_prefix(&storage, 3);
    let dup = storage.get_block_by_hash(&hashes[&3]).unwrap().unwrap();
    let st = state_for_prefix(3);
    for _ in 0..100 {
        storage.commit_block(&dup, &tip, &st).unwrap();
    }
    storage.flush().unwrap();
    drop(storage);
    for _ in 0..10 {
        let storage = Storage::open(&dir).unwrap();
        assert_prefix_coherent(&storage, &hashes, 3);
        drop(storage);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// Real-kill crash tests (child process + TerminateProcess, no cleanup)
// ============================================================================

/// Child entrypoint (also runs as a no-op pass without the env gate so the
/// harness lists it normally). Modes: `park` commits COUNT then parks for
/// the kill; `loop` commits forever until killed (kill lands mid-stream).
#[test]
fn crash_child_worker() {
    let dir = match std::env::var("CHROMA_CRASH_CHILD_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => return,
    };
    let mode = std::env::var("CHROMA_CRASH_CHILD_MODE").unwrap_or_default();
    let count: u32 = std::env::var("CHROMA_CRASH_CHILD_COUNT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let storage = Storage::open(&dir).unwrap();
    // Genesis if absent (first child to arrive initializes).
    if storage.get_tip().unwrap().is_none() {
        let genesis = Block {
            header: header_for(0, Hash::ZERO),
            transactions: vec![],
        };
        storage.apply_block(&genesis).unwrap();
        let tip = PersistedTip {
            height: 0,
            hash: genesis.hash(),
            cumulative_work: [0u8; 32],
            supply: 0,
        };
        storage.put_tip(&tip).unwrap();
    }
    let mut h = storage.get_tip().unwrap().unwrap().height;
    let mut prev = storage.get_tip().unwrap().unwrap().hash;
    let mut prev_ts = 1_700_000_000u64;
    if h > 0 {
        if let Some(hdr) = storage.get_header(h).unwrap() {
            prev_ts = hdr.timestamp;
        }
    }
    let commit_one = |storage: &Storage, h: u32, prev: Hash, prev_ts: u64| -> (Hash, u64) {
        let mut header = header_for(h, prev);
        header.timestamp = prev_ts + 10;
        let block = Block {
            header,
            transactions: vec![],
        };
        let st = state_for_prefix(h);
        let tip = PersistedTip {
            height: h,
            hash: block.hash(),
            cumulative_work: [h as u8; 32],
            supply: st.total_supply(),
        };
        storage.commit_block(&block, &tip, &st).unwrap();
        (block.hash(), header_timestamp(&block))
    };
    if mode == "park" {
        for _ in 0..count {
            h += 1;
            let (nh, nts) = commit_one(&storage, h, prev, prev_ts);
            prev = nh;
            prev_ts = nts;
        }
        // Flush like every production commit path does (commit→flush is the
        // durability unit; unflushed commits are NOT kill-safe — see the
        // loop-mode test). Signal readiness only afterwards.
        storage.flush().unwrap();
        println!("CRASH_CHILD_READY height={}", h);
        use std::io::Write;
        let _ = std::io::stdout().flush();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    } else {
        // Paced loop: ~hundreds of commits before the parent's kill lands
        // at an arbitrary mid-stream point (kill timing, not count, varies).
        // Signal readiness after genesis is committed so parent can synchronize.
        if h == 0 {
            storage.flush().unwrap();
            println!("CRASH_CHILD_READY height=0");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
        loop {
            h += 1;
            let (nh, nts) = commit_one(&storage, h, prev, prev_ts);
            prev = nh;
            prev_ts = nts;
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }
}

fn header_timestamp(block: &Block) -> u64 {
    block.header.timestamp
}

fn spawn_crash_child(dir: &Path, mode: &str, count: u32) -> std::process::Child {
    let exe = std::env::current_exe().unwrap();
    std::process::Command::new(exe)
        .args(["--exact", "crash_child_worker", "--nocapture"])
        .env("CHROMA_CRASH_CHILD_DIR", dir)
        .env("CHROMA_CRASH_CHILD_MODE", mode)
        .env("CHROMA_CRASH_CHILD_COUNT", count.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

fn wait_ready(child: &mut std::process::Child) {
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "child died before READY");
        if line.contains("CRASH_CHILD_READY") {
            // Hand the pipe back so kill() can proceed; child keeps running.
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "child never became ready"
        );
    }
    // NOTE: stdout pipe intentionally dropped here (child blocks only on
    // sleep, never on stdout afterwards).
}

#[test]
fn crash_real_kill_parked_recovers_exact() {
    // 3× real kills after flushed commits (the production durability unit):
    // recovery is EXACT every time. Unflushed commits are NOT covered here
    // by design — see the loop-mode test for that boundary.
    for round in 0..3 {
        let dir = test_dir(&format!("killpark{}", round));
        let mut child = spawn_crash_child(&dir, "park", 20);
        wait_ready(&mut child);
        child.kill().unwrap();
        let _ = child.wait();
        let storage = Storage::open(&dir).unwrap();
        let tip = storage.get_tip().unwrap().unwrap();
        assert_eq!(
            tip.height, 20,
            "round {}: exact tip must survive kill",
            round
        );
        let mut hashes = BTreeMap::new();
        let mut prev = None;
        for h in 0..=20u32 {
            let header = storage.get_header(h).unwrap().unwrap_or_else(|| {
                panic!("round {}: header {} missing after kill", round, h);
            });
            if h > 0 {
                assert_eq!(header.previous_hash, prev.unwrap());
            }
            let hh = header.hash();
            assert_eq!(
                storage.get_height_for_hash(&hh).unwrap(),
                Some(h),
                "round {}: index broken at {}",
                round,
                h
            );
            assert_eq!(
                storage
                    .get_block_by_hash(&hh)
                    .unwrap()
                    .unwrap()
                    .header
                    .hash(),
                hh
            );
            prev = Some(hh);
            hashes.insert(h, hh);
        }
        assert_prefix_coherent(&storage, &hashes, 20);
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn crash_real_kill_mid_stream_recovers_coherent_prefix() {
    // 3× kills landing mid-commit-stream: recovery must be a COHERENT prefix
    // (any height — atomicity means all-or-nothing per batch, never torn).
    for round in 0..3 {
        let dir = test_dir(&format!("killloop{}", round));
        let mut child = spawn_crash_child(&dir, "loop", 0);
        wait_ready(&mut child);
        std::thread::sleep(std::time::Duration::from_millis(400));
        child.kill().unwrap();
        let _ = child.wait();
        let storage = Storage::open(&dir).unwrap();
        let tip = storage.get_tip().unwrap().unwrap();
        let mut hashes = BTreeMap::new();
        let mut prev = None;
        for h in 0..=tip.height {
            let header = storage
                .get_header(h)
                .unwrap()
                .unwrap_or_else(|| panic!("round {}: header {} missing", round, h));
            if h > 0 {
                assert_eq!(header.previous_hash, prev.unwrap());
            }
            let hh = header.hash();
            assert_eq!(storage.get_height_for_hash(&hh).unwrap(), Some(h));
            prev = Some(hh);
            hashes.insert(h, hh);
        }
        assert_prefix_coherent(&storage, &hashes, tip.height);
        eprintln!(
            "kill-loop round {}: recovered coherent tip {}",
            round, tip.height
        );
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ============================================================================
// Corruption classification (raw sled writes bypassing all validation)
// ============================================================================

fn raw_sled(dir: &Path) -> sled::Db {
    sled::Config::new().path(dir).open().unwrap()
}

#[test]
fn corruption_classification_per_record_kind() {
    // Each corruption primitive is classified: hard error (fail-closed),
    // skip (fail-open, backstopped by startup state-root verification), or
    // silent acceptance (finding if any survives to chain logic).
    let dir = test_dir("corrupt");
    let storage = Storage::open(&dir).unwrap();
    let (_, _) = commit_prefix(&storage, 3);
    drop(storage);

    // 1. Truncated account record (5 bytes, not 16): get_account ERRORS.
    // (Key must match a real account: test_address(1) == [0x01, 0×19].)
    {
        let db = raw_sled(&dir);
        let mut key = b"accounts:".to_vec();
        key.extend_from_slice(&[vec![0x01], vec![0u8; 19]].concat());
        db.insert(key, vec![0u8; 5]).unwrap();
        db.flush().unwrap();
        drop(db);
        let storage = Storage::open(&dir).unwrap();
        assert!(storage.get_account(&test_address(1)).is_err());
        // load_state SKIPS it (fail-open at loader level)...
        let loaded = storage.load_state().unwrap();
        assert_eq!(loaded.get_account(&test_address(1)).balance, 0);
        drop(storage);
    }
    // 2. Truncated tip record: get_tip ERRORS (never misread).
    {
        let db = raw_sled(&dir);
        db.insert("tip", vec![0u8; 10]).unwrap();
        db.flush().unwrap();
        drop(db);
        let storage = Storage::open(&dir).unwrap();
        assert!(storage.get_tip().is_err());
        drop(storage);
    }
    // 3. Short supply record: get_supply ERRORS; missing supply defaults 0.
    {
        let db = raw_sled(&dir);
        db.insert("supply", vec![0u8; 3]).unwrap();
        db.flush().unwrap();
        drop(db);
        let storage = Storage::open(&dir).unwrap();
        assert!(storage.get_supply().is_err());
        drop(storage);
        let db = raw_sled(&dir);
        db.remove("supply").unwrap();
        db.flush().unwrap();
        drop(db);
        let storage = Storage::open(&dir).unwrap();
        assert_eq!(storage.get_supply().unwrap(), 0);
        drop(storage);
    }
    // 4. Wrong-value (valid-length) balance: SILENT at the getter level...
    // (Key must match test_address(2) == [0x02, 0×19].)
    {
        let db = raw_sled(&dir);
        let mut key = b"accounts:".to_vec();
        key.extend_from_slice(&[vec![0x02], vec![0u8; 19]].concat());
        let mut data = vec![0u8; 16];
        data[..8].copy_from_slice(&999_999_999u64.to_le_bytes());
        db.insert(key, data).unwrap();
        db.flush().unwrap();
        drop(db);
        let storage = Storage::open(&dir).unwrap();
        let acc = storage.get_account(&test_address(2)).unwrap().unwrap();
        assert_eq!(acc.balance, 999_999_999);
        drop(storage);
        // ...but startup state-root verification (p2p init_chain_state)
        // recomputes the root from loaded accounts and REFUSES to boot on
        // mismatch: silent getter acceptance never becomes silent chain
        // operation. (Proven by the p2p tampered-balance refusal test.)
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Recursive directory copy (cold backup primitive under test).
fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &dst_path);
        } else {
            std::fs::copy(entry.path(), dst_path).unwrap();
        }
    }
}

#[test]
fn backup_cold_copy_restores_coherent_chain() {
    // Operator cold backup: stop node (drop + flush here), copy the data
    // directory with plain file copy, open the COPY elsewhere. The copy
    // must be fully coherent; the source must remain usable afterwards.
    let dir = test_dir("backup_src");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, _) = commit_prefix(&storage, 6);
    storage.flush().unwrap();
    drop(storage);
    let backup = test_dir("backup_dst");
    let _ = std::fs::remove_dir_all(&backup);
    copy_dir_recursive(&dir, &backup);
    // The copy opens and verifies exactly.
    let restored = Storage::open(&backup).unwrap();
    assert_prefix_coherent(&restored, &hashes, 6);
    drop(restored);
    // The source is untouched and still opens coherently (copy is non-
    // destructive; sled file locks were released by drop).
    let source = Storage::open(&dir).unwrap();
    assert_prefix_coherent(&source, &hashes, 6);
    drop(source);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&backup);
}

#[test]
fn missing_records_classified_no_silent_merge() {
    // Deleted individual records must degrade loudly or not at all — never
    // merge into a wrong-but-plausible view.
    let dir = test_dir("missingrec");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, _) = commit_prefix(&storage, 5);
    storage.flush().unwrap();
    drop(storage);
    // Delete one header record via raw sled (simulates partial loss).
    {
        let db = raw_sled(&dir);
        let mut key = b"headers:".to_vec();
        key.extend_from_slice(&3u32.to_be_bytes());
        db.remove(key).unwrap();
        db.flush().unwrap();
        drop(db);
    }
    let storage = Storage::open(&dir).unwrap();
    // Header gone, but the tip record, block store, and indexes still name
    // height 3: stores diverge per-record (no cross-checks at this layer —
    // chain-level coherence is enforced at startup by init_chain_state,
    // which refuses a tip whose headers are missing).
    assert!(storage.get_header(3).unwrap().is_none());
    assert!(storage.get_tip().unwrap().unwrap().height == 5);
    assert!(storage.get_block_by_hash(&hashes[&3]).unwrap().is_some());
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn db_growth_per_block_is_small_and_logged() {
    // Long-horizon retention math needs a measured per-block cost, not a
    // guess. 200 empty blocks; report mean bytes/block for the final report.
    let dir = test_dir("growth");
    let storage = Storage::open(&dir).unwrap();
    let (hashes, _) = commit_prefix(&storage, 200);
    storage.flush().unwrap();
    let bytes = storage.size_on_disk().unwrap();
    let mean = bytes as f64 / 201.0;
    eprintln!(
        "db-growth: 201 blocks occupy {} bytes ({:.0} mean B/block)",
        bytes, mean
    );
    assert_prefix_coherent(&storage, &hashes, 200);
    assert!(
        bytes < 201 * 256 * 1024,
        "pathological per-block bloat: {} bytes for 201 blocks",
        bytes
    );
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn versioning_pin_no_schema_version_record() {
    // CURRENT STATUS: no schema/database version key exists anywhere.
    // Pinned so any future versioning addition is a deliberate diff here.
    let dir = test_dir("noversion");
    let storage = Storage::open(&dir).unwrap();
    drop(storage);
    let db = raw_sled(&dir);
    let has_version = db
        .scan_prefix("meta:")
        .flatten()
        .any(|(k, _)| k.starts_with(b"meta:version") || k.starts_with(b"meta:schema"));
    drop(db);
    assert!(!has_version, "no version record exists today");
    // PersistedTip wire format pins: exactly 76 bytes; short errors;
    // trailing bytes tolerated (forward-tolerant read).
    let tip = PersistedTip {
        height: 7,
        hash: Hash::blake3(b"tip"),
        cumulative_work: [9u8; 32],
        supply: 42,
    };
    let enc = tip.encode();
    assert_eq!(enc.len(), 76);
    assert!(PersistedTip::decode(&enc[..75]).is_err());
    let mut longer = enc.clone();
    longer.extend_from_slice(&[0u8; 32]);
    assert!(PersistedTip::decode(&longer).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

// ============================================================================
// Schema Versioning Tests
// ============================================================================

#[test]
fn test_schema_version_new_database_gets_current_version() {
    // New database should get CURRENT_SCHEMA_VERSION written on first open.
    let dir = test_dir("schema_new");
    {
        let storage = Storage::open(&dir).unwrap();
        drop(storage);
    }
    let db = raw_sled(&dir);
    let version_ivec = db.get(SCHEMA_VERSION_KEY).unwrap().unwrap();
    let version_bytes: [u8; 4] = version_ivec.as_ref().try_into().unwrap();
    let version = u32::from_le_bytes(version_bytes);
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_schema_version_existing_matching_version_opens() {
    // Database with matching schema version should open successfully.
    let dir = test_dir("schema_match");
    {
        let storage = Storage::open(&dir).unwrap();
        // First open writes the version
        drop(storage);
    }
    // Second open should succeed with matching version
    let storage = Storage::open(&dir).unwrap();
    let _ = storage.get_tip().unwrap();
    drop(storage);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_schema_version_newer_fails_closed() {
    // Database with newer schema version must fail closed.
    let dir = test_dir("schema_newer");
    let storage = Storage::open(&dir).unwrap();
    drop(storage);
    // Manually write a newer schema version
    {
        let db = raw_sled(&dir);
        let newer_version = CURRENT_SCHEMA_VERSION + 1;
        let key = SCHEMA_VERSION_KEY.to_vec();
        let value = newer_version.to_le_bytes().to_vec();
        db.insert(key, value).unwrap();
        db.flush().unwrap();
        drop(db);
    }
    // Reopening must fail
    let result = Storage::open(&dir);
    assert!(result.is_err(), "newer schema version must fail closed");
    let err = result.as_ref().unwrap_err().to_string();
    assert!(err.contains("newer than supported version"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_schema_version_older_fails_closed() {
    // Database with older schema version must fail closed (migration not yet implemented).
    let dir = test_dir("schema_older");
    let storage = Storage::open(&dir).unwrap();
    drop(storage);
    // Manually write an older schema version
    {
        let db = raw_sled(&dir);
        let older_version = CURRENT_SCHEMA_VERSION.saturating_sub(1);
        let key = SCHEMA_VERSION_KEY.to_vec();
        let value = older_version.to_le_bytes().to_vec();
        db.insert(key, value).unwrap();
        db.flush().unwrap();
        drop(db);
    }
    // Reopening must fail
    let result = Storage::open(&dir);
    assert!(result.is_err(), "older schema version must fail closed");
    let err = result.as_ref().unwrap_err().to_string();
    assert!(
        err.contains("older than current version") || err.contains("migration not yet implemented")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_schema_version_corrupted_encoding_fails_closed() {
    // Corrupted schema version (wrong length) must fail closed, never be
    // misread as a valid version or silently re-initialized.
    for bad_len in [0usize, 1, 2, 3, 5, 8] {
        let dir = test_dir(&format!("schema_corrupt{}", bad_len));
        let storage = Storage::open(&dir).unwrap();
        drop(storage);
        {
            let db = raw_sled(&dir);
            let key = SCHEMA_VERSION_KEY.to_vec();
            let value = vec![0xFFu8; bad_len];
            db.insert(key, value).unwrap();
            db.flush().unwrap();
            drop(db);
        }
        let result = Storage::open(&dir);
        assert!(
            result.is_err(),
            "corrupted schema version (len {}) must fail closed",
            bad_len
        );
        let err = result.as_ref().unwrap_err().to_string();
        assert!(
            err.contains("invalid schema version encoding"),
            "unexpected error for len {}: {}",
            bad_len,
            err
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ============================================================================
// Upgrade/Downgrade Compatibility Tests
// ============================================================================

#[test]
fn test_upgrade_downgrade_compatibility() {
    // Test: V1 -> V2 upgrade, then V2 -> V1 downgrade
    // Since migration is not implemented, V2 (newer) should fail to open V1 DB
    // and V1 should fail to open V2 DB
    let dir = test_dir("upgrade_downgrade");

    // Create V1 database (current version)
    let storage_v1 = Storage::open(&dir).unwrap();
    let (_hashes, _) = commit_prefix(&storage_v1, 3);
    drop(storage_v1);

    // Reopen with V1 - should work
    let storage_v1_reopen = Storage::open(&dir).unwrap();
    assert_eq!(storage_v1_reopen.get_tip().unwrap().unwrap().height, 3);
    drop(storage_v1_reopen);

    // Simulate V2 by writing a newer schema version
    {
        let db = raw_sled(&dir);
        let newer_version = CURRENT_SCHEMA_VERSION + 1;
        let key = SCHEMA_VERSION_KEY.to_vec();
        let value = newer_version.to_le_bytes().to_vec();
        db.insert(key, value).unwrap();
        db.flush().unwrap();
        drop(db);
    }

    // Try to open with current binary (V1) - should fail because DB has newer schema
    let result = Storage::open(&dir);
    assert!(
        result.is_err(),
        "current binary must refuse to open newer schema DB"
    );
    let err = result.as_ref().unwrap_err().to_string();
    assert!(err.contains("newer than supported version"));
    drop(result);

    // Reset to current version
    {
        let db = raw_sled(&dir);
        let key = SCHEMA_VERSION_KEY.to_vec();
        let value = CURRENT_SCHEMA_VERSION.to_le_bytes().to_vec();
        db.insert(key, value).unwrap();
        db.flush().unwrap();
        drop(db);
    }

    // Verify we can reopen with current version
    let storage_v1_again = Storage::open(&dir).unwrap();
    assert_eq!(storage_v1_again.get_tip().unwrap().unwrap().height, 3);
    drop(storage_v1_again);

    let _ = std::fs::remove_dir_all(&dir);
}
