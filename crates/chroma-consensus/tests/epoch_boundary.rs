//! RandomX epoch-1000 live-chain boundary validation.
//!
//! Production-path proof (no PoW bypass, real `RANDOMX_EPOCH_LENGTH = 1000`):
//! fresh regtest chain → assemble → `ensure_randomx_for_height` (miner) →
//! `mine_block_with_limit` (production canonical RandomX) → `apply_block`
//! (validator: ensure + `validate_block` PoW check + state commit) for every
//! height 1..=1001, crossing the epoch 0 → 1 boundary at height 1000.
//!
//! Isolated in its own test target (own process) because the RandomX worker
//! is process-global: parallel tests in other targets use the genesis seed,
//! while this test legitimately switches the VM to the epoch-1 seed.

use chroma_consensus::{
    build_genesis_for_network,
    miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext},
    NetworkKind,
};
use chroma_core::constants::{
    GENESIS_RANDOMX_SEED, RANDOMX_EPOCH_LENGTH, RANDOMX_SEED_LAG, REGTEST_MAGIC,
};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, BlockHeight};
use chroma_crypto::randomx::{
    derive_seed, ensure_randomx_for_height, epoch_for_height, hash_meets_target, pow_randomx,
};

fn miner_addr() -> Address {
    let mut h = [0u8; 20];
    h[0] = 0xDE;
    h[1] = 0xAD;
    h[2] = 0xBE;
    h[3] = 0xEF;
    Address::from_hash160(Hash160(h))
}

/// Test A+B+C in one sequential run (single #[test] => no intra-process
/// RandomX races): mine heights 1..=1001 through the full production
/// pipeline, assert the epoch transition at 1000 with miner/validator seed
/// agreement, then restart from storage and re-validate PoW.
#[test]
fn test_randomx_epoch1000_live_chain_boundary() {
    // --- Epoch selection sanity (pure function, no RandomX needed) ---
    assert_eq!(epoch_for_height(999, RANDOMX_EPOCH_LENGTH), 0);
    assert_eq!(epoch_for_height(1000, RANDOMX_EPOCH_LENGTH), 1);
    assert_eq!(epoch_for_height(1001, RANDOMX_EPOCH_LENGTH), 1);
    assert_eq!(RANDOMX_SEED_LAG, 100);

    let genesis = build_genesis_for_network(&NetworkKind::Regtest);
    let genesis_hash = genesis.hash();
    let mut chain =
        chroma_consensus::ChainState::with_genesis_from(&genesis, REGTEST_MAGIC);
    assert_eq!(chain.tip.height.0, 0);

    let storage = chroma_storage::Storage::open_temporary().unwrap();
    storage.apply_block(&genesis).unwrap();
    let genesis_work = chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    );
    storage
        .put_tip(&chroma_storage::PersistedTip {
            height: 0,
            hash: genesis_hash,
            cumulative_work: genesis_work,
            supply: 0,
        })
        .unwrap();
    storage.flush().unwrap();

    let miner = miner_addr();
    let genesis_seed = Hash::blake3(GENESIS_RANDOMX_SEED);

    let mut hashes: std::collections::BTreeMap<u32, Hash> = Default::default();
    hashes.insert(0, genesis_hash);
    let mut reinit_at: Vec<u32> = Vec::new();

    // --- Test A: full production pipeline for heights 1..=1001 ---
    for height in 1u32..=1001u32 {
        let (prev_hash, prev_ts) = {
            let tip = chain.best_tip();
            (tip.hash, tip.header.timestamp)
        };
        let bits =
            chroma_consensus::calculate_target_for_height(height, &chain.headers).unwrap();
        // Easy regtest target must hold across all 1001 blocks (hold-steady).
        assert_eq!(
            bits.0, 0x20ffffff,
            "height {}: regtest difficulty must hold steady",
            height
        );
        // Coinbase-only prospective state root, exactly as the production
        // miner computes it before assembly.
        let prospective = chain
            .state
            .compute_prospective_state_root(height, &miner, &[])
            .unwrap();

        let actx = BlockAssemblyContext {
            height: BlockHeight(height),
            previous_hash: prev_hash,
            previous_timestamp: prev_ts,
            state_root: prospective,
            bits,
            coinbase_recipient: miner,
        };
        let mut block = assemble_block(&actx, &[]).unwrap();
        block.header.timestamp = prev_ts + 10;

        // Miner side: epoch selection + seed init (production entry point).
        let miner_reinit =
            ensure_randomx_for_height(height, |h| chain.headers.get(&h).map(|hdr| hdr.hash()))
                .expect("miner ensure must succeed");
        if miner_reinit {
            reinit_at.push(height);
        }

        mine_block_with_limit(&mut block, 10_000_000).expect("regtest mining must succeed");

        // Validator side: apply_block re-ensures the same epoch seed
        // internally, then validate_block runs pow_randomx + target check.
        chain.apply_block(&block).unwrap_or_else(|e| {
            panic!("height {}: production validation must succeed: {}", height, e)
        });

        assert_eq!(chain.tip.height.0, height);
        assert_eq!(chain.tip.hash, block.hash());
        hashes.insert(height, block.hash());

        // Persist every block so restart/revalidation reads real storage.
        let tip = &chain.tip;
        storage
            .commit_block(
                &block,
                &chroma_storage::PersistedTip {
                    height: tip.height.0,
                    hash: tip.hash,
                    cumulative_work: tip.cumulative_work.to_be_bytes(),
                    supply: tip.supply,
                },
                &chain.state,
            )
            .unwrap();

        // Explicit PoW validity on boundary blocks (beyond apply success):
        // recompute under the CURRENT (validator-agreed) VM context.
        if (998..=1001).contains(&height) {
            let pow = pow_randomx(
                &block.header.previous_hash,
                &block.header.tx_merkle_root,
                block.header.nonce,
                &[],
            )
            .expect("pow recompute must succeed");
            assert!(
                hash_meets_target(&pow, &block.header.bits.to_full_target()),
                "height {}: PoW must meet target under agreed seed",
                height
            );
            // Linkage + height pins.
            assert_eq!(block.header.height.0, height);
            assert_eq!(block.header.previous_hash, hashes[&(height - 1)]);
        }
    }
    storage.flush().unwrap();

    // --- Test B: the epoch transition actually happened at height 1000 ---
    // Exactly two (re-)inits: initial VM creation at height 1, then the
    // epoch 0 → 1 transition at height 1000. No other height may rebuild.
    assert_eq!(
        reinit_at,
        vec![1, 1000],
        "only height 1 (initial init) and 1000 (epoch transition) may re-init"
    );
    let seed_block_height = 1 * RANDOMX_EPOCH_LENGTH - RANDOMX_SEED_LAG;
    assert_eq!(seed_block_height, 900);
    let expected_epoch1_seed = derive_seed(&hashes[&900]);
    assert_ne!(
        expected_epoch1_seed, genesis_seed,
        "epoch-1 seed must differ from genesis seed"
    );
    // The live VM must now serve the epoch-1 seed: a fresh ensure for epoch 1
    // is a no-op (already current), proving miner & validator converged.
    let again = ensure_randomx_for_height(1001, |h| hashes.get(&h).cloned())
        .expect("ensure must succeed");
    assert!(
        !again,
        "epoch-1 context must already be current after the boundary"
    );
    // Boundary linkage pins.
    for h in [998u32, 999, 1000, 1001] {
        let blk = storage.get_block_by_height(h).unwrap().unwrap();
        assert_eq!(blk.header.height.0, h);
        assert_eq!(blk.hash(), hashes[&h]);
    }

    // --- Test C: restart — tip/lookup/PoW revalidation from storage ---
    let tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(tip.height, 1001);
    assert_eq!(tip.hash, hashes[&1001]);
    drop(chain);
    for h in [999u32, 1000, 1001] {
        let blk = storage.get_block_by_height(h).unwrap().unwrap();
        assert_eq!(blk.header.height.0, h, "restart: block lookup");
        // Re-resolve the epoch seed from STORED canonical hashes (the same
        // closure shape the p2p miner uses) and re-verify PoW.
        let epoch = epoch_for_height(h, RANDOMX_EPOCH_LENGTH);
        let seed_ok = ensure_randomx_for_height(h, |wanted| {
            storage.get_canonical_hash_at_height(wanted).ok().flatten()
        });
        assert!(seed_ok.is_ok(), "restart: seed resolution must succeed");
        if epoch == 1 {
            // Stored seed preimage must be height 900.
            let preimage = storage
                .get_canonical_hash_at_height(900)
                .unwrap()
                .unwrap();
            assert_eq!(preimage, hashes[&900]);
            assert_eq!(derive_seed(&preimage), expected_epoch1_seed);
        }
        let pow = pow_randomx(
            &blk.header.previous_hash,
            &blk.header.tx_merkle_root,
            blk.header.nonce,
            &[],
        )
        .expect("restart: pow recompute must succeed");
        assert!(
            hash_meets_target(&pow, &blk.header.bits.to_full_target()),
            "restart: height {} PoW must still verify",
            h
        );
    }
}
