# Changelog

## [0.1.0] — V1.0 Release Candidate (UNRELEASED, NO-GO)

### Added

- DB schema versioning (`schema_version`, `CURRENT_SCHEMA_VERSION = 1`)
  with fail-closed startup checks (newer/older/corrupted refused).
- Crash-recovery test harness readiness signal for loop-mode kill tests.
- Corrupted schema-encoding rejection test.
- Non-blocking mining: RandomX PoW moved off tokio async workers
  (`spawn_blocking`); consensus logic unchanged.
- Operator documentation: `OPERATIONS.md`, `RELEASE.md`.
- Canonical RandomX: replaced `rustdom-x` (noncanonical + GPL-3.0) with
  vendored `randomx-rs` 1.6.0 (BSD-3-Clause, `[patch.crates-io]` at
  `vendor/randomx-rs`); dedicated worker thread (no `unsafe`); light mode.
  Measured: 4/4 official vectors under interpreter AND recommended
  (JIT/HARD_AES) flags; regtest release mining ~7 blocks/s at 288 MB RSS
  (was ~2.6 GB).
- Idle read deadline (`IDLE_EVICT_SECS`) in the P2P message loop so
  half-open connections self-terminate (SPEC §10 bound).

### Fixed

- `crash_real_kill_mid_stream_recovers_coherent_prefix` harness race
  (parent killed child before genesis commit): 100/100 PASS after fix.
- `e2e_chaos_reconnect_invalid_tx_cycle` handshake/scoring timeouts under
  mining load (miner starved async runtime; PoW moved to `spawn_blocking`,
  consensus logic unchanged): 4/4 PASS after fix, full E2E 48/61 → 60/61.
- Half-open connections now self-terminate after `IDLE_EVICT_SECS` without
  frames (same bound as peer-tick idle eviction); tick-level `Disconnect`
  alone only removed bookkeeping and could leave a zombie read task.
- `e2e_soak_restart_mining_continues` drain budget derived from the
  product's `IDLE_EVICT_SECS` bound instead of a fixed 60 s (assertion
  still exact-zero; leak detection preserved).

### Proven blockers (measured, not assumed)

- `rustdom-x 1.1.0` is NOT canonical RandomX: key "test key 000" + input
  "This is a test" yields `1829809f…` vs reference `639183aa…`. Chroma PoW
  is a consensus-incompatible variant. Equivalence DISPROVEN.
- `rustdom-x 1.1.0` is GPL-3.0; workspace is MIT OR Apache-2.0. Sole
  copyleft crate in the 301-crate tree. Distribution blocker.
- `cargo audit` (1243 advisories): 0 vulnerabilities; 2 unmaintained
  warnings (`fxhash`, `instant`, both via `sled 0.34.7`).

### Known issues (release blockers)

- DNS seeds `seed.chroma.network` / `seed-testnet.chroma.network` return
  NXDOMAIN; automatic bootstrap NOT PROVEN.
- Full E2E: 60/61 post-fix; `e2e_soak_restart_mining_continues` ~50% fail
  (miner holds departed inbound entry past 150 s; duplicate inbound
  ephemerals observed) — open FAIL, not labeled flaky.
- Release reproducibility NOT PROVEN (dirty tree, no tag, single build).
- Public testnet absent; cross-host restore untested.
