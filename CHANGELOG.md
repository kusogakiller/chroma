# Changelog

## [0.1.0] — V1.0 Release Candidate (UNRELEASED, NO-GO)

### 追加

- DB schema versioning (`schema_version`、`CURRENT_SCHEMA_VERSION = 1`)。
  fail-closed起動チェックつき（newer/older/corruptedは拒否）。
- loop-mode kill test用のcrash-recovery test harness readiness signal。
- schema-encoding壊れのrejection test。
- ノンブロッキングマイニング: RandomX PoWをtokio async workerから外して
  (`spawn_blocking`)。consensus logic不変。
- 運用ドキュメント: `OPERATIONS.md`、`RELEASE.md`。
- Canonical RandomX: `rustdom-x`（非正規＋GPL-3.0）をvendored
  `randomx-rs` 1.6.0 (BSD-3-Clause、`vendor/randomx-rs`の`[patch.crates-io]`)に
  置換。専用worker thread (`unsafe`なし)。light mode。
  実測: official vector 4/4がinterpreterとrecommended (JIT/HARD_AES)の
  両方で一致。regtest release mining約7 blocks/sでRSS 288 MB (前は約2.6 GB)。
- P2P message loopにidle read deadline (`IDLE_EVICT_SECS`)。half-open
  connectionが自分で終わるように (SPEC §10 bound)。

### 修正

- `crash_real_kill_mid_stream_recovers_coherent_prefix`のharness race
  （genesis commit前に親が子をkill）: 修正後100/100 PASS。
- `e2e_chaos_reconnect_invalid_tx_cycle`のmining負荷下handshake/scoring timeout
  （minerがasync runtimeを枯渇。PoWを`spawn_blocking`へ。consensus logic不変）:
  修正後4/4 PASS、E2E全体48/61 → 60/61。
- frameなし`IDLE_EVICT_SECS`超えのhalf-open connectionが自分で終わるように。
  tick側`Disconnect`だけだとbookkeepingしか消えずzombie read taskが残った。
- `e2e_soak_restart_mining_continues`のdrain budgetを固定60秒からproductの
  `IDLE_EVICT_SECS` bound由来に（assertionはexact-zeroのまま。leak検出維持）。

### 実測済みblocker

- `rustdom-x 1.1.0`はcanonical RandomXではない: key "test key 000"＋input
  "This is a test"で`1829809f…`が出る。正規は`639183aa…`。Chroma PoWとは
  consensus互換なし。等価性は否定済み。
- `rustdom-x 1.1.0`はGPL-3.0。workspaceはMIT OR Apache-2.0。301-crate treeで
  唯一のcopyleft crate。配布blocker。
- `cargo audit` (1243 advisories): 脆弱性0。unmaintained警告2つ
  (`fxhash`、`instant`、どちらも`sled 0.34.7`経由)。

### 既知の問題 (release blocker)

- DNS seed `seed.chroma.network` / `seed-testnet.chroma.network`は
  NXDOMAIN。自動bootstrap未実証。
- Full E2E: 修正後60/61。`e2e_soak_restart_mining_continues`が約50% fail
  （departed inbound entryが150秒超残る。duplicate inbound ephemeralあり）。
  open FAIL。flaky扱いなし。
- Release再現性未証明（dirty tree、tagなし、単一build）。
- Public testnetなし。cross-host restore未試験。
