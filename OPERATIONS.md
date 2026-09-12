# Chroma Node Operations Guide (V1.0 RC)

This document is the operator contract for Chroma `0.1.0`.
Anything not documented here is NOT supported in V1.0.

## 1. Installation

Supported target (verified): `x86_64-pc-windows-msvc`, Rust `1.98.1`.

From source (locked build):

```text
cargo build --release --locked
```

Binary: `target/release/chroma.exe` (`chroma 0.1.0`).

## 2. Networks

| Network | Genesis hash | P2P default port | Magic |
|---|---|---|---|
| mainnet | `aa49c7aedb454e70623b9e5f0a5b0f2ad7245f646df5906c2ab97665c2db8374` | 8333 | `C4 48 52 4F` ("CHRO") |
| testnet | `7a127bb73b88c9c4b833bcd24b4ef47111535f01e4bb100f54cd6bc1126c56be` | 18333 | `C4 54 45 53` |
| regtest | `1461c3e8f0d2827433cd94f8ccbabdab92609274e7c696143f81f1f505a427ed` | 8333 | `C4 52 54 54` |

Protocol version: `1`. Schema version: `1`.

## 3. Starting a node

Mainnet (default network):

```text
chroma node --data-dir <DIR> --miner-address <BECH32M_ADDRESS>
```

Regtest (local testing):

```text
chroma node --regtest --data-dir <DIR> --miner-address <ADDR>
```

Testnet:

```text
chroma node --testnet --data-dir <DIR> --miner-address <ADDR>
```

Important defaults:

- `--listen` defaults to `127.0.0.1:8333` (loopback only). To accept
  inbound public peers, bind explicitly, e.g.
  `--listen 0.0.0.0:8333`, and open TCP 8333 (mainnet) in the firewall.
- `--connect <ADDR>` may be repeated to add bootstrap peers.
  Regtest performs NO DNS discovery; peers come only from `--connect`.
- RPC is opt-in: `--rpc-listen <ADDR>` plus `CHROMA_RPC_API_KEY` env.
  Never expose RPC without an API key.
- `--insecure-plaintext-peers` is test/debug only and is REFUSED on mainnet.

## 4. Bootstrap (current status)

Mainnet/testnet DNS seeds are configured (`seed.chroma.network`,
`seed-testnet.chroma.network`) but **as of this RC they do not resolve
(NXDOMAIN)**. Therefore a fresh node with no `--connect` will stay at
0 peers. For V1.0 RC, bootstrap requires an explicit `--connect` to a
known reachable peer. Automatic DNS bootstrap is NOT PROVEN and must
not be assumed.

## 5. Monitoring

Logs report: listen address, network, genesis hash, Noise static public
key, mined heights (`[BLOCK] Mined: height=N`), peer errors.

An operator can determine height/tip via node logs and (if enabled) RPC.
There is no separate metrics endpoint in V1.0.

## 6. Shutdown

Stop the process (Ctrl-C / service stop) for a clean shutdown; the node
flushes state on commit paths. Forced termination is crash-safe at the
storage layer (atomic batches), but unflushed tail commits may roll back
to the last flushed prefix — this is expected and never torn.

## 7. Backup — official V1.0 contract

```text
BACKUP TYPE: STOPPED-NODE COLD BACKUP ONLY.
Live directory copying is NOT an atomic backup method and is NOT supported.
```

Procedure:

```text
1. stop node, wait for clean shutdown
2. copy the entire data directory to backup media
3. restart the original node
4. to restore: copy the backup to a separate directory on the target machine
5. start a node with --data-dir <restored dir>
6. verify: genesis hash, tip height/hash, state root, supply, balances
```

Cross-machine restore of a cold backup is supported by design (plain
files); it has been tested same-machine to a separate directory, not
yet across distinct hosts for this RC.

## 8. Upgrade policy (V1.0 contract: Option A — no migration)

V1.0 accepts ONLY schema version 1:

- schema > 1 → startup REFUSES (`newer than supported version`)
- schema < 1 → startup REFUSES (`migration not yet implemented`)
- missing version → initialized as new DB with version 1
- corrupted version encoding → startup REFUSES (`invalid schema version encoding`)

There is NO supported database migration in V1.0. Any future schema
change requires an explicit migration release. Before ANY upgrade:
take a cold backup (see §7); upgrades requiring migration will refuse
to start rather than risk data.

Downgrade across schema versions is NOT supported.

## 9. Resource requirements (measured, plus margin)

PoW backend: canonical RandomX reference (light cache-only VM, ~256 MB
Argon2 cache per seed; JIT/HARD_AES where the CPU offers them).
A previous RC used a noncanonical pure-Rust PoW (~2.6 GB RSS); those
figures no longer apply. Re-measure before sizing from this document.

Older measurement (obsolete backend, kept for history, DO NOT USE for
sizing): RSS ~2.6 GB, virtual ~6.8 GB, 19 threads.

- Disk: ~1.9 KB per empty block (377,835 bytes / 201 blocks; backend-independent)
- Regtest mining: a few seconds per block on the test machine (debug builds slower)

Requirements (conservative, light-mode RandomX):

- Minimum RAM: 2 GB (RandomX cache ~256 MB + chain state + OS headroom)
- Recommended RAM: 4 GB
- Mining node: 4 GB (light-mode mining needs no dataset; a future
  FULL_MEM mode would need ~2 GB extra for the dataset)
- Minimum free disk: 10 GB (chain growth plus OS/pagefile headroom)

Measured (Windows x86_64, release binary, regtest mining node,
canonical light mode): RSS **288 MB**, 22 threads, 110 handles,
~7 blocks/s on easy regtest difficulty (i7-9700K). Debug builds hash
slower (~1–3 s per light-mode hash all-in); validation costs one hash
per block.

Mainnet sync measurements are impossible until public bootstrap exists;
treat the above as floor values, not sync-validated sizing.

## 10. Security notes

- Transport: Noise XX (`25519-ChaChaPoly-BLAKE2s`), TOFU identity
  binding. First-contact MITM is NOT prevented (no trust anchor).
- RPC: require API key, bind loopback unless a reverse proxy with auth
  is in front.
- Firewall: expose only the P2P port you intend to serve.
