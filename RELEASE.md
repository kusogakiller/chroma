# Chroma V1.0 Release Candidate — Artifact Record

## Artifact (Windows x86_64, built 2026-09-10)

- Version: `chroma 0.1.0` (`cargo --version` path: `target/release/chroma.exe`)
- Protocol version: `1`
- Schema version: `1`
- Networks: mainnet / testnet / regtest (default: mainnet)
- Mainnet genesis: `aa49c7aedb454e70623b9e5f0a5b0f2ad7245f646df5906c2ab97665c2db8374`
- Git commit: `689e6898a2346733fa04d71317a36d24058cc043` (branch `main`, NO tag)
- Target: `x86_64-pc-windows-msvc`
- Toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1`
- Size: 8,793,600 bytes (old backend; SUPERSEDED, see below)
- SHA-256: `A0C62A41B4A6021295B887B30D068D4219AC9F10B8986243614B72AB8B4AF091`
  (old backend; SUPERSEDED)

## Artifact (canonical RandomX, in-tree vendor)

- Built: release profile (`cargo build --release --locked -p chroma-cli`),
  exit 0, from the working tree including `vendor/randomx-rs`
- Version: `chroma 0.1.0`, protocol 1, schema 1
- Size: 8,978,944 bytes
- SHA-256: `0C34750FB0C08165C21E5AB3D52666BF867DFBDA16AD6F89D882AFA7F8FBA623`
- Toolchain/target: rustc 1.98.1, `x86_64-pc-windows-msvc`, CMake +
  MSVC 14.44 (MASM) for the vendored reference C++
- Single build only: reproducibility NOT PROVEN (see below)

## Environment-integrity incident (recorded, unresolved attribution)

During this phase, the file
`RandomX/src/asm/configuration.asm` (inside both the cargo-registry
extracted copy of `randomx-rs-1.6.0` and the in-tree vendor copy) was
found overwritten with ~2.4 KB of local-machine `fastfetch` output
(hostname, OS, hardware) three times (~23:15, ~23:51, and once more),
each time breaking the MASM step with `error A2008`. The pristine bytes
were verified against the checksum-verified `.crate` (1438 bytes,
`; File start: ..\src\configuration.h…`), restored, and set read-only;
the release build above completed with both copies verified intact
throughout (10 s polling). No fastfetch binary exists on PATH; no
scheduled task or process was identified; our own commands never wrote
to those paths. Cause UNKNOWN — recorded here so the next auditor can
re-verify: compare `vendor/randomx-rs/RandomX/src/asm/configuration.asm`
(1438 bytes) against the `.crate` before trusting any build.

## Provenance / reproducibility

- Built from a DIRTY working tree (48 modified files at audit time).
- NO release tag exists (`git describe` fails).
- NO independent rebuild / checksum comparison has been performed.
- Therefore: byte-for-byte reproducibility is NOT claimed. The checksum
  above identifies this specific local artifact only, not a published
  release.

## Consensus backend correction (must-read)

The artifact above was built with a NONCANONICAL PoW backend
(`rustdom-x`, also GPL-3.0) and is SUPERSEDED. The current tree uses
canonical reference RandomX (`randomx-rs`, BSD-3-Clause) with no GPL
dependencies remaining. Any binary built from the old backend MUST NOT
be distributed: it disagrees with canonical RandomX on every block and
carries an incompatible license.

Current mainnet genesis (`aa49c7ae…db8374`, bytes unchanged) is
trust-by-hash on all production paths (genesis PoW is never validated,
before or after the correction). Measured canonical PoW of the genesis
nonce-0 header does NOT meet mainnet target (expected: ~2^-32 luck);
re-mining at mainnet difficulty is computationally infeasible, no public
chain exists to migrate, and no validating path checks genesis PoW —
so the genesis bytes are kept, loudly documented here, NOT silently.

## Release-gate status

See the final audit report: `MAINNET V1.0: NO-GO`. Do not publish either
artifact as a final release.

## Reproducible build record (v0.1.0-rc2)

Release procedure (both proof builds):

```text
git checkout v0.1.0-rc2 (clean tree, submodules n/a — vendor is in-tree)
set RUSTFLAGS=-C link-arg=/Brepro -C link-arg=/PDBALTPATH:%_PDB%
  (also pinned in-tree as .cargo/config.toml for x86_64-pc-windows-msvc)
set CHROMA_RANDOMX_PATHMAP=<checkout>\vendor\randomx-rs\RandomX=RandomX
cargo build --release --locked -p chroma-cli
```

Bit-for-bit result (two separate clean checkouts, separate target dirs):

- Build #1 SHA-256: `F04B3F60AE66D2B7D1972E6AE8F8E6DF96EE309112B1820B1A6CED14F9A489F7`
- Build #2 SHA-256: `F04B3F60AE66D2B7D1972E6AE8F8E6DF96EE309112B1820B1A6CED14F9A489F7`
- `fc /b`: no differences. Sizes: 8,979,968 bytes each.

Nondeterminism sources found and neutralized (all build-metadata only,
no consensus/behavior change):

- PE COFF TimeDateStamp + CodeView PDB GUID (final link) → `/Brepro`.
- Absolute PDB path in the CodeView record → `/PDBALTPATH:%_PDB%`.
- Absolute C++ `__FILE__` literals (CRT assert paths in
  `randomx.cpp`/`dataset.cpp`/`reciprocal.c`) → `/pathmap` + `/d1trimfile`
  via `CHROMA_RANDOMX_PATHMAP` (see `vendor/randomx-rs/build.rs`).

Environment-integrity note: during this audit the file
`vendor/randomx-rs/RandomX/src/asm/configuration.asm` was twice overwritten
with local `fastfetch` output, breaking the MASM step (`error A2008`).
Root cause (proven): RandomX's VS build regenerates that file via
`powershell -File h2inc.ps1 ... > configuration.asm`, and this machine's
PowerShell `$PROFILE` runs `fastfetch` (+ `Set-Location`, which also breaks
h2inc's relative paths so only the fastfetch banner lands in the file).
Mitigation for release builds: verify the file (1438 bytes LF in git,
`57541A81…ADC` SHA-256 of the CRLF checkout copy) and set it read-only
before building. The committed blob is pristine; DNS steps and the two
proof builds above used the pristine bytes.
