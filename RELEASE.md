# Chroma V1.0 Release Candidate — 成果物記録

## 成果物 (Windows x86_64、2026-09-10 build)

- Version: `chroma 0.1.0` (`cargo --version` path: `target/release/chroma.exe`)
- Protocol version: `1`
- Schema version: `1`
- Networks: mainnet / testnet / regtest (既定: mainnet)
- Mainnet genesis: `aa49c7aedb454e70623b9e5f0a5b0f2ad7245f646df5906c2ab97665c2db8374`
- Git commit: `689e6898a2346733fa04d71317a36d24058cc043` (branch `main`、tagなし)
- Target: `x86_64-pc-windows-msvc`
- Toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`、`cargo 1.98.1`
- Size: 8,793,600 bytes (旧backend。SUPERSEDED、下参照)
- SHA-256: `A0C62A41B4A6021295B887B30D068D4219AC9F10B8986243614B72AB8B4AF091`
  (旧backend。SUPERSEDED)

## 成果物 (canonical RandomX、in-tree vendor)

- Build: release profile (`cargo build --release --locked -p chroma-cli`)、
  exit 0。`vendor/randomx-rs`込みのworking treeから
- Version: `chroma 0.1.0`、protocol 1、schema 1
- Size: 8,978,944 bytes
- SHA-256: `0C34750FB0C08165C21E5AB3D52666BF867DFBDA16AD6F89D882AFA7F8FBA623`
- Toolchain/target: rustc 1.98.1、`x86_64-pc-windows-msvc`、vendored reference C++用にCMake +
  MSVC 14.44 (MASM)
- 1回だけのbuildです。再現性は未証明（下参照）

## 環境完全性インシデント（記録済み、原因は不明のまま）

この期間中、ファイル
`RandomX/src/asm/configuration.asm`（cargo-registry展開の`randomx-rs-1.6.0`
コピーとin-tree vendorコピーの両方）が、ローカルマシンの`fastfetch`出力
約2.4 KB（hostname、OS、hardware）で3回上書きされました（23:15頃、23:51頃、
もう1回）。毎回MASMが`error A2008`で壊れました。pristine bytesはchecksum
済み`.crate`（1438 bytes、`; File start: ..\src\configuration.h…`）と
照合して戻し、read-onlyにしました。上のrelease buildは両コピーが壊れて
いないことを確認しながら通りました（10秒poll）。PATHにfastfetch binaryは
ありません。scheduled taskもプロセスも見つかりませんでした。自分たちの
コマンドがそのpathに書いたこともありません。原因不明です。次の監査の人が
再確認できるよう残します。buildを信じる前に`vendor/randomx-rs/RandomX/src/asm/configuration.asm`
(1438 bytes)を`.crate`と比べてください。

## Provenance / 再現性

- DIRTY working treeからbuildしました（監査時点で48 modified files）。
- release tagはありません（`git describe`失敗）。
- 独立rebuild / checksum比較はしていません。
- なのでbyte-for-byte再現性は主張しません。上のchecksumはこのローカル
  成果物の記録だけで、公開releaseのものではありません。

## Consensus backend訂正（必読）

上の成果物はNONCANONICAL PoW backend（`rustdom-x`、GPL-3.0つき）でbuild
したもので、SUPERSEDEDです。今のtreeはcanonical reference RandomX
（`randomx-rs`、BSD-3-Clause）で、GPL依存は残っていません。旧backendの
バイナリを配布してはいけません。全ブロックでcanonical RandomXと食い違い
ますし、licenseも合いません。

今のmainnet genesis（`aa49c7ae…db8374`、bytes不変）は全production pathで
trust-by-hashです（genesis PoWは前も後も検証しません）。genesis nonce-0
headerのcanonical PoW実測はmainnet targetに届きません（期待通り。約2^-32の
運）。mainnet difficultyで掘り直すのは計算量的に無理ですし、移行すべき
public chainもありません。genesis PoWを見るvalidating pathもありません。
なのでgenesis bytesはそのまま残します。黙ってではなく、ここにはっきり
書いて残します。

## 再現build記録 (v0.1.0-rc2)

Release手順（2回のproof buildとも）:

```text
git checkout v0.1.0-rc2 (clean tree、submodulesなし — vendorはin-tree)
set RUSTFLAGS=-C link-arg=/Brepro -C link-arg=/PDBALTPATH:%_PDB%
  (.cargo/config.tomlにもx86_64-pc-windows-msvc用に固定してあります)
set CHROMA_RANDOMX_PATHMAP=<checkout>\vendor\randomx-rs\RandomX=RandomX
cargo build --release --locked -p chroma-cli
```

bit-for-bit結果（別々のclean checkout、別々のtarget dir）:

- Build #1 SHA-256: `F04B3F60AE66D2B7D1972E6AE8F8E6DF96EE309112B1820B1A6CED14F9A489F7`
- Build #2 SHA-256: `F04B3F60AE66D2B7D1972E6AE8F8E6DF96EE309112B1820B1A6CED14F9A489F7`
- `fc /b`: 差分なし。Sizes: 8,979,968 bytesずつ。

見つけて潰した非決定性（build-metadataだけで、consensus/behavior不変）:

- PE COFF TimeDateStamp＋CodeView PDB GUID（最終link）→ `/Brepro`。
- CodeView recordの絶対PDB path → `/PDBALTPATH:%_PDB%`。
- C++ `__FILE__`リテラル絶対path（`randomx.cpp`/`dataset.cpp`/`reciprocal.c`の
  CRT assert path）→ `/pathmap`＋`/d1trimfile`
 （`CHROMA_RANDOMX_PATHMAP`経由。`vendor/randomx-rs/build.rs`参照）。

環境完全性メモ: この監査中にファイル
`vendor/randomx-rs/RandomX/src/asm/configuration.asm`が2回`fastfetch`出力で
上書きされ、MASMが`error A2008`で壊れました。
原因は確定しました。RandomXのVS buildがそのファイルを
`powershell -File h2inc.ps1 ... > configuration.asm`で作り直すのですが、
このマシンのPowerShell `$PROFILE`が`fastfetch`（＋`Set-Location`。h2incの
相対pathも壊すのでfastfetch bannerだけがファイルに入ります）を実行します。
release build前の緩和策: ファイルを確認して（gitで1438 bytes LF、
CRLF checkoutコピーのSHA-256 `57541A81…ADC`）read-onlyにしてからbuild
してください。commit済みblobはpristineです。DNS手順と2回のproof buildは
pristine bytesでやっています。

## リリース可否

最終監査報告を見てください。`MAINNET V1.0: NO-GO`です。どちらの成果物も
最終releaseとして公開しないでください。
