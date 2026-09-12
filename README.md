# Chroma

Chroma（CHR）は、Rustで開発されている独立型のProof-of-Work（PoW）ブロックチェーンです。

**ティッカー:** CHR
**開発状況:** 初期開発段階

## 概要

Chromaは、独立した分散型PoWネットワークの構築を目的としたブロックチェーンプロジェクトです。

プロトコルの仕様は [`protocol/SPEC.md`](protocol/SPEC.md) に定義されています。

## ワークスペース構成

```text
chroma/
 crates/
    chroma-block/       # ブロック構造ブロック関連処理
    chroma-cli/         # コマンドラインインターフェース
    chroma-consensus/   # コンセンサスマイニング
    chroma-core/        # コア型基本プリミティブ
    chroma-crypto/      # 暗号プリミティブ
    chroma-p2p/         # P2Pネットワーク
    chroma-state/       # ブロックチェーン状態
    chroma-storage/     # 永続ストレージ
    chroma-tx/          # トランザクション
    chroma-wallet/      # ウォレット
 protocol/
    SPEC.md             # プロトコル仕様
 tests/
    integration/        # 統合テスト
 Cargo.toml
 Cargo.lock
```

## ビルド

必要なもの：

* Rust toolchain
* Cargo

ワークスペース全体をビルド：

```bash
cargo build --workspace
```

## テスト

ワークスペース全体のテストを実行：

```bash
cargo test --workspace
```

## 開発状況

Chromaは現在、初期開発段階です。

プロトコルおよび実装は、今後の開発に伴って大きく変更される可能性があります。

コンセンサスやプロトコルレベルの仕様については、[`protocol/SPEC.md`](protocol/SPEC.md) を主要なリファレンスとします。

## 運用 (Operators)

ノードの運用手順は [`OPERATIONS.md`](OPERATIONS.md) を参照してください。
リリース成果物の記録は [`RELEASE.md`](RELEASE.md)、変更履歴は
[`CHANGELOG.md`](CHANGELOG.md) にあります。

注意: 現時点で `seed.chroma.network` は名前解決できません (NXDOMAIN)。
`--connect` なしの自動ブートストラップは未実証です。バックアップは
停止中コールドバックアップのみ対応です。詳細は `OPERATIONS.md` を参照。

## License (planned)

`Cargo.toml` declares `MIT OR Apache-2.0` as the intended workspace
license; the final license text files have not been added yet.

## ライセンス

ライセンスはプロジェクトのライセンス方針確定後に追加されます。
