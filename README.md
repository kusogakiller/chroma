# Chroma

Rustで書かれた、独立したProof-of-Workブロックチェーンです。ティッカーはCHMです。

まだ開発の初期段階です。仕様は[`protocol/SPEC.md`](protocol/SPEC.md)に書いてあります。

## 構成

```text
chroma/
  crates/
    chroma-block/       # ブロック
    chroma-cli/         # 実行バイナリ
    chroma-consensus/   # コンセンサスとマイニング
    chroma-core/        # 基本の型と定数
    chroma-crypto/      # 署名、ハッシュ、RandomX、Noise
    chroma-p2p/         # P2Pネットワーク
    chroma-rpc/         # JSON-RPCサーバー
    chroma-state/       # アカウント状態
    chroma-storage/     # sledによる保存
    chroma-tx/          # トランザクション
    chroma-wallet/      # 鍵管理
  protocol/
    SPEC.md             # プロトコル仕様
```

## ビルド

```bash
cargo build --release --locked -p chroma-cli
```

再現性のあるビルド手順は[`RELEASE.md`](RELEASE.md)を見てください。

## テスト

```bash
cargo test --workspace
```

## 使い方

ノードの起動方法は[`OPERATIONS.md`](OPERATIONS.md)にあります。変更履歴は
[`CHANGELOG.md`](CHANGELOG.md)です。

注意: `seed.chroma.network`は今は名前解決できません (NXDOMAIN)。
`--connect`なしの自動bootstrapは未実証です。バックアップは
停止中のコールドバックアップだけ対応しています。

## ライセンス

`MIT OR Apache-2.0`
