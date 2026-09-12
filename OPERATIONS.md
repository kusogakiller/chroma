# Chromaノード運用ガイド (V1.0 RC)

この文書はChroma `0.1.0`の運用契約です。
ここに書いていないことはV1.0ではサポート外です。

## 1. インストール

対応ターゲット（確認済み）: `x86_64-pc-windows-msvc`、Rust `1.98.1`。

ソースから（locked build）:

```text
cargo build --release --locked
```

バイナリ: `target/release/chroma.exe` (`chroma 0.1.0`)。

## 2. ネットワーク

| Network | Genesis hash | P2P default port | Magic |
|---|---|---|---|
| mainnet | `aa49c7aedb454e70623b9e5f0a5b0f2ad7245f646df5906c2ab97665c2db8374` | 8333 | `C4 48 52 4F` ("CHRO") |
| testnet | `7a127bb73b88c9c4b833bcd24b4ef47111535f01e4bb100f54cd6bc1126c56be` | 18333 | `C4 54 45 53` |
| regtest | `1461c3e8f0d2827433cd94f8ccbabdab92609274e7c696143f81f1f505a427ed` | 8333 | `C4 52 54 54` |

Protocol version: `1`。Schema version: `1`。

## 3. ノードの起動

Mainnet（既定）:

```text
chroma node --data-dir <DIR> --miner-address <BECH32M_ADDRESS>
```

Regtest（ローカル試験）:

```text
chroma node --regtest --data-dir <DIR> --miner-address <ADDR>
```

Testnet:

```text
chroma node --testnet --data-dir <DIR> --miner-address <ADDR>
```

大事な既定値:

- `--listen`は既定で`127.0.0.1:8333`（loopbackのみ）。外からの接続を
  受けるには`--listen 0.0.0.0:8333`のように明示して、ファイアウォールで
  TCP 8333 (mainnet)を開けてください。
- `--connect <ADDR>`は繰り返し指定できて、bootstrap peerを追加します。
  RegtestはDNS探索をしません。peerは`--connect`だけで増えます。
- RPCはopt-inです。`--rpc-listen <ADDR>`と環境変数`CHROMA_RPC_API_KEY`が
  要ります。APIキーなしでRPCを公開しないでください。
- `--insecure-plaintext-peers`は試験・デバッグ用で、mainnetでは拒否されます。

## 4. Bootstrap（今の状態）

Mainnet/testnetのDNS seedは設定してあります（`seed.chroma.network`、
`seed-testnet.chroma.network`）が、**このRC時点では解決しません
(NXDOMAIN)**。なので`--connect`なしのfresh nodeはpeerが0のままです。
V1.0 RCのbootstrapは、到達できる既知peerへの明示`--connect`が必要です。
DNS自動bootstrapは未実証なので当てにしないでください。

## 5. 監視

ログに出るのは: listen address、network、genesis hash、Noise static public
key、採掘height（`[BLOCK] Mined: height=N`）、peer errorです。

height/tipはノードログと（有効なら）RPCで確認できます。
V1.0にmetrics endpointはありません。

## 6. 停止

きれいに止めるにはプロセスを止めます（Ctrl-C / service stop）。commit
経路でflushするので、強制終了でもstorage層は壊れません（atomic batch）。
flush前の末尾commitは最後のflushed prefixまで戻ることがあります。
想定内ですし、壊れた状態にはなりません。

## 7. バックアップ — V1.0の正式契約

```text
BACKUP TYPE: STOPPED-NODE COLD BACKUP ONLY.
起動中のディレクトリコピーはatomicなバックアップ方法ではなく、非対応です。
```

手順:

```text
1. ノードを止めて、きれいに終わるのを待つ
2. データディレクトリ全体をバックアップ媒体へコピーする
3. 元ノードを再起動する
4. 戻すときは別ディレクトリへコピーしてから使う
5. --data-dir <戻したdir> でノードを起動する
6. 確認: genesis hash、tip height/hash、state root、supply、balances
```

別マシンへのcold backup戻しは設計上できます（ただのファイルです）。
same-machineの別ディレクトリでは試験済みですが、このRCでは
別host間はまだ試していません。

## 8. アップグレード方針（V1.0契約: migrationなし）

V1.0が受け付けるのはschema version 1だけです:

- schema > 1 → 起動拒否 (`newer than supported version`)
- schema < 1 → 起動拒否 (`migration not yet implemented`)
- versionなし → version 1の新規DBとして作る
- version壊れ → 起動拒否 (`invalid schema version encoding`)

V1.0にDB migrationはありません。将来schemaが変わったらmigration用の
リリースが必要です。アップグレード前は必ずcold backupを取ってください
(§7)。migrationが必要なアップグレードは、データを危険にさらすより
起動拒否します。

schema versionをまたぐダウングレードは非対応です。

## 9. リソース要件（実測＋余裕）

PoW backend: canonical RandomXリファレンス（light cache-only VM。seed
ごとに約256 MBのArgon2 cache。CPUが対応していればJIT/HARD_AES）。
昔のRCは非正規のpure-Rust PoW（RSS約2.6 GB）でしたが、その数字はもう
使いません。サイズ見積もり前に測り直してください。

古い測定（旧backendのもの。歴史として残します。サイズ見積もりに
使わないでください）: RSS約2.6 GB、virtual約6.8 GB、19 threads。

- Disk: 空ブロック1個あたり約1.9 KB (377,835 bytes / 201 blocks。backend不問)
- Regtest mining: 試験マシンで1ブロック数秒 (debug buildは遅いです)

要件（light-mode RandomXで余裕を見て）:

- 最小RAM: 2 GB (RandomX cache約256 MB＋chain state＋OS余裕)
- 推奨RAM: 4 GB
- マイニングノード: 4 GB (light-mode miningにdatasetは不要。将来の
  FULL_MEM modeは約2 GB余分に要ります)
- 最小空きdisk: 10 GB (chain増加＋OS/pagefile余裕)

実測（Windows x86_64、release binary、regtest mining node、
canonical light mode）: RSS **288 MB**、22 threads、110 handles、
easy regtest difficultyで約7 blocks/s (i7-9700K)。debug buildのhashは
遅いです（全部で1 hash 1〜3秒くらい）。validationは1ブロック1 hashです。

Mainnet syncの測定はpublic bootstrapができるまで無理です。
上は下限値として見てください。sync済みの値ではありません。

## 10. セキュリティ注意

- Transport: Noise XX (`25519-ChaChaPoly-BLAKE2s`)、TOFUのidentity
  binding。初回MITMは防げません（trust anchorなし）。
- RPC: APIキー必須。loopbackにbindしてください。前にauth付きの
  reverse proxyを置く場合を除きます。
- Firewall: 公開するつもりのP2P portだけ開けてください。
