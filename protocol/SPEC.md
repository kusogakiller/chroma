# Chroma プロトコル仕様書 v0.1

> "We are truly free."

## 1. プロトコル識別情報

| パラメータ    | 値                                           |
| -------- | ------------------------------------------- |
| 名称       | Chroma                                      |
| ティッカー    | CHR                                         |
| 最小単位     | 1 unit = 10⁻⁶ CHR                           |
| 最大供給量    | 100,000,000 CHR = 100,000,000,000,000 units |
| 初期供給量    | 0 CHR（プレマインなし）                              |
| ブロック報酬   | 1 CHR/block                                 |
| 上限到達後の報酬 | 0                                           |
| 目標ブロック時間 | 10秒                                         |

## 2. コンセンサス

### 2.1 フォーク選択

* 累積PoW仕事量が最大のチェーンを正規チェーンとする
* ブロック数ではなく、チェーン全体の累積仕事量を比較する
* 累積仕事量は各ブロックについて `2²⁵⁶ / target_i` を合計して求める
* 累積仕事量が同一の場合、先端ブロックのハッシュが小さいチェーンを優先する

### 2.2 実用上のファイナリティ

* 1ブロック確認はUX上の目安であり、プロトコル上の確定性を意味しない
* プロトコルレベルのファイナリティ機構は設けない
* チェックポイントおよび投票による確定機構は使用しない

### 2.3 Reorg

* 直近2000ブロック分（約5.5時間）のState Journalを保持する
* Reorg発生時はJournalを巻き戻し、新しいチェーンを適用する
* Journalの範囲を超えるReorgではGenesisから状態を再計算する

## 3. RandomX Seed

| パラメータ    | 値                                 |
| -------- | --------------------------------- |
| Epoch長   | 1000ブロック                          |
| Seed Lag | 100ブロック                           |
| Seed導出   | `epoch_start - lag` のブロックハッシュから導出 |
| ハッシュ関数   | BLAKE3                            |
| PoW実装    | canonical RandomX リファレンス実装（`randomx-rs` 経由の tevador/RandomX C++ ソース。非互換な代替実装は認めない） |
| VMモード    | light（cache-only）または full。どちらも同一のコンセンサスハッシュを生成しなければならない（リファレンス保証） |
| Cacheコスト | light: 約256 MB RAM、初期化1〜数秒。full dataset（約2 GB）を使う場合もコンセンサス結果は同一 |

100ブロックのSeed Lagにより、Seedのgrindingを抑制する。

* Seedを意図的に操作するためのブロック隠蔽確率：1/1000 per block
* 100ブロック未満のReorgではSeedは変更されない

### 3.1 PoW入力と検証

RandomXへの入力バイト列（固定レイアウト、順序変更はhard fork）:

```text
pow_input = prev_hash (32 bytes, raw)
          || tx_merkle_root (32 bytes, raw)
          || nonce (8 bytes, u64 little-endian)
          || extra_nonce (可変長、そのまま連結)
```

* 出力32 bytesをbig-endian u256として解釈し、`output <= target(bits)` の場合のみ有効。
* ブロック識別のためのBLAKE3 header hashはPoW判定に使わない（PoW hashとblock hashは別物）。
* Genesisブロック（height 0）はPoW検証の対象外とし、genesis hashによるtrust-by-hashで受け入れる。全ネットワークのgenesisは固定バイト列であり、PoW関数の変更でgenesisバイト列は変わらない。

### 3.2 Canonical RandomX適合性

* 実装はcanonical RandomXリファレンス（tevador/RandomX）とバイト一致しなければならない。
* 適合性テストベクター（key `"test key 000"`, input `"This is a test"` → `639183aa…b4e3f` 他）はリポジトリ内の回帰テストで固定する。非互換なPoW実装への置換はconsensus breaking changeとして扱う。

## 4. Canonical Serialization

### 4.1 ルール

* エンコーダーとデコーダーは明示的に定義する
* `repr(C)` およびSerdeのデフォルトシリアライズには依存しない
* 整数は固定幅のlittle-endianでエンコードする
* Hashはbig-endian（display order）で扱う
* 可変長データはLEB128 length prefixを使用する
* 配列はLEB128 length prefixに続けて各要素を連結する
* `Option` は1-byte tagを使用する（`0x00 = None`, `0x01 = Some`）
* Structのフィールドは宣言順にエンコードする
* Enumは1-byte discriminantに続けてvariant dataをエンコードする

### 4.2 Canonical Hash

```text
canonical_hash(S) = BLAKE3(encode(S))
```

### 4.3 Test Vectors

```text
u64(0)                          → 00 00 00 00 00 00 00 00
u64(1_000_000)                 → 40 42 0F 00 00 00 00 00
u64(18446744073709551615)      → FF FF FF FF FF FF FF FF
Vec<u8>([])                     → 00
Vec<u8>([1,2,3])                → 03 01 02 03
Option(u32, Some(42))           → 01 2A 00 00 00
```

## 5. ブロックおよびトランザクションの制限

| 制限                 | 値                     |
| ------------------ | --------------------- |
| 最大ブロックサイズ          | 1 MB（1,048,576 bytes） |
| 最大トランザクションサイズ      | 64 KB                 |
| Mempool最大サイズ       | 50 MB                 |
| Mempool最大トランザクション数 | 100,000               |
| Peerレート制限          | 100 msg/s / peer      |
| Txレート制限            | 10 tx/s / peer        |

## 6. 署名

**アルゴリズム:** secp256k1上のSchnorr署名（BIP-340 style）

**Batch Verification:** 有効

**Nonce:** 決定論的Nonce（RFC 6979 / BIP-340 synthetic nonce）

### 6.1 トランザクション正規エンコーディング

通常トランザクションは固定132 bytes:

```text
sender_pubkey: 32 bytes (x-only BIP-340 public key, raw bytes)
recipient:     20 bytes (raw Hash160, Bech32変換なし)
amount:         8 bytes (u64 little-endian, atomic units)
nonce:          8 bytes (u64 little-endian)
signature:     64 bytes (BIP-340 Schnorr r||s, raw bytes)
```

`txid = BLAKE3(canonical_encode(tx))`。`network_magic` は正規エンコーディング自体には含まれない。

### 6.2 ネットワークマジック

| ネットワーク | マジック (4 bytes) | 備考 |
| ------- | ---------------- | ---- |
| Mainnet | `C4 48 52 4F` | P2P `MAGIC` / sighash domain と共用 |
| Testnet | `C4 54 45 53` | P2P `TESTNET_MAGIC` と共用 |
| Regtest | `C4 52 54 54` | P2P `REGTEST_MAGIC` と共用 |

* サイズ: 4 bytes。エンディアン変換なし（raw byte列としてそのまま使用）。
* P2Pマジックはtransport framing専用であり、トランザクションのcryptographic replay protectionではない。P2Pマジックのみをreplay protectionの根拠にしてはならない。

### 6.3 トランザクションSighash（ネットワークドメイン分離あり）

署名対象preimage（87 bytes固定）:

```text
sighash = BLAKE3(
    b"Chroma Transaction Signing v1" ||  // 27 bytes, ASCII domain tag
    network_magic                ||  // 4 bytes, raw, sighash内の挿入位置はdomain tag直後
    sender                       ||  // 20 bytes, raw Hash160
    recipient                    ||  // 20 bytes, raw Hash160
    amount_le8                   ||  // 8 bytes, u64 little-endian
    nonce_le8                        // 8 bytes, u64 little-endian
)
```

* `network_magic` はdomain tag直後・sender直前に挿入する。順序変更はhard fork。
* `amount` / `nonce` は正規エンコーディングと同一のlittle-endian u64。
* `sender` / `recipient` はraw 20-byte Hash160（Bech32文字列ではない）。
* 署名自身（64 bytes）はsighashに含めない（unsigned preimageのみ署名）。
* 同一 `(sender, recipient, amount, nonce)` でもネットワークが異なればsighashが異なり、署名は他ネットワークで検証失敗する。これがconsensus-levelのcross-network replay protectionである。
* 正規エンコーディングの先頭68 bytes（pubkey 32 + recipient 20 + amount 8 + nonce 8）はネットワーク間で同一だが、署名64 bytesが異なるため、エンコーディング全体およびtxidはネットワークごとに異なる。

### 6.4 Coinbaseの扱い

* Coinbaseは署名対象外。`sender_pubkey = [0u8; 32]`、`signature = [0u8; 64]` のsentinel値を持ち、sighash経路に入ってはならない。
* Coinbaseは `verify_signature()` をいかなる `network_magic` でも通過してはならない（全ネットワークで失敗すること）。
* Coinbaseはmempoolの署名検証で拒否されなければならず、ブロック先頭txとしてのみ有効（報酬額・nonce=0・zero sentinelの検査あり）。

## 7. State Model

### 7.1 Account

```text
key: Hash160(pubkey) → 20 bytes
value: { balance: u64, nonce: u64 } → 16 bytes
```

### 7.2 State Commitment

Stateは、`(key, value)` ペアをkeyの辞書順でソートしたSorted Merkle Treeによってcommitする。

* Leaf: `H(encode(key) || encode(value))`
* Internal Node: `H(left || right)`
* Empty Root: 32 bytes of zero
* Proof: Merkle path（`log₂N` sibling hashes）

## 8. Difficulty Adjustment

**調整間隔:** 10ブロック

**計算式:**

```text
new_target = old_target × actual_time / target_time
```

**変化幅:** 0.25×〜4× / adjustment

**最初の調整:** height 10。GenesisからBlock 10までのtimestampを使用する。

**演算:** overflow防止のため、intermediate calculationにはu256を使用する。

**表現:** Compact `bits`（1-byte exponent + 3-byte mantissa）

**絶対範囲:** retarget結果は`[MINIMUM_TARGET, MAXIMUM_TARGET]`にclampされる。`MAXIMUM_TARGET`はgenesis難度の約4倍の易しさ（bytes `00 03 FF FF C0 00…`、canonical compact `0x1F03FFFF`）。

**Easy-regime hold:** current target（U256数値比較。compact直接比較ではない）が`MAXIMUM_TARGET`より易しい場合、retargetでもclampせず現行`bits`をそのまま維持する（compactのroundtripなし）。clampするとmainnet級難度（`0x1f03ffff`、約16k倍）に跳ね上がるため。

### 8.1 Network別 difficulty policy（正式仕様）

| network | genesis bits | regime | retarget時の挙動 |
| ------- | ------------ | ------ | --------------- |
| mainnet | `0x1d00ffff`（difficulty 1、範囲内） | production regime | 通常algorithm。`current > MAXIMUM`にはvalid chainから到達不能（genesis範囲内＋毎heightの`bits`一致検証による）。旧実装とbit-exact同一 |
| testnet | `0x20ffffff`（easy、範囲外。`MAXIMUM`より約16k倍易しい） | easy-regime（意図的・固定） | 全retargetでhold。difficultyは進化しない（height 10/20/…/1000で`0x20ffffff`維持）。開発・E2E用の高速採掘を目的とする |
| regtest | `0x20ffffff`（easy、範囲外） | easy-regime（意図的・固定） | testnetと同一。local testing用 |

**`current_target > MAXIMUM_TARGET`が存在した場合の各networkの動作:**

* mainnet: 起きない。万一そのようなheaderが提出されても`expected_bits`不一致で却下される（`validate_block`の`bits`一致検証）。minerもvalidatorも同一共有関数を使うためskewしない
* testnet/regtest: 正常系。genesis自体が該当し、holdにより採掘可能difficultyを維持する

**将来の公開testnet:** 現行のeasy固定testnetは公開用には不適切（PoW securityなし）。公開testnet開始時はproduction-validなgenesis（範囲内bits＋新規genesis hash＋chain restart）で別途定義する。本SPECのtestnet条項は開発・E2E用testnetの仕様である。

## 9. Timestamp

| ルール        | 値                               |
| ---------- | ------------------------------- |
| 過去側の制限     | `T > median_time_past`（直近7ブロック） |
| 未来側の制限     | `T ≤ network_time + 20 seconds` |
| MTP Window | 7ブロック                           |
| 使用箇所       | Difficulty Adjustment           |

## 10. Networking

| プロパティ                | 値                                    |
| -------------------- | ------------------------------------ |
| Transport            | TCP + Noise_XX_25519_ChaChaPoly_BLAKE2s（§10.6参照） |
| Node Identity        | data-dir永続のX25519 static key（§10.6参照） |
| Discovery（Regtest）   | 明示 `--connect` のみ（DNS不使用）          |
| Discovery（Testnet以降） | DNS Seeds + 明示 `--connect`            |
| Outbound Connections | 8（`MAX_OUTBOUND_PEERS`）               |
| Inbound Connections  | 16（`MAX_INBOUND_PEERS`）               |
| Total Connections    | 24（全状態合算。handshakeも消費する）         |
| Per-IP Connections   | 3（`MAX_PER_IP_PEERS`。port rotationで回避不可） |
| Handshake Concurrency | 8（`MAX_HANDSHAKE_CONCURRENT`）        |
| Peer Scoring         | Score ≤ -200 → Ban（§10.3参照）         |

### 10.1 Framing制限

* Message frame: magic 4 + type 1 + len 4 (LE u32) + checksum 4 + payload
* `MAX_MESSAGE_SIZE` = 4 MiB。lengthはallocation前に検証する
* `MAX_INV_ENTRIES` = 100,000（Inv/GetDataのdecode上限）
* `MAX_INV_FOLLOW` = 500（1メッセージあたりの後続処理上限。lookup/応答をboundする）
* Headers応答: 最大2000件（`MAX_HEADERS_PER_RESPONSE`）。受信側も2000件超のcountを拒否する
* Block要求バッチ: 最大500件（`MAX_BLOCKS_PER_REQUEST`）

### 10.2 Handshake

* `Version` (32 bytes) → `VerAck` (空) の順序のみ受理。それ以外の順序・種別は拒否
* `VERSION_TIMEOUT_SECS` = 10。timeout時はslot解放＋score -20
* protocol version不一致・self-connection（nonce一致）は拒否＋score -20
* handshake失敗は全て単一cleanup経路を通る（slot leakなし、score記録あり）
* idle eviction: 90秒無言のReady peerは切断（`IDLE_EVICT_SECS`）

### 10.3 Scoring / Ban（確定的tier）

| 事象 | Score | 備考 |
| ---- | ----- | ---- |
| dial失敗/timeout | -5 | 通常のnetwork error。banに直結しない |
| rate limit違反 | -10 | msg 100/s、tx 10/s（burst可） |
| malformed handshake/message | -20 | 10回でban |
| invalid transaction | -50 | 4回でban |
| invalid block/header batch | -100 | 2回でban |

* Ban条件: score ≤ -200（`BAN_SCORE_THRESHOLD`）。Ban期間は3600秒
* BanはSocketAddrとIPの両方に記録する。source port rotationでは回避できない
* Ban record上限は1024件（超過分は最古expiryからevict）。切断時もlive banは保持する
* score decay: 5分ごとに±1ずつ0へ戻す（ban expiryも同時にreap）

### 10.4 Reconnect

* 自動reconnectはoperator指定 `--connect` 先のみ対象
* exponential backoff: 5, 10, 20, … 上限300秒（`RECONNECT_BASE_SECS` / `MAX_RECONNECT_BACKOFF_SECS`）。deterministic（jitterはloop側で0〜4秒）
* reconnect tickは15秒。peer不足時のみdialする。shutdown後はdialしない

### 10.5 Sync / IBD

* Header batchはchain linkageを検証する（先頭がknown chainに接続し、heightが+1ずつ連続）。unlinked/conflicting batchはbufferせず、scoreせず無視する。header層ではhonest forkと区別できないため、有効・無効の判定はblock適用時のPoW/state検証で行い、確定したByzantine判定だけscoreする
* sync中はsync peer以外のbatch（空batch含む）を無視する。切断時はsync stateをresetし、健全peerが引き継げる
* header buffer上限は10,000件（`MAX_PENDING_HEADERS`）
* GetHeaders応答は2000件まで。block batch要求は500件まで
* sync失敗カウンタは5回でpeer-ban event（`MAX_SYNC_FAILURES`）。invalid blockのうちPoW・state/merkle root・coinbase・size・署名の確定失敗だけ送信peerにscore -100する。fork/orphan/staleの競合はscoreしない

### 10.6 Noise Transport（implemented）

**Suite:** `Noise_XX_25519_ChaChaPoly_BLAKE2s`（pattern XX / DH X25519 / cipher ChaChaPoly / hash BLAKE2s）。suite文字列は`chroma-crypto::noise::NOISE_PARAMS`の一箇所で定義し、transport層はそれを参照する（drift不可）。

**Handshake順序（全接続共通）:** TCP → connection gate（§10 caps）→ Noise handshake → application handshake（Version/VerAck）→ framed messages。Noise handshakeにも既存のconnection/handshake capsとtimeoutが適用され、迂回はできない。

**Handshake sequence（empty payloads）:**

```text
initiator (outbound dialer)          responder (inbound listener)
  -- e ------------------------------------>
  <--------------------------- e, ee, s, es
  -- s, se -------------------------------->
```

Framingは`u16 LE length || bytes`、1メッセージ上限2048 bytes、全体deadline 10秒。handshake payloadは常に空であり、network magic等のapplication dataは混ぜない（replay protection semantics不変のため）。

**Node identity:**

* X25519 static private key（32 bytes）を`<data-dir>/noise_identity`に永続化。形式は64文字hex単一行
* 初回起動時にOS CSPRNGで生成し、temp file + renameでatomic write、Unixでは0600
* 再起動後は同一ファイルからloadし、同一static public keyを維持する
* malformed/wrong-length/all-zeroのkey fileはfatal startup errorとする。無言の再生成は禁止（backupからrestoreすること）
* wallet/consensus秘密鍵とは完全分離。identity keyをargv/log/error/RPCに出さない（Debug表示はpublic keyのみ）
* 起動時にstatic public key（hex）をinfo logへ出力する

**Authentication model（TOFU — 明確化）:**

* XXは事前知識なしで両者のstatic keyを交換する。初回接続のMITMは防止できない（trust anchorなし）
* passive盗聴は防止する。handshake完了後のactive MITMはChaChaPoly認証で検出・切断する
* 各peer addressに初見static keyをbindし、変更時は警告eventを発してbind更新する（availability優先。scoreは付けない）
* static key一致によるself-connection検出あり（app nonce検査はdefense in depthとして維持）

**Plaintext policy:**

* defaultはNoise必須。Noise handshake失敗は即切断し、plaintext fallbackは存在しない（fallback path自体がコードにない）
* test/debug用の明示opt-in `allow_plaintext_peers`（CLI `--insecure-plaintext-peers`）のみplaintextを話す。mainnetでは指定しても起動拒否する
* opt-in時もcaps/scoring/framing等のhardeningは同一コード pathで有効

**Session:**

* 送受信はsnow TransportStateの独立nonce系列（64-bit）。順序・重複排除はTCP順序＋nonce検証で成立し、tamper/replay/truncationは復号失敗→切断（fail closed）
* `REKEY_AFTER_MESSAGES` = 100,000ごとに両方向rekey（TCP順序保証により両端が同一messageで同期）
* transport message上限は65535 bytes（タグ含む）。application frameは32 KiB chunkに分割して送信する
* 暗号化後のframingは`u32 LE length || ciphertext`（上限65551）。lengthはallocation前に検証する。復号後の既存wire limits（4 MiB等）はそのまま適用する

**Failure behavior:**

* handshake timeout、malformed、crypto失敗は全てscore -20＋slot解放。shutdown中はscoreなしでquiet teardownする
* read/write taskはbounded channel（64）のまま。暗号化はµs単位のCPU処理のみで`.await`を跨がないため、backpressure特性はplaintext時と同一

## 11. 不変条件

以下の条件は、いかなる場合も破ってはならない。

1. Total Supply ≤ 100,000,000 CHR
2. Balanceが負にならないこと（checked arithmetic）
3. AccountごとのNonceが厳密に増加すること
4. Signatureが有効であること（Schnorr verification）
5. RandomX PoWハッシュ（§3.1の入力レイアウト）がPoW Targetを満たすこと（headerのBLAKE3ハッシュではない）
6. Merkle RootがTransactionと一致すること
7. State RootがBlock適用後のStateと一致すること
8. `Timestamp > MTP` かつ `Timestamp ≤ network_time + 20s`
9. Block Size ≤ 1 MB
10. Transaction Size ≤ 64 KB
11. Integer overflow / underflowが発生しないこと

## 12. 実装アーキテクチャ

```text
chroma/
├── Cargo.toml
├── crates/
│   ├── chroma-core/          # Constants, Types, Serialization
│   ├── chroma-crypto/        # Schnorr, Hashing, RandomX, Noise
│   ├── chroma-state/         # Merkle Tree, State Transition, Journal
│   ├── chroma-tx/            # Transaction, Validation, Mempool
│   ├── chroma-block/         # Header, Block, Validation
│   ├── chroma-consensus/     # Fork Choice, Difficulty, PoW Verify
│   ├── chroma-storage/       # sled Backend
│   ├── chroma-p2p/           # Networking
│   ├── chroma-wallet/        # Key Management
│   ├── chroma-rpc/           # JSON-RPC
│   └── chroma-cli/           # Main Binary
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── consensus/
│   ├── fuzz/
│   └── devnet/
└── protocol/
    ├── SPEC.md               # 本仕様書
    └── test_vectors/
```

### Consensus-Critical Crates

1. `chroma-core`
2. `chroma-crypto`
3. `chroma-state`
4. `chroma-tx`
5. `chroma-block`
6. `chroma-consensus`
7. `chroma-storage`（State Root persistence）

## 13. 未解決事項

* Upgrade mechanism（v1では仕様をfreezeし、別途設計する）
* DNS Seed Operatorのgovernance
* Light Client Protocol
* RPC/API仕様
* Wallet Seed Phrase（Protocolでは規定しない。UX上の方式は別途検討する）
* Testnet parameters（Mainnetとは異なる可能性がある）
