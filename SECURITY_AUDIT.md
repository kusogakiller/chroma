# Chroma Phase 1 & 2 セキュリティ監査報告

**日付:** 2026-09-06
**範囲:** Phase 1 (Wallet Keystore) + Phase 2 (JSON-RPC Server)
**監査:** 実装コードのadversarial review

---

## A. Keystore: KDF (Argon2id)

**場所:** `crates/chroma-wallet/src/keystore.rs:50-60`

| Finding | Severity | Status |
|---------|----------|--------|
| Argon2idでm=65536 (64MB)、t=3、p=4は妥当な選択 | OK | — |
| `derive_key`がOOM時に`.expect("argon2 hash failed")`でpanicする | LOW | testnetは許容。本番はerrorを返すべき |
| Argon2 allocatorのメモリ上限なし | INFO | 標準Rust Argon2 crateはjemalloc/stdlib。許容 |

**結論:** KDFパラメータは十分です。latency budgetが許せばmainnet用に`m`を131072 (128MB)に上げてもいいです。失敗時のpanicは許容します。derivation失敗はfatal errorなので。

---

## B. Keystore: AES-256-GCM暗号化

**場所:** `crates/chroma-wallet/src/keystore.rs:69-111`

| Finding | Severity | Status |
|---------|----------|--------|
| AES-256-GCM、暗号化ごとにrandom 12-byte nonce | OK | — |
| Nonceは`rand::thread_rng()` (CSPRNG)で作る | OK | — |
| 暗号化失敗は`.expect("encryption failed")`で扱う | INFO | 許容。暗号化失敗＝メモリ破壊だから |

**結論:** 暗号化は健全です。random nonceで一意です。問題ありません。

---

## C. Keystore: MAC検証

**場所:** `crates/chroma-wallet/src/keystore.rs:62-67, 125-129`

| Finding | Severity | Status |
|---------|----------|--------|
| MAC = Blake3(ciphertext ‖ derived_key) | OK | — |
| MAC比較が`[u8]` sliceの`!=` (constant-timeではない) | MEDIUM | `subtle::ConstantTimeEq`を使うべき |
| 導出鍵をMACと暗号化で兼用 (dual-use) | INFO | 標準通りで許容。AEADがintegrityを持っている |

**攻撃シナリオ:** keystore fileに触れるローカル攻撃者が、MAC比較タイミングを測ってpassword正誤を当てる手があります。実際はArgon2id derivation (~50-200ms)が支配的なので非現実的です。でもdefense-in-depthでconstant-time比較がいいです。

**推奨:** `subtle` crateを入れて`ConstantTimeEq`を使う:
```rust
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&expected_mac).into() { ... }
```

---

## D. Keystore: ファイル形式とシリアライズ

**場所:** `crates/chroma-wallet/src/keystore.rs:19-48, 149-162`

| Finding | Severity | Status |
|---------|----------|--------|
| Keystore形式: v1 version fieldつきJSON | OK | — |
| `save_keystore`は`serde_json::to_string_pretty`を使う | INFO | 人間可読で許容 |
| `save_keystore`がfile permissionを設定しない (0644で作る) | HIGH | Linux/macOSでworld-readable |
| atomic writeなし (書き込み中crash＝壊れfile) | MEDIUM | temp file＋renameにすべき |
| Keystore fileに平文addressとhash160が入る | INFO | 想定通り。addressはpublicだから |

**攻撃シナリオ (HIGH):** 共有Linuxで`wallet create`が`wallets/<name>.json`を既定umask (大体0644)で作ります。全ローカルユーザーが読めます。鍵は暗号化されていますが、弱いpasswordならoffline brute-forceされます。

**推奨:**
1. 作った後に0600にする: `std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))`
2. atomic write: `.tmp`に書いてからrenameする。

---

## E. Keystore: メモリセキュリティ

**場所:** `crates/chroma-wallet/src/keystore.rs:113-147`、`crates/chroma-wallet/src/lib.rs:128-131`

| Finding | Severity | Status |
|---------|----------|--------|
| `Wallet::drop`が`secret_key.0.zeroize()`を呼ぶ | OK | — |
| `decrypt_key`は`[u8; 32]`を返す — 呼び出し側がzeroize必須 | MEDIUM | `change_password`の`key_bytes`は`_key_bytes` bindでzeroizeするがDropが動くか不明 |
| `derive_key`のローカル`key`配列を明示zeroizeしない | LOW | スタック確保。scope exitで落ちるがzeroingが最適化で消えるかも |
| `encrypt_key`は`&[u8; 32]` secret受取 — 使用後zeroizeしない | MEDIUM | 呼び出し側責任だが指針なし |

**攻撃シナリオ (MEDIUM):** `decrypt_key`が返った後、平文鍵がstack frame上書きまでプロセスメモリに残ります。process dump (core dump、/proc/memなど)で漏れます。

**推奨:**
1. `decrypt_key`の戻りにwrapper typeで`zeroize`をつける。
2. `change_password`で`_key_bytes`を明示zeroizeする (`[u8; 32]`のDropはRustが保証しない)。
3. 戻り型に`zeroize::Zeroizing<[u8; 32]>`を検討する。

---

## F. CLIセキュリティ

**場所:** `crates/chroma-cli/src/main.rs:297-377`

| Finding | Severity | Status |
|---------|----------|--------|
| `wallet create`は隠し入力に`rpassword`を使う | OK | — |
| `wallet export`は`yes`確認がないと鍵を出さない | OK | — |
| `wallet export`は鍵を`println!`でstdoutに出す | MEDIUM | terminal scrollbackに見える。pipeすればshell historyにも |
| `wallet import --key`はhex鍵をCLI argで受ける | HIGH | `/proc/<pid>/cmdline`、shell history、`ps`に見える |
| password比較`password != confirm`がconstant-timeでない | INFO | 許容。security-criticalではない |
| password promptにtimeoutなし | INFO | CLIなので許容 |

**攻撃シナリオ (HIGH):** `chroma wallet import --name my --key <hex>`は秘密鍵をprocess command lineに載せます。全ローカルユーザーが`ps aux`や`/proc/*/cmdline`で見えます。shell historyにも残ります。

**推奨:** `--key` CLI argを消す。stdinかfileで渡す:
```
echo "abcdef1234..." | chroma wallet import --name my --key-stdin
chroma wallet import --name my --key-file /path/to/key.txt
```

---

## G. RPC: Bindと認証

**場所:** `crates/chroma-rpc/src/lib.rs:32-53`、`crates/chroma-rpc/src/auth.rs`

| Finding | Severity | Status |
|---------|----------|--------|
| RPCは`SocketAddr`にbindする (設定可、既定127.0.0.1) | OK | — |
| API key認証は`X-API-Key` header | OK | — |
| API key比較が`==` (constant-timeではない) | HIGH | タイミングside-channel |
| API keyなし＝open access (認証不要) | HIGH | networkに届くとcritical |
| CORSが`CorsLayer::permissive()` (全origin許可) | MEDIUM | browser経由攻撃がありうる |
| per-IP rate limitingなし | MEDIUM | DoS vector |
| connection limitなし | LOW | DoS vector |
| `lib.rs:69-74`と`handler.rs:18-23`の二重auth check | INFO | 冗長だが無害 |

**攻撃シナリオ:**

1. **タイミング攻撃 (HIGH):** `auth.rs:13`が`provided == key`です。たくさん測ってAPI keyをbyteずつ当てられます。auth pathにArgon2はないので測れます。

2. **Open access (HIGH):** `--rpc-api-key`なしだと`state.api_key`が`None`で、`verify_api_key`は全requestに`Ok(())`を返します。RPC portがnetworkに届くと全endpointが露出します。

3. **CORS (MEDIUM):** `CorsLayer::permissive()`は全originを許します。悪意webページがユーザーのローカルノードへcross-origin RPCできます。

**推奨:**
1. API key比較に`subtle::ConstantTimeEq`を使う。
2. API keyなしは警告を出す。non-localhost bind時はkey必須も検討する。
3. CORSはlocalhost originに絞るか、CORS layerを取る (RPCはbrowserから使わない)。

---

## H. RPC: Rate Limitingと並行処理

**場所:** `crates/chroma-rpc/src/lib.rs:39-53`

| Finding | Severity | Status |
|---------|----------|--------|
| `RequestBodyLimitLayer::new(1024 * 1024)` — body上限1MB | OK | — |
| `TimeoutLayer::new(30s)` — request timeout 30秒 | OK | — |
| per-IP rate limitingなし | HIGH | Amplification/DoS |
| global request rate limitingなし | MEDIUM | DoS |
| `sendRawTransaction`がvalidation中ずっと`mempool.write()`を持つ | MEDIUM | lock競合。単一tx bottleneck |
| `getHeaders`が最大1001 iterationsまで`chain_state.read()`を持つ | LOW | read lockが長いことがある |

**攻撃シナリオ:**

1. **Amplification DoS (HIGH):** 攻撃者がそれっぽいtransactionで`sendRawTransaction`をfloodできます。各requestがmempool write lockを取るので全部直列化します。rate limitingと合わさってnodeが止まります。

2. **メモリ枯渇 (MEDIUM):** global request数上限なし。たくさん同時接続を開いて、各1MBまでbody bufferを持てます。

**推奨:**
1. `tower::limit::ConcurrencyLimitLayer`を入れる (同時100くらい)。
2. `tower::limit::RateLimitLayer`か自前middlewareでper-IP rate limitを入れる。
3. `sendRawTransaction`だけの`RateLimit`も検討する (IPごと10/secくらい)。

---

## I. RPC: JSON-RPC正しさとerror handling

**場所:** `crates/chroma-rpc/src/error.rs`、`crates/chroma-rpc/src/handler.rs`

| Finding | Severity | Status |
|---------|----------|--------|
| JSON-RPC 2.0 error code (-32700、-32600、-32601、-32602、-32603)を正しく使う | OK | — |
| batch request非対応 | INFO | specではbatchは任意 |
| `jsonrpc` fieldを検証しない (何でも受ける) | LOW | "2.0"を見るべき |
| `handle_get_block_by_height`が`u64`をrange checkなしで`u32`にcastする | LOW | JSONのparamsはu32::MAXを超えられる |
| `handle_get_block_by_hash`が全headerの線形scan O(n) | LOW | 性能問題。securityではない |
| 内部error messageをclientに出す (例 "password incorrect") | MEDIUM | 情報漏れ |
| request ID検証なし (何のJSON値でも受ける) | INFO | specではIDは何でもいい |

**攻撃シナリオ:**

1. **情報漏れ (MEDIUM):** `sendRawTransaction`がmempool validationの`e.to_string()`を返します。"transaction signature verification failed"とか"mempool full"とか内部状態が見えます。

2. **u32 overflow (LOW):** `params.get("height").as_u64() as u32`はu32::MAX超えを黙って切り捨てます。

**推奨:**
1. clientに返す前にerror messageをsanitizeする。
2. range checkを入れる: `if height > u32::MAX as u64 { return Err(...) }`。

---

## J. Transaction Validation (Mempool連携)

**場所:** `crates/chroma-p2p/src/mempool.rs:41-67`、`crates/chroma-rpc/src/handler.rs:209-233`

| Finding | Severity | Status |
|---------|----------|--------|
| Mempool検証: signature、amount > 0、sender ≠ recipient | OK | — |
| Mempoolはchain stateに対するbalance/nonceを見ない | INFO | 設計通り。block inclusion時に検証する |
| `sendRawTransaction`はhash計算のためdeserializeしてre-serializeする | LOW | 無駄。raw bytesからhashできる |
| mempool AND chainをまたぐ(sender, nonce)重複検出なし | LOW | confirm済みtxを受け入れるかも |

**攻撃シナリオ (LOW):** 攻撃者がconfirm済みtransactionを`sendRawTransaction`で出せます。mempoolに入って、block inclusionで初めて落ちます。mempoolが無駄になります。

**推奨:** mempoolに入れる前に(sender, nonce)をchain stateと照合してもいいです。

---

## K. Wallet ↔ Transaction連携の用意

| Finding | Severity | Status |
|---------|----------|--------|
| `Wallet::create_transaction`は`chroma_tx::create_transaction`に正しく委譲する | OK | — |
| `create_transaction`はamount > 0、sender ≠ recipientを見る | OK | — |
| `create_transaction`は導出addressがsenderと一致するか見る | OK | — |
| nonce管理なし (呼び出し側が正しいnonceを出す) | INFO | Phase 3の仕事 |
| `Wallet::secret_bytes()`はraw `[u8; 32]`を返す — 使用後zeroizeされない | MEDIUM | 呼び出し側がzeroize必須 |

**Phase 3の前提:**
1. chain stateからのnonce取得 (RPCかlocal storage accessが必要)。
2. 送る前のbalance check (RPCかlocal storage accessが必要)。
3. `secret_bytes()`の戻りは使用後zeroize必須。

---

## L. Cross-Networkセキュリティ

| Finding | Severity | Status |
|---------|----------|--------|
| Mainnet、testnet、regtestでnetwork magic bytesが別 | OK | — |
| networkごとにgenesis hashがpin留め | OK | — |
| RPC serverはnetwork contextを強制しない | INFO | 許容。1ノード1networkだから |

---

## M. 回帰テストカバー

| Area | Tests | Status |
|------|-------|--------|
| Keystore encrypt/decrypt roundtrip | ✅ `test_encrypt_decrypt_roundtrip` | OK |
| Wrong password rejection | ✅ `test_wrong_password_fails` | OK |
| Save/load roundtrip | ✅ `test_save_load_roundtrip` | OK |
| Change password | ✅ `test_change_password` | OK |
| Salt uniqueness | ✅ `test_different_salts_produce_different_ciphertext` | OK |
| JSON format validation | ✅ `test_keystore_json_format` | OK |
| Mempool validation (valid, zero amount, self-send, bad sig) | ✅ 4 tests | OK |
| Mempool nonce replacement | ✅ `test_nonce_replacement` | OK |
| **RPC API key auth** | ❌ MISSING | **追加必須** |
| **RPC unauthorized rejection** | ❌ MISSING | **追加必須** |
| **RPC malformed request** | ❌ MISSING | **追加必須** |
| **RPC body size limit** | ❌ MISSING | **追加必須** |
| **Keystore file permissions** | ❌ MISSING | **追加必須** |
| **Constant-time MAC comparison** | ❌ MISSING | **追加必須** |

---

## Summary: Severity別Findings

| Severity | Count | Items |
|----------|-------|-------|
| **HIGH** | 4 | API keyタイミング攻撃、keyなしopen access、cmdlineのCLI `--key`、keystore file permission |
| **MEDIUM** | 6 | MAC非constant-time、keystore非atomic write、permissive CORS、rate limitingなし、sendRawTransaction lock競合、error message漏れ |
| **LOW** | 5 | Argon2 panic、jsonrpc field未検証、u32切捨て、線形hash scan、hash再計算 |
| **INFO** | 7 | 設計判断いろいろ。testnetは許容 |

---

## 推奨修正優先度

### CRITICAL (testnet前に直す)
1. **API keyタイミング攻撃** — `auth.rs`に`subtle::ConstantTimeEq`を使う
2. **API keyなしopen access** — 警告を出す。non-localhost bind時はkey必須を検討する
3. **CLI `--key`のprocess cmdline露出** — `--key` argを消してstdin/fileにする
4. **Keystore file permission** — Linux/macOSで0600にする

### HIGH (testnet前に直すべき)
5. **MAC比較constant-time** — `subtle::ConstantTimeEq`を使う
6. **Atomic keystore write** — temp fileに書いてrenameする
7. **CORS制限** — localhostに絞るか取る
8. **Rate limiting** — concurrency limit＋per-IP rate limitを入れる

### MEDIUM (mainnetまででいい)
9. **メモリzeroization** — `decrypt_key`の戻りkey bytesをzeroizeする
10. **Error message sanitization** — 内部validation errorを出さない
11. **重複tx検出** — mempool受け入れ前に(sender, nonce)をchain stateと照合する

### LOW (あればいい)
12. `jsonrpc` fieldが"2.0"か見る
13. height parameterのrange check
14. `sendRawTransaction`のhash計算を速くする

---

## Phase 3 Blocker

wallet send flow (Phase 3)の前に以下を片付けること:

1. **Constant-time API key比較** (HIGH)
2. **Keystore file permission** (HIGH)
3. **CLI `--key`セキュリティ** (HIGH)
4. **RPC authの回帰テスト追加** (MEDIUM)

Phase 3実装はこれらを直して検証してから進めていいです。
