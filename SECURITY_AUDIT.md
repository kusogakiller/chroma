# Chroma Phase 1 & 2 Security Audit Report

**Date:** 2026-09-06  
**Scope:** Phase 1 (Wallet Keystore) + Phase 2 (JSON-RPC Server)  
**Auditor:** Adversarial review of implementation code

---

## A. Keystore: KDF (Argon2id)

**Location:** `crates/chroma-wallet/src/keystore.rs:50-60`

| Finding | Severity | Status |
|---------|----------|--------|
| Argon2id with m=65536 (64MB), t=3, p=4 is a reasonable choice | OK | — |
| `derive_key` panics with `.expect("argon2 hash failed")` on OOM | LOW | Acceptable for testnet; production should propagate error |
| No memory limit enforcement for Argon2 allocator | INFO | Standard Rust Argon2 crate uses jemalloc/stdlib; acceptable |

**Verdict:** KDF parameters are adequate. Consider raising `m` to 131072 (128MB) for mainnet if latency budget allows. The panic on failure is acceptable since a failed derivation is a fatal error.

---

## B. Keystore: AES-256-GCM Encryption

**Location:** `crates/chroma-wallet/src/keystore.rs:69-111`

| Finding | Severity | Status |
|---------|----------|--------|
| AES-256-GCM with random 12-byte nonce per encryption | OK | — |
| Nonce generated via `rand::thread_rng()` (CSPRNG) | OK | — |
| Encryption failure handled with `.expect("encryption failed")` | INFO | Acceptable; encryption failure = memory corruption |

**Verdict:** Encryption is sound. Random nonces ensure uniqueness. No issues found.

---

## C. Keystore: MAC Verification

**Location:** `crates/chroma-wallet/src/keystore.rs:62-67, 125-129`

| Finding | Severity | Status |
|---------|----------|--------|
| MAC = Blake3(ciphertext ‖ derived_key) | OK | — |
| MAC comparison uses `!=` on `[u8]` slices (NOT constant-time) | MEDIUM | Should use `subtle::ConstantTimeEq` |
| Derived key is reused for MAC and encryption (dual-use) | INFO | Acceptable per standard practice; AEAD already provides integrity |

**Attack scenario:** A local attacker with access to the keystore file could theoretically measure MAC comparison timing to confirm password correctness. In practice, Argon2id derivation (~50-200ms) dominates timing, making this attack unrealistic. However, defense-in-depth recommends constant-time comparison.

**Recommendation:** Add `subtle` crate dependency, use `ConstantTimeEq`:
```rust
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&expected_mac).into() { ... }
```

---

## D. Keystore: File Format & Serialization

**Location:** `crates/chroma-wallet/src/keystore.rs:19-48, 149-162`

| Finding | Severity | Status |
|---------|----------|--------|
| Keystore format: JSON with v1 version field | OK | — |
| `save_keystore` uses `serde_json::to_string_pretty` | INFO | Human-readable, acceptable |
| `save_keystore` does NOT set file permissions (creates 0644) | HIGH | World-readable on Linux/macOS |
| No atomic write (crash during write = corrupted file) | MEDIUM | Should use temp file + rename |
| Keystore file contains plaintext address and hash160 | INFO | Expected; address is public |

**Attack scenario (HIGH):** On a shared Linux system, `wallet create` creates `wallets/<name>.json` with default umask permissions (typically 0644). Any local user can read the file. While the key is encrypted, an attacker can offline-brute-force weak passwords.

**Recommendations:**
1. Set file permissions to 0600 after creation: `std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))`
2. Use atomic write: write to `.tmp` file, then rename.

---

## E. Keystore: Memory Security

**Location:** `crates/chroma-wallet/src/keystore.rs:113-147`, `crates/chroma-wallet/src/lib.rs:128-131`

| Finding | Severity | Status |
|---------|----------|--------|
| `Wallet::drop` calls `secret_key.0.zeroize()` | OK | — |
| `decrypt_key` returns `[u8; 32]` — caller must zeroize | MEDIUM | `key_bytes` in `change_password` is zeroed via `_key_bytes` binding but Drop may not trigger |
| `derive_key` local `key` array not explicitly zeroized | LOW | Stack-allocated; drops on scope exit but compiler may optimize out zeroing |
| `encrypt_key` receives `&[u8; 32]` secret — not zeroized after use | MEDIUM | Caller responsibility, but no guidance |

**Attack scenario (MEDIUM):** After `decrypt_key` returns, the plaintext key remains in process memory until the stack frame is overwritten. If the process is dumped (e.g., core dump, /proc/mem), the key is exposed.

**Recommendation:**
1. Add `zeroize` to the return of `decrypt_key` via a wrapper type.
2. In `change_password`, ensure `_key_bytes` is explicitly zeroized (Rust doesn't guarantee Drop for `[u8; 32]`).
3. Consider `zeroize::Zeroizing<[u8; 32]>` as return type.

---

## F. CLI Security

**Location:** `crates/chroma-cli/src/main.rs:297-377`

| Finding | Severity | Status |
|---------|----------|--------|
| `wallet create` uses `rpassword` for hidden input | OK | — |
| `wallet export` requires `yes` confirmation before displaying key | OK | — |
| `wallet export` prints key to stdout via `println!` | MEDIUM | Visible in terminal scrollback, shell history if piped |
| `wallet import --key` accepts hex key via CLI arg | HIGH | Visible in `/proc/<pid>/cmdline`, shell history, `ps` output |
| Password comparison `password != confirm` not constant-time | INFO | Acceptable; not security-critical |
| No timeout on password prompts | INFO | Acceptable for CLI |

**Attack scenario (HIGH):** `chroma wallet import --name my --key <hex>` stores the private key in the process command line, visible to all local users via `ps aux` or `/proc/*/cmdline`. Shell history also retains it.

**Recommendation:** Remove `--key` CLI arg option. Require `--key` to be provided via stdin or file:
```
echo "abcdef1234..." | chroma wallet import --name my --key-stdin
chroma wallet import --name my --key-file /path/to/key.txt
```

---

## G. RPC: Binding & Authentication

**Location:** `crates/chroma-rpc/src/lib.rs:32-53`, `crates/chroma-rpc/src/auth.rs`

| Finding | Severity | Status |
|---------|----------|--------|
| RPC binds to `SocketAddr` (configurable, defaults to 127.0.0.1) | OK | — |
| API key auth via `X-API-Key` header | OK | — |
| API key comparison uses `==` (NOT constant-time) | HIGH | Timing side-channel |
| No API key = open access (no auth required) | HIGH | Critical if exposed to network |
| CORS layer is `CorsLayer::permissive()` (allows all origins) | MEDIUM | Browser-based attacks possible |
| No rate limiting per-IP or global | MEDIUM | DoS vector |
| No connection limit | LOW | DoS vector |
| Double auth check in `lib.rs:69-74` AND `handler.rs:18-23` | INFO | Redundant but not harmful |

**Attack scenarios:**

1. **Timing attack (HIGH):** `auth.rs:13` uses `provided == key`. An attacker can measure response times across many requests to guess the API key byte-by-byte. Argon2 is not in the auth path, so timing is measurable.

2. **Open access (HIGH):** If `--rpc-api-key` is not provided, `state.api_key` is `None`, and `verify_api_key` returns `Ok(())` for any request. If the RPC port is reachable from the network, all endpoints are exposed.

3. **CORS (MEDIUM):** `CorsLayer::permissive()` allows any origin. A malicious webpage could make cross-origin RPC calls to a user's local node.

**Recommendations:**
1. Use `subtle::ConstantTimeEq` for API key comparison.
2. If no API key is set, log a warning. Consider requiring API key when binding to non-localhost.
3. Restrict CORS to localhost origins, or remove CORS layer (RPC is not browser-accessible).

---

## H. RPC: Rate Limiting & Concurrency

**Location:** `crates/chroma-rpc/src/lib.rs:39-53`

| Finding | Severity | Status |
|---------|----------|--------|
| `RequestBodyLimitLayer::new(1024 * 1024)` — 1MB body limit | OK | — |
| `TimeoutLayer::new(30s)` — 30s request timeout | OK | — |
| No per-IP rate limiting | HIGH | Amplification/DoS |
| No global request rate limiting | MEDIUM | DoS |
| `sendRawTransaction` holds `mempool.write()` for entire validation | MEDIUM | Lock contention, single-transaction bottleneck |
| `getHeaders` holds `chain_state.read()` for up to 1001 iterations | LOW | Read lock held for potentially long time |

**Attack scenarios:**

1. **Amplification DoS (HIGH):** An attacker can flood `sendRawTransaction` with valid-looking transactions. Each request acquires a write lock on the mempool, serializing all submissions. Combined with no rate limiting, this can stall the node.

2. **Memory exhaustion (MEDIUM):** No global request count limit. An attacker can open many concurrent connections, each holding a body buffer up to 1MB.

**Recommendations:**
1. Add `tower::limit::ConcurrencyLimitLayer` (e.g., 100 concurrent requests).
2. Add per-IP rate limiting via `tower::limit::RateLimitLayer` or custom middleware.
3. Consider adding a `RateLimit` to `sendRawTransaction` specifically (e.g., 10/sec per IP).

---

## I. RPC: JSON-RPC Correctness & Error Handling

**Location:** `crates/chroma-rpc/src/error.rs`, `crates/chroma-rpc/src/handler.rs`

| Finding | Severity | Status |
|---------|----------|--------|
| JSON-RPC 2.0 error codes (-32700, -32600, -32601, -32602, -32603) correctly used | OK | — |
| No batch request support | INFO | Per spec, batch is optional |
| `jsonrpc` field not validated (accepts any string) | LOW | Should verify "2.0" |
| `handle_get_block_by_height` casts `u64` to `u32` without range check | LOW | Params from JSON can exceed u32::MAX |
| `handle_get_block_by_hash` linear scan O(n) over all headers | LOW | Performance issue, not security |
| Internal error messages exposed to client (e.g., "password incorrect") | MEDIUM | Information leakage |
| No request ID validation (accepts any JSON value) | INFO | Per spec, ID can be any value |

**Attack scenarios:**

1. **Information leakage (MEDIUM):** `sendRawTransaction` returns `e.to_string()` from mempool validation, which includes "transaction signature verification failed" or "mempool full". This reveals internal state.

2. **u32 overflow (LOW):** `params.get("height").as_u64() as u32` silently truncates values > u32::MAX.

**Recommendations:**
1. Sanitize error messages before returning to client.
2. Add range check: `if height > u32::MAX as u64 { return Err(...) }`.

---

## J. Transaction Validation (Mempool Integration)

**Location:** `crates/chroma-p2p/src/mempool.rs:41-67`, `crates/chroma-rpc/src/handler.rs:209-233`

| Finding | Severity | Status |
|---------|----------|--------|
| Mempool validates: signature, amount > 0, sender ≠ recipient | OK | — |
| Mempool does NOT validate balance or nonce against chain state | INFO | By design; validation at block inclusion time |
| `sendRawTransaction` deserializes then re-serializes to compute hash | LOW | Wasteful; could compute hash from raw bytes |
| No duplicate detection by (sender, nonce) across mempool AND chain | LOW | Could accept tx that's already confirmed |

**Attack scenario (LOW):** An attacker can submit an already-confirmed transaction via `sendRawTransaction`. It will be accepted into the mempool and only fail at block inclusion. This wastes mempool space.

**Recommendation:** Optionally check (sender, nonce) against chain state before accepting into mempool.

---

## K. Wallet ↔ Transaction Integration Readiness

| Finding | Severity | Status |
|---------|----------|--------|
| `Wallet::create_transaction` correctly delegates to `chroma_tx::create_transaction` | OK | — |
| `create_transaction` validates amount > 0, sender ≠ recipient | OK | — |
| `create_transaction` verifies derived address matches sender | OK | — |
| No nonce management (caller must provide correct nonce) | INFO | Phase 3 responsibility |
| `Wallet::secret_bytes()` returns raw `[u8; 32]` — not zeroized after use | MEDIUM | Caller must zeroize |

**Phase 3 prerequisites:**
1. Nonce acquisition from chain state (requires RPC call or local storage access).
2. Balance check before sending (requires RPC call or local storage access).
3. `secret_bytes()` return value must be zeroized after use.

---

## L. Cross-Network Security

| Finding | Severity | Status |
|---------|----------|--------|
| Mainnet, testnet, regtest have distinct network magic bytes | OK | — |
| Genesis hash pinned per network | OK | — |
| RPC server does not enforce network context | INFO | Acceptable; same node handles one network |

---

## M. Regression Test Coverage

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
| **RPC API key auth** | ❌ MISSING | **Must add** |
| **RPC unauthorized rejection** | ❌ MISSING | **Must add** |
| **RPC malformed request** | ❌ MISSING | **Must add** |
| **RPC body size limit** | ❌ MISSING | **Must add** |
| **Keystore file permissions** | ❌ MISSING | **Must add** |
| **Constant-time MAC comparison** | ❌ MISSING | **Must add** |

---

## Summary: Findings by Severity

| Severity | Count | Items |
|----------|-------|-------|
| **HIGH** | 4 | API key timing attack, open access when no key, CLI `--key` in cmdline, keystore file permissions |
| **MEDIUM** | 6 | MAC not constant-time, no atomic keystore write, CORS permissive, no rate limiting, sendRawTransaction lock contention, error message leakage |
| **LOW** | 5 | Argon2 panic, jsonrpc field unvalidated, u32 truncation, linear hash scan, hash recomputation |
| **INFO** | 7 | Various design decisions, acceptable for testnet |

---

## Recommended Fix Priority

### CRITICAL (must fix before testnet)
1. **API key timing attack** — Use `subtle::ConstantTimeEq` in `auth.rs`
2. **Open access when no API key** — Log warning; consider requiring key for non-localhost binds
3. **CLI `--key` in process cmdline** — Remove `--key` arg, use stdin/file instead
4. **Keystore file permissions** — Set 0600 on Linux/macOS

### HIGH (should fix before testnet)
5. **MAC comparison constant-time** — Use `subtle::ConstantTimeEq`
6. **Atomic keystore write** — Write to temp file, then rename
7. **CORS restriction** — Remove or restrict to localhost
8. **Rate limiting** — Add concurrency limit + per-IP rate limit

### MEDIUM (can defer to mainnet)
9. **Memory zeroization** — Zeroize returned key bytes in `decrypt_key`
10. **Error message sanitization** — Don't expose internal validation errors
11. **Duplicate tx detection** — Check (sender, nonce) against chain state

### LOW (nice to have)
12. Validate `jsonrpc` field equals "2.0"
13. Range check height parameter
14. Optimize hash computation in `sendRawTransaction`

---

## Phase 3 Blockers

Before implementing the wallet send flow (Phase 3), the following must be resolved:

1. **Constant-time API key comparison** (HIGH)
2. **Keystore file permissions** (HIGH)  
3. **CLI `--key` security** (HIGH)
4. **Add missing regression tests** for RPC auth (MEDIUM)

Phase 3 implementation may proceed after these items are fixed and verified.
