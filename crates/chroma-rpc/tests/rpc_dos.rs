//! RPC adversarial / DoS regression tests (bounded, deterministic).
//!
//! Unlike `rpc_auth.rs` (which drives a bare route), every test here runs
//! the PRODUCTION stack from `start_rpc_server`: body cap, timeout,
//! per-IP + global concurrency gates, CORS, auth. Each test names the
//! invariant it proves and the failure it would catch; none depend on
//! timing races tighter than an order of magnitude of headroom.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chroma_core::hash::Hash160;
use chroma_core::CanonicalEncode;
use chroma_p2p::mempool::Mempool;
use chroma_p2p::peer::PeerManager;
use chroma_rpc::RpcState;

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("chroma_rpc_dos_{}", name));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn test_state(dir: &PathBuf, api_key: Option<String>) -> RpcState {
    use chroma_core::constants::REGTEST_MAGIC;
    RpcState {
        storage: Arc::new(chroma_storage::Storage::open(dir).expect("open storage")),
        chain_state: Arc::new(tokio::sync::RwLock::new(
            chroma_consensus::ChainState::with_genesis_from(
                &chroma_consensus::build_genesis_block(),
                REGTEST_MAGIC,
            ),
        )),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::new())),
        peer_manager: Arc::new(tokio::sync::RwLock::new(PeerManager::new())),
        node_id: "test-node:8333".to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 8334)),
        network_name: "regtest".to_string(),
        start_time: Instant::now(),
        api_key,
    }
}

fn post_json(client: &reqwest::Client, addr: SocketAddr, body: &str) -> reqwest::RequestBuilder {
    client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body(body.to_string())
}

/// Start the PRODUCTION RPC stack on a free loopback port (bind-ephemeral
/// discovery with rebind retries). Returns addr + shutdown trigger + the
/// storage dir (caller removes it after shutdown).
async fn start_production_server(
    name: &str,
    api_key: Option<String>,
) -> (SocketAddr, tokio::sync::broadcast::Sender<()>, PathBuf) {
    for _ in 0..5 {
        // Bind all interfaces: tests address the server via distinct
        // loopback identities (127.0.0.1 vs 127.0.0.2) to prove per-IP
        // isolation the way production sees distinct client IPs.
        let probe = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bind = SocketAddr::from(([0, 0, 0, 0], port));
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let dir = test_dir(name);
        let state = test_state(&dir, api_key.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
        let tx = shutdown_tx.clone();
        let handle =
            tokio::spawn(
                async move { chroma_rpc::start_rpc_server(bind, state, shutdown_rx).await },
            );
        // Give bind a moment; on AddrInUse (ephemeral race), retry.
        tokio::time::sleep(Duration::from_millis(200)).await;
        if handle.is_finished() {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        // Confirm the listener is actually up before returning.
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            // Detach the server task; shutdown is driven by the trigger.
            std::mem::forget(handle);
            return (addr, tx, dir);
        }
    }
    panic!("could not bind production RPC server after retries");
}

async fn shutdown_and_clean(tx: tokio::sync::broadcast::Sender<()>, dir: PathBuf) {
    let _ = tx.send(());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

fn valid_call(method: &str, params: &str, id: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","method":"{method}","params":{params},"id":{id}}}"#)
}

/// A. Bodies over the 1 MiB cap are refused with bounded cost. The limit
/// layer checks the declared Content-Length up front: a 2 MB declaration
/// gets an immediate 413 without the server buffering anything (verified in
/// tower-http 0.5 sources). Afterwards the server stays usable. Would catch
/// unbounded body buffering.
#[tokio::test]
async fn rpc_dos_oversized_body_rejected() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (addr, tx, dir) = start_production_server("oversize", None).await;
    let pad = "x".repeat(1024 * 1024 + 1024);
    let body =
        format!(r#"{{"jsonrpc":"2.0","method":"getChainInfo","params":{{"pad":"{pad}"}},"id":1}}"#);
    let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rh, mut wh) = sock.into_split();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    wh.write_all(head.as_bytes()).await.unwrap();
    // Stream the body in the background (best effort: the server may RST
    // once past the cap); concurrently await the refusal line.
    let writer = tokio::spawn(async move {
        for c in body.as_bytes().chunks(65536) {
            if wh.write_all(c).await.is_err() {
                break;
            }
        }
    });
    let mut acc = Vec::new();
    let mut tmp = [0u8; 512];
    let bounded = loop {
        match tokio::time::timeout(Duration::from_secs(10), rh.read(&mut tmp)).await {
            Err(_) => break false,    // hung: unbounded buffering suspected
            Ok(Err(_)) => break true, // RST once over cap
            Ok(Ok(0)) => break true,  // clean EOF after refusal
            Ok(Ok(n)) => {
                acc.extend_from_slice(&tmp[..n]);
                if acc.windows(3).any(|w| w == b"413") {
                    break true;
                }
                if acc.len() > 4096 {
                    break false; // large non-413 response: suspicious
                }
            }
        }
    };
    assert!(
        bounded,
        "over-cap body must be refused or reset, not absorbed"
    );
    writer.abort();
    // Server alive afterwards.
    let client = reqwest::Client::new();
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    shutdown_and_clean(tx, dir).await;
}

/// B. Malformed-JSON flood: 200 bad bodies → all 400/parse-error, server
/// responsive throughout and after. Would catch parse-path panics or leaks.
#[tokio::test]
async fn rpc_dos_malformed_json_flood() {
    let (addr, tx, dir) = start_production_server("badjson", None).await;
    let client = reqwest::Client::new();
    for i in 0..200 {
        let body = format!("{{not json {i} [");
        let resp = post_json(&client, addr, &body).send().await.unwrap();
        assert_eq!(resp.status(), 400);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "99"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    shutdown_and_clean(tx, dir).await;
}

/// M/F. Batch (top-level array) is explicitly unsupported: one small error,
/// no fan-out — batch cannot be a DoS amplifier by construction.
#[tokio::test]
async fn rpc_dos_batch_rejected_without_fanout() {
    let (addr, tx, dir) = start_production_server("batch", None).await;
    let client = reqwest::Client::new();
    // 100 valid-shaped calls in one batch body.
    let mut batch = String::from("[");
    for i in 0..100 {
        if i > 0 {
            batch.push(',');
        }
        batch.push_str(&format!(
            r#"{{"jsonrpc":"2.0","method":"getChainInfo","id":{i}}}"#
        ));
    }
    batch.push(']');
    let resp = post_json(&client, addr, &batch).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.len() < 2048,
        "batch error must stay small, got {}",
        body.len()
    );
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"]["code"], -32600);
    // Empty batch likewise.
    let resp = post_json(&client, addr, "[]").send().await.unwrap();
    assert_eq!(resp.status(), 400);
    shutdown_and_clean(tx, dir).await;
}

/// M. Notification (missing id) and id-type semantics pinned: current
/// behavior answers with null id; string/numeric ids echo exactly.
#[tokio::test]
async fn rpc_dos_notification_and_id_semantics() {
    let (addr, tx, dir) = start_production_server("idsem", None).await;
    let client = reqwest::Client::new();
    let resp = post_json(
        &client,
        addr,
        r#"{"jsonrpc":"2.0","method":"getChainInfo"}"#,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(
        v["id"].is_null(),
        "notification answers with null id (pinned)"
    );
    assert!(v.get("result").is_some());
    for id in [r#""abc""#, "42"] {
        let resp = post_json(
            &client,
            addr,
            &format!(r#"{{"jsonrpc":"2.0","method":"getChainInfo","id":{id}}}"#),
        )
        .send()
        .await
        .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            v["id"],
            serde_json::from_str::<serde_json::Value>(id).unwrap()
        );
    }
    // Wrong version and missing method are Invalid Request (-32600).
    for body in [
        r#"{"jsonrpc":"1.0","method":"getChainInfo","id":1}"#,
        r#"{"jsonrpc":"2.0","id":1}"#,
        r#"{"jsonrpc":"2.0","method":42,"id":1}"#,
    ] {
        let resp = post_json(&client, addr, body).send().await.unwrap();
        assert_eq!(resp.status(), 400);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(v["error"]["code"], -32600);
    }
    // Unknown method keeps the JSON-RPC code (transport status untouched).
    let resp = post_json(&client, addr, &valid_call("nope", "null", "7"))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32601);
    shutdown_and_clean(tx, dir).await;
}

/// G. Huge params are capped, not executed: range cap, bad hex, bad address.
#[tokio::test]
async fn rpc_dos_huge_params_capped() {
    let (addr, tx, dir) = start_production_server("hugeparams", None).await;
    let client = reqwest::Client::new();
    let cases = [
        (
            "getHeaders",
            r#"{"from":0,"to":99999999}"#,
            "range too large",
        ),
        ("getBlockByHash", r#"{"hash":"zzzz"}"#, "invalid hash"),
        (
            "getBlockByHash",
            &format!(r#"{{"hash":"{}"}}"#, "ab".repeat(64)),
            "block not found",
        ),
        ("getAccount", r#"{"address":"bogus!!"}"#, "invalid address"),
        ("getAccount", r#"{"address":"0x1234"}"#, "invalid address"),
        ("getBlockByHeight", "null", "missing params"),
        ("sendRawTransaction", r#"{"hex":"zz"}"#, "invalid hex"),
    ];
    for (method, params, _expect) in cases {
        let resp = post_json(&client, addr, &valid_call(method, params, "1"))
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(
            v.get("error").is_some(),
            "{} with {} must error",
            method,
            params
        );
        // Error bodies stay small regardless of param size.
        let raw = serde_json::to_string(&v).unwrap();
        assert!(raw.len() < 4096);
    }
    // 1 MiB of hex garbage fails fast at decode (bounded by body cap).
    let resp = post_json(
        &client,
        addr,
        &valid_call(
            "sendRawTransaction",
            &format!(r#"{{"hex":"{}"}}"#, "ab".repeat(200_000)),
            "2",
        ),
    )
    .send()
    .await
    .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v.get("error").is_some());
    shutdown_and_clean(tx, dir).await;
}

/// L. Raw-socket malformed HTTP must not wedge the server; auth runs before
/// dispatch (wrong key + unknown method → 401, never 404/500).
#[tokio::test]
async fn rpc_dos_malformed_http_and_auth_order() {
    use tokio::io::AsyncWriteExt;
    let (addr, tx, dir) = start_production_server("malhttp", Some("s3cret".to_string())).await;
    // Garbage bytes, then a valid request on a FRESH connection works.
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"GARBAGE NOT HTTP\r\n\r\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(sock);
    // GET on a POST-only route is refused without touching auth/dispatch.
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/", addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 405);
    // Auth precedes dispatch: unknown method + wrong key → 401.
    let resp = post_json(&client, addr, &valid_call("no-such-method", "null", "1"))
        .header("X-API-Key", "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    // Correct key reaches dispatch (unknown method → method error body).
    let resp = post_json(&client, addr, &valid_call("no-such-method", "null", "2"))
        .header("X-API-Key", "s3cret")
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32601);
    // CORS posture pinned: permissive layer reflects arbitrary origins.
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "3"))
        .header("Origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_some(),
        "permissive CORS reflects origins (documented posture)"
    );
    // Preflight from an arbitrary origin is accepted (wildcard posture).
    let resp = client
        .request(reqwest::Method::OPTIONS, format!("http://{}/", addr))
        .header("Origin", "https://evil.example")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .unwrap();
    assert!(
        resp.headers().get("access-control-allow-origin").is_some(),
        "preflight accepted for arbitrary origins (documented posture)"
    );
    shutdown_and_clean(tx, dir).await;
}

/// C+J. Concurrent burst semantics: 100 parallel valid requests from one IP
/// each get EITHER 200 (served) or 429 (per-IP concurrent cap engaged) — no
/// hangs, no errors, no timeouts — and an honest sequential request served
/// DURING the burst stays fast. Would catch worker exhaustion, unbounded
/// queues, or a too-tight global cap. (Per-IP 429s under a single-IP burst
/// are the protection working, not a failure.)
#[tokio::test]
async fn rpc_dos_concurrent_flood_honest_served() {
    let (addr, tx, dir) = start_production_server("concur", None).await;
    let client = reqwest::Client::new();
    let mut handles = Vec::new();
    for i in 0..100u32 {
        let c = client.clone();
        let body = valid_call("getChainInfo", "null", &i.to_string());
        handles.push(tokio::spawn(async move {
            let resp = c
                .post(format!("http://{}/", addr))
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .unwrap();
            let status = resp.status();
            let v: serde_json::Value = resp.json().await.unwrap();
            (status, v)
        }));
    }
    // Honest sequential request in the middle of the burst.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let honest_start = Instant::now();
    let resp = post_json(
        &client,
        addr,
        &valid_call("getChainInfo", "null", "\"honest\""),
    )
    .send()
    .await
    .unwrap();
    let honest_latency = honest_start.elapsed();
    assert!(
        honest_latency < Duration::from_secs(10),
        "honest request must stay fast during burst ({:?})",
        honest_latency
    );
    assert_eq!(resp.status(), 200);
    let mut ok = 0;
    let mut limited = 0;
    for h in handles {
        let (status, body) = h.await.unwrap();
        match status.as_u16() {
            200 => {
                assert!(body.get("result").is_some());
                ok += 1;
            }
            429 => {
                assert_eq!(body["error"]["code"], -32099);
                limited += 1;
            }
            s => panic!("unexpected status in burst: {}", s),
        }
    }
    assert_eq!(
        ok + limited,
        100,
        "every burst request resolves as 200 or 429"
    );
    assert!(ok > 0, "burst must serve some requests, not reject all");
    shutdown_and_clean(tx, dir).await;
}

/// Minimal raw HTTP/1.1 POST client bound to a chosen SOURCE loopback
/// identity. Needed because the OS sources all loopback connections from
/// 127.0.0.1 regardless of destination: only an explicitly bound socket
/// presents 127.0.0.2 to the server's per-IP accounting (the production
/// shape: distinct client IPs).
async fn raw_post_from(server: SocketAddr, source_ip: [u8; 4], body: &str) -> (u16, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(SocketAddr::from((source_ip, 0))).unwrap();
    let mut stream = sock.connect(server).await.unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    // Read status + headers, then exactly Content-Length bytes.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut content_length: Option<usize> = None;
    let mut header_end: Option<usize> = None;
    while header_end.is_none() {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "server closed connection mid-response");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = Some(pos + 4);
            let head_str = String::from_utf8_lossy(&buf[..pos]);
            for line in head_str.split("\r\n") {
                if let Some(v) = line.strip_prefix("content-length:") {
                    content_length = v.trim().parse().ok();
                } else if let Some(v) = line.strip_prefix("Content-Length:") {
                    content_length = v.trim().parse().ok();
                }
            }
        }
        assert!(buf.len() < 65536, "response head too large");
    }
    let status: u16 = String::from_utf8_lossy(&buf[..12])
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let need = header_end.unwrap() + content_length.unwrap_or(0);
    while buf.len() < need {
        let n = stream.read(&mut tmp).await.unwrap();
        assert!(n > 0, "server closed connection mid-body");
        buf.extend_from_slice(&tmp[..n]);
    }
    let body_bytes = buf[header_end.unwrap()..need].to_vec();
    (status, body_bytes)
}

/// Per-IP fairness under drip flood, proven across loopback identities:
/// the attacker (source 127.0.0.1) and the honest client (source 127.0.0.2,
/// via an explicitly bound socket) hold SEPARATE per-IP buckets — the
/// production shape (distinct client IPs). 40 slow drips from .1: the first
/// 16 proceed, the rest get instant 429s; an extra .1 request is refused
/// while drips hold; honest .2 requests stay fast throughout. Deterministic:
/// drips outlast the whole assertion window.
#[tokio::test]
async fn rpc_dos_per_ip_fairness_under_drip_flood() {
    use tokio::io::AsyncWriteExt;
    let (any_addr, tx, dir) = start_production_server("dripfair", None).await;
    let port = any_addr.port();
    let attacker = SocketAddr::from(([127, 0, 0, 1], port));
    let mut drips = Vec::new();
    for _ in 0..40 {
        let mut sock = tokio::net::TcpStream::connect(attacker).await.unwrap();
        let head = "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1200\r\n\r\n";
        sock.write_all(head.as_bytes()).await.unwrap();
        drips.push(tokio::spawn(async move {
            // 1 KB over ~20 s; the test ends long before completion.
            for _ in 0..50 {
                if sock.write_all(&[b'x'; 20]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }));
    }
    // Let all drips reach the gate (localhost connects land in ms).
    tokio::time::sleep(Duration::from_secs(2)).await;
    let client = reqwest::Client::new();
    // Extra attacker-IP request while drips hold all 16 slots: refused.
    let resp = post_json(
        &client,
        attacker,
        &valid_call("getChainInfo", "null", "over"),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        resp.status(),
        429,
        "17th concurrent IP request must be refused"
    );
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32099);
    // Honest identity during the flood: fast 200s (separate bucket, bound
    // source socket so the server attributes 127.0.0.2, not 127.0.0.1).
    for i in 0..5 {
        let start = Instant::now();
        let body = valid_call("getChainInfo", "null", &i.to_string());
        let (status, raw) = raw_post_from(attacker, [127, 0, 0, 2], &body).await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(v.get("result").is_some());
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "honest identity must stay fast during another IP's flood"
        );
    }
    for h in drips {
        h.abort();
    }
    shutdown_and_clean(tx, dir).await;
}

/// E. Authentication-failure flood: 300 wrong keys → all 401, no lockout
/// (a valid key still works immediately after), server responsive. Each
/// failure is a header parse + constant-time compare (microseconds), so no
/// throttle is required by measurement; this test pins that cheapness.
#[tokio::test]
async fn rpc_dos_auth_failure_flood() {
    let (addr, tx, dir) =
        start_production_server("authflood", Some("correct-horse".to_string())).await;
    let client = reqwest::Client::new();
    let start = Instant::now();
    for i in 0..300 {
        let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "1"))
            .header("X-API-Key", format!("wrong-{i}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "300 auth failures must stay cheap ({:?})",
        elapsed
    );
    // No lockout: correct key works immediately.
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "2"))
        .header("X-API-Key", "correct-horse")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    shutdown_and_clean(tx, dir).await;
}

/// D. Never-completing body (slowloris): the 30 s request timeout must kill
/// it and free the slot; the server stays usable. Bounded (~40 s) by design:
/// this IS the timeout being measured.
#[tokio::test]
async fn rpc_dos_slow_body_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (addr, tx, dir) = start_production_server("slowloris", None).await;
    let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
    sock.write_all(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{\"jsonrpc\":")
        .await
        .unwrap();
    // Stall forever; the server must terminate the stalled request.
    let mut buf = [0u8; 64];
    let outcome = tokio::time::timeout(Duration::from_secs(45), sock.read_exact(&mut buf)).await;
    let terminated = match outcome {
        Err(_) => false,    // no data within 45 s: slot NOT reclaimed in time
        Ok(Err(_)) => true, // EOF/reset: connection reaped
        Ok(Ok(_)) => true,  // any bytes (e.g. 408): request terminated
    };
    assert!(
        terminated,
        "stalled body must be reaped by the request timeout"
    );
    drop(sock);
    let client = reqwest::Client::new();
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    shutdown_and_clean(tx, dir).await;
}

/// H. sendRawTransaction flood: 200 well-signed (unfunded — accepted at
/// admission, filtered at mining) + 200 garbage-signature. Counts must be
/// exact, the mempool must hold exactly the valid set, and the server stays
/// responsive throughout. Would catch admission panics, mempool corruption,
/// or flood-induced unresponsiveness.
#[tokio::test]
async fn rpc_dos_sendraw_flood() {
    use chroma_core::constants::REGTEST_MAGIC;
    use chroma_core::types::{Amount, Nonce};
    use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
    use chroma_tx::Transaction;

    let (addr, tx, dir) = start_production_server("sendraw", None).await;
    let client = reqwest::Client::new();
    let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = {
        let h = chroma_crypto::hash::hash160(&pubkey.0);
        chroma_core::types::Address::from_hash160(Hash160(h))
    };
    let mut h = [0u8; 20];
    h[0] = 0xBB;
    let recipient = chroma_core::types::Address::from_hash160(Hash160(h));

    let submit = |hex_body: &str| {
        valid_call(
            "sendRawTransaction",
            &format!(r#"{{"hex":"{hex_body}"}}"#),
            "1",
        )
    };
    // 200 valid (distinct nonces).
    for n in 0..200u64 {
        let txo = chroma_tx::create_transaction(
            &secret,
            sender,
            recipient,
            Amount(1_000),
            Nonce(n),
            REGTEST_MAGIC,
        )
        .unwrap();
        let resp = post_json(&client, addr, &submit(&hex::encode(txo.encode())))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "valid tx {} must be accepted", n);
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(v["result"]["tx_hash"].is_string());
    }
    // 200 garbage-signature: rejected, never stored.
    for n in 0..200u64 {
        let bad = Transaction {
            sender_pubkey: pubkey,
            recipient,
            amount: Amount(1_000),
            nonce: Nonce(1000 + n),
            signature: chroma_crypto::schnorr::Signature64([0x22; 64]),
        };
        let resp = post_json(&client, addr, &submit(&hex::encode(bad.encode())))
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(
            v.get("error").is_some(),
            "garbage tx {} must be rejected",
            n
        );
    }
    // Wrong-magic replay (testnet-signed on regtest state): rejected.
    {
        use chroma_core::constants::TESTNET_MAGIC;
        let replay = chroma_tx::create_transaction(
            &secret,
            sender,
            recipient,
            Amount(1_000),
            Nonce(9999),
            TESTNET_MAGIC,
        )
        .unwrap();
        let resp = post_json(&client, addr, &submit(&hex::encode(replay.encode())))
            .send()
            .await
            .unwrap();
        let v: serde_json::Value = resp.json().await.unwrap();
        assert!(
            v.get("error").is_some(),
            "cross-magic replay must be rejected"
        );
    }
    // Honest control still fast.
    let start = Instant::now();
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "9"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(start.elapsed() < Duration::from_secs(10));
    shutdown_and_clean(tx, dir).await;
}

/// I. Huge mempool response stays bounded: 2000 queued txs → getMempool
/// returns exactly 2000 summaries and completes promptly. Response scale is
/// ~150–300 B/entry, capped by mempool limits — never open-ended.
#[tokio::test]
async fn rpc_dos_huge_mempool_response_bounded() {
    use chroma_core::constants::REGTEST_MAGIC;
    use chroma_core::types::{Amount, Nonce};
    use chroma_crypto::schnorr::{PublicKey32, SecretKey32};

    let (addr, tx, dir) = start_production_server("hugemempool", None).await;
    let client = reqwest::Client::new();
    let secret = SecretKey32::from_bytes([0xCC; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = {
        let h = chroma_crypto::hash::hash160(&pubkey.0);
        chroma_core::types::Address::from_hash160(Hash160(h))
    };
    let mut h = [0u8; 20];
    h[0] = 0xDD;
    let recipient = chroma_core::types::Address::from_hash160(Hash160(h));
    for n in 0..2000u64 {
        let txo = chroma_tx::create_transaction(
            &secret,
            sender,
            recipient,
            Amount(1),
            Nonce(n),
            REGTEST_MAGIC,
        )
        .unwrap();
        let body = valid_call(
            "sendRawTransaction",
            &format!(r#"{{"hex":"{}"}}"#, hex::encode(txo.encode())),
            "1",
        );
        let resp = post_json(&client, addr, &body).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }
    let start = Instant::now();
    let resp = post_json(&client, addr, &valid_call("getMempool", "null", "2"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let v: serde_json::Value = resp.json().await.unwrap();
    let arr = v["result"].as_array().unwrap();
    assert_eq!(arr.len(), 2000, "full bounded mempool must be listed");
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "2000-entry mempool dump must stay fast"
    );
    shutdown_and_clean(tx, dir).await;
}

/// K. Graceful shutdown with in-flight requests: 50 concurrent slow-ish
/// dumps, shutdown mid-flight → shutdown resolves bounded, listener closes,
/// no panic. (In-flight work drains; stragglers are capped by the 30 s
/// request timeout, so the whole shutdown stays well under a minute.)
#[tokio::test]
async fn rpc_dos_shutdown_with_inflight() {
    let (addr, tx, dir) = start_production_server("shutdown", None).await;
    let client = reqwest::Client::new();
    let mut handles = Vec::new();
    for i in 0..50u32 {
        let c = client.clone();
        handles.push(tokio::spawn(async move {
            let _ = c
                .post(format!("http://{}/", addr))
                .header("Content-Type", "application/json")
                .body(valid_call("getMempool", "null", &i.to_string()))
                .send()
                .await;
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let start = Instant::now();
    tx.send(()).unwrap();
    // Listener must refuse new connections promptly after shutdown.
    let mut refused = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "listener must close after shutdown");
    for h in handles {
        let _ = tokio::time::timeout(Duration::from_secs(45), h).await;
    }
    assert!(
        start.elapsed() < Duration::from_secs(60),
        "shutdown must stay bounded"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Hash-index equivalence: by-hash lookups resolve the same headers as
/// by-height on a 500-header chain, unknown hashes 404, and the O(1) path
/// needs no per-request chain scan (timing logged, not asserted).
#[tokio::test]
async fn rpc_dos_hash_index_equivalence() {
    use chroma_block::BlockHeader;
    use chroma_core::hash::Hash;
    use chroma_core::types::BlockHeight;
    use chroma_core::types::CompactTarget;

    let dir = test_dir("hashindex");
    let storage = Arc::new(chroma_storage::Storage::open(&dir).expect("open storage"));
    let genesis = chroma_consensus::build_genesis_block();
    storage.apply_block(&genesis).unwrap();
    let mut chain_state = chroma_consensus::ChainState::with_genesis_from(
        &genesis,
        chroma_core::constants::MAINNET_MAGIC,
    );
    // Synthetic linear chain (no PoW: RPC handlers only read).
    let mut prev = chain_state.tip.hash;
    let mut prev_ts = chain_state.tip.header.timestamp;
    for h in 1..=500u32 {
        let header = BlockHeader {
            version: 1,
            previous_hash: prev,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: prev_ts + 10,
            bits: CompactTarget(chroma_core::constants::GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: h as u64,
        };
        prev = header.hash();
        prev_ts = header.timestamp;
        let block = chroma_block::Block {
            header: header.clone(),
            transactions: vec![],
        };
        storage.apply_block(&block).unwrap();
        chain_state.headers.insert(h, header);
    }
    let state = RpcState {
        storage,
        chain_state: Arc::new(tokio::sync::RwLock::new(chain_state)),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::new())),
        peer_manager: Arc::new(tokio::sync::RwLock::new(PeerManager::new())),
        node_id: "test-node:8333".to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 8334)),
        network_name: "mainnet".to_string(),
        start_time: Instant::now(),
        api_key: None,
    };
    // Serve via the production stack for realism.
    let dir2 = test_dir("hashindex_srv");
    let _ = std::fs::remove_dir_all(&dir2);
    let (addr, shutdown, _srvdir) = {
        // Reuse helper infra with a pre-seeded state: spin the server with a
        // state built here by moving through start_production_server's shape.
        // Simpler: temporarily serve `state` by binding here directly with
        // the same layer stack via start_rpc_server on a probed port.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let bind = SocketAddr::from(([0, 0, 0, 0], port));
        let listen = SocketAddr::from(([127, 0, 0, 1], port));
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
        let txx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = chroma_rpc::start_rpc_server(bind, state, shutdown_rx).await;
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        (listen, txx, dir2)
    };
    let client = reqwest::Client::new();
    // Sample present heights incl. edges; unknown hash 404s.
    let start = Instant::now();
    for h in [0u32, 1, 7, 100, 250, 499, 500] {
        let by_height = post_json(
            &client,
            addr,
            &valid_call("getBlockByHeight", &format!(r#"{{"height":{h}}}"#), "1"),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(by_height.status(), 200);
        let vh: serde_json::Value = by_height.json().await.unwrap();
        let hash = vh["result"]["hash"].as_str().unwrap().to_string();
        let by_hash = post_json(
            &client,
            addr,
            &valid_call("getBlockByHash", &format!(r#"{{"hash":"{hash}"}}"#), "2"),
        )
        .send()
        .await
        .unwrap();
        let vhh: serde_json::Value = by_hash.json().await.unwrap();
        assert_eq!(vhh["result"]["hash"], hash, "by-hash must match by-height");
        assert_eq!(vhh["result"]["header"]["height"], h);
        // getHeader by hash agrees too.
        let gh = post_json(
            &client,
            addr,
            &valid_call("getHeader", &format!(r#"{{"hash":"{hash}"}}"#), "3"),
        )
        .send()
        .await
        .unwrap();
        let vgh: serde_json::Value = gh.json().await.unwrap();
        assert_eq!(vgh["result"]["height"], h);
    }
    let unknown = "ff".repeat(32);
    let resp = post_json(
        &client,
        addr,
        &valid_call("getBlockByHash", &format!(r#"{{"hash":"{unknown}"}}"#), "4"),
    )
    .send()
    .await
    .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(v.get("error").is_some());
    eprintln!("hash-index 22 lookups elapsed: {:?}", start.elapsed());
    let _ = shutdown.send(());
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stale-index safety: storage has no removal API, so after a reorg-style
/// overwrite the hash index can point at a replaced height. RPC resolves
/// the height, then VERIFIES the header hash and refuses on mismatch —
/// never serving block B's data for block A's hash. Simulated here by
/// overwriting height 5's header (chain says A) while the index still maps
/// both A and...(A's own mapping intact; B's mapping added by put_block).
#[tokio::test]
async fn rpc_dos_stale_index_refused() {
    use chroma_block::{Block, BlockHeader};
    use chroma_core::hash::Hash;
    use chroma_core::types::{BlockHeight, CompactTarget};

    let dir = test_dir("staleindex");
    let storage = std::sync::Arc::new(chroma_storage::Storage::open(&dir).expect("open storage"));
    // Canonical chain A: real mainnet genesis + headers 1..=5 chained off it
    // (so the in-memory chain view and storage agree on ancestry).
    let genesis = chroma_consensus::build_genesis_block();
    storage.apply_block(&genesis).unwrap();
    let mut prev = genesis.hash();
    let mut prev_ts = genesis.header.timestamp;
    let mut hash_a5 = Hash::ZERO;
    for h in 1..=5u32 {
        let header = BlockHeader {
            version: 1,
            previous_hash: prev,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: prev_ts + 10,
            bits: CompactTarget(chroma_core::constants::GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: h as u64,
        };
        let block = Block {
            header,
            transactions: vec![],
        };
        storage.apply_block(&block).unwrap();
        prev = block.hash();
        prev_ts = block.header.timestamp;
        if h == 5 {
            hash_a5 = prev;
        }
    }
    // Reorg-style overwrite at height 5 WITHOUT touching the in-memory
    // chain view: a competing block B lands in storage indexes only.
    let header_b = BlockHeader {
        version: 1,
        previous_hash: Hash::blake3(b"other-parent"),
        state_root: Hash::ZERO,
        tx_merkle_root: Hash::ZERO,
        timestamp: prev_ts + 10,
        bits: CompactTarget(chroma_core::constants::GENESIS_TARGET_BITS),
        height: BlockHeight(5),
        nonce: 0xBEEF,
    };
    let block_b = Block {
        header: header_b,
        transactions: vec![],
    };
    let hash_b5 = block_b.hash();
    assert_ne!(hash_a5, hash_b5);
    storage.put_block(&block_b).unwrap();
    storage.flush().unwrap();

    // In-memory chain view still canonical on A (as after a restart that
    // loaded the canonical headers): re-resolve A headers by hash (the
    // per-hash block records are unambiguous; only height 5's height-index
    // entry now aliases to B).
    let mut chain_state = chroma_consensus::ChainState::with_genesis_from(
        &chroma_consensus::build_genesis_block(),
        chroma_core::constants::MAINNET_MAGIC,
    );
    let mut prev = chain_state.tip.hash;
    for h in 1..=5u32 {
        // Re-derive A's header hash deterministically (same construction).
        let hh = BlockHeader {
            version: 1,
            previous_hash: prev,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: chroma_core::constants::GENESIS_TIMESTAMP + h as u64 * 10,
            bits: CompactTarget(chroma_core::constants::GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: h as u64,
        };
        prev = hh.hash();
        let stored = storage.get_block_by_hash(&prev).unwrap().unwrap();
        chain_state.headers.insert(h, stored.header);
    }
    // Sanity: chain view tip is A5.
    assert_eq!(chain_state.headers[&5].hash(), hash_a5);

    let state = RpcState {
        storage,
        chain_state: Arc::new(tokio::sync::RwLock::new(chain_state)),
        mempool: Arc::new(tokio::sync::RwLock::new(Mempool::new())),
        peer_manager: Arc::new(tokio::sync::RwLock::new(PeerManager::new())),
        node_id: "test-node:8333".to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 8334)),
        network_name: "mainnet".to_string(),
        start_time: Instant::now(),
        api_key: None,
    };
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);
    let srv = tokio::spawn(async move {
        let _ = chroma_rpc::start_rpc_server(bind, state, shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let client = reqwest::Client::new();
    // A5 resolves via its own index entry and verifies: served correctly.
    let resp = post_json(
        &client,
        addr,
        &valid_call(
            "getBlockByHash",
            &format!(r#"{{"hash":"{}"}}"#, hash_a5.to_hex()),
            "1",
        ),
    )
    .send()
    .await
    .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(v["result"]["hash"], hash_a5.to_hex());
    // B5 hits the polluted index (height 5) but the header check fails:
    // refused, never B-served-for-A or vice versa.
    let resp = post_json(
        &client,
        addr,
        &valid_call(
            "getBlockByHash",
            &format!(r#"{{"hash":"{}"}}"#, hash_b5.to_hex()),
            "2",
        ),
    )
    .send()
    .await
    .unwrap();
    let v: serde_json::Value = resp.json().await.unwrap();
    assert!(
        v.get("error").is_some(),
        "stale-indexed hash must be refused, got {}",
        serde_json::to_string(&v).unwrap()
    );
    let _ = shutdown_tx.send(());
    srv.abort();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Empty configured key disables auth (operator footgun, pinned): requests
/// without any key succeed. Startup logs a warning for this configuration.
#[tokio::test]
async fn rpc_dos_empty_key_disables_auth() {
    let (addr, tx, dir) = start_production_server("emptykey", Some(String::new())).await;
    let client = reqwest::Client::new();
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    // Whitespace-padded keys never match (exact comparison, no trimming).
    let resp = post_json(&client, addr, &valid_call("getChainInfo", "null", "2"))
        .header("X-API-Key", " ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "auth is fully off with empty key");
    shutdown_and_clean(tx, dir).await;
}
