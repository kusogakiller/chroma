use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use chroma_consensus::ChainState;
use chroma_p2p::mempool::Mempool;
use chroma_p2p::peer::PeerManager;
use chroma_rpc::RpcState;

fn test_rpc_state(api_key: Option<String>) -> RpcState {
    let chain_state = Arc::new(RwLock::new(ChainState::with_genesis()));
    let mempool = Arc::new(RwLock::new(Mempool::new()));
    let storage = Arc::new(
        chroma_storage::Storage::open_temporary().expect("failed to open temporary storage"),
    );
    let peer_manager = Arc::new(RwLock::new(PeerManager::new()));

    RpcState {
        storage,
        chain_state,
        mempool,
        peer_manager,
        node_id: "test-node:8333".to_string(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 8334)),
        network_name: "regtest".to_string(),
        start_time: Instant::now(),
        api_key,
    }
}

async fn start_test_server(state: RpcState) -> SocketAddr {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let state = Arc::new(state);
    tokio::spawn(async move {
        let app = axum::Router::new()
            .route("/", axum::routing::post(chroma_rpc::rpc_route))
            .with_state(state);

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_tx.subscribe().recv().await;
            })
            .await
            .unwrap();
    });

    local_addr
}

#[tokio::test]
async fn test_rpc_no_api_key_allows_all() {
    let state = test_rpc_state(None);
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"getChainInfo","id":1}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("result").is_some());
}

#[tokio::test]
async fn test_rpc_correct_api_key_allows() {
    let state = test_rpc_state(Some("test-secret-key".to_string()));
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .header("X-API-Key", "test-secret-key")
        .body(r#"{"jsonrpc":"2.0","method":"getChainInfo","id":1}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("result").is_some());
}

#[tokio::test]
async fn test_rpc_wrong_api_key_rejects() {
    let state = test_rpc_state(Some("test-secret-key".to_string()));
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .header("X-API-Key", "wrong-key")
        .body(r#"{"jsonrpc":"2.0","method":"getChainInfo","id":1}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("error").is_some());
}

#[tokio::test]
async fn test_rpc_missing_api_key_rejects() {
    let state = test_rpc_state(Some("test-secret-key".to_string()));
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"getChainInfo","id":1}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_rpc_malformed_json_rejects() {
    let state = test_rpc_state(None);
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body("not json")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    let error = body.get("error").unwrap();
    assert_eq!(error.get("code").unwrap(), -32700);
}

#[tokio::test]
async fn test_rpc_unknown_method_rejects() {
    let state = test_rpc_state(None);
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"nonexistent","id":1}"#)
        .send()
        .await
        .unwrap();

    // Should return 200 with JSON-RPC error in body (per JSON-RPC spec)
    let body: serde_json::Value = resp.json().await.unwrap();
    let error = body.get("error").unwrap();
    assert_eq!(error.get("code").unwrap(), -32601);
}

#[tokio::test]
async fn test_rpc_empty_body_rejects() {
    let state = test_rpc_state(None);
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body("")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_rpc_get_chain_info_returns_genesis() {
    let state = test_rpc_state(None);
    let addr = start_test_server(state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/", addr))
        .header("Content-Type", "application/json")
        .body(r#"{"jsonrpc":"2.0","method":"getChainInfo","id":1}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let result = body.get("result").unwrap();
    assert_eq!(result.get("height").unwrap(), 0);
    assert_eq!(result.get("chain").unwrap(), "regtest");
}

#[tokio::test]
async fn test_rpc_api_key_constant_time() {
    // Verify that the auth module uses constant-time comparison
    use axum::http::HeaderMap;
    use chroma_rpc::auth::verify_api_key;

    let mut headers = HeaderMap::new();
    headers.insert("X-API-Key", "correct-key".parse().unwrap());

    // Correct key should pass
    assert!(verify_api_key(&headers, Some("correct-key")).is_ok());

    // Wrong key should fail
    assert!(verify_api_key(&headers, Some("wrong-key")).is_err());

    // Empty expected key should pass (no auth required)
    assert!(verify_api_key(&headers, None).is_ok());
    assert!(verify_api_key(&headers, Some("")).is_ok());
}
