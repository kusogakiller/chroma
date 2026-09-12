pub mod auth;
pub mod error;
pub mod handler;
pub mod limits;
pub mod types;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use limits::{PerIpCapLayer, DEFAULT_MAX_CONCURRENT_GLOBAL, DEFAULT_MAX_CONCURRENT_PER_IP};

pub use error::{JsonRpcRequest, JsonRpcResponse, RpcError};

pub struct RpcState {
    pub storage: Arc<chroma_storage::Storage>,
    pub chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    pub mempool: Arc<RwLock<chroma_p2p::mempool::Mempool>>,
    pub peer_manager: Arc<RwLock<chroma_p2p::peer::PeerManager>>,
    pub node_id: String,
    pub listen_addr: SocketAddr,
    pub network_name: String,
    pub start_time: Instant,
    pub api_key: Option<String>,
}

pub async fn start_rpc_server(
    addr: SocketAddr,
    state: RpcState,
    shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> std::io::Result<()> {
    let api_key = state.api_key.clone();
    if api_key.as_deref().is_none_or(|k| k.is_empty()) {
        tracing::warn!(
            "RPC server starting WITHOUT API key authentication — bind localhost, \
             set --rpc-api-key / CHROMA_RPC_API_KEY, or front with a reverse proxy"
        );
    }

    // Layer order (outermost last): Timeout → BodyLimit → PerIpCap →
    // ConcurrencyLimit → Cors → Extension → route. Rejections (timeout,
    // oversize, per-IP over-limit) all fire BEFORE request bodies are
    // buffered and before taking a global slot; the timeout covers queue
    // wait as well.
    let app = Router::new()
        .route("/", post(rpc_route))
        .layer(axum::extract::Extension(api_key.clone()))
        .layer(CorsLayer::permissive())
        .layer(ConcurrencyLimitLayer::new(DEFAULT_MAX_CONCURRENT_GLOBAL))
        .layer(PerIpCapLayer::new(DEFAULT_MAX_CONCURRENT_PER_IP))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("RPC server listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(shutdown_rx))
    .await
}

async fn shutdown_signal(mut rx: tokio::sync::broadcast::Receiver<()>) {
    let _ = rx.recv().await;
}

pub async fn rpc_route(
    axum::extract::State(state): axum::extract::State<Arc<RpcState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Two-step parse so malformed JSON (-32700) and well-formed JSON with a
    // wrong shape (-32600) map to distinct codes. Batch (top-level array)
    // is deliberately unsupported: it would be a DoS amplification vector
    // (one request fanning out to N method executions), so it is rejected
    // here in O(shape) time instead of executed.
    let value: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let response = JsonRpcResponse::error(None, RpcError::parse_error(&e.to_string()));
            return (StatusCode::BAD_REQUEST, axum::Json(response));
        }
    };
    let req: JsonRpcRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(_) => {
            let response = JsonRpcResponse::error(
                None,
                RpcError::invalid_request(
                    "invalid Request object; batch requests are not supported",
                ),
            );
            return (StatusCode::BAD_REQUEST, axum::Json(response));
        }
    };
    if req.jsonrpc != "2.0" {
        let response = JsonRpcResponse::error(
            req.id.clone(),
            RpcError::invalid_request("unsupported jsonrpc version (want \"2.0\")"),
        );
        return (StatusCode::BAD_REQUEST, axum::Json(response));
    }

    let response = handler::rpc_route_handler(state.clone(), req, headers).await;
    match response {
        Ok(r) => (StatusCode::OK, axum::Json(r)),
        Err((code, r)) => (code, axum::Json(r)),
    }
}
