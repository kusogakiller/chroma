use axum::http::StatusCode;
use chroma_core::hash::Hash;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::verify_api_key;
use crate::error::{JsonRpcRequest, JsonRpcResponse, RpcError};
use crate::types::*;
use crate::RpcState;

#[allow(clippy::result_large_err)]
pub async fn rpc_route_handler(
    state: Arc<RpcState>,
    req: JsonRpcRequest,
    headers: axum::http::HeaderMap,
) -> Result<JsonRpcResponse, (StatusCode, JsonRpcResponse)> {
    if verify_api_key(&headers, state.api_key.as_deref()).is_err() {
        return Err((
            StatusCode::UNAUTHORIZED,
            JsonRpcResponse::error(req.id.clone(), RpcError::internal_error("unauthorized")),
        ));
    }

    let response = match req.method.as_str() {
        "getChainInfo" => handle_get_chain_info(&state).await,
        "getBlockByHeight" => handle_get_block_by_height(&state, &req.params).await,
        "getBlockByHash" => handle_get_block_by_hash(&state, &req.params).await,
        "getHeader" => handle_get_header(&state, &req.params).await,
        "getHeaders" => handle_get_headers(&state, &req.params).await,
        "getAccount" => handle_get_account(&state, &req.params).await,
        "getMempool" => handle_get_mempool(&state).await,
        "sendRawTransaction" => handle_send_raw_transaction(&state, &req.params).await,
        "getPeerInfo" => handle_get_peer_info(&state).await,
        "getNodeInfo" => handle_get_node_info(&state).await,
        _ => Err(RpcError::method_not_found(&req.method)),
    };

    match response {
        Ok(result) => Ok(JsonRpcResponse::success(req.id, result)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            JsonRpcResponse::error(req.id, e),
        )),
    }
}

async fn handle_get_chain_info(state: &RpcState) -> Result<Value, RpcError> {
    let cs = state.chain_state.read().await;
    let tip = &cs.tip;
    Ok(json!(ChainInfo {
        height: tip.height.0,
        best_block_hash: tip.hash.to_hex(),
        difficulty: format!("0x{:08x}", tip.header.bits.0),
        supply: tip.supply,
        chain: state.network_name.clone(),
    }))
}

async fn handle_get_block_by_height(
    state: &RpcState,
    params: &Option<Value>,
) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;
    let height = params
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("missing height"))? as u32;

    let cs = state.chain_state.read().await;
    let header = cs
        .headers
        .get(&height)
        .ok_or_else(|| RpcError::invalid_params("block not found"))?;

    let block_hash = header.hash();
    Ok(json!({
        "hash": block_hash.to_hex(),
        "header": header_value(header, height),
        "tx_count": 1,
        "transactions": []
    }))
}

async fn handle_get_block_by_hash(
    state: &RpcState,
    params: &Option<Value>,
) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;
    let hash_str = params
        .get("hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing hash"))?;

    let hash = Hash::from_hex(hash_str).map_err(|_| RpcError::invalid_params("invalid hash"))?;

    // O(1) hash→height index lookup. The previous linear scan hashed every
    // header per request — O(chain) CPU while holding the chain read lock,
    // which both slowed with chain growth and starved block writers under
    // request floods. Storage mirrors every applied header, so the index
    // resolves the same block.
    let height = state
        .storage
        .get_height_for_hash(&hash)
        .map_err(|_| RpcError::invalid_params("block not found"))?
        .ok_or_else(|| RpcError::invalid_params("block not found"))?;

    let cs = state.chain_state.read().await;
    let header = cs
        .headers
        .get(&height)
        .ok_or_else(|| RpcError::invalid_params("block not found"))?;
    // Storage has no removal API, so a reorg can leave a stale index entry
    // pointing at a replaced height: verify the resolved header matches.
    if header.hash() != hash {
        return Err(RpcError::invalid_params("block not found"));
    }
    Ok(json!({
        "hash": hash.to_hex(),
        "header": header_value(header, height),
        "tx_count": 1,
        "transactions": []
    }))
}

async fn handle_get_header(state: &RpcState, params: &Option<Value>) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;

    let cs = state.chain_state.read().await;
    if let Some(height_val) = params.get("height").and_then(|v| v.as_u64()) {
        let height = height_val as u32;
        let header = cs
            .headers
            .get(&height)
            .ok_or_else(|| RpcError::invalid_params("header not found"))?;
        return Ok(header_value(header, height));
    }
    if let Some(hash_str) = params.get("hash").and_then(|v| v.as_str()) {
        let hash =
            Hash::from_hex(hash_str).map_err(|_| RpcError::invalid_params("invalid hash"))?;
        // O(1) index lookup (see getBlockByHash): no per-request chain scan.
        let height = state
            .storage
            .get_height_for_hash(&hash)
            .map_err(|_| RpcError::invalid_params("header not found"))?
            .ok_or_else(|| RpcError::invalid_params("header not found"))?;
        let header = cs
            .headers
            .get(&height)
            .ok_or_else(|| RpcError::invalid_params("header not found"))?;
        // Same stale-index guard as getBlockByHash (storage keeps replaced
        // fork headers with no removal API).
        if header.hash() != hash {
            return Err(RpcError::invalid_params("header not found"));
        }
        return Ok(header_value(header, height));
    }
    Err(RpcError::invalid_params("provide height or hash"))
}

async fn handle_get_headers(state: &RpcState, params: &Option<Value>) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;
    let from = params
        .get("from")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("missing from"))? as u32;
    let to = params
        .get("to")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| RpcError::invalid_params("missing to"))? as u32;

    if to.saturating_sub(from) > 1000 {
        return Err(RpcError::invalid_params("range too large (max 1000)"));
    }

    let cs = state.chain_state.read().await;
    let mut headers = Vec::new();
    for h in from..=to {
        if let Some(header) = cs.headers.get(&h) {
            headers.push(header_value(header, h));
        }
    }
    Ok(json!(headers))
}

async fn handle_get_account(state: &RpcState, params: &Option<Value>) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;
    let address_str = params
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing address"))?;

    let address =
        parse_address(address_str).ok_or_else(|| RpcError::invalid_params("invalid address"))?;

    let cs = state.chain_state.read().await;
    let account = cs.state.get_account(&address);

    Ok(json!(AccountInfo {
        address: address_str.to_string(),
        balance: account.balance,
        nonce: account.nonce,
    }))
}

async fn handle_get_mempool(state: &RpcState) -> Result<Value, RpcError> {
    let mp = state.mempool.read().await;
    let txs: Vec<Value> = mp
        .transactions()
        .iter()
        .map(|tx| {
            let tx_hash = Hash::blake3(&tx.encode());
            json!(TxSummary {
                tx_hash: tx_hash.to_hex(),
                sender: tx.sender_address().to_string(),
                recipient: tx.recipient.to_string(),
                amount: tx.amount.0,
                nonce: tx.nonce.0,
            })
        })
        .collect();
    Ok(json!(txs))
}

async fn handle_send_raw_transaction(
    state: &RpcState,
    params: &Option<Value>,
) -> Result<Value, RpcError> {
    let params = params
        .as_ref()
        .ok_or_else(|| RpcError::invalid_params("missing params"))?;
    let hex_str = params
        .get("hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcError::invalid_params("missing hex"))?;

    let bytes = hex::decode(hex_str).map_err(|_| RpcError::invalid_params("invalid hex"))?;

    let tx = chroma_tx::Transaction::decode(&bytes)
        .map_err(|e| RpcError::invalid_params(&format!("invalid transaction: {}", e)))?;

    let tx_hash = Hash::blake3(&tx.encode());

    let network_magic = state.chain_state.read().await.network_magic;
    let mut mp = state.mempool.write().await;
    mp.add_transaction(tx, network_magic)
        .map_err(|e| RpcError::internal_error(&e.to_string()))?;

    Ok(json!({ "tx_hash": tx_hash.to_hex() }))
}

async fn handle_get_peer_info(state: &RpcState) -> Result<Value, RpcError> {
    let pm = state.peer_manager.read().await;
    let peers: Vec<Value> = pm
        .connected_peers()
        .iter()
        .map(|p| {
            json!(PeerInfo {
                addr: p.addr.to_string(),
                score: p.score,
                connected_since: None,
            })
        })
        .collect();
    Ok(json!(peers))
}

async fn handle_get_node_info(state: &RpcState) -> Result<Value, RpcError> {
    let pm = state.peer_manager.read().await;
    let cs = state.chain_state.read().await;
    Ok(json!(NodeInfo {
        id: state.node_id.clone(),
        listen_addr: state.listen_addr.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime: state.start_time.elapsed().as_secs(),
        height: cs.tip.height.0,
        peer_count: pm.connected_count(),
    }))
}

fn header_value(header: &chroma_block::BlockHeader, height: u32) -> Value {
    json!({
        "version": header.version,
        "previous_hash": header.previous_hash.to_hex(),
        "tx_merkle_root": header.tx_merkle_root.to_hex(),
        "timestamp": header.timestamp,
        "bits": format!("0x{:08x}", header.bits.0),
        "nonce": header.nonce,
        "height": height,
    })
}

fn parse_address(s: &str) -> Option<chroma_core::types::Address> {
    if s.starts_with("chr1") {
        let addr_str = chroma_crypto::address::AddressString(s.to_string());
        let h = addr_str.to_hash160()?;
        Some(chroma_core::types::Address::from_hash160(h))
    } else {
        let hex_str = s.trim_start_matches("0x");
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes);
        Some(chroma_core::types::Address::from_hash160(
            chroma_core::hash::Hash160(h),
        ))
    }
}
