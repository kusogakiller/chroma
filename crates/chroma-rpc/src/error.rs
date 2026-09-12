use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    pub fn parse_error(msg: &str) -> Self {
        RpcError {
            code: -32700,
            message: msg.to_string(),
        }
    }

    pub fn invalid_request(msg: &str) -> Self {
        RpcError {
            code: -32600,
            message: msg.to_string(),
        }
    }

    pub fn method_not_found(method: &str) -> Self {
        RpcError {
            code: -32601,
            message: format!("method not found: {}", method),
        }
    }

    pub fn invalid_params(msg: &str) -> Self {
        RpcError {
            code: -32602,
            message: msg.to_string(),
        }
    }

    pub fn internal_error(msg: &str) -> Self {
        RpcError {
            code: -32603,
            message: msg.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcError>,
    pub id: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: Option<serde_json::Value>, error: RpcError) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}
