use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    pub height: u32,
    pub best_block_hash: String,
    pub difficulty: String,
    pub supply: u64,
    pub chain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_hash: String,
    pub tx_merkle_root: String,
    pub timestamp: u64,
    pub bits: String,
    pub nonce: u64,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxSummary {
    pub tx_hash: String,
    pub sender: String,
    pub recipient: String,
    pub amount: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    pub hash: String,
    pub header: BlockHeader,
    pub tx_count: u32,
    pub transactions: Vec<TxSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: String,
    pub balance: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub addr: String,
    pub score: i32,
    pub connected_since: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub listen_addr: String,
    pub version: String,
    pub uptime: u64,
    pub height: u32,
    pub peer_count: usize,
}
