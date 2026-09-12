//! Error Types

use thiserror::Error;

/// Core protocol errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid data format
    #[error("invalid format: {0}")]
    InvalidFormat(String),

    /// Integer overflow/underflow
    #[error("arithmetic overflow: {0}")]
    Overflow(String),

    /// Supply invariant violation
    #[error("supply invariant violation: {0}")]
    SupplyInvariant(String),

    /// Invalid block structure
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Invalid transaction
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Invalid signature
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid nonce
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Insufficient balance
    #[error("insufficient balance: {0}")]
    InsufficientBalance(String),

    /// Invalid state root
    #[error("invalid state root: {0}")]
    InvalidStateRoot(String),

    /// Invalid Merkle root
    #[error("invalid merkle root: {0}")]
    InvalidMerkleRoot(String),

    /// Invalid PoW
    #[error("invalid proof of work: {0}")]
    InvalidProofOfWork(String),

    /// Invalid timestamp
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),

    /// Invalid difficulty/target
    #[error("invalid difficulty: {0}")]
    InvalidDifficulty(String),

    /// Block size exceeded
    #[error("block size exceeded: {0} bytes > max {1}")]
    BlockSizeExceeded(usize, usize),

    /// Transaction size exceeded
    #[error("transaction size exceeded: {0} bytes > max {1}")]
    TransactionSizeExceeded(usize, usize),

    /// Mempool full
    #[error("mempool full: size {0} > max {1}")]
    MempoolFull(usize, usize),

    /// Peer banned
    #[error("peer banned: {0}")]
    PeerBanned(String),

    /// Invalid network ID
    #[error("invalid network ID: {0}")]
    InvalidNetworkId(String),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Genesis error
    #[error("genesis error: {0}")]
    Genesis(String),

    /// IO error
    #[error("io error: {0}")]
    Io(String),
}

/// Result type for core operations
pub type Result<T> = std::result::Result<T, CoreError>;
