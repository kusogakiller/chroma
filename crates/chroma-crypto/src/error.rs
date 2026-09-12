//! Cryptographic Error Types

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid secret key
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Invalid public key
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid address
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// RandomX error
    #[error("randomx error: {0}")]
    RandomX(String),

    /// Noise protocol error
    #[error("noise error: {0}")]
    Noise(String),
}

/// Re-export Result type that other chroma-crypto modules use
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
