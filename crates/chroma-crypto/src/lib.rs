//! Chroma Cryptography
//!
//! Cryptographic primitives for Chroma:
//! - secp256k1 / BIP-340 Schnorr signatures
//! - BLAKE3, SHA-256, RIPEMD-160 hashing
//! - Bech32m address encoding (HRP: "chr")
//! - RandomX PoW (canonical reference implementation via the `randomx-rs`
//!   crate, BSD-3-Clause; built from vendored tevador/RandomX C++ sources)
//! - Noise protocol transport (for P2P encryption)

pub mod address;
pub mod error;
pub mod hash;
pub mod mine_pool;
pub mod noise;
pub mod randomx;
pub mod schnorr;

pub use address::*;
pub use error::*;
pub use hash::*;
pub use mine_pool::*;
pub use noise::*;
pub use randomx::*;
pub use schnorr::*;
