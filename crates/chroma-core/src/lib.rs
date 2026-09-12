//! Chroma Protocol Core
//!
//! Contains fundamental protocol constants, type definitions, and the
//! canonical binary serialization framework.
//!
//! The wire format is explicitly specified here — it is NOT tied to
//! Rust memory layout (no `repr(C)`, no serde defaults). Every type
//! implements `CanonicalEncode` and `CanonicalDecode` for deterministic
//! serialization.

pub mod constants;
pub mod error;
pub mod hash;
pub mod serialize;
pub mod types;
pub mod u256;

pub use constants::*;
pub use error::*;
pub use hash::*;
pub use serialize::*;
pub use types::*;

#[cfg(test)]
mod tests;
