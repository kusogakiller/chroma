//! Protocol Constants
//!
//! All values here are FINALIZED per Chroma Protocol Specification v0.1.
//! Changing any of these requires a hard fork.

/// Project identity
pub const PROJECT_NAME: &str = "Chroma";
pub const TICKER: &str = "CHR";
pub const SLOGAN: &str = "We are truly free.";

/// Monetary parameters
/// 1 CHR = 1,000,000 units (integer-only arithmetic)
pub const UNITS_PER_CHR: u64 = 1_000_000;
pub const MAX_SUPPLY_CHR: u64 = 100_000_000;
pub const MAX_SUPPLY_UNITS: u128 = (MAX_SUPPLY_CHR as u128) * (UNITS_PER_CHR as u128); // 100,000,000,000,000
pub const INITIAL_SUPPLY_UNITS: u128 = 0;

/// Block reward (fixed 1 CHR per block)
pub const BLOCK_REWARD_UNITS: u64 = UNITS_PER_CHR; // 1,000,000 units

/// Block timing
pub const TARGET_BLOCK_TIME_SECS: u64 = 10;
pub const DIFFICULTY_ADJUSTMENT_WINDOW: u32 = 10; // blocks

/// Difficulty bounds
pub const MAX_DIFFICULTY_INCREASE_FACTOR: u64 = 4; // 4x max increase per window
pub const MAX_DIFFICULTY_DECREASE_FACTOR: u64 = 4; // 4x max decrease per window (1/4)

/// Block size limits
pub const MAX_BLOCK_SIZE: usize = 1_048_576; // 1 MiB per spec
pub const MAX_TRANSACTION_SIZE: usize = 65536; // 64 KiB per spec

/// Mempool limits
pub const MAX_MEMPOOL_SIZE: usize = 50_000_000; // 50 MB
pub const MAX_MEMPOOL_TXS: usize = 100_000;

/// Network
pub const DEFAULT_PORT: u16 = 8333;
pub const PROTOCOL_VERSION: u32 = 1;

/// Genesis
pub const GENESIS_TIMESTAMP: u64 = 1767225600; // 2026-01-01 00:00:00 UTC
pub const GENESIS_TARGET_BITS: u32 = 0x1d00ffff; // Difficulty 1

/// Timestamp validation
pub const MTP_WINDOW: usize = 7; // Median Time Past window
pub const MAX_FUTURE_TIMESTAMP_OFFSET: i64 = 20; // seconds in future allowed

/// RandomX
pub const RANDOMX_EPOCH_LENGTH: u32 = 1000; // blocks
pub const RANDOMX_SEED_LAG: u32 = 100; // blocks
pub const GENESIS_RANDOMX_SEED: &[u8] = b"Chroma Genesis Seed";

/// Reorg journal
pub const REORG_JOURNAL_DEPTH: u32 = 2000; // blocks (~5.5 hours)

/// State
pub const ADDRESS_HASH_LEN: usize = 20; // RIPEMD160(SHA256(pubkey))
pub const ACCOUNT_VALUE_LEN: usize = 16; // balance: u64 (8) + nonce: u64 (8)

/// Network identifiers
pub const DEVNET_NETWORK_ID: &str = "chroma-devnet";
pub const TESTNET_NETWORK_ID: &str = "chroma-testnet";
pub const MAINNET_NETWORK_ID: &str = "chroma-mainnet";

/// Address HRP (Human Readable Part)
pub const ADDRESS_HRP: &str = "chr";

/// Rate limits (per peer)
pub const PEER_MSG_RATE_LIMIT: usize = 100; // messages per second
pub const PEER_TX_RATE_LIMIT: usize = 10; // transactions per second

/// Connection limits
pub const DEFAULT_OUTBOUND_CONNECTIONS: usize = 8;
pub const DEFAULT_INBOUND_CONNECTIONS: usize = 16;

// ============================================================================
// Testnet-specific genesis
// ============================================================================

/// Testnet genesis timestamp (2026-09-01 00:00:00 UTC)
pub const TESTNET_GENESIS_TIMESTAMP: u64 = 1756684800;
/// Testnet RandomX seed
pub const TESTNET_GENESIS_RANDOMX_SEED: &[u8] = b"Chroma Testnet Genesis Seed";
/// Testnet default port
pub const TESTNET_PORT: u16 = 18333;
/// Testnet max supply (same as mainnet)
pub const TESTNET_MAX_SUPPLY_CHR: u64 = 100_000_000;
/// Testnet block reward (same as mainnet)
pub const TESTNET_BLOCK_REWARD_UNITS: u64 = UNITS_PER_CHR;

/// Network magic bytes (4 bytes, used for wire protocol and transaction domain separation)
/// Mainnet: "CHRO" = 0xC4 0x48 0x52 0x4F
/// Testnet: "CTES" = 0xC4 0x54 0x45 0x53  
/// Regtest: "CRTT" = 0xC4 0x52 0x54 0x54
pub const MAINNET_MAGIC: [u8; 4] = [0xC4, 0x48, 0x52, 0x4F];
pub const TESTNET_MAGIC: [u8; 4] = [0xC4, 0x54, 0x45, 0x53];
pub const REGTEST_MAGIC: [u8; 4] = [0xC4, 0x52, 0x54, 0x54];
