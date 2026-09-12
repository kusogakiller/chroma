//! Chroma Storage
//!
//! sled-based persistence for blocks, chain state, and account data.
//!
//! ## Database Schema
//!
//! - `headers:{height:u32}` → serialized BlockHeader
//! - `blocks:{hash:32}` → serialized full Block
//! - `hash_to_height:{hash:32}` → height as u32 LE
//! - `height_to_hash:{height:u32}` → hash as 32 bytes
//! - `tip` → serialized ChainTip metadata
//! - `accounts:{address:20}` → account data (balance_le64 || nonce_le64)
//! - `supply` → total supply as u64 LE
//! - `meta:{key}` → arbitrary metadata

use std::path::Path;

use chroma_block::Block;
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::Address;
use chroma_state::{Account, State};

// ============================================================================
// Storage Keys
// ============================================================================

fn header_key(height: u32) -> Vec<u8> {
    let mut key = b"headers:".to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn block_key(hash: &Hash) -> Vec<u8> {
    let mut key = b"blocks:".to_vec();
    key.extend_from_slice(hash.as_bytes());
    key
}

fn hash_to_height_key(hash: &Hash) -> Vec<u8> {
    let mut key = b"hash_to_height:".to_vec();
    key.extend_from_slice(hash.as_bytes());
    key
}

fn height_to_hash_key(height: u32) -> Vec<u8> {
    let mut key = b"height_to_hash:".to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn account_key(address: &Address) -> Vec<u8> {
    let mut key = b"accounts:".to_vec();
    key.extend_from_slice(address.as_hash160().as_bytes());
    key
}

const TIP_KEY: &[u8] = b"tip";
const SUPPLY_KEY: &[u8] = b"supply";
const GENESIS_HASH_KEY: &[u8] = b"genesis_hash";
pub const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

/// Current database schema version.
/// Increment when making breaking changes to the database format.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

// ============================================================================
// Chain Tip Metadata
// ============================================================================

/// Persisted chain tip metadata.
#[derive(Clone, Debug)]
pub struct PersistedTip {
    pub height: u32,
    pub hash: Hash,
    pub cumulative_work: [u8; 32],
    pub supply: u64,
}

impl CanonicalEncode for PersistedTip {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 32 + 32 + 8);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.hash.as_bytes());
        buf.extend_from_slice(&self.cumulative_work);
        buf.extend_from_slice(&self.supply.to_le_bytes());
        buf
    }
}

impl CanonicalDecode for PersistedTip {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 76 {
            return Err(CoreError::Serialization(
                "persisted tip too short".to_string(),
            ));
        }
        let height = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[4..36]);
        let mut work = [0u8; 32];
        work.copy_from_slice(&data[36..68]);
        let supply = u64::from_le_bytes([
            data[68], data[69], data[70], data[71], data[72], data[73], data[74], data[75],
        ]);
        Ok(PersistedTip {
            height,
            hash: Hash::from_bytes(hash),
            cumulative_work: work,
            supply,
        })
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let tip = PersistedTip::decode(data)?;
        Ok((tip, 76))
    }
}

// ============================================================================
// Storage
// ============================================================================

/// Persistent blockchain storage backed by sled.
#[derive(Debug)]
pub struct Storage {
    db: sled::Db,
    #[allow(dead_code)]
    path: Option<std::path::PathBuf>,
}

impl Storage {
    /// Open or create a storage database at the given path.
    ///
    /// Performs schema version validation:
    /// - New databases get CURRENT_SCHEMA_VERSION written
    /// - Existing databases must have compatible schema version
    /// - Incompatible versions cause fail-closed (return error)
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
        let db = sled::Config::new()
            .path(&p)
            .open()
            .map_err(|e| CoreError::Storage(format!("failed to open database: {}", e)))?;

        let storage = Storage { db, path: Some(p) };

        storage.check_or_init_schema_version()?;

        Ok(storage)
    }

    /// Open a temporary database for testing.
    pub fn open_temporary() -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::current_dir().unwrap_or_default().join("test_dbs");
        let dir = base.join(format!("sled_{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| CoreError::Storage(format!("failed to create test dir: {}", e)))?;
        let db = sled::Config::new()
            .path(&dir)
            .open()
            .map_err(|e| CoreError::Storage(format!("failed to open temp database: {}", e)))?;
        Ok(Storage {
            db,
            path: Some(dir),
        })
    }

    /// Check or initialize the schema version.
    ///
    /// - If no schema version exists (new database), writes CURRENT_SCHEMA_VERSION.
    /// - If schema version exists and matches CURRENT_SCHEMA_VERSION, proceeds.
    /// - Older versions are refused (migration not yet implemented).
    /// - If schema version is newer or incompatible, returns error (fail-closed).
    fn check_or_init_schema_version(&self) -> Result<()> {
        match self
            .db
            .get(SCHEMA_VERSION_KEY)
            .map_err(|e| CoreError::Storage(format!("schema version read: {}", e)))?
        {
            Some(version_bytes) => {
                if version_bytes.len() != 4 {
                    return Err(CoreError::Storage(
                        "invalid schema version encoding".to_string(),
                    ));
                }
                let stored_version = u32::from_le_bytes([
                    version_bytes[0],
                    version_bytes[1],
                    version_bytes[2],
                    version_bytes[3],
                ]);
                if stored_version > CURRENT_SCHEMA_VERSION {
                    return Err(CoreError::Storage(format!(
                        "database schema version {} is newer than supported version {}; please upgrade your node",
                        stored_version, CURRENT_SCHEMA_VERSION
                    )));
                }
                if stored_version < CURRENT_SCHEMA_VERSION {
                    // TODO: Implement migration for version < CURRENT_SCHEMA_VERSION
                    // For now, fail-closed on older versions to prevent silent corruption
                    return Err(CoreError::Storage(format!(
                        "database schema version {} is older than current version {}; migration not yet implemented",
                        stored_version, CURRENT_SCHEMA_VERSION
                    )));
                }
                Ok(())
            }
            None => {
                let version_bytes = CURRENT_SCHEMA_VERSION.to_le_bytes();
                self.db
                    .insert(SCHEMA_VERSION_KEY, &version_bytes[..])
                    .map_err(|e| CoreError::Storage(format!("schema version write: {}", e)))?;
                self.db
                    .flush()
                    .map_err(|e| CoreError::Storage(format!("schema version flush: {}", e)))?;
                Ok(())
            }
        }
    }

    // ========================================================================
    // Block Headers
    // ========================================================================

    /// Store a block header at its height.
    pub fn put_header(&self, height: u32, header: &chroma_block::BlockHeader) -> Result<()> {
        let key = header_key(height);
        let encoded = header.encode();
        self.db
            .insert(&key, encoded)
            .map_err(|e| CoreError::Storage(format!("put_header: {}", e)))?;
        Ok(())
    }

    /// Retrieve a block header by height.
    pub fn get_header(&self, height: u32) -> Result<Option<chroma_block::BlockHeader>> {
        let key = header_key(height);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_header: {}", e)))?
        {
            Some(data) => {
                let header = chroma_block::BlockHeader::decode(&data)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Check if a header exists at the given height.
    pub fn has_header(&self, height: u32) -> Result<bool> {
        let key = header_key(height);
        self.db
            .contains_key(&key)
            .map_err(|e| CoreError::Storage(format!("has_header: {}", e)))
    }

    // ========================================================================
    // Full Blocks
    // ========================================================================

    /// Store a full block, keyed by its hash.
    /// Uses a sled Batch for atomic writes across all three keys.
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let key = block_key(&hash);
        let encoded = block.encode_block();

        let height_key = hash_to_height_key(&hash);
        let h2h_key = height_to_hash_key(block.header.height.0);

        let mut batch = sled::Batch::default();
        batch.insert(key.as_slice(), encoded);
        batch.insert(
            height_key.as_slice(),
            block.header.height.0.to_le_bytes().to_vec(),
        );
        batch.insert(h2h_key.as_slice(), hash.as_bytes().to_vec());

        self.db
            .apply_batch(batch)
            .map_err(|e| CoreError::Storage(format!("put_block: {}", e)))?;

        Ok(())
    }

    /// Retrieve a full block by its hash.
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        let key = block_key(hash);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_block: {}", e)))?
        {
            Some(data) => {
                let block = Block::decode_block(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Retrieve the height for a block hash.
    pub fn get_height_for_hash(&self, hash: &Hash) -> Result<Option<u32>> {
        let key = hash_to_height_key(hash);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_height_for_hash: {}", e)))?
        {
            Some(data) => {
                if data.len() < 4 {
                    return Err(CoreError::Storage("invalid height data".to_string()));
                }
                let height = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Get a block by height using O(1) height→hash lookup.
    pub fn get_block_by_height(&self, height: u32) -> Result<Option<Block>> {
        let key = height_to_hash_key(height);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_block_by_height: {}", e)))?
        {
            Some(data) => {
                if data.len() < 32 {
                    return Err(CoreError::Storage(
                        "invalid height_to_hash data".to_string(),
                    ));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data[..32]);
                let hash = Hash::from_bytes(hash_bytes);
                self.get_block_by_hash(&hash)
            }
            None => Ok(None),
        }
    }

    /// Get the canonical block hash at a height.
    pub fn get_canonical_hash_at_height(&self, height: u32) -> Result<Option<Hash>> {
        let key = height_to_hash_key(height);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_canonical_hash_at_height: {}", e)))?
        {
            Some(data) => {
                if data.len() < 32 {
                    return Err(CoreError::Storage(
                        "invalid height_to_hash data".to_string(),
                    ));
                }
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&data[..32]);
                Ok(Some(Hash::from_bytes(hash_bytes)))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Chain Tip
    // ========================================================================

    /// Store the chain tip metadata.
    pub fn put_tip(&self, tip: &PersistedTip) -> Result<()> {
        let encoded = tip.encode();
        self.db
            .insert(TIP_KEY, encoded)
            .map_err(|e| CoreError::Storage(format!("put_tip: {}", e)))?;
        Ok(())
    }

    /// Retrieve the chain tip metadata.
    pub fn get_tip(&self) -> Result<Option<PersistedTip>> {
        match self
            .db
            .get(TIP_KEY)
            .map_err(|e| CoreError::Storage(format!("get_tip: {}", e)))?
        {
            Some(data) => {
                let tip = PersistedTip::decode(&data)?;
                Ok(Some(tip))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Account State
    // ========================================================================

    /// Store an account.
    pub fn put_account(&self, address: &Address, account: &Account) -> Result<()> {
        let key = account_key(address);
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&account.balance.to_le_bytes());
        data.extend_from_slice(&account.nonce.to_le_bytes());
        self.db
            .insert(&key, data)
            .map_err(|e| CoreError::Storage(format!("put_account: {}", e)))?;
        Ok(())
    }

    /// Retrieve an account.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = account_key(address);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_account: {}", e)))?
        {
            Some(data) => {
                if data.len() != 16 {
                    return Err(CoreError::Storage(format!(
                        "account data: expected 16 bytes, got {}",
                        data.len()
                    )));
                }
                let balance = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                let nonce = u64::from_le_bytes([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ]);
                Ok(Some(Account { balance, nonce }))
            }
            None => Ok(None),
        }
    }

    /// Store the total supply.
    pub fn put_supply(&self, supply: u64) -> Result<()> {
        self.db
            .insert(SUPPLY_KEY, supply.to_le_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_supply: {}", e)))?;
        Ok(())
    }

    /// Retrieve the total supply.
    pub fn get_supply(&self) -> Result<u64> {
        match self
            .db
            .get(SUPPLY_KEY)
            .map_err(|e| CoreError::Storage(format!("get_supply: {}", e)))?
        {
            Some(data) => {
                if data.len() < 8 {
                    return Err(CoreError::Storage("supply data too short".to_string()));
                }
                Ok(u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]))
            }
            None => Ok(0),
        }
    }

    /// Store the genesis block hash.
    pub fn put_genesis_hash(&self, hash: &Hash) -> Result<()> {
        self.db
            .insert(GENESIS_HASH_KEY, hash.as_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_genesis_hash: {}", e)))?;
        Ok(())
    }

    /// Retrieve the genesis block hash.
    pub fn get_genesis_hash(&self) -> Result<Option<Hash>> {
        match self
            .db
            .get(GENESIS_HASH_KEY)
            .map_err(|e| CoreError::Storage(format!("get_genesis_hash: {}", e)))?
        {
            Some(data) => {
                if data.len() < 32 {
                    return Err(CoreError::Storage("genesis hash too short".to_string()));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&data[..32]);
                Ok(Some(Hash::from_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    /// Apply a full block to storage: header, full block, hash mapping.
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height.0;
        self.put_header(height, &block.header)?;
        self.put_block(block)?;
        Ok(())
    }

    /// Atomically commit a block, tip, and full state into a single sled batch.
    ///
    /// This ensures that if the process crashes mid-write, the database is either:
    /// - fully updated (all three committed), or
    /// - unchanged (all three rolled back via sled WAL).
    ///
    /// This prevents the inconsistent state where tip is ahead of accounts.
    pub fn commit_block(&self, block: &Block, tip: &PersistedTip, state: &State) -> Result<()> {
        let mut batch = sled::Batch::default();

        let height = block.header.height.0;
        let header_key = header_key(height);
        batch.insert(header_key, block.header.encode());

        let block_hash = block.hash();
        let block_k = block_key(&block_hash);
        batch.insert(block_k, block.encode_block());

        let h2h_key = hash_to_height_key(&block_hash);
        batch.insert(h2h_key, height.to_le_bytes().to_vec());

        let h2h_reverse = height_to_hash_key(height);
        batch.insert(h2h_reverse, block_hash.as_bytes().to_vec());

        batch.insert(TIP_KEY.to_vec(), tip.encode());

        batch.insert(
            SUPPLY_KEY.to_vec(),
            state.total_supply().to_le_bytes().to_vec(),
        );
        for (addr_bytes, account) in state.accounts_iter() {
            let addr =
                chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(*addr_bytes));
            let key = account_key(&addr);
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&account.balance.to_le_bytes());
            data.extend_from_slice(&account.nonce.to_le_bytes());
            batch.insert(key, data);
        }

        self.db
            .apply_batch(batch)
            .map_err(|e| CoreError::Storage(format!("commit_block: {}", e)))?;

        Ok(())
    }

    /// Store all accounts from a State.
    pub fn put_state(&self, state: &State) -> Result<()> {
        self.put_supply(state.total_supply())?;
        for (addr_bytes, account) in state.accounts_iter() {
            let key =
                chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(*addr_bytes));
            self.put_account(&key, account)?;
        }
        Ok(())
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| CoreError::Storage(format!("flush: {}", e)))?;
        Ok(())
    }

    /// Load all accounts from storage into a State object.
    pub fn load_state(&self) -> Result<chroma_state::State> {
        use chroma_core::hash::Hash160;
        use chroma_core::types::Address;
        use chroma_state::State;

        let mut state = State::new();
        let total_supply = self.get_supply().unwrap_or(0);
        state.set_total_supply(total_supply);

        let prefix = b"accounts:";
        for entry in self.db.scan_prefix(prefix) {
            let (key, data) =
                entry.map_err(|e| CoreError::Storage(format!("load_state: {}", e)))?;
            if data.len() != 16 {
                eprintln!(
                    "load_state: skipping corrupted account at key {:?} (expected 16 bytes, got {})",
                    &key[prefix.len()..],
                    data.len()
                );
                continue;
            }
            let mut addr_bytes = [0u8; 20];
            if key.len() == prefix.len() + 20 {
                addr_bytes.copy_from_slice(&key[prefix.len()..]);
            } else {
                continue;
            }
            let balance = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            let nonce = u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]);
            let address = Address::from_hash160(Hash160(addr_bytes));
            state.set_account_direct(&address, chroma_state::Account { balance, nonce });
        }

        Ok(state)
    }

    /// Get the approximate size of the database on disk.
    pub fn size_on_disk(&self) -> Result<u64> {
        self.db
            .size_on_disk()
            .map_err(|e| CoreError::Storage(format!("size_on_disk: {}", e)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_block::BlockHeader;
    use chroma_core::hash::Hash160;
    use chroma_core::types::{BlockHeight, CompactTarget};

    fn test_header(height: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            previous_hash: Hash::blake3(&height.to_le_bytes()),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: 1_700_000_000 + (height as u64) * 10,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(height),
            nonce: 0,
        }
    }

    fn test_block(height: u32) -> Block {
        Block {
            header: test_header(height),
            transactions: vec![],
        }
    }

    fn test_address(n: u8) -> Address {
        let mut h = [0u8; 20];
        h[0] = n;
        Address::from_hash160(Hash160(h))
    }

    #[test]
    fn test_open_and_close() {
        let storage = Storage::open_temporary().unwrap();
        let _ = storage;
    }

    #[test]
    fn test_put_and_get_header() {
        let storage = Storage::open_temporary().unwrap();
        let header = test_header(1);
        storage.put_header(1, &header).unwrap();
        let retrieved = storage.get_header(1).unwrap().unwrap();
        assert_eq!(retrieved, header);
    }

    #[test]
    fn test_get_header_missing() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_header(999).unwrap().is_none());
    }

    #[test]
    fn test_has_header() {
        let storage = Storage::open_temporary().unwrap();
        assert!(!storage.has_header(0).unwrap());
        storage.put_header(0, &test_header(0)).unwrap();
        assert!(storage.has_header(0).unwrap());
    }

    #[test]
    fn test_put_and_get_block() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(5);
        let hash = block.hash();
        storage.put_block(&block).unwrap();
        let retrieved = storage.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header, block.header);
    }

    #[test]
    fn test_get_height_for_hash() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(42);
        let hash = block.hash();
        storage.put_block(&block).unwrap();
        let height = storage.get_height_for_hash(&hash).unwrap().unwrap();
        assert_eq!(height, 42);
    }

    #[test]
    fn test_apply_block() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(1);
        let hash = block.hash();
        storage.apply_block(&block).unwrap();

        assert!(storage.has_header(1).unwrap());
        let retrieved = storage.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header.height.0, 1);
    }

    #[test]
    fn test_put_and_get_tip() {
        let storage = Storage::open_temporary().unwrap();
        let tip = PersistedTip {
            height: 100,
            hash: Hash::blake3(b"tip"),
            cumulative_work: [1u8; 32],
            supply: 100_000_000,
        };
        storage.put_tip(&tip).unwrap();
        let retrieved = storage.get_tip().unwrap().unwrap();
        assert_eq!(retrieved.height, 100);
        assert_eq!(retrieved.hash, tip.hash);
        assert_eq!(retrieved.supply, 100_000_000);
    }

    #[test]
    fn test_get_tip_missing() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_tip().unwrap().is_none());
    }

    #[test]
    fn test_put_and_get_account() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xAA);
        let account = Account::new(5_000_000, 42);
        storage.put_account(&addr, &account).unwrap();
        let retrieved = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.balance, 5_000_000);
        assert_eq!(retrieved.nonce, 42);
    }

    #[test]
    fn test_get_account_missing() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xBB);
        assert!(storage.get_account(&addr).unwrap().is_none());
    }

    #[test]
    fn test_supply_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        assert_eq!(storage.get_supply().unwrap(), 0);
        storage.put_supply(50_000_000).unwrap();
        assert_eq!(storage.get_supply().unwrap(), 50_000_000);
    }

    #[test]
    fn test_genesis_hash_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_genesis_hash().unwrap().is_none());
        let hash = Hash::blake3(b"genesis");
        storage.put_genesis_hash(&hash).unwrap();
        assert_eq!(storage.get_genesis_hash().unwrap().unwrap(), hash);
    }

    #[test]
    fn test_multiple_blocks() {
        let storage = Storage::open_temporary().unwrap();
        let mut hashes = Vec::new();
        for h in 0..10u32 {
            let block = test_block(h);
            let hash = block.hash();
            hashes.push(hash);
            storage.apply_block(&block).unwrap();
        }

        for h in 0..10u32 {
            assert!(storage.has_header(h).unwrap());
        }

        for (i, hash) in hashes.iter().enumerate() {
            let block = storage.get_block_by_hash(hash).unwrap().unwrap();
            assert_eq!(block.header.height.0, i as u32);
        }
    }

    #[test]
    fn test_persisted_tip_serialization_roundtrip() {
        let tip = PersistedTip {
            height: 999,
            hash: Hash::blake3(b"test"),
            cumulative_work: [0xFF; 32],
            supply: u64::MAX,
        };
        let encoded = tip.encode();
        let decoded = PersistedTip::decode(&encoded).unwrap();
        assert_eq!(decoded.height, tip.height);
        assert_eq!(decoded.hash, tip.hash);
        assert_eq!(decoded.cumulative_work, tip.cumulative_work);
        assert_eq!(decoded.supply, tip.supply);
    }

    #[test]
    fn test_account_overwrite() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xCC);
        let acc1 = Account::new(100, 0);
        let acc2 = Account::new(200, 5);
        storage.put_account(&addr, &acc1).unwrap();
        storage.put_account(&addr, &acc2).unwrap();
        let retrieved = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.balance, 200);
        assert_eq!(retrieved.nonce, 5);
    }

    #[test]
    fn test_flush() {
        let storage = Storage::open_temporary().unwrap();
        storage.put_supply(42).unwrap();
        storage.flush().unwrap();
        assert_eq!(storage.get_supply().unwrap(), 42);
    }

    #[test]
    fn test_many_accounts() {
        let storage = Storage::open_temporary().unwrap();
        for i in 0..100u8 {
            let addr = test_address(i);
            let acc = Account::new((i as u64) * 1_000_000, i as u64);
            storage.put_account(&addr, &acc).unwrap();
        }

        for i in 0..100u8 {
            let addr = test_address(i);
            let acc = storage.get_account(&addr).unwrap().unwrap();
            assert_eq!(acc.balance, (i as u64) * 1_000_000);
            assert_eq!(acc.nonce, i as u64);
        }
    }

    // ====================================================================
    // AUDIT 3: Atomic commit_block tests
    // ====================================================================

    #[test]
    fn test_commit_block_is_atomic() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(1);
        let block_hash = block.hash();

        let mut state = chroma_state::State::new();
        let addr = test_address(0);
        state.set_account_direct(
            &addr,
            Account {
                balance: 5000,
                nonce: 3,
            },
        );
        state.set_total_supply(5000);

        let tip = PersistedTip {
            height: 1,
            hash: block_hash,
            cumulative_work: [1u8; 32],
            supply: 5000,
        };

        storage.commit_block(&block, &tip, &state).unwrap();
        storage.flush().unwrap();

        let retrieved_block = storage.get_block_by_hash(&block_hash).unwrap().unwrap();
        assert_eq!(retrieved_block.header.height.0, 1);

        let retrieved_tip = storage.get_tip().unwrap().unwrap();
        assert_eq!(retrieved_tip.height, 1);
        assert_eq!(retrieved_tip.hash, block_hash);

        let retrieved_acc = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved_acc.balance, 5000);
        assert_eq!(retrieved_acc.nonce, 3);

        assert_eq!(storage.get_supply().unwrap(), 5000);
    }

    #[test]
    fn test_commit_block_overwrites_previous_state() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0);

        let block1 = test_block(1);
        let mut state1 = chroma_state::State::new();
        state1.set_account_direct(
            &addr,
            Account {
                balance: 1000,
                nonce: 1,
            },
        );
        state1.set_total_supply(1000);
        let tip1 = PersistedTip {
            height: 1,
            hash: block1.hash(),
            cumulative_work: [1u8; 32],
            supply: 1000,
        };
        storage.commit_block(&block1, &tip1, &state1).unwrap();

        let block2 = test_block(2);
        let mut state2 = chroma_state::State::new();
        state2.set_account_direct(
            &addr,
            Account {
                balance: 2000,
                nonce: 2,
            },
        );
        state2.set_total_supply(2000);
        let tip2 = PersistedTip {
            height: 2,
            hash: block2.hash(),
            cumulative_work: [2u8; 32],
            supply: 2000,
        };
        storage.commit_block(&block2, &tip2, &state2).unwrap();
        storage.flush().unwrap();

        let tip = storage.get_tip().unwrap().unwrap();
        assert_eq!(tip.height, 2);

        let acc = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(acc.balance, 2000);
        assert_eq!(acc.nonce, 2);

        assert_eq!(storage.get_supply().unwrap(), 2000);
    }
}
