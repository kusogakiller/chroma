use std::collections::HashMap;

use chroma_core::constants::MAX_TRANSACTION_SIZE;
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::serialize::CanonicalEncode;
use chroma_core::types::{Address, Amount};
use chroma_state::State;
use chroma_tx::Transaction;

pub const MAX_MEMPOOL_SIZE: usize = 50_000_000;
pub const MAX_MEMPOOL_TXS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub tx_hash: Hash,
    pub size: usize,
    pub added_at: u64,
}

pub struct Mempool {
    entries: HashMap<Hash, MempoolEntry>,
    tx_order: Vec<Hash>,
    total_size: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            entries: HashMap::new(),
            tx_order: Vec::new(),
            total_size: 0,
        }
    }

    /// Validate a transaction before adding it to the mempool.
    ///
    /// Checks:
    /// - Schnorr signature validity (with network magic for cross-network replay protection)
    /// - Amount > 0
    /// - Sender != recipient
    ///
    /// Does NOT check state-dependent conditions (balance, nonce against state)
    /// because the mempool has no access to chain state.
    pub fn validate_transaction(tx: &Transaction, network_magic: [u8; 4]) -> Result<()> {
        if !tx.verify_signature(network_magic) {
            return Err(CoreError::InvalidSignature(
                "transaction signature verification failed".to_string(),
            ));
        }
        if tx.amount == Amount::ZERO {
            return Err(CoreError::InvalidTransaction(
                "amount must be greater than zero".to_string(),
            ));
        }
        if tx.sender_address() == tx.recipient {
            return Err(CoreError::InvalidTransaction(
                "sender and recipient must differ".to_string(),
            ));
        }
        Ok(())
    }

    /// Add a validated transaction to the mempool.
    ///
    /// Returns `Ok(true)` if added, `Ok(false)` if duplicate by hash.
    /// If a transaction with the same (sender, nonce) already exists,
    /// the old one is replaced (first-seen policy).
    /// Returns `Err` if validation fails or the mempool is full.
    pub fn add_transaction(&mut self, tx: Transaction, network_magic: [u8; 4]) -> Result<bool> {
        Self::validate_transaction(&tx, network_magic)?;

        let encoded = tx.encode();
        let tx_hash = Hash::blake3(&encoded);
        if self.entries.contains_key(&tx_hash) {
            return Ok(false);
        }

        // Remove any existing transaction from the same sender with the same nonce
        let sender_address = tx.sender_address();
        let nonce = tx.nonce;
        let existing_keys: Vec<(Hash, usize)> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.tx.sender_address() == sender_address
                    && e.tx.nonce == nonce
                    && e.tx_hash != tx_hash
            })
            .map(|(h, e)| (*h, e.size))
            .collect();
        for (old_hash, _old_size) in existing_keys {
            if let Some(entry) = self.entries.remove(&old_hash) {
                self.total_size -= entry.size;
                self.tx_order.retain(|h| *h != old_hash);
            }
        }

        if self.tx_order.len() >= MAX_MEMPOOL_TXS {
            return Err(CoreError::InvalidTransaction(
                "mempool full: too many transactions".to_string(),
            ));
        }
        let size = encoded.len();
        if self.total_size + size > MAX_MEMPOOL_SIZE {
            return Err(CoreError::InvalidTransaction(
                "mempool full: size limit exceeded".to_string(),
            ));
        }
        let entry = MempoolEntry {
            tx,
            tx_hash,
            size,
            added_at: 0,
        };
        self.total_size += size;
        self.tx_order.push(tx_hash);
        self.entries.insert(tx_hash, entry);
        Ok(true)
    }

    pub fn remove_transaction(&mut self, hash: &Hash) -> bool {
        if let Some(entry) = self.entries.remove(hash) {
            self.total_size -= entry.size;
            self.tx_order.retain(|h| *h != *hash);
            true
        } else {
            false
        }
    }

    pub fn has_transaction(&self, hash: &Hash) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn get_transaction(&self, hash: &Hash) -> Option<&Transaction> {
        self.entries.get(hash).map(|e| &e.tx)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size(&self) -> usize {
        self.total_size
    }

    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.tx_order.clone()
    }

    pub fn transactions(&self) -> Vec<&Transaction> {
        self.tx_order
            .iter()
            .filter_map(|h| self.entries.get(h).map(|e| &e.tx))
            .collect()
    }

    pub fn remove_transactions(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove_transaction(hash);
        }
    }

    /// Select transactions for block assembly, in pool order, skipping any
    /// that would fail block validation against `state`.
    ///
    /// Without this, one state-invalid (unfunded balance, wrong nonce) but
    /// well-signed mempool entry poisons EVERY candidate: the prospective
    /// state root fails, the mined block is invalid, and the entry stays
    /// queued — a permanent mining halt reachable via a single RPC call or
    /// gossip message. Skipped entries stay queued (funding or missing
    /// nonces may arrive later), so selection only DEFERS, never censors.
    ///
    /// Mirrors `validate_block`'s per-transaction checks exactly (size,
    /// amount, self-send, nonce, balance, checked arithmetic); validation
    /// remains the sole consensus judge. Signatures are NOT re-verified:
    /// `add_transaction` already enforces them, so every pooled entry is
    /// known-good there. At most `limit` entries are examined (matching the
    /// miner's inclusion cap) to bound CPU under floods.
    pub fn select_for_block(&self, state: &State, limit: usize) -> Vec<Transaction> {
        // Overlay of simulated (balance, nonce) per touched address, seeded
        // lazily from chain state. Mirrors sequential application order.
        let mut overlay: HashMap<Address, (u64, u64)> = HashMap::new();
        let mut kept = Vec::new();
        for tx in self
            .tx_order
            .iter()
            .filter_map(|h| self.entries.get(h))
            .take(limit)
            .map(|e| &e.tx)
        {
            if tx.encode().len() > MAX_TRANSACTION_SIZE {
                continue;
            }
            if tx.amount.0 == 0 {
                continue;
            }
            let sender = tx.sender_address();
            if sender == tx.recipient {
                continue;
            }
            let (balance, nonce) = match overlay.get(&sender) {
                Some(&(b, n)) => (b, n),
                None => {
                    let a = state.get_account(&sender);
                    (a.balance, a.nonce)
                }
            };
            if tx.nonce.0 != nonce {
                continue;
            }
            let new_balance = match balance.checked_sub(tx.amount.0) {
                Some(b) => b,
                None => continue,
            };
            let new_nonce = match nonce.checked_add(1) {
                Some(n) => n,
                None => continue,
            };
            let (recipient_balance, recipient_nonce) = match overlay.get(&tx.recipient) {
                Some(&(b, n)) => (b, n),
                None => {
                    let a = state.get_account(&tx.recipient);
                    (a.balance, a.nonce)
                }
            };
            let new_recipient_balance = match recipient_balance.checked_add(tx.amount.0) {
                Some(b) => b,
                None => continue,
            };
            overlay.insert(sender, (new_balance, new_nonce));
            overlay.insert(tx.recipient, (new_recipient_balance, recipient_nonce));
            kept.push(tx.clone());
        }
        kept
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.tx_order.clear();
        self.total_size = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
    use chroma_core::types::{Amount, Nonce};
    use chroma_crypto::hash::hash160;
    use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
    use chroma_tx::{create_transaction, Transaction};

    fn alice_secret() -> SecretKey32 {
        SecretKey32::from_bytes([0xAA; 32]).unwrap()
    }

    fn bob_address() -> chroma_core::types::Address {
        let mut h = [0u8; 20];
        h[0] = 0xBB;
        chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn alice_address() -> chroma_core::types::Address {
        let secret = alice_secret();
        let pubkey = PublicKey32::from_secret(&secret).unwrap();
        let h = hash160(&pubkey.0);
        chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn valid_tx(amount: u64, nonce_val: u64) -> Transaction {
        create_transaction(
            &alice_secret(),
            alice_address(),
            bob_address(),
            Amount(amount),
            Nonce(nonce_val),
            REGTEST_MAGIC,
        )
        .unwrap()
    }

    #[test]
    fn test_empty_mempool() {
        let pool = Mempool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_has_nonexistent() {
        let pool = Mempool::new();
        assert!(!pool.has_transaction(&Hash::blake3(b"nope")));
        assert!(pool.get_transaction(&Hash::blake3(b"nope")).is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut pool = Mempool::new();
        assert!(!pool.remove_transaction(&Hash::blake3(b"nope")));
    }

    #[test]
    fn test_clear_empty() {
        let mut pool = Mempool::new();
        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_transaction_hashes_empty() {
        let pool = Mempool::new();
        assert!(pool.transaction_hashes().is_empty());
    }

    #[test]
    fn test_transactions_empty() {
        let pool = Mempool::new();
        assert!(pool.transactions().is_empty());
    }

    #[test]
    fn test_remove_transactions_empty() {
        let mut pool = Mempool::new();
        pool.remove_transactions(&[]);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_validate_valid_transaction() {
        let tx = valid_tx(1_000_000, 0);
        assert!(Mempool::validate_transaction(&tx, REGTEST_MAGIC).is_ok());
    }

    #[test]
    fn test_validate_rejects_zero_amount() {
        let tx = valid_tx(1_000_000, 0);
        // Build a tx with amount zero — create_transaction rejects this,
        // so construct manually via tampering
        let mut tampered = tx;
        tampered.amount = Amount::ZERO;
        assert!(Mempool::validate_transaction(&tampered, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_validate_rejects_self_send() {
        // Build a tx where sender == recipient — create_transaction rejects this,
        // so we tamper after creation
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let mut tampered = tx;
        tampered.recipient = alice_address();
        assert!(Mempool::validate_transaction(&tampered, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_validate_rejects_bad_signature() {
        let tx = valid_tx(1_000_000, 0);
        let mut tampered = tx.clone();
        tampered.amount = Amount(999_999);
        // Signature won't match the tampered amount
        assert!(!tampered.verify_signature(REGTEST_MAGIC));
        assert!(Mempool::validate_transaction(&tampered, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_add_validated_transaction() {
        let mut pool = Mempool::new();
        let tx = valid_tx(1_000_000, 0);
        assert!(pool.add_transaction(tx, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_add_duplicate_hash_returns_false() {
        let mut pool = Mempool::new();
        let tx = valid_tx(1_000_000, 0);
        assert!(pool.add_transaction(tx.clone(), REGTEST_MAGIC).unwrap());
        assert!(!pool.add_transaction(tx, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_add_rejects_invalid_transaction() {
        let mut pool = Mempool::new();
        let tx = valid_tx(1_000_000, 0);
        let mut bad = tx;
        bad.amount = Amount::ZERO;
        assert!(pool.add_transaction(bad, REGTEST_MAGIC).is_err());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_nonce_replacement() {
        let mut pool = Mempool::new();
        // Two transactions with same (sender, nonce) but different amount (and thus different hash)
        let tx1 = valid_tx(1_000_000, 5);
        let tx2 = valid_tx(2_000_000, 5);

        assert!(pool.add_transaction(tx1, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 1);

        // tx2 replaces tx1 (same sender + nonce)
        assert!(pool.add_transaction(tx2, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 1);

        // The old tx should be gone, the new one present
        let hashes = pool.transaction_hashes();
        let encoded_new = valid_tx(2_000_000, 5).encode();
        let new_hash = Hash::blake3(&encoded_new);
        assert!(hashes.contains(&new_hash));
    }

    #[test]
    fn test_different_nonces_coexist() {
        let mut pool = Mempool::new();
        let tx1 = valid_tx(1_000_000, 0);
        let tx2 = valid_tx(1_000_000, 1);

        assert!(pool.add_transaction(tx1, REGTEST_MAGIC).unwrap());
        assert!(pool.add_transaction(tx2, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_different_senders_same_nonce_coexist() {
        let mut pool = Mempool::new();

        let secret1 = SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let secret2 = SecretKey32::from_bytes([0xBB; 32]).unwrap();

        let pk1 = PublicKey32::from_secret(&secret1).unwrap();
        let pk2 = PublicKey32::from_secret(&secret2).unwrap();

        let addr1 =
            chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(hash160(&pk1.0)));
        let addr2 =
            chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(hash160(&pk2.0)));

        let tx1 = create_transaction(
            &secret1,
            addr1,
            bob_address(),
            Amount(100),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let tx2 = create_transaction(
            &secret2,
            addr2,
            bob_address(),
            Amount(200),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        assert!(pool.add_transaction(tx1, REGTEST_MAGIC).unwrap());
        assert!(pool.add_transaction(tx2, REGTEST_MAGIC).unwrap());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_nonce_replacement_updates_size() {
        let mut pool = Mempool::new();
        let tx1 = valid_tx(1_000_000, 0);
        let size_before = pool.size();
        pool.add_transaction(tx1, REGTEST_MAGIC).unwrap();
        let size_with_one = pool.size();

        // Replace with a new tx (same sender+nonce) — size should not double
        let tx2 = valid_tx(2_000_000, 0);
        pool.add_transaction(tx2, REGTEST_MAGIC).unwrap();
        let size_with_replacement = pool.size();

        assert!(size_with_one > size_before);
        assert_eq!(size_with_replacement, size_with_one);
    }

    #[test]
    fn test_remove_transactions_clears_mining() {
        let mut pool = Mempool::new();
        let tx = valid_tx(1_000_000, 0);
        pool.add_transaction(tx, REGTEST_MAGIC).unwrap();
        assert_eq!(pool.len(), 1);

        let hashes = pool.transaction_hashes();
        pool.remove_transactions(&hashes);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_mempool_rejects_cross_network_mainnet_tx_on_regtest() {
        let tx = create_transaction(
            &alice_secret(),
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            MAINNET_MAGIC,
        )
        .unwrap();
        // Same key/fields, but mempool validates with regtest magic → must fail.
        assert!(Mempool::validate_transaction(&tx, REGTEST_MAGIC).is_err());
        let mut pool = Mempool::new();
        assert!(pool.add_transaction(tx, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_mempool_rejects_cross_network_testnet_tx_on_regtest() {
        let tx = create_transaction(
            &alice_secret(),
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            TESTNET_MAGIC,
        )
        .unwrap();
        assert!(Mempool::validate_transaction(&tx, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_mempool_accepts_matching_network_magic() {
        for magic in [MAINNET_MAGIC, TESTNET_MAGIC, REGTEST_MAGIC] {
            let tx = create_transaction(
                &alice_secret(),
                alice_address(),
                bob_address(),
                Amount(1_000_000),
                Nonce(0),
                magic,
            )
            .unwrap();
            assert!(
                Mempool::validate_transaction(&tx, magic).is_ok(),
                "matching magic must validate"
            );
        }
    }

    #[test]
    fn test_mempool_rejects_coinbase_sentinel_on_all_networks() {
        use chroma_crypto::schnorr::{PublicKey32, Signature64};
        for magic in [MAINNET_MAGIC, TESTNET_MAGIC, REGTEST_MAGIC] {
            let coinbase = Transaction {
                sender_pubkey: PublicKey32([0u8; 32]),
                recipient: bob_address(),
                amount: Amount(1_000_000),
                nonce: Nonce(0),
                signature: Signature64([0u8; 64]),
            };
            assert!(
                Mempool::validate_transaction(&coinbase, magic).is_err(),
                "coinbase sentinel must never validate"
            );
        }
    }

    /// Long-run transaction soak at mempool level: interleaved valid,
    /// duplicate, conflicting-nonce, zero-amount, bad-signature, and
    /// cross-magic-replay transactions. Pins per-category outcomes plus the
    /// end-state invariant (exactly the valid, latest-nonce set survives).
    /// State-dependent rules (balance) live at block application, NOT here —
    /// the mempool must accept a well-formed but unfunded tx (documented
    /// layering, verified by e2e insufficient-balance rejection at apply).
    #[test]
    fn test_mempool_tx_soak_sequence() {
        use chroma_crypto::schnorr::Signature64;
        let mut pool = Mempool::new();
        // 1. Valid nonces 0..9 all accepted.
        for n in 0..10u64 {
            assert!(pool
                .add_transaction(valid_tx(1_000, n), REGTEST_MAGIC)
                .unwrap());
        }
        assert_eq!(pool.len(), 10);
        // 2. Exact duplicates rejected as duplicates (Ok(false)), no growth.
        for n in 0..10u64 {
            assert!(!pool
                .add_transaction(valid_tx(1_000, n), REGTEST_MAGIC)
                .unwrap());
        }
        assert_eq!(pool.len(), 10);
        // 3. Conflicting nonce (same sender+nonce, different amount) replaces.
        let conflict = valid_tx(9_999, 3);
        assert!(pool
            .add_transaction(conflict.clone(), REGTEST_MAGIC)
            .unwrap());
        assert_eq!(pool.len(), 10, "replacement must not grow the pool");
        let stored = pool
            .get_transaction(&Hash::blake3(&conflict.encode()))
            .unwrap();
        assert_eq!(stored.amount, Amount(9_999));
        // 4. Zero amount rejected.
        let mut zero = valid_tx(1_000, 10);
        zero.amount = Amount::ZERO;
        assert!(pool.add_transaction(zero, REGTEST_MAGIC).is_err());
        // 5. Bad signature rejected (garbage sig, well-formed otherwise).
        let mut badsig = valid_tx(1_000, 11);
        badsig.signature = Signature64([0x22; 64]);
        assert!(pool.add_transaction(badsig, REGTEST_MAGIC).is_err());
        // 6. Cross-magic replay rejected: testnet-signed bytes fail regtest.
        let replay = create_transaction(
            &alice_secret(),
            alice_address(),
            bob_address(),
            Amount(1_000),
            Nonce(12),
            TESTNET_MAGIC,
        )
        .unwrap();
        assert!(Mempool::validate_transaction(&replay, REGTEST_MAGIC).is_err());
        assert!(pool.add_transaction(replay, REGTEST_MAGIC).is_err());
        // 7. Self-send rejected.
        let secret = alice_secret();
        let mut self_send = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000),
            Nonce(13),
            REGTEST_MAGIC,
        )
        .unwrap();
        self_send.recipient = alice_address();
        assert!(pool.add_transaction(self_send, REGTEST_MAGIC).is_err());
        // End state: exactly nonces 0..10 (with nonce 3 replaced), nothing else.
        assert_eq!(pool.len(), 10);
        let mut nonces: Vec<u64> = pool.transactions().iter().map(|t| t.nonce.0).collect();
        nonces.sort_unstable();
        assert_eq!(nonces, (0..10u64).collect::<Vec<_>>());
    }

    /// Miner selection: only state-valid txs are chosen, in pool order,
    /// with failed ones skipped but left queued.
    #[test]
    fn test_select_for_block_skips_state_invalid() {
        use chroma_state::State;
        let mut state = State::new();
        // Fund Alice with one block subsidy.
        state.apply_subsidy(&alice_address(), 1).unwrap();
        let funded = state.get_account(&alice_address()).balance;
        assert!(funded > 0);

        let mut pool = Mempool::new();
        // Valid chain: nonce 0 spends 600k, nonce 1 spends 300k of the rest.
        assert!(pool
            .add_transaction(valid_tx(600_000, 0), REGTEST_MAGIC)
            .unwrap());
        assert!(pool
            .add_transaction(valid_tx(300_000, 1), REGTEST_MAGIC)
            .unwrap());
        // Overspend at nonce 2 (only 100k left): skipped, stays queued.
        assert!(pool
            .add_transaction(valid_tx(500_000, 2), REGTEST_MAGIC)
            .unwrap());
        // Gap nonce + unfunded sender: skipped.
        let gap = create_transaction(
            &alice_secret(),
            alice_address(),
            bob_address(),
            Amount(10),
            Nonce(99),
            REGTEST_MAGIC,
        )
        .unwrap();
        assert!(pool.add_transaction(gap, REGTEST_MAGIC).unwrap());

        let selected = pool.select_for_block(&state, 10_000);
        assert_eq!(selected.len(), 2, "only the valid chain is selected");
        assert_eq!(selected[0].nonce.0, 0);
        assert_eq!(selected[1].nonce.0, 1);
        assert_eq!(selected[0].amount.0, 600_000);
        assert_eq!(selected[1].amount.0, 300_000);
        // Skipped entries remain queued (deferred, not censored).
        assert_eq!(pool.len(), 4);
        // Limit truncates in pool order.
        let limited = pool.select_for_block(&state, 1);
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].nonce.0, 0);
        // Empty state selects nothing but errors nothing.
        let bare = State::new();
        assert!(pool.select_for_block(&bare, 10_000).is_empty());
    }

    /// Adversarial uniqueness flood: thousands of distinct garbage-signature
    /// transactions must ALL be rejected with zero memory growth. There is no
    /// per-hash negative cache by design (re-validation is cheap, storage of
    /// attacker-chosen keys would be the actual leak vector).
    #[test]
    fn test_mempool_unique_garbage_flood_stays_empty() {
        use chroma_crypto::schnorr::{PublicKey32, Signature64};
        let mut pool = Mempool::new();
        for i in 0..5000u64 {
            let mut pk = [0u8; 32];
            pk[..8].copy_from_slice(&i.to_le_bytes());
            let tx = Transaction {
                sender_pubkey: PublicKey32(pk),
                recipient: bob_address(),
                amount: Amount(1_000),
                nonce: Nonce(i),
                signature: Signature64([0x22; 64]),
            };
            assert!(pool.add_transaction(tx, REGTEST_MAGIC).is_err());
        }
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.size(), 0);
        // Pool still fully functional afterwards.
        assert!(pool
            .add_transaction(valid_tx(1_000, 0), REGTEST_MAGIC)
            .unwrap());
    }
}
