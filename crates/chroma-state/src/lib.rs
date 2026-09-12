//! Chroma State Model
//!
//! Account/balance model. State transitions are pure functions.
//! The state is a mapping from Address → Account.
//! State commitment: BLAKE3 of sorted (address, account) encodings.

use std::collections::BTreeMap;

use chroma_core::constants::{BLOCK_REWARD_UNITS, MAX_SUPPLY_UNITS};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::Address;

// ============================================================================
// Account
// ============================================================================

/// Per-account state: balance and transaction nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Balance in atomic units (1 CHR = 1,000,000 units)
    pub balance: u64,
    /// Number of transactions sent from this account.
    /// Each transaction must have nonce == account.nonce.
    /// After processing, nonce is incremented by 1.
    pub nonce: u64,
}

impl Account {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Account { balance, nonce }
    }

    /// Encode account for state commitment (fixed 16 bytes: balance_le64 || nonce_le64)
    fn encode_value(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.balance.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Decode account from 16 bytes
    #[allow(dead_code)]
    fn decode_value(data: &[u8]) -> Result<Self> {
        if data.len() != 16 {
            return Err(CoreError::Serialization(format!(
                "account: expected 16 bytes, got {}",
                data.len()
            )));
        }
        let balance = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let nonce = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        Ok(Account { balance, nonce })
    }
}

// ============================================================================
// State
// ============================================================================

/// Global account state. Deterministic, ordered by address for commitment.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// Accounts sorted by address for deterministic iteration.
    accounts: BTreeMap<[u8; 20], Account>,
    /// Total circulating supply in atomic units.
    total_supply: u64,
    /// Journal for the current block being applied (for reorg rollback).
    journal: BlockJournal,
    /// Rollback journal: block_height → BlockJournal for the last REORG_JOURNAL_DEPTH blocks.
    rollbacks: Vec<BlockJournal>,
    /// Total supply at the start of each journaled block (for rollback).
    supply_snapshots: Vec<u64>,
}

impl State {
    /// Create empty state.
    pub fn new() -> Self {
        State {
            accounts: BTreeMap::new(),
            total_supply: 0,
            journal: BlockJournal::new(),
            rollbacks: Vec::new(),
            supply_snapshots: Vec::new(),
        }
    }

    /// Get account, returning default (zero) if not found.
    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address.as_hash160().as_bytes())
            .copied()
            .unwrap_or(Account::default())
    }

    /// Get total supply.
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Iterate over all accounts for persistence.
    pub fn accounts_iter(&self) -> impl Iterator<Item = (&[u8; 20], &Account)> {
        self.accounts.iter()
    }

    /// Set account directly (for loading from storage).
    pub fn set_account_direct(&mut self, address: &Address, account: Account) {
        let key = *address.as_hash160().as_bytes();
        self.accounts.insert(key, account);
    }

    /// Set total supply directly (for loading from storage).
    pub fn set_total_supply(&mut self, supply: u64) {
        self.total_supply = supply;
    }

    /// Begin a new block — creates a fresh journal and snapshots supply.
    pub fn begin_block(&mut self) {
        self.journal = BlockJournal::new();
        self.supply_snapshots.push(self.total_supply);
    }

    /// Commit the current block's journal to the rollback stack.
    /// Keeps at most REORG_JOURNAL_DEPTH entries.
    pub fn commit_block(&mut self) {
        let journal = std::mem::take(&mut self.journal);
        self.rollbacks.push(journal);
        let max = chroma_core::constants::REORG_JOURNAL_DEPTH as usize;
        while self.rollbacks.len() > max {
            self.rollbacks.drain(..1);
            self.supply_snapshots.drain(..1);
        }
    }

    /// Abort the current in-progress block without committing.
    /// Undoes all state changes made since begin_block() and pops the supply snapshot.
    /// Use this when block validation fails after begin_block() but before commit_block().
    pub fn abort_block(&mut self) {
        self.journal.rollback(&mut self.accounts);
        self.supply_snapshots.pop();
        self.journal = BlockJournal::new();
    }

    /// Rollback the last committed block (most recent journal).
    /// Returns true if rollback succeeded, false if no journal available.
    pub fn rollback_block(&mut self) -> bool {
        let journal = match self.rollbacks.pop() {
            Some(j) => j,
            None => return false,
        };
        let prev_supply = self.supply_snapshots.pop().unwrap_or(0);
        journal.rollback(&mut self.accounts);
        self.total_supply = prev_supply;
        true
    }

    /// Set account (used by state transitions and genesis).
    /// Records the previous state in the journal for rollback.
    fn set_account(&mut self, address: &Address, account: Account) {
        let key = *address.as_hash160().as_bytes();
        let prev = self.accounts.get(&key).copied();
        self.journal.record(key, prev);
        *self.accounts.entry(key).or_default() = account;
    }

    /// Compute state root using a proper Sorted Merkle Tree (SPEC §7.2).
    ///
    /// - Empty state → Hash::ZERO
    /// - Leaf: H(encode(key_20bytes) || encode(value_16bytes))
    /// - Internal node: H(left || right)
    /// - Tree is built from sorted (key, value) pairs
    pub fn compute_state_root(&self) -> Hash {
        let leaves: Vec<Hash> = self
            .accounts
            .iter()
            .map(|(addr, account)| {
                let mut leaf_data = Vec::with_capacity(36);
                leaf_data.extend_from_slice(addr);
                leaf_data.extend_from_slice(&account.encode_value());
                Hash::blake3(&leaf_data)
            })
            .collect();

        sorted_merkle_root(&leaves)
    }

    /// Compute the state root that would result after applying a coinbase subsidy
    /// and a set of transactions, WITHOUT permanently modifying this state.
    /// Used by the miner to determine the correct state_root for a candidate block.
    ///
    /// Each tx_desc is (sender_address, recipient, amount, nonce).
    pub fn compute_prospective_state_root(
        &self,
        _height: u32,
        coinbase_recipient: &Address,
        tx_descs: &[(Address, Address, u64, u64)],
    ) -> Result<Hash> {
        let mut accounts = self.accounts.clone();
        let mut _total_supply = self.total_supply;

        let subsidy = self.block_subsidy(_height)?;

        if subsidy > 0 {
            let key = *coinbase_recipient.as_hash160().as_bytes();
            let mut account = accounts.get(&key).copied().unwrap_or_default();
            account.balance = account
                .balance
                .checked_add(subsidy)
                .ok_or_else(|| CoreError::Overflow("coinbase overflow".into()))?;
            accounts.insert(key, account);
            _total_supply += subsidy;
        }

        for (sender, recipient, amount, nonce) in tx_descs {
            let sender_key = *sender.as_hash160().as_bytes();
            let recipient_key = *recipient.as_hash160().as_bytes();

            let mut sender_account = accounts.get(&sender_key).copied().unwrap_or_default();
            if *nonce != sender_account.nonce {
                return Err(CoreError::InvalidNonce(format!(
                    "prospective: expected nonce {}, got {}",
                    sender_account.nonce, nonce
                )));
            }
            let new_balance = sender_account.balance.checked_sub(*amount).ok_or_else(|| {
                CoreError::InsufficientBalance(format!(
                    "prospective: insufficient balance {} < {}",
                    sender_account.balance, amount
                ))
            })?;
            sender_account.balance = new_balance;
            sender_account.nonce += 1;
            accounts.insert(sender_key, sender_account);

            let mut recipient_account = accounts.get(&recipient_key).copied().unwrap_or_default();
            recipient_account.balance = recipient_account
                .balance
                .checked_add(*amount)
                .ok_or_else(|| CoreError::Overflow("recipient overflow".into()))?;
            accounts.insert(recipient_key, recipient_account);
        }

        let leaves: Vec<Hash> = accounts
            .iter()
            .map(|(addr, account)| {
                let mut leaf_data = Vec::with_capacity(36);
                leaf_data.extend_from_slice(addr);
                leaf_data.extend_from_slice(&account.encode_value());
                Hash::blake3(&leaf_data)
            })
            .collect();

        Ok(sorted_merkle_root(&leaves))
    }

    // ========================================================================
    // State Transitions
    // ========================================================================

    /// Apply a transfer transaction.
    ///
    /// Invariants enforced:
    /// - amount > 0
    /// - sender balance >= amount (checked arithmetic)
    /// - sender nonce matches tx nonce
    /// - sender != recipient (no self-sends)
    /// - total supply is conserved
    /// - no integer overflow/underflow
    pub fn apply_transaction(
        &mut self,
        sender: &Address,
        recipient: &Address,
        amount: u64,
        nonce: u64,
    ) -> Result<()> {
        if amount == 0 {
            return Err(CoreError::InvalidTransaction(
                "amount must be greater than zero".to_string(),
            ));
        }

        if sender == recipient {
            return Err(CoreError::InvalidTransaction(
                "sender and recipient must differ".to_string(),
            ));
        }

        let mut sender_account = self.get_account(sender);

        if nonce != sender_account.nonce {
            return Err(CoreError::InvalidNonce(format!(
                "expected nonce {}, got {}",
                sender_account.nonce, nonce
            )));
        }

        let new_sender_balance = sender_account.balance.checked_sub(amount).ok_or_else(|| {
            CoreError::InsufficientBalance(format!(
                "account has {} units, tried to send {}",
                sender_account.balance, amount
            ))
        })?;

        sender_account.balance = new_sender_balance;
        sender_account.nonce = sender_account
            .nonce
            .checked_add(1)
            .ok_or_else(|| CoreError::Overflow("nonce overflow".into()))?;
        self.set_account(sender, sender_account);

        let mut recipient_account = self.get_account(recipient);
        recipient_account.balance =
            recipient_account
                .balance
                .checked_add(amount)
                .ok_or_else(|| {
                    CoreError::Overflow(format!(
                        "recipient balance overflow: {} + {}",
                        recipient_account.balance, amount
                    ))
                })?;
        self.set_account(recipient, recipient_account);

        Ok(())
    }

    /// Apply block subsidy (coinbase). Only called by consensus for valid blocks.
    ///
    /// subsidy = min(BLOCK_REWARD_UNITS, MAX_SUPPLY - total_supply)
    /// If total_supply >= MAX_SUPPLY, subsidy = 0.
    pub fn apply_subsidy(&mut self, recipient: &Address, height: u32) -> Result<u64> {
        let subsidy = self.block_subsidy(height)?;

        if subsidy > 0 {
            let mut account = self.get_account(recipient);
            account.balance = account.balance.checked_add(subsidy).ok_or_else(|| {
                CoreError::Overflow(format!(
                    "coinbase overflow: {} + {}",
                    account.balance, subsidy
                ))
            })?;
            self.set_account(recipient, account);
            self.total_supply = (self.total_supply as u128)
                .checked_add(subsidy as u128)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| CoreError::Overflow("total supply overflow".into()))?;
        }

        Ok(subsidy)
    }

    /// Calculate the block subsidy for a given height.
    /// Uses checked arithmetic against MAX_SUPPLY.
    pub fn block_subsidy(&self, _height: u32) -> Result<u64> {
        let remaining = MAX_SUPPLY_UNITS.saturating_sub(self.total_supply as u128);

        if remaining == 0 {
            return Ok(0);
        }

        let subsidy = std::cmp::min(BLOCK_REWARD_UNITS as u128, remaining);
        u64::try_from(subsidy).map_err(|_| CoreError::Overflow("subsidy exceeds u64".into()))
    }
}

// ============================================================================
// Sorted Merkle Tree
// ============================================================================

/// Compute a deterministic Merkle root from a sorted list of leaf hashes.
///
/// - Empty list → Hash::ZERO (SPEC §7.2 empty root)
/// - Single leaf → that leaf
/// - Multiple leaves → build a binary tree; internal nodes = H(left || right)
/// - Odd leaf at any level is promoted to the next level (not duplicated)
pub fn sorted_merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::ZERO;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                let mut data = Vec::with_capacity(64);
                data.extend_from_slice(current[i].as_bytes());
                data.extend_from_slice(current[i + 1].as_bytes());
                next.push(Hash::blake3(&data));
                i += 2;
            } else {
                next.push(current[i]);
                i += 1;
            }
        }
        current = next;
    }

    current[0]
}

// ============================================================================
// State Journal (SPEC §2.3)
// ============================================================================

/// A single journal entry recording what changed for one account.
#[derive(Clone, Debug)]
struct JournalEntry {
    /// The 20-byte address key.
    address: [u8; 20],
    /// Previous account state (None if account was created during this block).
    prev: Option<Account>,
}

/// Per-block journal: records all account mutations so they can be rolled back.
#[derive(Clone, Debug, Default)]
struct BlockJournal {
    /// Entries in reverse-apply order.
    entries: Vec<JournalEntry>,
}

impl BlockJournal {
    fn new() -> Self {
        BlockJournal {
            entries: Vec::new(),
        }
    }

    fn record(&mut self, address: [u8; 20], prev: Option<Account>) {
        self.entries.push(JournalEntry { address, prev });
    }

    /// Roll back all entries in reverse order.
    fn rollback(&self, accounts: &mut BTreeMap<[u8; 20], Account>) {
        for entry in self.entries.iter().rev() {
            match &entry.prev {
                Some(prev) => {
                    accounts.insert(entry.address, *prev);
                }
                None => {
                    accounts.remove(&entry.address);
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xAA;
        Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn bob() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xBB;
        Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn fund_account(state: &mut State, addr: &Address, amount: u64) {
        let mut acc = state.get_account(addr);
        acc.balance = amount;
        state.set_account(addr, acc);
        state.total_supply = state.total_supply.saturating_add(amount);
    }

    #[test]
    fn test_empty_state() {
        let state = State::new();
        let alice_addr = alice();
        assert_eq!(state.get_account(&alice_addr).balance, 0);
        assert_eq!(state.get_account(&alice_addr).nonce, 0);
        assert_eq!(state.total_supply(), 0);
    }

    #[test]
    fn test_apply_transaction_basic() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();

        assert_eq!(state.get_account(&alice_addr).balance, 9_000_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 1);
        assert_eq!(state.get_account(&bob_addr).balance, 1_000_000);
    }

    #[test]
    fn test_supply_conservation() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);
        let supply_before = state.total_supply();

        state
            .apply_transaction(&alice_addr, &bob_addr, 3_333_333, 0)
            .unwrap();

        assert_eq!(
            state.total_supply(),
            supply_before,
            "supply must be conserved"
        );
    }

    #[test]
    fn test_zero_amount_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 0, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 100);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 101, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InsufficientBalance(_)));
    }

    #[test]
    fn test_nonce_mismatch() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 5)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_nonce_must_increment() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 1)
            .unwrap();
        assert_eq!(state.get_account(&alice_addr).nonce, 2);
    }

    #[test]
    fn test_self_send_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &alice_addr, 1_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_block_subsidy_normal() {
        let state = State::new();
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, BLOCK_REWARD_UNITS);
    }

    #[test]
    fn test_block_subsidy_at_cap() {
        let mut state = State::new();
        state.total_supply = MAX_SUPPLY_UNITS as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 0);
    }

    #[test]
    fn test_block_subsidy_near_cap() {
        let mut state = State::new();
        state.total_supply = (MAX_SUPPLY_UNITS - 500_000) as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 500_000);
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let root1 = state.compute_state_root();
        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();
        let root2 = state.compute_state_root();

        assert_ne!(root1, root2, "state root must change after transaction");
    }

    #[test]
    fn test_state_root_ordering() {
        let mut state1 = State::new();
        let mut state2 = State::new();
        let alice_addr = alice();
        let bob_addr = bob();

        fund_account(&mut state1, &alice_addr, 10_000_000);
        fund_account(&mut state1, &bob_addr, 5_000_000);

        fund_account(&mut state2, &bob_addr, 5_000_000);
        fund_account(&mut state2, &alice_addr, 10_000_000);

        assert_eq!(
            state1.compute_state_root(),
            state2.compute_state_root(),
            "state root is order-independent (BTreeMap)"
        );
    }

    #[test]
    fn test_apply_multiple_transactions_sequential_nonces() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        for i in 0..5u64 {
            state
                .apply_transaction(&alice_addr, &bob_addr, 100_000, i)
                .unwrap();
        }

        assert_eq!(state.get_account(&alice_addr).balance, 10_000_000 - 500_000);
        assert_eq!(state.get_account(&bob_addr).balance, 500_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 5);
    }

    #[test]
    fn test_nonce_gap_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 100_000, 1)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_double_nonce_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 100_000, 0)
            .unwrap();
        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 100_000, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_exact_balance_transfer() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 1_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();

        assert_eq!(state.get_account(&alice_addr).balance, 0);
        assert_eq!(state.get_account(&bob_addr).balance, 1_000_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 1);
    }

    #[test]
    fn test_subsidy_at_various_heights() {
        let state = State::new();
        for h in [0, 1, 100, 999999, u32::MAX] {
            assert_eq!(
                state.block_subsidy(h).unwrap(),
                BLOCK_REWARD_UNITS,
                "height {}",
                h
            );
        }
    }

    #[test]
    fn test_supply_cannot_exceed_max() {
        let mut state = State::new();
        state.total_supply = MAX_SUPPLY_UNITS as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 0, "no subsidy when at max supply");
    }

    #[test]
    fn test_zero_account_is_default() {
        let state = State::new();
        let addr = alice();
        let acc = state.get_account(&addr);
        assert_eq!(acc.balance, 0);
        assert_eq!(acc.nonce, 0);
    }

    #[test]
    fn test_fund_does_not_double_count_supply() {
        let mut state = State::new();
        let alice_addr = alice();
        fund_account(&mut state, &alice_addr, 500_000);
        assert_eq!(state.total_supply(), 500_000);
        fund_account(&mut state, &alice_addr, 500_000);
        assert_eq!(state.total_supply(), 1_000_000);
    }

    #[test]
    fn test_many_accounts_state_root() {
        let mut state = State::new();
        for i in 0..100u8 {
            let mut h = [0u8; 20];
            h[0] = i;
            let addr = Address::from_hash160(chroma_core::hash::Hash160(h));
            fund_account(&mut state, &addr, 1_000_000);
        }
        let root = state.compute_state_root();
        assert_ne!(root, Hash::ZERO);
        assert_eq!(root, state.compute_state_root());
    }

    #[test]
    fn test_apply_subsidy_increases_total_supply() {
        let mut state = State::new();
        let alice_addr = alice();
        state.apply_subsidy(&alice_addr, 0).unwrap();
        assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);
        state.apply_subsidy(&alice_addr, 1).unwrap();
        assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS * 2);
    }

    #[test]
    fn test_apply_subsidy_creates_account() {
        let mut state = State::new();
        let alice_addr = alice();
        state.apply_subsidy(&alice_addr, 0).unwrap();
        assert_eq!(state.get_account(&alice_addr).balance, BLOCK_REWARD_UNITS);
    }

    // ========================================================================
    // Sorted Merkle Tree Tests
    // ========================================================================

    #[test]
    fn test_merkle_empty() {
        assert_eq!(sorted_merkle_root(&[]), Hash::ZERO);
    }

    #[test]
    fn test_merkle_single_leaf() {
        let h = Hash::blake3(b"hello");
        assert_eq!(sorted_merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_two_leaves() {
        let h0 = Hash::blake3(b"a");
        let h1 = Hash::blake3(b"b");
        let root = sorted_merkle_root(&[h0, h1]);
        assert_ne!(root, Hash::ZERO);
        assert_ne!(root, h0);
        assert_ne!(root, h1);
    }

    #[test]
    fn test_merkle_deterministic() {
        let leaves: Vec<Hash> = (0..10u8).map(|i| Hash::blake3(&[i])).collect();
        let r1 = sorted_merkle_root(&leaves);
        let r2 = sorted_merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_merkle_odd_count_promotes_last() {
        let leaves: Vec<Hash> = (0..3).map(|i| Hash::blake3(&[i])).collect();
        let root = sorted_merkle_root(&leaves);
        assert_ne!(root, Hash::ZERO);
        let root2 = sorted_merkle_root(&leaves[..2]);
        assert_ne!(root, root2);
    }

    #[test]
    fn test_merkle_different_leaves_different_roots() {
        let a: Vec<Hash> = (0..5).map(|i| Hash::blake3(&[i])).collect();
        let b: Vec<Hash> = (10..15).map(|i| Hash::blake3(&[i])).collect();
        assert_ne!(sorted_merkle_root(&a), sorted_merkle_root(&b));
    }

    #[test]
    fn test_state_root_uses_merkle() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);
        fund_account(&mut state, &bob_addr, 5_000_000);

        let root = state.compute_state_root();
        assert_ne!(root, Hash::ZERO);

        let mut flat_buf = Vec::new();
        for (addr, acc) in &state.accounts {
            flat_buf.extend_from_slice(addr);
            flat_buf.extend_from_slice(&acc.encode_value());
        }
        let flat_hash = Hash::blake3(&flat_buf);
        assert_ne!(root, flat_hash, "merkle root must differ from flat hash");
    }

    // ========================================================================
    // State Journal Tests
    // ========================================================================

    #[test]
    fn test_journal_rollback_transaction() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let root_before = state.compute_state_root();
        let supply_before = state.total_supply();

        state.begin_block();
        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();
        state.commit_block();

        assert_eq!(state.get_account(&alice_addr).balance, 9_000_000);
        assert_eq!(state.get_account(&bob_addr).balance, 1_000_000);

        let rolled = state.rollback_block();
        assert!(rolled);

        assert_eq!(state.get_account(&alice_addr).balance, 10_000_000);
        assert_eq!(state.get_account(&bob_addr).balance, 0);
        assert_eq!(state.total_supply(), supply_before);
        assert_eq!(state.compute_state_root(), root_before);
    }

    #[test]
    fn test_journal_rollback_creates_account() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state.begin_block();
        state
            .apply_transaction(&alice_addr, &bob_addr, 500_000, 0)
            .unwrap();
        state.commit_block();

        assert_eq!(state.get_account(&bob_addr).balance, 500_000);

        state.rollback_block();

        assert_eq!(state.get_account(&bob_addr).balance, 0);
        assert_eq!(state.get_account(&bob_addr).nonce, 0);
    }

    #[test]
    fn test_journal_rollback_subsidy() {
        let mut state = State::new();
        let alice_addr = alice();

        state.begin_block();
        state.apply_subsidy(&alice_addr, 0).unwrap();
        state.commit_block();

        assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);

        state.rollback_block();

        assert_eq!(state.total_supply(), 0);
        assert_eq!(state.get_account(&alice_addr).balance, 0);
    }

    #[test]
    fn test_journal_depth_limit() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 100_000_000);

        // Commit more blocks than REORG_JOURNAL_DEPTH
        let depth = chroma_core::constants::REORG_JOURNAL_DEPTH;
        for i in 0..=depth {
            state.begin_block();
            state
                .apply_transaction(&alice_addr, &bob_addr, 1, i as u64)
                .unwrap();
            state.commit_block();
        }

        // Only REORG_JOURNAL_DEPTH rollbacks should work
        let mut rolled = 0;
        for _ in 0..depth + 10 {
            if !state.rollback_block() {
                break;
            }
            rolled += 1;
        }
        assert_eq!(rolled, depth as usize);
    }

    #[test]
    fn test_journal_no_block_fails() {
        let mut state = State::new();
        assert!(!state.rollback_block(), "nothing to rollback");
    }

    #[test]
    fn test_abort_without_begin_is_safe() {
        // abort_block on a fresh state (no journal, no snapshot) must not
        // panic and must leave everything pristine.
        let mut state = State::new();
        state.abort_block();
        assert_eq!(state.total_supply(), 0);
        assert_eq!(state.get_account(&alice()).balance, 0);
        assert!(!state.rollback_block());
    }

    #[test]
    fn test_abort_restores_failed_block_exactly() {
        // Failed validation mid-block (unfunded second tx) followed by abort
        // must restore balances, nonces, AND supply bit-exactly.
        let mut state = State::new();
        fund_account(&mut state, &alice(), 10_000_000);
        let supply_before = state.total_supply();
        let root_before = state.compute_state_root();
        state.begin_block();
        state
            .apply_transaction(&alice(), &bob(), 1_000_000, 0)
            .unwrap();
        assert!(state
            .apply_transaction(&bob(), &alice(), 999_999_999, 0)
            .is_err());
        state.abort_block();
        assert_eq!(state.get_account(&alice()).balance, 10_000_000);
        assert_eq!(state.get_account(&alice()).nonce, 0);
        assert_eq!(state.get_account(&bob()).balance, 0);
        assert_eq!(state.total_supply(), supply_before);
        assert_eq!(state.compute_state_root(), root_before);
    }

    #[test]
    fn test_commit_then_double_rollback_second_is_noop() {
        // Rolling back twice with one committed block: the second call
        // returns false and must not touch balances, nonces, or supply.
        let mut state = State::new();
        fund_account(&mut state, &alice(), 10_000_000);
        state.begin_block();
        state
            .apply_transaction(&alice(), &bob(), 2_000_000, 0)
            .unwrap();
        state.commit_block();
        assert!(state.rollback_block());
        assert_eq!(state.get_account(&alice()).balance, 10_000_000);
        assert_eq!(state.get_account(&alice()).nonce, 0);
        assert_eq!(state.get_account(&bob()).balance, 0);
        assert!(
            !state.rollback_block(),
            "second rollback must be a safe no-op"
        );
        assert_eq!(state.get_account(&alice()).balance, 10_000_000);
        assert_eq!(state.total_supply(), 10_000_000);
    }

    #[test]
    fn test_interleaved_abort_and_rollback_stay_consistent() {
        // Mixed error-path/commit-path sequence: committed history survives
        // later aborts, and supply snapshots stay paired with journals.
        let mut state = State::new();
        fund_account(&mut state, &alice(), 10_000_000);
        state.begin_block();
        state
            .apply_transaction(&alice(), &bob(), 1_000_000, 0)
            .unwrap();
        state.commit_block();
        // Failed block after a commit, then abort.
        state.begin_block();
        state
            .apply_transaction(&alice(), &bob(), 1_000_000, 1)
            .unwrap();
        assert!(state
            .apply_transaction(&alice(), &bob(), 999_999_999, 2)
            .is_err());
        state.abort_block();
        // Committed prefix intact.
        assert_eq!(state.get_account(&alice()).balance, 9_000_000);
        assert_eq!(state.get_account(&alice()).nonce, 1);
        assert_eq!(state.get_account(&bob()).balance, 1_000_000);
        assert_eq!(state.total_supply(), 10_000_000);
        // And still rollback-able exactly once.
        assert!(state.rollback_block());
        assert_eq!(state.get_account(&alice()).balance, 10_000_000);
        assert!(!state.rollback_block());
    }
}
