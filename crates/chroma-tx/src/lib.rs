//! Chroma Transaction
//!
//! Canonical transaction type with deterministic serialization.
//!
//! Transaction carries the sender's public key (32 bytes) for Schnorr
//! signature verification. The sender address is derived as
//! Hash160(sender_pubkey).
//!
//! Canonical wire layout (little-endian):
//!   sender_pubkey: 32 bytes (x-only BIP-340 public key)
//!   recipient:     20 bytes (raw Hash160 address)
//!   amount:        8 bytes (u64 LE)
//!   nonce:         8 bytes (u64 LE)
//!   signature:     64 bytes (BIP-340 Schnorr, r||s)
//!
//! Total: 132 bytes fixed.

use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash160;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{Address, Amount, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{
    compute_sighash, schnorr_sign, schnorr_verify, PublicKey32, SecretKey32, Signature64,
};

// ============================================================================
// Transaction
// ============================================================================

/// A signed transfer of CHR from sender to recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Sender's x-only public key (32 bytes). Address = Hash160(this).
    pub sender_pubkey: PublicKey32,
    /// Recipient address (20-byte Hash160)
    pub recipient: Address,
    /// Amount in atomic units (1 CHR = 1,000,000 units)
    pub amount: Amount,
    /// Sender's current nonce (must equal sender's account nonce)
    pub nonce: Nonce,
    /// BIP-340 Schnorr signature over sighash
    pub signature: Signature64,
}

impl std::fmt::Debug for Transaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transaction")
            .field("sender", &hex::encode(self.sender_pubkey.0))
            .field("recipient", &self.recipient)
            .field("amount", &self.amount)
            .field("nonce", &self.nonce)
            .field("signature", &hex::encode(self.signature.0))
            .finish()
    }
}

/// Unsigned transaction fields used for signing/verification preimage.
#[derive(Clone, Debug)]
pub struct TxPreimage {
    pub sender_address: Address,
    pub recipient: Address,
    pub amount: Amount,
    pub nonce: Nonce,
    pub network_magic: [u8; 4],
}

impl TxPreimage {
    /// Compute the domain-separated sighash for this transaction preimage.
    pub fn sighash(&self) -> [u8; 32] {
        compute_sighash(
            self.sender_address.as_hash160().as_bytes(),
            self.recipient.as_hash160().as_bytes(),
            self.amount.0,
            self.nonce.0,
            self.network_magic,
        )
    }
}

impl Transaction {
    /// Canonical wire size (fixed: 132 bytes).
    pub const SERIALIZED_SIZE: usize = 32 + 20 + 8 + 8 + 64;

    /// Derive sender address from public key.
    pub fn sender_address(&self) -> Address {
        let h = hash160(&self.sender_pubkey.0);
        Address::from_hash160(Hash160(h))
    }

    /// Build the preimage for sighash computation.
    pub fn preimage(&self, network_magic: [u8; 4]) -> TxPreimage {
        TxPreimage {
            sender_address: self.sender_address(),
            recipient: self.recipient,
            amount: self.amount,
            nonce: self.nonce,
            network_magic,
        }
    }

    /// Verify signature using the embedded sender public key.
    pub fn verify_signature(&self, network_magic: [u8; 4]) -> bool {
        let sighash = self.preimage(network_magic).sighash();
        schnorr_verify(&self.sender_pubkey, &sighash, &self.signature)
    }
}

// ============================================================================
// Transaction Builder
// ============================================================================

/// Create and sign a transaction. Returns the transaction and the sender's public key.
pub fn create_transaction(
    secret: &SecretKey32,
    sender: Address,
    recipient: Address,
    amount: Amount,
    nonce: Nonce,
    network_magic: [u8; 4],
) -> Result<Transaction> {
    if amount == Amount::ZERO {
        return Err(CoreError::InvalidTransaction(
            "amount must be greater than zero".to_string(),
        ));
    }
    if sender == recipient {
        return Err(CoreError::InvalidTransaction(
            "sender and recipient must differ".to_string(),
        ));
    }

    let pubkey = PublicKey32::from_secret(secret)
        .map_err(|e| CoreError::InvalidSignature(format!("key derivation failed: {}", e)))?;

    let derived = {
        let h = hash160(&pubkey.0);
        Address::from_hash160(Hash160(h))
    };
    if derived != sender {
        return Err(CoreError::InvalidSignature(
            "sender address does not match secret key".to_string(),
        ));
    }

    let preimage = TxPreimage {
        sender_address: sender,
        recipient,
        amount,
        nonce,
        network_magic,
    };
    let sighash = preimage.sighash();
    let signature = schnorr_sign(secret, &sighash)
        .map_err(|e| CoreError::InvalidSignature(format!("signing failed: {}", e)))?;

    Ok(Transaction {
        sender_pubkey: pubkey,
        recipient,
        amount,
        nonce,
        signature,
    })
}

// ============================================================================
// Canonical Serialization
// ============================================================================

impl CanonicalEncode for Transaction {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SERIALIZED_SIZE);
        buf.extend_from_slice(&self.sender_pubkey.0); // 32
        buf.extend_from_slice(self.recipient.as_hash160().as_bytes()); // 20
        buf.extend_from_slice(&self.amount.0.to_le_bytes()); // 8
        buf.extend_from_slice(&self.nonce.0.to_le_bytes()); // 8
        buf.extend_from_slice(&self.signature.0); // 64
        buf
    }
}

impl CanonicalDecode for Transaction {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "transaction: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }

        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&data[0..32]);
        let sender_pubkey = PublicKey32(pubkey_bytes);

        let mut recipient_bytes = [0u8; 20];
        recipient_bytes.copy_from_slice(&data[32..52]);

        let amount = u64::from_le_bytes([
            data[52], data[53], data[54], data[55], data[56], data[57], data[58], data[59],
        ]);
        let nonce = u64::from_le_bytes([
            data[60], data[61], data[62], data[63], data[64], data[65], data[66], data[67],
        ]);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&data[68..132]);

        let signature = Signature64(sig_bytes);

        Ok(Transaction {
            sender_pubkey,
            recipient: Address::from_hash160(Hash160(recipient_bytes)),
            amount: Amount(amount),
            nonce: Nonce(nonce),
            signature,
        })
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < Self::SERIALIZED_SIZE {
            return Err(CoreError::Serialization(format!(
                "transaction: expected {} bytes, got {}",
                Self::SERIALIZED_SIZE,
                data.len()
            )));
        }
        let tx = Transaction::decode(&data[..Self::SERIALIZED_SIZE])?;
        Ok((tx, Self::SERIALIZED_SIZE))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};

    fn alice_secret() -> SecretKey32 {
        SecretKey32::from_bytes([0xAA; 32]).unwrap()
    }

    fn bob_address() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xBB;
        Address::from_hash160(Hash160(h))
    }

    fn alice_address() -> Address {
        let secret = alice_secret();
        let pubkey = PublicKey32::from_secret(&secret).unwrap();
        let h = hash160(&pubkey.0);
        Address::from_hash160(Hash160(h))
    }

    #[test]
    fn test_create_and_verify_transaction() {
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

        assert!(tx.verify_signature(REGTEST_MAGIC));
        assert_eq!(tx.sender_address(), alice_address());
    }

    #[test]
    fn test_signature_fails_with_tampered_amount() {
        let secret = alice_secret();
        let mut tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        tx.amount = Amount(999_999);
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_signature_fails_with_tampered_nonce() {
        let secret = alice_secret();
        let mut tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        tx.nonce = Nonce(1);
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_signature_fails_with_tampered_recipient() {
        let secret = alice_secret();
        let mut tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        let mut h = [0u8; 20];
        h[0] = 0xCC;
        tx.recipient = Address::from_hash160(Hash160(h));
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_signature_fails_with_wrong_key() {
        let secret = alice_secret();
        let mut tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();

        let wrong_secret = SecretKey32::from_bytes([0xBB; 32]).unwrap();
        let wrong_pubkey = PublicKey32::from_secret(&wrong_secret).unwrap();
        tx.sender_pubkey = wrong_pubkey;
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_zero_amount_rejected() {
        let secret = alice_secret();
        let err = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(0),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_self_send_rejected() {
        let secret = alice_secret();
        let addr = alice_address();
        let err = create_transaction(
            &secret,
            addr,
            addr,
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_canonical_serialization_roundtrip() {
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

        let encoded = tx.encode();
        assert_eq!(encoded.len(), Transaction::SERIALIZED_SIZE);

        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_serialization_is_deterministic() {
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

        let enc1 = tx.encode();
        let enc2 = tx.encode();
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn test_different_nonces_different_encoding() {
        let secret = alice_secret();
        let tx0 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let tx1 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(1),
            REGTEST_MAGIC,
        )
        .unwrap();

        assert_ne!(tx0.encode(), tx1.encode());
        assert_ne!(tx0.signature.0, tx1.signature.0);
    }

    #[test]
    fn test_decode_rejects_truncated() {
        assert!(Transaction::decode(&[0u8; 50]).is_err());
        assert!(Transaction::decode(&[]).is_err());
    }

    #[test]
    fn test_wrong_sender_address_rejected() {
        let secret = alice_secret();
        let wrong_sender = bob_address();
        let err = create_transaction(
            &secret,
            wrong_sender,
            alice_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidSignature(_)));
    }

    #[test]
    fn test_signature_deterministic() {
        let secret = alice_secret();
        let tx1 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let tx2 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        assert_eq!(
            tx1.signature, tx2.signature,
            "same inputs → same signature (deterministic)"
        );
    }

    #[test]
    fn test_different_amounts_different_sighash() {
        let secret = alice_secret();
        let tx1 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let tx2 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(2_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        assert_ne!(tx1.signature.0, tx2.signature.0);
    }

    #[test]
    fn test_different_recipients_different_sighash() {
        let secret = alice_secret();
        let mut h3 = [0u8; 20];
        h3[0] = 0xCC;
        let charlie = Address::from_hash160(Hash160(h3));

        let tx1 = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let tx2 = create_transaction(
            &secret,
            alice_address(),
            charlie,
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        assert_ne!(tx1.signature.0, tx2.signature.0);
    }

    #[test]
    fn test_transaction_sender_address_consistent() {
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
        assert_eq!(tx.sender_address(), alice_address());
    }

    #[test]
    fn test_preimage_sighash_matches() {
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
        let preimage = tx.preimage(REGTEST_MAGIC);
        let sighash = preimage.sighash();
        assert!(schnorr_verify(&tx.sender_pubkey, &sighash, &tx.signature));
    }

    #[test]
    fn test_max_amount_transaction() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(u64::MAX),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        assert!(tx.verify_signature(REGTEST_MAGIC));
        assert_eq!(tx.amount.0, u64::MAX);
    }

    #[test]
    fn test_different_keys_different_pubkeys() {
        let secret1 = SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let secret2 = SecretKey32::from_bytes([0xBB; 32]).unwrap();
        let pk1 = PublicKey32::from_secret(&secret1).unwrap();
        let pk2 = PublicKey32::from_secret(&secret2).unwrap();
        assert_ne!(pk1.0, pk2.0);
    }

    #[test]
    fn test_decode_exact_size() {
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
        let encoded = tx.encode();
        assert_eq!(encoded.len(), Transaction::SERIALIZED_SIZE);
        assert_eq!(encoded.len(), 132);
    }

    #[test]
    fn test_decode_rejects_too_large() {
        let data = vec![0u8; 200];
        assert!(Transaction::decode(&data).is_err());
    }

    #[test]
    fn test_decode_rejects_empty() {
        assert!(Transaction::decode(&[]).is_err());
    }

    #[test]
    fn test_decode_rejects_131_bytes() {
        assert!(Transaction::decode(&[0u8; 131]).is_err());
    }

    #[test]
    fn test_amount_zero_rejected() {
        let secret = alice_secret();
        let err = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(0),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_various_nonces() {
        let secret = alice_secret();
        for nonce_val in [0u64, 1, 42, 100, u64::MAX - 1] {
            let tx = create_transaction(
                &secret,
                alice_address(),
                bob_address(),
                Amount(1),
                Nonce(nonce_val),
                REGTEST_MAGIC,
            )
            .unwrap();
            assert!(
                tx.verify_signature(REGTEST_MAGIC),
                "nonce {} should produce valid signature",
                nonce_val
            );
        }
    }

    #[test]
    fn test_decode_rejects_trailing_data() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(500_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let mut encoded = tx.encode();
        encoded.push(0xFF);
        assert!(
            Transaction::decode(&encoded).is_err(),
            "should reject trailing byte"
        );
        encoded.push(0x00);
        assert!(
            Transaction::decode(&encoded).is_err(),
            "should reject 2 trailing bytes"
        );
    }

    #[test]
    fn test_decode_rejects_exact_truncation() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(500_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let encoded = tx.encode();
        assert!(Transaction::decode(&encoded[..131]).is_err());
        let mut extended = encoded;
        extended.push(0x00);
        assert!(Transaction::decode(&extended).is_err());
    }

    #[test]
    fn test_decode_partial_allows_trailing() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(500_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        let mut encoded = tx.encode();
        encoded.push(0xFF);
        let (decoded, consumed) = Transaction::decode_partial(&encoded).unwrap();
        assert_eq!(consumed, Transaction::SERIALIZED_SIZE);
        assert_eq!(decoded.amount, tx.amount);
    }

    #[test]
    fn test_valid_normal_tx_encode_decode_verify() {
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

        let encoded = tx.encode();
        assert_eq!(encoded.len(), 132);

        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(tx, decoded);
        assert!(decoded.verify_signature(REGTEST_MAGIC));
        assert_eq!(decoded.sender_address(), alice_address());
    }

    #[test]
    fn test_malformed_normal_tx_decode_rejects_invalid_pubkey() {
        let mut data = [0u8; 132];
        data[0] = 0xFF;
        let tx = Transaction::decode(&data).unwrap();
        assert!(
            !tx.verify_signature(REGTEST_MAGIC),
            "decoded tx with invalid pubkey must fail verify_signature"
        );
    }

    #[test]
    fn test_malformed_normal_tx_decode_rejects_invalid_signature() {
        let mut data = [0u8; 132];
        data[68] = 0xFF;
        let tx = Transaction::decode(&data).unwrap();
        assert!(
            !tx.verify_signature(REGTEST_MAGIC),
            "decoded tx with invalid signature must fail verify_signature"
        );
    }

    #[test]
    fn test_coinbase_zero_pubkey_sig_decodes() {
        let coinbase = Transaction {
            sender_pubkey: PublicKey32([0u8; 32]),
            recipient: bob_address(),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: Signature64([0u8; 64]),
        };
        let encoded = coinbase.encode();
        assert_eq!(encoded.len(), 132);

        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(decoded.sender_pubkey.0, [0u8; 32]);
        assert_eq!(decoded.signature.0, [0u8; 64]);
        assert_eq!(decoded.amount, Amount(1_000_000));
    }

    #[test]
    fn test_network_replay_mainnet_sign_mainnet_verify_ok() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            MAINNET_MAGIC,
        )
        .unwrap();
        assert!(tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_network_replay_mainnet_sign_testnet_verify_fails() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            MAINNET_MAGIC,
        )
        .unwrap();
        assert!(!tx.verify_signature(TESTNET_MAGIC));
    }

    #[test]
    fn test_network_replay_mainnet_sign_regtest_verify_fails() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            MAINNET_MAGIC,
        )
        .unwrap();
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_network_replay_testnet_sign_mainnet_verify_fails() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            TESTNET_MAGIC,
        )
        .unwrap();
        assert!(tx.verify_signature(TESTNET_MAGIC));
        assert!(!tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_network_replay_testnet_sign_regtest_verify_fails() {
        let secret = alice_secret();
        let tx = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            TESTNET_MAGIC,
        )
        .unwrap();
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_network_replay_regtest_sign_mainnet_verify_fails() {
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
        assert!(tx.verify_signature(REGTEST_MAGIC));
        assert!(!tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_network_replay_regtest_sign_testnet_verify_fails() {
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
        assert!(!tx.verify_signature(TESTNET_MAGIC));
    }

    #[test]
    fn test_network_magic_not_in_canonical_encoding() {
        let secret = alice_secret();
        let tx_main = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            MAINNET_MAGIC,
        )
        .unwrap();
        let tx_reg = create_transaction(
            &secret,
            alice_address(),
            bob_address(),
            Amount(1_000_000),
            Nonce(0),
            REGTEST_MAGIC,
        )
        .unwrap();
        // Canonical encoding is always 132 bytes regardless of network.
        assert_eq!(tx_main.encode().len(), 132);
        assert_eq!(tx_reg.encode().len(), 132);
        // First 68 bytes (pubkey 32 + recipient 20 + amount 8 + nonce 8) are
        // identical across networks; only the 64-byte signature differs.
        // This proves network_magic is signature domain separation only and
        // is not mixed into the canonical transaction body itself.
        assert_eq!(tx_main.encode()[..68], tx_reg.encode()[..68]);
        assert_ne!(tx_main.encode(), tx_reg.encode());
        assert_ne!(tx_main.signature.0, tx_reg.signature.0);
        // Txid commits to the full encoding (including signature), so txids
        // differ per network even though the unsigned body is identical.
        let id_main = chroma_core::hash::Hash::blake3(&tx_main.encode());
        let id_reg = chroma_core::hash::Hash::blake3(&tx_reg.encode());
        assert_ne!(id_main, id_reg);
    }

    #[test]
    fn test_coinbase_never_verifies_on_any_network() {
        let coinbase = Transaction {
            sender_pubkey: PublicKey32([0u8; 32]),
            recipient: bob_address(),
            amount: Amount(1_000_000),
            nonce: Nonce(0),
            signature: Signature64([0u8; 64]),
        };
        // Coinbase sentinel must never pass signature verification, on any
        // network. It must not enter the sighash path as a valid signature.
        assert!(!coinbase.verify_signature(MAINNET_MAGIC));
        assert!(!coinbase.verify_signature(TESTNET_MAGIC));
        assert!(!coinbase.verify_signature(REGTEST_MAGIC));
    }
}
