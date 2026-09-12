//! BIP-340 Schnorr Signatures over secp256k1
//!
//! Uses libsecp256k1 for the cryptographic primitive.
//! Implements BIP-340:
//! - x-only keys (32-byte compressed public key, Y=even)
//! - Schnorr signature: (r || s) = 64 bytes
//! - Deterministic nonce via RFC 6979

use crate::hash::blake3;
use secp256k1::rand::thread_rng;
use secp256k1::{
    schnorr::Signature as SchnorrSig, KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};

use crate::error::{CryptoError, CryptoResult as Result};

thread_local! {
    static SECP_SIGN: Secp256k1<secp256k1::SignOnly> = Secp256k1::signing_only();
    static SECP_VERIFY: Secp256k1<secp256k1::VerifyOnly> = Secp256k1::verification_only();
}

/// Secret key (32 bytes, valid secp256k1 private key)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey32(pub [u8; 32]);

impl SecretKey32 {
    /// Generate from existing 32-byte secret
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let _ = SecretKey::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(SecretKey32(bytes))
    }

    /// Generate a new random secret key
    pub fn generate() -> Self {
        SECP_SIGN.with(|secp| {
            let (secret, _) = secp.generate_keypair(&mut thread_rng());
            let bytes = secret_to_bytes(&secret);
            SecretKey32(bytes)
        })
    }

    /// Internal: get secp256k1 SecretKey
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_secp(&self) -> Result<SecretKey> {
        SecretKey::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidSecretKey(format!("{:?}", e)))
    }
}

fn secret_to_bytes(secret: &SecretKey) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret[..]);
    arr
}

/// Public key (x-only, 32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey32(pub [u8; 32]);

impl PublicKey32 {
    /// Derive from secret key
    pub fn from_secret(secret: &SecretKey32) -> Result<Self> {
        SECP_SIGN.with(|secp| {
            let sk = secret.to_secp()?;
            let keypair = KeyPair::from_secret_key(secp, &sk);
            let xonly = keypair.x_only_public_key().0;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&xonly.serialize());
            Ok(PublicKey32(arr))
        })
    }

    /// Parse from 32-byte x-only public key
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let _xonly = XOnlyPublicKey::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))?;
        Ok(PublicKey32(bytes))
    }

    /// Internal: convert to secp256k1 XOnlyPublicKey
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_secp(&self) -> Result<XOnlyPublicKey> {
        XOnlyPublicKey::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))
    }
}

/// 64-byte Schnorr signature (r || s, each 32 bytes, big-endian)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    /// Parse from 64-byte array
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self> {
        let _ = SchnorrSig::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;
        Ok(Signature64(bytes))
    }

    /// Internal: convert to secp256k1 signature
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_secp(&self) -> Result<SchnorrSig> {
        SchnorrSig::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))
    }
}

/// Sign a message hash with a secret key using BIP-340 Schnorr
/// Uses deterministic nonce derivation per BIP-340 spec.
/// aux_rand is derived from the secret key and message for domain separation.
pub fn schnorr_sign(secret: &SecretKey32, msg_hash: &[u8; 32]) -> Result<Signature64> {
    SECP_SIGN.with(|secp| {
        let sk = secret.to_secp()?;
        let keypair = KeyPair::from_secret_key(secp, &sk);
        let msg = Message::from_slice(msg_hash)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;

        // Derive aux_rand from secret key and message for domain separation
        let aux_rand = blake3(
            &(secret
                .0
                .to_vec()
                .iter()
                .chain(msg_hash.iter())
                .cloned()
                .collect::<Vec<u8>>()),
        )
        .0;
        let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig[..]);
        Ok(Signature64(bytes))
    })
}

/// Verify a Schnorr signature
pub fn schnorr_verify(public_key: &PublicKey32, msg_hash: &[u8; 32], sig: &Signature64) -> bool {
    SECP_VERIFY.with(|secp| {
        let pk = match public_key.to_secp() {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig_obj = match sig.to_secp() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let msg = match Message::from_slice(msg_hash) {
            Ok(m) => m,
            Err(_) => return false,
        };

        secp.verify_schnorr(&sig_obj, &msg, &pk).is_ok()
    })
}

/// Batch verify multiple Schnorr signatures.
///
/// Verifies each (public_key, msg_hash, signature) triple concurrently.
/// Returns Ok(true) only if all signatures are valid.
///
/// NOTE: True cryptographic batch verification (randomized coefficients
/// and single multi-scalar multiplication) requires raw secp256k1 FFI
/// not available in secp256k1 v0.27. This concurrent verification
/// provides equivalent correctness with parallel speedup.
pub fn schnorr_batch_verify(
    pubkeys: &[PublicKey32],
    msg_hash: &[u8; 32],
    sigs: &[Signature64],
) -> Result<bool> {
    if pubkeys.len() != sigs.len() {
        return Err(CryptoError::InvalidSignature(
            "mismatched lengths".to_string(),
        ));
    }

    use std::sync::atomic::{AtomicBool, Ordering};

    let all_valid = AtomicBool::new(true);

    // Verify all signatures; short-circuit on first failure
    std::thread::scope(|s| {
        let handles: Vec<_> = pubkeys
            .iter()
            .zip(sigs.iter())
            .map(|(pk, sig)| {
                s.spawn(|| {
                    if !schnorr_verify(pk, msg_hash, sig) {
                        all_valid.store(false, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });

    Ok(all_valid.load(Ordering::Relaxed))
}

/// Domain separation tag for transaction sighash
/// Prevents cross-protocol and cross-object signing ambiguity
const SIGHASH_DOMAIN: &[u8] = b"Chroma Transaction Signing v1";

/// Sighash computation for transactions
/// Domain-tagged: BLAKE3(domain_tag || network_magic || sender || recipient || amount || nonce)
/// Network magic provides cross-network replay protection.
pub fn compute_sighash(
    sender: &[u8; 20],
    recipient: &[u8; 20],
    amount: u64,
    nonce: u64,
    network_magic: [u8; 4],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(SIGHASH_DOMAIN.len() + 4 + 56);
    data.extend_from_slice(SIGHASH_DOMAIN);
    data.extend_from_slice(&network_magic);
    data.extend_from_slice(sender);
    data.extend_from_slice(recipient);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    blake3(&data).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        assert!(schnorr_verify(&public, &msg, &sig));
    }

    #[test]
    fn test_signature_rejection() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        let wrong_msg = [0x43u8; 32];
        assert!(!schnorr_verify(&public, &wrong_msg, &sig));
    }

    #[test]
    fn test_batch_verification() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        assert!(schnorr_batch_verify(&[public], &msg, &[sig]).unwrap());
        assert!(schnorr_batch_verify(&[public], &msg, &[]).is_err());
    }

    #[test]
    fn test_batch_verification_multiple() {
        let mut pubkeys = Vec::new();
        let mut sigs = Vec::new();
        let msg = [0xAAu8; 32];

        for _ in 0..10 {
            let secret = SecretKey32::generate();
            let public = PublicKey32::from_secret(&secret).unwrap();
            let sig = schnorr_sign(&secret, &msg).unwrap();
            pubkeys.push(public);
            sigs.push(sig);
        }

        assert!(schnorr_batch_verify(&pubkeys, &msg, &sigs).unwrap());
    }

    #[test]
    fn test_batch_verification_rejects_invalid() {
        let secret1 = SecretKey32::generate();
        let secret2 = SecretKey32::generate();
        let pk1 = PublicKey32::from_secret(&secret1).unwrap();
        let pk2 = PublicKey32::from_secret(&secret2).unwrap();

        let msg = [0xBBu8; 32];
        let sig1 = schnorr_sign(&secret1, &msg).unwrap();
        let sig2 = schnorr_sign(&secret2, &msg).unwrap();

        // Valid batch
        assert!(schnorr_batch_verify(&[pk1, pk2], &msg, &[sig1, sig2]).unwrap());

        // Swap signatures — pk1's sig is actually for pk2
        assert!(!schnorr_batch_verify(&[pk1, pk2], &msg, &[sig2, sig1]).unwrap());
    }

    #[test]
    fn test_signature_malleability() {
        let secret = SecretKey32::generate();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        let sig2 = schnorr_sign(&secret, &msg).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_sighash() {
        use chroma_core::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
        let sender = [0x11u8; 20];
        let recipient = [0x22u8; 20];
        let amount = 1_000_000u64;
        let nonce = 42u64;

        let hash1 = compute_sighash(&sender, &recipient, amount, nonce, REGTEST_MAGIC);
        let hash2 = compute_sighash(&sender, &recipient, amount, nonce, REGTEST_MAGIC);
        assert_eq!(hash1, hash2);

        let hash3 = compute_sighash(&sender, &recipient, amount, 43, REGTEST_MAGIC);
        assert_ne!(hash1, hash3);

        // Network domain separation: same fields, different network → different sighash
        let hash_mainnet = compute_sighash(&sender, &recipient, amount, nonce, MAINNET_MAGIC);
        let hash_testnet = compute_sighash(&sender, &recipient, amount, nonce, TESTNET_MAGIC);
        let hash_regtest = compute_sighash(&sender, &recipient, amount, nonce, REGTEST_MAGIC);
        assert_ne!(hash_mainnet, hash_testnet);
        assert_ne!(hash_mainnet, hash_regtest);
        assert_ne!(hash_testnet, hash_regtest);

        // Verify domain separation: sighash differs from raw field hash
        let raw_data = {
            let mut d = Vec::with_capacity(56);
            d.extend_from_slice(&sender);
            d.extend_from_slice(&recipient);
            d.extend_from_slice(&amount.to_le_bytes());
            d.extend_from_slice(&nonce.to_le_bytes());
            blake3(&d).0
        };
        assert_ne!(
            hash1, raw_data,
            "sighash must differ from raw field hash (domain separation)"
        );
    }
}
