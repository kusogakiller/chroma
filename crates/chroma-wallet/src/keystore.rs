use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use chroma_core::error::{CoreError, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use subtle::ConstantTimeEq;

use crate::Wallet;

const ARGON2_M_COST: u32 = 65536;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeystoreCrypto {
    pub cipher: String,
    pub cipherparams: CipherParams,
    pub ciphertext: String,
    pub kdf: String,
    pub kdfparams: KdfParams,
    pub mac: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CipherParams {
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeystoreEntry {
    pub address: String,
    pub address_hash160: String,
    pub crypto: KeystoreCrypto,
    pub version: u32,
}

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32)).unwrap(),
    )
    .hash_password_into(password.as_bytes(), salt, &mut key)
    .expect("argon2 hash failed");
    key
}

fn compute_mac(ciphertext: &[u8], derived_key: &[u8; 32]) -> [u8; 32] {
    let mut mac_input = Vec::with_capacity(ciphertext.len() + 32);
    mac_input.extend_from_slice(ciphertext);
    mac_input.extend_from_slice(derived_key);
    *blake3::hash(&mac_input).as_bytes()
}

pub fn encrypt_key(
    password: &str,
    secret: &[u8; 32],
    address: &str,
    hash160: &[u8; 20],
) -> KeystoreEntry {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let derived_key = derive_key(password, &salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&derived_key).expect("invalid key length");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, secret.as_ref())
        .expect("encryption failed");

    let mac = compute_mac(&ciphertext, &derived_key);

    KeystoreEntry {
        address: address.to_string(),
        address_hash160: hex::encode(hash160),
        crypto: KeystoreCrypto {
            cipher: "aes-256-gcm".to_string(),
            cipherparams: CipherParams {
                nonce: hex::encode(nonce_bytes),
            },
            ciphertext: hex::encode(&ciphertext),
            kdf: "argon2id".to_string(),
            kdfparams: KdfParams {
                m: ARGON2_M_COST,
                t: ARGON2_T_COST,
                p: ARGON2_P_COST,
                salt: hex::encode(salt),
            },
            mac: hex::encode(mac),
        },
        version: 1,
    }
}

pub fn decrypt_key(password: &str, entry: &KeystoreEntry) -> Result<[u8; 32]> {
    let salt = hex::decode(&entry.crypto.kdfparams.salt)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid salt hex: {}", e)))?;
    let nonce_bytes = hex::decode(&entry.crypto.cipherparams.nonce)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid nonce hex: {}", e)))?;
    let ciphertext = hex::decode(&entry.crypto.ciphertext)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid ciphertext hex: {}", e)))?;
    let expected_mac = hex::decode(&entry.crypto.mac)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid mac hex: {}", e)))?;

    let derived_key = derive_key(password, &salt);

    let computed_mac = compute_mac(&ciphertext, &derived_key);
    if computed_mac.ct_eq(expected_mac.as_slice()).into() {
        // MAC matches, proceed to decryption
    } else {
        return Err(CoreError::InvalidSignature(
            "password incorrect".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| CoreError::InvalidSignature(format!("cipher init failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| CoreError::InvalidSignature(format!("decryption failed: {}", e)))?;

    let mut key = [0u8; 32];
    if plaintext.len() != 32 {
        return Err(CoreError::InvalidSignature(
            "unexpected key length".to_string(),
        ));
    }
    key.copy_from_slice(&plaintext);
    Ok(key)
}

pub fn save_keystore(path: &Path, entry: &KeystoreEntry) -> Result<()> {
    let json = serde_json::to_string_pretty(entry)
        .map_err(|e| CoreError::InvalidSignature(format!("serialization failed: {}", e)))?;
    std::fs::write(path, &json)
        .map_err(|e| CoreError::InvalidSignature(format!("failed to write keystore: {}", e)))?;

    // Set restrictive file permissions on Unix systems (0600 = owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            // Non-fatal: warn but don't fail
            tracing::warn!("Failed to set keystore file permissions: {}", e);
        }
    }

    Ok(())
}

pub fn load_keystore(path: &Path) -> Result<KeystoreEntry> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| CoreError::InvalidSignature(format!("failed to read keystore: {}", e)))?;
    serde_json::from_str(&data)
        .map_err(|e| CoreError::InvalidSignature(format!("failed to parse keystore: {}", e)))
}

impl Wallet {
    pub fn save(&self, path: &Path, password: &str) -> Result<()> {
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(self.secret_key())
            .map_err(|e| CoreError::InvalidSignature(format!("key derivation failed: {}", e)))?;
        let h = chroma_crypto::hash::hash160(&pubkey.0);
        let entry = encrypt_key(
            password,
            &self.secret_bytes(),
            &self.address().to_string(),
            &h,
        );
        save_keystore(path, &entry)
    }

    pub fn load(path: &Path, password: &str, name: &str) -> Result<Self> {
        let entry = load_keystore(path)?;
        let key_bytes = decrypt_key(password, &entry)?;
        let secret_key = chroma_crypto::schnorr::SecretKey32::from_bytes(key_bytes)
            .map_err(|e| CoreError::InvalidSignature(format!("invalid key: {}", e)))?;
        Wallet::from_secret_key(name, secret_key)
    }

    pub fn change_password(
        &self,
        path: &Path,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let entry = load_keystore(path)?;
        let key_bytes = decrypt_key(old_password, &entry)?;
        // Verify old password is correct by checking key matches
        let result = self.save(path, new_password);
        // Zeroize the key bytes
        use zeroize::Zeroize;
        let mut key = key_bytes;
        key.zeroize();
        result
    }

    pub fn with_secret<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&[u8; 32]) -> R,
    {
        f(&self.secret_key.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> Wallet {
        Wallet::generate("test_keystore")
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wallet = test_wallet();
        let secret = wallet.secret_bytes();
        let entry = encrypt_key(
            "password123",
            &secret,
            &wallet.address().to_string(),
            &[0xDE; 20],
        );
        let recovered = decrypt_key("password123", &entry).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_wrong_password_fails() {
        let wallet = test_wallet();
        let secret = wallet.secret_bytes();
        let entry = encrypt_key(
            "correct",
            &secret,
            &wallet.address().to_string(),
            &[0xDE; 20],
        );
        let result = decrypt_key("wrong", &entry);
        assert!(result.is_err());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let wallet = test_wallet();
        let dir = std::env::temp_dir().join("chroma_keystore_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        wallet.save(&path, "mypassword").unwrap();
        let loaded = Wallet::load(&path, "mypassword", "loaded").unwrap();
        assert_eq!(wallet.address(), loaded.address());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_change_password() {
        let wallet = test_wallet();
        let dir = std::env::temp_dir().join("chroma_keystore_chgpass");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test.json");

        wallet.save(&path, "old_pass").unwrap();
        wallet
            .change_password(&path, "old_pass", "new_pass")
            .unwrap();

        let loaded = Wallet::load(&path, "new_pass", "t").unwrap();
        assert_eq!(wallet.address(), loaded.address());
        assert!(Wallet::load(&path, "old_pass", "t").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_different_salts_produce_different_ciphertext() {
        let wallet = test_wallet();
        let secret = wallet.secret_bytes();
        let e1 = encrypt_key("pass", &secret, &wallet.address().to_string(), &[0xAA; 20]);
        let e2 = encrypt_key("pass", &secret, &wallet.address().to_string(), &[0xAA; 20]);
        assert_ne!(e1.crypto.ciphertext, e2.crypto.ciphertext);
        assert_ne!(e1.crypto.kdfparams.salt, e2.crypto.kdfparams.salt);
    }

    #[test]
    fn test_keystore_json_format() {
        let wallet = test_wallet();
        let secret = wallet.secret_bytes();
        let entry = encrypt_key("test", &secret, &wallet.address().to_string(), &[0xBB; 20]);
        let json = serde_json::to_string_pretty(&entry).unwrap();
        assert!(json.contains("aes-256-gcm"));
        assert!(json.contains("argon2id"));
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"address\":"));
    }
}
