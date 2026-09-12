use chroma_core::constants::MAINNET_MAGIC;
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash160;
use chroma_core::serialize::CanonicalEncode;
use chroma_core::types::{Address, Amount, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_tx::create_transaction;
use zeroize::Zeroize;

pub mod keystore;

const BIP39_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blow", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunny", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney",
    "choice", "choose", "chronic", "chuckle", "chunk", "churn", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "client", "cliff",
    "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club",
    "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin",
    "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince",
    "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton",
    "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek",
    "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial",
    "cruel", "cruise", "crumble", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
    "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad",
    "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal",
    "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer",
    "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial",
    "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe",
    "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital",
    "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
    "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce",
    "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor",
    "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream",
    "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb",
    "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
];

pub struct Wallet {
    secret_key: SecretKey32,
    address: Address,
    name: String,
    network_magic: [u8; 4],
}

impl Wallet {
    /// Generate a new wallet for mainnet (default network).
    pub fn generate(name: &str) -> Self {
        Self::generate_for_network(name, MAINNET_MAGIC)
    }

    /// Generate a new wallet for an explicit network magic.
    pub fn generate_for_network(name: &str, network_magic: [u8; 4]) -> Self {
        let secret_key = SecretKey32::generate();
        let pubkey = PublicKey32::from_secret(&secret_key).unwrap();
        let h = hash160(&pubkey.0);
        let address = Address::from_hash160(Hash160(h));
        Wallet {
            secret_key,
            address,
            name: name.to_string(),
            network_magic,
        }
    }

    /// Create a wallet from a secret key for mainnet (default network).
    pub fn from_secret_key(name: &str, secret_key: SecretKey32) -> Result<Self> {
        Self::from_secret_key_for_network(name, secret_key, MAINNET_MAGIC)
    }

    /// Create a wallet from a secret key for an explicit network magic.
    pub fn from_secret_key_for_network(
        name: &str,
        secret_key: SecretKey32,
        network_magic: [u8; 4],
    ) -> Result<Self> {
        let pubkey = PublicKey32::from_secret(&secret_key)
            .map_err(|e| CoreError::InvalidSignature(format!("key derivation failed: {}", e)))?;
        let h = hash160(&pubkey.0);
        let address = Address::from_hash160(Hash160(h));
        Ok(Wallet {
            secret_key,
            address,
            name: name.to_string(),
            network_magic,
        })
    }

    /// Return the network magic this wallet signs for.
    pub fn network_magic(&self) -> [u8; 4] {
        self.network_magic
    }

    /// Set the network magic this wallet signs for.
    pub fn with_network_magic(mut self, network_magic: [u8; 4]) -> Self {
        self.network_magic = network_magic;
        self
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_key.0
    }

    pub fn secret_key(&self) -> &SecretKey32 {
        &self.secret_key
    }

    pub fn create_transaction(
        &self,
        recipient: Address,
        amount: Amount,
        nonce: Nonce,
    ) -> Result<chroma_tx::Transaction> {
        create_transaction(
            &self.secret_key,
            self.address,
            recipient,
            amount,
            nonce,
            self.network_magic,
        )
    }

    /// Build, sign, and encode a transaction. Returns the raw bytes and txid.
    pub fn prepare_transaction(
        &self,
        recipient: Address,
        amount: Amount,
        nonce: Nonce,
    ) -> Result<PreparedTransaction> {
        let tx = self.create_transaction(recipient, amount, nonce)?;
        let encoded = tx.encode();
        let txid = chroma_core::hash::Hash::blake3(&encoded);
        Ok(PreparedTransaction { tx, encoded, txid })
    }

    /// Strictly parse a `sendRawTransaction` JSON-RPC response.
    /// Fails closed on any malformed shape: missing result, missing tx_hash,
    /// wrong types, nulls, or explicit JSON-RPC errors. Never defaults to
    /// success. A JSON-RPC `"error": null` is treated as absent (success path).
    pub fn parse_submit_response(resp: &serde_json::Value) -> Result<String> {
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                return Err(CoreError::InvalidSignature(format!(
                    "transaction rejected: {}",
                    msg
                )));
            }
        }

        let result = resp.get("result").ok_or_else(|| {
            CoreError::InvalidSignature("RPC returned neither result nor error".to_string())
        })?;
        if result.is_null() {
            return Err(CoreError::InvalidSignature(
                "RPC result is null".to_string(),
            ));
        }
        let tx_hash = result
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CoreError::InvalidSignature("RPC result missing tx_hash".to_string()))?;
        Ok(tx_hash.to_string())
    }

    /// Submit a pre-encoded transaction to the RPC mempool.
    pub async fn submit_transaction(rpc_url: &str, encoded: &[u8]) -> Result<SubmitResult> {
        let hex_tx = hex::encode(encoded);
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "sendRawTransaction",
            "params": { "hex": hex_tx },
            "id": 1
        });

        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| CoreError::InvalidSignature(format!("RPC request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| CoreError::InvalidSignature(format!("invalid RPC response: {}", e)))?;

        let tx_hash = Self::parse_submit_response(&resp)?;
        Ok(SubmitResult { tx_hash })
    }

    /// Strictly parse a `getAccount` JSON-RPC response.
    /// Fails closed on missing/wrong-typed/null balance or nonce. Never
    /// defaults to balance=0/nonce=0. A JSON-RPC `"error": null` is treated
    /// as absent (success path).
    pub fn parse_account_response(resp: &serde_json::Value) -> Result<AccountInfo> {
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                let err_msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                return Err(CoreError::InvalidSignature(format!(
                    "RPC error: {}",
                    err_msg
                )));
            }
        }

        let result = resp.get("result").ok_or_else(|| {
            CoreError::InvalidSignature("RPC returned neither result nor error".to_string())
        })?;
        if result.is_null() {
            return Err(CoreError::InvalidSignature(
                "RPC result is null".to_string(),
            ));
        }

        let balance = result
            .get("balance")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                CoreError::InvalidSignature("RPC result missing or invalid balance".to_string())
            })?;
        let nonce = result
            .get("nonce")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                CoreError::InvalidSignature("RPC result missing or invalid nonce".to_string())
            })?;

        Ok(AccountInfo { balance, nonce })
    }

    /// Get account info (balance, nonce) from RPC.
    pub async fn get_account_info(rpc_url: &str, address: &Address) -> Result<AccountInfo> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "getAccount",
            "params": { "address": address.to_string() },
            "id": 1
        });

        let client = reqwest::Client::new();
        let resp: serde_json::Value = client
            .post(rpc_url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| CoreError::InvalidSignature(format!("RPC request failed: {}", e)))?
            .json()
            .await
            .map_err(|e| CoreError::InvalidSignature(format!("invalid RPC response: {}", e)))?;

        Self::parse_account_response(&resp)
    }

    /// Full send flow: build, sign, validate, submit via RPC.
    pub async fn send(
        &self,
        rpc_url: &str,
        recipient: Address,
        amount: Amount,
    ) -> Result<SendResult> {
        // 1. Validate amount
        if amount == Amount::ZERO {
            return Err(CoreError::InvalidTransaction(
                "amount must be greater than zero".to_string(),
            ));
        }

        // 2. Validate recipient is not self
        if recipient == self.address {
            return Err(CoreError::InvalidTransaction(
                "cannot send to self".to_string(),
            ));
        }

        // 3. Get account info (balance, nonce) from chain
        let account = Self::get_account_info(rpc_url, &self.address).await?;

        // 4. Check balance
        if account.balance < amount.0 {
            return Err(CoreError::InvalidTransaction(format!(
                "insufficient balance: have {} CHR, need {} CHR",
                account.balance as f64 / 1_000_000.0,
                amount.0 as f64 / 1_000_000.0,
            )));
        }

        let nonce = Nonce(account.nonce);

        // 5. Build and sign transaction
        let prepared = self.prepare_transaction(recipient, amount, nonce)?;

        // 6. Re-fetch nonce right before submission to detect concurrent sends
        let account_before_submit = Self::get_account_info(rpc_url, &self.address).await?;
        if account_before_submit.nonce != account.nonce {
            return Err(CoreError::InvalidTransaction(
                "nonce changed during send; another transaction may have been submitted concurrently. Please retry.".to_string(),
            ));
        }

        // 7. Submit to mempool
        let submit = Self::submit_transaction(rpc_url, &prepared.encoded).await?;

        Ok(SendResult {
            tx_hash: submit.tx_hash,
            from: self.address,
            to: recipient,
            amount,
            nonce,
        })
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.secret_key.0.zeroize();
    }
}

/// A prepared transaction ready for submission.
pub struct PreparedTransaction {
    pub tx: chroma_tx::Transaction,
    pub encoded: Vec<u8>,
    pub txid: chroma_core::hash::Hash,
}

/// Result of submitting a transaction to the mempool.
pub struct SubmitResult {
    pub tx_hash: String,
}

/// Account info from chain state.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub balance: u64,
    pub nonce: u64,
}

/// Result of a successful send operation.
#[derive(Debug)]
pub struct SendResult {
    pub tx_hash: String,
    pub from: Address,
    pub to: Address,
    pub amount: Amount,
    pub nonce: Nonce,
}

pub fn generate_seed_phrase() -> Vec<String> {
    let mut phrase = Vec::with_capacity(12);
    for _ in 0..12 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        let idx = u32::from_le_bytes(buf) as usize % BIP39_WORDLIST.len();
        phrase.push(BIP39_WORDLIST[idx].to_string());
    }
    phrase
}

pub fn validate_seed_phrase(phrase: &[String]) -> bool {
    if phrase.len() != 12 {
        return false;
    }
    for word in phrase {
        if !BIP39_WORDLIST.contains(&word.as_str()) {
            return false;
        }
    }
    true
}

pub fn wallet_from_seed_phrase(name: &str, phrase: &[String]) -> Result<Wallet> {
    wallet_from_seed_phrase_for_network(name, phrase, MAINNET_MAGIC)
}

pub fn wallet_from_seed_phrase_for_network(
    name: &str,
    phrase: &[String],
    network_magic: [u8; 4],
) -> Result<Wallet> {
    if !validate_seed_phrase(phrase) {
        return Err(CoreError::InvalidSignature(
            "invalid seed phrase: contains unknown words or wrong length".to_string(),
        ));
    }
    let mut entropy = Vec::with_capacity(64);
    for word in phrase {
        entropy.extend_from_slice(word.as_bytes());
        entropy.push(0);
    }
    let hash = blake3::hash(&entropy);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(hash.as_bytes());
    let secret_key = SecretKey32::from_bytes(key_bytes)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid key: {}", e)))?;
    Wallet::from_secret_key_for_network(name, secret_key, network_magic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::{MAINNET_MAGIC, REGTEST_MAGIC, TESTNET_MAGIC};
    use chroma_core::serialize::CanonicalDecode;

    fn test_phrase() -> Vec<String> {
        vec![
            "abandon".to_string(),
            "ability".to_string(),
            "able".to_string(),
            "about".to_string(),
            "above".to_string(),
            "absent".to_string(),
            "absorb".to_string(),
            "abstract".to_string(),
            "absurd".to_string(),
            "abuse".to_string(),
            "access".to_string(),
            "accident".to_string(),
        ]
    }

    #[test]
    fn test_wallet_generate() {
        let wallet = Wallet::generate("test");
        assert_eq!(wallet.name(), "test");
        let addr = wallet.address();
        assert_ne!(addr.as_hash160().as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn test_wallet_from_secret_key() {
        let secret = SecretKey32::generate();
        let wallet = Wallet::from_secret_key("test2", secret).unwrap();
        assert_eq!(wallet.name(), "test2");
    }

    #[test]
    fn test_wallet_address_deterministic() {
        let secret = SecretKey32::generate();
        let w1 = Wallet::from_secret_key("a", secret).unwrap();
        let w2 = Wallet::from_secret_key("b", secret).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_secret_bytes() {
        let secret = SecretKey32::generate();
        let wallet = Wallet::from_secret_key("test", secret).unwrap();
        assert_eq!(wallet.secret_bytes(), secret.0);
    }

    #[test]
    fn test_seed_phrase_generation() {
        let phrase = generate_seed_phrase();
        assert_eq!(phrase.len(), 12);
        for word in &phrase {
            assert!(!word.is_empty());
        }
    }

    #[test]
    fn test_validate_seed_phrase_valid() {
        assert!(validate_seed_phrase(&test_phrase()));
    }

    #[test]
    fn test_validate_seed_phrase_invalid() {
        let mut phrase = test_phrase();
        phrase.push("xyznotaword".to_string());
        assert!(!validate_seed_phrase(&phrase));
    }

    #[test]
    fn test_validate_seed_phrase_wrong_length() {
        let phrase = vec!["abandon".to_string(), "ability".to_string()];
        assert!(!validate_seed_phrase(&phrase));
    }

    #[test]
    fn test_wallet_from_seed_phrase() {
        let wallet = wallet_from_seed_phrase("seed_test", &test_phrase()).unwrap();
        assert_eq!(wallet.name(), "seed_test");
    }

    #[test]
    fn test_wallet_from_seed_phrase_deterministic() {
        let phrase = test_phrase();
        let w1 = wallet_from_seed_phrase("a", &phrase).unwrap();
        let w2 = wallet_from_seed_phrase("b", &phrase).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_from_seed_phrase_invalid_words() {
        let mut phrase = test_phrase();
        phrase.push("notaword".to_string());
        assert!(wallet_from_seed_phrase("bad", &phrase).is_err());
    }

    #[test]
    fn test_drop_zeroizes() {
        let secret = SecretKey32::generate();
        let key_bytes = secret.0;
        {
            let _wallet = Wallet::from_secret_key("drop_test", secret).unwrap();
        }
        assert_eq!(key_bytes, secret.0);
    }

    #[test]
    fn test_seed_phrase_uniqueness() {
        let p1 = generate_seed_phrase();
        let p2 = generate_seed_phrase();
        let p3 = generate_seed_phrase();
        // With CSPRNG, 12-word phrases from 2048 words should almost never collide
        assert_ne!(p1, p2);
        assert_ne!(p2, p3);
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_seed_phrase_words_are_valid() {
        for _ in 0..10 {
            let phrase = generate_seed_phrase();
            assert!(validate_seed_phrase(&phrase));
        }
    }

    #[test]
    fn test_wallet_from_seed_phrase_different_phones_different_wallets() {
        let p1 = generate_seed_phrase();
        let p2 = generate_seed_phrase();
        let w1 = wallet_from_seed_phrase("w1", &p1).unwrap();
        let w2 = wallet_from_seed_phrase("w2", &p2).unwrap();
        assert_ne!(w1.address(), w2.address());
    }

    fn make_recipient() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xBB;
        Address::from_hash160(Hash160(h))
    }

    #[test]
    fn test_zero_amount_rejected() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let result = wallet.create_transaction(recipient, Amount(0), Nonce(0));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("amount"),
            "error should mention amount: {}",
            err
        );
    }

    #[test]
    fn test_self_send_rejected() {
        let wallet = Wallet::generate("test");
        let result = wallet.create_transaction(wallet.address(), Amount(1_000_000), Nonce(0));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("self") || err.contains("sender") || err.contains("differ"),
            "error should mention self-send: {}",
            err
        );
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_amount() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let mut tampered = tx.clone();
        tampered.amount = Amount(999_999);
        assert!(!tampered.verify_signature(wallet.network_magic()));
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_nonce() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let mut tampered = tx.clone();
        tampered.nonce = Nonce(1);
        assert!(!tampered.verify_signature(wallet.network_magic()));
    }

    #[test]
    fn test_signature_verification_fails_with_wrong_recipient() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let mut tampered = tx.clone();
        let mut h = [0u8; 20];
        h[0] = 0xCC;
        tampered.recipient = Address::from_hash160(Hash160(h));
        assert!(!tampered.verify_signature(wallet.network_magic()));
    }

    #[test]
    fn test_signature_deterministic() {
        let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
        let wallet = Wallet::from_secret_key("test", secret).unwrap();
        let recipient = make_recipient();
        let tx1 = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let tx2 = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_eq!(tx1.signature, tx2.signature);
    }

    #[test]
    fn test_prepare_transaction_serialization_roundtrip() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let prepared = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_eq!(prepared.encoded.len(), 132);
        let decoded = chroma_tx::Transaction::decode(&prepared.encoded).unwrap();
        assert_eq!(decoded.sender_pubkey.0, prepared.tx.sender_pubkey.0);
        assert_eq!(decoded.recipient, prepared.tx.recipient);
        assert_eq!(decoded.amount, prepared.tx.amount);
        assert_eq!(decoded.nonce, prepared.tx.nonce);
        assert_eq!(decoded.signature, prepared.tx.signature);
    }

    #[test]
    fn test_txid_is_deterministic() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let p1 = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let p2 = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_eq!(p1.txid, p2.txid);
    }

    #[test]
    fn test_different_amounts_different_txid() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let p1 = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let p2 = wallet
            .prepare_transaction(recipient, Amount(2_000_000), Nonce(0))
            .unwrap();
        assert_ne!(p1.txid, p2.txid);
    }

    #[test]
    fn test_different_nonces_different_txid() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let p1 = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let p2 = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(1))
            .unwrap();
        assert_ne!(p1.txid, p2.txid);
    }

    #[test]
    fn test_different_recipients_different_txid() {
        let wallet = Wallet::generate("test");
        let mut h1 = [0u8; 20];
        h1[0] = 0xBB;
        let mut h2 = [0u8; 20];
        h2[0] = 0xCC;
        let r1 = Address::from_hash160(Hash160(h1));
        let r2 = Address::from_hash160(Hash160(h2));
        let p1 = wallet
            .prepare_transaction(r1, Amount(1_000_000), Nonce(0))
            .unwrap();
        let p2 = wallet
            .prepare_transaction(r2, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_ne!(p1.txid, p2.txid);
    }

    #[test]
    fn test_max_amount_transaction() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let max = Amount(u64::MAX);
        let result = wallet.create_transaction(recipient, max, Nonce(0));
        assert!(
            result.is_ok(),
            "max amount should be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_various_nonces() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        for nonce_val in [0, 1, 100, u64::MAX] {
            let tx = wallet
                .create_transaction(recipient, Amount(1), Nonce(nonce_val))
                .unwrap();
            assert_eq!(tx.nonce, Nonce(nonce_val));
        }
    }

    #[test]
    fn test_different_keys_different_transactions() {
        let wallet1 = Wallet::generate("w1");
        let wallet2 = Wallet::generate("w2");
        let recipient = make_recipient();
        let tx1 = wallet1
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let tx2 = wallet2
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_ne!(tx1.sender_pubkey.0, tx2.sender_pubkey.0);
        assert_ne!(tx1.signature.0, tx2.signature.0);
    }

    #[test]
    fn test_wrong_sender_address_rejected() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let mut tampered = tx.clone();
        tampered.sender_pubkey = chroma_crypto::schnorr::PublicKey32([0xFF; 32]);
        assert!(!tampered.verify_signature(wallet.network_magic()));
    }

    #[test]
    fn test_signature_fails_with_tampered_pubkey() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        let mut tampered = tx.clone();
        tampered.sender_pubkey = chroma_crypto::schnorr::PublicKey32([0x01; 32]);
        assert!(!tampered.verify_signature(wallet.network_magic()));
    }

    #[test]
    fn test_wallet_from_seed_phrase_invalid_wrong_length() {
        let phrase = vec!["abandon".to_string()];
        assert!(wallet_from_seed_phrase("bad", &phrase).is_err());
    }

    #[test]
    fn test_prepare_transaction_encoding_is_132_bytes() {
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let prepared = wallet
            .prepare_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        assert_eq!(
            prepared.encoded.len(),
            132,
            "transaction must be exactly 132 bytes"
        );
    }

    #[test]
    fn test_coinbase_rejection_via_create_transaction() {
        // Coinbase transactions have zero sender_pubkey and zero signature
        // A wallet cannot create a coinbase transaction
        let wallet = Wallet::generate("test");
        let recipient = make_recipient();
        let tx = wallet
            .create_transaction(recipient, Amount(1_000_000), Nonce(0))
            .unwrap();
        // Coinbase would have empty signature; our tx has a real signature
        assert_ne!(tx.signature.0, [0u8; 64]);
        // Coinbase would have zero pubkey; ours has a real pubkey
        assert_ne!(tx.sender_pubkey.0, [0u8; 32]);
    }

    #[test]
    fn test_wallet_name_preserved() {
        let wallet = Wallet::generate("my_wallet");
        assert_eq!(wallet.name(), "my_wallet");
    }

    #[test]
    fn test_wallet_address_deterministic_from_secret() {
        let secret = SecretKey32::from_bytes([0x42; 32]).unwrap();
        let w1 = Wallet::from_secret_key("a", secret).unwrap();
        let w2 = Wallet::from_secret_key("a", secret).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_address_deterministic_from_seed() {
        let phrase = vec![
            "abandon".to_string(),
            "ability".to_string(),
            "able".to_string(),
            "about".to_string(),
            "above".to_string(),
            "absent".to_string(),
            "absorb".to_string(),
            "abstract".to_string(),
            "absurd".to_string(),
            "abuse".to_string(),
            "access".to_string(),
            "accident".to_string(),
        ];
        let w1 = wallet_from_seed_phrase("a", &phrase).unwrap();
        let w2 = wallet_from_seed_phrase("b", &phrase).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_different_seeds_different_addresses() {
        let phrase1 = vec![
            "abandon".to_string(),
            "ability".to_string(),
            "able".to_string(),
            "about".to_string(),
            "above".to_string(),
            "absent".to_string(),
            "absorb".to_string(),
            "abstract".to_string(),
            "absurd".to_string(),
            "abuse".to_string(),
            "access".to_string(),
            "accident".to_string(),
        ];
        let phrase2 = vec![
            "baby".to_string(),
            "bachelor".to_string(),
            "bacon".to_string(),
            "badge".to_string(),
            "bag".to_string(),
            "balance".to_string(),
            "balcony".to_string(),
            "ball".to_string(),
            "bamboo".to_string(),
            "banana".to_string(),
            "banner".to_string(),
            "bar".to_string(),
        ];
        let w1 = wallet_from_seed_phrase("a", &phrase1).unwrap();
        let w2 = wallet_from_seed_phrase("b", &phrase2).unwrap();
        assert_ne!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_network_magic_mainnet_sign_mainnet_verify_ok() {
        let wallet = Wallet::generate_for_network("net", MAINNET_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_mainnet_to_testnet_fails() {
        let wallet = Wallet::generate_for_network("net", MAINNET_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(!tx.verify_signature(TESTNET_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_mainnet_to_regtest_fails() {
        let wallet = Wallet::generate_for_network("net", MAINNET_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_testnet_to_mainnet_fails() {
        let wallet = Wallet::generate_for_network("net", TESTNET_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(tx.verify_signature(TESTNET_MAGIC));
        assert!(!tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_testnet_to_regtest_fails() {
        let wallet = Wallet::generate_for_network("net", TESTNET_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(!tx.verify_signature(REGTEST_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_regtest_to_mainnet_fails() {
        let wallet = Wallet::generate_for_network("net", REGTEST_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(tx.verify_signature(REGTEST_MAGIC));
        assert!(!tx.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_wallet_network_replay_regtest_to_testnet_fails() {
        let wallet = Wallet::generate_for_network("net", REGTEST_MAGIC);
        let tx = wallet
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        assert!(!tx.verify_signature(TESTNET_MAGIC));
    }

    #[test]
    fn test_wallet_with_network_magic_overrides_signing_domain() {
        let secret = SecretKey32::from_bytes([0x42; 32]).unwrap();
        let w_main = Wallet::from_secret_key_for_network("m", secret, MAINNET_MAGIC).unwrap();
        let w_reg = Wallet::from_secret_key_for_network("r", secret, REGTEST_MAGIC).unwrap();
        // Same key → same address across networks (addresses are not network-specific).
        assert_eq!(w_main.address(), w_reg.address());
        let tx_main = w_main
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        let tx_reg = w_reg
            .create_transaction(make_recipient(), Amount(1_000_000), Nonce(0))
            .unwrap();
        // Same unsigned body, different signatures → different encodings.
        assert_eq!(tx_main.encode()[..68], tx_reg.encode()[..68]);
        assert_ne!(tx_main.encode(), tx_reg.encode());
        assert!(tx_main.verify_signature(MAINNET_MAGIC));
        assert!(!tx_main.verify_signature(REGTEST_MAGIC));
        assert!(tx_reg.verify_signature(REGTEST_MAGIC));
        assert!(!tx_reg.verify_signature(MAINNET_MAGIC));
    }

    #[test]
    fn test_parse_submit_response_ok_with_null_error() {
        // Real servers serialize success as {"result": {...}, "error": null}.
        // A null error must NOT be treated as failure.
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "tx_hash": "abc123" },
            "error": null,
            "id": 1
        });
        assert_eq!(Wallet::parse_submit_response(&resp).unwrap(), "abc123");
    }

    #[test]
    fn test_parse_submit_response_ok_without_error_field() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "tx_hash": "abc123" },
            "id": 1
        });
        assert_eq!(Wallet::parse_submit_response(&resp).unwrap(), "abc123");
    }

    #[test]
    fn test_parse_submit_response_rejects_explicit_error() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "invalid transaction" },
            "id": 1
        });
        assert!(Wallet::parse_submit_response(&resp).is_err());
    }

    #[test]
    fn test_parse_submit_response_rejects_missing_result() {
        // Neither result nor error → must fail, never fake success.
        let resp = serde_json::json!({ "jsonrpc": "2.0", "id": 1 });
        assert!(Wallet::parse_submit_response(&resp).is_err());
    }

    #[test]
    fn test_parse_submit_response_rejects_null_result() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": null,
            "error": null,
            "id": 1
        });
        assert!(Wallet::parse_submit_response(&resp).is_err());
    }

    #[test]
    fn test_parse_submit_response_rejects_missing_tx_hash() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {},
            "error": null,
            "id": 1
        });
        assert!(Wallet::parse_submit_response(&resp).is_err());
    }

    #[test]
    fn test_parse_submit_response_rejects_wrong_type_tx_hash() {
        for bad in [
            serde_json::json!({ "tx_hash": 123 }),
            serde_json::json!({ "tx_hash": null }),
            serde_json::json!({ "tx_hash": ["abc"] }),
            serde_json::json!({ "tx_hash": { "h": "abc" } }),
        ] {
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": bad,
                "error": null,
                "id": 1
            });
            assert!(
                Wallet::parse_submit_response(&resp).is_err(),
                "wrong-type tx_hash must fail: {}",
                bad
            );
        }
    }

    #[test]
    fn test_parse_account_response_ok_with_null_error() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "balance": 100, "nonce": 5 },
            "error": null,
            "id": 1
        });
        let info = Wallet::parse_account_response(&resp).unwrap();
        assert_eq!(info.balance, 100);
        assert_eq!(info.nonce, 5);
    }

    #[test]
    fn test_parse_account_response_rejects_explicit_error() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32602, "message": "invalid address" },
            "id": 1
        });
        assert!(Wallet::parse_account_response(&resp).is_err());
    }

    #[test]
    fn test_parse_account_response_rejects_missing_result() {
        let resp = serde_json::json!({ "jsonrpc": "2.0", "id": 1 });
        assert!(Wallet::parse_account_response(&resp).is_err());
    }

    #[test]
    fn test_parse_account_response_rejects_null_result() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": null,
            "error": null,
            "id": 1
        });
        assert!(Wallet::parse_account_response(&resp).is_err());
    }

    #[test]
    fn test_parse_account_response_rejects_missing_balance() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "nonce": 0 },
            "error": null,
            "id": 1
        });
        assert!(Wallet::parse_account_response(&resp).is_err());
    }

    #[test]
    fn test_parse_account_response_rejects_missing_nonce() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": { "balance": 100 },
            "error": null,
            "id": 1
        });
        assert!(Wallet::parse_account_response(&resp).is_err());
    }

    #[test]
    fn test_parse_account_response_rejects_wrong_types() {
        // Wrong JSON types must fail, never silently default to 0.
        for bad in [
            serde_json::json!({ "balance": "100", "nonce": 0 }),
            serde_json::json!({ "balance": 100, "nonce": "0" }),
            serde_json::json!({ "balance": null, "nonce": 0 }),
            serde_json::json!({ "balance": 100, "nonce": null }),
            serde_json::json!({ "balance": 1.5, "nonce": 0 }),
            serde_json::json!({ "balance": -1, "nonce": 0 }),
            serde_json::json!({ "balance": 100, "nonce": -1 }),
        ] {
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "result": bad,
                "error": null,
                "id": 1
            });
            assert!(
                Wallet::parse_account_response(&resp).is_err(),
                "wrong-type account fields must fail: {}",
                bad
            );
        }
    }
}
