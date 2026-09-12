//! Noise Protocol Transport
//!
//! Implements Noise_XX_25519_ChaChaPoly_BLAKE2s for encrypted P2P communication.
//! (Earlier revisions of these docs said XK; the code has always used XX.
//! XX requires no prior key knowledge: both sides learn each other's static
//! keys during the handshake.)
//!
//! Properties:
//! - Mutual authentication (both parties know each other's static keys)
//! - Forward secrecy (ephemeral key exchange)
//! - Authenticated encryption (ChaChaPoly)
//!
//! NOT an admission-control mechanism -- any node can join by generating
//! an identity and connecting.
//!
//! NOTE: as of this release the P2P node does NOT use this module yet —
//! production P2P traffic is plaintext TCP (see protocol/SPEC.md §10).
//! Wiring Noise into the connection handler is a mainnet blocker.

use crate::error::{CryptoError, CryptoResult as Result};
use getrandom::getrandom;
use snow::{Builder, HandshakeState, TransportState};

/// Noise protocol parameters — XX pattern (no prior key knowledge).
/// Public so the P2P transport layer uses exactly this suite; there is one
/// definition site and therefore no suite/pattern drift.
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext bytes per Noise transport message.
/// The Noise spec caps transport messages at 65535 bytes total including the
/// 16-byte AEAD tag; larger payloads must be chunked by the caller.
pub const NOISE_MAX_PLAINTEXT: usize = 65_535 - 16;
/// Maximum ciphertext bytes per Noise transport message.
pub const NOISE_MAX_CIPHERTEXT: usize = 65_535;
/// Rekey both directions after this many transport messages each. Rekey
/// timing is application-synchronized: TCP preserves order and both sides
/// count independently, so sender-side `rekey_outgoing` always coincides with
/// receiver-side `rekey_incoming` after the same message.
pub const REKEY_AFTER_MESSAGES: u64 = 100_000;

/// Node identity (32-byte static key)
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generate a new random NodeId
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes).expect("CSPRNG failure");
        NodeId(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }
}

/// Handshake role in Noise_XX
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Derive the X25519 static public key for a 32-byte static private key.
/// Uses the same clamping as the Noise DH so the result always matches what
/// the peer observes via `get_remote_static_key` after the handshake.
pub fn x25519_public_from_private(secret: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

/// Generate a fresh 32-byte static private key from the OS CSPRNG.
pub fn generate_static_key() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom(&mut bytes).expect("CSPRNG failure");
    // Astronomically unlikely, but an all-zero scalar is a degenerate
    // X25519 key (identity point) — never emit one.
    if bytes == [0u8; 32] {
        getrandom(&mut bytes).expect("CSPRNG failure");
    }
    bytes
}

/// Validate raw static-key file material: exactly 32 bytes and not the
/// degenerate all-zero scalar. (X25519 clamps every other input into a
/// working key, so length + non-zero is the complete check.)
pub fn is_valid_static_key(bytes: &[u8]) -> bool {
    bytes.len() == 32 && bytes != [0u8; 32]
}

/// Noise transport wrapper that provides encrypted read/write.
///
/// After the handshake completes, all messages are encrypted with
/// ChaChaPoly and authenticated with BLAKE2s.
pub struct NoiseTransport {
    state: TransportState,
    sent_messages: u64,
    received_messages: u64,
}

impl NoiseTransport {
    /// Create a new Noise transport from a completed handshake state.
    pub fn from_handshake(handshake: HandshakeState) -> Result<Self> {
        let transport = handshake
            .into_transport_mode()
            .map_err(|e| CryptoError::Noise(format!("failed to enter transport mode: {}", e)))?;
        Ok(NoiseTransport {
            state: transport,
            sent_messages: 0,
            received_messages: 0,
        })
    }

    /// Encrypt a message for sending.
    ///
    /// Returns the encrypted payload (without length framing — caller handles framing).
    /// Rekeys automatically every REKEY_AFTER_MESSAGES sends.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > NOISE_MAX_PLAINTEXT {
            return Err(CryptoError::Noise(format!(
                "message too large: {} > {}",
                plaintext.len(),
                NOISE_MAX_PLAINTEXT
            )));
        }

        // AEAD adds 16 bytes of tag
        let mut buf = vec![0u8; plaintext.len() + 16];
        let encrypted_len = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("encrypt failed: {}", e)))?;
        buf.truncate(encrypted_len);
        self.sent_messages = self.sent_messages.saturating_add(1);
        self.rekey_if_due();
        Ok(buf)
    }

    /// Decrypt a received message.
    /// Rekeys automatically every REKEY_AFTER_MESSAGES receives.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() > NOISE_MAX_CIPHERTEXT {
            return Err(CryptoError::Noise(format!(
                "encrypted frame too large: {}",
                ciphertext.len()
            )));
        }

        // Plaintext is always shorter than its ciphertext (16-byte tag), so
        // allocating ciphertext.len() is both sufficient and bounded by the
        // validated cap above — never a fixed 1 MB per call.
        let mut decrypted = vec![0u8; ciphertext.len()];
        let n = self
            .state
            .read_message(ciphertext, &mut decrypted)
            .map_err(|e| CryptoError::Noise(format!("decrypt failed: {}", e)))?;
        decrypted.truncate(n);
        self.received_messages = self.received_messages.saturating_add(1);
        self.rekey_if_due();
        Ok(decrypted)
    }

    /// Rekey both directions once each side has exchanged
    /// REKEY_AFTER_MESSAGES messages. See REKEY_AFTER_MESSAGES for why the
    /// two sides stay synchronized without extra protocol messages.
    fn rekey_if_due(&mut self) {
        if self.sent_messages > 0 && self.sent_messages.is_multiple_of(REKEY_AFTER_MESSAGES) {
            self.state.rekey_outgoing();
        }
        if self.received_messages > 0 && self.received_messages.is_multiple_of(REKEY_AFTER_MESSAGES)
        {
            self.state.rekey_incoming();
        }
    }

    /// Number of transport messages encrypted on this session.
    pub fn sent_count(&self) -> u64 {
        self.sent_messages
    }

    /// Number of transport messages decrypted on this session.
    pub fn received_count(&self) -> u64 {
        self.received_messages
    }

    #[cfg(test)]
    pub(crate) fn set_counts_for_test(&mut self, sent: u64, received: u64) {
        self.sent_messages = sent;
        self.received_messages = received;
    }

    /// Get the remote party's static public key (available after handshake).
    pub fn get_remote_static_key(&self) -> Option<&[u8]> {
        self.state.get_remote_static()
    }

    /// Consume the transport and return the underlying `TransportState`.
    pub fn into_inner(self) -> TransportState {
        self.state
    }
}

/// Perform a Noise_XX handshake using synchronous read/write callbacks.
///
/// XX pattern: no prior key knowledge. Both sides learn each other's static keys.
/// Returns the completed `NoiseTransport` ready for encrypted communication.
///
/// # Arguments
/// * `role` - Whether this side is the Initiator or Responder
/// * `static_key` - The local static private key (32 bytes)
/// * `reader` - Callback that reads bytes into the buffer, returns bytes read
/// * `writer` - Callback that writes bytes
pub fn perform_handshake<FRead, FWrite>(
    role: HandshakeRole,
    static_key: &[u8; 32],
    mut reader: FRead,
    mut writer: FWrite,
) -> Result<NoiseTransport>
where
    FRead: FnMut(&mut [u8]) -> Result<usize>,
    FWrite: FnMut(&[u8]) -> Result<()>,
{
    let builder = Builder::new(NOISE_PARAMS.parse().unwrap());

    match role {
        HandshakeRole::Initiator => {
            let mut handshake = builder
                .local_private_key(static_key)
                .build_initiator()
                .map_err(|e| CryptoError::Noise(format!("init handshake: {}", e)))?;

            // Message 1: e
            let mut msg1 = vec![0u8; 64];
            let n1 = handshake
                .write_message(&[], &mut msg1)
                .map_err(|e| CryptoError::Noise(format!("write msg1: {}", e)))?;
            writer(&msg1[..n1])?;

            // Message 2: e, ee, s, es (from responder)
            let mut msg2 = vec![0u8; 128];
            let n2 = reader(&mut msg2)?;
            let mut payload2 = vec![0u8; 0];
            handshake
                .read_message(&msg2[..n2], &mut payload2)
                .map_err(|e| CryptoError::Noise(format!("read msg2: {}", e)))?;

            // Message 3: s, se (from initiator)
            let mut msg3 = vec![0u8; 64];
            let n3 = handshake
                .write_message(&[], &mut msg3)
                .map_err(|e| CryptoError::Noise(format!("write msg3: {}", e)))?;
            writer(&msg3[..n3])?;

            NoiseTransport::from_handshake(handshake)
        }
        HandshakeRole::Responder => {
            let mut handshake = builder
                .local_private_key(static_key)
                .build_responder()
                .map_err(|e| CryptoError::Noise(format!("resp handshake: {}", e)))?;

            // Message 1: e (from initiator)
            let mut msg1 = vec![0u8; 64];
            let n1 = reader(&mut msg1)?;
            let mut payload1 = vec![0u8; 0];
            handshake
                .read_message(&msg1[..n1], &mut payload1)
                .map_err(|e| CryptoError::Noise(format!("read msg1: {}", e)))?;

            // Message 2: e, ee, s, es (from responder)
            let mut msg2 = vec![0u8; 128];
            let n2 = handshake
                .write_message(&[], &mut msg2)
                .map_err(|e| CryptoError::Noise(format!("write msg2: {}", e)))?;
            writer(&msg2[..n2])?;

            // Message 3: s, se (from initiator)
            let mut msg3 = vec![0u8; 64];
            let n3 = reader(&mut msg3)?;
            let mut payload3 = vec![0u8; 0];
            handshake
                .read_message(&msg3[..n3], &mut payload3)
                .map_err(|e| CryptoError::Noise(format!("read msg3: {}", e)))?;

            NoiseTransport::from_handshake(handshake)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let id1 = NodeId::generate();
        let id2 = NodeId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_from_bytes() {
        let bytes = [0x42u8; 32];
        let id = NodeId::from_bytes(bytes);
        assert_eq!(id.0, bytes);
    }

    #[test]
    fn test_noise_params_valid() {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
        // XK pattern should parse successfully
        assert!(!format!("{:?}", params).is_empty());
    }

    #[test]
    fn test_noise_transport_encrypt_decrypt() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();

        let mut buf = vec![0u8; 512];

        // Msg1: e
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();

        // Msg2: e, ee, s, es
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();

        // Msg3: s, se
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();

        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        // Encrypt from t1, decrypt on t2
        let plaintext = b"hello, encrypted world!";
        let encrypted = t1.encrypt(plaintext).unwrap();
        assert_ne!(encrypted.as_slice(), plaintext.as_slice());

        let decrypted = t2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Encrypt from t2, decrypt on t1
        let plaintext2 = b"response from responder";
        let encrypted2 = t2.encrypt(plaintext2).unwrap();
        let decrypted2 = t1.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_noise_transport_rejects_tampered() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();

        let mut buf = vec![0u8; 512];

        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();

        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();

        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();

        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        let plaintext = b"secret data";
        let mut encrypted = t1.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if encrypted.len() > 10 {
            encrypted[10] ^= 0xFF;
        }

        let result = t2.decrypt(&encrypted);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail decryption"
        );
    }

    #[test]
    fn test_perform_handshake_in_memory() {
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];

        // Build handshake states directly (perform_handshake blocks, so we
        // manually step through the XX pattern using snow's API).
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();

        let mut buf = vec![0u8; 512];

        // Msg1: e
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();

        // Msg2: e, ee, s, es
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();

        // Msg3: s, se
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();

        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        let msg = b"Noise_XX works!";
        let enc = t1.encrypt(msg).unwrap();
        let dec = t2.decrypt(&enc).unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn test_noise_multiple_messages() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();

        let mut buf = vec![0u8; 512];

        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();

        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();

        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();

        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        for i in 0..10u64 {
            let msg = format!("message {}", i);
            let enc = t1.encrypt(msg.as_bytes()).unwrap();
            let dec = t2.decrypt(&enc).unwrap();
            assert_eq!(dec, msg.as_bytes());

            let reply = format!("reply {}", i);
            let enc2 = t2.encrypt(reply.as_bytes()).unwrap();
            let dec2 = t1.decrypt(&enc2).unwrap();
            assert_eq!(dec2, reply.as_bytes());
        }
    }

    #[test]
    fn test_x25519_public_matches_snow_remote_static() {
        // Our clamping derivation must agree with what snow computes
        // internally, otherwise identity binding would compare garbage.
        let key1 = [0xAAu8; 32];
        let key2 = [0xBBu8; 32];

        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();

        let mut buf = vec![0u8; 512];
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();

        let t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let t2 = NoiseTransport::from_handshake(responder).unwrap();

        // Each side's view of the remote static key equals our derivation.
        assert_eq!(
            t1.get_remote_static_key().unwrap(),
            &x25519_public_from_private(&key2)
        );
        assert_eq!(
            t2.get_remote_static_key().unwrap(),
            &x25519_public_from_private(&key1)
        );
        // Distinct keys, distinct identities.
        assert_ne!(
            x25519_public_from_private(&key1),
            x25519_public_from_private(&key2)
        );
    }

    #[test]
    fn test_static_key_generate_and_validate() {
        let k1 = generate_static_key();
        let k2 = generate_static_key();
        assert_ne!(k1, k2);
        assert!(is_valid_static_key(&k1));
        assert!(is_valid_static_key(&[0x01u8; 32]));
        assert!(!is_valid_static_key(&[0u8; 32]));
        assert!(!is_valid_static_key(&[0u8; 31]));
        assert!(!is_valid_static_key(&[0u8; 33]));
        assert!(!is_valid_static_key(&[]));
    }

    #[test]
    fn test_manual_rekey_keeps_session_alive() {
        let key1 = [0x31u8; 32];
        let key2 = [0x32u8; 32];
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();
        let mut buf = vec![0u8; 512];
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();
        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        // Both sides rekey their directional ciphers symmetrically.
        t1.state.rekey_outgoing();
        t2.state.rekey_incoming();
        let enc = t1.encrypt(b"after manual rekey").unwrap();
        assert_eq!(t2.decrypt(&enc).unwrap(), b"after manual rekey");
        // And back operational in the other direction too.
        t2.state.rekey_outgoing();
        t1.state.rekey_incoming();
        let enc2 = t2.encrypt(b"reply after rekey").unwrap();
        assert_eq!(t1.decrypt(&enc2).unwrap(), b"reply after rekey");
    }

    #[test]
    fn test_auto_rekey_fires_and_stays_in_sync() {
        let key1 = [0x41u8; 32];
        let key2 = [0x42u8; 32];
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();
        let mut buf = vec![0u8; 512];
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();
        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        // Drive both counters to just below the threshold, then exchange
        // one message each way: the threshold crossing rekeys both sides
        // symmetrically and communication must continue uninterrupted.
        t1.set_counts_for_test(REKEY_AFTER_MESSAGES - 1, REKEY_AFTER_MESSAGES - 1);
        t2.set_counts_for_test(REKEY_AFTER_MESSAGES - 1, REKEY_AFTER_MESSAGES - 1);
        let enc = t1.encrypt(b"rekey boundary").unwrap();
        assert_eq!(t2.decrypt(&enc).unwrap(), b"rekey boundary");
        let enc2 = t2.encrypt(b"post rekey").unwrap();
        assert_eq!(t1.decrypt(&enc2).unwrap(), b"post rekey");
        assert_eq!(t1.sent_count(), REKEY_AFTER_MESSAGES);
    }

    #[test]
    fn test_transport_size_caps_fail_fast() {
        let key1 = [0x51u8; 32];
        let key2 = [0x52u8; 32];
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut initiator = builder.local_private_key(&key1).build_initiator().unwrap();
        let builder = Builder::new(NOISE_PARAMS.parse().unwrap());
        let mut responder = builder.local_private_key(&key2).build_responder().unwrap();
        let mut buf = vec![0u8; 512];
        let mut msg1 = vec![0u8; 64];
        let n1 = initiator.write_message(&[], &mut msg1).unwrap();
        responder.read_message(&msg1[..n1], &mut buf).unwrap();
        let mut msg2 = vec![0u8; 128];
        let n2 = responder.write_message(&[], &mut msg2).unwrap();
        initiator.read_message(&msg2[..n2], &mut buf).unwrap();
        let mut msg3 = vec![0u8; 64];
        let n3 = initiator.write_message(&[], &mut msg3).unwrap();
        responder.read_message(&msg3[..n3], &mut buf).unwrap();
        let mut t1 = NoiseTransport::from_handshake(initiator).unwrap();
        let mut t2 = NoiseTransport::from_handshake(responder).unwrap();

        // Oversize plaintext rejected before touching snow.
        let big = vec![0xAAu8; NOISE_MAX_PLAINTEXT + 1];
        assert!(t1.encrypt(&big).is_err());
        // Oversize ciphertext rejected before allocating.
        let big_ct = vec![0xBBu8; NOISE_MAX_CIPHERTEXT + 1];
        assert!(t2.decrypt(&big_ct).is_err());
        // Boundary sizes still work.
        let max_ok = vec![0xCCu8; NOISE_MAX_PLAINTEXT];
        let enc = t1.encrypt(&max_ok).unwrap();
        assert_eq!(enc.len(), NOISE_MAX_PLAINTEXT + 16);
        assert_eq!(t2.decrypt(&enc).unwrap(), max_ok);
    }
}
