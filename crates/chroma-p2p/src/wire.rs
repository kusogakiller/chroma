use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;

/// Mainnet magic bytes
pub const MAGIC: [u8; 4] = [0xC4, 0x48, 0x52, 0x4F];

/// Re-export network magic constants from chroma-core
pub use chroma_core::constants::{REGTEST_MAGIC, TESTNET_MAGIC};
pub const MAX_MESSAGE_SIZE: usize = 4 * 1024 * 1024;
pub const HEADER_SIZE: usize = 13;
/// Maximum entries in a single Inv/GetData message (defense-in-depth against OOM).
pub const MAX_INV_ENTRIES: usize = 100_000;
/// Maximum inventory entries acted upon per message. Decode accepts up to
/// MAX_INV_ENTRIES, but follow-up work (storage lookups, responses) is capped
/// here so one message cannot force unbounded work or bandwidth.
pub const MAX_INV_FOLLOW: usize = 500;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum MessageType {
    Version = 0x01,
    VerAck = 0x02,
    Ping = 0x03,
    Pong = 0x04,
    GetAddr = 0x05,
    Addr = 0x06,
    GetHeaders = 0x07,
    Headers = 0x08,
    Inv = 0x09,
    GetData = 0x0A,
    Tx = 0x0B,
    Block = 0x0C,
    NotFound = 0x0D,
    Reject = 0x0E,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(MessageType::Version),
            0x02 => Ok(MessageType::VerAck),
            0x03 => Ok(MessageType::Ping),
            0x04 => Ok(MessageType::Pong),
            0x05 => Ok(MessageType::GetAddr),
            0x06 => Ok(MessageType::Addr),
            0x07 => Ok(MessageType::GetHeaders),
            0x08 => Ok(MessageType::Headers),
            0x09 => Ok(MessageType::Inv),
            0x0A => Ok(MessageType::GetData),
            0x0B => Ok(MessageType::Tx),
            0x0C => Ok(MessageType::Block),
            0x0D => Ok(MessageType::NotFound),
            0x0E => Ok(MessageType::Reject),
            _ => Err(CoreError::Serialization(format!(
                "unknown message type: 0x{:02X}",
                v
            ))),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum InvType {
    Block = 0x01,
    Tx = 0x02,
}

impl InvType {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(InvType::Block),
            0x02 => Ok(InvType::Tx),
            _ => Err(CoreError::Serialization(format!("unknown inv type: {}", v))),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Message {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
    pub magic: [u8; 4],
}

impl Message {
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Message {
            msg_type,
            payload,
            magic: MAGIC,
        }
    }

    pub fn with_magic(msg_type: MessageType, payload: Vec<u8>, magic: [u8; 4]) -> Self {
        Message {
            msg_type,
            payload,
            magic,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.magic);
        buf.push(self.msg_type as u8);
        let len = self.payload.len() as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        let checksum = blake3::hash(&self.payload);
        buf.extend_from_slice(&checksum.as_bytes()[..4]);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Message, usize)> {
        Self::decode_with_magic(data, MAGIC)
    }

    pub fn decode_with_magic(data: &[u8], expected_magic: [u8; 4]) -> Result<(Message, usize)> {
        if data.len() < HEADER_SIZE {
            return Err(CoreError::Serialization(
                "message: header too short".to_string(),
            ));
        }
        if data[0..4] != expected_magic {
            return Err(CoreError::Serialization("message: bad magic".to_string()));
        }
        let msg_type = MessageType::from_u8(data[4])?;
        let len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(CoreError::Serialization(format!(
                "message: payload too large: {}",
                len
            )));
        }
        let checksum = [data[9], data[10], data[11], data[12]];
        let total = HEADER_SIZE + len;
        if data.len() < total {
            return Err(CoreError::Serialization(
                "message: payload truncated".to_string(),
            ));
        }
        let payload = data[HEADER_SIZE..total].to_vec();
        let expected = blake3::hash(&payload);
        if checksum != expected.as_bytes()[..4] {
            return Err(CoreError::Serialization(
                "message: checksum mismatch".to_string(),
            ));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&data[0..4]);
        Ok((
            Message {
                msg_type,
                payload,
                magic,
            },
            total,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct VersionMessage {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub height: u32,
    pub nonce: u64,
}

impl VersionMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.services.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(CoreError::Serialization("version: too short".to_string()));
        }
        Ok(VersionMessage {
            version: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            services: u64::from_le_bytes(data[4..12].try_into().unwrap()),
            timestamp: u64::from_le_bytes(data[12..20].try_into().unwrap()),
            height: u32::from_le_bytes(data[20..24].try_into().unwrap()),
            nonce: u64::from_le_bytes(data[24..32].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct PingMessage {
    pub nonce: u64,
}

impl PingMessage {
    pub fn encode(&self) -> Vec<u8> {
        self.nonce.to_le_bytes().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(CoreError::Serialization("ping: too short".to_string()));
        }
        Ok(PingMessage {
            nonce: u64::from_le_bytes(data[0..8].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug)]
pub struct GetHeadersMessage {
    pub start_hash: Hash,
    pub stop_hash: Hash,
}

impl GetHeadersMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(self.start_hash.as_bytes());
        buf.extend_from_slice(self.stop_hash.as_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(CoreError::Serialization(
                "getheaders: too short".to_string(),
            ));
        }
        let mut start = [0u8; 32];
        let mut stop = [0u8; 32];
        start.copy_from_slice(&data[0..32]);
        stop.copy_from_slice(&data[32..64]);
        Ok(GetHeadersMessage {
            start_hash: Hash::from_bytes(start),
            stop_hash: Hash::from_bytes(stop),
        })
    }
}

#[derive(Clone, Debug)]
pub struct InvEntry {
    pub inv_type: InvType,
    pub hash: Hash,
}

#[derive(Clone, Debug)]
pub struct InvMessage {
    pub inventory: Vec<InvEntry>,
}

impl InvMessage {
    pub fn encode(&self) -> Vec<u8> {
        let count = self.inventory.len() as u32;
        let mut buf = Vec::with_capacity(4 + self.inventory.len() * 33);
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.inventory {
            buf.push(entry.inv_type as u8);
            buf.extend_from_slice(entry.hash.as_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CoreError::Serialization("inv: too short".to_string()));
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if count > MAX_INV_ENTRIES {
            return Err(CoreError::Serialization(
                "inv: count exceeds limit".to_string(),
            ));
        }
        let expected = 4_usize
            .checked_add(
                count
                    .checked_mul(33)
                    .ok_or_else(|| CoreError::Serialization("inv: count overflow".to_string()))?,
            )
            .ok_or_else(|| CoreError::Serialization("inv: size overflow".to_string()))?;
        if data.len() < expected {
            return Err(CoreError::Serialization("inv: truncated".to_string()));
        }
        let mut inventory = Vec::with_capacity(count);
        let mut pos = 4;
        for _ in 0..count {
            let inv_type = InvType::from_u8(data[pos])?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[pos + 1..pos + 33]);
            inventory.push(InvEntry {
                inv_type,
                hash: Hash::from_bytes(hash),
            });
            pos += 33;
        }
        Ok(InvMessage { inventory })
    }
}

#[derive(Clone, Debug)]
pub struct GetDataMessage {
    pub inventory: Vec<InvEntry>,
}

impl GetDataMessage {
    pub fn encode(&self) -> Vec<u8> {
        let count = self.inventory.len() as u32;
        let mut buf = Vec::with_capacity(4 + self.inventory.len() * 33);
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in &self.inventory {
            buf.push(entry.inv_type as u8);
            buf.extend_from_slice(entry.hash.as_bytes());
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CoreError::Serialization("getdata: too short".to_string()));
        }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if count > MAX_INV_ENTRIES {
            return Err(CoreError::Serialization(
                "getdata: count exceeds limit".to_string(),
            ));
        }
        let expected =
            4_usize
                .checked_add(count.checked_mul(33).ok_or_else(|| {
                    CoreError::Serialization("getdata: count overflow".to_string())
                })?)
                .ok_or_else(|| CoreError::Serialization("getdata: size overflow".to_string()))?;
        if data.len() < expected {
            return Err(CoreError::Serialization("getdata: truncated".to_string()));
        }
        let mut inventory = Vec::with_capacity(count);
        let mut pos = 4;
        for _ in 0..count {
            let inv_type = InvType::from_u8(data[pos])?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[pos + 1..pos + 33]);
            inventory.push(InvEntry {
                inv_type,
                hash: Hash::from_bytes(hash),
            });
            pos += 33;
        }
        Ok(GetDataMessage { inventory })
    }
}

#[derive(Clone, Debug)]
pub struct RejectMessage {
    pub message: String,
    pub code: u8,
    pub reason: String,
}

impl RejectMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let msg_bytes = self.message.as_bytes();
        buf.push(msg_bytes.len() as u8);
        buf.extend_from_slice(msg_bytes);
        buf.push(self.code);
        let reason_bytes = self.reason.as_bytes();
        buf.push(reason_bytes.len() as u8);
        buf.extend_from_slice(reason_bytes);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 3 {
            return Err(CoreError::Serialization("reject: too short".to_string()));
        }
        let msg_len = data[0] as usize;
        if data.len() < 2 + msg_len {
            return Err(CoreError::Serialization(
                "reject: message truncated".to_string(),
            ));
        }
        let message = String::from_utf8_lossy(&data[1..1 + msg_len]).to_string();
        let code = data[1 + msg_len];
        let reason_start = 2 + msg_len;
        if data.len() < reason_start + 1 {
            return Err(CoreError::Serialization(
                "reject: reason length missing".to_string(),
            ));
        }
        let reason_len = data[reason_start] as usize;
        let reason_end = reason_start + 1 + reason_len;
        if data.len() < reason_end {
            return Err(CoreError::Serialization(
                "reject: reason truncated".to_string(),
            ));
        }
        let reason = String::from_utf8_lossy(&data[reason_start + 1..reason_end]).to_string();
        Ok(RejectMessage {
            message,
            code,
            reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::new(MessageType::Ping, vec![1, 2, 3, 4]);
        let encoded = msg.encode();
        let (decoded, consumed) = Message::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_message_rejects_bad_magic() {
        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[0] = 0xFF;
        assert!(Message::decode(&data).is_err());
    }

    #[test]
    fn test_message_rejects_bad_checksum() {
        let mut data = Message::new(MessageType::Ping, vec![0]).encode();
        data[9] ^= 0xFF;
        assert!(Message::decode(&data).is_err());
    }

    #[test]
    fn test_message_rejects_truncated() {
        let data = Message::new(MessageType::Ping, vec![0]).encode();
        assert!(Message::decode(&data[..5]).is_err());
    }

    #[test]
    fn test_message_rejects_oversized() {
        let msg = Message::new(MessageType::Block, vec![0u8; MAX_MESSAGE_SIZE + 1]);
        let encoded = msg.encode();
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn test_version_roundtrip() {
        let v = VersionMessage {
            version: 1,
            services: 0,
            timestamp: 1700000000,
            height: 100,
            nonce: 42,
        };
        let enc = v.encode();
        let dec = VersionMessage::decode(&enc).unwrap();
        assert_eq!(dec.version, 1);
        assert_eq!(dec.height, 100);
        assert_eq!(dec.nonce, 42);
    }

    #[test]
    fn test_version_rejects_short() {
        assert!(VersionMessage::decode(&[0u8; 31]).is_err());
    }

    #[test]
    fn test_ping_roundtrip() {
        let p = PingMessage { nonce: 999 };
        let enc = p.encode();
        let dec = PingMessage::decode(&enc).unwrap();
        assert_eq!(dec.nonce, 999);
    }

    #[test]
    fn test_ping_rejects_short() {
        assert!(PingMessage::decode(&[0u8; 7]).is_err());
    }

    #[test]
    fn test_getheaders_roundtrip() {
        let gh = GetHeadersMessage {
            start_hash: Hash::blake3(b"start"),
            stop_hash: Hash::blake3(b"stop"),
        };
        let enc = gh.encode();
        let dec = GetHeadersMessage::decode(&enc).unwrap();
        assert_eq!(dec.start_hash, gh.start_hash);
        assert_eq!(dec.stop_hash, gh.stop_hash);
    }

    #[test]
    fn test_inv_roundtrip() {
        let inv = InvMessage {
            inventory: vec![
                InvEntry {
                    inv_type: InvType::Block,
                    hash: Hash::blake3(b"block1"),
                },
                InvEntry {
                    inv_type: InvType::Tx,
                    hash: Hash::blake3(b"tx1"),
                },
            ],
        };
        let enc = inv.encode();
        let dec = InvMessage::decode(&enc).unwrap();
        assert_eq!(dec.inventory.len(), 2);
        assert_eq!(dec.inventory[0].inv_type, InvType::Block);
        assert_eq!(dec.inventory[1].inv_type, InvType::Tx);
    }

    #[test]
    fn test_inv_empty() {
        let inv = InvMessage { inventory: vec![] };
        let enc = inv.encode();
        let dec = InvMessage::decode(&enc).unwrap();
        assert!(dec.inventory.is_empty());
    }

    #[test]
    fn test_getdata_roundtrip() {
        let gd = GetDataMessage {
            inventory: vec![InvEntry {
                inv_type: InvType::Block,
                hash: Hash::blake3(b"test"),
            }],
        };
        let enc = gd.encode();
        let dec = GetDataMessage::decode(&enc).unwrap();
        assert_eq!(dec.inventory.len(), 1);
    }

    #[test]
    fn test_reject_roundtrip() {
        let r = RejectMessage {
            message: "tx".to_string(),
            code: 0x01,
            reason: "bad sig".to_string(),
        };
        let enc = r.encode();
        let dec = RejectMessage::decode(&enc).unwrap();
        assert_eq!(dec.message, "tx");
        assert_eq!(dec.code, 0x01);
        assert_eq!(dec.reason, "bad sig");
    }

    #[test]
    fn test_reject_rejects_short() {
        assert!(RejectMessage::decode(&[0u8; 2]).is_err());
    }

    #[test]
    fn test_message_type_roundtrips() {
        for i in 0x01..=0x0E {
            let mt = MessageType::from_u8(i).unwrap();
            assert_eq!(MessageType::from_u8(mt as u8).unwrap(), mt);
        }
        assert!(MessageType::from_u8(0x00).is_err());
        assert!(MessageType::from_u8(0x0F).is_err());
    }

    #[test]
    fn test_inv_type_roundtrips() {
        assert_eq!(InvType::from_u8(0x01).unwrap(), InvType::Block);
        assert_eq!(InvType::from_u8(0x02).unwrap(), InvType::Tx);
        assert!(InvType::from_u8(0x00).is_err());
        assert!(InvType::from_u8(0x03).is_err());
    }

    #[test]
    fn test_multiple_messages_concatenated() {
        let m1 = Message::new(MessageType::Ping, PingMessage { nonce: 1 }.encode());
        let m2 = Message::new(MessageType::Pong, PingMessage { nonce: 2 }.encode());
        let mut buf = m1.encode();
        buf.extend_from_slice(&m2.encode());

        let (msg1, pos1) = Message::decode(&buf).unwrap();
        assert_eq!(msg1.msg_type, MessageType::Ping);
        let (msg2, pos2) = Message::decode(&buf[pos1..]).unwrap();
        assert_eq!(msg2.msg_type, MessageType::Pong);
        assert_eq!(pos1 + pos2, buf.len());
    }

    // ====================================================================
    // AUDIT 1: Network Magic Rejection Tests
    // ====================================================================

    const MAINNET_MAGIC: [u8; 4] = [0xC4, 0x48, 0x52, 0x4F];
    const REGTEST_MAGIC: [u8; 4] = [0xC4, 0x52, 0x54, 0x54];

    #[test]
    fn test_decode_with_magic_rejects_cross_network_mainnet_node_rejects_regtest() {
        let msg = Message::with_magic(MessageType::Ping, vec![1, 2, 3], REGTEST_MAGIC);
        let wire = msg.encode();

        let result = Message::decode_with_magic(&wire, MAINNET_MAGIC);
        assert!(result.is_err(), "mainnet node must reject regtest magic");
        let err = result.unwrap_err();
        assert!(
            format!("{}", err).contains("bad magic"),
            "error should mention bad magic, got: {}",
            err
        );
    }

    #[test]
    fn test_decode_with_magic_rejects_cross_network_regtest_node_rejects_mainnet() {
        let msg = Message::with_magic(MessageType::Ping, vec![4, 5, 6], MAINNET_MAGIC);
        let wire = msg.encode();

        let result = Message::decode_with_magic(&wire, REGTEST_MAGIC);
        assert!(result.is_err(), "regtest node must reject mainnet magic");
    }

    #[test]
    fn test_decode_with_magic_accepts_matching_network() {
        let msg = Message::with_magic(MessageType::Ping, vec![7, 8], MAINNET_MAGIC);
        let wire = msg.encode();
        let (decoded, consumed) = Message::decode_with_magic(&wire, MAINNET_MAGIC).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Ping);
        assert_eq!(decoded.payload, vec![7, 8]);
        assert_eq!(consumed, wire.len());

        let msg = Message::with_magic(MessageType::Pong, vec![9, 10], REGTEST_MAGIC);
        let wire = msg.encode();
        let (decoded, consumed) = Message::decode_with_magic(&wire, REGTEST_MAGIC).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Pong);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn test_decode_with_magic_preserves_wire_magic_in_message() {
        let msg = Message::with_magic(MessageType::Ping, vec![1], REGTEST_MAGIC);
        let wire = msg.encode();
        let (decoded, _) = Message::decode_with_magic(&wire, REGTEST_MAGIC).unwrap();
        assert_eq!(decoded.magic, REGTEST_MAGIC);
    }

    // ====================================================================
    // Allocation-DoS Tests: every length/count is validated BEFORE allocation
    // ====================================================================

    #[test]
    fn test_frame_rejects_huge_length_without_big_alloc() {
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(&REGTEST_MAGIC);
        header.push(MessageType::Block as u8);
        header.extend_from_slice(&1_000_000_000u32.to_le_bytes());
        header.extend_from_slice(&[0u8; 4]);
        assert_eq!(header.len(), HEADER_SIZE);
        let err = Message::decode_with_magic(&header, REGTEST_MAGIC).unwrap_err();
        assert!(
            format!("{}", err).contains("too large"),
            "must reject on length pre-check, got: {}",
            err
        );
    }

    #[test]
    fn test_frame_rejects_truncated_payload() {
        let mut buf = Vec::with_capacity(HEADER_SIZE + 10);
        buf.extend_from_slice(&REGTEST_MAGIC);
        buf.push(MessageType::Ping as u8);
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        buf.extend_from_slice(&[9u8; 10]);
        assert!(Message::decode_with_magic(&buf, REGTEST_MAGIC).is_err());
    }

    #[test]
    fn test_inv_rejects_count_over_limit() {
        let mut data = Vec::new();
        data.extend_from_slice(&((MAX_INV_ENTRIES + 1) as u32).to_le_bytes());
        let err = InvMessage::decode(&data).unwrap_err();
        assert!(
            format!("{}", err).contains("limit"),
            "must reject on count pre-check, got: {}",
            err
        );
    }

    #[test]
    fn test_inv_rejects_truncated_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.push(InvType::Tx as u8);
        data.extend_from_slice(&[0xABu8; 32]);
        assert!(InvMessage::decode(&data).is_err());
    }

    #[test]
    fn test_getdata_rejects_count_over_limit() {
        let mut data = Vec::new();
        data.extend_from_slice(&((MAX_INV_ENTRIES + 1) as u32).to_le_bytes());
        let err = GetDataMessage::decode(&data).unwrap_err();
        assert!(
            format!("{}", err).contains("limit"),
            "must reject on count pre-check, got: {}",
            err
        );
    }

    #[test]
    fn test_getdata_rejects_truncated_entries() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.push(InvType::Block as u8);
        data.extend_from_slice(&[0xCDu8; 32]);
        assert!(GetDataMessage::decode(&data).is_err());
    }

    #[test]
    fn test_follow_cap_bounds_work() {
        const {
            assert!(MAX_INV_FOLLOW <= 1000);
            assert!(MAX_INV_FOLLOW * 33 <= MAX_MESSAGE_SIZE);
        }
    }

    // ====================================================================
    // Deterministic fuzz: malformed input → clean rejection, never panic/OOM
    // ====================================================================

    /// Fixed-seed xorshift64: reproducible across runs, no harness needed.
    struct XorShift64(u64);

    impl XorShift64 {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    #[test]
    fn test_fuzz_decoders_reject_garbage_cleanly() {
        let mut rng = XorShift64(0x12345678_9ABCDEF0);
        for _ in 0..5000 {
            let len = (rng.next() % 300) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (rng.next() & 0xFF) as u8;
            }
            for magic in [MAGIC, TESTNET_MAGIC, REGTEST_MAGIC] {
                let _ = Message::decode_with_magic(&buf, magic);
            }
            let _ = InvMessage::decode(&buf);
            let _ = GetDataMessage::decode(&buf);
            let _ = VersionMessage::decode(&buf);
            let _ = PingMessage::decode(&buf);
            let _ = GetHeadersMessage::decode(&buf);
            let _ = RejectMessage::decode(&buf);
        }
    }

    #[test]
    fn test_fuzz_mutated_valid_messages_stay_safe() {
        let mut rng = XorShift64(0x0FEDCBA9_87654321);
        let valid_inv = InvMessage {
            inventory: vec![InvEntry {
                inv_type: InvType::Tx,
                hash: Hash::blake3(b"fuzz"),
            }],
        }
        .encode();
        let valid_frame = Message::with_magic(MessageType::Inv, valid_inv.clone(), MAGIC).encode();
        for _ in 0..2000 {
            let mut frame = valid_frame.clone();
            let flips = 1 + (rng.next() % 4) as usize;
            for _ in 0..flips {
                let pos = (rng.next() as usize) % frame.len();
                frame[pos] ^= 1u8 << (rng.next() % 8);
            }
            if let Ok((msg, consumed)) = Message::decode_with_magic(&frame, MAGIC) {
                assert_eq!(consumed, frame.len());
                assert_eq!(msg.magic, MAGIC);
            }
            // Mutate the inventory body.
            let mut body = valid_inv.clone();
            let pos = (rng.next() as usize) % body.len();
            body[pos] = body[pos].wrapping_add(1);
            // Either rejected or parsed without panic; if parsed, the count
            // prefix still bounds the allocation (implicit: no OOM in test).
            let _ = InvMessage::decode(&body);
        }
    }
}
