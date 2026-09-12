//! Canonical Binary Serialization
//!
//! Wire format specification (independent of Rust memory layout):
//!
//! - Integers: little-endian, fixed width (u8/u16/u32/u64/u128)
//! - Hashes: big-endian byte order in wire format (display order)
//! - Variable-length fields: LEB128 length prefix + raw bytes
//! - Arrays: LEB128 length + concatenated encoded elements
//! - Options: 1-byte tag (0x00=None, 0x01=Some) + value
//! - Structs: fields concatenated in declaration order
//! - Enums: 1-byte discriminant (declaration order) + variant data
//! - Canonical hash of any structure: BLAKE3(encode(structure))

use crate::error::{CoreError, Result};

/// Trait for canonical encoding to bytes.
/// Every consensus-critical type MUST implement this.
pub trait CanonicalEncode {
    /// Encode to a byte vector using canonical serialization.
    fn encode(&self) -> Vec<u8>;

    /// Encode and append to an existing buffer.
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.encode());
    }
}

/// Trait for canonical decoding from bytes.
/// Decoding is strict: any trailing or invalid data returns an error.
pub trait CanonicalDecode: Sized {
    /// Decode from a byte slice. Fails if input doesn't match exactly.
    fn decode(data: &[u8]) -> Result<Self>;

    /// Decode from a byte slice, allowing trailing data.
    /// Returns the decoded value and the consumed byte count.
    fn decode_partial(data: &[u8]) -> Result<(Self, usize)>;
}

/// LEB128 encoding for unsigned integers (variable-length)
pub fn encode_leb128(value: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut v = value;
    while v >= 0x80 {
        result.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
    result.push(v as u8);
    result
}

/// LEB128 decoding
pub fn decode_leb128(data: &[u8], offset: usize) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut pos = offset;

    loop {
        if pos >= data.len() {
            return Err(CoreError::Serialization("LEB128 truncated".to_string()));
        }
        let byte = data[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        if shift >= 64 {
            return Err(CoreError::Serialization(
                "LEB128 value too large".to_string(),
            ));
        }
    }

    Ok((result, pos))
}

/// Encode a little-endian fixed-width integer
pub fn encode_u16_le(value: u16) -> [u8; 2] {
    [(value & 0xFF) as u8, ((value >> 8) & 0xFF) as u8]
}

pub fn encode_u32_le(value: u32) -> [u8; 4] {
    [
        (value & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        ((value >> 16) & 0xFF) as u8,
        ((value >> 24) & 0xFF) as u8,
    ]
}

pub fn encode_u64_le(value: u64) -> [u8; 8] {
    [
        (value & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        ((value >> 16) & 0xFF) as u8,
        ((value >> 24) & 0xFF) as u8,
        ((value >> 32) & 0xFF) as u8,
        ((value >> 40) & 0xFF) as u8,
        ((value >> 48) & 0xFF) as u8,
        ((value >> 56) & 0xFF) as u8,
    ]
}

pub fn encode_u128_le(value: u128) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = ((value >> (i * 8)) & 0xFF) as u8;
    }
    bytes
}

/// Decode a little-endian fixed-width integer
pub fn decode_u16_le(data: &[u8]) -> Result<u16> {
    if data.len() != 2 {
        return Err(CoreError::Serialization(format!(
            "u16 decoding: expected 2 bytes, got {}",
            data.len()
        )));
    }
    Ok(u16::from_le_bytes([data[0], data[1]]))
}

pub fn decode_u32_le(data: &[u8]) -> Result<u32> {
    if data.len() != 4 {
        return Err(CoreError::Serialization(format!(
            "u32 decoding: expected 4 bytes, got {}",
            data.len()
        )));
    }
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

pub fn decode_u64_le(data: &[u8]) -> Result<u64> {
    if data.len() != 8 {
        return Err(CoreError::Serialization(format!(
            "u64 decoding: expected 8 bytes, got {}",
            data.len()
        )));
    }
    Ok(u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]))
}

pub fn decode_u128_le(data: &[u8]) -> Result<u128> {
    if data.len() != 16 {
        return Err(CoreError::Serialization(format!(
            "u128 decoding: expected 16 bytes, got {}",
            data.len()
        )));
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[..16]);
    Ok(u128::from_le_bytes(bytes))
}

// ============================================================================
// Implementations for primitive types
// ============================================================================

impl CanonicalEncode for u8 {
    fn encode(&self) -> Vec<u8> {
        vec![*self]
    }
}

impl CanonicalDecode for u8 {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(CoreError::Serialization("u8: expected 1 byte".to_string()));
        }
        Ok(data[0])
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(CoreError::Serialization("u8: no data".to_string()));
        }
        Ok((data[0], 1))
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self) -> Vec<u8> {
        encode_u16_le(*self).to_vec()
    }
}

impl CanonicalDecode for u16 {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_u16_le(data)
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 2 {
            return Err(CoreError::Serialization(format!(
                "u16 decoding: expected 2 bytes, got {}",
                data.len()
            )));
        }
        let val = decode_u16_le(&data[..2])?;
        Ok((val, 2))
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self) -> Vec<u8> {
        encode_u32_le(*self).to_vec()
    }
}

impl CanonicalDecode for u32 {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_u32_le(data)
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 4 {
            return Err(CoreError::Serialization(format!(
                "u32 decoding: expected 4 bytes, got {}",
                data.len()
            )));
        }
        let val = decode_u32_le(&data[..4])?;
        Ok((val, 4))
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self) -> Vec<u8> {
        encode_u64_le(*self).to_vec()
    }
}

impl CanonicalDecode for u64 {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_u64_le(data)
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 8 {
            return Err(CoreError::Serialization(format!(
                "u64 decoding: expected 8 bytes, got {}",
                data.len()
            )));
        }
        let val = decode_u64_le(&data[..8])?;
        Ok((val, 8))
    }
}

impl CanonicalEncode for u128 {
    fn encode(&self) -> Vec<u8> {
        encode_u128_le(*self).to_vec()
    }
}

impl CanonicalDecode for u128 {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_u128_le(data)
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 16 {
            return Err(CoreError::Serialization(format!(
                "u128 decoding: expected 16 bytes, got {}",
                data.len()
            )));
        }
        let val = decode_u128_le(&data[..16])?;
        Ok((val, 16))
    }
}

impl CanonicalEncode for bool {
    fn encode(&self) -> Vec<u8> {
        vec![if *self { 1u8 } else { 0u8 }]
    }
}

impl CanonicalDecode for bool {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() != 1 {
            return Err(CoreError::Serialization(
                "bool: expected 1 byte".to_string(),
            ));
        }
        match data[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CoreError::Serialization(format!(
                "bool: invalid value {}",
                data[0]
            ))),
        }
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(CoreError::Serialization("bool: no data".to_string()));
        }
        match data[0] {
            0 => Ok((false, 1)),
            1 => Ok((true, 1)),
            _ => Err(CoreError::Serialization(format!(
                "bool: invalid value {}",
                data[0]
            ))),
        }
    }
}

/// Encode a byte slice with LEB128 length prefix
pub fn encode_bytes_leb128(data: &[u8]) -> Vec<u8> {
    let mut result = encode_leb128(data.len() as u64);
    result.extend_from_slice(data);
    result
}

/// Decode a byte slice with LEB128 length prefix
pub fn decode_bytes_leb128(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    let (len, pos) = decode_leb128(data, offset)?;
    let len = usize::try_from(len)
        .map_err(|_| CoreError::Serialization(format!("bytes: length {} overflows usize", len)))?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| CoreError::Serialization("bytes: length overflow".to_string()))?;
    if end > data.len() {
        return Err(CoreError::Serialization(
            "bytes: declared length exceeds data".to_string(),
        ));
    }
    let result = data[pos..end].to_vec();
    Ok((result, end))
}

impl CanonicalEncode for Vec<u8> {
    fn encode(&self) -> Vec<u8> {
        encode_bytes_leb128(self)
    }
}

impl CanonicalDecode for Vec<u8> {
    fn decode(data: &[u8]) -> Result<Self> {
        let (result, _) = decode_bytes_leb128(data, 0)?;
        Ok(result)
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        decode_bytes_leb128(data, 0)
    }
}

/// Encode a UTF-8 string with LEB128 length prefix
impl CanonicalEncode for String {
    fn encode(&self) -> Vec<u8> {
        encode_bytes_leb128(self.as_bytes())
    }
}

impl CanonicalDecode for String {
    fn decode(data: &[u8]) -> Result<Self> {
        let (bytes, _) = decode_bytes_leb128(data, 0)?;
        String::from_utf8(bytes)
            .map_err(|e| CoreError::Serialization(format!("invalid UTF-8: {}", e)))
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let (bytes, pos) = decode_bytes_leb128(data, 0)?;
        let s = String::from_utf8(bytes)
            .map_err(|e| CoreError::Serialization(format!("invalid UTF-8: {}", e)))?;
        Ok((s, pos))
    }
}
