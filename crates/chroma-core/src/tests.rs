//! Unit Tests for chroma-core

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::constants::*;
    use crate::hash::{Hash, Hash160};
    use crate::serialize::*;
    use crate::types::*;
    use crate::u256::U256;

    #[test]
    fn test_constants() {
        assert_eq!(UNITS_PER_CHR, 1_000_000);
        assert_eq!(MAX_SUPPLY_UNITS, 100_000_000_000_000);
        assert_eq!(BLOCK_REWARD_UNITS, 1_000_000);
        assert_eq!(TARGET_BLOCK_TIME_SECS, 10);
        assert_eq!(DIFFICULTY_ADJUSTMENT_WINDOW, 10);
        assert_eq!(MAX_BLOCK_SIZE, 1_048_576);
        assert_eq!(MAX_TRANSACTION_SIZE, 65536);
        assert_eq!(RANDOMX_EPOCH_LENGTH, 1000);
        assert_eq!(RANDOMX_SEED_LAG, 100);
    }

    #[test]
    fn test_hash() {
        let h = Hash::blake3(b"test");
        assert_eq!(h.as_bytes().len(), 32);

        let h2 = Hash::blake3(b"test2");
        assert_ne!(h, h2);

        // Test hex encoding
        let hex_str = h.to_hex();
        assert_eq!(hex_str.len(), 64);
        let parsed = Hash::from_hex(&hex_str).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn test_hash160() {
        let h = Hash160::from_bytes([1u8; 20]);
        assert_eq!(h.as_bytes().len(), 20);

        let hex_str = h.to_hex();
        assert_eq!(hex_str.len(), 40);
        let parsed = Hash160::from_hex(&hex_str).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn test_leb128() {
        // Test encoding
        assert_eq!(encode_leb128(0), vec![0x00]);
        assert_eq!(encode_leb128(127), vec![0x7F]);
        assert_eq!(encode_leb128(128), vec![0x80, 0x01]);
        assert_eq!(encode_leb128(300), vec![0xAC, 0x02]);
        assert_eq!(encode_leb128(16383), vec![0xFF, 0x7F]);
        assert_eq!(encode_leb128(16384), vec![0x80, 0x80, 0x01]);

        // Test decoding
        assert_eq!(decode_leb128(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(decode_leb128(&[0x7F], 0).unwrap(), (127, 1));
        assert_eq!(decode_leb128(&[0x80, 0x01], 0).unwrap(), (128, 2));
        assert_eq!(decode_leb128(&[0xAC, 0x02], 0).unwrap(), (300, 2));
        assert_eq!(decode_leb128(&[0xFF, 0x7F], 0).unwrap(), (16383, 2));
        assert_eq!(decode_leb128(&[0x80, 0x80, 0x01], 0).unwrap(), (16384, 3));

        // Test max u64
        let max = u64::MAX;
        let encoded = encode_leb128(max);
        let (decoded, _) = decode_leb128(&encoded, 0).unwrap();
        assert_eq!(decoded, max);
    }

    #[test]
    fn test_bytes_leb128() {
        let data = vec![1u8, 2, 3, 4, 5];
        let encoded = encode_bytes_leb128(&data);
        let (decoded, _) = decode_bytes_leb128(&encoded, 0).unwrap();
        assert_eq!(data, decoded);

        // Empty
        let empty = vec![];
        let encoded = encode_bytes_leb128(&empty);
        let (decoded, _) = decode_bytes_leb128(&encoded, 0).unwrap();
        assert_eq!(empty, decoded);
    }

    #[test]
    fn test_canonical_primitives() {
        // u8
        assert_eq!(u8::encode(&0xFF), vec![0xFF]);
        assert_eq!(u8::decode(&[0x42]).unwrap(), 0x42);

        // u16
        assert_eq!(0x1234u16.encode(), vec![0x34, 0x12]); // little-endian
        assert_eq!(u16::decode(&[0x34, 0x12]).unwrap(), 0x1234);

        // u32
        assert_eq!(0x12345678u32.encode(), vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(u32::decode(&[0x78, 0x56, 0x34, 0x12]).unwrap(), 0x12345678);

        // u64
        assert_eq!(
            0x123456789ABCDEFu64.encode(),
            vec![0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]
        );
        assert_eq!(
            u64::decode(&[0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]).unwrap(),
            0x123456789ABCDEF
        );

        // u128
        let val = 0x123456789ABCDEF0123456789ABCDEFu128;
        let encoded = val.encode();
        assert_eq!(u128::decode(&encoded).unwrap(), val);

        // bool
        assert_eq!(true.encode(), vec![0x01]);
        assert_eq!(false.encode(), vec![0x00]);
        assert!(bool::decode(&[0x01]).unwrap());
        assert!(!bool::decode(&[0x00]).unwrap());
        assert!(bool::decode(&[0x02]).is_err());
    }

    #[test]
    fn test_vec_u8() {
        let v = vec![1u8, 2, 3];
        let encoded = v.encode();
        let decoded = Vec::<u8>::decode(&encoded).unwrap();
        assert_eq!(v, decoded);

        // Check LEB128 length prefix
        assert_eq!(encoded[0], 3); // length 3
        assert_eq!(&encoded[1..], &[1u8, 2, 3]);
    }

    #[test]
    fn test_string() {
        let s = "hello chroma".to_string();
        let encoded = s.encode();
        let decoded = String::decode(&encoded).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn test_block_height() {
        let h = BlockHeight::new(12345);
        let encoded = h.encode();
        let decoded = BlockHeight::decode(&encoded).unwrap();
        assert_eq!(h, decoded);

        // GENESIS
        let genesis = BlockHeight::GENESIS;
        assert_eq!(genesis.0, 0);
    }

    #[test]
    fn test_amount() {
        let a = Amount::new(1_000_000); // 1 CHR
        assert_eq!(u64::from(a), 1_000_000);

        let b = Amount::new(500_000); // 0.5 CHR
        let sum = a.checked_add(b).unwrap();
        assert_eq!(u64::from(sum), 1_500_000);

        // Overflow check (u64 limit)
        let max_u64 = Amount::new(u64::MAX);
        assert!(max_u64.checked_add(Amount::new(1)).is_none());

        // Supply invariant check
        let max_supply = Amount::MAX_SUPPLY;
        assert_eq!(u64::from(max_supply), 100_000_000_000_000);

        // Underflow check
        let zero = Amount::ZERO;
        assert!(zero.checked_sub(Amount::new(1)).is_none());

        // Canonical encode/decode
        let encoded = a.encode();
        let decoded = Amount::decode(&encoded).unwrap();
        assert_eq!(a, decoded);
    }

    #[test]
    fn test_nonce() {
        let n = Nonce::new(42);
        assert_eq!(n.next().unwrap(), Nonce::new(43));
        assert_eq!(Nonce::ZERO.next().unwrap(), Nonce::new(1));

        // Encode/decode
        let encoded = n.encode();
        let decoded = Nonce::decode(&encoded).unwrap();
        assert_eq!(n, decoded);
    }

    #[test]
    fn test_network_id() {
        let encoded = NetworkId::Mainnet.encode();
        assert_eq!(encoded, vec![2u8]);

        let decoded = NetworkId::decode(&[2u8]).unwrap();
        assert_eq!(decoded, NetworkId::Mainnet);

        assert!(NetworkId::decode(&[3u8]).is_err());
    }

    #[test]
    fn test_address() {
        let h = Hash160::from_bytes([0x42u8; 20]);
        let addr = Address::from_hash160(h);

        let encoded = addr.encode();
        assert_eq!(encoded.len(), 20);

        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_compact_target() {
        // Test difficulty 1
        let bits = CompactTarget::DIFFICULTY_1;
        let target = bits.to_full_target();
        let _ = target;
        assert_eq!(bits.0, 0x1d00ffff);

        // Encode/decode
        let encoded = bits.encode();
        assert_eq!(encoded.len(), 4);
        let decoded = CompactTarget::decode(&encoded).unwrap();
        assert_eq!(bits, decoded);
    }

    #[test]
    fn test_difficulty_from_bits() {
        // DIFFICULTY_1 bits → difficulty should be 1
        let d1 = Difficulty::from_bits(CompactTarget::DIFFICULTY_1);
        assert_eq!(d1, Difficulty(1));

        // Verify determinism
        let d1_again = Difficulty::from_bits(CompactTarget::DIFFICULTY_1);
        assert_eq!(d1, d1_again);

        // Larger exponent = easier target = lower difficulty
        let d_30 = Difficulty::from_bits(CompactTarget(0x1e00ffff));
        assert!(d_30.0 < d1.0, "exponent 30 = easier than exponent 29");

        // Slightly smaller mantissa = slightly smaller target = slightly higher difficulty
        let d_harder = Difficulty::from_bits(CompactTarget(0x1d00fffd));
        let d_easy = Difficulty::from_bits(CompactTarget(0x1d010000));
        assert!(
            d_harder.0 >= d1.0,
            "d_harder={d_harder:?} should be >= d1={d1:?}"
        );
        assert!(d_easy.0 <= d1.0, "d_easy={d_easy:?} should be <= d1={d1:?}");
    }

    #[test]
    fn test_roundtrip_u8() {
        for v in [0u8, 1, 127, 128, 255] {
            let encoded = v.encode();
            assert_eq!(u8::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn test_roundtrip_u16() {
        for v in [0u16, 1, 0xFF, 0x0100, 0xFFFF] {
            let encoded = v.encode();
            assert_eq!(u16::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn test_roundtrip_u32() {
        for v in [0u32, 1, 0xFF, 0x0100, 0x010000, 0xFFFFFFFF] {
            let encoded = v.encode();
            assert_eq!(u32::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn test_roundtrip_u64() {
        for v in [
            0u64,
            1,
            0xFF,
            0x0100,
            0x010000,
            0x01000000,
            0xFFFFFFFFFFFFFFFF,
        ] {
            let encoded = v.encode();
            assert_eq!(u64::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn test_roundtrip_bool() {
        for v in [true, false] {
            let encoded = v.encode();
            assert_eq!(bool::decode(&encoded).unwrap(), v);
        }
    }

    #[test]
    fn test_compact_target_roundtrip() {
        let cases = [
            CompactTarget::DIFFICULTY_1,
            CompactTarget(0x1d00ffff),
            CompactTarget(0x1e00ffff),
            CompactTarget(0x1d00fffe),
            CompactTarget(0x1d010000),
            CompactTarget(0x00000000),
        ];
        for bits in cases {
            let target = bits.to_full_target();
            let recovered = CompactTarget::from_full_target(&target);
            assert_eq!(bits, recovered, "roundtrip failed for bits={:08x}", bits.0);
        }
    }

    #[test]
    fn test_compact_target_difficulty_1_target() {
        let target = CompactTarget::DIFFICULTY_1.to_full_target();
        // CompactTarget(0x1d00ffff): exponent=29, mantissa=0x00ffff
        // shift_bytes = 26, target placed at bytes [3..5] = [0x00, 0xff, 0xff]
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // Other bytes should be zero
        assert_eq!(target[0], 0x00);
        assert_eq!(target[31], 0x00);
    }

    #[test]
    fn test_difficulty_from_bits_genesis() {
        let d = Difficulty::from_bits(CompactTarget::DIFFICULTY_1);
        assert_eq!(d, Difficulty(1));
    }

    #[test]
    fn test_difficulty_from_bits_zero_target() {
        // Zero target → max difficulty
        let d = Difficulty::from_bits(CompactTarget(0));
        assert_eq!(d.0, u64::MAX);
    }

    #[test]
    fn test_difficulty_ordering() {
        // Larger exponent = easier target = lower difficulty
        let d_30 = Difficulty::from_bits(CompactTarget(0x1e00ffff));
        let d_29 = Difficulty::from_bits(CompactTarget(0x1d00ffff));
        assert!(d_30 < d_29, "exponent 30 should be easier than 29");

        // Smaller mantissa = smaller target = higher difficulty
        let d_harder = Difficulty::from_bits(CompactTarget(0x1d00fffd));
        let d_easier = Difficulty::from_bits(CompactTarget(0x1d010000));
        assert!(d_harder >= d_easier);
    }

    #[test]
    fn test_u256_from_to_be_bytes_roundtrip() {
        let cases = [
            U256::ZERO,
            U256::ONE,
            U256::from_u64(42),
            U256::from_u64(u64::MAX),
            U256::MAX,
        ];
        for val in cases {
            let bytes = val.to_be_bytes();
            let recovered = U256::from_be_bytes(&bytes);
            assert_eq!(val, recovered, "U256 roundtrip failed for {:?}", val);
        }
    }

    #[test]
    fn test_u256_leading_zeros() {
        assert_eq!(U256::ZERO.leading_zeros(), 256);
        assert_eq!(U256::ONE.leading_zeros(), 255);
        assert_eq!(U256::from_u64(0x80).leading_zeros(), 248);
        assert_eq!(U256::MAX.leading_zeros(), 0);
    }

    #[test]
    fn test_u256_is_zero() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::ONE.is_zero());
        assert!(!U256::from_u64(1).is_zero());
    }

    #[test]
    fn test_u256_div_rem() {
        let a = U256::from_u64(10);
        let b = U256::from_u64(3);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, U256::from_u64(3));
        assert_eq!(r, U256::from_u64(1));
    }

    /// MAXIMUM_TARGET boundary, reconstructed byte-exact:
    /// bytes [00, 03, FF, FF, C0, 00×27] (~4× genesis target).
    fn maximum_target_bytes() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[1] = 0x03;
        t[2] = 0xFF;
        t[3] = 0xFF;
        t[4] = 0xC0;
        t
    }

    #[test]
    fn test_compact_maximum_target_boundary() {
        let max = maximum_target_bytes();
        let max_u = U256::from_be_bytes(&max);
        // Canonical compact of the boundary value.
        assert_eq!(
            CompactTarget::from_full_target(&max),
            CompactTarget(0x1F03FFFF)
        );
        // Precision absorption: MAX±1 (5th byte C0→C1/BF, below mantissa
        // resolution) map to the same compact. Documented Bitcoin-style
        // behavior — consensus compares full U256 values, never compacts.
        let mut plus = max;
        plus[4] = 0xC1;
        assert_eq!(
            CompactTarget::from_full_target(&plus),
            CompactTarget(0x1F03FFFF)
        );
        let mut minus = max;
        minus[4] = 0xBF;
        assert_eq!(
            CompactTarget::from_full_target(&minus),
            CompactTarget(0x1F03FFFF)
        );
        // Just below / above as full values: canonical compacts straddle it.
        let below_full = CompactTarget(0x1F03FFFF).to_full_target();
        assert!(U256::from_be_bytes(&below_full) <= max_u);
        let above_full = CompactTarget(0x1F04FFFF).to_full_target();
        assert!(U256::from_be_bytes(&above_full) > max_u);
        // Roundtrip of the boundary compact is lossy in sub-mantissa bytes
        // (C0→00) — pinned, pre-existing behavior, harmless because the
        // retarget hold compares numeric targets and returns header bits
        // verbatim instead of roundtripping them.
        let rt = CompactTarget::from_full_target(&CompactTarget(0x1F03FFFF).to_full_target());
        assert_eq!(rt, CompactTarget(0x1F03FFFF));
    }

    #[test]
    fn test_compact_edge_values() {
        // Zero / underflowing mantissas denote the zero target.
        assert_eq!(CompactTarget(0).to_full_target(), [0u8; 32]);
        assert_eq!(CompactTarget(0x00000001).to_full_target(), [0u8; 32]);
        assert_eq!(CompactTarget(0x01003456).to_full_target(), [0u8; 32]);
        // Small exponents place small values at the tail (big-endian).
        let mut tail = [0u8; 32];
        tail[31] = 0xFF;
        assert_eq!(CompactTarget(0x0200FFFF).to_full_target(), tail);
        let mut tail2 = [0u8; 32];
        tail2[30] = 0xFF;
        tail2[31] = 0xFF;
        assert_eq!(CompactTarget(0x0300FFFF).to_full_target(), tail2);
        // Non-canonical MSB-set mantissa: to_full is literal, from_full
        // canonicalizes (size bump). Validation compares header bits exactly
        // and PoW uses to_full of those same bits, so this is self-consistent.
        let full = CompactTarget(0x1DFFFFFF).to_full_target();
        assert_eq!(&full[3..6], &[0xFF, 0xFF, 0xFF]);
        assert_eq!(
            CompactTarget::from_full_target(&full),
            CompactTarget(0x1E00FFFF)
        );
        // Saturating exponents denote the maximum target.
        assert_eq!(CompactTarget(0x2100FFFF).to_full_target(), [0xFF; 32]);
        assert_eq!(CompactTarget(0xFF123456).to_full_target(), [0xFF; 32]);
        // Canonical encode/decode roundtrip for boundary compacts.
        for raw in [
            0x00000000u32,
            0x1D00FFFF,
            0x1F03FFFF,
            0x1F04FFFF,
            0x20FFFFFF,
            0x2100FFFF,
            0xFFFFFFFF,
        ] {
            let bits = CompactTarget(raw);
            assert_eq!(CompactTarget::decode(&bits.encode()).unwrap(), bits);
        }
    }

    #[test]
    fn test_compact_order_matches_numeric_for_canonical() {
        // For canonical compacts, u32 ordering agrees with numeric target
        // ordering. Non-canonical encodings (MSB-set mantissa without size
        // bump) are the only divergence — which is why consensus always
        // converts to full U256 targets before comparing.
        let canonical = [
            CompactTarget(0x1700FFFF),
            CompactTarget(0x1C00FFFF),
            CompactTarget(0x1D00FFFE),
            CompactTarget(0x1D00FFFF),
            CompactTarget(0x1D010000),
            CompactTarget(0x1E00FFFF),
            CompactTarget(0x1E0FFFFF),
            CompactTarget(0x1F03FFFF),
            CompactTarget(0x1F04FFFF),
            CompactTarget(0x2002D82D),
            CompactTarget(0x20FFFFFF),
        ];
        for pair in canonical.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            assert!(a.0 < b.0);
            let fa = U256::from_be_bytes(&a.to_full_target());
            let fb = U256::from_be_bytes(&b.to_full_target());
            assert!(
                fa < fb,
                "order inversion: {:08x} < {:08x} but targets disagree",
                a.0,
                b.0
            );
        }
    }

    #[test]
    fn test_u256_shl() {
        let a = U256::from_u64(1);
        assert_eq!(a.shl(1), U256::from_u64(2));
        assert_eq!(a.shl(64), U256([0, 1, 0, 0]));
        assert_eq!(a.shl(128), U256([0, 0, 1, 0]));
        assert_eq!(a.shl(255), {
            let mut v = [0u64; 4];
            v[3] = 1u64 << 63;
            U256(v)
        });
    }

    #[test]
    fn test_u256_shr() {
        // U256([0, 0, 1, 0]) = 2^128
        let a = U256([0, 0, 1, 0]);
        // 2^128 >> 64 = 2^64 = U256([0, 1, 0, 0])
        assert_eq!(a.shr(64), U256([0, 1, 0, 0]));
        // 2^128 >> 128 = 1 = U256([1, 0, 0, 0])
        assert_eq!(a.shr(128), U256::from_u64(1));
        // 2^128 >> 256 = 0
        assert_eq!(a.shr(256), U256::ZERO);
        // 2 * 2^128 >> 1 = 2^128
        let b = U256([0, 0, 2, 0]);
        assert_eq!(b.shr(1), a);
    }

    #[test]
    fn test_u256_wrapping_add() {
        let a = U256::from_u64(42);
        let b = U256::from_u64(58);
        assert_eq!(a.wrapping_add(&b), U256::from_u64(100));

        // Overflow wraps
        let max = U256::MAX;
        assert_eq!(max.wrapping_add(&U256::ONE), U256::ZERO);
    }

    #[test]
    fn test_u256_with_bit_set() {
        let a = U256::ZERO.with_bit_set(0);
        assert_eq!(a, U256::ONE);

        let a2 = U256::ZERO.with_bit_set(64);
        assert_eq!(a2, U256([0, 1, 0, 0]));

        let a3 = U256::ZERO.with_bit_set(255);
        assert_eq!(a3.0[3], 1u64 << 63);
    }

    #[test]
    fn test_nonce_next() {
        assert_eq!(Nonce::ZERO.next().unwrap(), Nonce(1));
        assert_eq!(Nonce(100).next().unwrap(), Nonce(101));
        assert!(Nonce(u64::MAX).next().is_none());
    }

    #[test]
    fn test_amount_arithmetic() {
        let a = Amount(500_000);
        let b = Amount(500_000);
        assert_eq!(a.checked_add(b).unwrap(), Amount(1_000_000));
        assert!(a.checked_sub(b).unwrap() == Amount(0));
        assert!(Amount(100).checked_sub(Amount(200)).is_none());
    }

    #[test]
    fn test_network_id_all_variants() {
        for (id, expected_byte) in [
            (NetworkId::Devnet, 0u8),
            (NetworkId::Testnet, 1),
            (NetworkId::Mainnet, 2),
        ] {
            assert_eq!(id.encode(), vec![expected_byte]);
            assert_eq!(NetworkId::decode(&[expected_byte]).unwrap(), id);
        }
    }

    #[test]
    fn test_network_id_invalid() {
        assert!(NetworkId::decode(&[3u8]).is_err());
        assert!(NetworkId::decode(&[100u8]).is_err());
    }

    #[test]
    fn test_amount_max_supply() {
        let max = Amount::MAX_SUPPLY;
        assert_eq!(max.0, 100_000_000_000_000);
    }

    #[test]
    fn test_address_roundtrip() {
        let h = Hash160::from_bytes([0x42u8; 20]);
        let addr = Address::from_hash160(h);
        let encoded = addr.encode();
        let decoded = Address::decode(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_different_values_different() {
        let a1 = Address::from_hash160(Hash160([0u8; 20]));
        let a2 = Address::from_hash160(Hash160([1u8; 20]));
        assert_ne!(a1, a2);
    }

    #[test]
    fn test_address_bech32_roundtrip() {
        let h = Hash160::from_bytes([0x42u8; 20]);
        let addr = Address::from_hash160(h);
        let bech32_str = addr.to_bech32();
        assert!(bech32_str.starts_with("chr1"), "should start with chr1");
        let decoded = Address::from_bech32(&bech32_str).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_address_display_is_bech32() {
        let h = Hash160::from_bytes([0xABu8; 20]);
        let addr = Address::from_hash160(h);
        let display = format!("{}", addr);
        assert!(
            display.starts_with("chr1"),
            "display should be bech32: {}",
            display
        );
    }

    #[test]
    fn test_address_from_str_bech32() {
        use std::str::FromStr;
        let h = Hash160::from_bytes([0xCDu8; 20]);
        let addr = Address::from_hash160(h);
        let bech32_str = addr.to_bech32();
        let parsed = Address::from_str(&bech32_str).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_address_from_str_hex() {
        use std::str::FromStr;
        let hex_str = "0x4242424242424242424242424242424242424242";
        let parsed = Address::from_str(hex_str).unwrap();
        assert_eq!(parsed.0 .0, [0x42u8; 20]);
    }

    #[test]
    fn test_address_from_str_hex_no_prefix() {
        use std::str::FromStr;
        let hex_str = "4242424242424242424242424242424242424242";
        let parsed = Address::from_str(hex_str).unwrap();
        assert_eq!(parsed.0 .0, [0x42u8; 20]);
    }

    #[test]
    fn test_address_from_bech32_wrong_hrp() {
        let result = Address::from_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(result.is_err(), "wrong HRP should fail");
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = Hash::blake3(b"test");
        let h2 = Hash::blake3(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = Hash::blake3(b"test1");
        let h2 = Hash::blake3(b"test2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash160_roundtrip() {
        let h = Hash160::from_bytes([0xABu8; 20]);
        let hex_str = h.to_hex();
        let parsed = Hash160::from_hex(&hex_str).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn test_leb128_edge_cases() {
        // Test max value
        let max = u64::MAX;
        let encoded = encode_leb128(max);
        assert_eq!(encoded.len(), 10);
        let (decoded, _) = decode_leb128(&encoded, 0).unwrap();
        assert_eq!(decoded, max);

        // Test boundary values
        let boundary = 128u64;
        let encoded = encode_leb128(boundary);
        assert_eq!(encoded, vec![0x80, 0x01]);
    }

    #[test]
    fn test_strict_decode_rejects_trailing_u16() {
        assert!(u16::decode(&[0x34, 0x12, 0xFF]).is_err());
        assert!(u16::decode(&[0x34]).is_err());
    }

    #[test]
    fn test_strict_decode_rejects_trailing_u32() {
        assert!(u32::decode(&[0x78, 0x56, 0x34, 0x12, 0xFF]).is_err());
        assert!(u32::decode(&[0x78, 0x56]).is_err());
    }

    #[test]
    fn test_strict_decode_rejects_trailing_u64() {
        let data = 0x123456789ABCDEFu64.encode();
        let mut with_trailing = data.clone();
        with_trailing.push(0xFF);
        assert!(u64::decode(&with_trailing).is_err());
        assert!(u64::decode(&data[..4]).is_err());
    }

    #[test]
    fn test_strict_decode_rejects_trailing_u128() {
        let val = 0x123456789ABCDEF0123456789ABCDEFu128;
        let mut with_trailing = val.encode();
        with_trailing.push(0xFF);
        assert!(u128::decode(&with_trailing).is_err());
        assert!(u128::decode(&val.encode()[..8]).is_err());
    }

    #[test]
    fn test_strict_decode_rejects_trailing_bool() {
        assert!(bool::decode(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn test_strict_decode_exact_sizes() {
        // All primitive decoders reject wrong sizes
        assert!(u16::decode(&[]).is_err());
        assert!(u16::decode(&[0x01]).is_err());
        assert!(u16::decode(&[0x01, 0x02, 0x03]).is_err());

        assert!(u32::decode(&[]).is_err());
        assert!(u32::decode(&[0x01, 0x02, 0x03]).is_err());
        assert!(u32::decode(&[0x01, 0x02, 0x03, 0x04, 0x05]).is_err());

        assert!(u64::decode(&[0u8; 7]).is_err());
        assert!(u64::decode(&[0u8; 9]).is_err());
    }
}
