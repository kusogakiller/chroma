//! Minimal 256-bit unsigned integer for difficulty/work calculations.
//!
//! Internal representation: [u64; 4] in little-endian limb order (limb 0 = lowest 64 bits).

/// A 256-bit unsigned integer stored as four little-endian u64 limbs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0, 0, 0, 0]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    pub const fn from_u64(v: u64) -> Self {
        U256([v, 0, 0, 0])
    }

    /// Construct from a big-endian 32-byte array.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let base = (3 - i) * 8;
            *limb = u64::from_be_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
                bytes[base + 4],
                bytes[base + 5],
                bytes[base + 6],
                bytes[base + 7],
            ]);
        }
        U256(limbs)
    }

    /// Convert to a big-endian 32-byte array.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let be = self.0[3 - i].to_be_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&be);
        }
        bytes
    }

    /// Count leading zero bits (0..=256).
    pub fn leading_zeros(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return ((3 - i) as u32) * 64 + self.0[i].leading_zeros();
            }
        }
        256
    }

    pub fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    pub fn to_u64(&self) -> Option<u64> {
        if self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0 {
            Some(self.0[0])
        } else {
            None
        }
    }

    /// Shift left by `n` bits. If n >= 256, returns ZERO.
    pub fn shl(&self, n: u32) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        if n == 0 {
            return *self;
        }
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let mut result = [0u64; 4];
        for i in 0..4 {
            if i + limb_shift < 4 {
                result[i + limb_shift] |= self.0[i] << bit_shift;
            }
            if bit_shift > 0 && i + limb_shift + 1 < 4 {
                result[i + limb_shift + 1] |= self.0[i] >> (64 - bit_shift);
            }
        }
        U256(result)
    }

    /// Shift right by `n` bits.
    #[allow(clippy::needless_range_loop)]
    pub fn shr(&self, n: u32) -> U256 {
        if n >= 256 {
            return U256::ZERO;
        }
        if n == 0 {
            return *self;
        }
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        let mut r = [0u64; 4];
        for i in 0..(4 - limb_shift) {
            r[i] = self.0[i + limb_shift] >> bit_shift;
            if bit_shift > 0 && (i + limb_shift + 1) < 4 {
                r[i] |= self.0[i + limb_shift + 1] << (64 - bit_shift);
            }
        }
        U256(r)
    }

    /// self - other, wrapping (assumes self >= other for correct results).
    #[allow(clippy::needless_range_loop)]
    pub fn wrapping_sub(&self, other: &U256) -> U256 {
        let mut result = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (diff1, overflow1) = self.0[i].overflowing_sub(other.0[i]);
            let (diff2, overflow2) = diff1.overflowing_sub(borrow as u64);
            result[i] = diff2;
            borrow = overflow1 || overflow2;
        }
        U256(result)
    }

    /// self + other, wrapping.
    #[allow(clippy::needless_range_loop)]
    pub fn wrapping_add(&self, other: &U256) -> U256 {
        let mut result = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        U256(result)
    }

    /// self + other, returning None on overflow.
    #[allow(clippy::needless_range_loop)]
    pub fn checked_add(&self, other: &U256) -> Option<U256> {
        let mut result = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        if carry > 0 {
            None
        } else {
            Some(U256(result))
        }
    }

    /// Set a specific bit and return the new value.
    pub fn with_bit_set(&self, bit: u32) -> U256 {
        self.with_bit(bit)
    }

    /// Bitwise OR with a value placed into a specific bit position.
    /// `bit_pos` is the bit position within the 256-bit number.
    fn with_bit(&self, bit_pos: u32) -> U256 {
        let mut result = *self;
        let limb = (bit_pos / 64) as usize;
        let bit = bit_pos % 64;
        if limb < 4 {
            result.0[limb] |= 1u64 << bit;
        }
        result
    }

    /// Divide self by divisor, returning (quotient, remainder).
    /// Panics if divisor is zero.
    pub fn div_rem(&self, divisor: &U256) -> (U256, U256) {
        assert!(!divisor.is_zero(), "division by zero");

        if self.cmp(divisor) == std::cmp::Ordering::Less {
            return (U256::ZERO, *self);
        }
        if self.cmp(divisor) == std::cmp::Ordering::Equal {
            return (U256::ONE, U256::ZERO);
        }

        let mut quotient = U256::ZERO;
        let mut remainder = U256::ZERO;

        let bit_len = 256 - self.leading_zeros();

        for bit in (0..bit_len).rev() {
            remainder = remainder.shl(1);
            // Set bit 0 of remainder to bit `bit` of self
            let self_limb = (bit / 64) as usize;
            let self_bit = bit % 64;
            if (self.0[self_limb] >> self_bit) & 1 == 1 {
                remainder = remainder.with_bit(0);
            }
            if remainder.cmp(divisor) != std::cmp::Ordering::Less {
                remainder = remainder.wrapping_sub(divisor);
                quotient = quotient.with_bit(bit);
            }
        }

        (quotient, remainder)
    }

    /// self / other (integer division).
    pub fn div(&self, other: &U256) -> U256 {
        self.div_rem(other).0
    }

    /// self % other (modulus).
    pub fn rem(&self, other: &U256) -> U256 {
        self.div_rem(other).1
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_one() {
        assert!(U256::ZERO.is_zero());
        assert!(!U256::ONE.is_zero());
        assert_eq!(U256::ONE.to_u64(), Some(1));
    }

    #[test]
    fn test_from_to_be_bytes() {
        let val = U256::from_u64(0x0102030405060708);
        let bytes = val.to_be_bytes();
        assert_eq!(bytes[24], 0x01);
        assert_eq!(bytes[31], 0x08);
        assert_eq!(U256::from_be_bytes(&bytes), val);
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(U256::ZERO.leading_zeros(), 256);
        assert_eq!(U256::ONE.leading_zeros(), 255);
        assert_eq!(U256::from_u64(0x8000000000000000).leading_zeros(), 192);
        let mut high = [0u8; 32];
        high[0] = 0x80;
        assert_eq!(U256::from_be_bytes(&high).leading_zeros(), 0);
    }

    #[test]
    fn test_shl_shr() {
        let a = U256::from_u64(1);
        assert_eq!(a.shl(64), U256([0, 1, 0, 0]));
        assert_eq!(a.shl(128), U256([0, 0, 1, 0]));

        let b = U256([0, 1, 0, 0]);
        assert_eq!(b.shr(64), U256::ONE);

        let c = U256([0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0]);
        assert_eq!(c.shl(0), c);
        assert_eq!(c.shr(0), c);
    }

    #[test]
    fn test_wrapping_sub() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(30);
        assert_eq!(a.wrapping_sub(&b).to_u64(), Some(70));

        let c = U256::from_u64(5);
        let d = U256::from_u64(10);
        let result = c.wrapping_sub(&d);
        assert_eq!(result.0[0], u64::MAX - 4);
    }

    #[test]
    fn test_wrapping_add() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(200);
        assert_eq!(a.wrapping_add(&b).to_u64(), Some(300));
    }

    #[test]
    fn test_div_rem_basic() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(7);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q.to_u64(), Some(14));
        assert_eq!(r.to_u64(), Some(2));
    }

    #[test]
    fn test_div_rem_equal() {
        let a = U256::from_u64(42);
        let b = U256::from_u64(42);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, U256::ONE);
        assert_eq!(r, U256::ZERO);
    }

    #[test]
    fn test_div_rem_less() {
        let a = U256::from_u64(5);
        let b = U256::from_u64(10);
        let (q, r) = a.div_rem(&b);
        assert_eq!(q, U256::ZERO);
        assert_eq!(r, a);
    }

    #[test]
    fn test_div_large_numbers() {
        let a = U256([0, 1, 0, 0]); // 2^64
        let b = U256::from_u64(1);
        let (q, _r) = a.div_rem(&b);
        assert_eq!(q, a);

        let two_128 = U256([0, 0, 1, 0]);
        let two_64 = U256([0, 1, 0, 0]);
        let (q, r) = two_128.div_rem(&two_64);
        assert_eq!(q, two_64);
        assert_eq!(r, U256::ZERO);
    }

    #[test]
    fn test_difficulty_1_division() {
        let bits = 0x1d00ffffu32;
        let exponent = bits >> 24;
        let mantissa = bits & 0x00ffffff;
        let shift_bytes = exponent - 3;
        let target = U256::from_u64(mantissa as u64).shl(shift_bytes * 8);
        let (q, r) = target.div_rem(&target);
        assert_eq!(q, U256::ONE);
        assert_eq!(r, U256::ZERO);
    }

    #[test]
    fn test_cmp() {
        assert!(U256::ZERO < U256::ONE);
        assert!(U256::ONE < U256::from_u64(2));
        assert!(U256::from_u64(u64::MAX) < U256([0, 1, 0, 0]));
        assert_eq!(U256::from_u64(42), U256::from_u64(42));
    }

    #[test]
    fn test_div_max_by_2() {
        let max = U256::MAX;
        let two = U256::from_u64(2);
        let (q, r) = max.div_rem(&two);
        assert_eq!(r, U256::ONE);
        let expected_q = U256::MAX.shr(1);
        assert_eq!(q, expected_q, "(2^256-1)/2 should be 2^255-1");
    }

    #[test]
    fn test_div_by_1() {
        let a = U256::MAX;
        let one = U256::ONE;
        let (q, r) = a.div_rem(&one);
        assert_eq!(q, a);
        assert_eq!(r, U256::ZERO);
    }
}
