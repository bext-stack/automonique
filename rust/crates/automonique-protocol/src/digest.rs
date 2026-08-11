// SPDX-License-Identifier: Elastic-2.0

//! SHA-256 over in-memory bytes, in dependency-free safe Rust.
//!
//! This crate declares no dependencies and forbids `unsafe`, so the hash a
//! pinned schema bundle is verified against is implemented here from FIPS 180-4
//! rather than imported. "No dependencies" is a reason to write the hash, not a
//! reason to trust a digest somebody else computed.
//!
//! The implementation is a value transform: it reads no file, opens no socket
//! and consults no clock.
//!
//! ```
//! use automonique_protocol::digest::Sha256;
//!
//! // FIPS 180-4 / RFC 6234 one-block vector.
//! assert_eq!(
//!     Sha256::digest(b"abc").to_hex(),
//!     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
//! );
//! ```

use core::fmt;
use core::str::FromStr;
use std::error::Error;

/// The algorithm name every digest spelling carries.
pub const ALGORITHM: &str = "sha256";

/// Bytes in one SHA-256 digest.
pub const DIGEST_BYTES: usize = 32;

/// Bytes in one SHA-256 compression block.
const BLOCK_BYTES: usize = 64;

/// Offset within a block at which the 64-bit length suffix begins.
const LENGTH_OFFSET: usize = 56;

/// FIPS 180-4 initial hash value: the fractional parts of the square roots of
/// the first eight primes.
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4 round constants: the fractional parts of the cube roots of the
/// first sixty-four primes.
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Why a digest spelling was rejected.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DigestError {
    /// The value did not begin with `sha256:`.
    ///
    /// A digest is never accepted without its algorithm name: two hashes of the
    /// same length are not interchangeable.
    AlgorithmUnnamed,
    /// The body was not exactly 64 lowercase hexadecimal digits.
    ///
    /// Uppercase is refused rather than folded, so one digest has exactly one
    /// accepted spelling.
    HexInvalid,
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmUnnamed => {
                write!(formatter, "digest does not begin with {ALGORITHM}:")
            }
            Self::HexInvalid => {
                formatter.write_str("digest body is not exactly 64 lowercase hexadecimal digits")
            }
        }
    }
}

impl Error for DigestError {}

/// A SHA-256 digest.
///
/// Produced by hashing bytes with [`Sha256`] or by parsing the canonical
/// `sha256:<64 lowercase hex digits>` spelling. The 32 bytes are private, so a
/// digest of the wrong width or an unnamed algorithm is unrepresentable rather
/// than rejected later.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; DIGEST_BYTES]);

impl Sha256Digest {
    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    /// The 64 lowercase hexadecimal digits, without the algorithm name.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(DIGEST_BYTES * 2);
        for byte in self.0 {
            hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        hex
    }
}

/// The canonical spelling: the algorithm name, a colon, then the hex body.
///
/// This is the spelling [`FromStr`] accepts, so `digest.to_string().parse()`
/// round-trips.
impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{ALGORITHM}:{}", self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value
            .strip_prefix(ALGORITHM)
            .and_then(|rest| rest.strip_prefix(':'))
            .ok_or(DigestError::AlgorithmUnnamed)?;
        if hex.len() != DIGEST_BYTES * 2 {
            return Err(DigestError::HexInvalid);
        }
        let mut bytes = [0u8; DIGEST_BYTES];
        for (byte, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let mut value = 0u8;
            for digit in pair {
                value = (value << 4) | hex_value(*digit).ok_or(DigestError::HexInvalid)?;
            }
            *byte = value;
        }
        Ok(Self(bytes))
    }
}

/// A streaming SHA-256 state.
///
/// Feeding the same bytes in any chunking yields the same digest.
///
/// ```
/// use automonique_protocol::digest::Sha256;
///
/// let mut chunked = Sha256::new();
/// chunked.update(b"ab");
/// chunked.update(b"c");
/// assert_eq!(chunked.finish(), Sha256::digest(b"abc"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_BYTES],
    filled: usize,
    bytes: u64,
}

impl Sha256 {
    /// Start an empty hash state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0u8; BLOCK_BYTES],
            filled: 0,
            bytes: 0,
        }
    }

    /// Hash one slice in a single call.
    #[must_use]
    pub fn digest(input: &[u8]) -> Sha256Digest {
        let mut hasher = Self::new();
        hasher.update(input);
        hasher.finish()
    }

    /// Append bytes to the message.
    pub fn update(&mut self, input: &[u8]) {
        self.bytes = self.bytes.wrapping_add(input.len() as u64);
        self.absorb(input);
    }

    /// Pad the message and return its digest.
    ///
    /// The length suffix is the message length in bits modulo 2^64, which is
    /// FIPS 180-4's domain: a message of 2^61 bytes or more is outside it.
    #[must_use]
    pub fn finish(mut self) -> Sha256Digest {
        let bits = self.bytes.wrapping_mul(8);
        self.absorb(&[0x80]);
        let zeros = [0u8; BLOCK_BYTES];
        let padding = (LENGTH_OFFSET + BLOCK_BYTES - self.filled) % BLOCK_BYTES;
        self.absorb(&zeros[..padding]);
        self.absorb(&bits.to_be_bytes());

        let mut digest = [0u8; DIGEST_BYTES];
        for (slot, word) in digest.chunks_exact_mut(4).zip(self.state) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        Sha256Digest(digest)
    }

    /// Consume bytes into the block buffer without counting them.
    ///
    /// Padding uses this so the length suffix describes the message rather than
    /// the padding.
    fn absorb(&mut self, input: &[u8]) {
        let mut input = input;
        if self.filled > 0 {
            let taken = (BLOCK_BYTES - self.filled).min(input.len());
            let (head, tail) = input.split_at(taken);
            self.block[self.filled..self.filled + taken].copy_from_slice(head);
            self.filled += taken;
            input = tail;
            if self.filled == BLOCK_BYTES {
                compress(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
        let mut blocks = input.chunks_exact(BLOCK_BYTES);
        for block in &mut blocks {
            let mut whole = [0u8; BLOCK_BYTES];
            whole.copy_from_slice(block);
            compress(&mut self.state, &whole);
        }
        // `self.filled` is non-zero here only when the head branch consumed the
        // whole input without completing a block, in which case `rest` is empty.
        let rest = blocks.remainder();
        self.block[self.filled..self.filled + rest.len()].copy_from_slice(rest);
        self.filled += rest.len();
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One SHA-256 compression round over a full block.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_BYTES]) {
    let mut schedule = [0u32; 64];
    for (word, chunk) in schedule.iter_mut().zip(block.chunks_exact(4)) {
        *word = chunk
            .iter()
            .fold(0u32, |value, byte| (value << 8) | u32::from(*byte));
    }
    for index in 16..schedule.len() {
        let near = schedule[index - 15];
        let far = schedule[index - 2];
        let sigma0 = near.rotate_right(7) ^ near.rotate_right(18) ^ (near >> 3);
        let sigma1 = far.rotate_right(17) ^ far.rotate_right(19) ^ (far >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (word, constant) in schedule.iter().zip(ROUND_CONSTANTS) {
        let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(sum1)
            .wrapping_add(choose)
            .wrapping_add(constant)
            .wrapping_add(*word);
        let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = sum0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *slot = slot.wrapping_add(value);
    }
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}
