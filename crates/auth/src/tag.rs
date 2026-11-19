//! Tags, their length, and bit-packed sequences of them.

use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, Write};
use commonware_utils::{Faults, N5f1, Participant};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Security parameter `lambda`: beyond the PRF advantage, Input Authenticity fails
/// with probability at most `2^-SECURITY_BITS`.
pub const SECURITY_BITS: u32 = 128;

/// Base-2 logarithm of `Q`, the number of transactions the bound covers.
pub const TRANSACTIONS_LOG2: u32 = 40;

/// The length of a tag never exceeds the output of the PRF.
const MAX_TAG_BITS: u32 = 256;
const TAG_BYTES: usize = (MAX_TAG_BITS / 8) as usize;

/// Tag length `t` in bits for `participants` validators.
///
/// This is the smallest `t` with `f * Q * C(n - f, f + 1) * 2^(-t(f + 1)) <= 2^-lambda`
/// (Section 4 of the paper), where `f` is the number of faults `n` validators tolerate
/// under `n >= 5f + 1`. A committee that tolerates no fault has no Byzantine proposer to
/// bound; it uses the length for one.
///
/// The computation is exact integer arithmetic, so every node derives the same length.
///
/// # Panics
///
/// Panics if `participants` is zero.
pub fn tag_bits(participants: u32) -> u32 {
    let faults = N5f1::max_faults(participants);

    // forgeries = f * C(n - f, f + 1). The running product is a binomial coefficient
    // after every step, so each division is exact.
    let mut forgeries = Natural::one();
    let chosen = faults + 1;
    let from = participants - faults;
    for i in 1..=chosen {
        forgeries.mul(from - chosen + i);
        forgeries.div_exact(i);
    }
    forgeries.mul(faults.max(1));

    // 2^(t(f + 1)) >= 2^(lambda + log2 Q) * forgeries
    let exponent = SECURITY_BITS + TRANSACTIONS_LOG2 + forgeries.ceil_log2();
    let bits = exponent.div_ceil(chosen);
    assert!(bits <= MAX_TAG_BITS, "tag length exceeds the PRF output");
    bits
}

/// A non-negative integer of any size, with the three operations [`tag_bits`] needs.
struct Natural {
    /// Little-endian limbs without trailing zeros.
    limbs: Vec<u32>,
}

impl Natural {
    fn one() -> Self {
        Self { limbs: vec![1] }
    }

    fn mul(&mut self, by: u32) {
        let mut carry = 0u64;
        for limb in &mut self.limbs {
            let product = u64::from(*limb) * u64::from(by) + carry;
            *limb = product as u32;
            carry = product >> 32;
        }
        if carry != 0 {
            self.limbs.push(carry as u32);
        }
        self.trim();
    }

    fn div_exact(&mut self, by: u32) {
        let mut remainder = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let dividend = (remainder << 32) | u64::from(*limb);
            *limb = (dividend / u64::from(by)) as u32;
            remainder = dividend % u64::from(by);
        }
        assert_eq!(remainder, 0, "division must be exact");
        self.trim();
    }

    fn trim(&mut self) {
        while self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// The smallest `e` with `2^e >= self`, for a positive value.
    fn ceil_log2(&self) -> u32 {
        let top = *self.limbs.last().expect("value must be positive");
        let bit_length = (self.limbs.len() as u32 - 1) * 32 + (32 - top.leading_zeros());
        let power_of_two =
            top.is_power_of_two() && self.limbs[..self.limbs.len() - 1].iter().all(|l| *l == 0);
        if power_of_two {
            bit_length - 1
        } else {
            bit_length
        }
    }
}

/// The first bits of a PRF output. The bits past the tag length are zero.
#[derive(Clone, Copy, Debug)]
pub struct Tag([u8; TAG_BYTES]);

impl Tag {
    /// Keeps the first `bits` bits of `output`.
    fn truncate(mut output: [u8; TAG_BYTES], bits: u32) -> Self {
        assert!(bits <= MAX_TAG_BITS, "tag length exceeds the PRF output");
        let whole = (bits / 8) as usize;
        if whole < TAG_BYTES {
            output[whole] &= !(0xffu8 >> (bits % 8));
            output[whole + 1..].fill(0);
        }
        Self(output)
    }
}

// Comparison takes the same time whether or not the tags match.
impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(&other.0)
            .fold(0u8, |difference, (a, b)| difference | (a ^ b))
            == 0
    }
}

impl Eq for Tag {}

/// The tag half of a key shared by a user and a validator.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TagKey([u8; 32]);

impl TagKey {
    pub(crate) const fn new(key: [u8; 32]) -> Self {
        Self(key)
    }

    /// The tag of the transaction with digest `transaction`, submitted to `proposer`.
    ///
    /// `Tag_K(k, tr) = Trunc_t(PRF(K, Encode(k, tr)))`, with keyed BLAKE3 as the PRF. The
    /// proposer index has a fixed width and so does a digest, so the encoding is
    /// unambiguous.
    pub fn tag(&self, proposer: Participant, transaction: &[u8], bits: u32) -> Tag {
        let mut hasher = blake3::Hasher::new_keyed(&self.0);
        hasher.update(&proposer.get().to_be_bytes());
        hasher.update(transaction);
        Tag::truncate(*hasher.finalize().as_bytes(), bits)
    }
}

/// A sequence of tags of one length, packed without padding between them.
///
/// An authenticator is the sequence of one transaction's tags, one per validator. A
/// column is the sequence of one validator's tags, one per MAC transaction of a block.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tags {
    /// Length of each tag in bits.
    bits: u32,
    /// Number of tags.
    len: usize,
    /// The tags, most significant bit first. Unused bits of the last byte are zero.
    data: Vec<u8>,
}

impl Tags {
    /// Creates an empty sequence of tags of `bits` bits.
    pub const fn new(bits: u32) -> Self {
        assert!(bits <= MAX_TAG_BITS, "tag length exceeds the PRF output");
        Self {
            bits,
            len: 0,
            data: Vec::new(),
        }
    }

    /// Creates an empty sequence with room for `capacity` tags.
    pub fn with_capacity(bits: u32, capacity: usize) -> Self {
        let mut tags = Self::new(bits);
        tags.data.reserve(packed_bytes(bits, capacity));
        tags
    }

    /// Length of each tag in bits.
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Number of tags.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the sequence holds no tag.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends a tag. Its length must be the length of this sequence.
    pub fn push(&mut self, tag: &Tag) {
        let start = self.len * self.bits as usize;
        self.len += 1;
        self.data.resize(packed_bytes(self.bits, self.len), 0);

        // The tag's bytes land `shift` bits into the byte at `start / 8`. Its bits past
        // the tag length are zero, so they do not disturb the bytes that follow.
        let shift = start % 8;
        let bytes = (self.bits as usize).div_ceil(8);
        for (offset, byte) in tag.0[..bytes].iter().enumerate() {
            let position = start / 8 + offset;
            self.data[position] |= byte >> shift;
            if shift != 0 && position + 1 < self.data.len() {
                self.data[position + 1] |= byte << (8 - shift);
            }
        }
    }

    /// Returns the tag at `index`.
    pub fn get(&self, index: usize) -> Option<Tag> {
        if index >= self.len {
            return None;
        }
        let start = index * self.bits as usize;
        let shift = start % 8;
        let bytes = (self.bits as usize).div_ceil(8);
        let mut output = [0u8; TAG_BYTES];
        for (offset, byte) in output[..bytes].iter_mut().enumerate() {
            let position = start / 8 + offset;
            *byte = self.data[position] << shift;
            if shift != 0 && position + 1 < self.data.len() {
                *byte |= self.data[position + 1] >> (8 - shift);
            }
        }
        Some(Tag::truncate(output, self.bits))
    }

    /// The packed tags.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Encoded size of `len` tags of `bits` bits.
    pub fn encoded_size(bits: u32, len: usize) -> usize {
        len.encode_size() + packed_bytes(bits, len)
    }
}

impl Extend<Tag> for Tags {
    fn extend<I: IntoIterator<Item = Tag>>(&mut self, tags: I) {
        for tag in tags {
            self.push(&tag);
        }
    }
}

const fn packed_bytes(bits: u32, len: usize) -> usize {
    (len * bits as usize).div_ceil(8)
}

impl Write for Tags {
    fn write(&self, buf: &mut impl BufMut) {
        self.len.write(buf);
        buf.put_slice(&self.data);
    }
}

impl EncodeSize for Tags {
    fn encode_size(&self) -> usize {
        self.len.encode_size() + self.data.len()
    }
}

impl Read for Tags {
    /// The tag length in bits and the accepted numbers of tags.
    type Cfg = (u32, RangeCfg<usize>);

    fn read_cfg(buf: &mut impl Buf, (bits, range): &Self::Cfg) -> Result<Self, Error> {
        if *bits > MAX_TAG_BITS {
            return Err(Error::Invalid("Tags", "tag length exceeds the PRF output"));
        }
        let len = usize::read_cfg(buf, range)?;
        let bytes = len
            .checked_mul(*bits as usize)
            .ok_or(Error::Invalid("Tags", "length overflow"))?
            .div_ceil(8);
        if buf.remaining() < bytes {
            return Err(Error::EndOfBuffer);
        }
        let mut data = vec![0; bytes];
        buf.copy_to_slice(&mut data);

        // One encoding per sequence: the unused bits of the last byte are zero.
        let used = len * *bits as usize % 8;
        if used != 0 && data[bytes - 1] & (0xff >> used) != 0 {
            return Err(Error::Invalid("Tags", "non-zero padding"));
        }
        Ok(Self {
            bits: *bits,
            len,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn tag_bits_match_the_paper() {
        // Table 1: f = 1, 10, 51.
        assert_eq!(tag_bits(6), 86);
        assert_eq!(tag_bits(51), 19);
        assert_eq!(tag_bits(256), 7);
    }

    #[test]
    fn tag_bits_match_the_plan() {
        assert_eq!(tag_bits(16), 45);
        assert_eq!(tag_bits(50), 21);
    }

    #[test]
    fn tag_bits_are_defined_for_every_committee() {
        for participants in 1..=1024 {
            let bits = tag_bits(participants);
            assert!((1..=MAX_TAG_BITS).contains(&bits), "n = {participants}");
        }
    }

    #[test]
    fn tag_bits_match_the_closed_form() {
        // t >= (lambda + log2(f Q) + log2 C(n - f, f + 1)) / (f + 1), in floating point.
        for participants in 6..=300u32 {
            let faults = N5f1::max_faults(participants);
            let mut log2_binomial = 0f64;
            for i in 1..=faults + 1 {
                log2_binomial += f64::from(participants - 2 * faults - 1 + i).log2();
                log2_binomial -= f64::from(i).log2();
            }
            let bound = (f64::from(SECURITY_BITS + TRANSACTIONS_LOG2)
                + f64::from(faults).log2()
                + log2_binomial)
                / f64::from(faults + 1);
            let bits = f64::from(tag_bits(participants));
            assert!(bits >= bound - 1e-9, "n = {participants}");
            assert!(bits < bound + 1.0 + 1e-9, "n = {participants}");
        }
    }

    #[test]
    fn natural_ceil_log2() {
        for (value, expected) in [(1u32, 0), (2, 1), (3, 2), (4, 2), (5, 3), (1 << 31, 31)] {
            let mut natural = Natural::one();
            natural.mul(value);
            assert_eq!(natural.ceil_log2(), expected, "value = {value}");
        }
        let mut natural = Natural::one();
        natural.mul(1 << 31);
        natural.mul(2);
        assert_eq!(natural.ceil_log2(), 32);
        natural.mul(3);
        assert_eq!(natural.ceil_log2(), 34);
    }

    fn key(seed: u8) -> TagKey {
        TagKey::new([seed; 32])
    }

    #[test]
    fn tag_depends_on_key_proposer_and_transaction() {
        let tag = key(1).tag(Participant::new(0), b"transaction", 86);
        assert_eq!(tag, key(1).tag(Participant::new(0), b"transaction", 86));
        assert_ne!(tag, key(2).tag(Participant::new(0), b"transaction", 86));
        assert_ne!(tag, key(1).tag(Participant::new(1), b"transaction", 86));
        assert_ne!(tag, key(1).tag(Participant::new(0), b"transactioN", 86));
    }

    #[test]
    fn tag_is_a_prefix_of_the_prf_output() {
        let full = key(3).tag(Participant::new(7), b"tr", 256);
        for bits in 0..=256u32 {
            let tag = key(3).tag(Participant::new(7), b"tr", bits);
            for bit in 0..256u32 {
                let get = |t: &Tag| t.0[(bit / 8) as usize] >> (7 - bit % 8) & 1;
                let expected = if bit < bits { get(&full) } else { 0 };
                assert_eq!(get(&tag), expected, "bits = {bits}, bit = {bit}");
            }
        }
    }

    #[test]
    fn tags_roundtrip_at_every_length() {
        for bits in [1u32, 7, 8, 9, 19, 21, 45, 64, 86, 171, 256] {
            let mut tags = Tags::new(bits);
            let expected: Vec<Tag> = (0..23u32)
                .map(|i| key(bits as u8).tag(Participant::new(i), b"tr", bits))
                .collect();
            tags.extend(expected.iter().copied());
            assert_eq!(tags.len(), expected.len());
            assert_eq!(tags.as_bytes().len(), (23 * bits as usize).div_ceil(8));
            for (index, tag) in expected.iter().enumerate() {
                assert_eq!(tags.get(index).as_ref(), Some(tag), "bits = {bits}");
            }
            assert_eq!(tags.get(expected.len()), None);

            let encoded = tags.encode();
            assert_eq!(encoded.len(), Tags::encoded_size(bits, tags.len()));
            let decoded = Tags::decode_cfg(encoded, &(bits, RangeCfg::new(23..=23))).unwrap();
            assert_eq!(decoded, tags);
        }
    }

    #[test]
    fn tags_decode_rejects_wrong_count_padding_and_truncation() {
        let mut tags = Tags::new(7);
        tags.push(&key(1).tag(Participant::new(0), b"tr", 7));
        let encoded = tags.encode();

        assert!(Tags::decode_cfg(encoded.clone(), &(7, RangeCfg::new(2..=2))).is_err());

        let mut padded = encoded.to_vec();
        *padded.last_mut().unwrap() |= 1;
        assert!(Tags::decode_cfg(padded, &(7, RangeCfg::new(1..=1))).is_err());

        let truncated = encoded.slice(..encoded.len() - 1);
        assert!(Tags::decode_cfg(truncated, &(7, RangeCfg::new(1..=1))).is_err());
        assert!(Tags::decode_cfg(encoded, &(257, RangeCfg::new(1..=1))).is_err());
    }

    #[test]
    fn empty_tags_encode_to_a_count() {
        let tags = Tags::new(86);
        assert!(tags.is_empty());
        assert_eq!(tags.encode().as_ref(), &[0]);
    }
}
