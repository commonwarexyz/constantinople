use bytes::{Bytes, BytesMut};

/// Maximum physical key length in bytes.
///
/// All key lengths must fit in a `u8` so the largest valid key is 254 bytes.
pub const MAX_KEY_LEN: usize = 254;

/// Minimum physical key length in bytes.
pub const MIN_KEY_LEN: usize = 0;

/// A store key. Variable-length, lexicographically ordered raw bytes.
///
/// Stored as [`Bytes`] so keys can share backing storage (e.g. RPC wire buffers via
/// [`bytes::Bytes::slice_ref`]) without copying.
pub type Key = Bytes;

/// Mutable buffer used while constructing a key. Freeze to [`Key`] with
/// [`Bytes::from`] / [`BytesMut::freeze`] when done mutating.
pub type KeyMut = BytesMut;

/// A store value. Variable length.
pub type Value = Bytes;

/// Errors returned by key-length validation helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyValidationError {
    #[error("key length {len} exceeds max {max}")]
    TooLong { len: usize, max: usize },
}

/// Errors returned by [`Prefix`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    #[error("prefix length {len} exceeds max {max}")]
    PrefixTooLong { len: usize, max: usize },
    #[error("key length {len} exceeds max {max}")]
    KeyTooLong { len: usize, max: usize },
    #[error("key does not match this prefix")]
    PrefixMismatch,
}

/// Key namespace prefix. A key belongs to the prefix iff it
/// starts with these bytes; the payload is everything after them. Composing
/// namespaces is byte concatenation, which is always associative and
/// unambiguous.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Prefix(Bytes);

impl Prefix {
    /// Build a prefix from bytes. Fails when longer than [`MAX_KEY_LEN`].
    pub fn new(prefix: impl Into<Bytes>) -> Result<Self, PrefixError> {
        let prefix = prefix.into();
        if prefix.len() > MAX_KEY_LEN {
            return Err(PrefixError::PrefixTooLong {
                len: prefix.len(),
                max: MAX_KEY_LEN,
            });
        }
        Ok(Self(prefix))
    }

    /// The empty prefix: the composition identity. It matches every key and
    /// passes payloads through unchanged.
    pub const fn empty() -> Self {
        Self(Bytes::new())
    }

    /// Const constructor for static family prefixes, letting callers keep
    /// `const FAMILY: Prefix`. Panics when `prefix` is longer than
    /// [`MAX_KEY_LEN`]; in a const context the panic surfaces at compile time.
    pub const fn from_static(prefix: &'static [u8]) -> Self {
        assert!(prefix.len() <= MAX_KEY_LEN, "prefix exceeds MAX_KEY_LEN");
        Self(Bytes::from_static(prefix))
    }

    /// One-byte family prefix.
    pub fn from_byte(b: u8) -> Self {
        Self(Bytes::copy_from_slice(&[b]))
    }

    /// The raw prefix bytes.
    #[inline]
    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Length of the prefix in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when this is the empty (identity) prefix.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Maximum payload length that still yields a key within [`MAX_KEY_LEN`].
    #[inline]
    pub fn max_payload_len(&self) -> usize {
        MAX_KEY_LEN - self.0.len()
    }

    /// Concatenate this prefix with `payload` to form a physical key. Fails
    /// with [`PrefixError::KeyTooLong`] if the result exceeds
    /// [`MAX_KEY_LEN`].
    pub fn encode(&self, payload: &[u8]) -> Result<Key, PrefixError> {
        let total = self.0.len() + payload.len();
        if total > MAX_KEY_LEN {
            return Err(PrefixError::KeyTooLong {
                len: total,
                max: MAX_KEY_LEN,
            });
        }
        let mut key = BytesMut::with_capacity(total);
        key.extend_from_slice(&self.0);
        key.extend_from_slice(payload);
        Ok(key.freeze())
    }

    /// Prepend this prefix to an existing [`Key`]. When the prefix is empty
    /// this is a refcount-only clone of `key` (no bytes copied).
    pub fn encode_key(&self, key: &Key) -> Result<Key, PrefixError> {
        if self.0.is_empty() {
            if key.len() > MAX_KEY_LEN {
                return Err(PrefixError::KeyTooLong {
                    len: key.len(),
                    max: MAX_KEY_LEN,
                });
            }
            return Ok(key.clone());
        }
        self.encode(key)
    }

    /// True when `key` belongs to this prefix. The empty prefix matches all.
    #[inline]
    pub fn matches(&self, key: &[u8]) -> bool {
        key.starts_with(&self.0)
    }

    /// Strip the prefix from a borrowed key slice, returning the payload
    /// slice, or `None` when `key` does not start with this prefix. The
    /// zero-copy [`Prefix::strip`] is preferable when the key is a [`Key`].
    #[inline]
    pub fn strip_slice<'a>(&self, key: &'a [u8]) -> Option<&'a [u8]> {
        key.strip_prefix(self.0.as_ref())
    }

    /// Strip the prefix from `key`, returning the payload as a zero-copy slice
    /// of the same backing storage. Fails with
    /// [`PrefixError::PrefixMismatch`] when `key` does not start with this
    /// prefix.
    pub fn strip(&self, key: &Key) -> Result<Key, PrefixError> {
        if !self.matches(key) {
            return Err(PrefixError::PrefixMismatch);
        }
        Ok(key.slice(self.0.len()..))
    }

    /// Inclusive lower and upper bounds spanning every key under this prefix:
    /// the prefix itself, and the prefix followed by `0xFF` padding to
    /// [`MAX_KEY_LEN`].
    pub fn bounds(&self) -> (Key, Key) {
        let start = self.0.clone();
        let mut end = Vec::with_capacity(MAX_KEY_LEN);
        end.extend_from_slice(&self.0);
        end.resize(MAX_KEY_LEN, 0xFF);
        (start, Bytes::from(end))
    }

    /// Compose two prefixes by concatenation. Always valid and associative;
    /// fails only if the concatenation exceeds [`MAX_KEY_LEN`].
    pub fn join(&self, other: &Prefix) -> Result<Prefix, PrefixError> {
        let total = self.0.len() + other.0.len();
        if total > MAX_KEY_LEN {
            return Err(PrefixError::PrefixTooLong {
                len: total,
                max: MAX_KEY_LEN,
            });
        }
        if self.0.is_empty() {
            return Ok(other.clone());
        }
        if other.0.is_empty() {
            return Ok(self.clone());
        }
        let mut buf = BytesMut::with_capacity(total);
        buf.extend_from_slice(&self.0);
        buf.extend_from_slice(&other.0);
        Ok(Prefix(buf.freeze()))
    }
}

/// True when a key size is valid for ingest/storage.
#[inline]
pub fn is_valid_key_size(size: usize) -> bool {
    (MIN_KEY_LEN..=MAX_KEY_LEN).contains(&size)
}

/// Validate a key length against the store's physical key limits.
#[inline]
pub fn validate_key_size(size: usize) -> Result<(), KeyValidationError> {
    if is_valid_key_size(size) {
        Ok(())
    } else {
        Err(KeyValidationError::TooLong {
            len: size,
            max: MAX_KEY_LEN,
        })
    }
}

/// Return the smallest valid key strictly greater than `key`.
///
/// Lexicographic ordering on variable-length byte strings means appending a
/// trailing `0x00` is the immediate successor whenever the key is shorter than
/// `MAX_KEY_LEN`.
pub fn next_key(key: &Key) -> Option<Key> {
    if key.len() < MAX_KEY_LEN {
        let mut out = key.to_vec();
        out.push(0);
        return Some(Bytes::from(out));
    }

    let mut out = key.to_vec();
    for idx in (0..out.len()).rev() {
        if out[idx] != u8::MAX {
            out[idx] += 1;
            out.truncate(idx + 1);
            return Some(Bytes::from(out));
        }
    }
    None
}

/// Return the greatest valid key strictly less than `key`.
pub fn previous_key(key: &Key) -> Option<Key> {
    if key.len() > MAX_KEY_LEN {
        return Some(key.slice(..MAX_KEY_LEN));
    }
    let mut bytes = key.to_vec();
    let last = bytes.pop()?;
    if last == 0 {
        return Some(Bytes::from(bytes));
    }
    bytes.push(last - 1);
    bytes.resize(MAX_KEY_LEN, u8::MAX);
    Some(Bytes::from(bytes))
}

pub(crate) fn read_bits_to_bytes(
    src: &[u8],
    src_bit_offset: usize,
    dst: &mut [u8],
    bit_len: usize,
) {
    dst.fill(0);
    if bit_len == 0 {
        return;
    }

    if bit_len.is_multiple_of(8) {
        let byte_len = bit_len / 8;
        let byte_offset = src_bit_offset / 8;
        let bit_shift = src_bit_offset % 8;
        if byte_len <= dst.len() {
            if let Some(end) = byte_offset.checked_add(byte_len) {
                if bit_shift == 0 && end <= src.len() {
                    dst[..byte_len].copy_from_slice(&src[byte_offset..end]);
                    return;
                }

                if bit_shift != 0 && end < src.len() {
                    let head_bits = 8 - bit_shift;
                    for idx in 0..byte_len {
                        dst[idx] = (src[byte_offset + idx] << bit_shift)
                            | (src[byte_offset + idx + 1] >> head_bits);
                    }
                    return;
                }
            }
        }
    }

    for bit_idx in 0..bit_len {
        let value = read_bit_be(src, src_bit_offset + bit_idx);
        write_bit_be(dst, bit_idx, value);
    }
}

pub(crate) fn read_bit_be(bytes: &[u8], bit_idx: usize) -> bool {
    let byte_idx = bit_idx / 8;
    let bit_in_byte = 7 - (bit_idx % 8);
    bytes
        .get(byte_idx)
        .is_some_and(|byte| ((byte >> bit_in_byte) & 1) != 0)
}

pub(crate) fn write_bit_be(bytes: &mut [u8], bit_idx: usize, value: bool) {
    let byte_idx = bit_idx / 8;
    let bit_in_byte = 7 - (bit_idx % 8);
    let mask = 1 << bit_in_byte;
    if let Some(byte) = bytes.get_mut(byte_idx) {
        if value {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_prefix_encode_strip_round_trip() {
        let prefix = Prefix::from_byte(0x05);
        let key = prefix.encode(&[0xAB, 0xCD]).expect("encoded key");
        assert_eq!(&key[..], &[0x05, 0xAB, 0xCD]);
        assert_eq!(
            prefix.strip(&key).expect("payload"),
            Bytes::from_static(&[0xAB, 0xCD])
        );
    }

    #[test]
    fn key_prefix_preserves_payload_order_within_prefix() {
        let prefix = Prefix::from_byte(0x03);
        let lower = prefix.encode(&[0x10, 0x00]).expect("lower key");
        let mid = prefix.encode(&[0x10, 0x01]).expect("mid key");
        let upper = prefix.encode(&[0x20, 0x00]).expect("upper key");
        assert!(lower < mid);
        assert!(mid < upper);
    }

    #[test]
    fn key_prefix_bounds_cover_only_one_prefix() {
        let prefix = Prefix::from_byte(0x0A);
        let (start, end) = prefix.bounds();
        let key = prefix.encode(&[0x11, 0x22]).expect("prefix key");
        assert!(prefix.matches(&start));
        assert!(prefix.matches(&end));
        assert!(prefix.matches(&key));
        assert!(start <= key && key <= end);

        // A same-length distinct prefix is disjoint from this one.
        let other = Prefix::from_byte(0x0B)
            .encode(&[0x11, 0x22])
            .expect("other key");
        assert!(!prefix.matches(&other));
        assert!(other > end || other < start);
        assert!(start <= end);
    }

    #[test]
    fn key_prefix_join_is_associative_and_composes_layers() {
        let a = Prefix::from_byte(0x0A);
        let b = Prefix::from_byte(0x0B);
        let c = Prefix::from_byte(0x0C);

        // Concatenation is associative.
        let left = a.join(&b).unwrap().join(&c).unwrap();
        let right = a.join(&b.join(&c).unwrap()).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.as_bytes().as_ref(), &[0x0A, 0x0B, 0x0C]);

        // Encoding layer-by-layer and via the joined prefix produce identical
        // keys, the composition case that the old bit-padding codec corrupted.
        let payload = [0x11u8, 0x22, 0x33];
        let joined = a.join(&b).unwrap();
        let layered = a.encode(&b.encode(&payload).unwrap()).unwrap();
        let combined = joined.encode(&payload).unwrap();
        assert_eq!(layered, combined);

        // Stripping unwinds symmetrically, layer-by-layer or via the join.
        let expected = Bytes::copy_from_slice(&payload);
        assert_eq!(joined.strip(&combined).unwrap(), expected);
        let outer = a.strip(&layered).unwrap();
        assert_eq!(b.strip(&outer).unwrap(), expected);
    }

    fn read_bits_to_bytes_naive(src: &[u8], src_bit_offset: usize, dst: &mut [u8], bit_len: usize) {
        dst.fill(0);
        for bit_idx in 0..bit_len {
            let value = read_bit_be(src, src_bit_offset + bit_idx);
            write_bit_be(dst, bit_idx, value);
        }
    }

    #[test]
    fn read_bits_to_bytes_matches_bit_by_bit_copy() {
        let src: Vec<u8> = (0..24)
            .map(|idx| (idx as u8).wrapping_mul(19).wrapping_add(7))
            .collect();
        for src_bit_offset in 0..16 {
            for bit_len in 0..=16 * 8 {
                let mut expected = vec![0x5A; 16];
                let mut actual = expected.clone();
                read_bits_to_bytes_naive(&src, src_bit_offset, &mut expected, bit_len);
                read_bits_to_bytes(&src, src_bit_offset, &mut actual, bit_len);
                assert_eq!(
                    actual, expected,
                    "src_bit_offset={src_bit_offset} bit_len={bit_len}"
                );
            }
        }
    }

    #[test]
    fn key_prefix_rejects_oversized_prefix() {
        let err = Prefix::new(vec![0u8; MAX_KEY_LEN + 1]).expect_err("prefix should not fit");
        assert!(matches!(err, PrefixError::PrefixTooLong { .. }));
    }

    #[test]
    fn key_prefix_rejects_oversized_key() {
        let prefix = Prefix::from_byte(0x01);
        let payload = vec![0u8; prefix.max_payload_len() + 1];
        let err = prefix.encode(&payload).expect_err("key should not fit");
        assert!(matches!(err, PrefixError::KeyTooLong { .. }));
    }

    #[test]
    fn empty_prefix_encode_key_rejects_oversized_key() {
        let prefix = Prefix::empty();
        let key = Bytes::from(vec![0u8; MAX_KEY_LEN + 1]);
        let err = prefix.encode_key(&key).expect_err("key should not fit");
        assert!(matches!(err, PrefixError::KeyTooLong { .. }));
        // A key exactly at the bound still round-trips as a zero-copy clone.
        let key = Bytes::from(vec![0u8; MAX_KEY_LEN]);
        assert_eq!(prefix.encode_key(&key).expect("fits"), key);
    }

    #[test]
    fn next_key_prefers_append_zero_for_short_keys() {
        assert_eq!(
            next_key(&Bytes::from(vec![0x12, 0x34])),
            Some(Bytes::from(vec![0x12, 0x34, 0x00]))
        );
    }

    #[test]
    fn next_key_carries_when_at_max_length() {
        let mut key = vec![0u8; MAX_KEY_LEN];
        key[MAX_KEY_LEN - 2] = 0x12;
        key[MAX_KEY_LEN - 1] = 0xFF;
        let key = Bytes::from(key);
        let next = next_key(&key).expect("next");
        assert_eq!(next.len(), MAX_KEY_LEN - 1);
        assert_eq!(next[MAX_KEY_LEN - 2], 0x13);
    }

    #[test]
    fn previous_key_is_the_immediate_predecessor() {
        for key in [
            vec![0],
            vec![1],
            vec![1, 0],
            vec![0xff],
            vec![0; MAX_KEY_LEN],
            vec![0xff; MAX_KEY_LEN],
        ] {
            let key = Bytes::from(key);
            let previous = previous_key(&key).expect("nonempty key has a predecessor");
            assert!(previous < key);
            assert_eq!(next_key(&previous), Some(key));
        }
        assert_eq!(previous_key(&Bytes::new()), None);
    }

    #[test]
    fn previous_key_clamps_oversized_bounds() {
        for len in [MAX_KEY_LEN + 1, MAX_KEY_LEN + 2, 1024] {
            for fill in [0, 1, 0xff] {
                for last in [0, 1, 0xff] {
                    let mut bytes = vec![fill; len];
                    bytes[len - 1] = last;
                    let key = Bytes::from(bytes);
                    let previous = previous_key(&key).expect("nonempty bound");
                    assert!(previous < key);
                    assert_eq!(previous, key.slice(..MAX_KEY_LEN));
                    assert!(validate_key_size(previous.len()).is_ok());
                }
            }
        }
    }

    #[test]
    fn key_size_validation_bounds() {
        assert!(validate_key_size(0).is_ok());
        assert!(validate_key_size(MAX_KEY_LEN).is_ok());
        assert!(validate_key_size(MAX_KEY_LEN + 1).is_err());
    }
}
