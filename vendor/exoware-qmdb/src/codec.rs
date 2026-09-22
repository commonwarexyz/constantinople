use commonware_codec::DecodeExt;
use commonware_cryptography::Digest;
use commonware_storage::merkle::{Family, Location, Position};
use commonware_utils::bitmap::Prunable;
use exoware_sdk::keys::{Key, KeyMut, Prefix};

use crate::error::QmdbError;
use crate::MAX_OPERATION_SIZE;

// A family byte encodes *row semantics* (what kind of row this is), not which
// instance or backend it belongs to. The same semantic row therefore uses the
// same family byte across ALL backend variants (ordered, unordered, immutable,
// keyless). Instance identity lives solely in the outer Store
// namespace (the SDK `StoreKeyPrefix`). A single raw Store keyspace must never
// be shared across multiple QMDB backends or instances, so reusing family bytes
// across variants is safe.
pub(crate) const UPDATE_FAMILY: u8 = 0x1;
pub(crate) const PRESENCE_FAMILY: u8 = 0x2;
pub(crate) const WATERMARK_FAMILY: u8 = 0x3;
pub(crate) const OP_FAMILY: u8 = 0x4;
pub const NODE_FAMILY: u8 = 0x5;
pub(crate) const GRAFTED_NODE_FAMILY: u8 = 0x6;
pub const CHUNK_FAMILY: u8 = 0x7;
pub(crate) const CURRENT_META_FAMILY: u8 = 0x8;
pub(crate) const OPS_ROOT_WITNESS_FAMILY: u8 = 0x9;

pub(crate) const UPDATE_VERSION_LEN: usize = 8;
const UPDATE_INDEX_INACTIVE: u8 = 0;
const UPDATE_INDEX_ACTIVE: u8 = 1;
// Ordered keys are embedded in store keys ahead of a fixed-width version suffix
// and compared lexicographically. A length prefix would sort by length before
// key bytes, so use an escaped zero terminator and escape embedded zero bytes.
pub(crate) const ORDERED_KEY_ESCAPE_BYTE: u8 = 0x00;
pub(crate) const ORDERED_KEY_ZERO_ESCAPE: u8 = 0xFF;
pub(crate) const ORDERED_KEY_TERMINATOR_LEN: usize = 2;

pub(crate) const UPDATE_PREFIX: Prefix = Prefix::from_static(&[UPDATE_FAMILY]);
pub(crate) const PRESENCE_PREFIX: Prefix = Prefix::from_static(&[PRESENCE_FAMILY]);
pub(crate) const WATERMARK_PREFIX: Prefix = Prefix::from_static(&[WATERMARK_FAMILY]);
pub(crate) const OPERATION_PREFIX: Prefix = Prefix::from_static(&[OP_FAMILY]);
pub(crate) const NODE_PREFIX: Prefix = Prefix::from_static(&[NODE_FAMILY]);
pub(crate) const CURRENT_META_PREFIX: Prefix = Prefix::from_static(&[CURRENT_META_FAMILY]);
pub(crate) const GRAFTED_NODE_PREFIX: Prefix = Prefix::from_static(&[GRAFTED_NODE_FAMILY]);
pub(crate) const CHUNK_PREFIX: Prefix = Prefix::from_static(&[CHUNK_FAMILY]);
pub(crate) const OPS_ROOT_WITNESS_PREFIX: Prefix = Prefix::from_static(&[OPS_ROOT_WITNESS_FAMILY]);

pub(crate) const fn bitmap_chunk_bits<const N: usize>() -> u64 {
    Prunable::<N>::CHUNK_SIZE_BITS
}

pub(crate) fn chunk_index_for_location<F: Family, const N: usize>(location: Location<F>) -> u64 {
    *location / bitmap_chunk_bits::<N>()
}

pub(crate) fn decode_digest<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<D, QmdbError> {
    D::decode(commonware_codec::Copying(bytes))
        .map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CurrentBoundaryMetadata<D: Digest> {
    pub(crate) root: D,
    pub(crate) pruned_chunks: u64,
}

impl<D: Digest> commonware_codec::Write for CurrentBoundaryMetadata<D> {
    fn write(&self, buf: &mut impl ::bytes::BufMut) {
        <(D, u64) as commonware_codec::Write>::write(&(self.root, self.pruned_chunks), buf);
    }
}

impl<D: Digest> commonware_codec::FixedSize for CurrentBoundaryMetadata<D> {
    const SIZE: usize =
        <D as commonware_codec::FixedSize>::SIZE + <u64 as commonware_codec::FixedSize>::SIZE;
}

impl<D: Digest> commonware_codec::Read for CurrentBoundaryMetadata<D> {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl commonware_codec::Buf,
        _: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let (root, pruned_chunks) = <(D, u64) as commonware_codec::Read>::read_cfg(buf, &((), ()))?;
        Ok(CurrentBoundaryMetadata {
            root,
            pruned_chunks,
        })
    }
}

pub(crate) fn decode_current_boundary_metadata<D: Digest>(
    bytes: &[u8],
    label: impl std::fmt::Display,
) -> Result<CurrentBoundaryMetadata<D>, QmdbError> {
    CurrentBoundaryMetadata::<D>::decode(commonware_codec::Copying(bytes))
        .map_err(|e| QmdbError::CorruptData(format!("{label} decode error: {e}")))
}

pub(crate) fn merkle_size_for_watermark<F: Family>(
    watermark: Location<F>,
) -> Result<Position<F>, QmdbError> {
    let leaves = op_count_for_watermark(watermark)?;
    Position::try_from(leaves)
        .map_err(|e| QmdbError::CorruptData(format!("invalid merkle size for watermark: {e}")))
}

pub(crate) fn op_count_for_watermark<F: Family>(
    watermark: Location<F>,
) -> Result<Location<F>, QmdbError> {
    watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))
}

pub(crate) fn ensure_encoded_value_size(len: usize) -> Result<(), QmdbError> {
    if len <= MAX_OPERATION_SIZE {
        Ok(())
    } else {
        Err(QmdbError::EncodedValueTooLarge {
            len,
            max: MAX_OPERATION_SIZE,
        })
    }
}

/// Read a big-endian `u64` location from the first 8 bytes of a stripped
/// payload, returning [`QmdbError::CorruptData`] when it is too short.
pub(crate) fn decode_location_bytes(
    payload: &[u8],
    label: impl std::fmt::Display,
) -> Result<u64, QmdbError> {
    let bytes: [u8; 8] = payload
        .get(..8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| QmdbError::CorruptData(format!("cannot decode {label}: short key")))?;
    Ok(u64::from_be_bytes(bytes))
}

pub(crate) fn ordered_key_encoded_len(raw_key: &[u8]) -> usize {
    raw_key.len()
        + raw_key
            .iter()
            .filter(|&&byte| byte == ORDERED_KEY_ESCAPE_BYTE)
            .count()
        + ORDERED_KEY_TERMINATOR_LEN
}

pub(crate) fn encode_ordered_key_bytes(raw_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ordered_key_encoded_len(raw_key));
    for &byte in raw_key {
        if byte == ORDERED_KEY_ESCAPE_BYTE {
            out.push(ORDERED_KEY_ESCAPE_BYTE);
            out.push(ORDERED_KEY_ZERO_ESCAPE);
        } else {
            out.push(byte);
        }
    }
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out
}

pub(crate) fn validate_ordered_key_bytes(bytes: &[u8], label: &str) -> Result<(), QmdbError> {
    if bytes.len() < ORDERED_KEY_TERMINATOR_LEN {
        return Err(QmdbError::CorruptData(format!(
            "{label} shorter than ordered-key terminator"
        )));
    }
    let mut idx = 0usize;
    let end = bytes.len() - ORDERED_KEY_TERMINATOR_LEN;
    while idx < end {
        if bytes[idx] == ORDERED_KEY_ESCAPE_BYTE {
            match bytes.get(idx + 1) {
                Some(&ORDERED_KEY_ZERO_ESCAPE) => idx += 2,
                Some(_) => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} contains invalid ordered-key escape"
                    )))
                }
                None => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} truncated in ordered-key escape"
                    )))
                }
            }
        } else {
            idx += 1;
        }
    }
    if bytes[end] != ORDERED_KEY_ESCAPE_BYTE || bytes[end + 1] != ORDERED_KEY_ESCAPE_BYTE {
        return Err(QmdbError::CorruptData(format!(
            "{label} missing ordered-key terminator"
        )));
    }
    Ok(())
}

pub(crate) fn decode_ordered_key_bytes(bytes: &[u8]) -> Result<Vec<u8>, QmdbError> {
    validate_ordered_key_bytes(bytes, "update key")?;
    let mut out = Vec::with_capacity(bytes.len().saturating_sub(ORDERED_KEY_TERMINATOR_LEN));
    let end = bytes.len() - ORDERED_KEY_TERMINATOR_LEN;
    let mut idx = 0usize;
    while idx < end {
        if bytes[idx] == ORDERED_KEY_ESCAPE_BYTE {
            out.push(ORDERED_KEY_ESCAPE_BYTE);
            idx += 2;
        } else {
            out.push(bytes[idx]);
            idx += 1;
        }
    }
    Ok(out)
}

pub(crate) fn encode_update_key<F: Family>(
    raw_key: &[u8],
    location: Location<F>,
) -> Result<Key, QmdbError> {
    let encoded = encode_ordered_key_bytes(raw_key);
    let payload_len = encoded.len() + UPDATE_VERSION_LEN;
    let max = UPDATE_PREFIX.max_payload_len();
    if payload_len > max {
        return Err(QmdbError::SortableKeyTooLarge {
            raw_len: raw_key.len(),
            encoded_len: payload_len,
            max,
        });
    }
    let mut key = KeyMut::with_capacity(UPDATE_PREFIX.len() + payload_len);
    key.extend_from_slice(UPDATE_PREFIX.as_bytes());
    key.extend_from_slice(&encoded);
    key.extend_from_slice(&location.as_u64().to_be_bytes());
    Ok(key.freeze())
}

/// Strip the update-family prefix and split the payload at the fixed-width
/// location suffix, returning the payload plus the ordered-key region length.
fn split_update_payload(key: &Key) -> Result<(Key, usize), QmdbError> {
    let payload = UPDATE_PREFIX
        .strip(key)
        .map_err(|_| QmdbError::CorruptData("update key prefix mismatch".to_string()))?;
    if payload.len() < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "update key payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload.len() - UPDATE_VERSION_LEN;
    Ok((payload, ordered_len))
}

pub(crate) fn decode_update_location<F: Family>(key: &Key) -> Result<Location<F>, QmdbError> {
    let (payload, ordered_len) = split_update_payload(key)?;
    validate_ordered_key_bytes(&payload[..ordered_len], "update key")?;
    Ok(Location::new(decode_location_bytes(
        &payload[ordered_len..],
        "update location",
    )?))
}

pub(crate) fn decode_update_raw_key(key: &Key) -> Result<Vec<u8>, QmdbError> {
    let (payload, ordered_len) = split_update_payload(key)?;
    decode_ordered_key_bytes(&payload[..ordered_len])
}

pub(crate) fn encode_update_index_value(value_present: bool) -> Vec<u8> {
    vec![if value_present {
        UPDATE_INDEX_ACTIVE
    } else {
        UPDATE_INDEX_INACTIVE
    }]
}

pub(crate) fn decode_update_index_value_present(bytes: &[u8]) -> Result<bool, QmdbError> {
    match bytes {
        [UPDATE_INDEX_INACTIVE] => Ok(false),
        [UPDATE_INDEX_ACTIVE] => Ok(true),
        _ => Err(QmdbError::CorruptData(format!(
            "update index value has unexpected length {}",
            bytes.len()
        ))),
    }
}

pub(crate) fn encode_presence_key<F: Family>(latest_location: Location<F>) -> Key {
    PRESENCE_PREFIX
        .encode(&latest_location.as_u64().to_be_bytes())
        .expect("presence key length should fit")
}

pub(crate) fn encode_watermark_key<F: Family>(location: Location<F>) -> Key {
    WATERMARK_PREFIX
        .encode(&location.as_u64().to_be_bytes())
        .expect("watermark key length should fit")
}

/// Strip `prefix` from `key` and decode the payload as a big-endian `u64`
/// location, labelling both failure modes with `label`.
fn decode_prefixed_location<F: Family>(
    prefix: &Prefix,
    key: &Key,
    label: &str,
) -> Result<Location<F>, QmdbError> {
    let payload = prefix
        .strip(key)
        .map_err(|_| QmdbError::CorruptData(format!("{label} key prefix mismatch")))?;
    Ok(Location::new(decode_location_bytes(
        &payload,
        format_args!("{label} location"),
    )?))
}

pub(crate) fn decode_watermark_location<F: Family>(key: &Key) -> Result<Location<F>, QmdbError> {
    decode_prefixed_location(&WATERMARK_PREFIX, key, "watermark")
}

pub(crate) fn encode_operation_key<F: Family>(location: Location<F>) -> Key {
    OPERATION_PREFIX
        .encode(&location.as_u64().to_be_bytes())
        .expect("operation key length should fit")
}

pub(crate) fn encode_node_key<F: Family>(position: Position<F>) -> Key {
    NODE_PREFIX
        .encode(&position.as_u64().to_be_bytes())
        .expect("node key length should fit")
}

pub(crate) fn encode_current_meta_key<F: Family>(location: Location<F>) -> Key {
    CURRENT_META_PREFIX
        .encode(&location.as_u64().to_be_bytes())
        .expect("current meta key length should fit")
}

pub(crate) fn encode_ops_root_witness_key<F: Family>(location: Location<F>) -> Key {
    OPS_ROOT_WITNESS_PREFIX
        .encode(&location.as_u64().to_be_bytes())
        .expect("ops root witness key length should fit")
}

pub(crate) fn encode_grafted_node_key<F: Family>(
    position: Position<F>,
    watermark: Location<F>,
) -> Key {
    let mut payload = [0u8; 16];
    payload[..8].copy_from_slice(&position.as_u64().to_be_bytes());
    payload[8..].copy_from_slice(&watermark.as_u64().to_be_bytes());
    GRAFTED_NODE_PREFIX
        .encode(&payload)
        .expect("grafted node key length should fit")
}

pub(crate) fn encode_chunk_key<F: Family>(chunk_index: u64, watermark: Location<F>) -> Key {
    let mut payload = [0u8; 16];
    payload[..8].copy_from_slice(&chunk_index.to_be_bytes());
    payload[8..].copy_from_slice(&watermark.as_u64().to_be_bytes());
    CHUNK_PREFIX
        .encode(&payload)
        .expect("chunk key length should fit")
}

/// Clear every bitmap bit below `floor` within the chunk at `chunk_index`.
///
/// Bits below the inactivity floor are definitionally 0 at any watermark. The
/// producer does not republish a chunk every time floor advancement flips one
/// of its bits, so the stored payload may carry stale 1s. Fold those clears
/// in deterministically at read time. Mirrors the bit layout used by
/// `commonware_utils::bitmap::BitMap`: byte offset within the chunk is
/// `(L / 8) % N`, bit mask is `1 << (L % 8)`.
pub(crate) fn clear_below_floor<F: Family, const N: usize>(
    chunk: &mut [u8; N],
    chunk_index: u64,
    floor: Location<F>,
) {
    let chunk_bits = bitmap_chunk_bits::<N>();
    let chunk_start = chunk_index.saturating_mul(chunk_bits);
    let chunk_end_exclusive = chunk_start.saturating_add(chunk_bits);
    if *floor <= chunk_start {
        return;
    }
    if *floor >= chunk_end_exclusive {
        *chunk = [0u8; N];
        return;
    }
    let bits_to_clear = (*floor - chunk_start) as usize;
    let whole_bytes = bits_to_clear / 8;
    let remainder = bits_to_clear % 8;
    for byte in &mut chunk[..whole_bytes] {
        *byte = 0;
    }
    if remainder != 0 {
        chunk[whole_bytes] &= !((1u8 << remainder) - 1);
    }
}

pub(crate) fn decode_operation_location_key<F: Family>(
    key: &Key,
) -> Result<Location<F>, QmdbError> {
    decode_prefixed_location(&OPERATION_PREFIX, key, "operation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::mmr;

    #[test]
    fn test_current_boundary_metadata_uses_commonware_codec_layout() {
        let root = Sha256::fill(0xA5);
        let metadata = CurrentBoundaryMetadata {
            root,
            pruned_chunks: 0x0102_0304_0506_0708,
        };
        let encoded = metadata.encode().to_vec();

        assert_eq!(encoded.len(), root.as_ref().len() + 8);
        assert_eq!(&encoded[..root.as_ref().len()], root.as_ref());
        assert_eq!(
            &encoded[root.as_ref().len()..],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );

        let decoded = decode_current_boundary_metadata::<commonware_cryptography::sha256::Digest>(
            &encoded,
            "test current boundary metadata".to_string(),
        )
        .unwrap();
        assert_eq!(decoded, metadata);
    }

    fn clear_below_floor_bitwise<F: Family, const N: usize>(
        chunk: &mut [u8; N],
        chunk_index: u64,
        floor: Location<F>,
    ) {
        let chunk_bits = bitmap_chunk_bits::<N>();
        let chunk_start = chunk_index.saturating_mul(chunk_bits);
        let chunk_end_exclusive = chunk_start.saturating_add(chunk_bits);
        if *floor <= chunk_start {
            return;
        }
        if *floor >= chunk_end_exclusive {
            *chunk = [0u8; N];
            return;
        }
        for bit in chunk_start..*floor {
            let byte_offset = ((bit / 8) % N as u64) as usize;
            let mask: u8 = 1u8 << (bit % 8);
            chunk[byte_offset] &= !mask;
        }
    }

    #[test]
    fn test_clear_below_floor_matches_bitwise_reference() {
        const N: usize = 4;
        let chunk_bits = bitmap_chunk_bits::<N>();
        for chunk_index in 0..3u64 {
            let chunk_start = chunk_index * chunk_bits;
            for floor_bit in 0..=(chunk_start + chunk_bits + 4) {
                let original = [0xAB_u8; N];
                let mut optimized = original;
                let mut reference = original;
                clear_below_floor::<mmr::Family, N>(
                    &mut optimized,
                    chunk_index,
                    Location::new(floor_bit),
                );
                clear_below_floor_bitwise::<mmr::Family, N>(
                    &mut reference,
                    chunk_index,
                    Location::new(floor_bit),
                );
                assert_eq!(
                    optimized, reference,
                    "mismatch at chunk_index={chunk_index} floor={floor_bit}"
                );
            }
        }
    }
}
