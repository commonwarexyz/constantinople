//! Raw indexer key layout.
//!
//! Full blocks and consensus certificates live in `exoware-simplex`. This
//! module only defines the raw KV families that remain outside Simplex:
//! transaction lookup/index rows and account proof rows.
//!
//! All keys live under a single 4-bit family prefix. Big-endian encoding is
//! used for every numeric field so natural byte order matches sortable order.
//!
//! | Family       | Prefix | Payload                              | Stored value |
//! | ------------ | ------ | ------------------------------------ | ------------ |
//! | `TX`         | `0x1`  | `tx_digest` (32B)                    | encoded `SignedTransaction` |
//! | `TX_BY_H`    | `0x2`  | `height` (u64 BE) ‖ `index` (u32 BE) | tx digest (32B) |
//! | `TX_BY_SENDER` | `0x3` | sender (32B) ‖ descending height/index | tx summary row |
//! | `ACCOUNT`    | `0x4`  | account key (32B)                    | account proof row |

use bytes::Bytes;
use exoware_sdk::keys::{Key, KeyCodec, KeyCodecError};

/// Number of high bits reserved for the family prefix.
pub const RESERVED_BITS: u8 = 4;

/// Family for `tx_digest -> SignedTransaction`.
pub const TX: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x1);
/// Family for `(height, index) -> tx_digest`.
pub const TX_BY_H: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x2);
/// Family for `sender -> recent sent transaction summary`.
pub const TX_BY_SENDER: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x3);
/// Family for `account key -> latest indexed account state`.
pub const ACCOUNT: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x4);

/// Encode a `TX` key for the given transaction digest.
pub fn tx(digest: &[u8]) -> Result<Key, KeyCodecError> {
    encode_indexer_key(TX.prefix(), digest)
}

/// Encode a `TX_BY_H` key for the (height, index) pair within a block.
pub fn tx_by_height(height: u64, index: u32) -> Result<Key, KeyCodecError> {
    let mut payload = [0u8; 12];
    payload[..8].copy_from_slice(&height.to_be_bytes());
    payload[8..].copy_from_slice(&index.to_be_bytes());
    encode_indexer_key(TX_BY_H.prefix(), &payload)
}

/// Encode a `TX_BY_SENDER` key sorted by newest transaction first.
pub fn tx_by_sender(sender: &[u8], height: u64, index: u32) -> Result<Key, KeyCodecError> {
    let mut payload = Vec::with_capacity(sender.len() + 12);
    payload.extend_from_slice(sender);
    payload.extend_from_slice(&(u64::MAX - height).to_be_bytes());
    payload.extend_from_slice(&(u32::MAX - index).to_be_bytes());
    encode_indexer_key(TX_BY_SENDER.prefix(), &payload)
}

/// Encode an `ACCOUNT` key for the given account public key bytes.
pub fn account(account: &[u8]) -> Result<Key, KeyCodecError> {
    encode_indexer_key(ACCOUNT.prefix(), account)
}

fn encode_indexer_key(prefix: u16, payload: &[u8]) -> Result<Key, KeyCodecError> {
    let max_payload_len = TX.max_payload_capacity_bytes();
    if payload.len() > max_payload_len {
        return Err(KeyCodecError::PayloadTooLarge {
            payload_len: payload.len(),
            max_payload_len,
        });
    }

    debug_assert_eq!(RESERVED_BITS, 4);
    debug_assert!(prefix <= 0x0f);

    let prefix = u8::try_from(prefix).expect("indexer key prefix fits u8") << 4;
    if payload.is_empty() {
        return Ok(Bytes::copy_from_slice(&[prefix]));
    }

    let mut key = Vec::with_capacity(payload.len() + 1);
    key.push(prefix | (payload[0] >> 4));
    for bytes in payload.windows(2) {
        key.push((bytes[0] << 4) | (bytes[1] >> 4));
    }
    key.push(payload[payload.len() - 1] << 4);
    Ok(Bytes::from(key))
}

/// Inclusive `(start, end)` bounds spanning every key under `TX`.
pub fn tx_bounds() -> (Key, Key) {
    TX.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `TX_BY_H`.
pub fn tx_by_height_bounds() -> (Key, Key) {
    TX_BY_H.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `TX_BY_SENDER`.
pub fn tx_by_sender_bounds() -> (Key, Key) {
    TX_BY_SENDER.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `ACCOUNT`.
pub fn account_bounds() -> (Key, Key) {
    ACCOUNT.prefix_bounds()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each active family must round-trip through `KeyCodec::matches`.
    #[test]
    fn family_keys_match_their_codec() {
        let digest = [0xABu8; 32];
        assert!(TX.matches(&tx(&digest).unwrap()));
        assert!(TX_BY_H.matches(&tx_by_height(17, 0).unwrap()));
        assert!(TX_BY_SENDER.matches(&tx_by_sender(&digest, 17, 0).unwrap()));
        assert!(ACCOUNT.matches(&account(&digest).unwrap()));
    }

    /// Family prefixes must not overlap; a key from one family must not match
    /// a sibling family's codec.
    #[test]
    fn family_prefixes_are_disjoint() {
        let digest = [0u8; 32];
        let k = tx(&digest).unwrap();
        assert!(!TX_BY_H.matches(&k));
        assert!(!TX_BY_SENDER.matches(&k));
        assert!(!ACCOUNT.matches(&k));
    }

    /// `tx_by_height` orders first by height, then by index within a block.
    #[test]
    fn tx_by_height_orders_height_before_index() {
        let h1_i9 = tx_by_height(1, 9).unwrap();
        let h2_i0 = tx_by_height(2, 0).unwrap();
        let h2_i5 = tx_by_height(2, 5).unwrap();
        assert!(h1_i9 < h2_i0);
        assert!(h2_i0 < h2_i5);
    }

    /// `tx_by_sender` keeps each sender grouped and orders newest rows first.
    #[test]
    fn tx_by_sender_orders_newest_first_within_sender() {
        let sender = [0x11u8; 32];
        let older = tx_by_sender(&sender, 9, 9).unwrap();
        let newer = tx_by_sender(&sender, 10, 0).unwrap();
        let same_height_later_index = tx_by_sender(&sender, 10, 2).unwrap();

        assert!(newer < older);
        assert!(same_height_later_index < newer);
    }

    /// `prefix_bounds` returned by helpers must match the underlying codec's
    /// own bounds, and must contain at least one valid key from that family.
    #[test]
    fn prefix_bounds_helpers_match_codec_bounds() {
        let pairs = [
            (tx_bounds(), TX.prefix_bounds()),
            (tx_by_height_bounds(), TX_BY_H.prefix_bounds()),
            (tx_by_sender_bounds(), TX_BY_SENDER.prefix_bounds()),
            (account_bounds(), ACCOUNT.prefix_bounds()),
        ];
        for (helper, codec) in pairs {
            assert_eq!(helper, codec);
        }

        let k = tx_by_height(42, 0).unwrap();
        let (lo, hi) = tx_by_height_bounds();
        assert!(lo <= k && k <= hi);
    }
}
