//! Indexer key layout.
//!
//! All keys live under a single 4-bit family prefix. Big-endian encoding is
//! used for every numeric field so the natural byte order matches the
//! sortable order of `view`/`height`/`index`.
//!
//! | Family       | Prefix | Payload                            | Stored value         |
//! | ------------ | ------ | ---------------------------------- | -------------------- |
//! | `BLOCK`      | `0x1`  | `digest` (32B)                     | encoded `EngineBlock` |
//! | `BLOCK_BY_H` | `0x2`  | `height` (u64 BE)                  | block digest (32B)   |
//! | `FINALIZED`  | `0x3`  | `view` (u64 BE)                    | encoded `Finalization` |
//! | `NOTARIZED`  | `0x4`  | `view` (u64 BE)                    | encoded `Notarization` |
//! | `TX`         | `0x5`  | `tx_digest` (32B)                  | encoded `SignedTransaction` |
//! | `TX_BY_H`    | `0x6`  | `height` (u64 BE) ‖ `index` (u32 BE) | tx digest (32B)    |
//! | `TX_BY_SENDER` | `0x7` | sender (32B) ‖ descending height/index | tx summary row |
//! | `ACCOUNT`    | `0xa`  | account key (32B)                  | account proof row |
//!
//! Reserved bits: 4. The remaining 4 bits of the first byte hold the family
//! prefix. The full payload (including any digest or numeric field) starts at
//! the second byte.
//!
//! The `latest_finalized_height` cursor and any other indexer metadata live
//! exclusively in the SQL `block_meta` table (see [`crate::sql_schema`]);
//! the KV path no longer carries a redundant `META` family.

use exoware_sdk::keys::{Key, KeyCodec, KeyCodecError};

/// Number of high bits reserved for the family prefix.
pub const RESERVED_BITS: u8 = 4;

/// Family for `digest -> Block`.
pub const BLOCK: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x1);
/// Family for `height -> block_digest`.
pub const BLOCK_BY_H: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x2);
/// Family for `view -> Finalization`.
pub const FINALIZED: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x3);
/// Family for `view -> Notarization`.
pub const NOTARIZED: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x4);
/// Family for `tx_digest -> SignedTransaction`.
pub const TX: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x5);
/// Family for `(height, index) -> tx_digest`.
pub const TX_BY_H: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x6);
/// Family for `sender -> recent sent transaction summary`.
pub const TX_BY_SENDER: KeyCodec = KeyCodec::new(RESERVED_BITS, 0x7);
/// Family for `account key -> latest indexed account state`.
pub const ACCOUNT: KeyCodec = KeyCodec::new(RESERVED_BITS, 0xa);

/// Encode a `BLOCK` key for the given block digest.
pub fn block(digest: &[u8]) -> Result<Key, KeyCodecError> {
    BLOCK.encode(digest)
}

/// Encode a `BLOCK_BY_H` key for the given block height.
pub fn block_by_height(height: u64) -> Result<Key, KeyCodecError> {
    BLOCK_BY_H.encode(&height.to_be_bytes())
}

/// Encode a `FINALIZED` key for the given consensus view.
pub fn finalized(view: u64) -> Result<Key, KeyCodecError> {
    FINALIZED.encode(&view.to_be_bytes())
}

/// Encode a `NOTARIZED` key for the given consensus view.
pub fn notarized(view: u64) -> Result<Key, KeyCodecError> {
    NOTARIZED.encode(&view.to_be_bytes())
}

/// Encode a `TX` key for the given transaction digest.
pub fn tx(digest: &[u8]) -> Result<Key, KeyCodecError> {
    TX.encode(digest)
}

/// Encode a `TX_BY_H` key for the (height, index) pair within a block.
pub fn tx_by_height(height: u64, index: u32) -> Result<Key, KeyCodecError> {
    let mut payload = [0u8; 12];
    payload[..8].copy_from_slice(&height.to_be_bytes());
    payload[8..].copy_from_slice(&index.to_be_bytes());
    TX_BY_H.encode(&payload)
}

/// Encode a `TX_BY_SENDER` key sorted by newest transaction first.
pub fn tx_by_sender(sender: &[u8], height: u64, index: u32) -> Result<Key, KeyCodecError> {
    let mut payload = Vec::with_capacity(sender.len() + 12);
    payload.extend_from_slice(sender);
    payload.extend_from_slice(&(u64::MAX - height).to_be_bytes());
    payload.extend_from_slice(&(u32::MAX - index).to_be_bytes());
    TX_BY_SENDER.encode(&payload)
}

/// Encode an `ACCOUNT` key for the given account public key bytes.
pub fn account(account: &[u8]) -> Result<Key, KeyCodecError> {
    ACCOUNT.encode(account)
}

/// Inclusive `(start, end)` bounds spanning every key under the `BLOCK` family.
pub fn block_bounds() -> (Key, Key) {
    BLOCK.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `BLOCK_BY_H`.
pub fn block_by_height_bounds() -> (Key, Key) {
    BLOCK_BY_H.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `FINALIZED`.
pub fn finalized_bounds() -> (Key, Key) {
    FINALIZED.prefix_bounds()
}

/// Inclusive `(start, end)` bounds spanning every key under `NOTARIZED`.
pub fn notarized_bounds() -> (Key, Key) {
    NOTARIZED.prefix_bounds()
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

    /// Each family must round-trip through `KeyCodec::matches`.
    #[test]
    fn family_keys_match_their_codec() {
        let digest = [0xABu8; 32];
        assert!(BLOCK.matches(&block(&digest).unwrap()));
        assert!(BLOCK_BY_H.matches(&block_by_height(7).unwrap()));
        assert!(FINALIZED.matches(&finalized(11).unwrap()));
        assert!(NOTARIZED.matches(&notarized(13).unwrap()));
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
        let k = block(&digest).unwrap();
        assert!(!BLOCK_BY_H.matches(&k));
        assert!(!FINALIZED.matches(&k));
        assert!(!NOTARIZED.matches(&k));
        assert!(!TX.matches(&k));
        assert!(!TX_BY_H.matches(&k));
        assert!(!TX_BY_SENDER.matches(&k));
        assert!(!ACCOUNT.matches(&k));
    }

    /// Big-endian numeric encoding must preserve sortable order.
    #[test]
    fn block_by_height_keys_are_sortable() {
        let lo = block_by_height(1).unwrap();
        let mid = block_by_height(1_000).unwrap();
        let hi = block_by_height(u64::MAX).unwrap();
        assert!(lo < mid);
        assert!(mid < hi);
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
            (block_bounds(), BLOCK.prefix_bounds()),
            (block_by_height_bounds(), BLOCK_BY_H.prefix_bounds()),
            (finalized_bounds(), FINALIZED.prefix_bounds()),
            (notarized_bounds(), NOTARIZED.prefix_bounds()),
            (tx_bounds(), TX.prefix_bounds()),
            (tx_by_height_bounds(), TX_BY_H.prefix_bounds()),
            (tx_by_sender_bounds(), TX_BY_SENDER.prefix_bounds()),
            (account_bounds(), ACCOUNT.prefix_bounds()),
        ];
        for (helper, codec) in pairs {
            assert_eq!(helper, codec);
        }

        let k = block_by_height(42).unwrap();
        let (lo, hi) = block_by_height_bounds();
        assert!(lo <= k && k <= hi);
    }
}
