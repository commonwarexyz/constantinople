use bytes::{BufMut, Bytes, BytesMut};
use commonware_consensus::types::{Height, Round};
use commonware_cryptography::Digest;
use exoware_sdk::keys::Key;

/// Leading byte of every Simplex row key within the client's Store namespace
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    HeaderByDigest = 1,
    BlockByDigest = 2,
    NotarizationByRound = 3,
    FinalizationByRound = 4,
    FinalizedByHeight = 5,
}

impl RecordKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

fn key_from_parts(kind: RecordKind, suffix: &[u8]) -> Key {
    let mut key = BytesMut::with_capacity(1 + suffix.len());
    key.put_u8(kind.as_u8());
    key.put_slice(suffix);
    key.freeze()
}

pub fn header_by_digest<D: Digest>(digest: &D) -> Key {
    key_from_parts(RecordKind::HeaderByDigest, digest.as_ref())
}

pub fn block_by_digest<D: Digest>(digest: &D) -> Key {
    key_from_parts(RecordKind::BlockByDigest, digest.as_ref())
}

fn round_key(kind: RecordKind, round: Round) -> Key {
    let mut suffix = [0; 16];
    suffix[..8].copy_from_slice(&round.epoch().get().to_be_bytes());
    suffix[8..].copy_from_slice(&round.view().get().to_be_bytes());
    key_from_parts(kind, &suffix)
}

pub fn notarization_by_round(round: Round) -> Key {
    round_key(RecordKind::NotarizationByRound, round)
}

pub fn finalization_by_round(round: Round) -> Key {
    round_key(RecordKind::FinalizationByRound, round)
}

pub fn finalized_by_height(height: Height) -> Key {
    key_from_parts(RecordKind::FinalizedByHeight, &height.get().to_be_bytes())
}

pub fn finalized_height_from_key(key: &[u8]) -> Option<Height> {
    let suffix = key.strip_prefix(&[RecordKind::FinalizedByHeight.as_u8()])?;
    Some(Height::new(u64::from_be_bytes(suffix.try_into().ok()?)))
}

pub fn range_for_kind(kind: RecordKind) -> (Key, Key) {
    let start = Bytes::copy_from_slice(&[kind.as_u8()]);
    let end = Bytes::copy_from_slice(&[kind.as_u8() + 1]);
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::types::{Epoch, View};
    use commonware_cryptography::Sha256;

    // The TypeScript client test "simplex keys match the Rust key layout" asserts the same bytes
    #[test]
    fn key_layout() {
        let digest = Sha256::fill(0xab);
        assert_eq!(
            hex::encode(header_by_digest(&digest)),
            format!("01{}", "ab".repeat(32))
        );
        assert_eq!(
            hex::encode(block_by_digest(&digest)),
            format!("02{}", "ab".repeat(32))
        );
        let round = Round::new(Epoch::new(0x1_0000_0000), View::new(7));
        assert_eq!(
            hex::encode(notarization_by_round(round)),
            "0300000001000000000000000000000007"
        );
        assert_eq!(
            hex::encode(finalization_by_round(round)),
            "0400000001000000000000000000000007"
        );
        let height = Height::new(258);
        assert_eq!(
            hex::encode(finalized_by_height(height)),
            "050000000000000102"
        );
        assert_eq!(
            finalized_height_from_key(&finalized_by_height(height)),
            Some(height)
        );
        assert_eq!(
            finalized_height_from_key(&notarization_by_round(round)),
            None
        );
        let (start, end) = range_for_kind(RecordKind::FinalizedByHeight);
        assert_eq!((start.as_ref(), end.as_ref()), (&[5u8][..], &[6u8][..]));
    }
}
