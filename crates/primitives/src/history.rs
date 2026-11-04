//! Authenticated transaction-history values.

use bytes::BufMut;
use commonware_codec::{Buf, Error, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::Digest;

/// A transaction and its zero-based position in each participant's history.
///
/// Indices advance in block order. A self-transfer uses the same index for both
/// roles and consumes one position. The fixed encoding is the message digest,
/// sender index, and recipient index, with both indices in big-endian order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionHistoryEntry<D> {
    /// Sealed transaction message digest.
    pub digest: D,
    /// Position in the sender's history.
    pub sender_index: u64,
    /// Position in the recipient's history.
    pub recipient_index: u64,
}

impl<D: Digest> FixedSize for TransactionHistoryEntry<D> {
    const SIZE: usize = D::SIZE + 2 * u64::SIZE;
}

impl<D: Digest> Write for TransactionHistoryEntry<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.digest.write(buf);
        self.sender_index.write(buf);
        self.recipient_index.write(buf);
    }
}

impl<D: Digest> Read for TransactionHistoryEntry<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            digest: D::read(buf)?,
            sender_index: u64::read(buf)?,
            recipient_index: u64::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::sha256;

    #[test]
    fn fixed_encoding_binds_both_indices() {
        let entry = TransactionHistoryEntry {
            digest: sha256::Digest::from([7; 32]),
            sender_index: 0x0102030405060708,
            recipient_index: u64::MAX,
        };
        let bytes = entry.encode();
        assert_eq!(TransactionHistoryEntry::<sha256::Digest>::SIZE, 48);
        assert_eq!(&bytes[..32], &[7; 32]);
        assert_eq!(&bytes[32..40], &entry.sender_index.to_be_bytes());
        assert_eq!(&bytes[40..48], &entry.recipient_index.to_be_bytes());
        assert_eq!(
            TransactionHistoryEntry::decode(bytes.clone()).unwrap(),
            entry
        );
        for length in 0..bytes.len() {
            assert!(
                TransactionHistoryEntry::<sha256::Digest>::decode(bytes.slice(..length)).is_err()
            );
        }
    }
}
