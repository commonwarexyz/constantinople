//! Block row encoding shared by the metadata and bulk publisher lanes.

use crate::publisher::{
    SqlRow,
    sql::{
        BlockMetaRow, TxActivityRole, TxActivityRow, TxMetaRow, encode_block_meta_row,
        encode_tx_activity_row, encode_tx_meta_row,
    },
};
use bytes::Bytes;
use commonware_codec::FixedSize;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{
    AccountKey, LazySignedTransaction, Transaction, TransactionPublicKey,
};
use std::array::TryFromSliceError;
use tracing::warn;

/// Bulk-lane rows for a finalized block.
///
/// The `block_meta` row is deliberately absent. The metadata fast lane commits
/// it separately, ahead of this batch, so feed visibility of the block does
/// not wait on the multi-MB bulk upload.
pub(crate) struct BulkBlockRows<D: Digest> {
    /// SQL rows for transaction metadata and account activity.
    pub sql: Vec<SqlRow>,
    /// Transaction digests in append order.
    pub transaction_digests: Vec<D>,
}

struct IndexedTransaction<D: Digest> {
    block_index: usize,
    digest: D,
    bytes: Bytes,
    sender: AccountKey,
    to: [u8; AccountKey::SIZE],
    value: u64,
    nonce: u64,
}

/// Build only the `block_meta` row for the metadata fast lane.
///
/// This runs the same transaction classification as the bulk encoding because
/// `tx_count` must count exactly the transactions the bulk rows index. The
/// duplicated classification keeps the lanes independent. The metadata Put
/// never waits behind bulk row expansion or QMDB preparation.
pub(crate) fn encode_block_meta_only_at<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
) -> SqlRow
where
    H: Hasher,
    P: PublicKey,
{
    let tx_count =
        u64::try_from(indexed_transactions(block).count()).expect("transaction count fits u64");
    block_meta_row(block, tx_count, finalized_ts_micros)
}

fn block_meta_row<H, P>(
    block: &EngineBlock<H, P>,
    tx_count: u64,
    finalized_ts_micros: i64,
) -> SqlRow
where
    H: Hasher,
    P: PublicKey,
{
    // SQL `block_meta.digest` is `FixedSizeBinary(32)`. Copy it into a
    // `[u8; 32]` for the typed CellValue path.
    let mut block_digest_arr = [0u8; 32];
    block_digest_arr.copy_from_slice(block.seal().as_ref());
    let mut transactions_root = [0u8; 32];
    transactions_root.copy_from_slice(block.header.transactions_root.as_ref());

    // `view` is currently 0.
    // See `encode_block_meta_row` docs for why.
    encode_block_meta_row(BlockMetaRow {
        height: block.header.height,
        digest: block_digest_arr,
        tx_count,
        transactions_root,
        transactions_tip: block.header.transactions_range.end() - 1,
        view: 0,
        finalized_ts_micros,
    })
}

fn indexed_transactions<H, P>(
    block: &EngineBlock<H, P>,
) -> impl Iterator<Item = IndexedTransaction<H::Digest>> + '_
where
    H: Hasher,
    P: PublicKey,
{
    let height = block.header.height;
    block
        .body
        .iter()
        .enumerate()
        .filter_map(move |(idx, lazy)| index_transaction::<H>(height, idx, lazy))
}

pub(crate) fn encode_bulk_block_rows<H, P>(block: &EngineBlock<H, P>) -> BulkBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let height = block.header.height;
    let body_len = block.body.len();
    let indexed_txs = indexed_transactions(block).collect::<Vec<_>>();
    let tx_count = u64::try_from(indexed_txs.len()).expect("transaction count fits u64");
    let append_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(tx_count + 1)
        .expect("transaction range includes appends plus commit");

    let mut sql = Vec::with_capacity(3 * body_len);

    // One tx_meta row plus sender/receiver tx_activity rows per transaction.
    let mut transaction_digests = Vec::with_capacity(indexed_txs.len());
    for (materialized_idx, tx) in indexed_txs.into_iter().enumerate() {
        transaction_digests.push(tx.digest);
        let idx_u32 = u32::try_from(tx.block_index).expect("transaction index fits u32");
        let qmdb_location = append_start + u64::try_from(materialized_idx).expect("index fits u64");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(tx.digest.as_ref());
        let mut sender = [0u8; AccountKey::SIZE];
        sender.copy_from_slice(tx.sender.as_ref());
        let receiver = tx.to;
        sql.push(encode_tx_meta_row(TxMetaRow {
            digest,
            qmdb_location,
            body: tx.bytes,
        }));
        sql.push(encode_tx_activity_row(TxActivityRow {
            account: sender,
            role: TxActivityRole::Sender,
            height,
            index: idx_u32,
            digest,
            counterparty: receiver,
            value: tx.value,
            nonce: tx.nonce,
        }));
        if receiver != sender {
            sql.push(encode_tx_activity_row(TxActivityRow {
                account: receiver,
                role: TxActivityRole::Receiver,
                height,
                index: idx_u32,
                digest,
                counterparty: sender,
                value: tx.value,
                nonce: tx.nonce,
            }));
        }
    }

    BulkBlockRows {
        sql,
        transaction_digests,
    }
}

fn index_transaction<H>(
    height: u64,
    block_index: usize,
    transaction: &LazySignedTransaction<H>,
) -> Option<IndexedTransaction<H::Digest>>
where
    H: Hasher,
{
    let signed_bytes = transaction.encoded_signed_transaction();
    let transaction_size = Transaction::<H::Digest>::SIZE;
    if signed_bytes.len() < transaction_size {
        warn!(
            height,
            block_index,
            signed_len = signed_bytes.len(),
            transaction_size,
            "indexer: skipping transaction with truncated signed payload"
        );
        return None;
    }

    let transaction_bytes = &signed_bytes[..transaction_size];
    let Some(sender) =
        AccountKey::from_public_key_bytes(&transaction_bytes[..TransactionPublicKey::SIZE])
    else {
        warn!(
            height,
            block_index, "indexer: sender public key bytes cannot derive an account key"
        );
        return None;
    };

    let to_start = TransactionPublicKey::SIZE;
    let to_end = to_start + AccountKey::SIZE;
    let value_start = to_end;
    let value_end = value_start + u64::SIZE;
    let nonce_start = value_end;
    let nonce_end = nonce_start + u64::SIZE;
    let value = read_u64(&transaction_bytes[value_start..value_end])
        .expect("transaction value slice has fixed width");
    if value == 0 {
        warn!(
            height,
            block_index, "indexer: skipping transaction with zero value"
        );
        return None;
    }

    let nonce = read_u64(&transaction_bytes[nonce_start..nonce_end])
        .expect("transaction nonce slice has fixed width");
    let mut to = [0u8; AccountKey::SIZE];
    to.copy_from_slice(&transaction_bytes[to_start..to_end]);

    Some(IndexedTransaction {
        block_index,
        digest: H::hash(&[transaction_bytes]),
        bytes: signed_bytes,
        sender,
        to,
        value,
        nonce,
    })
}

fn read_u64(bytes: &[u8]) -> Result<u64, TryFromSliceError> {
    Ok(u64::from_be_bytes(bytes.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_schema::{BLOCK_META_TABLE, TX_ACTIVITY_TABLE, TX_META_TABLE};
    use commonware_codec::{DecodeExt as _, EncodeSize as _, FixedSize, ReadExt as _, Write as _};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest, Signer,
        ed25519::{self, PublicKey},
        secp256r1::standard as secp256r1,
        sha256::{self, Sha256},
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{NZU16, non_empty_range, range::NonEmptyRange};
    use constantinople_primitives::{
        Block, Header, LazySignedTransaction, Sealable, Sealed, TRANSACTION_NAMESPACE, Transaction,
        TransactionPublicKey,
    };
    use core::num::NonZeroU64;
    use exoware_sql::CellValue;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn r1_sender_history_uses_account_key() {
        let mut rng = StdRng::from_seed([3; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender =
            TransactionPublicKey::secp256r1(secp256r1::PrivateKey::random(&mut rng).public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let sender_account = AccountKey::from_public_key(&sender);
        let transaction = Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), 1),
            vec![transaction],
        )
        .seal(&mut Sha256::default());

        let rows = encode_bulk_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
    }

    #[test]
    fn block_meta_row_counts_indexed_transactions() {
        let mut rng = StdRng::from_seed([5; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let transaction = Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let mut zero_value_bytes = Vec::with_capacity(transaction.encode_size());
        transaction.write(&mut zero_value_bytes);
        let value_start = TransactionPublicKey::SIZE + AccountKey::SIZE;
        zero_value_bytes[value_start..value_start + u64::SIZE].fill(0);
        let mut encoded =
            Vec::with_capacity(zero_value_bytes.len().encode_size() + zero_value_bytes.len());
        zero_value_bytes.len().write(&mut encoded);
        encoded.extend_from_slice(&zero_value_bytes);
        let zero_value = LazySignedTransaction::<Sha256>::read(&mut &encoded[..])
            .expect("zero-value lazy transaction should decode");
        let block = Sealed::new_unchecked(
            Block {
                header: test_header(consensus_key.public_key(), 1),
                body: vec![LazySignedTransaction::new(transaction), zero_value],
            },
            sha256::Digest::EMPTY,
        );

        let row = encode_block_meta_only_at(&block, 1_000);
        let bulk = encode_bulk_block_rows(&block);
        assert_eq!(row.table, BLOCK_META_TABLE);
        assert!(matches!(row.values.first(), Some(CellValue::UInt64(7))));
        assert!(matches!(row.values.get(2), Some(CellValue::UInt64(1))));
        assert_eq!(bulk.transaction_digests.len(), 1);
        assert!(matches!(
            row.values.get(6),
            Some(CellValue::Timestamp(1_000))
        ));
    }

    #[test]
    fn row_encoding_uses_lazy_transaction_bytes_without_materializing() {
        let mut rng = StdRng::from_seed([9; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let signed = Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default());

        let mut transaction = Vec::with_capacity(signed.encode_size());
        signed.write(&mut transaction);
        let invalid_sender = invalid_public_key_bytes();
        let sender_account = AccountKey::from_public_key_bytes(&invalid_sender)
            .expect("invalid ed25519 curve bytes still define an account key");
        transaction[..TransactionPublicKey::SIZE].copy_from_slice(&invalid_sender);
        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(&transaction);
        let lazy = LazySignedTransaction::<Sha256>::read(&mut &encoded[..])
            .expect("outer lazy transaction should decode");

        let block = Sealed::new_unchecked(
            Block {
                header: test_header(consensus_key.public_key(), 1),
                body: vec![lazy],
            },
            sha256::Digest::EMPTY,
        );

        let rows = encode_bulk_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
        assert_eq!(rows.transaction_digests.len(), 1);
        assert_tx_meta_body(&rows.sql, &transaction);
    }

    fn assert_activity_sender(rows: &[SqlRow], expected_account: &[u8]) {
        let sender = rows
            .iter()
            .find(|row| {
                row.table == TX_ACTIVITY_TABLE
                    && matches!(row.values.get(3), Some(CellValue::UInt64(0)))
            })
            .expect("sender activity row should be indexed");
        let Some(CellValue::FixedBinary(account)) = sender.values.first() else {
            panic!("sender activity account should be fixed binary");
        };
        assert_eq!(account.as_slice(), expected_account);
    }

    fn assert_tx_meta_body(rows: &[SqlRow], expected_body: &[u8]) {
        let meta = rows
            .iter()
            .find(|row| row.table == TX_META_TABLE)
            .expect("tx_meta row should be indexed");
        let Some(CellValue::Binary(body)) = meta.values.get(2) else {
            panic!("tx_meta body should be binary");
        };
        assert_eq!(body.as_slice(), expected_body);
    }

    fn test_header(
        leader: PublicKey,
        tx_count: usize,
    ) -> Header<Commitment, sha256::Digest, PublicKey> {
        let transactions_end = u64::try_from(tx_count).expect("tx count fits u64") + 1;
        Header {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), valid_commitment()),
            },
            parent: sha256::Digest::EMPTY,
            height: 7,
            timestamp: 1_000,
            state_root: sha256::Digest::EMPTY,
            state_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
            transactions_root: sha256::Digest::EMPTY,
            transactions_range: non_empty_range!(0u64, transactions_end) as NonEmptyRange<u64>,
        }
    }

    fn valid_commitment() -> Commitment {
        Commitment::from((
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            sha256::Digest::EMPTY,
            commonware_coding::Config {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(1),
            },
        ))
    }

    fn invalid_public_key_bytes() -> [u8; TransactionPublicKey::SIZE] {
        (0u8..=u8::MAX)
            .flat_map(|first| (0u8..=u8::MAX).map(move |last| (first, last)))
            .find_map(|(first, last)| {
                let mut candidate = [0; TransactionPublicKey::SIZE];
                candidate[0] = 0;
                candidate[1] = first;
                candidate[TransactionPublicKey::SIZE - 1] = last;

                TransactionPublicKey::decode(&mut &candidate[..])
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid public key bytes")
    }
}
