//! Block row encoding shared by the combined publisher.

use crate::publisher::{
    SqlRow,
    sql::{
        BlockMetaRow, TxActivityRole, TxActivityRow, TxKind, TxMetaRow, encode_block_meta_row,
        encode_tx_activity_row, encode_tx_meta_row,
    },
};
use commonware_codec::FixedSize;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{
    AccountKey, LazySignedTransaction, Operation, TransactionPublicKey,
};
use tracing::warn;

/// Encoded block rows split by index surface.
pub(crate) struct IndexedBlockRows<D: Digest> {
    /// SQL rows for block metadata, transaction metadata, and account activity.
    pub sql: Vec<SqlRow>,
    /// Transaction digests in append order.
    pub transaction_digests: Vec<D>,
}

struct IndexedTransaction<D: Digest> {
    block_index: usize,
    digest: D,
    bytes: Vec<u8>,
    nonce: u64,
    kind: TxKind,
    activities: Vec<Activity>,
}

/// One account's involvement in a transaction, as an activity row.
struct Activity {
    account: AccountKey,
    role: TxActivityRole,
    counterparty: AccountKey,
    value: u64,
}

/// Build every row for a finalized block, partitioned by destination store.
#[cfg(test)]
pub(crate) fn encode_indexed_block_rows<H, P>(
    block: &EngineBlock<H, P>,
) -> IndexedBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let finalized_ts_micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    encode_indexed_block_rows_at(block, finalized_ts_micros)
}

pub(crate) fn encode_indexed_block_rows_at<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
) -> IndexedBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let block_digest = block.seal();
    let height = block.header.height;
    let body_len = block.body.len();
    // SQL `block_meta.digest` is `FixedSizeBinary(32)` — copy it into a
    // `[u8; 32]` for the typed CellValue path.
    let mut block_digest_arr = [0u8; 32];
    block_digest_arr.copy_from_slice(block_digest.as_ref());
    let mut transactions_root = [0u8; 32];
    transactions_root.copy_from_slice(block.header.transactions_root.as_ref());
    let indexed_txs = block
        .body
        .iter()
        .enumerate()
        .filter_map(|(idx, lazy)| index_transaction::<H>(height, idx, lazy))
        .collect::<Vec<_>>();
    let tx_count = u64::try_from(indexed_txs.len()).expect("transaction count fits u64");
    let append_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(tx_count + 1)
        .expect("transaction range includes appends plus commit");

    let mut sql = Vec::with_capacity(1 + 3 * body_len);

    // One tx_meta row plus sender/receiver tx_activity rows per transaction.
    let mut transaction_digests = Vec::with_capacity(indexed_txs.len());
    for (materialized_idx, tx) in indexed_txs.into_iter().enumerate() {
        transaction_digests.push(tx.digest);
        let idx_u32 = u32::try_from(tx.block_index).expect("transaction index fits u32");
        let qmdb_location = append_start + u64::try_from(materialized_idx).expect("index fits u64");
        let mut digest = [0u8; 32];
        digest.copy_from_slice(tx.digest.as_ref());
        sql.push(encode_tx_meta_row(TxMetaRow {
            digest,
            qmdb_location,
            body: tx.bytes,
        }));
        for activity in &tx.activities {
            let mut account = [0u8; AccountKey::SIZE];
            account.copy_from_slice(activity.account.as_ref());
            let mut counterparty = [0u8; AccountKey::SIZE];
            counterparty.copy_from_slice(activity.counterparty.as_ref());
            sql.push(encode_tx_activity_row(TxActivityRow {
                account,
                role: activity.role,
                height,
                index: idx_u32,
                digest,
                counterparty,
                value: activity.value,
                nonce: tx.nonce,
                kind: tx.kind,
            }));
        }
    }

    // SQL: one block_meta row per finalized block.
    // `view` is currently 0; see `encode_block_meta_row` docs for why.
    sql.insert(
        0,
        encode_block_meta_row(BlockMetaRow {
            height,
            digest: block_digest_arr,
            tx_count,
            transactions_root,
            transactions_tip: block.header.transactions_range.end() - 1,
            view: 0,
            finalized_ts_micros,
        }),
    );

    IndexedBlockRows {
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
    // Derive the sender account from the raw key bytes (the transaction's first
    // field) without validating the curve point or materializing the sender, so
    // an account whose key is not a valid curve point is still indexed.
    if signed_bytes.len() < TransactionPublicKey::SIZE {
        warn!(
            height,
            block_index, "indexer: skipping transaction with truncated payload"
        );
        return None;
    }
    let Some(sender) =
        AccountKey::from_public_key_bytes(&signed_bytes[..TransactionPublicKey::SIZE])
    else {
        warn!(
            height,
            block_index, "indexer: sender public key bytes cannot derive an account key"
        );
        return None;
    };

    // Decoding leaves the sender lazy (unvalidated); only the nonce and
    // operation are needed below, neither of which depends on the sender key.
    let Some(signed) = transaction.get() else {
        warn!(
            height,
            block_index, "indexer: skipping transaction that fails to decode"
        );
        return None;
    };
    let tx = signed.value();

    // Build the activity rows for this operation. A transfer credits the
    // recipient; a channel open is a *reservation* by the sender (no funds are
    // credited to anyone, so only the sender gets a row); a channel close is a
    // settlement that pays `cumulative` from the payer to the receiver (the
    // transaction's sender). The `kind` column tells the explorer which is
    // which, so a reservation is not misread as a payment.
    let (kind, activities) = match tx.op() {
        Operation::Transfer { to, value } => {
            let value = value.get();
            let mut activities = vec![Activity {
                account: sender,
                role: TxActivityRole::Sender,
                counterparty: *to,
                value,
            }];
            if *to != sender {
                activities.push(Activity {
                    account: *to,
                    role: TxActivityRole::Receiver,
                    counterparty: sender,
                    value,
                });
            }
            (TxKind::Transfer, activities)
        }
        Operation::OpenChannel { receiver, deposit } => (
            TxKind::ChannelOpen,
            vec![Activity {
                account: sender,
                role: TxActivityRole::Sender,
                counterparty: *receiver,
                value: deposit.get(),
            }],
        ),
        Operation::CloseChannel {
            payer, cumulative, ..
        } => {
            let payer = AccountKey::from_public_key(payer);
            // The transaction sender is the receiver being paid.
            let mut activities = vec![Activity {
                account: sender,
                role: TxActivityRole::Receiver,
                counterparty: payer,
                value: *cumulative,
            }];
            if payer != sender {
                activities.push(Activity {
                    account: payer,
                    role: TxActivityRole::Sender,
                    counterparty: sender,
                    value: *cumulative,
                });
            }
            (TxKind::ChannelClose, activities)
        }
    };

    Some(IndexedTransaction {
        block_index,
        digest: *signed.message_digest(),
        bytes: signed_bytes.to_vec(),
        nonce: tx.nonce,
        kind,
        activities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_schema::{TX_ACTIVITY_TABLE, TX_META_TABLE};
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

        let rows = encode_indexed_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
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

        let rows = encode_indexed_block_rows(&block);
        assert_activity_sender(&rows.sql, sender_account.as_ref());
        assert_eq!(rows.transaction_digests.len(), 1);
        assert_tx_meta_body(&rows.sql, &transaction);
    }

    fn activity_rows(rows: &[SqlRow]) -> Vec<&SqlRow> {
        rows.iter()
            .filter(|row| row.table == TX_ACTIVITY_TABLE)
            .collect()
    }

    #[test]
    fn open_channel_indexes_a_single_reservation_row() {
        let mut rng = StdRng::from_seed([5; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let payer = ed25519::PrivateKey::random(&mut rng);
        let receiver = ed25519::PrivateKey::random(&mut rng);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_account = AccountKey::from_public_key(&payer_pk);
        let receiver_account = AccountKey::from_public_key(&receiver_pk);

        let tx = Transaction::<sha256::Digest>::open_channel(
            payer_pk,
            receiver_pk,
            NonZeroU64::new(50).expect("deposit is non-zero"),
            0,
        )
        .seal_and_sign(&payer, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), 1),
            vec![tx],
        )
        .seal(&mut Sha256::default());

        let rows = encode_indexed_block_rows(&block);
        let activity = activity_rows(&rows.sql);
        // An open is a reservation: only the payer gets a row, so the payee is
        // never shown as having received the deposit.
        assert_eq!(activity.len(), 1, "open indexes a single reservation row");
        let row = activity[0];
        let CellValue::FixedBinary(account) = &row.values[0] else {
            panic!("account is fixed binary");
        };
        assert_eq!(account.as_slice(), payer_account.as_ref());
        assert!(
            matches!(row.values[3], CellValue::UInt64(0)),
            "role = sender"
        );
        let CellValue::FixedBinary(counterparty) = &row.values[5] else {
            panic!("counterparty is fixed binary");
        };
        assert_eq!(counterparty.as_slice(), receiver_account.as_ref());
        assert!(
            matches!(row.values[6], CellValue::UInt64(50)),
            "value = deposit"
        );
        assert!(matches!(row.values[8], CellValue::UInt64(1)), "kind = open");
    }

    #[test]
    fn close_channel_indexes_payer_to_receiver_settlement() {
        let mut rng = StdRng::from_seed([6; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let payer = ed25519::PrivateKey::random(&mut rng);
        let receiver = ed25519::PrivateKey::random(&mut rng);
        let payer_pk = TransactionPublicKey::ed25519(payer.public_key());
        let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
        let payer_account = AccountKey::from_public_key(&payer_pk);
        let receiver_account = AccountKey::from_public_key(&receiver_pk);

        // The indexer does not verify the voucher, so any signature works here.
        let voucher = payer.sign(b"voucher", b"message");
        let tx =
            Transaction::<sha256::Digest>::close_channel(receiver_pk, payer_pk, 0, 20, voucher, 0)
                .seal_and_sign(&receiver, TRANSACTION_NAMESPACE, &mut Sha256::default());
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), 1),
            vec![tx],
        )
        .seal(&mut Sha256::default());

        let rows = encode_indexed_block_rows(&block);
        let activity = activity_rows(&rows.sql);
        assert_eq!(activity.len(), 2, "close indexes both settlement sides");

        // Receiver is credited the claimed amount.
        let received = activity
            .iter()
            .find(|row| matches!(row.values[3], CellValue::UInt64(1)))
            .expect("receiver row");
        let CellValue::FixedBinary(account) = &received.values[0] else {
            panic!("account is fixed binary");
        };
        assert_eq!(account.as_slice(), receiver_account.as_ref());
        let CellValue::FixedBinary(counterparty) = &received.values[5] else {
            panic!("counterparty is fixed binary");
        };
        assert_eq!(counterparty.as_slice(), payer_account.as_ref());
        assert!(
            matches!(received.values[6], CellValue::UInt64(20)),
            "value = cumulative"
        );
        assert!(
            matches!(received.values[8], CellValue::UInt64(2)),
            "kind = close"
        );

        // Payer is debited the claimed amount.
        let paid = activity
            .iter()
            .find(|row| matches!(row.values[3], CellValue::UInt64(0)))
            .expect("payer row");
        let CellValue::FixedBinary(account) = &paid.values[0] else {
            panic!("account is fixed binary");
        };
        assert_eq!(account.as_slice(), payer_account.as_ref());
        assert!(
            matches!(paid.values[8], CellValue::UInt64(2)),
            "kind = close"
        );
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
        let Some(CellValue::Utf8(body_hex)) = meta.values.get(2) else {
            panic!("tx_meta body should be hex");
        };
        assert_eq!(body_hex, &hex_lower(expected_body));
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
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
