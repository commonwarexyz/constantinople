//! Deterministic SQL rows for finalized blocks and their transactions.

use crate::publisher::{
    SqlRow,
    qmdb::PublishError,
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
use tracing::info_span;

struct IndexedTransaction<D: Digest> {
    digest: D,
    bytes: Bytes,
    sender: AccountKey,
    to: [u8; AccountKey::SIZE],
    value: u64,
    nonce: u64,
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

/// Encode SQL rows for a finalized block whose transaction history appends
/// `appended` starting at `append_start`.
///
/// Consensus only finalizes well-formed transactions and appends each body
/// digest in order, so any disagreement means the upload cannot be indexed.
pub(crate) fn encode_block_rows<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
    append_start: u64,
    appended: &[H::Digest],
) -> Result<Vec<SqlRow>, PublishError>
where
    H: Hasher,
    P: PublicKey,
{
    let height = block.header.height;
    let body_len = block.body.len();
    let _entered = info_span!(
        "indexer.qmdb.prepare.block_transactions",
        height,
        transactions = body_len
    )
    .entered();
    if appended.len() != body_len {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "transaction appends do not match the block body",
        });
    }
    let tx_count = u64::try_from(body_len).expect("transaction count fits u64");

    // Readers derive a transaction's height from block_meta, so no
    // per-transaction proof row is needed.
    let mut sql = Vec::with_capacity(1 + 3 * body_len);
    sql.push(block_meta_row(block, tx_count, finalized_ts_micros));

    for (index, (lazy, appended)) in block.body.iter().zip(appended).enumerate() {
        let tx = index_transaction::<H>(height, index, lazy)?;

        // Proofs for a tx_meta location must return this transaction's digest.
        if tx.digest != *appended {
            return Err(PublishError::InvalidTransaction {
                height,
                index,
                reason: "digest does not match its transaction history append",
            });
        }
        let idx_u32 = u32::try_from(index).expect("transaction index fits u32");
        let qmdb_location = append_start + u64::try_from(index).expect("index fits u64");
        let digest: [u8; 32] = tx
            .digest
            .as_ref()
            .try_into()
            .expect("transaction digest has fixed width");
        let sender: [u8; AccountKey::SIZE] = tx
            .sender
            .as_ref()
            .try_into()
            .expect("account key has fixed width");
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

    Ok(sql)
}

fn index_transaction<H>(
    height: u64,
    index: usize,
    transaction: &LazySignedTransaction<H>,
) -> Result<IndexedTransaction<H::Digest>, PublishError>
where
    H: Hasher,
{
    let invalid = |reason| PublishError::InvalidTransaction {
        height,
        index,
        reason,
    };
    let signed_bytes = transaction.encoded_signed_transaction();
    let transaction_size = Transaction::<H::Digest>::SIZE;
    if signed_bytes.len() < transaction_size {
        return Err(invalid("signed payload is shorter than a transaction"));
    }

    let transaction_bytes = &signed_bytes[..transaction_size];
    let sender =
        AccountKey::from_public_key_bytes(&transaction_bytes[..TransactionPublicKey::SIZE])
            .ok_or_else(|| invalid("sender public key bytes cannot derive an account key"))?;

    let to_start = TransactionPublicKey::SIZE;
    let to_end = to_start + AccountKey::SIZE;
    let value_start = to_end;
    let value_end = value_start + u64::SIZE;
    let nonce_start = value_end;
    let nonce_end = nonce_start + u64::SIZE;
    let value = read_u64(&transaction_bytes[value_start..value_end])
        .expect("transaction value slice has fixed width");
    if value == 0 {
        return Err(invalid("value is zero"));
    }

    let nonce = read_u64(&transaction_bytes[nonce_start..nonce_end])
        .expect("transaction nonce slice has fixed width");
    let mut to = [0u8; AccountKey::SIZE];
    to.copy_from_slice(&transaction_bytes[to_start..to_end]);

    Ok(IndexedTransaction {
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
    use commonware_codec::{Copying, DecodeExt as _, EncodeSize as _, FixedSize, Write as _};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        Digest, Signer,
        ed25519::{self, PublicKey},
        secp256r1::standard as secp256r1,
        sha256::{self, Sha256},
    };
    use commonware_math::algebra::Random;
    use commonware_utils::{NZU16, non_empty_range, range::NonEmptyRange};
    use constantinople_engine::types::{EngineBlock, EngineCommitment};
    use constantinople_primitives::{
        Block, Header, LazySignedTransaction, Sealable, Sealed, SignedTransaction,
        TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
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
        let digest = *transaction.message_digest();
        let block = EngineBlock::from(
            Block::<TestCommitment, PublicKey, Sha256>::new(
                test_header(consensus_key.public_key(), non_empty_range!(0u64, 2u64)),
                vec![transaction],
            )
            .seal(&mut Sha256::default()),
        );

        let rows = encode_block_rows(&block, 1_000, 0, &[digest]).expect("block should index");
        assert_activity_sender(&rows, sender_account.as_ref());
    }

    #[test]
    fn rows_locate_transactions_at_their_appends() {
        let first = transfer(1);
        let second = transfer(3);
        let digests = [*first.message_digest(), *second.message_digest()];

        // Earlier blocks' retained operations sit between the range start and these appends.
        let block = unchecked_block(
            vec![
                LazySignedTransaction::new(first),
                LazySignedTransaction::new(second),
            ],
            non_empty_range!(2u64, 10u64),
        );
        let rows = encode_block_rows(&block, 1_000, 7, &digests).expect("block should index");

        let meta = &rows[0];
        assert_eq!(meta.table, BLOCK_META_TABLE);
        assert!(matches!(meta.values.get(2), Some(CellValue::UInt64(2))));
        assert!(matches!(meta.values.get(4), Some(CellValue::UInt64(9))));
        let locations = rows
            .iter()
            .filter(|row| row.table == TX_META_TABLE)
            .map(|row| {
                let Some(CellValue::FixedBinary(digest)) = row.values.first() else {
                    panic!("tx_meta digest should be fixed binary");
                };
                let Some(CellValue::UInt64(location)) = row.values.get(1) else {
                    panic!("tx_meta location should be u64");
                };
                (digest.clone(), *location)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            locations,
            vec![
                (digests[0].as_ref().to_vec(), 7),
                (digests[1].as_ref().to_vec(), 8)
            ]
        );
    }

    #[test]
    fn appends_must_cover_the_body_exactly() {
        let transaction = transfer(1);
        let digest = *transaction.message_digest();

        // An empty block appends nothing before its commit.
        let empty = unchecked_block(Vec::new(), non_empty_range!(0u64, 4u64));
        let rows = encode_block_rows(&empty, 1_000, 3, &[]).expect("empty block should index");
        assert_eq!(rows.len(), 1);
        assert!(matches!(rows[0].values.get(2), Some(CellValue::UInt64(0))));

        let single = unchecked_block(
            vec![LazySignedTransaction::new(transaction)],
            non_empty_range!(0u64, 4u64),
        );
        for (block, appended) in [
            (&empty, vec![digest]),
            (&single, Vec::new()),
            (&single, vec![digest, digest]),
        ] {
            let Err(error) = encode_block_rows(block, 1_000, 1, &appended) else {
                panic!("invalid block should not index");
            };
            assert!(
                matches!(
                    error,
                    PublishError::InvalidQueuedUpload {
                        reason: "transaction appends do not match the block body"
                    }
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn append_digest_must_match_its_transaction() {
        let first = transfer(1);
        let second = transfer(3);
        let first_digest = *first.message_digest();
        let block = unchecked_block(
            vec![
                LazySignedTransaction::new(first),
                LazySignedTransaction::new(second),
            ],
            non_empty_range!(0u64, 3u64),
        );

        let Err(error) = encode_block_rows(&block, 1_000, 0, &[first_digest, first_digest]) else {
            panic!("invalid block should not index");
        };
        assert!(
            matches!(
                error,
                PublishError::InvalidTransaction {
                    height: 7,
                    index: 1,
                    reason: "digest does not match its transaction history append",
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn malformed_transactions_are_errors() {
        let valid = transfer(1);
        let digest = *valid.message_digest();
        let mut encoded = Vec::with_capacity(valid.encode_size());
        valid.write(&mut encoded);

        let value_start = TransactionPublicKey::SIZE + AccountKey::SIZE;
        let mut zero_value = encoded.clone();
        zero_value[value_start..value_start + u64::SIZE].fill(0);
        let mut unknown_scheme = encoded;
        unknown_scheme[0] = u8::MAX;

        for (malformed, reason) in [
            (zero_value, "value is zero"),
            (
                unknown_scheme,
                "sender public key bytes cannot derive an account key",
            ),
        ] {
            let block = unchecked_block(
                vec![
                    LazySignedTransaction::new(valid.clone()),
                    lazy_from_bytes(&malformed),
                ],
                non_empty_range!(0u64, 3u64),
            );
            let Err(error) = encode_block_rows(&block, 1_000, 0, &[digest, digest]) else {
                panic!("invalid block should not index");
            };
            assert!(
                matches!(
                    error,
                    PublishError::InvalidTransaction {
                        height: 7,
                        index: 1,
                        reason: actual,
                    } if actual == reason
                ),
                "{error}"
            );
        }
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
        let lazy = lazy_from_bytes(&transaction);

        // The append digest covers the unsigned transaction bytes.
        let digest = Sha256::hash(&[&transaction[..Transaction::<sha256::Digest>::SIZE]]);
        let block = EngineBlock::from(Sealed::new_unchecked(
            Block {
                header: test_header(consensus_key.public_key(), non_empty_range!(0u64, 2u64)),
                body: vec![lazy],
            },
            sha256::Digest::EMPTY,
        ));

        let rows = encode_block_rows(&block, 1_000, 0, &[digest]).expect("block should index");
        assert_activity_sender(&rows, sender_account.as_ref());
        assert_tx_meta_body(&rows, &transaction);
    }

    fn transfer(seed: u64) -> SignedTransaction<Sha256> {
        let signer = ed25519::PrivateKey::from_seed(seed);
        let recipient = ed25519::PrivateKey::from_seed(seed + 1).public_key();
        Transaction::<sha256::Digest>::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::MIN,
            0,
        )
        .seal_and_sign(&signer, TRANSACTION_NAMESPACE, &mut Sha256::default())
    }

    // Decoding defers validation, so arbitrary bytes can stand in for a body entry.
    fn lazy_from_bytes(transaction: &[u8]) -> LazySignedTransaction<Sha256> {
        let mut encoded = Vec::with_capacity(transaction.len().encode_size() + transaction.len());
        transaction.len().write(&mut encoded);
        encoded.extend_from_slice(transaction);
        LazySignedTransaction::<Sha256>::decode(encoded)
            .expect("outer lazy transaction should decode")
    }

    fn unchecked_block(
        body: Vec<LazySignedTransaction<Sha256>>,
        transactions_range: NonEmptyRange<u64>,
    ) -> EngineBlock<Sha256, PublicKey> {
        let leader = ed25519::PrivateKey::from_seed(0).public_key();
        EngineBlock::from(Sealed::new_unchecked(
            Block {
                header: test_header(leader, transactions_range),
                body,
            },
            sha256::Digest::EMPTY,
        ))
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
        assert_eq!(meta.values.len(), 3);
        assert!(matches!(meta.values.get(1), Some(CellValue::UInt64(0))));
        let Some(CellValue::Binary(body)) = meta.values.get(2) else {
            panic!("tx_meta body should be binary");
        };
        assert_eq!(body.as_slice(), expected_body);

        // Readers derive proof heights from block metadata.
        assert!(
            rows.iter().all(|row| {
                row.table == crate::sql_schema::TX_META_TABLE
                    || row.table == crate::sql_schema::TX_ACTIVITY_TABLE
                    || row.table == crate::sql_schema::BLOCK_META_TABLE
            }),
            "block rows contain no per-transaction proof rows"
        );
    }

    fn test_header(
        leader: PublicKey,
        transactions_range: NonEmptyRange<u64>,
    ) -> Header<TestCommitment, sha256::Digest, PublicKey> {
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
            transactions_range,
        }
    }

    type TestCommitment = EngineCommitment<Sha256, PublicKey>;

    fn valid_commitment() -> TestCommitment {
        TestCommitment::from((
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

                TransactionPublicKey::decode(Copying(&candidate[..]))
                    .is_err()
                    .then_some(candidate)
            })
            .expect("test should find invalid public key bytes")
    }
}
