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
    AccountKey, LazySignedTransaction, Transaction, TransactionHistoryEntry, TransactionPublicKey,
};
use std::{array::TryFromSliceError, collections::BTreeMap};
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
/// digest and participant indices in order, so any disagreement means the upload
/// cannot be indexed.
pub(crate) fn encode_block_rows<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
    append_start: u64,
    appended: &[TransactionHistoryEntry<H::Digest>],
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

    let mut sql = Vec::with_capacity(1 + 3 * body_len);
    sql.push(block_meta_row(block, tx_count, finalized_ts_micros));

    let mut account_indices = BTreeMap::<[u8; AccountKey::SIZE], u64>::new();
    for (index, (lazy, appended)) in block.body.iter().zip(appended).enumerate() {
        let tx = index_transaction::<H>(height, index, lazy)?;

        // Each SQL location refers to the captured entry for this transaction.
        if tx.digest != appended.digest {
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
        if sender == receiver && appended.sender_index != appended.recipient_index {
            return Err(PublishError::InvalidTransaction {
                height,
                index,
                reason: "self-transfer history indices differ",
            });
        }
        // The first captured position anchors each account's history in this
        // block; later appearances advance across both transaction roles.
        for (account, account_index) in [
            (sender, appended.sender_index),
            (receiver, appended.recipient_index),
        ]
        .into_iter()
        .take(if sender == receiver { 1 } else { 2 })
        {
            if let Some(previous) = account_indices.insert(account, account_index) {
                if previous.checked_add(1) != Some(account_index) {
                    return Err(PublishError::InvalidTransaction {
                        height,
                        index,
                        reason: "account history indices are not consecutive",
                    });
                }
            }
        }
        sql.push(encode_tx_meta_row(TxMetaRow {
            digest,
            qmdb_location,
            body: tx.bytes,
            height,
            sender_index: appended.sender_index,
            recipient_index: appended.recipient_index,
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
            qmdb_location,
            account_index: appended.sender_index,
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
                qmdb_location,
                account_index: appended.recipient_index,
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
        secp256r1::standard as secp256r1,
        sha256::{self, Sha256},
    };
    use commonware_cryptography_curve25519::signing as ed25519;
    use commonware_math::algebra::Random;
    use commonware_utils::{NZU16, non_empty_range, range::NonEmptyRange};
    use constantinople_engine::types::{EngineBlock, EngineCommitment};
    use constantinople_primitives::{
        Block, Header, LazySignedTransaction, Sealable, Sealed, SignedTransaction, StateSyncProof,
        TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
    };
    use core::num::NonZeroU64;
    use exoware_sql::CellValue;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn r1_sender_history_uses_account_key() {
        let mut rng = StdRng::from_seed([3; 32]);
        let consensus_key = ed25519::SigningKey::random(&mut rng);
        let signer = ed25519::SigningKey::random(&mut rng);
        let sender =
            TransactionPublicKey::secp256r1(secp256r1::PrivateKey::random(&mut rng).public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::SigningKey::random(&mut rng).public_key());
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
            Block::<TestCommitment, ed25519::VerifyingKey, Sha256>::new(
                test_header(consensus_key.public_key(), non_empty_range!(0u64, 2u64)),
                vec![transaction],
                StateSyncProof::initial::<Sha256>(),
            )
            .seal(&mut Sha256::default()),
        );

        let rows = encode_block_rows(&block, 1_000, 0, &[entry(digest, 0, 0)])
            .expect("block should index");
        assert_activity_sender(&rows, sender_account.as_ref());
    }

    #[test]
    fn rows_locate_transactions_at_their_appends() {
        let first = transfer(1);
        let second = transfer(3);
        let digests = [*first.message_digest(), *second.message_digest()];
        let entries = digests.map(|digest| entry(digest, 0, 0));

        // Earlier blocks' retained operations sit between the range start and these appends.
        let block = unchecked_block(
            vec![
                LazySignedTransaction::new(first),
                LazySignedTransaction::new(second),
            ],
            non_empty_range!(2u64, 10u64),
        );
        let rows = encode_block_rows(&block, 1_000, 7, &entries).expect("block should index");

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
                let Some(CellValue::UInt64(height)) = row.values.get(3) else {
                    panic!("tx_meta height should be u64");
                };
                assert_eq!(*height, block.header.height);
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

        // Activity rows repeat their transaction's location for account-page proofs.
        let activity = rows
            .iter()
            .filter(|row| row.table == TX_ACTIVITY_TABLE)
            .collect::<Vec<_>>();
        assert!(activity.len() >= digests.len());
        for row in activity {
            let Some(CellValue::FixedBinary(digest)) = row.values.get(4) else {
                panic!("tx_activity digest should be fixed binary");
            };
            let Some(CellValue::UInt64(location)) = row.values.get(8) else {
                panic!("tx_activity location should be u64");
            };
            assert!(locations.contains(&(digest.clone(), *location)));
        }
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
            (&empty, vec![entry(digest, 0, 0)]),
            (&single, Vec::new()),
            (&single, vec![entry(digest, 0, 0), entry(digest, 0, 0)]),
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

        let Err(error) = encode_block_rows(
            &block,
            1_000,
            0,
            &[entry(first_digest, 0, 0), entry(first_digest, 0, 0)],
        ) else {
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
    fn history_indices_follow_accounts_across_roles_and_self_transfers() {
        let transactions = [
            transfer_to(1, 2, 0),
            transfer_to(2, 3, 0),
            transfer_to(2, 2, 1),
            transfer_to(1, 2, 1),
        ];
        let indices = [(40, 5), (6, 20), (7, 7), (41, 8)];
        let entries: Vec<_> = transactions
            .iter()
            .zip(indices)
            .map(|(tx, (sender, recipient))| entry(*tx.message_digest(), sender, recipient))
            .collect();
        let block = unchecked_block(
            transactions
                .into_iter()
                .map(LazySignedTransaction::new)
                .collect(),
            non_empty_range!(3u64, 13u64),
        );
        let rows =
            encode_block_rows(&block, 1_000, 8, &entries).expect("consecutive account histories");
        let meta: Vec<_> = rows
            .iter()
            .filter(|row| row.table == TX_META_TABLE)
            .collect();
        for (row, (sender_index, recipient_index)) in meta.iter().zip(indices) {
            assert!(
                matches!(row.values.get(4), Some(CellValue::UInt64(value)) if *value == sender_index)
            );
            assert!(
                matches!(row.values.get(5), Some(CellValue::UInt64(value)) if *value == recipient_index)
            );
        }
        let account = |seed| {
            AccountKey::from_public_key(&TransactionPublicKey::ed25519(
                ed25519::SigningKey::from_seed(seed).public_key(),
            ))
        };
        let activity: Vec<_> = rows
            .iter()
            .filter(|row| row.table == TX_ACTIVITY_TABLE)
            .collect();
        let expected = [
            (account(1), 0, 40, 8),
            (account(2), 1, 5, 8),
            (account(2), 0, 6, 9),
            (account(3), 1, 20, 9),
            (account(2), 0, 7, 10),
            (account(1), 0, 41, 11),
            (account(2), 1, 8, 11),
        ];
        assert_eq!(activity.len(), expected.len());
        for (row, (account, role, index, location)) in activity.iter().zip(expected) {
            assert!(
                matches!(row.values.first(), Some(CellValue::FixedBinary(value)) if value.as_slice() == account.as_ref())
            );
            assert!(matches!(row.values.get(3), Some(CellValue::UInt64(value)) if *value == role));
            assert!(
                matches!(row.values.get(8), Some(CellValue::UInt64(value)) if *value == location)
            );
            assert!(matches!(row.values.get(9), Some(CellValue::UInt64(value)) if *value == index));
        }

        for (position, sender, recipient, reason) in [
            (1, 5, 20, "account history indices are not consecutive"),
            (1, 8, 20, "account history indices are not consecutive"),
            (1, 4, 20, "account history indices are not consecutive"),
            (2, 7, 8, "self-transfer history indices differ"),
            (3, 41, 9, "account history indices are not consecutive"),
        ] {
            let mut altered = entries.clone();
            altered[position].sender_index = sender;
            altered[position].recipient_index = recipient;
            let Err(error) = encode_block_rows(&block, 1_000, 8, &altered) else {
                panic!("invalid history indices should be rejected");
            };
            assert!(
                matches!(error, PublishError::InvalidTransaction { index, reason: actual, .. } if index == position && actual == reason)
            );
        }
    }

    #[test]
    fn account_history_indices_do_not_wrap() {
        let first = transfer_to(1, 1, 0);
        let second = transfer_to(1, 1, 1);
        let entries = [
            entry(*first.message_digest(), u64::MAX, u64::MAX),
            entry(*second.message_digest(), 0, 0),
        ];
        let block = unchecked_block(
            vec![
                LazySignedTransaction::new(first),
                LazySignedTransaction::new(second),
            ],
            non_empty_range!(0u64, 3u64),
        );
        let Err(error) = encode_block_rows(&block, 1_000, 0, &entries) else {
            panic!("overflowing account history should be rejected");
        };
        assert!(matches!(
            error,
            PublishError::InvalidTransaction {
                index: 1,
                reason: "account history indices are not consecutive",
                ..
            }
        ));
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
            let Err(error) = encode_block_rows(
                &block,
                1_000,
                0,
                &[entry(digest, 0, 0), entry(digest, 0, 0)],
            ) else {
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
        let consensus_key = ed25519::SigningKey::random(&mut rng);
        let signer = ed25519::SigningKey::random(&mut rng);
        let sender = TransactionPublicKey::ed25519(signer.public_key());
        let recipient =
            TransactionPublicKey::ed25519(ed25519::SigningKey::random(&mut rng).public_key());
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
                state_sync: StateSyncProof::initial::<Sha256>(),
                body: vec![lazy].into(),
            },
            sha256::Digest::EMPTY,
        ));

        let rows = encode_block_rows(&block, 1_000, 0, &[entry(digest, 0, 0)])
            .expect("block should index");
        assert_activity_sender(&rows, sender_account.as_ref());
        assert_tx_meta_body(&rows, &transaction);
    }

    fn entry(
        digest: sha256::Digest,
        sender_index: u64,
        recipient_index: u64,
    ) -> TransactionHistoryEntry<sha256::Digest> {
        TransactionHistoryEntry {
            digest,
            sender_index,
            recipient_index,
        }
    }

    fn transfer(seed: u64) -> SignedTransaction<Sha256> {
        transfer_to(seed, seed + 1, 0)
    }

    fn transfer_to(seed: u64, recipient: u64, nonce: u64) -> SignedTransaction<Sha256> {
        let signer = ed25519::SigningKey::from_seed(seed);
        let recipient = ed25519::SigningKey::from_seed(recipient).public_key();
        Transaction::<sha256::Digest>::new(
            TransactionPublicKey::ed25519(signer.public_key()),
            TransactionPublicKey::ed25519(recipient),
            NonZeroU64::MIN,
            nonce,
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
    ) -> EngineBlock<Sha256, ed25519::VerifyingKey> {
        let leader = ed25519::SigningKey::from_seed(0).public_key();
        EngineBlock::from(Sealed::new_unchecked(
            Block {
                header: test_header(leader, transactions_range),
                state_sync: StateSyncProof::initial::<Sha256>(),
                body: body.into(),
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
        assert_eq!(meta.values.len(), 6);
        assert!(matches!(meta.values.get(1), Some(CellValue::UInt64(0))));
        let Some(CellValue::Binary(body)) = meta.values.get(2) else {
            panic!("tx_meta body should be binary");
        };
        assert_eq!(body.as_slice(), expected_body);

        // Proof heights live on tx_meta rows, not in a separate table.
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
        leader: ed25519::VerifyingKey,
        transactions_range: NonEmptyRange<u64>,
    ) -> Header<TestCommitment, sha256::Digest, ed25519::VerifyingKey> {
        Header {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), valid_commitment()),
            },
            parent: sha256::Digest::EMPTY,
            height: 7,
            timestamp: 1_000,
            state_root: StateSyncProof::initial::<Sha256>().root::<Sha256>(),
            state_range: non_empty_range!(0u64, 1u64) as NonEmptyRange<u64>,
            transactions_root: sha256::Digest::EMPTY,
            transactions_range,
        }
    }

    type TestCommitment = EngineCommitment<Sha256, ed25519::VerifyingKey>;

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
