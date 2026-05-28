//! Block reporter that fans a finalized block out to raw KV and SQL metadata.
//!
//! Wired into the engine via the existing `marshal` reporter slot. On every
//! `Update::Block(block, ack)` we:
//!
//! 1. Encode two batches:
//!    - **raw KV**: BLOCK, BLOCK_BY_H, TX, and TX_BY_H rows.
//!    - **sql metadata** (`block_meta`): one row per block. The
//!      latest-finalized-height cursor is
//!      derived from `MAX(height)` on `block_meta`; the KV path no longer
//!      maintains a redundant META scalar.
//! 2. Clone the marshal acknowledgement once per backing path. Each path
//!    fulfills its clone after its own upload succeeds; the marshal waiter only
//!    resolves after every path has durably accepted its batch.
//! 3. Forward each batch to its uploader and return immediately so consensus
//!    is not blocked on the network store — marshal itself back-pressures
//!    the engine through the still-held ack.

use crate::{
    keys,
    publisher::{
        SqlBatch, SqlRow, UploadBatch, dispatch_batch,
        sql::{BlockMetaRow, dispatch_sql_batch, encode_sql_rows},
    },
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::Encode;
use commonware_consensus::{Reporter, marshal::Update};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{AccountKey, TransactionPublicKey};
use exoware_sdk::keys::Key;
use std::{
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tracing::warn;

const TX_BY_SENDER_ROW_BYTES: usize = 32 + 32 + 8 + 8 + 8 + 8 + 4;

/// Cloneable [`Reporter`] over `Update<EngineBlock<H, P>>`.
///
/// Holds one sender per active backing path. Cloning the reporter is cheap;
/// the senders are reference-counted MPSC channels.
pub struct BlockReporter<H, P> {
    raw: Option<mpsc::Sender<UploadBatch>>,
    sql: mpsc::Sender<SqlBatch>,
    _marker: PhantomData<fn() -> (H, P)>,
}

impl<H, P> BlockReporter<H, P> {
    /// Build a reporter that forwards raw KV and SQL metadata batches.
    ///
    /// The raw KV channel carries pre-encoded BLOCK, BLOCK_BY_H, TX, and
    /// TX_BY_H rows to the existing exoware Store. The SQL channel feeds the
    /// metadata uploader, which writes typed rows into the `block_meta` table
    /// declared by [`crate::sql_schema`].
    pub const fn new(raw: mpsc::Sender<UploadBatch>, sql: mpsc::Sender<SqlBatch>) -> Self {
        Self {
            raw: Some(raw),
            sql,
            _marker: PhantomData,
        }
    }

    /// Build a reporter that uploads only SQL metadata rows.
    pub const fn metadata_only(sql: mpsc::Sender<SqlBatch>) -> Self {
        Self {
            raw: None,
            sql,
            _marker: PhantomData,
        }
    }
}

impl<H, P> Clone for BlockReporter<H, P> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            sql: self.sql.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, P> Reporter for BlockReporter<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    type Activity = Update<EngineBlock<H, P>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            // Tip-only updates carry no block payload; nothing to upload.
            Update::Tip(_, _, _) => {}
            Update::Block(block, ack) => {
                // Encoding is cheap and synchronous. The actual store writes
                // are dispatched onto background tasks so this method never
                // blocks consensus — see `dispatch_batch` for back-pressure
                // semantics.
                let IndexedBlockRows { raw, sql, .. } = encode_indexed_block_rows(&block);

                // Clone the ack once per backing path. `Exact::clone`
                // increments the remaining count, so the marshal waiter only
                // resolves after each path has acknowledged.
                if let Some(raw_tx) = &self.raw {
                    dispatch_batch(
                        raw_tx,
                        UploadBatch {
                            rows: raw,
                            ack: Some(ack.clone()),
                        },
                    );
                }
                dispatch_sql_batch(
                    &self.sql,
                    SqlBatch {
                        rows: sql,
                        ack: Some(ack),
                    },
                );
            }
        }
        Feedback::Ok
    }
}

/// Encoded block rows split by index family.
pub(crate) struct IndexedBlockRows<D: Digest> {
    /// Raw KV rows for the block and contained transactions.
    pub raw: Vec<(Key, Bytes)>,
    /// SQL metadata row for the block.
    pub sql: Vec<SqlRow>,
    /// Transaction digests in append order.
    pub transaction_digests: Vec<D>,
}

/// Build every row for a finalized block, partitioned by destination store.
pub(crate) fn encode_indexed_block_rows<H, P>(
    block: &EngineBlock<H, P>,
) -> IndexedBlockRows<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let block_digest = block.seal();
    let height = block.header.height;
    let body_len = block.body.len();
    // Wall-clock at the moment marshal delivered this block; microseconds
    // since the Unix epoch (matches `Timestamp(TimeUnit::Microsecond, None)`
    // declared by `sql_schema::build_meta_schema`). A clock-skewed validator
    // simply records its own view of the time — the SQL store does not rely
    // on it for ordering (height is the primary key).
    let finalized_ts_micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0);
    // SQL `block_meta.digest` is `FixedSizeBinary(32)` — copy it into a
    // `[u8; 32]` for the typed CellValue path.
    let mut block_digest_arr = [0u8; 32];
    block_digest_arr.copy_from_slice(block_digest.as_ref());
    let mut transactions_root = [0u8; 32];
    transactions_root.copy_from_slice(block.header.transactions_root.as_ref());
    let materialized_txs = block
        .body
        .iter()
        .enumerate()
        .filter_map(|(idx, lazy)| {
            let Some(tx) = lazy.get() else {
                warn!(
                    height,
                    idx, "indexer: skipping transaction that failed to materialize"
                );
                return None;
            };
            let tx_digest = *tx.message_digest();
            Some((idx, lazy, tx, tx_digest))
        })
        .collect::<Vec<_>>();
    let tx_count = u64::try_from(materialized_txs.len()).expect("transaction count fits u64");
    let (secp256r1_tx_count, ed25519_tx_count) = transaction_scheme_counts(
        materialized_txs
            .iter()
            .filter_map(|(_, _, tx, _)| tx.value().sender()),
    );
    let append_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(tx_count + 1)
        .expect("transaction range includes appends plus commit");

    let mut raw = Vec::with_capacity(2 + 3 * body_len);
    raw.push((
        keys::block(block_digest.as_ref()).expect("block digest fits family payload"),
        block.encode(),
    ));
    raw.push((
        keys::block_by_height(height).expect("u64 height fits family payload"),
        Bytes::copy_from_slice(block_digest.as_ref()),
    ));

    // Per-transaction rows: TX, TX_BY_H, and TX_BY_SENDER for account lookup.
    let mut transaction_digests = Vec::with_capacity(materialized_txs.len());
    for (materialized_idx, (idx, lazy, tx, tx_digest)) in materialized_txs.iter().enumerate() {
        transaction_digests.push(*tx_digest);
        let tx_bytes = lazy.encode();
        let idx_u32 = u32::try_from(*idx).expect("transaction index fits u32");
        let qmdb_location = append_start + u64::try_from(materialized_idx).expect("index fits u64");

        raw.push((
            keys::tx(tx_digest.as_ref()).expect("tx digest fits family payload"),
            tx_bytes,
        ));
        raw.push((
            keys::tx_by_height(height, idx_u32).expect("(height, idx) fits family payload"),
            Bytes::copy_from_slice(tx_digest.as_ref()),
        ));
        if let Some(sender) = tx.value().sender() {
            let sender_account = AccountKey::from_public_key(sender);
            raw.push((
                keys::tx_by_sender(sender_account.as_ref(), height, idx_u32)
                    .expect("sender tx index fits family payload"),
                encode_tx_by_sender_row(
                    tx_digest.as_ref(),
                    tx.value().to.as_ref(),
                    tx.value().value.get(),
                    tx.value().nonce,
                    qmdb_location,
                    height,
                    idx_u32,
                ),
            ));
        }
    }

    // SQL: one block_meta row per finalized block. Per-transaction proof
    // lookups use raw `TX_BY_H` rows on demand for the wallet's own
    // transactions instead of maintaining a global SQL `tx_meta` index.
    // The `latest_finalized_height` cursor that the previous KV META family
    // carried is now derived from `MAX(block_meta.height)` instead.
    // `view` is currently 0; see `encode_sql_rows` docs for why.
    let sql = encode_sql_rows(BlockMetaRow {
        height,
        digest: block_digest_arr,
        tx_count,
        secp256r1_tx_count,
        ed25519_tx_count,
        transactions_root,
        transactions_tip: block.header.transactions_range.end() - 1,
        view: 0,
        finalized_ts_micros,
    });

    IndexedBlockRows {
        raw,
        sql,
        transaction_digests,
    }
}

fn transaction_scheme_counts<'a>(
    senders: impl Iterator<Item = &'a TransactionPublicKey>,
) -> (u64, u64) {
    let mut secp256r1 = 0u64;
    let mut ed25519 = 0u64;

    for sender in senders {
        match sender {
            TransactionPublicKey::Secp256r1 { .. } => secp256r1 += 1,
            TransactionPublicKey::Ed25519 { .. } => ed25519 += 1,
        }
    }

    (secp256r1, ed25519)
}

fn encode_tx_by_sender_row(
    digest: &[u8],
    to: &[u8],
    value: u64,
    nonce: u64,
    qmdb_location: u64,
    height: u64,
    block_index: u32,
) -> Bytes {
    let mut row = Vec::with_capacity(TX_BY_SENDER_ROW_BYTES);
    row.extend_from_slice(digest);
    row.extend_from_slice(to);
    row.extend_from_slice(&value.to_be_bytes());
    row.extend_from_slice(&nonce.to_be_bytes());
    row.extend_from_slice(&qmdb_location.to_be_bytes());
    row.extend_from_slice(&height.to_be_bytes());
    row.extend_from_slice(&block_index.to_be_bytes());
    Bytes::from(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize;
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
        Block, Header, Sealable, TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
    };
    use core::num::NonZeroU64;
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
        let tx_by_sender = rows
            .raw
            .iter()
            .find(|(key, _)| keys::TX_BY_SENDER.matches(key))
            .expect("sender history row should be indexed");
        let payload = keys::TX_BY_SENDER
            .decode(&tx_by_sender.0, AccountKey::SIZE + 12)
            .expect("sender history key should decode");

        assert_eq!(&payload[..AccountKey::SIZE], sender_account.as_ref());
    }

    #[test]
    fn block_meta_counts_transaction_sender_schemes() {
        let mut rng = StdRng::from_seed([4; 32]);
        let consensus_key = ed25519::PrivateKey::random(&mut rng);
        let signer = ed25519::PrivateKey::random(&mut rng);
        let recipient =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::random(&mut rng).public_key());
        let r1_sender =
            TransactionPublicKey::secp256r1(secp256r1::PrivateKey::random(&mut rng).public_key());
        let ed_sender = TransactionPublicKey::ed25519(signer.public_key());
        let transactions = vec![
            test_transaction(r1_sender, recipient.clone(), &signer, 0),
            test_transaction(ed_sender, recipient, &signer, 1),
        ];
        let block = Block::<Commitment, PublicKey, Sha256>::new(
            test_header(consensus_key.public_key(), transactions.len()),
            transactions,
        )
        .seal(&mut Sha256::default());

        let rows = encode_indexed_block_rows(&block);
        let [sql] = rows.sql.as_slice() else {
            panic!("expected one block_meta row");
        };

        assert_eq!(uint64_cell(&sql.values[2]), 2);
        assert_eq!(uint64_cell(&sql.values[3]), 1);
        assert_eq!(uint64_cell(&sql.values[4]), 1);
    }

    fn uint64_cell(value: &exoware_sql::CellValue) -> u64 {
        let exoware_sql::CellValue::UInt64(value) = value else {
            panic!("expected UInt64 cell");
        };
        *value
    }

    fn test_transaction(
        sender: TransactionPublicKey,
        recipient: TransactionPublicKey,
        signer: &ed25519::PrivateKey,
        nonce: u64,
    ) -> constantinople_primitives::SignedTransaction<Sha256> {
        Transaction::<sha256::Digest>::new(
            sender,
            recipient,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign(signer, TRANSACTION_NAMESPACE, &mut Sha256::default())
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
}
