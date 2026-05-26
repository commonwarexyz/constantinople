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
use commonware_cryptography::{Hasher, PublicKey};
use constantinople_engine::types::EngineBlock;
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
                let IndexedBlockRows { raw, sql } = encode_indexed_block_rows(&block);

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
pub(crate) struct IndexedBlockRows {
    /// Raw KV rows for the block and contained transactions.
    pub raw: Vec<(Key, Bytes)>,
    /// SQL metadata row for the block.
    pub sql: Vec<SqlRow>,
}

/// Build every row for a finalized block, partitioned by destination store.
pub(crate) fn encode_indexed_block_rows<H, P>(block: &EngineBlock<H, P>) -> IndexedBlockRows
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
            Some((idx, lazy, tx))
        })
        .collect::<Vec<_>>();
    let tx_count = u64::try_from(materialized_txs.len()).expect("transaction count fits u64");
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
    for (materialized_idx, (idx, lazy, tx)) in materialized_txs.iter().enumerate() {
        let tx_digest = tx.message_digest();
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
            raw.push((
                keys::tx_by_sender(sender.as_ref(), height, idx_u32)
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
        transactions_root,
        transactions_tip: block.header.transactions_range.end() - 1,
        view: 0,
        finalized_ts_micros,
    });

    IndexedBlockRows { raw, sql }
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
