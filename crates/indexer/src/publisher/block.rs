//! Block reporter that fans a finalized block out across three exoware stores.
//!
//! Wired into the engine via the existing `marshal` reporter slot. On every
//! `Update::Block(block, ack)` we:
//!
//! 1. Encode three batches:
//!    - **blocks store**: BLOCK + BLOCK_BY_H rows (block payload + height index).
//!    - **transactions store**: TX + TX_BY_H rows for every contained tx.
//!    - **meta store**: the META `latest_finalized_height` cursor.
//! 2. Clone the marshal acknowledgement once per uploader. Each uploader
//!    fulfills its clone after its own put succeeds; the marshal waiter only
//!    resolves after every store has durably accepted its batch.
//! 3. Forward each batch to its uploader and return immediately so consensus
//!    is not blocked on the network store — marshal itself back-pressures
//!    the engine through the still-held ack.

use crate::{
    keys,
    publisher::{
        SqlBatch, UploadBatch, dispatch_batch,
        sql::{dispatch_sql_batch, encode_sql_rows},
    },
};
use bytes::Bytes;
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

/// Cloneable [`Reporter`] over `Update<EngineBlock<H, P>>`.
///
/// Holds one sender per backing store. Cloning the reporter is cheap; the
/// senders are reference-counted MPSC channels.
pub struct BlockReporter<H, P> {
    blocks: mpsc::Sender<UploadBatch>,
    transactions: mpsc::Sender<UploadBatch>,
    meta: mpsc::Sender<UploadBatch>,
    sql: mpsc::Sender<SqlBatch>,
    _marker: PhantomData<fn() -> (H, P)>,
}

impl<H, P> BlockReporter<H, P> {
    /// Build a reporter that forwards batches to the per-store uploader channels.
    ///
    /// Three KV channels mirror the existing per-store layout (BLOCK,
    /// TX, META). The fourth (`sql`) feeds the SQL metadata uploader,
    /// which writes typed rows into the `block_meta` and `tx_meta`
    /// tables declared by [`crate::sql_schema`].
    pub const fn new(
        blocks: mpsc::Sender<UploadBatch>,
        transactions: mpsc::Sender<UploadBatch>,
        meta: mpsc::Sender<UploadBatch>,
        sql: mpsc::Sender<SqlBatch>,
    ) -> Self {
        Self {
            blocks,
            transactions,
            meta,
            sql,
            _marker: PhantomData,
        }
    }
}

impl<H, P> Clone for BlockReporter<H, P> {
    fn clone(&self) -> Self {
        Self {
            blocks: self.blocks.clone(),
            transactions: self.transactions.clone(),
            meta: self.meta.clone(),
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

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            // Tip-only updates carry no block payload; nothing to upload.
            Update::Tip(_, _, _) => {}
            Update::Block(block, ack) => {
                // Encoding is cheap and synchronous. The actual store writes
                // are dispatched onto background tasks so this method never
                // blocks consensus — see `dispatch_batch` for back-pressure
                // semantics.
                let EncodedRows {
                    blocks,
                    transactions,
                    meta,
                    sql,
                } = encode_block_rows(&block);

                // Clone the ack once per uploader. `Exact::clone` increments
                // the remaining count, so the marshal waiter only resolves
                // after each uploader's clone has been acknowledged. If a
                // batch is empty (e.g. a block with no transactions) the
                // dispatcher fulfills its clone immediately.
                let ack_blocks = ack.clone();
                let ack_transactions = ack.clone();
                let ack_meta = ack.clone();
                let ack_sql = ack;

                dispatch_batch(
                    &self.blocks,
                    UploadBatch {
                        rows: blocks,
                        ack: Some(ack_blocks),
                    },
                );
                dispatch_batch(
                    &self.transactions,
                    UploadBatch {
                        rows: transactions,
                        ack: Some(ack_transactions),
                    },
                );
                dispatch_batch(
                    &self.meta,
                    UploadBatch {
                        rows: meta,
                        ack: Some(ack_meta),
                    },
                );
                dispatch_sql_batch(
                    &self.sql,
                    SqlBatch {
                        rows: sql,
                        ack: Some(ack_sql),
                    },
                );
            }
        }
    }
}

/// Encoded rows split by destination store.
struct EncodedRows {
    blocks: Vec<(Key, Bytes)>,
    transactions: Vec<(Key, Bytes)>,
    meta: Vec<(Key, Bytes)>,
    sql: Vec<crate::publisher::SqlRow>,
}

/// Build every key-value row for a finalized block, partitioned by destination store.
fn encode_block_rows<H, P>(block: &EngineBlock<H, P>) -> EncodedRows
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
    // SQL `block_meta.digest` and per-row `tx_meta.tx_digest` are
    // `FixedSizeBinary(32)` — copy each digest into a `[u8; 32]` for the
    // typed CellValue path.
    let mut block_digest_arr = [0u8; 32];
    block_digest_arr.copy_from_slice(block_digest.as_ref());
    let mut tx_digests: Vec<[u8; 32]> = Vec::with_capacity(body_len);

    // BLOCK family: digest -> encoded SealedBlock (which serializes the inner Block).
    // BLOCK_BY_H family: height -> block digest (32 bytes).
    let blocks = vec![
        (
            keys::block(block_digest.as_ref()).expect("block digest fits family payload"),
            block.encode(),
        ),
        (
            keys::block_by_height(height).expect("u64 height fits family payload"),
            Bytes::copy_from_slice(block_digest.as_ref()),
        ),
    ];

    // Per-transaction rows: TX (digest -> encoded tx) and TX_BY_H ((height, idx) -> tx digest).
    let mut transactions = Vec::with_capacity(2 * body_len);
    for (idx, lazy) in block.body.iter().enumerate() {
        let Some(tx) = lazy.get() else {
            // Marshal must have already verified each tx upstream, so a decode
            // failure here means we received a malformed block. Skip rather
            // than abort the whole batch — the block still goes up.
            warn!(
                height,
                idx, "indexer: skipping transaction that failed to materialize"
            );
            continue;
        };
        let tx_digest = tx.message_digest();
        let tx_bytes = lazy.encode();
        let idx_u32 = u32::try_from(idx).expect("transaction index fits u32");

        transactions.push((
            keys::tx(tx_digest.as_ref()).expect("tx digest fits family payload"),
            tx_bytes,
        ));
        transactions.push((
            keys::tx_by_height(height, idx_u32).expect("(height, idx) fits family payload"),
            Bytes::copy_from_slice(tx_digest.as_ref()),
        ));
        // Collect for SQL `tx_meta` after the per-tx KV rows are recorded.
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(tx_digest.as_ref());
        tx_digests.push(digest_arr);
    }

    // META: latest_finalized_height = u64 BE.
    let meta = vec![(
        keys::meta_latest_height().expect("meta key fits family payload"),
        Bytes::copy_from_slice(&height.to_be_bytes()),
    )];

    // SQL: one block_meta row + one tx_meta row per surviving transaction.
    // `view` is currently 0; see `encode_sql_rows` docs for why.
    let tx_count = u64::try_from(tx_digests.len()).expect("tx count fits u64");
    let sql = encode_sql_rows(
        height,
        block_digest_arr,
        tx_count,
        0,
        finalized_ts_micros,
        &tx_digests,
    );

    EncodedRows {
        blocks,
        transactions,
        meta,
        sql,
    }
}
