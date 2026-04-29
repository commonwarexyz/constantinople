//! SQL metadata publisher and uploader.
//!
//! This is the metadata-streaming half of the indexer's two-path layout
//! (see [`crate::sql_schema`] for the table definitions). Per finalized
//! `Update::Block` the [`BlockReporter`] dispatches a single [`SqlBatch`]
//! containing one [`crate::sql_schema::BLOCK_META_TABLE`] row plus one
//! [`crate::sql_schema::TX_META_TABLE`] row per contained transaction. A
//! dedicated uploader task drains the channel, inserts every row into a
//! reused [`BatchWriter`], and flushes once per block — never batching
//! multiple blocks together.
//!
//! Failure model: the flush is retried indefinitely with the standard
//! `retry_backoff` ladder shared with the KV uploaders. The marshal
//! [`Exact`] acknowledgement cloned by the reporter is held until the
//! flush succeeds, so consensus back-pressures naturally if the SQL
//! store is unhealthy.
//!
//! [`BlockReporter`]: super::BlockReporter
//! [`BatchWriter`]: exoware_sql::BatchWriter

use super::retry_backoff;
use crate::sql_schema::{BLOCK_META_TABLE, TX_META_TABLE, build_meta_schema};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use exoware_sdk::StoreClient;
use exoware_sql::{BatchWriter, CellValue};
use tokio::{sync::mpsc, time::sleep};
use tracing::{debug, error, warn};

/// One row destined for a SQL metadata table.
///
/// `table` identifies the destination by name (one of the constants in
/// [`crate::sql_schema`]); `values` is the column-ordered cell list that
/// matches the schema declared by [`build_meta_schema`].
pub struct SqlRow {
    pub table: &'static str,
    pub values: Vec<CellValue>,
}

/// One atomic SQL flush per finalized block.
///
/// A single [`SqlBatch`] always contains exactly one `block_meta` row plus
/// zero or more `tx_meta` rows for the transactions in that block. The
/// uploader inserts all rows then issues a single `flush().await` so the
/// underlying KV store sees one atomic put per finalized block.
pub struct SqlBatch {
    pub rows: Vec<SqlRow>,
    pub ack: Option<Exact>,
}

/// Hand a [`SqlBatch`] off to the SQL uploader on a fresh tokio task.
///
/// Mirrors the back-pressure semantics of [`super::dispatch_batch`]: the
/// reporter never blocks consensus, marshal back-pressures via the still-
/// held ack, and a closed channel logs and drops the batch (canceling the
/// ack, matching the documented "drop = shutdown" behaviour on
/// [`commonware_consensus::marshal::Update`]).
pub(crate) fn dispatch_sql_batch(tx: &mpsc::Sender<SqlBatch>, batch: SqlBatch) {
    let tx = tx.clone();
    tokio::spawn(async move {
        if let Err(error) = tx.send(batch).await {
            error!("indexer sql channel closed; dropping batch and ack: {error}");
        }
    });
}

/// Spawn the SQL uploader task on the current tokio runtime.
///
/// Returns the sender for the bounded MPSC channel and the task's join
/// handle. The task owns the [`BatchWriter`] and flushes once per block.
pub fn spawn_sql_uploader(
    client: StoreClient,
    buffer: usize,
) -> (mpsc::Sender<SqlBatch>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel::<SqlBatch>(buffer);
    let join = tokio::spawn(run_sql_uploader(client, rx));
    (tx, join)
}

async fn run_sql_uploader(client: StoreClient, mut rx: mpsc::Receiver<SqlBatch>) {
    // The schema builder is infallible for our hard-coded layout; treat a
    // failure as a bug and panic so the uploader never silently degrades.
    let schema = build_meta_schema(client).expect("meta schema must build");
    let mut writer = schema.batch_writer();

    while let Some(batch) = rx.recv().await {
        flush_with_retry(&mut writer, &batch.rows).await;
        if let Some(ack) = batch.ack {
            ack.acknowledge();
        }
    }
    debug!("indexer sql uploader task exiting: channel closed");
}

/// Insert every row, then retry `flush().await` until the store accepts it.
///
/// On a flush error [`BatchWriter`] internally stashes the prepared batch
/// into `failed_prepared` so the next `flush()` call re-sends the same
/// rows; we therefore never re-`insert` after a failure.
async fn flush_with_retry(writer: &mut BatchWriter, rows: &[SqlRow]) {
    for row in rows {
        if let Err(error) = writer.insert(row.table, row.values.clone()) {
            // A row-encoding failure here means the schema and the row
            // construction site disagree — that's a bug. Log and skip the
            // bad row rather than aborting the entire batch.
            error!(table = row.table, %error, "sql row insert failed; skipping");
        }
    }

    let row_count = rows.len();
    let mut attempt: u32 = 0;
    loop {
        match writer.flush().await {
            Ok(seq) => {
                debug!(seq, rows = row_count, "indexer uploaded sql batch");
                return;
            }
            Err(error) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    %error,
                    attempt,
                    rows = row_count,
                    "indexer sql flush failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    }
}

/// Encode the SQL rows for a finalized block.
///
/// Returns one `block_meta` row plus one `tx_meta` row per transaction.
/// The `finalized_ts_micros` is captured by the reporter at the moment the
/// block is delivered (wall-clock on this validator).
///
/// The `view` column is currently always `0` because the BlockReporter
/// slot does not see consensus rounds; the certificate observer slot owns
/// that signal. A future enrichment can pipe round/view metadata through
/// either by joining tables or by extending [`SqlRow`] with an update
/// path.
pub(crate) fn encode_sql_rows(
    height: u64,
    digest: [u8; 32],
    tx_count: u64,
    view: u64,
    finalized_ts_micros: i64,
    tx_digests: &[[u8; 32]],
) -> Vec<SqlRow> {
    let mut rows = Vec::with_capacity(1 + tx_digests.len());
    rows.push(SqlRow {
        table: BLOCK_META_TABLE,
        values: vec![
            CellValue::UInt64(height),
            CellValue::FixedBinary(digest.to_vec()),
            CellValue::UInt64(tx_count),
            CellValue::UInt64(view),
            CellValue::Timestamp(finalized_ts_micros),
        ],
    });
    for (idx, tx_digest) in tx_digests.iter().enumerate() {
        rows.push(SqlRow {
            table: TX_META_TABLE,
            values: vec![
                CellValue::UInt64(height),
                CellValue::UInt64(idx as u64),
                CellValue::FixedBinary(tx_digest.to_vec()),
            ],
        });
    }
    rows
}
