//! Reporters and uploader actors for indexer publishing.
//!
//! The non-QMDB publisher is split in two halves:
//!
//! - One or more cloneable [`Reporter`] implementations that encode incoming
//!   consensus events into atomic [`UploadBatch`]es and push them to a bounded
//!   MPSC channel.
//! - Two uploader tasks (see [`spawn_uploaders`]) — one raw KV store plus
//!   one SQL metadata writer — that each own a [`StoreClient`] and drain
//!   their channel, retrying until the store accepts the batch. On
//!   success each task fulfills its clone of the marshal acknowledgement
//!   bundled with the batch (if any).
//!
//! Constantinople's metadata-only and non-QMDB full modes fan data across one
//! raw KV stream plus one SQL stream:
//!
//! | Path             | Families / tables                                            |
//! | ---------------- | ------------------------------------------------------------ |
//! | `raw` (KV)       | `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H`, `FINALIZED`, `NOTARIZED` |
//! | `sql` (metadata) | `block_meta`, `tx_meta`                                      |
//!
//! The marshal [`Exact`] acknowledgement is cloned once per uploader so the
//! waiter resolves only after every path has durably accepted its batch.
//! When QMDB upload is enabled on the single owning secondary,
//! [`QmdbPublisher`] replaces the block reporter and stages raw KV rows, SQL
//! rows, account-state QMDB rows, and transaction-hash QMDB rows into one
//! Store batch per finalized block.
//!
//! [`Reporter`]: commonware_consensus::Reporter
//! [`StoreClient`]: exoware_sdk::StoreClient

use bytes::Bytes;
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use exoware_sdk::{RetryConfig, StoreClient, keys::Key};
use std::time::Duration;
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};
use tracing::{debug, error, warn};

pub mod block;
pub mod certificate;
pub mod qmdb;
pub mod sql;

pub use block::BlockReporter;
pub use certificate::CertificateReporter;
pub use qmdb::QmdbPublisher;
pub use sql::{SqlBatch, SqlRow, spawn_sql_uploader};

/// One atomic write to a single exoware store.
///
/// The uploader uses `ingest().put` so every key in `rows` is committed in a
/// single store sequence number. If `ack` is `Some`, the uploader fulfills the
/// acknowledgement only after the put succeeds.
pub struct UploadBatch {
    /// Pre-encoded `(key, value)` pairs to ingest atomically.
    pub rows: Vec<(Key, Bytes)>,
    /// Marshal acknowledgement to release once this store has accepted the
    /// batch. When the same logical event spans multiple stores the caller
    /// clones the [`Exact`] handle once per store; the waiter only resolves
    /// after every clone has acknowledged.
    pub ack: Option<Exact>,
}

/// Handles for the uploader tasks and their feeder channels.
///
/// One channel carries pre-encoded KV [`UploadBatch`]es to the raw exoware
/// Store. The second carries typed
/// [`SqlBatch`]es to the SQL metadata uploader, which owns a single
/// [`exoware_sql::BatchWriter`] over its own [`StoreClient`]. Cloneable
/// [`BlockReporter`] / [`CertificateReporter`] instances clone these
/// senders and forward batches to the uploader tasks.
pub struct UploaderHandles {
    /// Sender for raw KV rows.
    pub raw: mpsc::Sender<UploadBatch>,
    /// Sender for the SQL metadata uploader (`block_meta`, `tx_meta`).
    pub sql: mpsc::Sender<SqlBatch>,
    /// Background uploader join handles, kept alive for the lifetime of the
    /// validator process so the tasks are not aborted prematurely.
    pub joins: [JoinHandle<()>; 2],
}

/// Spawn a raw KV uploader task on the current tokio runtime.
pub fn spawn_raw_uploader(
    raw_client: StoreClient,
    buffer: usize,
) -> (mpsc::Sender<UploadBatch>, JoinHandle<()>) {
    let (raw_tx, raw_rx) = mpsc::channel::<UploadBatch>(buffer);
    let raw_join = tokio::spawn(run_uploader("raw", raw_client, raw_rx));
    (raw_tx, raw_join)
}

/// Spawn one uploader task per backing store on the current tokio runtime.
///
/// The raw uploader coalesces queued pre-encoded KV batches through
/// [`StoreClient::ingest`]. The SQL uploader owns an
/// [`exoware_sql::BatchWriter`] and coalesces queued finalized blocks into
/// larger flushes.
pub fn spawn_uploaders(
    raw_client: StoreClient,
    sql_client: StoreClient,
    buffer: usize,
) -> UploaderHandles {
    let (raw_tx, raw_join) = spawn_raw_uploader(raw_client, buffer);
    let (sql_tx, sql_join) = spawn_sql_uploader(sql_client, buffer);

    UploaderHandles {
        raw: raw_tx,
        sql: sql_tx,
        joins: [raw_join, sql_join],
    }
}

async fn run_uploader(
    store: &'static str,
    client: StoreClient,
    mut rx: mpsc::Receiver<UploadBatch>,
) {
    while let Some(first) = rx.recv().await {
        let mut batches = vec![first];
        while let Ok(batch) = rx.try_recv() {
            batches.push(batch);
        }

        let batch_count = batches.len();
        let row_count: usize = batches.iter().map(|batch| batch.rows.len()).sum();
        upload_with_retry(
            store,
            &client,
            batches.iter().flat_map(|batch| batch.rows.iter()),
        )
        .await;

        for batch in batches {
            if let Some(ack) = batch.ack {
                ack.acknowledge();
            }
        }
        debug!(
            store,
            batches = batch_count,
            rows = row_count,
            "indexer acknowledged coalesced batches"
        );
    }
    debug!(store, "indexer uploader task exiting: channel closed");
}

/// Retry the put indefinitely with standard backoff until the store accepts it.
///
/// Marshal back-pressures the engine on the still-held ack, so retrying here
/// is the right way to express at-least-once delivery: we never lose a batch
/// and the engine slows down if the store is unhealthy.
async fn upload_with_retry<'a>(
    store: &'static str,
    client: &StoreClient,
    rows: impl Iterator<Item = &'a (Key, Bytes)>,
) {
    let kvs: Vec<(&Key, &[u8])> = rows.map(|(k, v)| (k, v.as_ref())).collect();
    let mut attempt: u32 = 0;
    loop {
        match client.ingest().put(&kvs).await {
            Ok(seq) => {
                debug!(store, seq, rows = kvs.len(), "indexer uploaded batch");
                return;
            }
            Err(error) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    store,
                    ?error,
                    attempt,
                    rows = kvs.len(),
                    "indexer upload failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    }
}

/// Exponential backoff capped at 2s, mirroring [`RetryConfig::standard`] but
/// applied across our own infinite retry loop above the SDK's per-call retry.
fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}

/// Convenience: build a [`StoreClient`] with the SDK's standard retry policy.
pub fn standard_store_client(url: &str) -> StoreClient {
    StoreClient::with_retry_config(url, RetryConfig::standard())
}

/// Hand a batch off to the uploader in the background.
///
/// `Reporter::report` must never block consensus, so we always dispatch the
/// channel send onto a fresh tokio task and return immediately. Back-pressure
/// comes solely from the marshal acknowledgement bundled with the batch:
/// while the uploader queue grows, marshal still considers the block
/// undelivered and refuses to admit new ones.
///
/// If the batch carries no rows (e.g. a transactions batch for an empty
/// block), the put is skipped and the bundled acknowledgement (if any) is
/// fulfilled immediately — the corresponding store has nothing to durably
/// accept, so we must not stall the waiter.
///
/// If the uploader channel is closed (the task has exited) the batch is
/// dropped and any associated acknowledgement is canceled, which matches the
/// documented "drop = shutdown" semantics on
/// [`commonware_consensus::marshal::Update`].
pub(crate) fn dispatch_batch(tx: &mpsc::Sender<UploadBatch>, batch: UploadBatch) {
    if batch.rows.is_empty() {
        if let Some(ack) = batch.ack {
            ack.acknowledge();
        }
        return;
    }
    let tx = tx.clone();
    tokio::spawn(async move {
        if let Err(error) = tx.send(batch).await {
            error!("indexer channel closed; dropping batch and ack: {error}");
        }
    });
}
