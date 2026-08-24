//! Publisher components for finalized index uploads.
//!
//! The production validator path uses [`Publisher`] on the single owning
//! secondary. It publishes finalized-block data through ordered metadata and
//! bulk lanes.
//!
//! | Path             | Families / tables                                            |
//! | ---------------- | ------------------------------------------------------------ |
//! | `simplex`        | certified headers, full blocks by digest, certificates       |
//! | `sql` (fast lane) | `block_meta`                                                 |
//! | `sql` (bulk)      | `tx_meta`, `tx_activity`, `account_meta`                     |
//! | `qmdb` (state)   | Account-state operation log                                  |
//! | `qmdb` (tx hash) | Transaction-hash operation log                                |
//!
//! Simplex block and certificate artifacts are uploaded separately through
//! [`CertificateReporter`] using `exoware-simplex` indexes in the same Store.
//!
//! [`StoreClient`]: exoware_sdk::StoreClient

pub(crate) mod block;
pub mod certificate;
pub mod qmdb;
pub mod sql;

pub use certificate::CertificateReporter;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Gauge, Histogram, MetricsExt as _},
};
use exoware_sdk::{StoreClient, StoreWriteBatch};
pub use qmdb::Publisher;
pub use sql::SqlRow;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::warn;

/// Commit latency buckets: 10ms to 60s.
const COMMIT_DURATION_BUCKETS: [f64; 12] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

/// Observability for store batch commits issued by the publishers.
#[derive(Clone)]
pub struct StoreCommitMetrics {
    in_flight: Gauge,
    commits: Counter,
    rows: Counter,
    retries: Counter,
    duration: Histogram,
}

impl StoreCommitMetrics {
    pub fn new(context: &impl Metrics) -> Self {
        Self {
            in_flight: context.gauge("store_commits_in_flight", "Store batch commits in flight"),
            commits: context.counter("store_commits", "Store batch commits completed"),
            rows: context.counter("store_commit_rows", "Rows committed to the store"),
            retries: context.counter(
                "store_commit_retries",
                "Store batch commit attempts that failed",
            ),
            duration: context.histogram(
                "store_commit_duration",
                "Store batch commit latency (s)",
                COMMIT_DURATION_BUCKETS,
            ),
        }
    }

    /// Metadata fast-lane commits register under distinct names so the bulk
    /// commit dashboards keep their meaning.
    pub fn new_metadata(context: &impl Metrics) -> Self {
        Self {
            in_flight: context.gauge(
                "metadata_store_commits_in_flight",
                "Metadata Store batch commits in flight",
            ),
            commits: context.counter(
                "metadata_store_commits",
                "Metadata Store batch commits completed",
            ),
            rows: context.counter(
                "metadata_store_commit_rows",
                "Rows committed to the store by the metadata lane",
            ),
            retries: context.counter(
                "metadata_store_commit_retries",
                "Metadata Store batch commit attempts that failed",
            ),
            duration: context.histogram(
                "metadata_store_commit_duration",
                "Metadata Store batch commit latency (s)",
                COMMIT_DURATION_BUCKETS,
            ),
        }
    }
}

/// Metric families used by [`Publisher`].
///
/// The caller registers this once because publisher connects are retried on
/// failure and must not re-register.
#[derive(Clone)]
pub struct PublisherMetrics {
    /// Bulk finalized-index batch commits.
    pub(crate) commit: StoreCommitMetrics,
    /// Metadata fast-lane block_meta commits.
    pub(crate) metadata_commit: StoreCommitMetrics,
    /// Time bulk commits spend waiting on the metadata persistence gate.
    pub(crate) metadata_gate_wait: Histogram,
    /// Block finalization to durable block_meta row.
    pub(crate) metadata_finalized_lag: Histogram,
}

impl PublisherMetrics {
    pub fn new(context: &impl Metrics) -> Self {
        Self {
            commit: StoreCommitMetrics::new(context),
            metadata_commit: StoreCommitMetrics::new_metadata(context),
            metadata_gate_wait: context.histogram(
                "metadata_gate_wait_duration",
                "Time bulk commits wait for block_meta persistence (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            metadata_finalized_lag: context.histogram(
                "metadata_finalized_lag",
                "Block finalization to durable block_meta row (s)",
                COMMIT_DURATION_BUCKETS,
            ),
        }
    }
}

/// Commits `batch` through the physical Store client, retrying with capped
/// exponential backoff until it lands. Rows are namespace-encoded when they
/// are staged, so the commit is a raw write.
pub(crate) async fn commit_with_retry(
    client: &StoreClient,
    batch: &StoreWriteBatch,
    what: &'static str,
    metrics: &StoreCommitMetrics,
) -> u64 {
    let start = Instant::now();
    metrics.in_flight.inc();
    let mut attempt = 0u32;
    let seq = loop {
        match batch.commit(client).await {
            Ok(seq) => break seq,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                metrics.retries.inc();
                warn!(
                    ?error,
                    attempt,
                    rows = batch.len(),
                    what,
                    "store batch commit failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    };
    metrics.in_flight.dec();
    metrics.commits.inc();
    metrics.rows.inc_by(batch.len() as u64);
    metrics.duration.observe(start.elapsed().as_secs_f64());
    seq
}

fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}
