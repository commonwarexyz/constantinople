//! Publisher components for finalized index uploads.
//!
//! The production validator path uses [`Publisher`] on the single owning
//! secondary. It persists finalized-block data before publishing an ordered
//! completeness barrier.
//!
//! | Path             | Families / tables                                            |
//! | ---------------- | ------------------------------------------------------------ |
//! | `simplex`        | certified headers, full blocks by digest, certificates       |
//! | `sql`            | `block_meta`, `tx_meta`, `tx_activity`, `account_meta`         |
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
use exoware_sdk::{ClientError, ErrorCode, StoreClient, StoreWriteBatch};
pub use qmdb::Publisher;
pub use sql::SqlRow;
use std::{
    future::Future,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use tracing::warn;

/// Commit latency buckets: 10ms to 60s.
const COMMIT_DURATION_BUCKETS: [f64; 12] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

// Preserve preparation latency differences below the first Store commit bucket.
const PREPARE_DURATION_BUCKETS: [f64; 15] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

// Queue recovery can leave finalized blocks waiting much longer than one commit.
const FINALIZATION_TO_PUBLICATION_BUCKETS: [f64; 17] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
    1800.0, 3600.0,
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
}

/// Metric families used by [`Publisher`].
///
/// The caller registers this once because publisher connects are retried on
/// failure and must not re-register.
#[derive(Clone)]
pub struct PublisherMetrics {
    /// Finalized-index data and publication commits.
    pub(crate) commit: StoreCommitMetrics,
    /// Data chunks belonging to successfully persisted blocks.
    pub(crate) chunk_commits: Counter,
    /// Row preparation for one block, from admission to staged rows.
    pub(crate) prepare_duration: Histogram,
    pub(crate) expansion_duration: Histogram,
    pub(crate) staging_duration: Histogram,
    /// One block's data path, from admission until its data is durable.
    pub(crate) persist_duration: Histogram,
    /// Wait from a block's data being durable until its barrier publishes.
    pub(crate) publication_wait_duration: Histogram,
    pub(crate) finalization_to_publication_duration: Histogram,
}

impl PublisherMetrics {
    pub fn new(context: &impl Metrics) -> Self {
        Self {
            commit: StoreCommitMetrics::new(context),
            chunk_commits: context.counter(
                "chunk_commits",
                "Data chunks in successfully persisted finalized blocks",
            ),
            prepare_duration: context.histogram(
                "prepare_duration",
                "Finalized block row preparation time (s)",
                PREPARE_DURATION_BUCKETS,
            ),
            expansion_duration: context.histogram(
                "expansion_duration",
                "Finalized block metadata and authenticated range preparation time (s)",
                PREPARE_DURATION_BUCKETS,
            ),
            staging_duration: context.histogram(
                "staging_duration",
                "Finalized block SQL preparation and Store row staging time (s)",
                PREPARE_DURATION_BUCKETS,
            ),
            persist_duration: context.histogram(
                "persist_duration",
                "Finalized block time from admission to data durable (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            publication_wait_duration: context.histogram(
                "publication_wait_duration",
                "Finalized block wait from data durable to barrier published (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            finalization_to_publication_duration: context.histogram(
                "finalization_to_publication_duration",
                "Finalized block time from recorded finalization to barrier published (s)",
                FINALIZATION_TO_PUBLICATION_BUCKETS,
            ),
        }
    }
}

// Persistent failures must release the worker so supervision can recover it.
const COMMIT_MAX_ATTEMPTS: u32 = 8;
const COMMIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Retries transient Store failures within a fixed attempt and time budget.
pub(crate) async fn commit_with_retry(
    client: &StoreClient,
    batch: &StoreWriteBatch,
    what: &'static str,
    metrics: &StoreCommitMetrics,
) -> Result<u64, ClientError> {
    let start = Instant::now();
    metrics.in_flight.inc();
    let result = bounded_commit_retry(
        || async {
            let result = batch.commit(client).await;
            if result.is_err() {
                metrics.retries.inc();
            }
            result
        },
        what,
        batch.len(),
    )
    .await;
    metrics.in_flight.dec();
    metrics.duration.observe(start.elapsed().as_secs_f64());
    if result.is_ok() {
        metrics.commits.inc();
        metrics.rows.inc_by(batch.len() as u64);
    }
    result
}

async fn bounded_commit_retry<F>(
    mut commit: impl FnMut() -> F,
    what: &'static str,
    rows: usize,
) -> Result<u64, ClientError>
where
    F: Future<Output = Result<u64, ClientError>>,
{
    timeout(COMMIT_TIMEOUT, async {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match commit().await {
                Ok(seq) => return Ok(seq),
                Err(error) => {
                    if !is_retryable_store_error(&error) || attempt == COMMIT_MAX_ATTEMPTS {
                        warn!(
                            ?error,
                            put_too_large = ?error.put_too_large(),
                            attempt,
                            rows,
                            what,
                            "store batch commit failed, stopping"
                        );
                        return Err(error);
                    }
                    warn!(
                        ?error,
                        attempt, rows, what, "store batch commit failed, retrying"
                    );
                    sleep(retry_backoff(attempt)).await;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        warn!(rows, what, "store batch commit retry deadline expired");
        Err(ClientError::Rpc(Box::new(
            exoware_sdk::ConnectError::deadline_exceeded("Store commit retry budget expired"),
        )))
    })
}

fn is_retryable_store_error(error: &ClientError) -> bool {
    if error.put_too_large().is_some() {
        return false;
    }

    match error {
        ClientError::Http(error) => error.is_connect() || error.is_timeout() || error.is_request(),
        ClientError::Rpc(_) => matches!(
            error.rpc_code(),
            Some(
                ErrorCode::Aborted
                    | ErrorCode::DeadlineExceeded
                    | ErrorCode::Internal
                    | ErrorCode::ResourceExhausted
                    | ErrorCode::Unavailable
                    | ErrorCode::Unknown
            )
        ),
        ClientError::Prefix(_)
        | ClientError::InvalidKeyLength { .. }
        | ClientError::WireFormat(_) => false,
    }
}

fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exoware_sdk::ConnectError;

    #[test]
    fn store_retry_classification_fails_deterministic_rejections() {
        let transient =
            ClientError::Rpc(Box::new(ConnectError::new(ErrorCode::Unavailable, "retry")));
        let rejected = ClientError::Rpc(Box::new(ConnectError::new(
            ErrorCode::InvalidArgument,
            "reject",
        )));

        assert!(is_retryable_store_error(&transient));
        assert!(!is_retryable_store_error(&rejected));
        assert!(!is_retryable_store_error(&ClientError::WireFormat(
            "reject".to_string()
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_recovers_from_transient_failure() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let sequence = bounded_commit_retry(
            || {
                attempts += 1;
                std::future::ready(if attempts == 1 {
                    Err(ClientError::Rpc(Box::new(ConnectError::unavailable(
                        "busy",
                    ))))
                } else {
                    Ok(17)
                })
            },
            "test",
            1,
        )
        .await
        .expect("transient failure should recover");

        assert_eq!(attempts, 2);
        assert_eq!(sequence, 17);
        assert_eq!(start.elapsed(), Duration::from_millis(200));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_stops_on_nonretryable_error() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                std::future::ready(Err(ClientError::WireFormat("reject".to_string())))
            },
            "test",
            1,
        )
        .await
        .expect_err("deterministic failure must stop");

        assert_eq!(attempts, 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(matches!(error, ClientError::WireFormat(message) if message == "reject"));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_stops_after_attempt_budget() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                std::future::ready(Err(ClientError::Rpc(Box::new(
                    ConnectError::resource_exhausted(format!("busy attempt {attempts}")),
                ))))
            },
            "test",
            1,
        )
        .await
        .expect_err("persistent overload must stop");

        assert_eq!(attempts, 8);
        assert_eq!(start.elapsed(), Duration::from_secs(9));
        assert_eq!(error.rpc_code(), Some(ErrorCode::ResourceExhausted));
        assert_eq!(
            error.rpc_error().unwrap().message.as_deref(),
            Some("busy attempt 8")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_deadline_cancels_stalled_commit() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                std::future::pending()
            },
            "test",
            1,
        )
        .await
        .expect_err("stalled commit must time out");

        assert_eq!(attempts, 1);
        assert_eq!(start.elapsed(), Duration::from_secs(60));
        assert_eq!(error.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_deadline_bounds_all_attempts() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                async {
                    sleep(Duration::from_secs(25)).await;
                    Err(ClientError::Rpc(Box::new(ConnectError::unavailable(
                        "busy",
                    ))))
                }
            },
            "test",
            1,
        )
        .await
        .expect_err("retries must share the deadline");

        assert_eq!(attempts, 3);
        assert_eq!(start.elapsed(), Duration::from_secs(60));
        assert_eq!(error.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_deadline_bounds_backoff() {
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                async {
                    sleep(Duration::from_millis(59_900)).await;
                    Err(ClientError::Rpc(Box::new(ConnectError::unavailable(
                        "busy",
                    ))))
                }
            },
            "test",
            1,
        )
        .await
        .expect_err("backoff must share the deadline");

        assert_eq!(attempts, 1);
        assert_eq!(start.elapsed(), Duration::from_secs(60));
        assert_eq!(error.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    }

    #[tokio::test(start_paused = true)]
    async fn store_retry_preserves_put_too_large_without_retrying() {
        use exoware_sdk::{
            google::rpc::ErrorInfo,
            limits::{INGEST_ERROR_DOMAIN, PUT_TOO_LARGE_REASON, PutTooLarge},
            with_error_info_detail,
        };

        let info = ErrorInfo {
            domain: INGEST_ERROR_DOMAIN.to_string(),
            reason: PUT_TOO_LARGE_REASON.to_string(),
            metadata: [
                ("entries", "2000001"),
                ("max_entries", "2000000"),
                ("extra", "preserve me"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
            ..Default::default()
        };
        let start = tokio::time::Instant::now();
        let mut attempts = 0;
        let error = bounded_commit_retry(
            || {
                attempts += 1;
                std::future::ready(Err(ClientError::Rpc(Box::new(with_error_info_detail(
                    ConnectError::invalid_argument("too large"),
                    info.clone(),
                )))))
            },
            "test",
            1,
        )
        .await
        .expect_err("oversized batch must fail immediately");

        assert_eq!(attempts, 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert_eq!(error.rpc_code(), Some(ErrorCode::InvalidArgument));
        assert_eq!(
            error.rpc_error().unwrap().message.as_deref(),
            Some("too large")
        );
        assert_eq!(
            error.put_too_large(),
            Some(PutTooLarge {
                entries: 2_000_001,
                max_entries: 2_000_000,
            })
        );
        assert_eq!(
            error.decoded_rpc_error().unwrap().unwrap().error_info,
            Some(info)
        );
    }
}
