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
    telemetry::metrics::{
        Counter, EncodeLabelSet, Gauge, Histogram, MetricsExt as _, Registered, raw,
    },
};
use exoware_sdk::{ClientError, ErrorCode, StoreClient, StoreWriteBatch};
pub use qmdb::Publisher;
pub use sql::SqlRow;
use std::{
    future::Future,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use tracing::{Instrument as _, info_span, warn};

// Resolve the subsecond differences between preparation and Store commits.
const COMMIT_DURATION_BUCKETS: [f64; 27] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.0625, 0.08, 0.1, 0.125, 0.16, 0.2, 0.25, 0.315, 0.4,
    0.5, 0.63, 0.8, 1.0, 1.25, 1.6, 2.0, 2.5, 5.0, 10.0, 30.0, 60.0,
];

// Queue recovery can leave finalized blocks waiting much longer than one commit.
const FINALIZATION_TO_PUBLICATION_BUCKETS: [f64; 32] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.0625, 0.08, 0.1, 0.125, 0.16, 0.2, 0.25, 0.315, 0.4,
    0.5, 0.63, 0.8, 1.0, 1.25, 1.6, 2.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0,
    3600.0,
];

const ROW_COUNT_BUCKETS: [f64; 20] = [
    1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0, 4096.0, 16384.0, 65536.0,
    131072.0, 250000.0, 500000.0, 1000000.0, 2000000.0, 4000000.0,
];

const ENCODED_BYTES_BUCKETS: [f64; 18] = [
    256.0,
    1024.0,
    4096.0,
    16384.0,
    65536.0,
    262144.0,
    1048576.0,
    2097152.0,
    4194304.0,
    8388608.0,
    16777216.0,
    33554432.0,
    67108864.0,
    100663296.0,
    134217728.0,
    268435456.0,
    536870912.0,
    1073741824.0,
];

const CHUNKS_PER_BLOCK_BUCKETS: [f64; 22] = [
    1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0, 24.0,
    32.0, 64.0, 128.0, 256.0, 512.0,
];

#[derive(Clone, Copy)]
pub(crate) enum CommitKind {
    Chunk,
    Barrier,
    Simplex,
}

impl CommitKind {
    const fn label(self) -> &'static str {
        match self {
            Self::Chunk => "chunk",
            Self::Barrier => "barrier",
            Self::Simplex => "simplex",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Chunk => "finalized index data",
            Self::Barrier => "contiguous publication barrier",
            Self::Simplex => "simplex upload",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CommitLabels {
    kind: &'static str,
}

type CommitHistogram = Registered<raw::Family<CommitLabels, raw::Histogram>>;

/// Observability for store batch commits issued by the publishers.
#[derive(Clone)]
pub struct StoreCommitMetrics {
    in_flight: Gauge,
    commits: Counter,
    rows: Counter,
    retries: Counter,
    duration: CommitHistogram,
    batch_rows: CommitHistogram,
    encoded_bytes: CommitHistogram,
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
            duration: context.register(
                "store_commit_duration",
                "Store logical batch commit latency including retries and backoff (s)",
                raw::Family::<CommitLabels, raw::Histogram>::new_with_constructor(|| {
                    raw::Histogram::new(COMMIT_DURATION_BUCKETS)
                }),
            ),
            batch_rows: context.register(
                "store_commit_batch_rows",
                "Rows per finished logical Store commit including failures",
                raw::Family::<CommitLabels, raw::Histogram>::new_with_constructor(|| {
                    raw::Histogram::new(ROW_COUNT_BUCKETS)
                }),
            ),
            encoded_bytes: context.register(
                "store_commit_encoded_bytes",
                "Uncompressed protobuf bytes per finished logical Store commit including failures",
                raw::Family::<CommitLabels, raw::Histogram>::new_with_constructor(|| {
                    raw::Histogram::new(ENCODED_BYTES_BUCKETS)
                }),
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
    pub(crate) prepare_duration: Histogram,
    pub(crate) prepare_wait_duration: Histogram,
    pub(crate) prepare_cpu_duration: Histogram,
    pub(crate) chunking_duration: Histogram,
    pub(crate) chunks_per_block: Histogram,
    pub(crate) transactions_per_block: Histogram,
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
                "Finalized block preparation execution wall time including splitting and excluding scheduling (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            prepare_wait_duration: context.histogram(
                "prepare_wait_duration",
                "Publisher enqueue to start of preparation (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            prepare_cpu_duration: context.histogram(
                "prepare_cpu_duration",
                "Finalized block current preparation thread CPU time excluding Rayon workers (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            chunking_duration: context.histogram(
                "chunking_duration",
                "Finalized block Store batch splitting time (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            chunks_per_block: context.histogram(
                "chunks_per_block",
                "Store data chunks per persisted finalized block",
                CHUNKS_PER_BLOCK_BUCKETS,
            ),
            transactions_per_block: context.histogram(
                "transactions_per_block",
                "Transactions per finalized block entering preparation",
                ROW_COUNT_BUCKETS,
            ),
            expansion_duration: context.histogram(
                "expansion_duration",
                "Finalized block metadata and authenticated range preparation time (s)",
                COMMIT_DURATION_BUCKETS,
            ),
            staging_duration: context.histogram(
                "staging_duration",
                "Finalized block SQL preparation and Store row staging time (s)",
                COMMIT_DURATION_BUCKETS,
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
    kind: CommitKind,
    metrics: &StoreCommitMetrics,
) -> Result<u64, ClientError> {
    let rows = batch.len();
    let encoded_bytes = batch.encoded_len();
    async {
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
            kind.description(),
            rows,
        )
        .await;
        metrics.in_flight.dec();

        // Count each logical batch once so retries do not distort its size distribution.
        let labels = CommitLabels { kind: kind.label() };
        metrics
            .duration
            .get_or_create(&labels)
            .observe(start.elapsed().as_secs_f64());
        metrics
            .batch_rows
            .get_or_create(&labels)
            .observe(rows as f64);
        metrics
            .encoded_bytes
            .get_or_create(&labels)
            .observe(encoded_bytes as f64);
        if result.is_ok() {
            metrics.commits.inc();
            metrics.rows.inc_by(rows as u64);
        }
        result
    }
    .instrument(info_span!(
        "store_commit",
        kind = kind.label(),
        rows,
        encoded_bytes
    ))
    .await
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
    use commonware_runtime::{Runner as _, telemetry::metrics::has_metric_value};
    use exoware_sdk::{ConnectError, Key};

    fn metric_sample(encoded: &str, name: &str, kind: CommitKind) -> f64 {
        let sample = format!("{name}{{kind=\"{}\"}} ", kind.label());
        encoded
            .lines()
            .find_map(|line| line.strip_prefix(&sample))
            .unwrap_or_else(|| panic!("missing sample {sample} in {encoded}"))
            .parse()
            .expect("numeric metric sample")
    }

    fn commit_batch(client: &StoreClient) -> StoreWriteBatch {
        let client = crate::namespaces::state_qmdb_client(client).expect("namespace builds");
        let mut batch = StoreWriteBatch::new();
        batch
            .push(&client, &Key::from(vec![1; 8]), vec![7; 200])
            .unwrap();
        batch
            .push(&client, &Key::from(vec![2; 8]), vec![9; 5])
            .unwrap();
        batch
    }

    fn assert_commit_samples(encoded: &str, kind: CommitKind, rows: usize, encoded_bytes: usize) {
        for name in [
            "store_commit_duration_count",
            "store_commit_batch_rows_count",
            "store_commit_encoded_bytes_count",
        ] {
            assert_eq!(metric_sample(encoded, name, kind), 1.0);
        }
        assert_eq!(
            metric_sample(encoded, "store_commit_batch_rows_sum", kind),
            rows as f64,
        );
        assert_eq!(
            metric_sample(encoded, "store_commit_encoded_bytes_sum", kind),
            encoded_bytes as f64,
        );
    }

    #[test]
    fn store_commit_metrics_distinguish_kinds_and_exact_encoded_bytes() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (server, url) = exoware_simulator::open_temp().await.expect("spawn Store");
            let client = crate::store::writer_store_client(&url, None).expect("client builds");
            let metrics = StoreCommitMetrics::new(&context);
            let batch = commit_batch(&client);

            // The larger value needs two-byte lengths for both its field and entry envelope.
            let expected_bytes =
                batch.entries()[0].0.len() + 200 + 8 + batch.entries()[1].0.len() + 5 + 6;
            assert_eq!(batch.encoded_len(), expected_bytes);
            for kind in [CommitKind::Chunk, CommitKind::Barrier, CommitKind::Simplex] {
                commit_with_retry(&client, &batch, kind, &metrics)
                    .await
                    .expect("commit succeeds");
                assert_commit_samples(&context.encode(), kind, 2, expected_bytes);
            }

            let encoded = context.encode();
            assert!(has_metric_value(&encoded, "store_commits_total", 3));
            assert!(has_metric_value(&encoded, "store_commit_rows_total", 6));
            assert!(has_metric_value(&encoded, "store_commit_retries_total", 0));
            assert!(has_metric_value(&encoded, "store_commits_in_flight", 0));
            server.abort();
        });
    }

    #[test]
    fn store_commit_metrics_record_failed_logical_batch_once_after_retry() {
        use axum::{
            Router,
            http::{StatusCode, header::CONTENT_TYPE},
        };
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let attempts = Arc::new(AtomicUsize::new(0));
            let observed_attempts = attempts.clone();
            let app = Router::new().fallback(move || {
                let attempts = observed_attempts.clone();
                async move {
                    let (status, body) = if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            r#"{"code":"unavailable","message":"retry"}"#,
                        )
                    } else {
                        (
                            StatusCode::BAD_REQUEST,
                            r#"{"code":"invalid_argument","message":"reject"}"#,
                        )
                    };
                    (status, [(CONTENT_TYPE, "application/json")], body)
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let client = crate::store::store_client(&url, None).expect("client builds");
            let metrics = StoreCommitMetrics::new(&context);
            let batch = commit_batch(&client);
            let error = commit_with_retry(&client, &batch, CommitKind::Chunk, &metrics)
                .await
                .expect_err("Store rejects commit");

            assert_eq!(error.rpc_code(), Some(ErrorCode::InvalidArgument));
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
            let encoded = context.encode();
            assert_commit_samples(
                &encoded,
                CommitKind::Chunk,
                batch.len(),
                batch.encoded_len(),
            );
            assert!(metric_sample(&encoded, "store_commit_duration_sum", CommitKind::Chunk) >= 0.2);
            assert!(has_metric_value(&encoded, "store_commits_total", 0));
            assert!(has_metric_value(&encoded, "store_commit_rows_total", 0));
            assert!(has_metric_value(&encoded, "store_commit_retries_total", 2));
            assert!(has_metric_value(&encoded, "store_commits_in_flight", 0));
            server.abort();
        });
    }

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
