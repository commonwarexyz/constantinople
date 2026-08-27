//! Async submission engine.
//!
//! Each relayer stream submits one batch at a time and advances to the next
//! pre-signed batch after finalization or drop.

use crate::signer::Tx;
use commonware_codec::Encode;
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use constantinople_mempool::webserver::{SubmitError, TxStatus};
use rand::{RngExt as _, rand_core::UnwrapErr, rngs::SysRng};
use std::{sync::Arc, time::Duration};
use tracing::{debug, info, warn};

struct Metrics {
    submitted_batches: Counter,
    submitted_transactions: Counter,
    finalized_transactions: Counter,
    filtered_transactions: Counter,
    dropped_transactions: Counter,
    submit_errors: Counter,
}

impl Metrics {
    fn init(context: &impl RuntimeMetrics) -> Self {
        Self {
            submitted_batches: context
                .counter("submitted_batches", "Submitted transaction batches"),
            submitted_transactions: context
                .counter("submitted_transactions", "Submitted transactions"),
            finalized_transactions: context
                .counter("finalized_transactions", "Finalized transactions"),
            filtered_transactions: context
                .counter("filtered_transactions", "Filtered transactions"),
            dropped_transactions: context.counter("dropped_transactions", "Dropped transactions"),
            submit_errors: context.counter("submit_errors", "Relayer submit errors"),
        }
    }
}

/// Prometheus counters shared across submitters, exported via the metrics endpoint and read back
/// by [`Stats::totals`] for the periodic progress log.
pub struct Stats {
    metrics: Metrics,
}

#[derive(Clone, Copy)]
pub struct Totals {
    pub finalized: u64,
    pub filtered: u64,
    pub dropped: u64,
    pub errors: u64,
}

impl Stats {
    pub fn new(context: impl RuntimeMetrics) -> Self {
        Self {
            metrics: Metrics::init(&context),
        }
    }

    pub fn totals(&self) -> Totals {
        Totals {
            finalized: self.metrics.finalized_transactions.get(),
            filtered: self.metrics.filtered_transactions.get(),
            dropped: self.metrics.dropped_transactions.get(),
            errors: self.metrics.submit_errors.get(),
        }
    }

    fn record_submitted(&self, count: u64) {
        self.metrics.submitted_batches.inc();
        self.metrics.submitted_transactions.inc_by(count);
    }

    fn record_finalized(&self, count: u64) {
        self.metrics.finalized_transactions.inc_by(count);
    }

    fn record_filtered(&self, count: u64) {
        self.metrics.filtered_transactions.inc_by(count);
    }

    fn record_dropped(&self, count: u64) {
        self.metrics.dropped_transactions.inc_by(count);
    }

    fn record_error(&self) {
        self.metrics.submit_errors.inc();
    }
}

const INITIAL_SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(500);
const MAX_SUBMIT_ERROR_BACKOFF: Duration = Duration::from_secs(5);

/// Submits batches through a relayer and records each batch outcome.
pub struct RelayerSubmitter {
    url: String,
    http: reqwest::Client,
    stats: Arc<Stats>,
    target_leader: Option<String>,
}

impl RelayerSubmitter {
    pub fn new(url: String, stats: Arc<Stats>, target_leader: Option<String>) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            stats,
            target_leader,
        }
    }

    /// Submits one signed batch until its final outcome is known.
    pub async fn submit(&self, batch: Vec<Tx>) {
        let count = batch.len() as u64;
        let body = batch.encode();
        self.stats.record_submitted(count);

        let mut failures = 0;
        loop {
            match self.submit_encoded(body.clone()).await {
                Ok(TxStatus::Finalized { height }) => {
                    self.stats.record_finalized(count);
                    debug!(height, count, "relayed batch finalized");
                    return;
                }
                Ok(TxStatus::PartiallyFinalized {
                    height,
                    included,
                    filtered,
                }) => {
                    self.stats.record_finalized(included);
                    self.stats.record_filtered(filtered);
                    info!(
                        height,
                        included, filtered, "relayed batch partially finalized, advancing"
                    );
                    return;
                }
                Ok(TxStatus::Dropped) => {
                    self.stats.record_dropped(count);
                    debug!(count, "relayed batch dropped, advancing");
                    return;
                }
                Err(error) if is_deterministic(&error) => {
                    self.stats.record_error();
                    warn!(error = %error, "relayer rejected batch, advancing");
                    return;
                }
                Err(error) => {
                    self.stats.record_error();
                    failures += 1;
                    let backoff = retry_backoff(failures);
                    warn!(
                        error = %error,
                        backoff_ms = backoff.as_millis(),
                        "relayer submit error, retrying same batch"
                    );
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    async fn submit_encoded(&self, body: bytes::Bytes) -> Result<TxStatus, SubmitError> {
        let mut request = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream");
        if let Some(target_leader) = &self.target_leader {
            request = request.header("x-constantinople-relayer-target-leader", target_leader);
        }
        let response = request.body(body).send().await?;

        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)
            }
            400 => Err(SubmitError::BadRequest),
            413 => Err(SubmitError::PayloadTooLarge),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
    }
}

const fn is_deterministic(error: &SubmitError) -> bool {
    matches!(
        error,
        SubmitError::BadRequest | SubmitError::PayloadTooLarge
    )
}

fn retry_backoff(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(6);
    let base = INITIAL_SUBMIT_ERROR_BACKOFF
        .saturating_mul(1 << exponent)
        .min(MAX_SUBMIT_ERROR_BACKOFF);
    let mut rng = UnwrapErr(SysRng);
    let jitter_percent = rng.random_range(75..=125);
    base.mul_f64(f64::from(jitter_percent) / 100.0)
}

#[cfg(test)]
mod tests {
    use super::{RelayerSubmitter, Stats};
    use crate::{
        accounts::generate_accounts,
        signer::{Tx, sign_batch},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Metrics as RuntimeMetrics, Name, Supervisor,
        telemetry::metrics::{Metric, Registered, Registration},
    };
    use std::{
        num::NonZeroU64,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn finalized_batch_advances_without_retrying() {
        let stats = test_stats();
        let response = json_response(r#"{"status":"finalized","height":7}"#);
        let (url, requests) = spawn_response_server(vec![response]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), Some("aa".to_string()));
        let batch = test_batch();
        let count = batch.len() as u64;

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(batch))
            .await
            .expect("finalized batch should complete");

        assert_eq!(stats.totals().finalized, count);
        assert_eq!(stats.totals().errors, 0);
        assert_eq!(requests.lock().expect("requests lock").len(), 1);
    }

    #[tokio::test]
    async fn transient_error_retries_same_batch() {
        let stats = test_stats();
        let finalized = json_response(r#"{"status":"finalized","height":7}"#);
        let (url, requests) =
            spawn_response_server(vec![empty_response("503 Service Unavailable"), finalized]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), Some("aa".to_string()));
        let count = test_batch().len() as u64;

        tokio::time::timeout(Duration::from_secs(2), submitter.submit(test_batch()))
            .await
            .expect("transient error should be retried");

        assert_eq!(stats.totals().errors, 1);
        assert_eq!(stats.totals().finalized, count);
        let requests = requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
    }

    #[tokio::test]
    async fn deterministic_error_advances_without_retrying() {
        let stats = test_stats();
        let (url, requests) = spawn_response_server(vec![empty_response("400 Bad Request")]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), Some("aa".to_string()));

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(test_batch()))
            .await
            .expect("deterministic error should complete");

        let totals = stats.totals();
        assert_eq!(totals.finalized, 0);
        assert_eq!(totals.errors, 1);
        assert_eq!(requests.lock().expect("requests lock").len(), 1);
    }

    #[tokio::test]
    async fn partial_finalization_records_each_outcome() {
        let stats = test_stats();
        let response = json_response(
            r#"{"status":"partially_finalized","height":7,"included":3,"filtered":1}"#,
        );
        let (url, requests) = spawn_response_server(vec![response]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), Some("aa".to_string()));

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(test_batch()))
            .await
            .expect("partial finalization should complete");

        let totals = stats.totals();
        assert_eq!(totals.finalized, 3);
        assert_eq!(totals.filtered, 1);
        assert_eq!(totals.dropped, 0);
        assert_eq!(requests.lock().expect("requests lock").len(), 1);
    }

    #[tokio::test]
    async fn dropped_batch_advances_without_retrying() {
        let stats = test_stats();
        let response = json_response(r#"{"status":"dropped"}"#);
        let (url, requests) = spawn_response_server(vec![response]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), Some("aa".to_string()));
        let count = test_batch().len() as u64;

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(test_batch()))
            .await
            .expect("dropped batch should complete");

        assert_eq!(stats.totals().dropped, count);
        assert_eq!(requests.lock().expect("requests lock").len(), 1);
    }

    #[derive(Clone, Default)]
    struct TestMetrics;

    impl Supervisor for TestMetrics {
        fn name(&self) -> Name {
            Name::default()
        }

        fn child(&self, _label: &'static str) -> Self {
            Self
        }

        fn with_attribute(self, _key: &'static str, _value: impl std::fmt::Display) -> Self {
            self
        }
    }

    impl RuntimeMetrics for TestMetrics {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            _name: N,
            _help: H,
            metric: M,
        ) -> Registered<M> {
            Registered::with_registration(metric, Registration::from(()))
        }

        fn encode(&self) -> String {
            String::new()
        }
    }

    fn test_stats() -> Arc<Stats> {
        Arc::new(Stats::new(TestMetrics))
    }

    fn test_batch() -> Vec<Tx> {
        let accounts = generate_accounts(4, 10_000);
        let value = NonZeroU64::new(1).expect("test value is non-zero");
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 4)
    }

    async fn spawn_response_server(responses: Vec<String>) -> (String, Arc<Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test server should bind");
        let addr = listener.local_addr().expect("test server has local addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();

        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("test server should accept request");
                let body = read_request_body(&mut stream).await;
                captured.lock().expect("requests lock").push(body);
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("test server should write response");
            }
        });

        (format!("http://{addr}"), requests)
    }

    async fn read_request_body(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("test server should read request");
            if read == 0 {
                panic!("request ended before headers completed");
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let headers =
            std::str::from_utf8(&request[..header_end]).expect("request headers are utf8");
        let content_length = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            .expect("request has content length");
        let request_end = header_end + content_length;
        while request.len() < request_end {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("test server should read request body");
            assert!(read > 0, "request ended before body completed");
            request.extend_from_slice(&buffer[..read]);
        }
        request[header_end..request_end].to_vec()
    }

    fn json_response(body: &str) -> String {
        response("200 OK", "application/json", body)
    }

    fn empty_response(status: &str) -> String {
        response(status, "text/plain", "")
    }

    fn response(status: &str, content_type: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }
}
