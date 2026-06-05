//! Async submission engine.
//!
//! Each relayer stream submits one batch at a time and advances to the next
//! pre-signed batch after finalization, drop, or submit failure.

use crate::signer::Tx;
use commonware_codec::Encode;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::{debug, info, warn};

/// Shared counters for progress reporting.
pub struct Stats {
    pub finalized: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            finalized: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

const SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Submits batches through a relayer and records each batch outcome.
pub struct RelayerSubmitter {
    url: String,
    http: reqwest::Client,
    stats: Arc<Stats>,
    target_leader: Option<String>,
    leader_fanout: usize,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RelayerBatchStatus {
    Finalized {
        height: u64,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped,
}

impl RelayerSubmitter {
    pub fn new(
        url: String,
        stats: Arc<Stats>,
        _target_offset: usize,
        target_leader: Option<String>,
    ) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            stats,
            target_leader,
            leader_fanout: 1,
        }
    }

    /// Submits a signed batch once. Failed or dropped batches are abandoned so
    /// the next outer loop iteration uses a fresh nonce set.
    pub async fn submit(&self, batch: Vec<Tx>) {
        let count = batch.len() as u64;
        let body = batch.encode();
        match self.submit_encoded(body).await {
            Ok(RelayerBatchStatus::Finalized { height }) => {
                self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                debug!(height, count, "relayed batch finalized");
            }
            Ok(RelayerBatchStatus::PartiallyFinalized {
                height,
                included,
                filtered,
            }) => {
                self.stats
                    .finalized
                    .fetch_add(included.len() as u64, Ordering::Relaxed);
                self.stats
                    .filtered
                    .fetch_add(filtered.len() as u64, Ordering::Relaxed);
                info!(
                    height,
                    included = included.len(),
                    filtered = filtered.len(),
                    "relayed batch partially finalized, advancing"
                );
            }
            Ok(RelayerBatchStatus::Dropped) => {
                self.stats.dropped.fetch_add(count, Ordering::Relaxed);
                debug!(count, "relayed batch dropped, advancing");
            }
            Err(error) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                warn!(
                    error = %error,
                    backoff_ms = SUBMIT_ERROR_BACKOFF.as_millis(),
                    "relayer submit error, advancing"
                );
                tokio::time::sleep(SUBMIT_ERROR_BACKOFF).await;
            }
        }
    }

    async fn submit_encoded(
        &self,
        body: bytes::Bytes,
    ) -> Result<RelayerBatchStatus, constantinople_mempool::webserver::client::SubmitError> {
        use constantinople_mempool::webserver::client::SubmitError;

        let mut request = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream")
            .header(
                "x-constantinople-relayer-leader-fanout",
                self.leader_fanout.to_string(),
            );
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

#[cfg(test)]
mod tests {
    use super::{RelayerSubmitter, Stats};
    use crate::{
        accounts::generate_accounts,
        signer::{Tx, sign_batch},
    };
    use commonware_parallel::Sequential;
    use std::{
        num::NonZeroU64,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn dropped_batch_advances_without_retrying() {
        let stats = Arc::new(Stats::new());
        let (url, requests) =
            spawn_response_server(vec![json_response(r#"{"status":"dropped"}"#)]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), 0, None);
        let batch = test_batch();
        let count = batch.len() as u64;

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(batch))
            .await
            .expect("dropped batch should not be retried");

        assert_eq!(stats.dropped.load(Ordering::Relaxed), count);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn submit_error_advances_without_retrying() {
        let stats = Arc::new(Stats::new());
        let (url, requests) =
            spawn_response_server(vec![empty_response("503 Service Unavailable")]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), 0, None);

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(test_batch()))
            .await
            .expect("submit error should not be retried");

        assert_eq!(stats.errors.load(Ordering::Relaxed), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn partially_finalized_batch_does_not_resubmit_filtered_transactions() {
        let stats = Arc::new(Stats::new());
        let batch = test_batch();
        let included = batch[0].message_digest().to_string();
        let filtered = batch[1].message_digest().to_string();
        let body = format!(
            r#"{{"status":"partially_finalized","height":7,"included":["{included}"],"filtered":["{filtered}"]}}"#
        );
        let (url, requests) = spawn_response_server(vec![json_response(&body)]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), 0, None);

        tokio::time::timeout(Duration::from_secs(1), submitter.submit(batch))
            .await
            .expect("filtered transactions should not be retried");

        assert_eq!(stats.finalized.load(Ordering::Relaxed), 1);
        assert_eq!(stats.filtered.load(Ordering::Relaxed), 1);
        assert_eq!(requests.load(Ordering::Relaxed), 1);
    }

    fn test_batch() -> Vec<Tx> {
        let accounts = generate_accounts(4, 10_000);
        let value = NonZeroU64::new(1).expect("test value is non-zero");
        let mut nonces = vec![0; accounts.len()];
        let mut cursor = 0;
        sign_batch(&Sequential, &accounts, value, &mut nonces, &mut cursor, 4)
    }

    async fn spawn_response_server(responses: Vec<String>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test server should bind");
        let addr = listener.local_addr().expect("test server has local addr");
        let requests = Arc::new(AtomicUsize::new(0));
        let request_count = requests.clone();

        tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("test server should accept request");
                request_count.fetch_add(1, Ordering::Relaxed);
                read_headers(&mut stream).await;
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("test server should write response");
            }
        });

        (format!("http://{addr}"), requests)
    }

    async fn read_headers(stream: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let read = stream
                .read(&mut buffer)
                .await
                .expect("test server should read request");
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return;
            }
        }
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
