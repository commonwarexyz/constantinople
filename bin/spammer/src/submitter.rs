//! Async submission engine.
//!
//! Each relayer stream submits one batch at a time and advances to the next
//! pre-signed batch after finalization, drop, or submit failure.

use crate::signer::Tx;
use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::sha256::Digest;
use commonware_formatting::from_hex;
use constantinople_mempool::webserver::client::SubmitError;
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::{debug, error, info, warn};

/// Shared counters for progress reporting.
pub struct Stats {
    pub finalized: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped: AtomicU64,
    pub errors: AtomicU64,
    /// On-chain channel transactions finalized (opens + closes).
    pub channel_txs: AtomicU64,
    /// Off-chain vouchers streamed and verified — the per-payment count that
    /// never touches the chain.
    pub vouchers: AtomicU64,
    /// Latest finalized height observed across every submission (transfers
    /// included). Channel expiry selection reads this, so it must stay fresh
    /// even when channel lifecycles are rare — an expiry computed from a stale
    /// height lands inside (or behind) the operator's registration runway and
    /// the lifecycle degrades to a timeout reclaim.
    pub height: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            finalized: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            channel_txs: AtomicU64::new(0),
            vouchers: AtomicU64::new(0),
            height: AtomicU64::new(0),
        }
    }
}

const SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Consecutive chain-judged no-progress submissions tolerated per warm-up
/// batch.
const WARM_UP_STALLED_ATTEMPTS: usize = 10;
#[cfg(not(test))]
const WARM_UP_BACKOFF: Duration = Duration::from_millis(500);
#[cfg(test)]
const WARM_UP_BACKOFF: Duration = Duration::from_millis(10);

/// Submits batches through a relayer and records each batch outcome.
/// Cloning shares the HTTP client and stats, so concurrent channel
/// lifecycles submit through the same connection pool.
#[derive(Clone)]
pub struct RelayerSubmitter {
    url: String,
    http: reqwest::Client,
    stats: Arc<Stats>,
    target_leader: Option<String>,
    leader_fanout: usize,
}

/// What the relayer reported for a submitted batch.
pub struct SubmitReport {
    /// Transactions the relayer reported finalized.
    pub finalized: u64,
    /// The finalization height, present only when the chain judged the batch.
    /// `None` (dropped batch or transport error) proves nothing about the
    /// transactions: they may still land.
    pub height: Option<u64>,
}

/// A submitted batch's judged outcome, after stats accounting.
enum BatchOutcome {
    /// Every transaction finalized.
    Finalized { height: u64 },
    /// The chain judged the batch and included only these (hex) digests.
    Partial { height: u64, included: Vec<String> },
    /// Nothing was judged (dropped batch or transport error).
    Unjudged,
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
        let _ = self.submit_reporting_with_height(batch).await;
    }

    /// Like [`Self::submit`], but returns what the relayer reported. Channel
    /// lifecycles use the count to gate a close on its open finalizing and
    /// the height to track the chain for expiry selection.
    pub async fn submit_reporting_with_height(&self, batch: Vec<Tx>) -> SubmitReport {
        match self.submit_accounted(&batch).await {
            BatchOutcome::Finalized { height } => SubmitReport {
                finalized: batch.len() as u64,
                height: Some(height),
            },
            BatchOutcome::Partial { height, included } => SubmitReport {
                finalized: included.len() as u64,
                height: Some(height),
            },
            BatchOutcome::Unjudged => SubmitReport {
                finalized: 0,
                height: None,
            },
        }
    }

    /// Like [`Self::submit`], but returns the transactions the relayer did not
    /// report as included (empty when the whole batch finalized) plus the
    /// finalization height (if any). Dropped batches and submit errors return
    /// the full batch. Only the warm-up path pays for identifying the missing
    /// transactions; other callers use the counting variants above.
    async fn submit_returning_missing(&self, mut batch: Vec<Tx>) -> (Vec<Tx>, Option<u64>) {
        match self.submit_accounted(&batch).await {
            BatchOutcome::Finalized { height } => (Vec::new(), Some(height)),
            BatchOutcome::Partial { height, included } => {
                // Parse the (smaller) included list into digests instead of
                // stringifying every batch transaction; an unparsable digest
                // just leaves its transaction in the missing set.
                let included: HashSet<Digest> = included
                    .iter()
                    .filter_map(|digest| Digest::decode(from_hex(digest)?.as_slice()).ok())
                    .collect();
                batch.retain(|tx| !included.contains(tx.message_digest()));
                (batch, Some(height))
            }
            BatchOutcome::Unjudged => (batch, None),
        }
    }

    /// Submits `batch` once and folds the outcome into the shared stats.
    async fn submit_accounted(&self, batch: &[Tx]) -> BatchOutcome {
        let count = batch.len() as u64;
        let body = batch.encode();
        match self.submit_encoded(body).await {
            Ok(RelayerBatchStatus::Finalized { height }) => {
                self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                self.stats.height.fetch_max(height, Ordering::Relaxed);
                debug!(height, count, "relayed batch finalized");
                BatchOutcome::Finalized { height }
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
                self.stats.height.fetch_max(height, Ordering::Relaxed);
                info!(
                    height,
                    included = included.len(),
                    filtered = filtered.len(),
                    "relayed batch partially finalized, advancing"
                );
                BatchOutcome::Partial { height, included }
            }
            Ok(RelayerBatchStatus::Dropped) => {
                self.stats.dropped.fetch_add(count, Ordering::Relaxed);
                debug!(count, "relayed batch dropped, advancing");
                BatchOutcome::Unjudged
            }
            Err(error) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                warn!(
                    error = %error,
                    backoff_ms = SUBMIT_ERROR_BACKOFF.as_millis(),
                    "relayer submit error, advancing"
                );
                tokio::time::sleep(SUBMIT_ERROR_BACKOFF).await;
                BatchOutcome::Unjudged
            }
        }
    }

    /// Lands a ring's warm-up mint batches, resubmitting only the mints the
    /// relayer did not report as included. A partially finalized batch must
    /// not strand its remainder: an unfunded account poisons every later
    /// batch it appears in, silently deflating the run's throughput.
    ///
    /// Retries indefinitely while nothing has landed (the chain may still be
    /// coming up), but once funding has started it bounds consecutive
    /// no-progress attempts — a mint whose inclusion acknowledgement was lost
    /// is reported filtered on every resubmission and would otherwise retry
    /// forever.
    pub async fn land_mints(&self, batches: Vec<Vec<Tx>>) {
        for batch in batches {
            let mut pending = batch;
            let mut stalled = 0;
            loop {
                let before = pending.len();
                let (missing, height) = self.submit_returning_missing(pending).await;
                pending = missing;
                if pending.is_empty() {
                    break;
                }
                if pending.len() < before {
                    stalled = 0;
                } else if height.is_some() {
                    // The chain judged the batch (a height came back) and
                    // still reported every remaining mint as filtered: their
                    // nonces are already consumed — an earlier ack was lost —
                    // so retrying cannot make progress. Dropped batches and
                    // transport errors return no height and never count: the
                    // chain hasn't judged the mints (still booting, or a
                    // relayer flap), so they retry indefinitely.
                    stalled += 1;
                    if stalled >= WARM_UP_STALLED_ATTEMPTS {
                        error!(
                            missing = pending.len(),
                            "warm-up mints repeatedly filtered across \
                             {WARM_UP_STALLED_ATTEMPTS} attempts; moving on (their nonces are \
                             consumed, so they most likely landed unacknowledged)"
                        );
                        break;
                    }
                }
                warn!(
                    missing = pending.len(),
                    "warm-up mints incomplete, retrying"
                );
                tokio::time::sleep(WARM_UP_BACKOFF).await;
            }
        }
    }

    async fn submit_encoded(&self, body: bytes::Bytes) -> Result<RelayerBatchStatus, SubmitError> {
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

    #[tokio::test]
    async fn land_mints_resubmits_only_missing_transactions() {
        let stats = Arc::new(Stats::new());
        let batch = test_batch();
        let digests: Vec<String> = batch
            .iter()
            .map(|tx| tx.message_digest().to_string())
            .collect();
        // First submission lands half the batch; the retry must carry only
        // the missing half (a full resubmission would double-count the
        // included transactions once the second response finalizes).
        let first = format!(
            r#"{{"status":"partially_finalized","height":3,"included":["{}","{}"],"filtered":["{}","{}"]}}"#,
            digests[0], digests[1], digests[2], digests[3]
        );
        let second = r#"{"status":"finalized","height":4}"#.to_string();
        let (url, requests) =
            spawn_response_server(vec![json_response(&first), json_response(&second)]).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), 0, None);

        tokio::time::timeout(Duration::from_secs(5), submitter.land_mints(vec![batch]))
            .await
            .expect("warm-up should land after one retry");

        assert_eq!(
            stats.finalized.load(Ordering::Relaxed),
            4,
            "every transaction finalized exactly once"
        );
        assert_eq!(stats.filtered.load(Ordering::Relaxed), 2);
        assert_eq!(requests.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn land_mints_gives_up_when_every_mint_is_repeatedly_filtered() {
        let stats = Arc::new(Stats::new());
        let batch = test_batch();
        let filtered: Vec<String> = batch
            .iter()
            .map(|tx| format!("\"{}\"", tx.message_digest()))
            .collect();
        // A lost ack on the very first batch: the mints landed, so every
        // resubmission reports them all filtered (nonces consumed) and no
        // attempt ever shrinks the pending set. The chain judged each attempt,
        // so the stall cap must engage instead of retrying forever.
        let body = format!(
            r#"{{"status":"partially_finalized","height":9,"included":[],"filtered":[{}]}}"#,
            filtered.join(",")
        );
        let responses = vec![json_response(&body); super::WARM_UP_STALLED_ATTEMPTS];
        let (url, requests) = spawn_response_server(responses).await;
        let submitter = RelayerSubmitter::new(url, stats.clone(), 0, None);

        tokio::time::timeout(Duration::from_secs(60), submitter.land_mints(vec![batch]))
            .await
            .expect("repeatedly filtered warm-up must give up, not livelock");

        assert_eq!(
            requests.load(Ordering::Relaxed),
            super::WARM_UP_STALLED_ATTEMPTS
        );
        assert_eq!(stats.finalized.load(Ordering::Relaxed), 0);
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
