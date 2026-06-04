//! Async submission engine with retry logic.
//!
//! Each relayer stream submits one batch at a time and blocks until that batch
//! resolves. Callers may keep later batches pre-signed locally.

use crate::signer::Tx;
use commonware_codec::Encode;
use std::{
    collections::HashSet,
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

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Submits batches through a relayer and waits for each batch to resolve.
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

    /// Submits the batch through the relayer and waits until every transaction
    /// is finalized.
    pub async fn submit_until_finalized(&self, batch: Vec<Tx>) {
        let mut pending = batch;
        let mut backoff = INITIAL_BACKOFF;

        while !pending.is_empty() {
            let body = pending.encode();
            match self.submit_encoded(body.clone()).await {
                Ok(status) => match status {
                    RelayerBatchStatus::Finalized { height } => {
                        let count = pending.len() as u64;
                        self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                        debug!(height, count, "relayed batch finalized");
                        return;
                    }
                    RelayerBatchStatus::PartiallyFinalized {
                        height,
                        included,
                        filtered,
                    } => {
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
                            "relayed batch partially finalized, resubmitting filtered"
                        );
                        pending = extract_filtered(&pending, &filtered);
                        backoff = INITIAL_BACKOFF;
                    }
                    RelayerBatchStatus::Dropped => {
                        self.stats
                            .dropped
                            .fetch_add(pending.len() as u64, Ordering::Relaxed);
                        debug!(
                            pending = pending.len(),
                            "relayed batch dropped, resubmitting"
                        );
                    }
                },
                Err(error) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        error = %error,
                        backoff_ms = backoff.as_millis(),
                        "relayer submit error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
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

/// Keeps only the transactions whose digest appears in `filtered_digests`.
fn extract_filtered(batch: &[Tx], filtered_digests: &[String]) -> Vec<Tx> {
    let filter_set: HashSet<&str> = filtered_digests.iter().map(String::as_str).collect();
    batch
        .iter()
        .filter(|tx| filter_set.contains(tx.message_digest().to_string().as_str()))
        .cloned()
        .collect()
}
