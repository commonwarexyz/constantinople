//! Async submission engine with retry logic.
//!
//! Each validator gets an independent [`ValidatorSubmitter`] that submits one
//! batch at a time and blocks until every transaction in the batch is
//! finalized. This guarantees nonce ordering.

use crate::signer::Tx;
use constantinople_mempool::webserver::{TxStatus, client::Client};
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
    pub retried: AtomicU64,
    pub errors: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            finalized: AtomicU64::new(0),
            filtered: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            retried: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }
}

const MAX_BACKOFF: Duration = Duration::from_secs(30);
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Submits batches to a single validator, one at a time.
pub struct ValidatorSubmitter {
    client: Arc<Client>,
    stats: Arc<Stats>,
    validator_index: usize,
}

impl ValidatorSubmitter {
    pub fn new(client: Client, stats: Arc<Stats>, validator_index: usize) -> Self {
        Self {
            client: Arc::new(client),
            stats,
            validator_index,
        }
    }

    /// Submits the batch and blocks until **every** transaction is finalized.
    ///
    /// On partial finalization, only the filtered transactions are resubmitted.
    /// On drop or error, the entire remaining batch is retried with backoff.
    /// Returns only after all transactions have been finalized.
    pub async fn submit_until_finalized(&self, batch: Vec<Tx>) {
        let mut pending = batch;
        let mut backoff = INITIAL_BACKOFF;

        while !pending.is_empty() {
            match self.client.submit(&pending).await {
                Ok(TxStatus::Finalized { height }) => {
                    let count = pending.len() as u64;
                    self.stats.finalized.fetch_add(count, Ordering::Relaxed);
                    debug!(
                        validator = self.validator_index,
                        height, count, "round finalized"
                    );
                    return;
                }
                Ok(TxStatus::PartiallyFinalized {
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
                        validator = self.validator_index,
                        height,
                        included = included.len(),
                        filtered = filtered.len(),
                        "partially finalized, resubmitting filtered"
                    );
                    pending = extract_filtered(&pending, &filtered);
                    backoff = INITIAL_BACKOFF;
                }
                Ok(TxStatus::Dropped) => {
                    self.stats
                        .dropped
                        .fetch_add(pending.len() as u64, Ordering::Relaxed);
                    debug!(
                        validator = self.validator_index,
                        pending = pending.len(),
                        "batch dropped, resubmitting"
                    );
                    // Resubmit same pending set — nonces are still valid.
                }
                Err(constantinople_mempool::webserver::client::SubmitError::ServiceUnavailable) => {
                    warn!(
                        validator = self.validator_index,
                        backoff_ms = backoff.as_millis(),
                        "pool full, backing off"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(e) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        validator = self.validator_index,
                        error = %e,
                        backoff_ms = backoff.as_millis(),
                        "submit error, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
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
