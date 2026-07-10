//! Publisher components for finalized index uploads.
//!
//! The production validator path uses [`Publisher`] on the single owning
//! secondary. It stages finalized-block data into one combined upload path:
//!
//! | Path             | Families / tables                                            |
//! | ---------------- | ------------------------------------------------------------ |
//! | `simplex`        | certified headers, full blocks by digest, certificates       |
//! | `sql` (metadata) | `block_meta`, `tx_meta`, `tx_activity`, `account_meta`       |
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
use exoware_sdk::{StoreClient, StoreWriteBatch};
pub use qmdb::Publisher;
pub use sql::SqlRow;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;

/// Commits `batch` through the physical Store client, retrying with capped
/// exponential backoff until it lands. Rows are namespace-encoded when they
/// are staged, so the commit is a raw write.
pub(crate) async fn commit_with_retry(
    client: &StoreClient,
    batch: &StoreWriteBatch,
    what: &'static str,
) -> u64 {
    let mut attempt = 0u32;
    loop {
        match batch.commit(client).await {
            Ok(seq) => return seq,
            Err(error) => {
                attempt = attempt.saturating_add(1);
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
    }
}

fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}
