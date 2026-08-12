//! Operational proposal pacing.

use commonware_runtime::Clock;
use futures::lock::Mutex;
use std::{num::NonZeroU64, sync::Arc, time::Duration};

/// Serializes proposal admission across application clones.
///
/// The last start is recorded only after any required wait completes. A
/// cancelled waiter therefore releases the mutex without reserving a proposal
/// slot that no caller will use.
#[derive(Clone)]
pub(super) struct ProposalPacer {
    interval: Duration,
    last_start: Arc<Mutex<Option<std::time::SystemTime>>>,
}

impl ProposalPacer {
    pub(super) fn new(interval_ms: NonZeroU64) -> Self {
        Self {
            interval: Duration::from_millis(interval_ms.get()),
            last_start: Arc::new(Mutex::new(None)),
        }
    }

    /// Waits until a proposal may begin and records its actual admission time.
    pub(super) async fn admit(&self, runtime: &impl Clock) {
        let mut last_start = self.last_start.lock().await;
        if let Some(last_start) = *last_start {
            let deadline = last_start
                .checked_add(self.interval)
                .expect("proposal pacing deadline overflowed");
            if runtime.current() < deadline {
                runtime.sleep_until(deadline).await;
            }
        }
        *last_start = Some(runtime.current());
    }
}
