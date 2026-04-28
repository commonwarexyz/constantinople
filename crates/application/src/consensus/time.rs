//! Consensus timestamp policy.

use commonware_runtime::Clock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Returns the current Unix timestamp in milliseconds.
pub(super) fn timestamp_ms(runtime: &impl Clock) -> u64 {
    let timestamp_ms = runtime
        .current()
        .duration_since(UNIX_EPOCH)
        .expect("clock moved before unix epoch")
        .as_millis();
    u64::try_from(timestamp_ms).expect("timestamp milliseconds exceeded u64")
}

/// Returns whether a child timestamp is valid for its parent.
pub(super) const fn is_valid_child_timestamp(
    parent_timestamp_ms: u64,
    child_timestamp_ms: u64,
) -> bool {
    parent_timestamp_ms < child_timestamp_ms && child_timestamp_ms <= MAX_BLOCK_TIMESTAMP_MS
}

/// Returns the absolute wakeup time for `block_timestamp_ms`.
///
/// # Panics
///
/// Panics if `block_timestamp_ms` cannot be represented as a [`SystemTime`]
/// offset from the Unix epoch.
pub(super) fn block_deadline(block_timestamp_ms: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_millis(block_timestamp_ms))
        .expect("block timestamp exceeded maximum")
}
