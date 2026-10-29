//! Consensus timestamp policy.

use commonware_runtime::Clock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Returns the timestamp for a child of a block stamped `parent_timestamp_ms`.
///
/// The child takes the current Unix time in milliseconds, or the parent's
/// timestamp while the local clock is behind it: a term-start proposal can
/// build on a parent stamped ahead of the local clock, before verification of
/// that parent has waited for its timestamp.
pub(super) fn child_timestamp_ms(runtime: &impl Clock, parent_timestamp_ms: u64) -> u64 {
    let timestamp_ms = runtime
        .current()
        .duration_since(UNIX_EPOCH)
        .expect("clock moved before unix epoch")
        .as_millis();
    u64::try_from(timestamp_ms)
        .expect("timestamp milliseconds exceeded u64")
        .max(parent_timestamp_ms)
}

/// Returns whether a child timestamp is valid for its parent.
///
/// A child may share its parent's timestamp but not precede it.
pub(super) const fn is_valid_child_timestamp(
    parent_timestamp_ms: u64,
    child_timestamp_ms: u64,
) -> bool {
    parent_timestamp_ms <= child_timestamp_ms && child_timestamp_ms <= MAX_BLOCK_TIMESTAMP_MS
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

#[cfg(test)]
mod tests {
    use super::{MAX_BLOCK_TIMESTAMP_MS, is_valid_child_timestamp};

    #[test]
    fn child_timestamp_validity_bounds() {
        assert!(is_valid_child_timestamp(10, 10));
        assert!(is_valid_child_timestamp(10, 11));
        assert!(!is_valid_child_timestamp(10, 9));
        assert!(is_valid_child_timestamp(10, MAX_BLOCK_TIMESTAMP_MS));
        assert!(!is_valid_child_timestamp(10, MAX_BLOCK_TIMESTAMP_MS + 1));
    }
}
