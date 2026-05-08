//! Consensus tracing helpers.

use tracing::warn;

pub(super) fn reject_verify(height: u64, reason: &'static str) {
    warn!(height, reason, "application.verify.reject");
}
