//! Inclusion evidence the relayer attaches to the finalization reports it forwards.

use commonware_consensus::types::Height;
use commonware_cryptography::{
    bls12381::primitives::variant::MinSig,
    sha256::{Digest, Sha256},
};
use commonware_cryptography_curve25519::signing::VerifyingKey;
use commonware_runtime::{
    Metrics,
    telemetry::metrics::{Counter, Histogram, MetricsExt as _},
};
use constantinople_application::consensus::FinalizedTransactionsHookFn;
use constantinople_engine::types::{EngineBlock, EngineCommitment, FinalizationReader};
use constantinople_indexer::explorer::{Absence, RecentFinalized};
use futures::future::{BoxFuture, FutureExt};
use std::{
    sync::{Arc, OnceLock},
    time::Instant,
};

/// Buckets for the time a request for evidence takes, up to its bound.
const DURATION_BUCKETS: [f64; 10] = [
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.125, 0.15,
];

/// Proves that a block this node finalized includes a transaction.
pub(crate) trait InclusionProver: Send + Sync + 'static {
    /// Returns the encoded transaction bundle for `digest` in the block finalized at
    /// `height`, or `None` when this node cannot provide it in time.
    fn prove(&self, height: u64, digest: Digest) -> BoxFuture<'_, Option<Vec<u8>>>;
}

/// How requests for evidence ended, one counter per outcome, and how long they took.
struct Outcomes {
    attached: Counter,
    late: Counter,
    no_certificate: Counter,
    parent_missing: Counter,
    too_large: Counter,
    not_found: Counter,
    duration: Histogram,
}

impl Outcomes {
    fn new(context: &impl Metrics) -> Self {
        Self {
            attached: context.counter("attached", "Finalization reports that carried evidence"),
            late: context.counter(
                "late",
                "Evidence omitted because this node finalized or proved the block too late",
            ),
            no_certificate: context.counter(
                "no_certificate",
                "Evidence omitted because this node holds no certificate for the block's height",
            ),
            parent_missing: context.counter(
                "parent_missing",
                "Evidence omitted because the preceding block is not retained",
            ),
            too_large: context.counter(
                "too_large",
                "Evidence omitted because the bundle exceeds the report bound",
            ),
            not_found: context.counter(
                "not_found",
                "Evidence omitted because no retained block holds the transaction at that height",
            ),
            duration: context.histogram(
                "duration",
                "Time a finalization report waited for its evidence (s)",
                DURATION_BUCKETS,
            ),
        }
    }
}

/// The blocks this node finalized recently and the certificates marshal stores for them.
pub(crate) struct Evidence {
    recent: RecentFinalized,
    /// Marshal's finalization certificates, installed once the engine exists.
    finalizations: OnceLock<FinalizationReader<Sha256, VerifyingKey, MinSig>>,
    outcomes: Outcomes,
}

impl Evidence {
    pub(crate) fn new(context: &impl Metrics) -> Arc<Self> {
        Arc::new(Self {
            recent: RecentFinalized::default(),
            finalizations: OnceLock::new(),
            outcomes: Outcomes::new(context),
        })
    }

    /// Returns the hook that records each finalized block with the range it appended.
    pub(crate) fn hook(
        self: &Arc<Self>,
    ) -> FinalizedTransactionsHookFn<EngineCommitment<Sha256, VerifyingKey>, Sha256, VerifyingKey>
    {
        let evidence = self.clone();
        Arc::new(move |block, transactions| {
            evidence
                .recent
                .record(EngineBlock::from(block), transactions);
        })
    }

    /// Installs the reader for marshal's finalization certificates.
    pub(crate) fn attach(&self, finalizations: FinalizationReader<Sha256, VerifyingKey, MinSig>) {
        assert!(
            self.finalizations.set(finalizations).is_ok(),
            "finalization reader must be installed exactly once"
        );
    }
}

impl InclusionProver for Evidence {
    fn prove(&self, height: u64, digest: Digest) -> BoxFuture<'_, Option<Vec<u8>>> {
        async move {
            let started = Instant::now();
            let finalization = async { self.finalizations.get()?.get(Height::new(height)).await };
            let evidence = self.recent.prove(height, digest, finalization).await;
            self.outcomes
                .duration
                .observe(started.elapsed().as_secs_f64());
            let outcome = match &evidence {
                Ok(_) => &self.outcomes.attached,
                Err(Absence::Late) => &self.outcomes.late,
                Err(Absence::NoCertificate) => &self.outcomes.no_certificate,
                Err(Absence::ParentMissing) => &self.outcomes.parent_missing,
                Err(Absence::TooLarge) => &self.outcomes.too_large,
                Err(Absence::NotFound) => &self.outcomes.not_found,
            };
            outcome.inc();
            evidence.ok()
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, Supervisor as _, telemetry::metrics::has_metric_value};

    #[test]
    fn a_request_this_node_cannot_answer_in_time_is_counted_as_late() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let evidence = Evidence::new(&context.child("evidence"));

            // No block is recorded, so the request waits out its bound.
            assert_eq!(evidence.prove(7, Digest::from([1; 32])).await, None);
            let metrics = context.encode();
            assert!(
                has_metric_value(&metrics, "evidence_late_total", 1),
                "{metrics}"
            );
            for other in [
                "attached",
                "no_certificate",
                "parent_missing",
                "too_large",
                "not_found",
            ] {
                assert!(
                    has_metric_value(&metrics, &format!("evidence_{other}_total"), 0),
                    "{metrics}"
                );
            }
        });
    }
}
