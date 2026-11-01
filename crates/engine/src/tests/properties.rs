use crate::tests::common::{RestartBarrier, TestPublicKey, ValidatorState};
use commonware_cryptography::PublicKey;
use commonware_glue::simulate::{
    exit::ExitCondition, property::Property, tracker::ProgressTracker,
};
use commonware_runtime::Metrics as _;
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy)]
pub(crate) struct BlockAgreementAtHeight {
    height: u64,
    minimum_count: Option<usize>,
}

impl BlockAgreementAtHeight {
    pub(crate) const fn new(height: u64) -> Self {
        Self {
            height,
            minimum_count: None,
        }
    }

    pub(crate) const fn at_least(height: u64, minimum_count: usize) -> Self {
        Self {
            height,
            minimum_count: Some(minimum_count),
        }
    }
}

impl Property<crate::tests::common::TestPublicKey, ValidatorState> for BlockAgreementAtHeight {
    fn name(&self) -> &str {
        "block_agreement_at_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<crate::tests::common::TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut expected = None;
            let mut present = 0usize;
            for state in states {
                let Some(digest) = state.digest_at_height(self.height).await else {
                    if self.minimum_count.is_some() {
                        continue;
                    }

                    return Err(format!(
                        "missing finalized digest at height {} on at least one validator",
                        self.height
                    ));
                };
                present += 1;

                if let Some(previous) = expected.as_ref() {
                    if previous != &digest {
                        return Err(format!(
                            "digest disagreement at finalized height {}",
                            self.height
                        ));
                    }
                    continue;
                }

                expected = Some(digest);
            }

            if let Some(minimum_count) = self.minimum_count
                && present < minimum_count
            {
                return Err(format!(
                    "only {present} validators observed finalized height {}, expected at least {minimum_count}",
                    self.height
                ));
            }

            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FinalizedHeightAtLeast {
    height: u64,
}

#[derive(Clone)]
pub(crate) struct RestartRecoveryComplete {
    barrier: RestartBarrier,
}

impl RestartRecoveryComplete {
    pub(crate) const fn new(barrier: RestartBarrier) -> Self {
        Self { barrier }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for RestartRecoveryComplete {
    fn name(&self) -> &str {
        "restart_recovery_complete"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let recovered_finalized = self.barrier.recovered_finalized();
            if recovered_finalized == 0 || self.barrier.observed_processed().is_none() {
                return Ok(false);
            }

            let mut recovered = 0;
            for state in states {
                if state.processed_height().await >= recovered_finalized {
                    recovered += 1;
                }
            }

            Ok(recovered >= target_count)
        })
    }
}

#[derive(Clone)]
pub(crate) struct RestartPreservesProcessedHeight {
    barrier: RestartBarrier,
}

impl RestartPreservesProcessedHeight {
    pub(crate) const fn new(barrier: RestartBarrier) -> Self {
        Self { barrier }
    }
}

impl Property<crate::tests::common::TestPublicKey, ValidatorState>
    for RestartPreservesProcessedHeight
{
    fn name(&self) -> &str {
        "restart_preserves_processed_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<crate::tests::common::TestPublicKey>,
        _states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let recovered_finalized = self.barrier.recovered_finalized();
            let expected_processed = self.barrier.processed_height();
            if recovered_finalized <= expected_processed + 1 {
                return Err(format!(
                    "restart recovered finalization {recovered_finalized}, expected a height above the held processed floor"
                ));
            }

            let observed_processed = self
                .barrier
                .observed_processed()
                .ok_or_else(|| "restart processed height was not observed".to_string())?;
            if observed_processed != expected_processed {
                return Err(format!(
                    "restart moved processed height from {expected_processed} to {observed_processed} before acknowledgement. Recovered finalization was {recovered_finalized}"
                ));
            }

            Ok(())
        })
    }
}

impl FinalizedHeightAtLeast {
    pub(crate) const fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for FinalizedHeightAtLeast {
    fn name(&self) -> &str {
        "finalized_height_at_least"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut reached = 0usize;
            for state in states {
                if state.digest_at_height(self.height).await.is_some() {
                    reached += 1;
                }
            }

            Ok(reached >= target_count)
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct StateSyncReadyAtHeight {
    height: u64,
}

impl StateSyncReadyAtHeight {
    pub(crate) const fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for StateSyncReadyAtHeight {
    fn name(&self) -> &str {
        "state_sync_ready_at_height"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            // The simulator evaluates this condition after every finalization
            // update and handles crash and schedule events only while no update
            // is pending. A block at the target height needs a view at least as
            // high, so until some validator finalizes one, answer without
            // querying validators, whose replies would hold that loop and could
            // keep fault events from ever running.
            if tracker.max_round().map_or(0, |round| round.view().get()) < self.height {
                return Ok(false);
            }

            let mut finalized = 0usize;
            let mut handoff = false;

            for state in states {
                if state.digest_at_height(self.height).await.is_some() {
                    finalized += 1;
                }

                let Some(sync_height) = state.startup_sync_height else {
                    continue;
                };
                if state.processed_height().await > sync_height {
                    handoff = true;
                }
            }

            Ok(finalized >= target_count.saturating_sub(1) && handoff)
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LateJoinerStateSyncHandoff;

impl Property<crate::tests::common::TestPublicKey, ValidatorState> for LateJoinerStateSyncHandoff {
    fn name(&self) -> &str {
        "late_joiner_state_sync_handoff"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<crate::tests::common::TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let Some(sync_height) = state.startup_sync_height else {
                    continue;
                };

                if state.processed_height().await > sync_height {
                    return Ok(());
                }
            }

            Err(
                "no validator both used startup state sync and advanced beyond the synced height"
                    .to_string(),
            )
        })
    }
}

/// Requires some incoming leader to have relayed its prepared term-start
/// proposal before the parent certified, and no leader to have voted for one
/// before then.
#[derive(Clone, Copy)]
pub(crate) struct PipelinedHandoffs;

impl Property<TestPublicKey, ValidatorState> for PipelinedHandoffs {
    fn name(&self) -> &str {
        "pipelined_handoffs"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let state = states
                .first()
                .ok_or_else(|| "no active validator".to_string())?;
            let metrics = state.context.encode();
            let handoff_events = |event: &str| -> u64 {
                let label = format!("event=\"{event}\"");
                metrics
                    .lines()
                    .filter(|line| line.contains("_handoff_events_total{") && line.contains(&label))
                    .filter_map(|line| line.rsplit(' ').next()?.parse::<u64>().ok())
                    .sum()
            };
            if handoff_events("RelayedBeforeCertification") == 0 {
                return Err(
                    "no leader relayed a prepared proposal before its parent certified".to_string(),
                );
            }
            let early_votes = handoff_events("VotedBeforeCertification");
            if early_votes > 0 {
                return Err(format!(
                    "{early_votes} prepared proposals were voted on before their parents certified"
                ));
            }

            Ok(())
        })
    }
}
