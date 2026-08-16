use crate::tests::common::{RestartBarrier, ValidatorState};
use commonware_cryptography::PublicKey;
use commonware_glue::simulate::{
    exit::ExitCondition, property::Property, tracker::ProgressTracker,
};
use constantinople_primitives::{Account, AccountKey, DEFAULT_ACCOUNT_BALANCE, Nonce};
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy)]
pub(crate) struct FreshStartupStateReadable;

impl<P: PublicKey> Property<P, ValidatorState> for FreshStartupStateReadable {
    fn name(&self) -> &str {
        "fresh_startup_state_readable"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if states.is_empty() {
                return Err("no validator state was available".to_string());
            }
            if states.iter().any(|state| state.startup_account.is_some()) {
                return Err("fresh zero-suffix startup returned an unexpected account".to_string());
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
enum TransferBoundary {
    Restart,
    StateSync,
}

#[derive(Clone)]
pub(crate) struct CommittedTransferAtBoundary {
    boundary: TransferBoundary,
    target_height: Option<u64>,
    sender: AccountKey,
    recipient: AccountKey,
    value: u64,
    sender_nonce: Nonce,
}

impl CommittedTransferAtBoundary {
    pub(crate) const fn after_restart(
        target_height: u64,
        sender: AccountKey,
        recipient: AccountKey,
        value: u64,
        sender_nonce: Nonce,
    ) -> Self {
        Self {
            boundary: TransferBoundary::Restart,
            target_height: Some(target_height),
            sender,
            recipient,
            value,
            sender_nonce,
        }
    }

    pub(crate) const fn after_archived_restart(
        sender: AccountKey,
        recipient: AccountKey,
        value: u64,
        sender_nonce: Nonce,
    ) -> Self {
        Self {
            boundary: TransferBoundary::Restart,
            target_height: None,
            sender,
            recipient,
            value,
            sender_nonce,
        }
    }

    pub(crate) const fn after_state_sync(
        target_height: u64,
        sender: AccountKey,
        recipient: AccountKey,
        value: u64,
        sender_nonce: Nonce,
    ) -> Self {
        Self {
            boundary: TransferBoundary::StateSync,
            target_height: Some(target_height),
            sender,
            recipient,
            value,
            sender_nonce,
        }
    }

    const fn selects(&self, state: &ValidatorState) -> bool {
        match self.boundary {
            TransferBoundary::Restart => state.restarted,
            TransferBoundary::StateSync => state.startup_sync_height.is_some(),
        }
    }
}

impl<P: PublicKey> Property<P, ValidatorState> for CommittedTransferAtBoundary {
    fn name(&self) -> &str {
        "committed_transfer_at_lifecycle_boundary"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let expected_sender = Account {
                balance: DEFAULT_ACCOUNT_BALANCE - self.value,
                nonce: self.sender_nonce,
            };
            let expected_recipient = Account {
                balance: DEFAULT_ACCOUNT_BALANCE + self.value,
                nonce: Nonce::default(),
            };
            let mut selected = 0usize;

            for state in states.iter().copied().filter(|state| self.selects(state)) {
                selected += 1;
                if state.startup_account != Some(expected_sender) {
                    return Err("startup handoff did not expose the committed sender".to_string());
                }
                if state.account(&self.sender).await? != Some(expected_sender) {
                    return Err("sender state diverged after lifecycle handoff".to_string());
                }
                if state.account(&self.recipient).await? != Some(expected_recipient) {
                    return Err("recipient state diverged after lifecycle handoff".to_string());
                }

                let target_height = match self.target_height {
                    Some(height) => height,
                    None => state.processed_height().await,
                };
                let expected_targets = state
                    .targets_at_height(target_height)
                    .await
                    .ok_or_else(|| format!("missing finalized block at height {target_height}"))?;
                let committed_targets = state.committed_targets().await;
                if committed_targets.0 != expected_targets.0 {
                    return Err("full QMDB target diverged after lifecycle handoff".to_string());
                }
                if committed_targets.1 != expected_targets.1 {
                    return Err("compact QMDB target diverged after lifecycle handoff".to_string());
                }
            }

            if selected == 0 {
                return Err("no validator crossed the requested lifecycle boundary".to_string());
            }
            Ok(())
        })
    }
}

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

#[derive(Clone, Copy)]
pub(crate) struct RestartedAtHeight {
    height: u64,
}

impl RestartedAtHeight {
    pub(crate) const fn new(height: u64) -> Self {
        Self { height }
    }
}

impl<P: PublicKey> ExitCondition<P, ValidatorState> for RestartedAtHeight {
    fn name(&self) -> &str {
        "restarted_at_height"
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
            if states.len() < target_count || !states.iter().any(|state| state.restarted) {
                return Ok(false);
            }
            for state in states {
                if state.digest_at_height(self.height).await.is_none() {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
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
            if recovered_finalized == 0 {
                return Err(
                    "restart did not recover a finalization above the held processed floor"
                        .to_string(),
                );
            }

            let observed_processed = self
                .barrier
                .observed_processed()
                .ok_or_else(|| "restart processed height was not observed".to_string())?;
            if observed_processed != 0 {
                return Err(format!(
                    "restart moved processed height from 0 to {observed_processed} before acknowledgement; recovered finalization was {recovered_finalized}"
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
        _tracker: &'a ProgressTracker<P>,
        states: &'a [&'a ValidatorState],
        target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
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
