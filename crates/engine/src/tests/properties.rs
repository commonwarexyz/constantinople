use super::final_height;
use crate::tests::common::{TestEpochInfo, TestPublicKey, ValidatorState};
use commonware_consensus::types::Epoch;
use commonware_glue::{
    dkg::{network::Directory as _, types::EpochOutcome},
    simulate::{exit::ExitCondition, property::Property, tracker::ProgressTracker},
};
use commonware_p2p::AddressableTrackedPeers;
use commonware_utils::{ordered::Set, sequence::U64, sync::Mutex};
use std::{collections::BTreeMap, future::Future, path::PathBuf, pin::Pin, sync::Arc};

#[derive(Clone)]
pub(crate) struct ParticipantQuorumFinalizedHeightAtLeast {
    height: u64,
    participants: Set<TestPublicKey>,
    required: Set<TestPublicKey>,
}

impl ParticipantQuorumFinalizedHeightAtLeast {
    pub(crate) fn new(height: u64, participants: Set<TestPublicKey>) -> Self {
        Self {
            height,
            participants,
            required: Set::default(),
        }
    }

    pub(crate) fn requiring(mut self, participant: TestPublicKey) -> Self {
        self.required = Set::from_iter_dedup([participant]);
        self
    }
}

impl ExitCondition<TestPublicKey, ValidatorState> for ParticipantQuorumFinalizedHeightAtLeast {
    fn name(&self) -> &str {
        "participant_quorum_finalized_height_at_least"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
        _target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            for participant in self.required.iter() {
                let Some(state) = states
                    .iter()
                    .copied()
                    .find(|state| &state.public_key == participant)
                else {
                    return Ok(false);
                };
                if state.processed_height().await < self.height {
                    return Ok(false);
                }
            }

            let mut reached = 0usize;
            for participant in self.participants.iter() {
                let Some(state) = states
                    .iter()
                    .copied()
                    .find(|state| &state.public_key == participant)
                else {
                    continue;
                };
                if state.processed_height().await >= self.height {
                    reached += 1;
                }
            }
            let quorum = self.participants.len() * 2 / 3 + 1;
            Ok(reached >= quorum)
        })
    }
}

async fn info(states: &[&ValidatorState], height: u64) -> Result<TestEpochInfo, String> {
    for state in states {
        if let Some(info) = state.epoch_info_at_height(height).await {
            return Ok(info);
        }
    }
    Err(format!("missing epoch artifact at height {height}"))
}

#[derive(Clone)]
pub(crate) struct FailedCeremonyCarriesCommittee {
    initial: Set<TestPublicKey>,
    updated: Set<TestPublicKey>,
}

impl FailedCeremonyCarriesCommittee {
    pub(crate) const fn new(initial: Set<TestPublicKey>, updated: Set<TestPublicKey>) -> Self {
        Self { initial, updated }
    }
}

impl Property<TestPublicKey, ValidatorState> for FailedCeremonyCarriesCommittee {
    fn name(&self) -> &str {
        "failed_ceremony_carries_committee"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let genesis = info(states, 0).await?;
            let boundary = info(states, final_height(0)).await?;
            if boundary.epoch != Epoch::new(1)
                || boundary.outcome != EpochOutcome::Failure
                || boundary.output != genesis.output
                || boundary.players != self.initial
                || boundary.next_players != self.updated
            {
                return Err("failed ceremony did not carry threshold state and lookahead".into());
            }
            Ok(())
        })
    }
}

fn tracked(
    states: &[&ValidatorState],
    epoch: Epoch,
) -> Option<AddressableTrackedPeers<TestPublicKey>> {
    let tracks = states.first()?.tracks.lock();
    tracks
        .values()
        .flat_map(|entries| entries.iter())
        .rev()
        .find(|(id, _)| *id == epoch.get())
        .map(|(_, peers)| peers.clone())
}

fn check_tracking(
    info: &TestEpochInfo,
    tracked: &AddressableTrackedPeers<TestPublicKey>,
) -> Result<(), String> {
    let expected = info.participants().tracked_peers();
    if tracked.primary.keys() != &expected.primary
        || tracked.secondary.keys() != &expected.secondary
    {
        return Err(format!(
            "epoch {} lookup primary/secondary roles differ from artifact",
            info.epoch
        ));
    }
    if !info.directory.matches(&expected.union()) {
        return Err(format!(
            "epoch {} directory does not exactly match tracked peers",
            info.epoch
        ));
    }
    for (peer, address) in tracked
        .primary
        .iter_pairs()
        .chain(tracked.secondary.iter_pairs())
    {
        if info.directory.get(peer) != Some(address) {
            return Err(format!(
                "epoch {} address for {peer} differs from artifact",
                info.epoch
            ));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct TwoCommitteeRotations {
    initial: Set<TestPublicKey>,
    updated: Set<TestPublicKey>,
    final_players: Set<TestPublicKey>,
    leaving: TestPublicKey,
    joining: TestPublicKey,
}

impl TwoCommitteeRotations {
    pub(crate) const fn new(
        initial: Set<TestPublicKey>,
        updated: Set<TestPublicKey>,
        final_players: Set<TestPublicKey>,
        leaving: TestPublicKey,
        joining: TestPublicKey,
    ) -> Self {
        Self {
            initial,
            updated,
            final_players,
            leaving,
            joining,
        }
    }
}

impl Property<TestPublicKey, ValidatorState> for TwoCommitteeRotations {
    fn name(&self) -> &str {
        "two_committee_rotations"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if states.len() != 6 {
                return Err(format!(
                    "future member did not join: {} states",
                    states.len()
                ));
            }
            let genesis = info(states, 0).await?;
            let one = info(states, final_height(0)).await?;
            let two = info(states, final_height(1)).await?;
            let three = info(states, final_height(2)).await?;
            let four = info(states, final_height(3)).await?;
            if [genesis.epoch, one.epoch, two.epoch, three.epoch, four.epoch]
                != [
                    Epoch::zero(),
                    Epoch::new(1),
                    Epoch::new(2),
                    Epoch::new(3),
                    Epoch::new(4),
                ]
            {
                return Err("did not finalize artifacts across four epoch boundaries".into());
            }
            if one.outcome != EpochOutcome::Success
                || one.output.players() != &self.initial
                || one.players != self.initial
                || one.next_players != self.updated
            {
                return Err(
                    "first reshare did not retain the committee or announce the E+2 update".into(),
                );
            }
            if two.outcome != EpochOutcome::Success
                || two.output.players() != &self.initial
                || two.players != self.updated
                || two.next_players != self.final_players
            {
                return Err(format!(
                    "second reshare mismatch: outcome={:?}, output={:?}, players={:?}, next={:?}",
                    two.outcome,
                    two.output.players(),
                    two.players,
                    two.next_players,
                ));
            }
            if three.outcome != EpochOutcome::Success
                || three.output.players() != &self.updated
                || three.players != self.final_players
                || three.next_players != self.final_players
                || four.outcome != EpochOutcome::Success
                || four.output.players() != &self.final_players
                || four.players != self.final_players
                || four.next_players != self.final_players
            {
                return Err("updated committee did not obtain a usable output".into());
            }
            if four.output.players().position(&self.joining).is_none()
                || four.output.players().position(&self.leaving).is_some()
            {
                return Err("committee add/remove was not reflected in activated output".into());
            }

            let reference = states
                .iter()
                .copied()
                .find(|state| state.public_key != self.joining)
                .ok_or_else(|| "missing original validator".to_string())?;
            let database = reference.committee()?;
            let database = database.read().await;
            let row = database
                .get(&U64::new(2))
                .await
                .map_err(|error| format!("committee row read failed: {error}"))?
                .ok_or_else(|| "E+2 row absent; fallback would be required".to_string())?;
            if row.into_members() != self.updated {
                return Err("materialized E+2 row differs from requested committee".into());
            }

            for artifact in [&one, &two, &three, &four] {
                let peers = tracked(states, artifact.epoch).ok_or_else(|| {
                    format!("missing lookup tracking for epoch {}", artifact.epoch)
                })?;
                check_tracking(artifact, &peers)?;
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(crate) struct RestartedAcrossBoundary {
    participant: TestPublicKey,
    starts: Arc<Mutex<BTreeMap<TestPublicKey, usize>>>,
    secret_path: Arc<PathBuf>,
    target: u64,
}

impl RestartedAcrossBoundary {
    pub(crate) const fn new(
        participant: TestPublicKey,
        starts: Arc<Mutex<BTreeMap<TestPublicKey, usize>>>,
        secret_path: Arc<PathBuf>,
        target: u64,
    ) -> Self {
        Self {
            participant,
            starts,
            secret_path,
            target,
        }
    }
}

impl Property<TestPublicKey, ValidatorState> for RestartedAcrossBoundary {
    fn name(&self) -> &str {
        "restarted_across_boundary"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let starts = self
                .starts
                .lock()
                .get(&self.participant)
                .copied()
                .unwrap_or_default();
            if starts != 2 {
                return Err(format!("validator started {starts} times, expected 2"));
            }
            let state = states
                .iter()
                .copied()
                .find(|state| state.public_key == self.participant)
                .ok_or_else(|| "restarted validator is not active".to_string())?;
            let artifact = state
                .epoch_info_at_height(final_height(0))
                .await
                .ok_or_else(|| "missing first boundary artifact after restart".to_string())?;
            if artifact.epoch != Epoch::new(1) {
                return Err(format!("first boundary has artifact {}", artifact.epoch));
            }
            if state.processed_height().await < self.target {
                return Err(format!(
                    "restarted validator did not reach target {}",
                    self.target
                ));
            }
            let share = self.secret_path.join("shares").join("1");
            if !share.is_file() {
                return Err(format!(
                    "missing persisted DKG share at {}",
                    share.display()
                ));
            }
            Ok(())
        })
    }
}

#[test]
fn production_epoch_length_remains_1024() {
    assert_eq!(super::TEST_EPOCH_LENGTH.get(), 64);
    assert_eq!(crate::EPOCH_LENGTH.get(), 1024);
    assert_eq!(
        constantinople_application::consensus::BLOCKS_PER_EPOCH,
        1024
    );
}
