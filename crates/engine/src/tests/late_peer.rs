//! A committee member introduced by finalized application state after genesis.

use super::{
    TEST_EPOCH_LENGTH, TRANSACTION_NAMESPACE, TestEngineDefinition, TestHasher, TestPrivateKey,
    TestPublicKey, ValidatorState, directory, final_height, plan, socket_address,
    validator_fixture,
};
use crate::tests::common::TestEpochInfo;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::Signer as _;
use commonware_glue::{
    dkg::types::EpochOutcome,
    simulate::{action::Crash, property::Property, tracker::ProgressTracker},
};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::Address;
use commonware_utils::{
    ordered::{Map, Set},
    sequence::U64,
};
use constantinople_primitives::{Transaction, TransactionPublicKey};
use std::{
    collections::BTreeMap, future::Future, net::SocketAddr, path::PathBuf, pin::Pin, sync::Arc,
};

const LATE_PEER_SEED: u64 = 2_000_000;
const LATE_PEER_INDEX: usize = 4;
const REGISTRATION_HEIGHT: u64 = 1;
const TARGET_EPOCH: u64 = 2;
const ACTIVE_EPOCH: u64 = 3;

fn late_peer_engine() -> (TestEngineDefinition, TestPublicKey, Set<TestPublicKey>) {
    let (mut signers, output, mut shares) = validator_fixture(4);
    let late_signer = TestPrivateKey::from_seed(LATE_PEER_SEED);
    let late_peer = late_signer.public_key();
    shares.insert(late_peer.clone(), None);
    signers.push(late_signer);

    let initial = output.players().clone();
    let expected = Set::from_iter_dedup(initial.iter().cloned().chain([late_peer.clone()]));
    let eligible = Map::from_iter_dedup(
        signers
            .iter()
            .take(initial.len())
            .enumerate()
            .map(|(index, signer)| (signer.public_key(), super::address(index))),
    );
    let genesis = commonware_glue::dkg::types::EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        output: output.clone(),
        players: initial.clone(),
        next_players: initial,
        directory: directory(output.players(), &eligible),
    };

    let sender = &signers[1];
    let transaction = Transaction::set_committee_member(
        TransactionPublicKey::ed25519(sender.public_key()),
        late_peer.clone(),
        Some(socket_address(LATE_PEER_INDEX)),
        0,
    )
    .seal_and_sign(sender, TRANSACTION_NAMESPACE, &mut TestHasher::default());
    let proposals = BTreeMap::from([(REGISTRATION_HEIGHT, vec![transaction])]);
    let engine =
        TestEngineDefinition::from_parts(signers, output, shares, genesis, eligible, proposals);
    (engine, late_peer, expected)
}

async fn epoch_info(states: &[&ValidatorState], height: u64) -> Result<TestEpochInfo, String> {
    for state in states {
        if let Some(info) = state.epoch_info_at_height(height).await {
            return Ok(info);
        }
    }
    Err(format!("missing epoch artifact at height {height}"))
}

#[derive(Clone)]
struct LatePeerLifecycle {
    initial: Set<TestPublicKey>,
    expected: Set<TestPublicKey>,
    late_peer: TestPublicKey,
    late_address: SocketAddr,
    secret_path: Arc<PathBuf>,
}

impl Property<TestPublicKey, ValidatorState> for LatePeerLifecycle {
    fn name(&self) -> &str {
        "late_peer_lifecycle"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<TestPublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let late_state = states
                .iter()
                .copied()
                .find(|state| state.public_key == self.late_peer)
                .ok_or_else(|| "late peer never started".to_string())?;
            let original_state = states
                .iter()
                .copied()
                .find(|state| state.public_key != self.late_peer)
                .ok_or_else(|| "missing an original validator".to_string())?;
            if states.len() != self.initial.len() + 1 {
                return Err(format!(
                    "expected {} active peers, found {}",
                    self.initial.len() + 1,
                    states.len()
                ));
            }
            if late_state.processed_height().await < final_height(ACTIVE_EPOCH - 1) + 1 {
                return Err("late peer did not participate after committee activation".into());
            }
            let first_processed = late_state
                .first_processed_height()
                .ok_or_else(|| "late peer never applied a finalized block".to_string())?;
            if first_processed <= REGISTRATION_HEIGHT {
                return Err(format!(
                    "late peer replay began at or before registration: first applied height {first_processed}"
                ));
            }

            let registration_block = original_state
                .block_at_height(REGISTRATION_HEIGHT)
                .await
                .ok_or_else(|| "registration block was not retained".to_string())?;
            if registration_block.inner().body.len() != 1 {
                return Err("registration block did not contain exactly one transaction".into());
            }

            let genesis = epoch_info(states, 0).await?;
            let one = epoch_info(states, final_height(0)).await?;
            let two = epoch_info(states, final_height(1)).await?;
            let three = epoch_info(states, final_height(2)).await?;

            if genesis.players != self.initial
                || genesis.next_players != self.initial
                || genesis.output.players() != &self.initial
                || genesis.directory.get(&self.late_peer).is_some()
            {
                return Err("late peer was present in genesis".into());
            }
            if one.epoch != Epoch::new(1)
                || one.outcome != EpochOutcome::Success
                || one.output.players() != &self.initial
                || one.players != self.initial
                || one.next_players != self.expected
                || one.directory.get(&self.late_peer)
                    != Some(&Address::Symmetric(self.late_address))
            {
                return Err("epoch 1 did not advertise the future committee member".into());
            }
            if two.epoch != Epoch::new(TARGET_EPOCH)
                || two.outcome != EpochOutcome::Success
                || two.output.players() != &self.initial
                || two.players != self.expected
                || two.next_players != self.expected
            {
                return Err("epoch 2 did not install and carry the application committee".into());
            }
            if three.epoch != Epoch::new(ACTIVE_EPOCH)
                || three.outcome != EpochOutcome::Success
                || three.output.players() != &self.expected
                || three.players != self.expected
                || three.next_players != self.expected
            {
                return Err("continuous reshare did not activate the expanded committee".into());
            }
            if !self
                .initial
                .iter()
                .all(|peer| self.expected.position(peer).is_some())
            {
                return Err("registration removed an existing genesis peer".into());
            }

            for state in [original_state, late_state] {
                let database = state.committee()?;
                let database = database.read().await;
                let committee = database
                    .get(&U64::new(TARGET_EPOCH))
                    .await
                    .map_err(|error| format!("committee row read failed: {error}"))?
                    .ok_or_else(|| "target committee row was not materialized".to_string())?;
                if committee.members() != &self.expected
                    || committee.addresses().get_value(&self.late_peer) != Some(&self.late_address)
                {
                    return Err(format!(
                        "peer {} has an incorrect epoch-{TARGET_EPOCH} committee row",
                        state.public_key
                    ));
                }
            }

            let tracks = late_state.tracks.lock();
            let late_tracks = tracks
                .get(&self.late_peer)
                .ok_or_else(|| "late peer never tracked an epoch directory".to_string())?;
            let future = late_tracks
                .iter()
                .rev()
                .find(|(epoch, _)| *epoch == 1)
                .ok_or_else(|| "late peer did not recover epoch-1 tracking".to_string())?;
            if future.1.primary.get_value(&self.late_peer).is_some()
                || future.1.secondary.get_value(&self.late_peer)
                    != Some(&Address::Symmetric(self.late_address))
            {
                return Err("late peer was not tracked as a future player".into());
            }
            let active = late_tracks
                .iter()
                .rev()
                .find(|(epoch, _)| *epoch == ACTIVE_EPOCH)
                .ok_or_else(|| "late peer did not track its active epoch".to_string())?;
            if active.1.primary.get_value(&self.late_peer)
                != Some(&Address::Symmetric(self.late_address))
            {
                return Err("late peer was not promoted to an active dealer".into());
            }
            drop(tracks);

            let share = self
                .secret_path
                .join("shares")
                .join(ACTIVE_EPOCH.to_string());
            if !share.is_file() {
                return Err(format!(
                    "late peer did not persist its epoch-{ACTIVE_EPOCH} threshold share"
                ));
            }
            Ok(())
        })
    }
}

#[test_group("slow")]
#[test_traced("WARN")]
fn engine_adds_post_genesis_peer_via_committee_transaction() {
    let (mut engine, late_peer, expected) = late_peer_engine();
    let initial = engine.initial_players();
    for participant in initial.iter() {
        engine = engine.with_hold_until_attached(
            participant.clone(),
            TEST_EPOCH_LENGTH.get() + 8,
            late_peer.clone(),
        );
    }
    let secret_path = engine.secret_path(&late_peer);
    let late_address = socket_address(LATE_PEER_INDEX);
    let start_round = Round::new(Epoch::new(1), View::zero());

    let result = plan(engine)
        .crash(Crash::DelayRound {
            participants: vec![late_peer.clone()],
            round: start_round,
        })
        .exit_condition(
            super::properties::ParticipantQuorumFinalizedHeightAtLeast::new(
                final_height(ACTIVE_EPOCH - 1) + 1,
                expected.clone(),
            )
            .requiring(late_peer.clone()),
        )
        .property(LatePeerLifecycle {
            initial,
            expected,
            late_peer,
            late_address,
            secret_path,
        })
        .run()
        .unwrap()
        .pop()
        .expect("one simulation seed must produce one result");

    assert!(
        result.delayed_started,
        "late peer must start after the cluster"
    );
}
