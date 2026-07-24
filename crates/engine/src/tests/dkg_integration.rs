//! Real multi-node Engine coverage for epoch-scoped DKG integration.

use super::{LARGE_PROPOSAL_TRANSACTIONS, TestEngineDefinition, final_height, plan};
use crate::tests::properties::{
    FailedCeremonyCarriesCommittee, FinalizedBlockHasTransactions,
    ParticipantQuorumFinalizedHeightAtLeast, RestartedAcrossBoundary, TwoCommitteeRotations,
};
use commonware_glue::simulate::{action::Crash, engine::EngineDefinition as _};
use commonware_macros::{test_group, test_traced};
use std::time::Duration;

#[test_traced("WARN")]
fn engine_stable_control_crosses_three_boundaries() {
    let engine = TestEngineDefinition::stable();
    let participants = engine.initial_players();
    plan(engine)
        .exit_condition(ParticipantQuorumFinalizedHeightAtLeast::new(
            final_height(2),
            participants,
        ))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("WARN")]
fn engine_finalizes_shards_larger_than_one_mibibyte() {
    let engine = TestEngineDefinition::rotating().with_large_proposal();
    let participants = engine.initial_players();
    plan(engine)
        .exit_condition(ParticipantQuorumFinalizedHeightAtLeast::new(
            1,
            participants.clone(),
        ))
        .property(FinalizedBlockHasTransactions::new(
            1,
            LARGE_PROPOSAL_TRANSACTIONS,
            participants,
        ))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("WARN")]
fn engine_dkg_applies_two_committee_rotations() {
    let engine = TestEngineDefinition::rotating();
    let property = TwoCommitteeRotations::new(
        engine.initial_players(),
        engine.updated_players(),
        engine.final_players(),
        engine.leaving(),
        engine.joining(),
    );
    let final_players = engine.final_players();

    plan(engine)
        .exit_condition(ParticipantQuorumFinalizedHeightAtLeast::new(
            final_height(3),
            final_players,
        ))
        .property(property)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("WARN")]
fn engine_failed_ceremony_carries_threshold_state() {
    let engine = TestEngineDefinition::rotating().with_failures([0]);
    let initial = engine.initial_players();
    let property = FailedCeremonyCarriesCommittee::new(initial.clone(), engine.updated_players());

    plan(engine)
        .exit_condition(ParticipantQuorumFinalizedHeightAtLeast::new(
            final_height(0),
            initial,
        ))
        .property(property)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("WARN")]
fn engine_dkg_restarts_immediately_before_and_after_boundary() {
    run_boundary_restart(final_height(0) - 1);
    run_boundary_restart(final_height(0));
}

fn run_boundary_restart(height: u64) {
    let engine = TestEngineDefinition::stable();
    let participant = engine.participants()[0].clone();
    let starts = engine.starts();
    let secret_path = engine.secret_path(&participant);
    let participants = engine.initial_players();
    let engine = engine.with_holds(participant.clone(), [height]);
    let target = if height < final_height(0) {
        final_height(0)
    } else {
        final_height(0) + 1
    };

    let result = plan(engine)
        .crash(Crash::ProcessedHeight {
            participant: participant.clone(),
            heights: height..=height,
            downtime: Duration::from_millis(100),
        })
        .exit_condition(
            ParticipantQuorumFinalizedHeightAtLeast::new(target, participants)
                .requiring(participant.clone()),
        )
        .property(RestartedAcrossBoundary::new(
            participant,
            starts,
            secret_path,
            target,
        ))
        .run()
        .unwrap()
        .pop()
        .expect("one simulation seed must produce one result");

    assert_eq!(result.crashes, 1, "boundary crash window must fire");
}
