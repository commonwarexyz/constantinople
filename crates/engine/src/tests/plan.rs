//! Focused deterministic plan for the engine integration tests.
//!
//! Commonware's general `glue::simulate::PlanBuilder` currently fixes the
//! simulated network to one retained peer set. DKG integration needs several
//! epoch-indexed sets so removed validators remain reachable while
//! lookup transitions are exercised. This small plan keeps only the
//! processed-height crash and delayed-start controls used by these tests.

use super::{TestEngineDefinition, ValidatorState};
use commonware_consensus::types::Round;
use commonware_glue::simulate::{
    action::Crash,
    engine::EngineDefinition as _,
    exit::ExitCondition,
    property::Property,
    team::Team,
    tracker::{FinalizationUpdate, ProgressTracker},
};
use commonware_macros::select;
use commonware_p2p::simulated::{self, Link, Network};
use commonware_runtime::{Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic};
use commonware_utils::{NZUsize, channel::mpsc};
use std::{collections::HashSet, ops::RangeInclusive, time::Duration};

struct ProcessedCrash {
    participant: super::TestPublicKey,
    heights: RangeInclusive<u64>,
    downtime: Duration,
    triggered: bool,
}

struct DelayedStart {
    participants: HashSet<super::TestPublicKey>,
    round: Round,
}

pub(crate) struct RunResult {
    pub(crate) crashes: u64,
    pub(crate) delayed_started: bool,
}

pub(crate) struct Plan {
    engine: TestEngineDefinition,
    link: Link,
    max_message_size: u32,
    timeout: Duration,
    delayed_start: Option<DelayedStart>,
    processed_crashes: Vec<ProcessedCrash>,
    exit: Option<Box<dyn ExitCondition<super::TestPublicKey, ValidatorState>>>,
    properties: Vec<Box<dyn Property<super::TestPublicKey, ValidatorState>>>,
}

impl Plan {
    pub(crate) fn new(engine: TestEngineDefinition) -> Self {
        Self {
            engine,
            link: super::default_link(),
            max_message_size: super::MAX_MESSAGE_SIZE,
            timeout: Duration::from_secs(600),
            delayed_start: None,
            processed_crashes: Vec::new(),
            exit: None,
            properties: Vec::new(),
        }
    }

    pub(crate) fn crash(mut self, crash: Crash<super::TestPublicKey>) -> Self {
        match crash {
            Crash::DelayRound {
                participants,
                round,
            } => {
                assert!(
                    self.delayed_start.is_none(),
                    "the engine integration plan supports one delayed-start group"
                );
                self.delayed_start = Some(DelayedStart {
                    participants: participants.into_iter().collect(),
                    round,
                });
            }
            Crash::ProcessedHeight {
                participant,
                heights,
                downtime,
            } => self.processed_crashes.push(ProcessedCrash {
                participant,
                heights,
                downtime,
                triggered: false,
            }),
            Crash::Random { .. } | Crash::Schedule(_) => {
                panic!("the engine integration plan only supports deterministic crash controls")
            }
        }
        self
    }

    pub(crate) fn exit_condition(
        mut self,
        exit: impl ExitCondition<super::TestPublicKey, ValidatorState> + 'static,
    ) -> Self {
        self.exit = Some(Box::new(exit));
        self
    }

    pub(crate) fn property(
        mut self,
        property: impl Property<super::TestPublicKey, ValidatorState> + 'static,
    ) -> Self {
        self.properties.push(Box::new(property));
        self
    }

    pub(crate) fn run(self) -> Result<Vec<RunResult>, String> {
        let config = deterministic::Config::new()
            .with_seed(0)
            .with_timeout(Some(self.timeout));
        let runner = deterministic::Runner::new(config);
        runner
            .start(move |context| self.run_inner(context))
            .map(|result| vec![result])
    }

    async fn run_inner(mut self, context: deterministic::Context) -> Result<RunResult, String> {
        let participants = self.engine.participants();
        let initial = self.engine.initial_players();
        let secondary = participants
            .iter()
            .filter(|participant| initial.position(participant).is_none())
            .cloned();
        let (network, oracle) = Network::<_, super::TestPublicKey>::new_with_split_peers(
            context.child("network"),
            simulated::Config {
                max_size: self.max_message_size,
                disconnect_on_block: true,
                // Genesis plus the four epoch transitions inspected by the
                // scenarios, with room for restart replays.
                tracked_peer_sets: NZUsize!(8),
            },
            initial.iter().cloned(),
            secondary,
        )
        .await;
        network.start();

        let delayed = self
            .delayed_start
            .as_ref()
            .map(|start| start.participants.clone())
            .unwrap_or_default();
        let mut team = Team::new(self.engine.clone(), participants);
        let (monitor_tx, mut monitor_rx) =
            mpsc::channel::<FinalizationUpdate<super::TestPublicKey>>(1024);
        let (restart_tx, mut restart_rx) = mpsc::channel::<super::TestPublicKey>(8);
        team.start(
            &context,
            &oracle,
            self.link.clone(),
            monitor_tx.clone(),
            &delayed,
        )
        .await;

        let mut tracker = ProgressTracker::default();
        let mut crashes = 0;
        let mut delayed_started = delayed.is_empty();
        let exit = self
            .exit
            .take()
            .expect("engine integration plan requires an exit condition");

        loop {
            select! {
                _ = context.stopped() => {
                    return Err("simulation stopped before completion".into());
                },
                public_key = restart_rx.recv() => {
                    let Some(public_key) = public_key else {
                        return Err("restart channel closed".into());
                    };
                    team.restart(
                        &context,
                        &oracle,
                        public_key.clone(),
                        monitor_tx.clone(),
                        false,
                    ).await;
                },
                update = monitor_rx.recv() => {
                    let Some(update) = update else {
                        return Err("monitor channel closed".into());
                    };
                    tracker.observe(update)?;
                },
                _ = context.sleep(Duration::from_millis(25)) => {},
            }

            if !delayed_started
                && self.delayed_start.as_ref().is_some_and(|start| {
                    tracker
                        .max_round()
                        .is_some_and(|round| round >= start.round)
                })
            {
                for participant in &delayed {
                    team.start_one(
                        &context,
                        &oracle,
                        participant.clone(),
                        monitor_tx.clone(),
                        true,
                    )
                    .await;
                }
                delayed_started = true;
            }

            crashes += self
                .trigger_processed_crashes(&context, &mut team, &restart_tx)
                .await?;

            let states = team.active_states();
            if !exit
                .reached(&tracker, &states, states.len())
                .await
                .map_err(|error| format!("exit condition {} failed: {error}", exit.name()))?
            {
                continue;
            }

            if self.processed_crashes.iter().any(|crash| !crash.triggered) {
                return Err("not every processed-height crash was triggered".into());
            }
            for property in &self.properties {
                property
                    .check(&tracker, &states)
                    .await
                    .map_err(|error| format!("property {} failed: {error}", property.name()))?;
            }
            return Ok(RunResult {
                crashes,
                delayed_started,
            });
        }
    }

    async fn trigger_processed_crashes(
        &mut self,
        context: &deterministic::Context,
        team: &mut Team<TestEngineDefinition>,
        restart_tx: &mpsc::Sender<super::TestPublicKey>,
    ) -> Result<u64, String> {
        let mut triggered = 0;
        for crash in &mut self.processed_crashes {
            if crash.triggered {
                continue;
            }
            let Some(state) = team.active_state(&crash.participant) else {
                continue;
            };
            let processed = state.processed_height().await;
            if processed < *crash.heights.start() {
                continue;
            }
            if !crash.heights.contains(&processed) {
                return Err(format!(
                    "validator skipped crash window: {processed} not in {:?}",
                    crash.heights
                ));
            }
            crash.triggered = true;
            if !team.crash(&crash.participant) {
                continue;
            }
            triggered += 1;
            let participant = crash.participant.clone();
            let downtime = crash.downtime;
            let restart_tx = restart_tx.clone();
            context
                .child("processed_height_restart")
                .spawn(move |context| async move {
                    context.sleep(downtime).await;
                    let _ = restart_tx.send(participant).await;
                });
        }
        Ok(triggered)
    }
}
