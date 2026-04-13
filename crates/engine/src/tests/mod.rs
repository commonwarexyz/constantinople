//! End-to-end engine tests driven by `commonware_glue::simulate`.

mod common;
mod properties;

use crate::{
    BOOTSTRAPPER_CHANNEL, CERTIFICATE_CHANNEL, Channels, Config, Engine, MARSHAL_CHANNEL,
    MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, VOTE_CHANNEL, bootstrapper,
};
use common::{
    HeightMonitorReporter, NoopReporter, TEST_QUOTA, TRANSACTION_NAMESPACE, TestHasher,
    TestPrivateKey, TestPublicKey, TestScheme, ValidatorState, state_sync_done, validator_fixture,
};
use commonware_consensus::{Heightable, simplex::elector::RoundRobin, types::coding::Commitment};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::Output,
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::Batch as Ed25519Batch,
};
use commonware_glue::{
    simulate::{
        action::{Action, Crash, Schedule},
        engine::{EngineDefinition, InitContext},
        plan::PlanBuilder,
    },
    stateful::{StartupMode, db::SyncEngineConfig},
};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Metrics, Quota, Spawner};
use commonware_utils::{NZU64, NZUsize, channel::oneshot, sync::Mutex, union};
use constantinople_mempool::mocks::StaticTransactionSource;
use properties::{
    BlockAgreementAtHeight, FinalizedHeightAtLeast, LateJoinerStateSyncHandoff,
    StateSyncReadyAtHeight,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tracing::{info, warn};

const NUM_VALIDATORS: u32 = 4;
const ENGINE_NAMESPACE: &[u8] = b"constantinople-engine-test";
const MAX_BOOTSTRAP_MESSAGE_SIZE: u32 = 12 * 1024 * 1024;

const fn default_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(1),
        success_rate: 1.0,
    }
}

const fn lossy_link() -> Link {
    Link {
        latency: Duration::from_millis(200),
        jitter: Duration::from_millis(150),
        success_rate: 0.7,
    }
}

#[derive(Clone)]
struct TestEngineDefinition {
    signers: Vec<TestPrivateKey>,
    output: Output<MinSig, TestPublicKey>,
    shares: BTreeMap<TestPublicKey, Option<Share>>,
    enable_state_sync: bool,
    sync_heights: Arc<Mutex<BTreeMap<TestPublicKey, u64>>>,
}

impl TestEngineDefinition {
    fn new(validators: u32) -> Self {
        let (signers, output, shares) = validator_fixture(validators);

        Self {
            signers,
            output,
            shares,
            enable_state_sync: false,
            sync_heights: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    const fn with_state_sync(mut self) -> Self {
        self.enable_state_sync = true;
        self
    }
}

impl EngineDefinition for TestEngineDefinition {
    type PublicKey = TestPublicKey;
    type Engine = Handle<()>;
    type State = ValidatorState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.signers
            .iter()
            .map(TestPrivateKey::public_key)
            .collect()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (VOTE_CHANNEL, TEST_QUOTA),
            (CERTIFICATE_CHANNEL, TEST_QUOTA),
            (RESOLVER_CHANNEL, TEST_QUOTA),
            (MARSHAL_CHANNEL, TEST_QUOTA),
            (MARSHAL_RESOLVER_CHANNEL, TEST_QUOTA),
            (STATE_RESOLVER_CHANNEL, TEST_QUOTA),
            (BOOTSTRAPPER_CHANNEL, TEST_QUOTA),
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            channels,
            participants: _,
            monitor,
        } = ctx;
        let public_key = public_key.clone();
        let signer = self.signers[index].clone();
        let share = self.shares.get(&public_key).cloned().flatten();
        let partition_prefix = format!("validator-{index}");
        let stateful_partition_prefix = format!("{partition_prefix}_stateful");
        let output = self.output.clone();
        let sync_heights = self.sync_heights.clone();
        let enable_state_sync = self.enable_state_sync;
        let uses_state_sync = enable_state_sync && index == 0;
        let genesis_leader = self.signers[0].public_key();
        let manager = oracle.manager();
        let blocker = oracle.control(public_key.clone());
        let (state_sender, state_receiver) = oneshot::channel();

        let handle = context
            .with_label("validator")
            .spawn(move |context| async move {
                let mut channels = channels.into_iter();
                let votes = channels.next().expect("vote channel must exist");
                let certificates = channels.next().expect("certificate channel must exist");
                let resolver = channels.next().expect("resolver channel must exist");
                let marshal = channels.next().expect("marshal channel must exist");
                let marshal_resolver = channels
                    .next()
                    .expect("marshal resolver channel must exist");
                let state_resolver = channels.next().expect("state resolver channel must exist");
                let bootstrapper_network =
                    channels.next().expect("bootstrapper channel must exist");
                assert!(channels.next().is_none(), "unexpected extra channel");

                let (bootstrapper, bootstrapper_mailbox) = bootstrapper::Actor::new(
                    context.with_label("bootstrapper"),
                    bootstrapper::Config {
                        public_key: public_key.clone(),
                        peer_provider: manager.clone(),
                        blocker: blocker.clone(),
                        scheme: TestScheme::verifier(
                            &union(ENGINE_NAMESPACE, b"_CONSENSUS"),
                            output.players().clone(),
                            output.public().clone(),
                        ),
                        mailbox_size: 32,
                        round_timeout: Duration::from_secs(1),
                        retry_interval: Duration::from_millis(100),
                        block_codec: Default::default(),
                    },
                );
                let bootstrapper_handle = bootstrapper.start(bootstrapper_network);

                let (startup, startup_sync_height) = if uses_state_sync
                    && !state_sync_done(&context, &stateful_partition_prefix).await
                {
                    bootstrapper_mailbox
                        .fetch_initial_target()
                        .await
                        .map(|block| {
                            let height = block.height().get();
                            sync_heights.lock().insert(public_key.clone(), height);
                            (StartupMode::StateSync { block }, Some(height))
                        })
                        .expect("bootstrapper actor exited before selecting a state-sync target")
                } else {
                    let prior = sync_heights.lock().get(&public_key).copied();
                    (StartupMode::MarshalSync, prior)
                };
                let startup_mode = match &startup {
                    StartupMode::MarshalSync => "marshal_sync",
                    StartupMode::StateSync { .. } => "state_sync",
                };
                info!(
                    validator = %public_key,
                    %startup_mode,
                    startup_sync_height,
                    "initialized validator startup mode",
                );

                let channels = Channels {
                    votes,
                    certificates,
                    resolver,
                    marshal,
                    marshal_resolver,
                    state_resolver,
                };

                let input = StaticTransactionSource::<Commitment, TestPublicKey, TestHasher>::new(
                    Vec::new(),
                );
                let reporter =
                    HeightMonitorReporter::new(public_key.clone(), monitor, NoopReporter);
                let engine = Engine::<
                    _,
                    _,
                    _,
                    _,
                    TestHasher,
                    MinSig,
                    RoundRobin<TestHasher>,
                    _,
                    _,
                    Ed25519Batch,
                >::new(
                    context.with_label("engine"),
                    Config {
                        signer,
                        manager,
                        blocker,
                        namespace: ENGINE_NAMESPACE.to_vec(),
                        output,
                        share,
                        input,
                        partition_prefix,
                        freezer_table_initial_size: 1024,
                        strategy: Sequential,
                        startup,
                        sync_config: SyncEngineConfig {
                            fetch_batch_size: NZU64!(16),
                            apply_batch_size: 64,
                            max_outstanding_requests: 8,
                            update_channel_size: NZUsize!(256),
                            max_retained_roots: 32,
                        },
                        genesis_leader,
                        transaction_namespace: TRANSACTION_NAMESPACE,
                        block_codec: Default::default(),
                        bootstrapper: bootstrapper_mailbox.clone(),
                    },
                )
                .await;

                let marshal = engine.marshal_mailbox();
                if state_sender
                    .send(ValidatorState {
                        marshal,
                        startup_sync_height,
                    })
                    .is_err()
                {
                    warn!(validator = %public_key, "validator state receiver dropped");
                    return;
                }

                let engine_handle = engine.start(channels, Some(reporter));
                let (bootstrapper_result, engine_result) =
                    futures::join!(bootstrapper_handle, engine_handle);
                if let Err(error) = bootstrapper_result {
                    warn!(validator = %public_key, ?error, "bootstrapper exited");
                }
                if let Err(error) = engine_result {
                    warn!(validator = %public_key, ?error, "engine exited");
                }
            });

        let state = state_receiver
            .await
            .expect("validator failed to initialize");
        (handle, state)
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        engine
    }
}

fn run_finalize(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .exit_condition(FinalizedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
}

fn run_determinism(engine: TestEngineDefinition) {
    let seeds = 0..2;
    let first = PlanBuilder::new(engine.clone())
        .link(default_link())
        .seeds(seeds.clone())
        .exit_condition(FinalizedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
    let second = PlanBuilder::new(engine)
        .link(default_link())
        .seeds(seeds.clone())
        .exit_condition(FinalizedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();

    for (seed, (left, right)) in seeds.zip(first.iter().zip(second.iter())) {
        assert_eq!(
            left.state, right.state,
            "seed {seed} produced different state"
        );
    }
}

fn run_crash_restart(engine: TestEngineDefinition) {
    let validator = engine.participants()[0].clone();

    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(2_500),
                    Action::Crash(validator.clone()),
                )
                .at(Duration::from_millis(5_000), Action::Restart(validator)),
        ))
        .exit_condition(FinalizedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_delayed_start(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Delay { count: 1, after: 5 })
        .exit_condition(FinalizedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
}

fn run_state_sync(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(0..2)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .exit_condition(StateSyncReadyAtHeight::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(150))
        .run()
        .unwrap();
}

fn run_state_sync_deterministic(engine: TestEngineDefinition) {
    let seeds = 0..2;
    let first = PlanBuilder::new(engine.clone())
        .link(default_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(seeds.clone())
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .exit_condition(StateSyncReadyAtHeight::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(150))
        .run()
        .unwrap();
    let second = PlanBuilder::new(engine)
        .link(default_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(seeds.clone())
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .exit_condition(StateSyncReadyAtHeight::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::new(150))
        .run()
        .unwrap();

    for (seed, (left, right)) in seeds.zip(first.iter().zip(second.iter())) {
        assert_eq!(
            left.state, right.state,
            "seed {seed} produced different state"
        );
    }
}

fn run_state_sync_random_crashes(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(0..2)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .crash(Crash::Random {
            frequency: Duration::from_secs(3),
            downtime: Duration::from_millis(500),
            count: 1,
        })
        .exit_condition(StateSyncReadyAtHeight::new(200))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::at_least(200, 3))
        .run()
        .unwrap();
}

fn run_state_sync_lossy(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(lossy_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(0..2)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .exit_condition(StateSyncReadyAtHeight::new(150))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::at_least(150, 3))
        .run()
        .unwrap();
}

fn run_lossy(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(lossy_link())
        .seeds(0..2)
        .exit_condition(FinalizedHeightAtLeast::new(20))
        .property(BlockAgreementAtHeight::new(20))
        .run()
        .unwrap();
}

fn run_random_crashes(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_secs(1),
            count: 1,
        })
        .exit_condition(FinalizedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_many_crashes(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(500),
            count: 3,
        })
        .exit_condition(FinalizedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_total_shutdown(engine: TestEngineDefinition) {
    let count = engine.participants().len();

    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..3)
        .crash(Crash::Random {
            frequency: Duration::from_secs(5),
            downtime: Duration::from_millis(300),
            count,
        })
        .timeout(Duration::from_secs(90))
        .exit_condition(FinalizedHeightAtLeast::new(100))
        .property(BlockAgreementAtHeight::new(100))
        .run()
        .unwrap();
}

fn run_state_sync_crash_during_sync(engine: TestEngineDefinition) {
    let delayed = engine.participants().first().cloned().unwrap();

    PlanBuilder::new(engine)
        .link(default_link())
        .max_message_size(MAX_BOOTSTRAP_MESSAGE_SIZE)
        .seeds(0..2)
        .crash(Crash::Delay {
            count: 1,
            after: 80,
        })
        .crash(Crash::Schedule(
            Schedule::new()
                .at(Duration::from_millis(9_000), Action::Crash(delayed.clone()))
                .at(Duration::from_millis(11_000), Action::Restart(delayed)),
        ))
        .exit_condition(StateSyncReadyAtHeight::new(180))
        .property(LateJoinerStateSyncHandoff)
        .property(BlockAgreementAtHeight::at_least(180, 3))
        .run()
        .unwrap();
}

fn run_rapid_crashes(engine: TestEngineDefinition) {
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Random {
            frequency: Duration::from_millis(750),
            downtime: Duration::from_millis(250),
            count: 1,
        })
        .exit_condition(FinalizedHeightAtLeast::new(40))
        .property(BlockAgreementAtHeight::new(40))
        .run()
        .unwrap();
}

fn run_network_partition(engine: TestEngineDefinition) {
    let participants = engine.participants();
    let isolated = participants[0].clone();
    let good_link = default_link();
    let dead_link = Link {
        latency: Duration::from_secs(1),
        jitter: Duration::ZERO,
        success_rate: 0.0,
    };
    let mut schedule = Schedule::new();
    for peer in &participants[1..] {
        schedule = schedule
            .at(
                Duration::from_millis(500),
                Action::UpdateLink {
                    from: isolated.clone(),
                    to: peer.clone(),
                    link: dead_link.clone(),
                },
            )
            .at(
                Duration::from_millis(500),
                Action::UpdateLink {
                    from: peer.clone(),
                    to: isolated.clone(),
                    link: dead_link.clone(),
                },
            );
    }
    schedule = schedule.at(Duration::from_secs(2), Action::Heal(good_link));

    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .crash(Crash::Schedule(schedule))
        .exit_condition(FinalizedHeightAtLeast::new(40))
        .property(BlockAgreementAtHeight::at_least(40, 3))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn all_validators_finalize_and_commit() {
    run_finalize(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn deterministic_across_seeds() {
    run_determinism(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn crash_and_restart_one_validator() {
    run_crash_restart(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn delayed_start_one_validator() {
    run_delayed_start(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_hands_off_to_marshal() {
    run_state_sync(TestEngineDefinition::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_deterministic() {
    run_state_sync_deterministic(TestEngineDefinition::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_random_crashes() {
    run_state_sync_random_crashes(TestEngineDefinition::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_lossy_network() {
    run_state_sync_lossy(TestEngineDefinition::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn lossy_network() {
    run_lossy(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn random_crashes() {
    run_random_crashes(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn many_concurrent_crashes() {
    run_many_crashes(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn full_cluster_outage_and_recovery() {
    run_total_shutdown(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn state_sync_crash_during_sync() {
    run_state_sync_crash_during_sync(TestEngineDefinition::new(NUM_VALIDATORS).with_state_sync());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn rapid_crashes() {
    run_rapid_crashes(TestEngineDefinition::new(NUM_VALIDATORS));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn network_partition_and_rejoin() {
    run_network_partition(TestEngineDefinition::new(NUM_VALIDATORS));
}
