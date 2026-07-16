//! End-to-end engine tests driven by `commonware_glue::simulate`.

mod common;
mod properties;

use crate::{
    CERTIFICATE_CHANNEL, Channels, Config, Engine, MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL,
    MAX_PENDING_ACKS, PROBE_CHANNEL, RESOLVER_CHANNEL, STATE_RESOLVER_CHANNEL, StartupMode,
    TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL,
};
use common::{
    HeightMonitorReporter, RestartBarrier, TEST_QUOTA, TRANSACTION_NAMESPACE, TestHasher,
    TestPrivateKey, TestPublicKey, TestReporter, TestScheme, ValidatorState, validator_fixture,
};
use commonware_consensus::{
    Heightable,
    marshal::core::CommitmentFallback,
    simplex::elector::RoundRobin,
    types::{Epoch, coding::Commitment},
};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group::Share, variant::MinSig},
    },
    certificate::ConstantProvider,
    ed25519::Batch as Ed25519Batch,
};
use commonware_glue::{
    simulate::{
        action::{Action, Crash, Schedule},
        engine::{EngineDefinition, InitContext},
        plan::PlanBuilder,
    },
    stateful::{
        PruneConfig,
        db::SyncEngineConfig,
        probe::{Config as ProbeConfig, Probe},
    },
};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::{Manager as _, TrackedPeers, simulated::Link};
use commonware_parallel::Sequential;
use commonware_runtime::{Handle, Quota, Spawner, Supervisor};
use commonware_utils::{
    NZDuration, NZU64, NZUsize, TryCollect, channel::oneshot, ordered::Set, sync::Mutex, union,
};
use constantinople_mempool::mocks::StaticTransactionSource;
use constantinople_primitives::PublicKeyCache;
use properties::{
    BlockAgreementAtHeight, FinalizedHeightAtLeast, LateJoinerStateSyncHandoff,
    RestartPreservesProcessedHeight, RestartRecoveryComplete, StateSyncReadyAtHeight,
};
use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc, time::Duration};
use tracing::{info, warn};

const NUM_VALIDATORS: u32 = 4;
const ENGINE_NAMESPACE: &[u8] = b"constantinople-engine-test";
const MAX_PROBE_MESSAGE_SIZE: u32 = 12 * 1024 * 1024;

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
    /// When `true`, every node re-tracks peer set 0 during `init` as
    /// `TrackedPeers::new(primary, secondary)` — primary = nodes with a DKG
    /// share, secondary = nodes without. Exercises the p2p discovery secondary
    /// mechanism. Default `false` leaves all nodes in the primary set as
    /// configured by `PlanBuilder`.
    use_discovery_split: bool,
    sync_heights: Arc<Mutex<BTreeMap<TestPublicKey, u64>>>,
    genesis_commitments: Arc<Mutex<BTreeMap<TestPublicKey, Commitment>>>,
    restart_barrier: Option<RestartBarrier>,
    prunable_items_per_section: NonZeroU64,
    retained_marshal_blocks: usize,
}

impl TestEngineDefinition {
    fn new(validators: u32) -> Self {
        let (signers, output, shares) = validator_fixture(validators);

        Self {
            signers,
            output,
            shares,
            enable_state_sync: false,
            use_discovery_split: false,
            sync_heights: Arc::new(Mutex::new(BTreeMap::new())),
            genesis_commitments: Arc::new(Mutex::new(BTreeMap::new())),
            restart_barrier: None,
            prunable_items_per_section: NZU64!(4_096),
            retained_marshal_blocks: 16,
        }
    }

    /// Extend the node set with `count` secondary (non-voting) participants.
    ///
    /// Secondaries receive an ed25519 identity but no DKG share, so the engine
    /// constructs their threshold scheme in verifier mode (`me() == None`).
    /// Simplex then runs as a silent observer: no votes, no certificates — the
    /// node only processes inbound messages and drives its local state machine.
    fn with_secondaries(mut self, count: u32) -> Self {
        const SECONDARY_SEED_OFFSET: u64 = 1_000_000;
        for i in 0..count {
            let signer = TestPrivateKey::from_seed(SECONDARY_SEED_OFFSET + u64::from(i));
            self.shares.insert(signer.public_key(), None);
            self.signers.push(signer);
        }
        self
    }

    /// Exercise the `p2p::discovery` secondary peer-set mechanism.
    ///
    /// With this enabled, each node re-tracks peer set 0 as
    /// `TrackedPeers::new(primary, secondary)` during `init`. Primary = nodes
    /// with a DKG share, secondary = the rest.
    const fn with_discovery_split(mut self) -> Self {
        self.use_discovery_split = true;
        self
    }

    const fn with_state_sync(mut self) -> Self {
        self.enable_state_sync = true;
        self
    }

    fn with_restart_barrier(mut self, barrier: RestartBarrier) -> Self {
        self.restart_barrier = Some(barrier);
        self.prunable_items_per_section = NZU64!(1);
        self
    }

    const fn with_aggressive_pruning(mut self) -> Self {
        self.prunable_items_per_section = NZU64!(1);
        self.retained_marshal_blocks = 0;
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
            (TRANSACTION_RESOLVER_CHANNEL, TEST_QUOTA),
            (PROBE_CHANNEL, TEST_QUOTA),
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
            ..
        } = ctx;
        let public_key = public_key.clone();
        let signer = self.signers[index].clone();
        let share = self.shares.get(&public_key).cloned().flatten();
        let partition_prefix = format!("validator-{index}");
        let output = self.output.clone();
        let sync_heights = self.sync_heights.clone();
        let genesis_commitments = self.genesis_commitments.clone();
        let prunable_items_per_section = self.prunable_items_per_section;
        let retained_marshal_blocks = self.retained_marshal_blocks;
        let enable_state_sync = self.enable_state_sync;
        let uses_state_sync = enable_state_sync && index == 0;
        let restart_barrier = (index == 0).then(|| self.restart_barrier.clone()).flatten();
        let is_restart = restart_barrier
            .as_ref()
            .is_some_and(RestartBarrier::begin_start);
        let genesis_leader = self.signers[0].public_key();
        let mut manager = oracle.manager();
        let blocker = oracle.control(public_key.clone());
        let (state_sender, state_receiver) = oneshot::channel();

        // Override PlanBuilder's default single-primary-set tracking with the
        // discovery primary/secondary split when requested.
        if self.use_discovery_split && index == 0 {
            let (primary, secondary): (Vec<_>, Vec<_>) = self
                .signers
                .iter()
                .map(TestPrivateKey::public_key)
                .partition(|pk| self.shares.get(pk).is_some_and(|share| share.is_some()));
            let primary: Set<TestPublicKey> = primary.into_iter().try_collect().unwrap();
            let secondary: Set<TestPublicKey> = secondary.into_iter().try_collect().unwrap();
            manager.track(0, TrackedPeers::new(primary, secondary));
        }

        let handle = context.child("validator").spawn(move |context| async move {
            let mut channels = channels.into_iter();
            let votes = channels.next().expect("vote channel must exist");
            let certificates = channels.next().expect("certificate channel must exist");
            let resolver = channels.next().expect("resolver channel must exist");
            let marshal = channels.next().expect("marshal channel must exist");
            let marshal_resolver = channels
                .next()
                .expect("marshal resolver channel must exist");
            let state_resolver = channels.next().expect("state resolver channel must exist");
            let transaction_resolver = channels
                .next()
                .expect("transaction resolver channel must exist");
            let probe_network = channels.next().expect("probe channel must exist");
            assert!(channels.next().is_none(), "unexpected extra channel");

            let (probe_handle, probe_mailbox) = if enable_state_sync {
                let provider = ConstantProvider::new(TestScheme::verifier(
                    &union(ENGINE_NAMESPACE, b"_CONSENSUS"),
                    output.players().clone(),
                    output.public().clone(),
                ));
                let (probe, probe_mailbox) = Probe::new(ProbeConfig {
                    context: context.child("probe"),
                    provider,
                    strategy: Sequential,
                    capacity: NZUsize!(32),
                    blocker: blocker.clone(),
                    minimum_epoch: Epoch::zero(),
                    retry_timeout: NZDuration!(Duration::from_millis(100)),
                });
                (Some(probe.start(probe_network)), Some(probe_mailbox))
            } else {
                (None, None)
            };

            let startup = if uses_state_sync {
                StartupMode::StateSync
            } else {
                StartupMode::MarshalSync
            };
            let startup_mode = match &startup {
                StartupMode::MarshalSync => "marshal_sync",
                StartupMode::StateSync => "state_sync",
            };
            info!(
                validator = %public_key,
                %startup_mode,
                "requested validator startup mode",
            );

            let channels = Channels {
                votes,
                certificates,
                resolver,
                marshal,
                marshal_resolver,
                state_resolver,
                transaction_resolver,
            };

            let input =
                StaticTransactionSource::<Commitment, TestPublicKey, TestHasher>::new(Vec::new());
            let reporter = HeightMonitorReporter::new(
                public_key.clone(),
                monitor,
                TestReporter::new(restart_barrier.clone()),
            );
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
                crate::types::NoopActivityReporter<TestPublicKey, MinSig>,
            >::new(
                context.child("engine"),
                Config {
                    signer,
                    manager,
                    blocker,
                    namespace: ENGINE_NAMESPACE.to_vec(),
                    // Small: simulation state is tiny and large caches slow
                    // deterministic runs.
                    state_page_cache_bytes: 32 * 1024 * 1024,
                    other_page_cache_bytes: 32 * 1024 * 1024,
                    output,
                    share,
                    input,
                    partition_prefix,
                    strategy: Sequential,
                    public_key_cache: PublicKeyCache::new(
                        context.child("public_key_cache"),
                        NZUsize!(1024),
                    ),
                    startup,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(16),
                        apply_batch_size: 64,
                        max_outstanding_requests: 8,
                        update_channel_size: NZUsize!(256),
                        max_retained_roots: 32,
                    },
                    prune_config: Some(PruneConfig {
                        max_pending_acks: MAX_PENDING_ACKS,
                        maintenance_interval: NZUsize!(16),
                        retained_marshal_blocks,
                        retained_qmdb_blocks: 0,
                    }),
                    genesis_leader,
                    transaction_namespace: TRANSACTION_NAMESPACE,
                    block_codec: Default::default(),
                    prunable_items_per_section,
                    probe: probe_mailbox.clone(),
                    simplex_observer: None,
                    finalized_hook: None,
                },
            )
            .await;

            let genesis_commitment = engine.genesis_commitment();
            if let Some(expected) = genesis_commitments
                .lock()
                .insert(public_key.clone(), genesis_commitment)
            {
                assert_eq!(genesis_commitment, expected, "genesis changed on restart");
            }

            let selected_sync_floor = engine.startup_sync_floor();
            let marshal = engine.marshal_mailbox();
            let restart_marshal = marshal.clone();
            let engine_handle = engine.start(channels, Some(reporter));
            let startup_sync_height = if let Some(finalization) = selected_sync_floor {
                let block = marshal
                    .subscribe_by_commitment(
                        finalization.proposal.payload,
                        CommitmentFallback::Wait,
                    )
                    .await
                    .expect("state-sync floor block must be available");
                let height = block.height().get();
                sync_heights.lock().insert(public_key.clone(), height);
                info!(validator = %public_key, height, "resolved state-sync floor block");
                Some(height)
            } else {
                sync_heights.lock().get(&public_key).copied()
            };
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

            if is_restart {
                let processed = restart_marshal
                    .get_processed_height()
                    .await
                    .map_or(0, |height| height.get());
                let barrier = restart_barrier.expect("restart barrier must exist");
                barrier.observe_processed(processed);
                barrier.release();
            }
            let engine_result = if let Some(probe_handle) = probe_handle {
                let (probe_result, engine_result) = futures::join!(probe_handle, engine_handle);
                if let Err(error) = probe_result {
                    warn!(validator = %public_key, ?error, "probe exited");
                }
                engine_result
            } else {
                engine_handle.await
            };
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
                .at(Duration::from_millis(500), Action::Crash(validator.clone()))
                .at(Duration::from_millis(1_000), Action::Restart(validator)),
        ))
        .exit_condition(FinalizedHeightAtLeast::new(50))
        .property(BlockAgreementAtHeight::new(50))
        .run()
        .unwrap();
}

fn run_restart_with_archived_finalizations() {
    let barrier = RestartBarrier::default();
    let engine = TestEngineDefinition::new(NUM_VALIDATORS).with_restart_barrier(barrier.clone());
    let validator = engine.participants()[0].clone();

    PlanBuilder::new(engine)
        .link(default_link())
        .seed(0)
        .crash(Crash::Schedule(
            Schedule::new()
                .at(
                    Duration::from_millis(2_500),
                    Action::Crash(validator.clone()),
                )
                .at(Duration::from_millis(5_000), Action::Restart(validator)),
        ))
        .timeout(Duration::from_secs(30))
        .exit_condition(RestartRecoveryComplete::new(barrier.clone()))
        .property(RestartPreservesProcessedHeight::new(barrier))
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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
    // One deterministic full blackout: every validator crashes at once and
    // restarts together. A fixed schedule guarantees the outage actually
    // happens; `Crash::Random` cycles can miss the run entirely when the
    // exit height finalizes before their first tick.
    let mut schedule = Schedule::new();
    let participants = engine.participants();
    for participant in participants.iter().cloned() {
        schedule = schedule.at(Duration::from_secs(3), Action::Crash(participant));
    }
    for participant in participants.iter().cloned() {
        schedule = schedule.at(Duration::from_millis(3_300), Action::Restart(participant));
    }

    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..3)
        .crash(Crash::Schedule(schedule))
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
        .max_message_size(MAX_PROBE_MESSAGE_SIZE)
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

fn run_secondaries_sync(engine: TestEngineDefinition) {
    // Every node (primary and secondary) must reach height 40 and agree on the
    // block at that height. `FinalizedHeightAtLeast` polls per-node state and
    // requires `target_count == participants.len()` to have the block, so
    // secondaries falling behind will cause the exit condition never to fire.
    PlanBuilder::new(engine)
        .link(default_link())
        .seeds(0..2)
        .exit_condition(FinalizedHeightAtLeast::new(40))
        .property(BlockAgreementAtHeight::new(40))
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
fn restart_preserves_genesis_after_pruning() {
    run_crash_restart(TestEngineDefinition::new(NUM_VALIDATORS).with_aggressive_pruning());
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn restart_replays_finalizations_archived_before_acknowledgement() {
    run_restart_with_archived_finalizations();
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

#[test_group("slow")]
#[test_traced("DEBUG")]
fn secondaries_sync_with_primaries() {
    run_secondaries_sync(TestEngineDefinition::new(NUM_VALIDATORS).with_secondaries(2));
}

#[test_group("slow")]
#[test_traced("DEBUG")]
fn secondaries_sync_with_discovery_split() {
    run_secondaries_sync(
        TestEngineDefinition::new(NUM_VALIDATORS)
            .with_secondaries(2)
            .with_discovery_split(),
    );
}
