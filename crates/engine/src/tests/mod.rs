//! Deterministic end-to-end tests for the complete validator engine.

mod common;
mod dkg_integration;
mod plan;
mod properties;

use crate::{
    CERTIFICATE_CHANNEL, COMMITTEE_RESOLVER_CHANNEL, Channels, Config, DKG_CHANNEL,
    DKG_PROBE_CHANNEL, Engine, MARSHAL_CHANNEL, MARSHAL_RESOLVER_CHANNEL, RESOLVER_CHANNEL,
    STATE_RESOLVER_CHANNEL, StartupMode, TRANSACTION_RESOLVER_CHANNEL, VOTE_CHANNEL,
};
use common::{
    EpochFilteredReceiver, HeightTransactionSource, RecordingManager, TRANSACTION_NAMESPACE,
    TestHasher, TestPrivateKey, TestPublicKey, TestReporter, TrackLog, ValidatorState,
    validator_fixture,
};
use commonware_consensus::{
    Heightable as _,
    marshal::Identifier,
    simplex::elector::RoundRobin,
    types::{Epoch, Height, coding::Commitment},
};
use commonware_cryptography::{
    Committable as _, Signer as _,
    bls12381::{
        dkg::feldman_desmedt::Output,
        primitives::{group::Share, variant::MinSig},
    },
    ed25519::Batch as Ed25519Batch,
};
use commonware_glue::{
    dkg::{
        network::Addresses,
        types::{EpochInfo, EpochOutcome, Payload},
    },
    simulate::{
        engine::{EngineDefinition, InitContext},
        reporter::MonitorReporter,
    },
    stateful::db::SyncEngineConfig,
};
use commonware_p2p::{Address, simulated::Link};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock as _, Handle, Quota, Spawner as _, Supervisor as _};
use commonware_utils::{
    NZU32, NZU64, NZUsize,
    channel::oneshot,
    ordered::{Map, Set},
    sync::Mutex,
};
use constantinople_application::consensus::{Committee, FinalizedHookFn};
use constantinople_primitives::{
    PublicKeyCache, Transaction, TransactionPublicKey, VerifiedTransaction,
};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    net::SocketAddr,
    num::NonZeroU64,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tracing::warn;

pub(crate) const TEST_EPOCH_LENGTH: NonZeroU64 = NZU64!(64);
const ENGINE_NAMESPACE: &[u8] = b"constantinople-engine-test";
const DKG_NAMESPACE: &[u8] = b"constantinople-engine-test-dkg";
const MAX_MESSAGE_SIZE: u32 = 12 * 1024 * 1024;
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));
static NEXT_SECRET_ROOT: AtomicU64 = AtomicU64::new(0);

pub(crate) const fn final_height(epoch: u64) -> u64 {
    TEST_EPOCH_LENGTH.get() * (epoch + 1) - 1
}

pub(crate) const fn default_link() -> Link {
    Link {
        latency: Duration::from_millis(10),
        jitter: Duration::from_millis(5),
        success_rate: 1.0,
    }
}

fn address(index: usize) -> Address {
    Address::Symmetric(SocketAddr::from((
        [127, 0, 0, 1],
        20_000 + u16::try_from(index).expect("test peer index must fit in u16"),
    )))
}

fn directory(
    participants: &Set<TestPublicKey>,
    eligible: &Map<TestPublicKey, Address>,
) -> Addresses<TestPublicKey> {
    participants
        .iter()
        .map(|peer| {
            (
                peer.clone(),
                eligible
                    .get_value(peer)
                    .expect("eligible peer must have an address")
                    .clone(),
            )
        })
        .collect()
}

#[derive(Clone)]
pub(crate) struct TestEngineDefinition {
    signers: Vec<TestPrivateKey>,
    output: Output<MinSig, TestPublicKey>,
    shares: BTreeMap<TestPublicKey, Option<Share>>,
    genesis: EpochInfo<MinSig, TestPublicKey, Addresses<TestPublicKey>>,
    eligible: Map<TestPublicKey, Address>,
    proposals: BTreeMap<u64, Vec<VerifiedTransaction<TestHasher>>>,
    failures: Arc<HashSet<u64>>,
    processed: Arc<Mutex<BTreeMap<TestPublicKey, u64>>>,
    holds: Arc<Mutex<BTreeMap<TestPublicKey, VecDeque<u64>>>>,
    starts: Arc<Mutex<BTreeMap<TestPublicKey, usize>>>,
    tracks: TrackLog,
    secret_root: Arc<PathBuf>,
}

impl TestEngineDefinition {
    pub(crate) fn rotating() -> Self {
        let (mut signers, output, mut shares) = validator_fixture(4);
        let added = TestPrivateKey::from_seed(1_000_000);
        shares.insert(added.public_key(), None);
        signers.push(added);
        let joining = TestPrivateKey::from_seed(1_000_001);
        shares.insert(joining.public_key(), None);
        signers.push(joining);

        let initial = output.players().clone();
        let eligible = Map::from_iter_dedup(
            signers
                .iter()
                .enumerate()
                .map(|(index, signer)| (signer.public_key(), address(index))),
        );
        let genesis = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output: output.clone(),
            players: initial.clone(),
            next_players: initial.clone(),
            directory: directory(&initial, &eligible),
        };

        let sender = &signers[1];
        let sender_key = TransactionPublicKey::ed25519(sender.public_key());
        let first_update = vec![
            Transaction::set_committee_member(
                sender_key.clone(),
                Epoch::new(2),
                signers[4].public_key(),
                true,
                0,
            )
            .seal_and_sign(sender, TRANSACTION_NAMESPACE, &mut TestHasher::default()),
            Transaction::set_committee_member(
                sender_key.clone(),
                Epoch::new(2),
                signers[0].public_key(),
                false,
                1,
            )
            .seal_and_sign(sender, TRANSACTION_NAMESPACE, &mut TestHasher::default()),
        ];
        let second_update = vec![
            Transaction::set_committee_member(
                sender_key.clone(),
                Epoch::new(3),
                signers[5].public_key(),
                true,
                2,
            )
            .seal_and_sign(sender, TRANSACTION_NAMESPACE, &mut TestHasher::default()),
            Transaction::set_committee_member(
                sender_key,
                Epoch::new(3),
                signers[1].public_key(),
                false,
                3,
            )
            .seal_and_sign(sender, TRANSACTION_NAMESPACE, &mut TestHasher::default()),
        ];
        let proposals =
            BTreeMap::from([(1, first_update), (TEST_EPOCH_LENGTH.get(), second_update)]);

        Self::from_parts(signers, output, shares, genesis, eligible, proposals)
    }

    pub(crate) fn stable() -> Self {
        let (signers, output, shares) = validator_fixture(7);
        let initial = output.players().clone();
        let eligible = Map::from_iter_dedup(
            signers
                .iter()
                .enumerate()
                .map(|(index, signer)| (signer.public_key(), address(index))),
        );
        let genesis = EpochInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output: output.clone(),
            players: initial.clone(),
            next_players: initial.clone(),
            directory: directory(&initial, &eligible),
        };
        Self::from_parts(signers, output, shares, genesis, eligible, BTreeMap::new())
    }

    fn from_parts(
        signers: Vec<TestPrivateKey>,
        output: Output<MinSig, TestPublicKey>,
        shares: BTreeMap<TestPublicKey, Option<Share>>,
        genesis: EpochInfo<MinSig, TestPublicKey, Addresses<TestPublicKey>>,
        eligible: Map<TestPublicKey, Address>,
        proposals: BTreeMap<u64, Vec<VerifiedTransaction<TestHasher>>>,
    ) -> Self {
        let id = NEXT_SECRET_ROOT.fetch_add(1, Ordering::Relaxed);
        let secret_root = std::env::temp_dir().join(format!(
            "constantinople-engine-e2e-{}-{id}",
            std::process::id(),
        ));
        if secret_root.exists() {
            std::fs::remove_dir_all(&secret_root)
                .expect("stale test secret root must be removable");
        }

        Self {
            signers,
            output,
            shares,
            genesis,
            eligible,
            proposals,
            failures: Arc::default(),
            processed: Arc::default(),
            holds: Arc::default(),
            starts: Arc::default(),
            tracks: Arc::default(),
            secret_root: Arc::new(secret_root),
        }
    }

    pub(crate) fn with_failures(mut self, epochs: impl IntoIterator<Item = u64>) -> Self {
        self.failures = Arc::new(epochs.into_iter().collect());
        self
    }

    pub(crate) fn with_holds(
        self,
        participant: TestPublicKey,
        heights: impl IntoIterator<Item = u64>,
    ) -> Self {
        self.holds
            .lock()
            .insert(participant, heights.into_iter().collect());
        self
    }

    pub(crate) fn initial_players(&self) -> Set<TestPublicKey> {
        self.output.players().clone()
    }

    pub(crate) fn updated_players(&self) -> Set<TestPublicKey> {
        let mut committee =
            Committee::new(self.initial_players()).expect("initial committee must be valid");
        committee
            .assign(self.signers[4].public_key(), true)
            .expect("joining peer must be assignable");
        committee
            .assign(self.signers[0].public_key(), false)
            .expect("leaving peer must be removable");
        committee.into_members()
    }

    pub(crate) fn final_players(&self) -> Set<TestPublicKey> {
        let mut committee =
            Committee::new(self.updated_players()).expect("updated committee must be valid");
        committee
            .assign(self.signers[5].public_key(), true)
            .expect("future joining peer must be assignable");
        committee
            .assign(self.signers[1].public_key(), false)
            .expect("second leaving peer must be removable");
        committee.into_members()
    }

    pub(crate) fn joining(&self) -> TestPublicKey {
        self.signers[5].public_key()
    }

    pub(crate) fn leaving(&self) -> TestPublicKey {
        self.signers[0].public_key()
    }

    pub(crate) fn starts(&self) -> Arc<Mutex<BTreeMap<TestPublicKey, usize>>> {
        self.starts.clone()
    }

    pub(crate) fn secret_path(&self, participant: &TestPublicKey) -> Arc<PathBuf> {
        let index = self
            .signers
            .iter()
            .position(|signer| &signer.public_key() == participant)
            .expect("test participant must have a signer identity");
        Arc::new(self.secret_root.join(index.to_string()))
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
            (COMMITTEE_RESOLVER_CHANNEL, TEST_QUOTA),
            (DKG_CHANNEL, TEST_QUOTA),
            (DKG_PROBE_CHANNEL, TEST_QUOTA),
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            delayed,
            public_key,
            oracle,
            channels,
            monitor,
            ..
        } = ctx;
        let public_key = public_key.clone();
        let signer = self.signers[index].clone();
        let share = self.shares.get(&public_key).cloned().flatten();
        let output = self.output.clone();
        let genesis = self.genesis.clone();
        let eligible = self.eligible.clone();
        let proposals = self.proposals.clone();
        let failures = self.failures.clone();
        let processed = self.processed.clone();
        let holds = self.holds.clone();
        let tracks = self.tracks.clone();
        let starts = self.starts.clone();
        let secret_root = self.secret_root.clone();
        let partition_prefix = format!("validator-{index}");
        let genesis_leader = self.signers[0].public_key();
        let manager =
            RecordingManager::new(oracle.socket_manager(), public_key.clone(), tracks.clone());
        let blocker = oracle.control(public_key.clone());
        let (state_sender, state_receiver) = oneshot::channel();

        let restarting = {
            let mut starts = starts.lock();
            let count = starts.entry(public_key.clone()).or_default();
            let restarting = *count > 0;
            *count += 1;
            restarting
        };
        if restarting {
            let mut holds = holds.lock();
            if let Some(heights) = holds.get_mut(&public_key) {
                heights.pop_front();
            }
        }

        let handle = context.child("validator").spawn(move |context| async move {
            let mut channels = channels.into_iter();
            let pass = |(sender, receiver)| (sender, EpochFilteredReceiver::pass(receiver));
            let votes = pass(channels.next().expect("vote channel must exist"));
            let certificates = pass(channels.next().expect("certificate channel must exist"));
            let resolver = pass(channels.next().expect("resolver channel must exist"));
            let marshal = pass(channels.next().expect("marshal channel must exist"));
            let marshal_resolver = pass(
                channels
                    .next()
                    .expect("marshal resolver channel must exist"),
            );
            let state_resolver = pass(channels.next().expect("state resolver channel must exist"));
            let transaction_resolver = pass(
                channels
                    .next()
                    .expect("transaction resolver channel must exist"),
            );
            let committee_resolver = pass(
                channels
                    .next()
                    .expect("committee resolver channel must exist"),
            );
            let (dkg_sender, dkg_receiver) = channels.next().expect("DKG channel must exist");
            let dkg = (
                dkg_sender,
                EpochFilteredReceiver::drop_epochs(dkg_receiver, failures),
            );
            let probe_network = pass(channels.next().expect("probe channel must exist"));
            assert!(channels.next().is_none(), "unexpected extra channel");

            let startup = if delayed {
                StartupMode::StateSync
            } else {
                StartupMode::MarshalSync
            };
            let channels = Channels {
                votes,
                certificates,
                resolver,
                marshal,
                marshal_resolver,
                state_resolver,
                transaction_resolver,
                committee_resolver,
                dkg,
            };
            let input = HeightTransactionSource::new(proposals);
            let hook_context = context.child("finalized_hook");
            let hook_key = public_key.clone();
            let hook_processed = processed.clone();
            let hook_holds = holds.clone();
            let finalized_hook: FinalizedHookFn<
                _,
                Commitment,
                TestHasher,
                TestPublicKey,
                Payload<MinSig, TestPrivateKey, Addresses<TestPublicKey>>,
                Sequential,
            > = Arc::new(move |block, _| {
                let height = block.height().get();
                let context = hook_context.child("block");
                let public_key = hook_key.clone();
                let processed = hook_processed.clone();
                let holds = hook_holds.clone();
                Box::pin(async move {
                    processed.lock().insert(public_key.clone(), height);
                    if height % TEST_EPOCH_LENGTH.get() == TEST_EPOCH_LENGTH.get() - 1 {
                        warn!(validator = %public_key, height, "test engine finalized boundary");
                    }
                    loop {
                        let held = holds
                            .lock()
                            .get(&public_key)
                            .and_then(VecDeque::front)
                            .is_some_and(|held| height >= *held);
                        if !held {
                            break;
                        }
                        context.sleep(Duration::from_millis(25)).await;
                    }
                })
            });
            let secret_path = secret_root.join(index.to_string());
            let secret_store = crate::secret_store::FileSecretStore::load(&secret_path)
                .expect("test secret store must initialize");
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
                context.child("engine"),
                Config {
                    signer,
                    manager,
                    blocker,
                    namespace: ENGINE_NAMESPACE.to_vec(),
                    output,
                    share,
                    genesis,
                    eligible_peers: eligible,
                    secret_store,
                    dkg_namespace: DKG_NAMESPACE,
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
                    prune_config: None,
                    genesis_leader,
                    transaction_namespace: TRANSACTION_NAMESPACE,
                    block_codec: constantinople_primitives::BlockCfg {
                        max_transactions: commonware_codec::RangeCfg::new(0..=usize::MAX),
                        payload: (
                            NZU32!(64),
                            commonware_cryptography::bls12381::primitives::sharing::ModeVersion::v0(
                            ),
                            commonware_codec::RangeCfg::new(0..=192),
                        ),
                    },
                    prunable_items_per_section: NZU64!(4096),
                    state_page_cache_bytes: 32 * 1024 * 1024,
                    other_page_cache_bytes: 32 * 1024 * 1024,
                    blocks_per_epoch: TEST_EPOCH_LENGTH,
                    simplex_timeouts: crate::SimplexTimeouts {
                        leader: Duration::from_secs(1),
                        certification: Duration::from_secs(2),
                        retry: Duration::from_millis(500),
                        fetch: Duration::from_secs(2),
                        skip: Duration::from_secs(5),
                    },
                    finalized_hook: Some(finalized_hook),
                },
                probe_network,
            )
            .await;

            let genesis_commitment = engine.genesis_commitment();
            let marshal = engine.marshal_mailbox();
            let committee = engine.subscribe_committee_detached();
            let committee_cell = Arc::new(std::sync::OnceLock::new());
            let reporter = MonitorReporter::new(public_key.clone(), monitor, TestReporter);
            let engine_handle = engine.start(channels, Some(reporter));
            if !delayed {
                let stored_genesis = marshal
                    .get_block(Identifier::Height(Height::zero()))
                    .await
                    .expect("marshal-sync engine must retain genesis");
                assert_eq!(
                    stored_genesis.commitment(),
                    genesis_commitment,
                    "engine genesis commitment must identify marshal genesis",
                );
            }

            if state_sender
                .send(ValidatorState {
                    public_key: public_key.clone(),
                    marshal,
                    committee: committee_cell.clone(),
                    processed,
                    tracks,
                })
                .is_err()
            {
                warn!(validator = %public_key, "validator state receiver dropped");
                return;
            }
            context
                .child("committee_attacher")
                .spawn(move |_| async move {
                    let database = committee.await;
                    let _ = committee_cell.set(database);
                });

            if let Err(error) = engine_handle.await {
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

pub(crate) fn plan(engine: TestEngineDefinition) -> plan::Plan {
    plan::Plan::new(engine)
}
