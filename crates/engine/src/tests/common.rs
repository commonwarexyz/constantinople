use crate::types::{CommitteeSyncDb, EngineBlock, EngineCodedBlock, EngineMarshalMailbox};
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
    marshal::{self, Identifier},
    types::{Height, Round},
};
use commonware_cryptography::{
    Signer,
    bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::{group::Share, variant::MinSig},
    },
    ed25519,
    sha256::Sha256,
};
use commonware_glue::{dkg::types::Payload, simulate::processed::ProcessedHeight};
use commonware_p2p::{
    Address, AddressableManager, AddressableTrackedPeers, Message, PeerSetSubscription, Provider,
    Receiver, utils::mux,
};
use commonware_parallel::Sequential;
use commonware_runtime::deterministic;
use commonware_utils::{
    Acknowledgement as _, N3f1, TryCollect as _, ordered::Map, sync::Mutex, test_rng,
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use std::{
    collections::{BTreeMap, HashSet},
    future::{Future, ready},
    sync::{Arc, OnceLock},
};

pub(crate) type TestHasher = Sha256;
pub(crate) type TestPrivateKey = ed25519::PrivateKey;
pub(crate) type TestPublicKey = ed25519::PublicKey;
pub(crate) type TestBlock = EngineBlock<TestHasher, TestPrivateKey, MinSig>;
pub(crate) type TestCodedBlock = EngineCodedBlock<TestHasher, TestPrivateKey, MinSig>;
pub(crate) type TestMarshalMailbox = EngineMarshalMailbox<TestHasher, TestPrivateKey, MinSig>;
pub(crate) type TestCommitteeDatabase =
    CommitteeSyncDb<deterministic::Context, TestHasher, Sequential>;
pub(crate) type TestEpochInfo = commonware_glue::dkg::types::EpochInfo<
    MinSig,
    TestPublicKey,
    commonware_glue::dkg::network::Addresses<TestPublicKey>,
>;
pub(crate) const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-engine-test-transactions";

#[derive(Clone, Debug, Default)]
pub(crate) struct HeightTransactionSource {
    proposals: BTreeMap<u64, Vec<VerifiedTransaction<TestHasher>>>,
}

impl HeightTransactionSource {
    pub(crate) const fn new(
        proposals: BTreeMap<u64, Vec<VerifiedTransaction<TestHasher>>>,
    ) -> Self {
        Self { proposals }
    }
}

impl TransactionSource<commonware_consensus::types::coding::Commitment, TestPublicKey, TestHasher>
    for HeightTransactionSource
{
    fn propose(
        &mut self,
        parent: &Header<
            commonware_consensus::types::coding::Commitment,
            <TestHasher as commonware_cryptography::Hasher>::Digest,
            TestPublicKey,
        >,
        _round: Round,
        filled: usize,
    ) -> impl Future<Output = Vec<VerifiedTransaction<TestHasher>>> + Send {
        if filled > 0 {
            return ready(Vec::new());
        }
        ready(
            self.proposals
                .get(&(parent.height + 1))
                .cloned()
                .unwrap_or_default(),
        )
    }
}

impl Reporter for HeightTransactionSource {
    type Activity = marshal::Update<
        SealedBlock<commonware_consensus::types::coding::Commitment, TestPublicKey, TestHasher>,
    >;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

pub(crate) type TrackLog =
    Arc<Mutex<BTreeMap<TestPublicKey, Vec<(u64, AddressableTrackedPeers<TestPublicKey>)>>>>;

type Fixture = (
    Vec<TestPrivateKey>,
    Output<MinSig, TestPublicKey>,
    BTreeMap<TestPublicKey, Option<Share>>,
);

pub(crate) fn validator_fixture(validators: u32) -> Fixture {
    let signers = (0..validators)
        .map(|seed| TestPrivateKey::from_seed(seed.into()))
        .collect::<Vec<_>>();
    let participants = signers
        .iter()
        .map(TestPrivateKey::public_key)
        .try_collect()
        .unwrap();

    let mut rng = test_rng();
    let (output, shares) = deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
        .expect("fixture deal should succeed");
    let shares = shares
        .into_iter()
        .map(|(public_key, share)| (public_key, Some(share)))
        .collect();

    (signers, output, shares)
}

#[derive(Clone)]
pub(crate) struct ValidatorState {
    pub(crate) public_key: TestPublicKey,
    pub(crate) marshal: TestMarshalMailbox,
    pub(crate) committee: Arc<OnceLock<TestCommitteeDatabase>>,
    pub(crate) processed: Arc<Mutex<BTreeMap<TestPublicKey, u64>>>,
    pub(crate) tracks: TrackLog,
}

impl PartialEq for ValidatorState {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl Eq for ValidatorState {}

impl ValidatorState {
    pub(crate) async fn block_at_height(&self, height: u64) -> Option<TestCodedBlock> {
        self.marshal
            .get_block(Identifier::Height(Height::new(height)))
            .await
    }

    pub(crate) async fn processed_height(&self) -> u64 {
        self.processed
            .lock()
            .get(&self.public_key)
            .copied()
            .unwrap_or_default()
    }

    pub(crate) fn committee(&self) -> Result<TestCommitteeDatabase, String> {
        self.committee
            .get()
            .cloned()
            .ok_or_else(|| format!("committee database for {} is not attached", self.public_key))
    }

    pub(crate) async fn epoch_info_at_height(&self, height: u64) -> Option<TestEpochInfo> {
        use commonware_glue::dkg::ReshareBlock as _;

        let block = self.block_at_height(height).await?;
        match block.inner().payload()? {
            Payload::EpochInfo(info) => Some(info),
            Payload::DealerLog(_) => None,
        }
    }
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.processed_height().await
    }
}

#[derive(Clone)]
pub(crate) struct TestReporter;

impl commonware_consensus::Reporter for TestReporter {
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}

/// Records the exact address-bearing peer sets handed to the production
/// addressable manager while delegating them to simulated lookup networking.
#[derive(Clone, Debug)]
pub(crate) struct RecordingManager<M> {
    inner: M,
    public_key: TestPublicKey,
    tracks: TrackLog,
}

impl<M> RecordingManager<M> {
    pub(crate) const fn new(inner: M, public_key: TestPublicKey, tracks: TrackLog) -> Self {
        Self {
            inner,
            public_key,
            tracks,
        }
    }
}

impl<M> Provider for RecordingManager<M>
where
    M: Provider<PublicKey = TestPublicKey>,
{
    type PublicKey = TestPublicKey;

    async fn peer_set(&mut self, id: u64) -> Option<commonware_p2p::TrackedPeers<Self::PublicKey>> {
        self.inner.peer_set(id).await
    }

    async fn subscribe(&mut self) -> PeerSetSubscription<Self::PublicKey> {
        self.inner.subscribe().await
    }
}

impl<M> AddressableManager for RecordingManager<M>
where
    M: AddressableManager<PublicKey = TestPublicKey>,
{
    fn track<R>(&mut self, id: u64, peers: R) -> Feedback
    where
        R: Into<AddressableTrackedPeers<Self::PublicKey>> + Send,
    {
        let peers = peers.into();
        self.tracks
            .lock()
            .entry(self.public_key.clone())
            .or_default()
            .push((id, peers.clone()));
        self.inner.track(id, peers)
    }

    fn overwrite(&mut self, peers: Map<Self::PublicKey, Address>) -> Feedback {
        self.inner.overwrite(peers)
    }
}

#[derive(Debug)]
pub(crate) struct EpochFilteredReceiver<R> {
    inner: R,
    failures: Option<Arc<HashSet<u64>>>,
}

impl<R> EpochFilteredReceiver<R> {
    pub(crate) const fn pass(inner: R) -> Self {
        Self {
            inner,
            failures: None,
        }
    }

    pub(crate) const fn drop_epochs(inner: R, failures: Arc<HashSet<u64>>) -> Self {
        Self {
            inner,
            failures: Some(failures),
        }
    }
}

impl<R> Receiver for EpochFilteredReceiver<R>
where
    R: Receiver<PublicKey = TestPublicKey>,
{
    type Error = R::Error;
    type PublicKey = TestPublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let message = self.inner.recv().await?;
            let Some(failures) = &self.failures else {
                return Ok(message);
            };
            let (_, bytes) = &message;
            let (epoch, _) = mux::parse(bytes.clone()).expect("failed to parse DKG mux message");
            if !failures.contains(&epoch) {
                return Ok(message);
            }
        }
    }
}
