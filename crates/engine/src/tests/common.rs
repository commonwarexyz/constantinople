use crate::{
    Scheme,
    block::ApplicationBlock,
    types::{EngineCommitment, EngineMarshalMailbox},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable, Reporter,
    marshal::{self, Identifier},
    types::Height,
};
use commonware_cryptography::{
    Digestible, Signer, ed25519,
    sha256::{self, Sha256},
};
use commonware_glue::simulate::{processed::ProcessedHeight, tracker::FinalizationUpdate};
use commonware_runtime::Quota;
use commonware_utils::{
    Acknowledgement, TryCollect, acknowledgement::Exact, channel::mpsc, ordered::Set, sync::Mutex,
};
use constantinople_auth::{Submission, Tags};
use constantinople_mempool::{Candidate, TransactionSource};
use constantinople_primitives::{Header, Transaction, TransactionPublicKey};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

pub(crate) type TestHasher = Sha256;
pub(crate) type TestPrivateKey = ed25519::PrivateKey;
pub(crate) type TestPublicKey = ed25519::PublicKey;
pub(crate) type TestScheme = Scheme;
pub(crate) type TestBlock = ApplicationBlock<TestHasher, TestPublicKey>;
pub(crate) type TestMarshalMailbox = EngineMarshalMailbox<TestHasher, TestPublicKey>;
pub(crate) const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-engine-test-transactions";
pub(crate) const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

#[derive(Clone, Default)]
pub(crate) struct RestartBarrier {
    processed_height: u64,
    held: Arc<Mutex<Vec<Exact>>>,
    released: Arc<AtomicBool>,
    starts: Arc<AtomicUsize>,
    latest_finalized: Arc<AtomicU64>,
    recovered_finalized: Arc<AtomicU64>,
    observed_processed: Arc<Mutex<Option<u64>>>,
}

impl RestartBarrier {
    pub(crate) fn new(processed_height: u64) -> Self {
        Self {
            processed_height,
            ..Self::default()
        }
    }

    pub(crate) const fn processed_height(&self) -> u64 {
        self.processed_height
    }

    pub(crate) fn begin_start(&self) -> bool {
        let restarting = self.starts.fetch_add(1, Ordering::SeqCst) > 0;
        if !restarting {
            return false;
        }

        self.recovered_finalized.store(
            self.latest_finalized.load(Ordering::SeqCst),
            Ordering::SeqCst,
        );
        self.held.lock().clear();
        true
    }

    fn observe_finalized(&self, height: u64) {
        self.latest_finalized.fetch_max(height, Ordering::SeqCst);
    }

    fn acknowledge(&self, block_height: u64, acknowledgement: Exact) {
        if block_height <= self.processed_height || self.released.load(Ordering::SeqCst) {
            acknowledgement.acknowledge();
            return;
        }

        self.held.lock().push(acknowledgement);
    }

    pub(crate) fn observe_processed(&self, height: u64) {
        *self.observed_processed.lock() = Some(height);
    }

    pub(crate) fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        let acknowledgements = std::mem::take(&mut *self.held.lock());
        for acknowledgement in acknowledgements {
            acknowledgement.acknowledge();
        }
    }

    pub(crate) fn recovered_finalized(&self) -> u64 {
        self.recovered_finalized.load(Ordering::SeqCst)
    }

    pub(crate) fn observed_processed(&self) -> Option<u64> {
        *self.observed_processed.lock()
    }
}

#[derive(Clone)]
pub(crate) struct TestReporter {
    restart_barrier: Option<RestartBarrier>,
    /// Checks the outcomes that finalized blocks carry.
    source: TestSource,
}

impl TestReporter {
    pub(crate) const fn new(restart_barrier: Option<RestartBarrier>, source: TestSource) -> Self {
        Self {
            restart_barrier,
            source,
        }
    }
}

impl Reporter for TestReporter {
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            marshal::Update::Tip(_, height, _) => {
                if let Some(barrier) = &self.restart_barrier {
                    barrier.observe_finalized(height.get());
                }
            }
            marshal::Update::Block(block, response) => {
                self.source.finalized(Arc::new(block.inner().clone()));
                if let Some(barrier) = &self.restart_barrier {
                    barrier.acknowledge(block.height().get(), response);
                } else {
                    response.acknowledge();
                }
            }
        }
        Feedback::Ok
    }
}

#[derive(Clone)]
pub(crate) struct HeightMonitorReporter<R> {
    inner: R,
    monitor: mpsc::UnboundedSender<FinalizationUpdate<TestPublicKey>>,
    public_key: TestPublicKey,
}

impl<R> HeightMonitorReporter<R> {
    pub(crate) const fn new(
        public_key: TestPublicKey,
        monitor: mpsc::UnboundedSender<FinalizationUpdate<TestPublicKey>>,
        inner: R,
    ) -> Self {
        Self {
            inner,
            monitor,
            public_key,
        }
    }
}

/// The validators' signing keys, the validator set, and the X25519 secret of
/// each validator.
type Fixture = (
    Vec<TestPrivateKey>,
    Set<TestPublicKey>,
    BTreeMap<TestPublicKey, constantinople_auth::PrivateKey>,
);

impl<R> Reporter for HeightMonitorReporter<R>
where
    R: Reporter<Activity = marshal::Update<TestBlock>>,
{
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Tip(round, height, digest) = &activity {
            let update = FinalizationUpdate {
                pk: self.public_key.clone(),
                round: *round,
                height: *height,
                block_digest: digest.as_ref().to_vec(),
            };
            let _ = self.monitor.send(update);
        }

        self.inner.report(activity)
    }
}

#[derive(Clone)]
pub(crate) struct ValidatorState {
    pub(crate) marshal: TestMarshalMailbox,
    pub(crate) startup_sync_height: Option<u64>,
}

impl PartialEq for ValidatorState {
    fn eq(&self, other: &Self) -> bool {
        self.startup_sync_height == other.startup_sync_height
    }
}

impl Eq for ValidatorState {}

impl ValidatorState {
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<Vec<u8>> {
        self.marshal
            .get_block(Identifier::Height(Height::new(height)))
            .await
            .map(|block| block.digest().as_ref().to_vec())
    }

    pub(crate) async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed()
            .await
            .map_or(0, |processed| processed.height().get())
    }
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.processed_height().await
    }
}

/// The X25519 secret of the node whose signing key has seed `seed`.
pub(crate) fn secret(seed: u64) -> constantinople_auth::PrivateKey {
    let mut bytes = [0xa5; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    constantinople_auth::PrivateKey::from(bytes)
}

pub(crate) fn validator_fixture(validators: u32) -> Fixture {
    let signers = (0..validators)
        .map(|seed| TestPrivateKey::from_seed(seed.into()))
        .collect::<Vec<_>>();
    let participants = signers
        .iter()
        .map(TestPrivateKey::public_key)
        .try_collect()
        .unwrap();
    let secrets = signers
        .iter()
        .zip(0u64..)
        .map(|(signer, seed)| (signer.public_key(), secret(seed)))
        .collect();

    (signers, participants, secrets)
}

/// How a test transaction is authenticated, and what must become of it.
///
/// A transaction's value says which kind it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Signed. Applied.
    Signed = 1,
    /// Tagged by its sender for every validator. Applied.
    Tagged,
    /// Tagged by a faulty sender, with wrong tags for four of six validators.
    /// At most two validators approve it, so it is never applied.
    Mistagged,
    /// Listed by a proposer that does not hold the sender's keys, with tags of
    /// another sender. Never applied.
    Forged,
}

pub(crate) const KINDS: [Kind; 4] = [Kind::Signed, Kind::Tagged, Kind::Mistagged, Kind::Forged];

/// Seed of the account that sends the transaction of kind `kind` in the block
/// validator `validator` proposes at height `height`.
///
/// Every transaction has its own account, which starts with the default
/// balance, so an authentic one always applies.
const fn account_seed(validator: usize, kind: Kind, height: u64) -> u64 {
    (height << 16) | ((validator as u64) << 4) | kind as u64
}

/// The number of transactions whose outcome bit was checked, by [`Kind`],
/// over all the nodes of a test.
pub(crate) type Checked = Arc<Mutex<[u64; 5]>>;

/// Proposes one transaction of each [`Kind`] per block and checks the outcome
/// of each as blocks finalize.
#[derive(Clone)]
pub(crate) struct TestSource {
    /// This node's index among the test's signers.
    index: usize,
    /// This node's index among the validators, if it is one.
    me: Option<commonware_utils::Participant>,
    /// The validators' X25519 public keys, in participant order.
    validators: Arc<Vec<constantinople_auth::PublicKey>>,
    /// The last finalized block, whose transactions the next one executes.
    last: Arc<Mutex<Option<Arc<TestBlock>>>>,
    checked: Checked,
}

impl TestSource {
    /// `signers` are all the test's nodes, `participants` the validators among
    /// them, and `secrets` every node's X25519 secret.
    pub(crate) fn new(
        index: usize,
        signers: &[TestPrivateKey],
        participants: &Set<TestPublicKey>,
        secrets: &BTreeMap<TestPublicKey, constantinople_auth::PrivateKey>,
        checked: Checked,
    ) -> Self {
        let me = participants
            .position(&signers[index].public_key())
            .map(commonware_utils::Participant::from_usize);
        let validators = participants
            .iter()
            .map(|validator| secrets[validator].public_key())
            .collect();
        Self {
            index,
            me,
            validators: Arc::new(validators),
            last: Arc::default(),
            checked,
        }
    }

    /// The authenticator the holder of `secret` computes for a transaction with
    /// digest `digest` that it submits to this validator.
    fn authenticator(&self, secret: &constantinople_auth::PrivateKey, digest: &[u8]) -> Tags {
        let keys: Vec<_> = self
            .validators
            .iter()
            .map(|validator| {
                secret
                    .with_validator(TRANSACTION_NAMESPACE, validator)
                    .expect("test keys are not low order")
            })
            .collect();
        let proposer = self.me.expect("only validators propose");
        Submission::new(&keys, proposer, (), digest).authenticator
    }

    /// The transaction of kind `kind` for this validator's block at `height`.
    fn candidate(&self, kind: Kind, height: u64) -> Candidate<TestHasher> {
        let seed = account_seed(self.index, kind, height);
        let recipient =
            TransactionPublicKey::ed25519(TestPrivateKey::from_seed(u64::MAX).public_key());
        let value = std::num::NonZeroU64::new(kind as u64).expect("kinds start at one");
        let hasher = &mut TestHasher::default();
        if kind == Kind::Signed {
            let signer = TestPrivateKey::from_seed(seed);
            let sender = TransactionPublicKey::ed25519(signer.public_key());
            return Transaction::new(sender, recipient, value, 0)
                .seal_and_sign(&signer, TRANSACTION_NAMESPACE, hasher)
                .into();
        }

        let sender = TransactionPublicKey::x25519(secret(seed).public_key());
        let transaction = Transaction::new(sender, recipient, value, 0).seal_for_mac(hasher);
        let digest = *transaction.message_digest();
        let authenticator = match kind {
            // The proposer does not hold the sender's secret.
            Kind::Forged => self.authenticator(&secret(!seed), digest.as_ref()),
            Kind::Mistagged => {
                // The sender's tags for another transaction, for the four
                // validators after the proposer.
                let right = self.authenticator(&secret(seed), digest.as_ref());
                let other = self.authenticator(&secret(seed), &[0xff; 32]);
                let me = usize::from(self.me.expect("only validators propose"));
                let n = self.validators.len();
                let wrong: Vec<_> = (1..=4).map(|offset| (me + offset) % n).collect();
                let mut mixed = Tags::with_capacity(right.bits(), n);
                mixed.extend((0..n).map(|validator| {
                    let tags = if wrong.contains(&validator) {
                        &other
                    } else {
                        &right
                    };
                    tags.get(validator).expect("one tag per validator")
                }));
                mixed
            }
            _ => self.authenticator(&secret(seed), digest.as_ref()),
        };
        Candidate {
            transaction,
            authenticator: Some(authenticator),
        }
    }

    /// Records a finalized block and checks the outcome bits it carries for the
    /// transactions of the block before it.
    ///
    /// Blocks arrive in order, but a restart replays some and a state sync
    /// skips some: only a block that follows the last one is checked.
    pub(crate) fn finalized(&self, block: Arc<TestBlock>) {
        let mut last = self.last.lock();
        let height = block.header.height;
        match &*last {
            Some(last) if last.header.height >= height => return,
            Some(previous) if previous.header.height + 1 == height => {
                let mut checked = self.checked.lock();
                assert_eq!(previous.body.len() as u64, block.outcomes.len());
                for (position, lazy) in previous.body.iter().enumerate() {
                    let transaction = lazy.get().expect("finalized transactions decode");
                    let kind = KINDS[transaction.value().value.get() as usize - 1];
                    let applied = block.outcomes.get(position as u64);
                    assert_eq!(
                        applied,
                        matches!(kind, Kind::Signed | Kind::Tagged),
                        "{kind:?} transaction of height {}",
                        previous.header.height
                    );
                    checked[kind as usize] += 1;
                }
            }
            _ => {}
        }
        *last = Some(block);
    }
}

impl TransactionSource<EngineCommitment<TestHasher, TestPublicKey>, TestPublicKey, TestHasher>
    for TestSource
{
    async fn propose(
        &mut self,
        parent: &Header<EngineCommitment<TestHasher, TestPublicKey>, sha256::Digest, TestPublicKey>,
        _round: commonware_consensus::types::Round,
        _filled: usize,
    ) -> Vec<Candidate<TestHasher>> {
        KINDS
            .iter()
            .map(|kind| self.candidate(*kind, parent.height + 1))
            .collect()
    }
}

impl Reporter for TestSource {
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(block, acknowledgement) = activity {
            self.finalized(Arc::new(block.inner().clone()));
            acknowledgement.acknowledge();
        }
        Feedback::Ok
    }
}
