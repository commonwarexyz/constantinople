use crate::{
    ThresholdScheme,
    types::{EngineBlock, EngineMarshalMailbox},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable, Reporter,
    marshal::{self, Identifier},
    types::{Height, View},
};
use commonware_cryptography::{
    Digestible, Signer,
    bls12381::{
        dkg::feldman_desmedt::{Output, deal},
        primitives::{group::Share, variant::MinSig},
    },
    ed25519,
    sha256::Sha256,
};
use commonware_glue::simulate::{processed::ProcessedHeight, tracker::FinalizationUpdate};
use commonware_runtime::Quota;
use commonware_utils::{
    Acknowledgement, N3f1, TryCollect, acknowledgement::Exact, channel::mpsc, sync::Mutex, test_rng,
};
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
pub(crate) type TestScheme = ThresholdScheme<TestPublicKey, MinSig>;
pub(crate) type TestBlock = EngineBlock<TestHasher, TestPublicKey>;
pub(crate) type TestMarshalMailbox = EngineMarshalMailbox<TestHasher, TestPublicKey, MinSig>;
pub(crate) const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-engine-test-transactions";
pub(crate) const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

#[derive(Clone, Default)]
pub(crate) struct RestartBarrier {
    held: Arc<Mutex<Vec<Exact>>>,
    released: Arc<AtomicBool>,
    starts: Arc<AtomicUsize>,
    latest_finalized: Arc<AtomicU64>,
    recovered_finalized: Arc<AtomicU64>,
    observed_processed: Arc<Mutex<Option<u64>>>,
}

impl RestartBarrier {
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
        if block_height == 0 || self.released.load(Ordering::SeqCst) {
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

#[derive(Clone, Default)]
pub(crate) struct TestReporter {
    restart_barrier: Option<RestartBarrier>,
}

impl TestReporter {
    pub(crate) const fn new(restart_barrier: Option<RestartBarrier>) -> Self {
        Self { restart_barrier }
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
    monitor: mpsc::Sender<FinalizationUpdate<TestPublicKey>>,
    public_key: TestPublicKey,
}

impl<R> HeightMonitorReporter<R> {
    pub(crate) const fn new(
        public_key: TestPublicKey,
        monitor: mpsc::Sender<FinalizationUpdate<TestPublicKey>>,
        inner: R,
    ) -> Self {
        Self {
            inner,
            monitor,
            public_key,
        }
    }
}

type Fixture = (
    Vec<TestPrivateKey>,
    Output<MinSig, TestPublicKey>,
    BTreeMap<TestPublicKey, Option<Share>>,
);

impl<R> Reporter for HeightMonitorReporter<R>
where
    R: Reporter<Activity = marshal::Update<TestBlock>>,
{
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Tip(_, height, digest) = &activity {
            let monitor = self.monitor.clone();
            let update = FinalizationUpdate {
                pk: self.public_key.clone(),
                view: View::new(height.get()),
                block_digest: digest.as_ref().to_vec(),
            };
            let _ = monitor.try_send(update);
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
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

impl ProcessedHeight for ValidatorState {
    async fn processed_height(&self) -> u64 {
        self.processed_height().await
    }
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

    let mut rng = test_rng();
    let (output, shares) = deal::<MinSig, _, N3f1>(&mut rng, Default::default(), participants)
        .expect("fixture deal should succeed");
    let shares = shares
        .into_iter()
        .map(|(public_key, share)| (public_key, Some(share)))
        .collect();

    (signers, output, shares)
}
