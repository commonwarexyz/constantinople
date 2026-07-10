use crate::{
    ThresholdScheme,
    types::{EngineBlock, EngineMarshalMailbox},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Reporter,
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
use commonware_runtime::{BufferPooler, Clock, Metrics, Quota, Storage};
use commonware_storage::metadata::{Config as MetadataConfig, Metadata};
use commonware_utils::{Acknowledgement, N3f1, TryCollect, channel::mpsc, sequence::U64, test_rng};
use std::collections::BTreeMap;

pub(crate) type TestHasher = Sha256;
pub(crate) type TestPrivateKey = ed25519::PrivateKey;
pub(crate) type TestPublicKey = ed25519::PublicKey;
pub(crate) type TestScheme = ThresholdScheme<TestPublicKey, MinSig>;
pub(crate) type TestBlock = EngineBlock<TestHasher, TestPublicKey>;
pub(crate) type TestMarshalMailbox = EngineMarshalMailbox<TestHasher, TestPublicKey, MinSig>;
pub(crate) const TRANSACTION_NAMESPACE: &[u8] = b"constantinople-engine-test-transactions";
const STATE_SYNC_METADATA_SUFFIX: &str = "_state_sync_metadata";
const SYNC_DONE_KEY: U64 = U64::new(0);
pub(crate) const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoopReporter;

impl Reporter for NoopReporter {
    type Activity = marshal::Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let marshal::Update::Block(_, response) = activity {
            Acknowledgement::acknowledge(response);
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

pub(crate) async fn state_sync_done(
    context: &(impl BufferPooler + Storage + Clock + Metrics),
    partition_prefix: &str,
) -> bool {
    let metadata = Metadata::<_, U64, bool>::init(
        context.child("state_sync_done"),
        MetadataConfig {
            partition: format!("{partition_prefix}{STATE_SYNC_METADATA_SUFFIX}"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to read state sync metadata");

    metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false)
}
