use std::{sync::Arc, time::Duration};

use bytes::{BufMut, Bytes, BytesMut};
use commonware_actor::Feedback;
use commonware_codec::{Buf, Decode, Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{
    marshal::{core::Actor, standard::Standard, Config as MarshalConfig, Start, Update},
    simplex::types::{Finalization, Finalize, Notarization, Notarize, Proposal},
    types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    Block as ConsensusBlock, CertifiableBlock, Heightable, Reporter,
};
use commonware_cryptography::{
    certificate::{mocks::Fixture, ConstantProvider},
    ed25519, sha256, Digest as _, Digestible, Hasher, Sha256, Signer,
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, tokio as cw_tokio, Runner as _, Supervisor as _,
};
use commonware_storage::archive::immutable;
use commonware_utils::{
    channel::{oneshot, oneshot::Sender as OneshotSender},
    non_empty,
    sync::Mutex,
    vec::NonEmptyVec,
    Acknowledgement as _, NZUsize, TestRng, NZU16, NZU64,
};
use exoware_sdk::{
    PrefixedStoreClient, RetryConfig, StoreBatchUpload, StoreClient, StoreWriteBatch,
};
use exoware_simplex::{
    init_marshal_resolver, keys, Finalized, Notarized, SimplexClient, SimplexError,
};

const NAMESPACE: &[u8] = b"_EXOWARE_SIMPLEX_TEST";

type Scheme = commonware_consensus::simplex::scheme::ed25519::Scheme;
type Sha256Digest = sha256::Digest;
type PublicKey = ed25519::PublicKey;
type Context = commonware_consensus::simplex::types::Context<Sha256Digest, PublicKey>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestBlock {
    context: Context,
    parent: Sha256Digest,
    height: Height,
    payload: Vec<u8>,
    digest: Sha256Digest,
}

impl TestBlock {
    fn new(height: u64, payload: &[u8]) -> Self {
        Self::with_parent(height, Sha256Digest::EMPTY, payload)
    }

    fn with_parent(height: u64, parent: Sha256Digest, payload: &[u8]) -> Self {
        let context = Context {
            round: Round::new(Epoch::zero(), View::new(height)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(height.saturating_sub(1)), parent),
        };
        let mut block = Self {
            context,
            parent,
            height: Height::new(height),
            payload: payload.to_vec(),
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        block
    }

    fn compute_digest(&self) -> Sha256Digest {
        let mut header = BytesMut::with_capacity(self.encode_size());
        self.write(&mut header);
        Sha256::hash(&[&header])
    }
}

#[derive(Clone)]
struct SinkReporter {
    expected: usize,
    delivered: Arc<Mutex<Vec<TestBlock>>>,
    done: Arc<Mutex<Option<OneshotSender<Vec<TestBlock>>>>>,
}

impl SinkReporter {
    fn new(expected: usize) -> (Self, oneshot::Receiver<Vec<TestBlock>>) {
        let (sender, receiver) = oneshot::channel();
        (
            Self {
                expected,
                delivered: Arc::default(),
                done: Arc::new(Mutex::new(Some(sender))),
            },
            receiver,
        )
    }
}

impl Reporter for SinkReporter {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, ack) = activity {
            let mut delivered = self.delivered.lock();
            delivered.push(Arc::unwrap_or_clone(block));
            if delivered.len() == self.expected {
                if let Some(sender) = self.done.lock().take() {
                    let _ = sender.send(delivered.clone());
                }
            }
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

impl Write for TestBlock {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.payload.write(buf);
    }
}

impl Read for TestBlock {
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_payload_len: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(buf)?;
        let parent = Sha256Digest::read(buf)?;
        let height = Height::read(buf)?;
        let payload = Vec::<u8>::read_cfg(buf, &((..=*max_payload_len).into(), ()))?;
        let mut block = Self {
            context,
            parent,
            height,
            payload,
            digest: Sha256Digest::EMPTY,
        };
        block.digest = block.compute_digest();
        Ok(block)
    }
}

impl EncodeSize for TestBlock {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.payload.encode_size()
    }
}

impl Digestible for TestBlock {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for TestBlock {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for TestBlock {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl CertifiableBlock for TestBlock {
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

/// Spawns a local simulator and returns a client for it.
async fn local_store_client() -> StoreClient {
    let (_task, url) = exoware_simulator::open_temp()
        .await
        .expect("spawn simulator");
    StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("store client")
}

fn schemes() -> Vec<Scheme> {
    let mut rng = TestRng::new(7);
    let Fixture { schemes, .. } =
        commonware_consensus::simplex::scheme::ed25519::fixture(&mut rng, NAMESPACE, 4);
    schemes
}

fn proposal(block: &TestBlock) -> Proposal<Sha256Digest> {
    Proposal::new(block.context.round, block.context.parent.0, block.digest())
}

fn notarized(block: TestBlock, schemes: &[Scheme]) -> Notarized<TestBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
        .collect();
    let proof = Notarization::from_notarizes(&schemes[0], non_empty![@&votes], &Sequential)
        .expect("notarization");
    Notarized::new(proof, block).expect("notarized")
}

fn finalized(block: TestBlock, schemes: &[Scheme]) -> Finalized<TestBlock, Scheme, Sha256Digest> {
    let proposal = proposal(&block);
    let votes: Vec<_> = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize"))
        .collect();
    let proof = Finalization::from_finalizes(&schemes[0], non_empty![@&votes], &Sequential)
        .expect("finalization");
    Finalized::new(proof, block).expect("finalized")
}

#[tokio::test]
async fn uploads_and_reads_notarized_and_finalized_blocks() {
    let store = local_store_client().await;
    let simplex = SimplexClient::new(PrefixedStoreClient::empty(store));
    let schemes = schemes();

    let block1 = TestBlock::new(1, b"notarized");
    let notarized = notarized(block1.clone(), &schemes);
    let receipt = simplex
        .upload_notarized(&notarized)
        .await
        .expect("upload notarized");
    assert_eq!(receipt.summary.headers, 1);
    assert_eq!(receipt.summary.blocks, 0);
    assert_eq!(receipt.summary.notarizations, 1);

    let got_header = simplex
        .get_header::<TestBlock, Sha256Digest>(&block1.digest(), &1024)
        .await
        .expect("get header")
        .expect("header exists");
    assert_eq!(got_header, block1);

    let got_notarized = simplex
        .get_notarized_by_round::<TestBlock, Scheme, Sha256Digest>(
            block1.context.round,
            &(10, 1024),
        )
        .await
        .expect("get notarized")
        .expect("notarized exists");
    assert_eq!(got_notarized, notarized);

    let block2 = TestBlock::new(2, b"finalized");
    let body = Bytes::from_static(b"finalized transaction body");
    simplex
        .upload_block(&block2, body.clone())
        .await
        .expect("upload block");
    let finalized = finalized(block2.clone(), &schemes);
    let receipt = simplex
        .upload_finalized(&finalized)
        .await
        .expect("upload finalized");
    assert_eq!(receipt.summary.headers, 1);
    assert_eq!(receipt.summary.blocks, 0);
    assert_eq!(receipt.summary.finalizations, 1);
    assert_eq!(receipt.summary.finalized_height_indexes, 1);

    let got_block = simplex
        .get_block::<TestBlock, Sha256Digest>(&block2.digest(), &1024)
        .await
        .expect("get full block")
        .expect("full block exists");
    assert_eq!(got_block.header, block2);
    assert_eq!(got_block.body, body);

    let got_finalized = simplex
        .get_finalized_by_height::<TestBlock, Scheme, Sha256Digest>(Height::new(2), &(10, 1024))
        .await
        .expect("get finalized")
        .expect("finalized exists");
    assert_eq!(got_finalized, finalized);

    let got_finalized = simplex
        .get_finalized_by_round::<TestBlock, Scheme, Sha256Digest>(
            block2.context.round,
            &(10, 1024),
        )
        .await
        .expect("get finalized by round")
        .expect("finalized by round exists");
    assert_eq!(got_finalized, finalized);

    let latest = simplex
        .latest_finalized::<TestBlock, Scheme, Sha256Digest>(&(10, 1024))
        .await
        .expect("latest finalized")
        .expect("latest exists");
    assert_eq!(latest, finalized);
}

#[tokio::test]
async fn prepared_uploads_can_share_one_store_batch() {
    let store = local_store_client().await;
    let simplex = SimplexClient::new(PrefixedStoreClient::empty(store.clone()));
    let schemes = schemes();

    let first = finalized(TestBlock::new(10, b"first"), &schemes);
    let second = finalized(TestBlock::new(11, b"second"), &schemes);

    let mut prepared = simplex.prepare_finalized(&first).expect("first");
    prepared.extend(simplex.prepare_finalized(&second).expect("second"));

    let receipt = simplex
        .commit_upload(prepared)
        .await
        .expect("commit combined");
    assert_eq!(receipt.summary.headers, 2);
    assert_eq!(receipt.summary.blocks, 0);
    assert_eq!(receipt.summary.finalizations, 2);

    let latest = simplex
        .latest_finalized_raw()
        .await
        .expect("latest finalized")
        .expect("latest exists");
    let latest = Finalized::<TestBlock, Scheme, Sha256Digest>::decode_cfg(latest, &(10, 1024))
        .expect("decode latest");
    assert_eq!(latest, second);
}

#[tokio::test]
async fn marshal_resolver_sinks_finalized_chain_from_simplex_api() {
    const BLOCKS_TO_PROCESS: u64 = 5;

    let store = local_store_client().await;
    let simplex = SimplexClient::new(PrefixedStoreClient::empty(store));
    let schemes = schemes();

    let genesis = TestBlock::new(0, b"genesis");
    let mut expected_blocks = Vec::new();
    expected_blocks.push(genesis.clone());
    let mut parent = genesis.digest();
    for height in 1..=BLOCKS_TO_PROCESS {
        let block =
            TestBlock::with_parent(height, parent, format!("from-simplex-{height}").as_bytes());
        parent = block.digest();
        let finalized = finalized(block.clone(), &schemes);
        simplex
            .upload_finalized(&finalized)
            .await
            .expect("upload finalized");
        expected_blocks.push(block);
    }

    let delivered = tokio::task::spawn_blocking({
        let simplex = simplex.clone();
        let genesis = genesis.clone();
        move || {
            cw_tokio::Runner::default().start(|context| async move {
                let partition_prefix = "simplex-marshal-resolver-sink";
                let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
                let config: MarshalConfig<_, _, _, TestBlock, TestBlock> = MarshalConfig {
                    provider: ConstantProvider::new(schemes[0].clone()),
                    epocher: FixedEpocher::new(NZU64!(100)),
                    start: Start::Genesis(genesis),
                    partition_prefix: partition_prefix.to_string(),
                    mailbox_size: NZUsize!(100),
                    view_retention: ViewDelta::new(10),
                    prunable_items_per_section: NZU64!(10),
                    page_cache,
                    replay_buffer: NZUsize!(1024),
                    key_write_buffer: NZUsize!(1024),
                    value_write_buffer: NZUsize!(1024),
                    block_codec_config: 1024,
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                };

                let finalizations_by_height: immutable::Archive<
                    _,
                    Sha256Digest,
                    Finalization<Scheme, Sha256Digest>,
                > = immutable::Archive::init(
                    context.child("finalizations_by_height"),
                    immutable::Config {
                        metadata_partition: format!(
                            "{partition_prefix}-finalizations-by-height-metadata"
                        ),
                        freezer_table_partition: format!(
                            "{partition_prefix}-finalizations-by-height-freezer-table"
                        ),
                        freezer_table_initial_size: 64,
                        freezer_table_resize_frequency: 10,
                        freezer_table_resize_chunk_size: 10,
                        freezer_key_partition: format!(
                            "{partition_prefix}-finalizations-by-height-freezer-key"
                        ),
                        freezer_key_page_cache: config.page_cache.clone(),
                        freezer_value_partition: format!(
                            "{partition_prefix}-finalizations-by-height-freezer-value"
                        ),
                        freezer_value_target_size: 1024,
                        freezer_value_compression: None,
                        ordinal_partition: format!(
                            "{partition_prefix}-finalizations-by-height-ordinal"
                        ),
                        items_per_section: NZU64!(10),
                        codec_config: <Scheme as commonware_cryptography::certificate::Verifier>::certificate_codec_config_unbounded(),
                        replay_buffer: config.replay_buffer,
                        freezer_key_write_buffer: config.key_write_buffer,
                        freezer_value_write_buffer: config.value_write_buffer,
                        ordinal_write_buffer: config.key_write_buffer,
                    },
                )
                .await
                .expect("init finalizations archive");

                let finalized_blocks: immutable::Archive<_, Sha256Digest, TestBlock> =
                    immutable::Archive::init(
                    context.child("finalized_blocks"),
                    immutable::Config {
                        metadata_partition: format!("{partition_prefix}-finalized-blocks-metadata"),
                        freezer_table_partition: format!(
                            "{partition_prefix}-finalized-blocks-freezer-table"
                        ),
                        freezer_table_initial_size: 64,
                        freezer_table_resize_frequency: 10,
                        freezer_table_resize_chunk_size: 10,
                        freezer_key_partition: format!(
                            "{partition_prefix}-finalized-blocks-freezer-key"
                        ),
                        freezer_key_page_cache: config.page_cache.clone(),
                        freezer_value_partition: format!(
                            "{partition_prefix}-finalized-blocks-freezer-value"
                        ),
                        freezer_value_target_size: 1024,
                        freezer_value_compression: None,
                        ordinal_partition: format!("{partition_prefix}-finalized-blocks-ordinal"),
                        items_per_section: NZU64!(10),
                        codec_config: config.block_codec_config,
                        replay_buffer: config.replay_buffer,
                        freezer_key_write_buffer: config.key_write_buffer,
                        freezer_value_write_buffer: config.value_write_buffer,
                        ordinal_write_buffer: config.key_write_buffer,
                    },
                )
                .await
                .expect("init finalized blocks archive");

                let (actor, mailbox, _) = Actor::<_, Standard<TestBlock>, _, _, _, _, _>::init(
                    context.child("actor"),
                    finalizations_by_height,
                    finalized_blocks,
                    config,
                )
                .await;
                let (application, delivered_rx) = SinkReporter::new(
                    (BLOCKS_TO_PROCESS + 1)
                        .try_into()
                        .expect("block count with genesis"),
                );
                let (resolver_rx, resolver) = init_marshal_resolver::<_, Sha256Digest, PublicKey>(
                    context.child("resolver"),
                    NZUsize!(100),
                    simplex,
                );
                let actor_handle = actor.start_unbuffered(application, (resolver_rx, resolver));

                mailbox.hint_finalized(
                    Height::new(BLOCKS_TO_PROCESS),
                    NonEmptyVec::new(ed25519::PrivateKey::from_seed(9).public_key()),
                );
                let delivered = tokio::time::timeout(Duration::from_secs(10), delivered_rx)
                    .await
                    .expect("marshal delivery timeout")
                    .expect("marshal delivered blocks");
                actor_handle.abort();
                let _ = actor_handle.await;
                delivered
            })
        }
    })
    .await
    .expect("runner join");

    assert_eq!(delivered, expected_blocks);
}

#[tokio::test]
async fn round_indices_retain_same_view_across_epochs() {
    let simplex = SimplexClient::new(PrefixedStoreClient::empty(local_store_client().await));
    let schemes = schemes();
    let mut expected = Vec::new();
    for epoch in [0, 1, u32::MAX as u64 + 1] {
        let mut block = TestBlock::new(epoch + 1, b"epoch boundary");
        block.context.round = Round::new(Epoch::new(epoch), View::new(7));
        block.digest = block.compute_digest();
        let notarized = notarized(block.clone(), &schemes);
        let finalized = finalized(block, &schemes);
        simplex.upload_notarized(&notarized).await.unwrap();
        simplex.upload_finalized(&finalized).await.unwrap();
        expected.push((notarized, finalized));
    }
    for (notarized, finalized) in expected {
        let round = notarized.header.context.round;
        assert_eq!(
            simplex
                .get_notarized_by_round::<TestBlock, Scheme, Sha256Digest>(round, &(10, 1024))
                .await
                .unwrap(),
            Some(notarized)
        );
        assert_eq!(
            simplex
                .get_finalized_by_round::<TestBlock, Scheme, Sha256Digest>(round, &(10, 1024))
                .await
                .unwrap(),
            Some(finalized)
        );
    }
}

#[tokio::test]
async fn round_reads_reject_certificates_stored_under_another_round() {
    let store = local_store_client().await;
    let client = PrefixedStoreClient::empty(store.clone());
    let simplex = SimplexClient::new(client.clone());
    let schemes = schemes();
    let mut block = TestBlock::new(9, b"round binding");
    block.context.round = Round::new(Epoch::new(1), View::new(9));
    block.digest = block.compute_digest();
    let notarized = notarized(block.clone(), &schemes);
    let finalized = finalized(block, &schemes);

    for round in [
        Round::new(Epoch::new(2), View::new(9)),
        Round::new(Epoch::new(1), View::new(10)),
    ] {
        let mut batch = StoreWriteBatch::new();
        batch
            .push(
                &client,
                &keys::notarization_by_round(round),
                notarized.encode(),
            )
            .unwrap();
        batch
            .push(
                &client,
                &keys::finalization_by_round(round),
                finalized.encode(),
            )
            .unwrap();
        batch.commit(&store).await.unwrap();

        assert!(matches!(
            simplex
                .get_notarized_by_round::<TestBlock, Scheme, Sha256Digest>(round, &(10, 1024))
                .await,
            Err(SimplexError::RecordKeyMismatch)
        ));
        assert!(matches!(
            simplex
                .get_finalized_by_round::<TestBlock, Scheme, Sha256Digest>(round, &(10, 1024))
                .await,
            Err(SimplexError::RecordKeyMismatch)
        ));
    }

    // A mis-keyed height row sorts last, so the latest-finalized read must reject it
    let mut batch = StoreWriteBatch::new();
    batch
        .push(
            &client,
            &keys::finalized_by_height(Height::new(u64::MAX)),
            finalized.encode(),
        )
        .unwrap();
    batch.commit(&store).await.unwrap();
    assert!(matches!(
        simplex
            .latest_finalized::<TestBlock, Scheme, Sha256Digest>(&(10, 1024))
            .await,
        Err(SimplexError::RecordKeyMismatch)
    ));
}
