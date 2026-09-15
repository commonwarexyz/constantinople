//! Stateless finalized SQL and QMDB publication.

use super::{
    block::encode_block_rows,
    sql::{AccountMetaRow, encode_account_meta_row},
};
use crate::{
    namespaces::{
        publication_target_client, simplex_client, sql_meta_client, state_qmdb_client,
        transactions_qmdb_client,
    },
    sql_schema::build_meta_schema,
    store::writer_store_client,
};
use bytes::Bytes;
use commonware_codec::{
    Codec, DecodeExt as _, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read,
    ReadExt, Write,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant, sha256::Sha256,
};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::Spawner;
use commonware_storage::{
    merkle::{Family as _, Location, Proof, mmr},
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        keyless,
    },
};
use commonware_utils::sequence::FixedBytes;
use constantinople_application::consensus::{
    FinalizedArtifacts, FinalizedRange, StateOperation as CapturedStateOperation,
    TransactionHistoryOperation,
};
use constantinople_engine::types::{EngineBlock, EngineFinalization};
use constantinople_primitives::{Account, AccountKey, BlockCfg};
use cpu_time::ThreadTime;
use exoware_qmdb::{
    AuthenticatedOperationRange, QmdbError, prepare_authenticated_range,
    stage_authenticated_range_with_existing_nodes, stage_watermark,
};
use exoware_sdk::{ClientError, PrefixedStoreClient, StoreClient, StoreWriteBatch, keys::Key};
use exoware_sql::{BatchWriter, KvSchema};
use futures::{StreamExt as _, future::BoxFuture, stream};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, warn};

const QUEUE_MAGIC: u32 = 0x4351_5545;
const QUEUE_FORMAT_VERSION: u16 = 1;
const ROW_LAYOUT_VERSION: u16 = 1;
pub const METADATA_ENCODER_VERSION: u16 = 1;
const HASHER_SHA256: u8 = 1;
const MERKLE_MMR: u8 = 1;
const STATE_UNORDERED: u8 = 1;
const TRANSACTIONS_KEYLESS: u8 = 1;
const STATE_OPERATION_CODEC_VERSION: u16 = 1;
const TRANSACTION_OPERATION_CODEC_VERSION: u16 = 1;
const MAX_BUFFERED_UPLOADS: usize = 64;

// Split byte-heavy SQL chunks to reduce encoding, compression, and transfer time.
const DATA_REQUEST_BYTES: usize = 24 * 1024 * 1024;

// Limit serial per-row Store work independently of request bytes.
const DATA_REQUEST_ROWS: usize = 250_000;

// Let a typical large block's chunks overlap without a second request wave.
const MAX_CONCURRENT_CHUNKS: usize = 10;

type QmdbFamily = mmr::Family;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateEncoding = FixedEncoding<AccountValue>;
type StateOperation = UnorderedOperation<QmdbFamily, AccountKey, StateEncoding>;
type TransactionEncoding<H> = FixedEncoding<<H as Hasher>::Digest>;
type TransactionOperation<H> = keyless::Operation<QmdbFamily, TransactionEncoding<H>>;

/// Completion details for one contiguously published block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationReceipt<D: Digest> {
    pub height: u64,
    pub block_digest: D,
    pub store_sequence_number: u64,
}

/// Completion signals for a queued finalized-block upload.
///
/// Persistence and publication are separate stages. Every data commit for a
/// block lands independently, while publication waits for the contiguous
/// prefix, so a caller can release resources held for the upload before
/// earlier blocks have published.
pub struct UploadCompletion<D: Digest> {
    height: u64,
    persisted: oneshot::Receiver<()>,
    published: oneshot::Receiver<PublicationReceipt<D>>,
}

impl<D: Digest> UploadCompletion<D> {
    /// Wait until every data commit for this block is durable in the Store.
    pub async fn persisted(&mut self) -> Result<(), PublishError> {
        (&mut self.persisted)
            .await
            .map_err(|_| PublishError::CommitterStopped {
                height: self.height,
            })
    }

    /// Wait until the contiguous prefix through this block is published.
    pub async fn published(self) -> Result<PublicationReceipt<D>, PublishError> {
        self.published
            .await
            .map_err(|_| PublishError::CommitterStopped {
                height: self.height,
            })
    }
}

/// Codec limits for one authenticated operation range.
#[derive(Clone, Debug)]
pub struct QueuedAuthenticatedRangeCfg {
    pub proof_digests: usize,
    pub pinned_nodes: RangeCfg<usize>,
    pub operations: RangeCfg<usize>,
    pub operation_bytes: RangeCfg<usize>,
}

// Valid captures can exceed a fixed operation count. The codec bounds
// allocations by the remaining payload bytes.
impl Default for QueuedAuthenticatedRangeCfg {
    fn default() -> Self {
        Self {
            proof_digests: 512,
            pinned_nodes: RangeCfg::from(0..=256),
            operations: RangeCfg::from(1..),
            operation_bytes: RangeCfg::from(0..=16 * 1024 * 1024),
        }
    }
}

/// Codec configuration for a durable finalized upload.
#[derive(Clone, Debug, Default)]
pub struct QueuedFinalizedUploadCfg {
    pub block: BlockCfg,
    pub state: QueuedAuthenticatedRangeCfg,
    pub transactions: QueuedAuthenticatedRangeCfg,
}

/// Operations of an authenticated range in their queue-payload layout.
///
/// A payload stores each operation as length-prefixed bytes, the layout the
/// codec uses for `Vec<Vec<u8>>`. The finalized hook writes that layout
/// straight from the application's captured `Arc<Vec<Op>>`, so the payload
/// never passes through a per-operation `Vec<u8>`. The publisher decodes
/// payloads into `Vec<Vec<u8>>` and re-encodes those exact bytes.
pub trait OperationList {
    fn count(&self) -> usize;

    fn encoded_size(&self) -> usize;

    fn write_encoded(&self, buf: &mut impl bytes::BufMut);
}

impl OperationList for Vec<Vec<u8>> {
    fn count(&self) -> usize {
        self.len()
    }

    fn encoded_size(&self) -> usize {
        EncodeSize::encode_size(self)
    }

    fn write_encoded(&self, buf: &mut impl bytes::BufMut) {
        Write::write(self, buf);
    }
}

impl<Op: Encode> OperationList for Arc<Vec<Op>> {
    fn count(&self) -> usize {
        self.len()
    }

    fn encoded_size(&self) -> usize {
        self.iter()
            .fold(self.len().encode_size(), |size, operation| {
                let operation_size = operation.encode_size();
                size + operation_size.encode_size() + operation_size
            })
    }

    fn write_encoded(&self, buf: &mut impl bytes::BufMut) {
        self.len().write(buf);
        for operation in self.iter() {
            operation.encode_size().write(buf);
            operation.write(buf);
        }
    }
}

/// Exact half-open operation range captured from a finalized batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedAuthenticatedRange<D: Digest, Ops = Vec<Vec<u8>>> {
    pub start: u64,
    pub end: u64,
    pub proof: Proof<QmdbFamily, D>,
    pub pinned_nodes: Vec<D>,
    pub operations: Ops,
}

impl<D: Digest, Op> QueuedAuthenticatedRange<D, Arc<Vec<Op>>> {
    fn from_finalized_range(range: FinalizedRange<D, Op>) -> Self {
        let FinalizedRange {
            start,
            end,
            proof,
            pinned_nodes,
            operations,
            ..
        } = range;

        Self {
            start: start.as_u64(),
            end: end.as_u64(),
            proof,
            pinned_nodes,
            operations,
        }
    }
}

impl<D: Digest, Ops: OperationList> EncodeSize for QueuedAuthenticatedRange<D, Ops> {
    fn encode_size(&self) -> usize {
        self.start.encode_size()
            + self.end.encode_size()
            + self.proof.encode_size()
            + self.pinned_nodes.encode_size()
            + self.operations.encoded_size()
    }
}

impl<D: Digest, Ops: OperationList> Write for QueuedAuthenticatedRange<D, Ops> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.start.write(buf);
        self.end.write(buf);
        self.proof.write(buf);
        self.pinned_nodes.write(buf);
        self.operations.write_encoded(buf);
    }
}

impl<D: Digest> Read for QueuedAuthenticatedRange<D> {
    type Cfg = QueuedAuthenticatedRangeCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            start: u64::read(buf)?,
            end: u64::read(buf)?,
            proof: Proof::read_cfg(buf, &cfg.proof_digests)?,
            pinned_nodes: Vec::<D>::read_cfg(buf, &(cfg.pinned_nodes, ()))?,
            operations: Vec::<Vec<u8>>::read_cfg(
                buf,
                &(cfg.operations, (cfg.operation_bytes, ())),
            )?,
        })
    }
}

/// Self-contained durable queue payload.
///
/// The default form holds decoded operation bytes and is what the publisher
/// works from. The finalized hook builds [CapturedFinalizedUpload], whose
/// operations are the application's own vectors, and both forms encode to
/// identical bytes.
pub struct QueuedFinalizedUpload<H, P, V, S = Vec<Vec<u8>>, T = Vec<Vec<u8>>>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    block: EngineBlock<H, P>,
    finalization: EngineFinalization<P, V, H>,
    finalized_ts_micros: i64,
    state: QueuedAuthenticatedRange<H::Digest, S>,
    transactions: QueuedAuthenticatedRange<H::Digest, T>,
}

/// Queue payload built in the finalized hook from captured artifacts.
pub type CapturedFinalizedUpload<H, P, V> = QueuedFinalizedUpload<
    H,
    P,
    V,
    Arc<Vec<CapturedStateOperation>>,
    Arc<Vec<TransactionHistoryOperation<H>>>,
>;

impl<H, P, V, S, T> Clone for QueuedFinalizedUpload<H, P, V, S, T>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    S: Clone,
    T: Clone,
    EngineFinalization<P, V, H>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            block: self.block.clone(),
            finalization: self.finalization.clone(),
            finalized_ts_micros: self.finalized_ts_micros,
            state: self.state.clone(),
            transactions: self.transactions.clone(),
        }
    }
}

impl<H, P, V> CapturedFinalizedUpload<H, P, V>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
    V: Variant,
    EngineFinalization<P, V, H>: Clone,
{
    /// Build an entry from the exact pre-apply handoff.
    pub fn from_finalized_artifacts(
        block: &EngineBlock<H, P>,
        finalization: EngineFinalization<P, V, H>,
        finalized_ts_micros: i64,
        artifacts: FinalizedArtifacts<H>,
    ) -> Result<Self, PublishError> {
        if artifacts.state.root != block.header.state_root {
            return Err(PublishError::InvalidQueuedUpload {
                reason: "state artifact root does not match the finalized header",
            });
        }
        if artifacts.transactions.root != block.header.transactions_root {
            return Err(PublishError::InvalidQueuedUpload {
                reason: "transaction artifact root does not match the finalized header",
            });
        }
        let state = QueuedAuthenticatedRange::from_finalized_range(artifacts.state);
        let transactions = QueuedAuthenticatedRange::from_finalized_range(artifacts.transactions);
        let upload = Self {
            block: block.clone(),
            finalization,
            finalized_ts_micros,
            state,
            transactions,
        };
        upload.validate()?;
        Ok(upload)
    }
}

impl<H, P, V, S, T> QueuedFinalizedUpload<H, P, V, S, T>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
    V: Variant,
    S: OperationList,
    T: OperationList,
    EngineFinalization<P, V, H>: Clone,
{
    pub fn height(&self) -> u64 {
        self.block.header.height
    }

    pub const fn block(&self) -> &EngineBlock<H, P> {
        &self.block
    }

    pub fn finalization(&self) -> EngineFinalization<P, V, H> {
        self.finalization.clone()
    }

    pub const fn state_start(&self) -> u64 {
        self.state.start
    }

    pub const fn state_end(&self) -> u64 {
        self.state.end
    }

    pub const fn transaction_start(&self) -> u64 {
        self.transactions.start
    }

    pub const fn transaction_end(&self) -> u64 {
        self.transactions.end
    }

    fn validate(&self) -> Result<(), PublishError> {
        if self.finalization.proposal.payload.block() != *self.block.seal() {
            return Err(PublishError::InvalidQueuedUpload {
                reason: "finalization commitment does not match the block",
            });
        }
        validate_range(&self.state, self.block.header.state_range.end(), "state")?;
        validate_range(
            &self.transactions,
            self.block.header.transactions_range.end(),
            "transaction",
        )?;
        Ok(())
    }
}

fn validate_range<D: Digest, Ops: OperationList>(
    range: &QueuedAuthenticatedRange<D, Ops>,
    header_end: u64,
    label: &'static str,
) -> Result<(), PublishError> {
    if range.start >= range.end {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "authenticated operation range is empty",
        });
    }
    if range.end != header_end {
        return Err(PublishError::InvalidQueuedUpload {
            reason: match label {
                "state" => "state range does not match the finalized header",
                _ => "transaction range does not match the finalized header",
            },
        });
    }
    if range.proof.leaves.as_u64() != range.end {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "authenticated proof does not target the range end",
        });
    }
    let count = range
        .end
        .checked_sub(range.start)
        .and_then(|count| usize::try_from(count).ok());
    if count != Some(range.operations.count()) {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "authenticated operation count does not match the range",
        });
    }
    Ok(())
}

impl<P, V, S, T> EncodeSize for QueuedFinalizedUpload<Sha256, P, V, S, T>
where
    P: PublicKey,
    V: Variant,
    S: OperationList,
    T: OperationList,
    EngineBlock<Sha256, P>: EncodeSize,
    EngineFinalization<P, V, Sha256>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        QUEUE_MAGIC.encode_size()
            + QUEUE_FORMAT_VERSION.encode_size()
            + ROW_LAYOUT_VERSION.encode_size()
            + METADATA_ENCODER_VERSION.encode_size()
            + HASHER_SHA256.encode_size()
            + MERKLE_MMR.encode_size()
            + STATE_UNORDERED.encode_size()
            + TRANSACTIONS_KEYLESS.encode_size()
            + STATE_OPERATION_CODEC_VERSION.encode_size()
            + TRANSACTION_OPERATION_CODEC_VERSION.encode_size()
            + self.block.encode_size()
            + self.finalization.encode_size()
            + self.finalized_ts_micros.encode_size()
            + self.state.encode_size()
            + self.transactions.encode_size()
    }
}

impl<P, V, S, T> Write for QueuedFinalizedUpload<Sha256, P, V, S, T>
where
    P: PublicKey,
    V: Variant,
    S: OperationList,
    T: OperationList,
    EngineBlock<Sha256, P>: Write,
    EngineFinalization<P, V, Sha256>: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        QUEUE_MAGIC.write(buf);
        QUEUE_FORMAT_VERSION.write(buf);
        ROW_LAYOUT_VERSION.write(buf);
        METADATA_ENCODER_VERSION.write(buf);
        HASHER_SHA256.write(buf);
        MERKLE_MMR.write(buf);
        STATE_UNORDERED.write(buf);
        TRANSACTIONS_KEYLESS.write(buf);
        STATE_OPERATION_CODEC_VERSION.write(buf);
        TRANSACTION_OPERATION_CODEC_VERSION.write(buf);
        self.block.write(buf);
        self.finalization.write(buf);
        self.finalized_ts_micros.write(buf);
        self.state.write(buf);
        self.transactions.write(buf);
    }
}

impl<P, V> Read for QueuedFinalizedUpload<Sha256, P, V>
where
    P: PublicKey,
    V: Variant,
    EngineBlock<Sha256, P>: Read<Cfg = BlockCfg>,
    EngineFinalization<P, V, Sha256>: Read<Cfg = ()> + Clone,
{
    type Cfg = QueuedFinalizedUploadCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if u32::read(buf)? != QUEUE_MAGIC
            || u16::read(buf)? != QUEUE_FORMAT_VERSION
            || u16::read(buf)? != ROW_LAYOUT_VERSION
        {
            return Err(CodecError::Invalid(
                "QueuedFinalizedUpload",
                "unsupported durable queue format",
            ));
        }
        let metadata_encoder_version = u16::read(buf)?;
        if metadata_encoder_version != METADATA_ENCODER_VERSION
            || u8::read(buf)? != HASHER_SHA256
            || u8::read(buf)? != MERKLE_MMR
            || u8::read(buf)? != STATE_UNORDERED
            || u8::read(buf)? != TRANSACTIONS_KEYLESS
            || u16::read(buf)? != STATE_OPERATION_CODEC_VERSION
            || u16::read(buf)? != TRANSACTION_OPERATION_CODEC_VERSION
        {
            return Err(CodecError::Invalid(
                "QueuedFinalizedUpload",
                "unsupported durable queue encoder identity",
            ));
        }
        let upload = Self {
            block: EngineBlock::<Sha256, P>::read_cfg(buf, &cfg.block)?,
            finalization: EngineFinalization::<P, V, Sha256>::read(buf)?,
            finalized_ts_micros: i64::read(buf)?,
            state: QueuedAuthenticatedRange::read_cfg(buf, &cfg.state)?,
            transactions: QueuedAuthenticatedRange::read_cfg(buf, &cfg.transactions)?,
        };
        upload.validate().map_err(|_| {
            CodecError::Invalid("QueuedFinalizedUpload", "invalid finalized upload payload")
        })?;
        Ok(upload)
    }
}

/// Finalized index publication failure.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("failed to configure Store client due to {0}")]
    ClientBuild(#[from] crate::StoreClientBuildError),
    #[error("failed to configure Store prefix due to {0}")]
    Prefix(#[from] exoware_sdk::StoreKeyPrefixError),
    #[error("QMDB authenticated range error due to {0}")]
    Qmdb(#[from] QmdbError),
    #[error("Store client error due to {0}")]
    Store(#[from] ClientError),
    #[error("failed to split finalized index data due to {0}")]
    Split(#[from] exoware_sdk::SplitError),
    #[error("failed to configure SQL metadata schema due to {0}")]
    SqlSchema(String),
    #[error("failed to stage SQL metadata rows due to {0}")]
    Sql(#[from] datafusion::error::DataFusionError),
    #[error("failed to encode SQL metadata row due to {0}")]
    SqlRow(String),
    #[error("invalid durable finalized upload because {reason}")]
    InvalidQueuedUpload { reason: &'static str },
    #[error("finalized publication expected height {expected}, got {actual}")]
    HeightOutOfOrder { expected: u64, actual: u64 },
    #[error("{family} range expected start {expected}, got {actual}")]
    RangeOutOfOrder {
        family: &'static str,
        expected: u64,
        actual: u64,
    },
    #[error("QMDB commit worker stopped before accepting height {height}")]
    CommitterStopped { height: u64 },
    #[error("fresh startup found existing rows in the {family} namespace")]
    NonFreshNamespace { family: &'static str },
}

#[derive(Clone, Copy, Debug)]
struct Admission {
    next_height: u64,
    state_next: u64,
    transaction_next: u64,
}

/// Owns stateless range preparation and contiguous publication.
#[derive(Debug)]
pub struct Publisher<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    tx: Option<mpsc::Sender<PendingUpload<H, P>>>,
    admission: Mutex<Option<Admission>>,
    has_durable_range: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    _marker: PhantomData<P>,
}

struct PendingUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    enqueued_at: Instant,
    height: u64,
    block: EngineBlock<H, P>,
    finalized_ts_micros: i64,
    state: QueuedAuthenticatedRange<H::Digest>,
    transactions: QueuedAuthenticatedRange<H::Digest>,
    omit_pinned_nodes: bool,
    has_durable_range: Arc<AtomicBool>,
    persisted: Option<oneshot::Sender<()>>,
    published: Option<oneshot::Sender<PublicationReceipt<H::Digest>>>,
}

struct PendingPublication<D: Digest> {
    height: u64,
    block_digest: D,
    finalized_ts_micros: i64,
    published: oneshot::Sender<PublicationReceipt<D>>,
}

struct PersistedUpload {
    height: u64,
    state: Location<QmdbFamily>,
    transactions: Location<QmdbFamily>,
    persisted_at: Instant,
}

struct WorkerClients {
    store: StoreClient,
    state: PrefixedStoreClient,
    transactions: PrefixedStoreClient,
    targets: PrefixedStoreClient,
    sql_schema: Arc<KvSchema>,
}

impl<H, P> Publisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    pub async fn connect<Cx>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
    {
        Self::connect_with_strategy(context, store_url, api_key, buffer, metrics, Sequential).await
    }

    pub async fn connect_with_strategy<Cx, S>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        strategy: S,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
        S: Strategy,
    {
        Self::connect_inner(
            context, store_url, api_key, buffer, metrics, strategy, false,
        )
        .await
    }

    /// Connect after verifying every remote namespace is empty.
    pub async fn connect_fresh_with_strategy<Cx, S>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        strategy: S,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
        S: Strategy,
    {
        Self::connect_inner(context, store_url, api_key, buffer, metrics, strategy, true).await
    }

    async fn connect_inner<Cx, S>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        strategy: S,
        require_fresh: bool,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
        S: Strategy,
    {
        let store = writer_store_client(store_url, api_key)?;
        let clients = WorkerClients {
            state: state_qmdb_client(&store)?,
            transactions: transactions_qmdb_client(&store)?,
            targets: publication_target_client(&store)?,
            sql_schema: Arc::new(
                build_meta_schema(sql_meta_client(&store)?).map_err(PublishError::SqlSchema)?,
            ),
            store,
        };
        if require_fresh {
            require_empty_namespace(&clients.state, "state QMDB").await?;
            require_empty_namespace(&clients.transactions, "transaction QMDB").await?;
            require_empty_namespace(&clients.targets, "publication target").await?;
            require_empty_namespace(&sql_meta_client(&clients.store)?, "SQL metadata").await?;
            require_empty_namespace(&simplex_client(&clients.store)?, "Simplex").await?;
        }
        let buffer = buffer.clamp(1, MAX_BUFFERED_UPLOADS);
        let (tx, rx) = mpsc::channel(buffer);
        let join = tokio::spawn(run_publisher(
            context, clients, strategy, metrics, rx, buffer,
        ));
        Ok(Self {
            tx: Some(tx),
            admission: Mutex::new(None),
            has_durable_range: Arc::new(AtomicBool::new(false)),
            join: Some(join),
            _marker: PhantomData,
        })
    }

    pub async fn enqueue_queued_finalized<V>(
        &self,
        upload: QueuedFinalizedUpload<H, P, V>,
    ) -> Result<UploadCompletion<H::Digest>, PublishError>
    where
        V: Variant,
        EngineFinalization<P, V, H>: Clone,
    {
        let enqueued_at = Instant::now();
        let height = upload.height();
        let mut admission = self.admission.lock().await;
        if let Some(expected) = *admission {
            if height != expected.next_height {
                return Err(PublishError::HeightOutOfOrder {
                    expected: expected.next_height,
                    actual: height,
                });
            }
            if upload.state.start != expected.state_next {
                return Err(PublishError::RangeOutOfOrder {
                    family: "state",
                    expected: expected.state_next,
                    actual: upload.state.start,
                });
            }
            if upload.transactions.start != expected.transaction_next {
                return Err(PublishError::RangeOutOfOrder {
                    family: "transactions",
                    expected: expected.transaction_next,
                    actual: upload.transactions.start,
                });
            }
        }
        let next_admission = Admission {
            next_height: height
                .checked_add(1)
                .ok_or(PublishError::InvalidQueuedUpload {
                    reason: "finalized height overflows",
                })?,
            state_next: upload.state.end,
            transaction_next: upload.transactions.end,
        };
        let (persisted_tx, persisted) = oneshot::channel();
        let (published_tx, published) = oneshot::channel();

        // Seed the prefix in this process before reusing earlier ranges' nodes.
        // Contiguous publication waits for any still-pending predecessor rows.
        let omit_pinned_nodes = self.has_durable_range.load(Ordering::Relaxed);
        let pending = PendingUpload {
            enqueued_at,
            height,
            block: upload.block,
            finalized_ts_micros: upload.finalized_ts_micros,
            state: upload.state,
            transactions: upload.transactions,
            omit_pinned_nodes,
            has_durable_range: self.has_durable_range.clone(),
            persisted: Some(persisted_tx),
            published: Some(published_tx),
        };
        self.tx
            .as_ref()
            .ok_or(PublishError::CommitterStopped { height })?
            .send(pending)
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        *admission = Some(next_admission);
        Ok(UploadCompletion {
            height,
            persisted,
            published,
        })
    }

    pub async fn shutdown(mut self) {
        drop(self.tx.take());
        if let Some(join) = self.join.take() {
            join.await.expect("finalized publisher task failed");
        }
    }
}

async fn require_empty_namespace(
    client: &PrefixedStoreClient,
    family: &'static str,
) -> Result<(), PublishError> {
    let start = Key::new();
    let end = Key::from(vec![u8::MAX; exoware_sdk::keys::MAX_KEY_LEN - 1]);
    if client.query().range(&start, &end, 1).await?.is_empty() {
        Ok(())
    } else {
        Err(PublishError::NonFreshNamespace { family })
    }
}

async fn run_publisher<Cx, H, P, S>(
    context: Cx,
    clients: WorkerClients,
    strategy: S,
    metrics: super::PublisherMetrics,
    mut rx: mpsc::Receiver<PendingUpload<H, P>>,
    max_in_flight: usize,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy,
{
    let mut rx_closed = false;
    let mut commits = JoinSet::<Result<PersistedUpload, PublishError>>::new();
    let mut pending = VecDeque::new();
    let mut persisted = BTreeMap::new();
    let mut publication = None::<BoxFuture<'static, (usize, u64)>>;
    loop {
        // Include every available completion before selecting the next publication prefix.
        while let Some(result) = commits.try_join_next() {
            let result = result
                .expect("finalized data commit task failed")
                .expect("finalized data preparation must succeed");
            persisted.insert(result.height, result);
        }
        if publication.is_none() {
            publication = publish_ready_prefix::<H>(&clients, &metrics, &pending, &persisted);
        }
        if rx_closed && commits.is_empty() && publication.is_none() {
            assert!(
                pending.is_empty(),
                "publisher stopped with an unpublished gap"
            );
            break;
        }

        tokio::select! {
            upload = rx.recv(), if !rx_closed && pending.len() < max_in_flight => {
                match upload {
                    Some(mut upload) => {
                        let publication = PendingPublication {
                            height: upload.height,
                            block_digest: *upload.block.seal(),
                            finalized_ts_micros: upload.finalized_ts_micros,
                            published: upload
                                .published
                                .take()
                                .expect("pending upload publication signal must be present"),
                        };
                        pending.push_back(publication);
                        spawn_data_commit(
                            &mut commits,
                            context.child("data"),
                            &clients,
                            strategy.clone(),
                            metrics.clone(),
                            upload,
                        );
                    }
                    None => rx_closed = true,
                }
            }
            result = commits.join_next(), if !commits.is_empty() => {
                let result = result
                    .expect("non-empty finalized commit set must produce a result")
                    .expect("finalized data commit task failed")
                    .expect("finalized data preparation must succeed");
                persisted.insert(result.height, result);
            }
            (ready, sequence) = async { publication.as_mut().expect("publication is active").await }, if publication.is_some() => {
                publication = None;
                complete_publication(ready, sequence, &metrics, &mut pending, &mut persisted);
            }
        }
    }
    debug!("stateless finalized publisher task exiting after channel closure");
}

fn spawn_data_commit<Cx, H, P, S>(
    commits: &mut JoinSet<Result<PersistedUpload, PublishError>>,
    context: Cx,
    clients: &WorkerClients,
    strategy: S,
    metrics: super::PublisherMetrics,
    mut upload: PendingUpload<H, P>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy,
{
    let store = clients.store.clone();
    let state_client = clients.state.clone();
    let transaction_client = clients.transactions.clone();
    let sql_schema = clients.sql_schema.clone();
    let persisted = upload
        .persisted
        .take()
        .expect("pending upload persistence signal must be present");
    let height = upload.height;
    let has_durable_range = upload.has_durable_range.clone();
    let admitted_at = Instant::now();

    // Supervise preparation and data commits without holding a blocking
    // thread while waiting for their completion.
    let commit = context.spawn(move |context| async move {
        let prepare_metrics = metrics.clone();
        let prepare = context
            .child("prepare")
            .shared(true)
            .spawn(move |_| async move {
                let started = Instant::now();
                prepare_metrics
                    .prepare_wait_duration
                    .observe(started.duration_since(upload.enqueued_at).as_secs_f64());
                prepare_metrics
                    .transactions_per_block
                    .observe(upload.block.body.len() as f64);

                // Keep both CPU-clock reads on this thread without an intervening await.
                let cpu_started = ThreadTime::try_now();
                let prepared = (|| {
                    let (batch, state, transactions) = prepare_data_batch::<H, P, S>(
                        state_client,
                        transaction_client,
                        sql_schema,
                        strategy,
                        upload,
                        &prepare_metrics,
                    )?;
                    let chunking_started = Instant::now();
                    let batches = batch.split(DATA_REQUEST_ROWS, DATA_REQUEST_BYTES);
                    prepare_metrics
                        .chunking_duration
                        .observe(chunking_started.elapsed().as_secs_f64());
                    Ok::<_, PublishError>((batches?, state, transactions))
                })();
                let cpu_elapsed = cpu_started.and_then(|started| started.try_elapsed());
                prepare_metrics
                    .prepare_duration
                    .observe(started.elapsed().as_secs_f64());
                match cpu_elapsed {
                    Ok(elapsed) => prepare_metrics
                        .prepare_cpu_duration
                        .observe(elapsed.as_secs_f64()),
                    Err(error) => warn!(?error, "failed to measure preparation thread CPU time"),
                }
                prepared
            });
        let (batches, state, transactions) = prepare
            .await
            .expect("finalized index preparation task failed")?;
        let chunks = batches.len() as u64;
        commit_chunks(context.child("commit"), &store, &metrics.commit, batches).await?;
        has_durable_range.store(true, Ordering::Relaxed);
        let persisted_at = Instant::now();
        metrics.chunk_commits.inc_by(chunks);
        metrics.chunks_per_block.observe(chunks as f64);
        metrics
            .persist_duration
            .observe(admitted_at.elapsed().as_secs_f64());

        // Publication still waits for the contiguous prefix in `publish_ready_prefix`.
        // The signal only tells the caller that this block's own rows are durable.
        let _ = persisted.send(());
        Ok(PersistedUpload {
            height,
            state,
            transactions,
            persisted_at,
        })
    });
    commits.spawn(async move { commit.await.expect("finalized index data task failed") });
}

async fn commit_chunks<Cx: Spawner>(
    context: Cx,
    store: &StoreClient,
    metrics: &super::StoreCommitMetrics,
    batches: Vec<StoreWriteBatch>,
) -> Result<(), ClientError> {
    // Spawn lazily so the limit covers request encoding, compression, and retries.
    let mut commits = stream::iter(batches)
        .map(|batch| {
            let store = store.clone();
            let metrics = metrics.clone();
            context
                .child("chunk")
                .shared(true)
                .spawn(move |_| async move {
                    super::commit_with_retry(&store, &batch, super::CommitKind::Chunk, &metrics)
                        .await
                })
        })
        .buffer_unordered(MAX_CONCURRENT_CHUNKS);

    while let Some(result) = commits.next().await {
        result.expect("finalized index chunk commit task failed")?;
    }
    Ok(())
}

fn prepare_data_batch<H, P, S>(
    state_client: PrefixedStoreClient,
    transaction_client: PrefixedStoreClient,
    sql_schema: Arc<KvSchema>,
    strategy: S,
    upload: PendingUpload<H, P>,
    metrics: &super::PublisherMetrics,
) -> Result<(StoreWriteBatch, Location<QmdbFamily>, Location<QmdbFamily>), PublishError>
where
    H: Hasher,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
    S: Strategy,
{
    let expansion_started = Instant::now();
    let state = prepare_authenticated_range::<QmdbFamily, H, StateOperation, S>(
        &as_authenticated_range(&upload.state),
        &upload.block.header.state_root,
        &(),
        &strategy,
    )?;
    let transactions = prepare_authenticated_range::<QmdbFamily, H, TransactionOperation<H>, S>(
        &as_authenticated_range(&upload.transactions),
        &upload.block.header.transactions_root,
        &(),
        &strategy,
    )?;
    let metadata_rows = encode_metadata_rows::<H, P>(
        &upload.block,
        upload.finalized_ts_micros,
        &upload.state,
        &upload.transactions,
    )?;
    metrics
        .expansion_duration
        .observe(expansion_started.elapsed().as_secs_f64());

    let staging_started = Instant::now();
    let mut sql_writer = sql_schema.batch_writer();
    let sql = prepare_sql(&mut sql_writer, metadata_rows)?;
    let mut batch = StoreWriteBatch::new();
    sql_writer.stage_flush(&sql, &mut batch)?;
    let state_end = state.latest_location();
    let transaction_end = transactions.latest_location();
    let existing_state_nodes = if upload.omit_pinned_nodes {
        QmdbFamily::nodes_to_pin(state.start_location()).collect()
    } else {
        BTreeSet::new()
    };
    let existing_transaction_nodes = if upload.omit_pinned_nodes {
        QmdbFamily::nodes_to_pin(transactions.start_location()).collect()
    } else {
        BTreeSet::new()
    };
    stage_authenticated_range_with_existing_nodes(
        &state_client,
        state,
        &existing_state_nodes,
        &mut batch,
    )?;
    stage_authenticated_range_with_existing_nodes(
        &transaction_client,
        transactions,
        &existing_transaction_nodes,
        &mut batch,
    )?;
    metrics
        .staging_duration
        .observe(staging_started.elapsed().as_secs_f64());
    Ok((batch, state_end, transaction_end))
}

fn as_authenticated_range<D: Digest>(
    range: &QueuedAuthenticatedRange<D>,
) -> AuthenticatedOperationRange<'_, D, QmdbFamily> {
    AuthenticatedOperationRange {
        start_location: Location::new(range.start),
        end_location: Location::new(range.end),
        inactive_peaks: range.proof.inactive_peaks,
        pinned_nodes: &range.pinned_nodes,
        encoded_operations: &range.operations,
    }
}

fn encode_metadata_rows<H, P>(
    block: &EngineBlock<H, P>,
    finalized_ts_micros: i64,
    state: &QueuedAuthenticatedRange<H::Digest>,
    transactions: &QueuedAuthenticatedRange<H::Digest>,
) -> Result<Vec<super::SqlRow>, PublishError>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
{
    let block_rows = encode_block_rows(block, finalized_ts_micros);
    validate_transaction_metadata_ops::<H>(&block_rows.transaction_digests, transactions)?;
    let mut rows = block_rows.sql;
    rows.extend(account_rows(state)?);
    Ok(rows)
}

fn validate_transaction_metadata_ops<H>(
    expected: &[H::Digest],
    range: &QueuedAuthenticatedRange<H::Digest>,
) -> Result<(), PublishError>
where
    H: Hasher,
    H::Digest: Codec,
{
    let mut expected = expected.iter();
    let mut matches = true;
    for encoded in &range.operations {
        let operation = TransactionOperation::<H>::decode(encoded.as_slice()).map_err(|_| {
            PublishError::InvalidQueuedUpload {
                reason: "transaction operation bytes do not decode",
            }
        })?;
        if let keyless::Operation::Append(digest) = operation {
            matches &= expected.next() == Some(&digest);
        }
    }
    if !matches || expected.next().is_some() {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "transaction operations do not match block metadata",
        });
    }
    Ok(())
}

fn account_rows<D: Digest>(
    range: &QueuedAuthenticatedRange<D>,
) -> Result<Vec<super::SqlRow>, PublishError> {
    let mut rows = Vec::new();
    for (offset, encoded) in range.operations.iter().enumerate() {
        let operation = StateOperation::decode(encoded.as_slice()).map_err(|_| {
            PublishError::InvalidQueuedUpload {
                reason: "state operation bytes do not decode",
            }
        })?;
        let AnyOperation::Update(UnorderedUpdate(key, account)) = operation else {
            continue;
        };
        let location = range
            .start
            .checked_add(u64::try_from(offset).expect("state operation offset fits u64"))
            .ok_or(PublishError::InvalidQueuedUpload {
                reason: "state operation location overflows",
            })?;
        rows.push(encode_account_meta_row(AccountMetaRow {
            account: key
                .as_ref()
                .try_into()
                .expect("account key has fixed width"),
            balance: account_u64(&account, 0),
            nonce_base: account_u64(&account, 8),
            nonce_bitmap: account_u64(&account, 16),
            qmdb_location: location,
        }));
    }
    Ok(rows)
}

fn account_u64(account: &AccountValue, offset: usize) -> u64 {
    u64::from_be_bytes(
        account.as_ref()[offset..offset + 8]
            .try_into()
            .expect("account field has fixed width"),
    )
}

fn prepare_sql(
    writer: &mut BatchWriter,
    rows: Vec<super::SqlRow>,
) -> Result<exoware_sql::PreparedBatch, PublishError> {
    for row in rows {
        writer
            .insert(row.table, row.values)
            .map_err(PublishError::SqlRow)?;
    }
    writer
        .prepare_flush()?
        .ok_or(PublishError::InvalidQueuedUpload {
            reason: "metadata encoder produced no rows",
        })
}

fn publish_ready_prefix<H>(
    clients: &WorkerClients,
    metrics: &super::PublisherMetrics,
    pending: &VecDeque<PendingPublication<H::Digest>>,
    persisted: &BTreeMap<u64, PersistedUpload>,
) -> Option<BoxFuture<'static, (usize, u64)>>
where
    H: Hasher,
    H::Digest: Codec,
{
    let ready = pending
        .iter()
        .take_while(|publication| persisted.contains_key(&publication.height))
        .count();
    if ready == 0 {
        return None;
    }
    let last = pending
        .get(ready - 1)
        .expect("ready publication prefix is nonempty");
    let last_data = persisted
        .get(&last.height)
        .expect("ready publication data must remain present");
    let mut batch = StoreWriteBatch::new();
    stage_watermark(&clients.state, last_data.state, &mut batch)
        .expect("validated state range has a watermark");
    stage_watermark(&clients.transactions, last_data.transactions, &mut batch)
        .expect("validated transaction range has a watermark");
    for publication in pending.iter().take(ready) {
        let key = Key::from(Bytes::copy_from_slice(&publication.height.to_be_bytes()));
        batch
            .push(&clients.targets, &key, publication.block_digest.as_ref())
            .expect("publication target row must stage");
    }
    let store = clients.store.clone();
    let metrics = metrics.commit.clone();
    Some(Box::pin(async move {
        let sequence =
            super::commit_with_retry(&store, &batch, super::CommitKind::Barrier, &metrics)
                .await
                .expect("contiguous publication barrier was rejected");
        (ready, sequence)
    }))
}

fn complete_publication<D: Digest>(
    ready: usize,
    barrier_sequence: u64,
    metrics: &super::PublisherMetrics,
    pending: &mut VecDeque<PendingPublication<D>>,
    persisted: &mut BTreeMap<u64, PersistedUpload>,
) {
    let published_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    for _ in 0..ready {
        let publication = pending
            .pop_front()
            .expect("ready publication prefix must remain present");
        let data = persisted
            .remove(&publication.height)
            .expect("ready publication data must remain present");
        metrics
            .publication_wait_duration
            .observe(data.persisted_at.elapsed().as_secs_f64());

        // The persisted timestamp includes queue waiting across process restarts.
        // Clamp negative lag if the wall clock moves backwards.
        metrics.finalization_to_publication_duration.observe(
            (published_at - publication.finalized_ts_micros as f64 / 1_000_000.0).max(0.0),
        );
        debug!(
            height = publication.height,
            barrier_sequence, "published finalized index prefix"
        );
        let _ = publication.published.send(PublicationReceipt {
            height: publication.height,
            block_digest: publication.block_digest,
            store_sequence_number: barrier_sequence,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Decode as _;
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::standard,
            types::{Context as SimplexContext, Finalization, Finalize, Proposal},
        },
        types::{Round, View},
    };
    use commonware_cryptography::{
        Signer as _,
        bls12381::primitives::variant::MinSig,
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Metrics as _, Runner as _, Supervisor as _, telemetry::metrics::has_metric_value,
    };
    use commonware_storage::merkle::mem::Mem;
    use commonware_utils::{NZU16, non_empty_range};
    use constantinople_engine::{ThresholdScheme, types::EngineCommitment};
    use constantinople_primitives::{Block, Header, Sealable, SignedTransaction};
    use exoware_qmdb::{KeylessClient, UnorderedClient, stage_authenticated_range};
    use rand::{SeedableRng, rngs::StdRng};

    type TestCommitment = EngineCommitment<Sha256, ed25519::PublicKey>;
    type TestFinalization =
        Finalization<ThresholdScheme<ed25519::PublicKey, MinSig>, TestCommitment>;

    #[test]
    fn queue_codec_round_trips_exact_inputs() {
        let state_operations = [
            StateOperation::CommitFloor(None, Location::new(0)),
            StateOperation::CommitFloor(None, Location::new(1)),
        ];
        let transaction_operations = [
            TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
            TransactionOperation::<Sha256>::Commit(None, Location::new(1)),
        ];
        let state = queued_range(&encode_operations(&state_operations), 1, 2);
        let transactions = queued_range(&encode_operations(&transaction_operations), 1, 2);
        let upload = queued_upload(1, state, transactions);
        let encoded = upload.encode();
        assert_eq!(
            &encoded[..18],
            &[
                0x43, 0x51, 0x55, 0x45, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1
            ]
        );
        let decoded = QueuedFinalizedUpload::<Sha256, ed25519::PublicKey, MinSig>::decode_cfg(
            encoded.clone(),
            &QueuedFinalizedUploadCfg::default(),
        )
        .expect("queue entry decodes");

        assert_eq!(decoded.encode(), encoded);
        assert_eq!(
            decoded.finalization().encode(),
            upload.finalization().encode()
        );
        assert_eq!(decoded.state_start(), upload.state_start());
        assert_eq!(decoded.state_end(), upload.state_end());
        assert_eq!(decoded.transaction_start(), upload.transaction_start());
        assert_eq!(decoded.transaction_end(), upload.transaction_end());

        for index in 0..18 {
            let mut unsupported = encoded.to_vec();
            unsupported[index] ^= u8::MAX;
            assert!(
                QueuedFinalizedUpload::<Sha256, ed25519::PublicKey, MinSig>::decode_cfg(
                    Bytes::from(unsupported),
                    &QueuedFinalizedUploadCfg::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn queue_range_round_trips_more_than_one_million_operations() {
        let operations = vec![
            StateOperation::Update(UnorderedUpdate(
                AccountKey::try_from(&[7u8; 32][..]).unwrap(),
                AccountValue::try_from(Account::default().encode().as_ref()).unwrap(),
            ));
            1_000_001
        ];
        let range = queued_range(&encode_operations(&operations), 0, operations.len() as u64);
        let encoded = range.encode();
        let decoded = QueuedAuthenticatedRange::<Sha256Digest>::decode_cfg(
            encoded.clone(),
            &QueuedAuthenticatedRangeCfg::default(),
        )
        .expect("captured operation ranges are bounded by payload bytes");
        assert_eq!(decoded, range);

        let limited = QueuedAuthenticatedRangeCfg {
            operations: RangeCfg::from(1..=1_000_000),
            ..QueuedAuthenticatedRangeCfg::default()
        };
        assert!(QueuedAuthenticatedRange::<Sha256Digest>::decode_cfg(encoded, &limited).is_err());
    }

    #[test]
    fn captured_upload_encodes_like_its_decoded_form() {
        let state_operations = vec![
            CapturedStateOperation::CommitFloor(None, Location::new(0)),
            CapturedStateOperation::CommitFloor(None, Location::new(1)),
        ];
        let transaction_operations = vec![
            TransactionHistoryOperation::<Sha256>::Commit(None, Location::new(0)),
            TransactionHistoryOperation::<Sha256>::Commit(None, Location::new(1)),
        ];
        let state_bytes = encode_operations(&state_operations);
        let transaction_bytes = encode_operations(&transaction_operations);
        let state = queued_range(&state_bytes, 1, 2);
        let transactions = queued_range(&transaction_bytes, 1, 2);
        let block = test_block(1, &state, &transactions);
        let finalization = test_finalization(&block);
        let artifacts = FinalizedArtifacts {
            state: captured_range(&state, block.header.state_root, state_operations),
            transactions: captured_range(
                &transactions,
                block.header.transactions_root,
                transaction_operations,
            ),
        };

        let captured =
            CapturedFinalizedUpload::<Sha256, ed25519::PublicKey, MinSig>::from_finalized_artifacts(
                &block,
                finalization.clone(),
                1,
                artifacts,
            )
            .expect("captured upload validates");
        let decoded = queued_upload_from(block, finalization, state, transactions);
        assert_eq!(captured.encode(), decoded.encode());
        assert_eq!(captured.encode_size(), decoded.encode_size());

        let round_trip = QueuedFinalizedUpload::<Sha256, ed25519::PublicKey, MinSig>::decode_cfg(
            captured.encode(),
            &QueuedFinalizedUploadCfg::default(),
        )
        .expect("captured payload decodes");
        assert_eq!(round_trip.state.operations, state_bytes[1..2]);
        assert_eq!(round_trip.transactions.operations, transaction_bytes[1..2]);
    }

    #[test]
    fn upload_completion_reports_persistence_before_publication() {
        commonware_runtime::tokio::Runner::default().start(|_| async move {
            let (persisted_tx, persisted) = oneshot::channel();
            let (published_tx, published) = oneshot::channel();
            let mut completion = UploadCompletion::<Sha256Digest> {
                height: 3,
                persisted,
                published,
            };

            persisted_tx.send(()).expect("persisted receiver is alive");
            completion
                .persisted()
                .await
                .expect("persisted stage resolves");

            let receipt = PublicationReceipt {
                height: 3,
                block_digest: Sha256Digest::from([3; Sha256Digest::SIZE]),
                store_sequence_number: 9,
            };
            published_tx
                .send(receipt)
                .expect("published receiver is alive");
            assert_eq!(completion.published().await.expect("published"), receipt);

            let (_persisted_tx, persisted) = oneshot::channel();
            let (published_tx, published) = oneshot::channel::<PublicationReceipt<Sha256Digest>>();
            let completion = UploadCompletion::<Sha256Digest> {
                height: 4,
                persisted,
                published,
            };
            drop(published_tx);
            assert!(matches!(
                completion.published().await,
                Err(PublishError::CommitterStopped { height: 4 })
            ));
        });
    }

    #[test]
    fn canceled_enqueue_preserves_publication_continuity() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open_gating_ingest(1)
                .await
                .expect("open Store");
            let physical = writer_store_client(&store.url, None).expect("build Store client");
            let targets = publication_target_client(&physical).expect("target namespace");
            let publisher = Publisher::connect(
                context.child("publisher_task"),
                &store.url,
                None,
                1,
                super::super::PublisherMetrics::new(&context.child("publisher")),
            )
            .await
            .expect("connect publisher");
            let state_operations = encode_operations(
                &(0..=3)
                    .map(|height| StateOperation::CommitFloor(None, Location::new(height)))
                    .collect::<Vec<_>>(),
            );
            let transaction_operations = encode_operations(
                &(0..=3)
                    .map(|height| {
                        TransactionOperation::<Sha256>::Commit(None, Location::new(height))
                    })
                    .collect::<Vec<_>>(),
            );
            let upload = |height| {
                queued_upload(
                    height,
                    queued_range(&state_operations, height, height + 1),
                    queued_range(&transaction_operations, height, height + 1),
                )
            };

            let mut first = publisher.enqueue_queued_finalized(upload(1)).await.unwrap();
            store.wait_for_first_ingest().await;
            first.persisted().await.unwrap();
            let second = publisher.enqueue_queued_finalized(upload(2)).await.unwrap();
            {
                let mut enqueue = Box::pin(publisher.enqueue_queued_finalized(upload(3)));
                assert!(futures::poll!(enqueue.as_mut()).is_pending());
            }

            store.release_first_ingest();
            let third = publisher.enqueue_queued_finalized(upload(3)).await.unwrap();
            for completion in [first, second, third] {
                completion.published().await.unwrap();
            }
            for height in 1..=3 {
                assert!(target(&targets, height).await.is_some());
            }
            publisher.shutdown().await;
            store.shutdown().await;
        });
    }

    #[test]
    fn chunk_commits_overlap_within_limit_and_wait_for_every_chunk() {
        use std::time::Duration;

        commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::default().with_worker_threads(1),
        )
        .start(|context| async move {
            let store =
                crate::test_store::GatedIngestStore::open_gating_ingests(0..MAX_CONCURRENT_CHUNKS)
                    .await
                    .expect("open Store");
            let physical = writer_store_client(&store.url, None).expect("build Store client");
            let client = PrefixedStoreClient::empty(physical.clone());
            let metrics = super::super::StoreCommitMetrics::new(&context);
            let count = MAX_CONCURRENT_CHUNKS + 2;
            let mut batch = StoreWriteBatch::new();
            for index in 0..count {
                let key = Key::from((index as u64).to_be_bytes().to_vec());
                batch
                    .push(&client, &key, Bytes::from(vec![7; 1024]))
                    .unwrap();
            }
            let expected = batch.entries().to_vec();
            let batches = batch.split(1, DATA_REQUEST_BYTES).unwrap();
            assert_eq!(batches.len(), count);
            let mut commit = context.spawn(move |context| async move {
                commit_chunks(context, &physical, &metrics, batches).await
            });

            tokio::time::timeout(
                Duration::from_secs(5),
                store.wait_for_ingests(MAX_CONCURRENT_CHUNKS),
            )
            .await
            .expect("chunks overlap");
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    store.wait_for_ingests(MAX_CONCURRENT_CHUNKS + 1),
                )
                .await
                .is_err()
            );

            // Later chunks can finish while the other initial chunks remain blocked.
            store.release_first_ingest();
            tokio::time::timeout(Duration::from_secs(5), store.wait_for_ingests(count))
                .await
                .expect("completed requests free concurrency slots");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut commit)
                    .await
                    .is_err()
            );

            for _ in 1..MAX_CONCURRENT_CHUNKS {
                store.release_first_ingest();
            }
            tokio::time::timeout(Duration::from_secs(5), commit)
                .await
                .expect("all chunks finish")
                .expect("commit task succeeds")
                .expect("all chunks are durable");
            for (key, value) in expected {
                assert_eq!(client.query().get(&key).await.unwrap(), Some(value));
            }
            store.shutdown().await;
        });
    }

    #[test]
    fn chunk_commit_rejection_does_not_wait_for_other_chunks() {
        use axum::{Router, http::StatusCode};
        use std::time::Duration;

        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (arrived, mut requests) = mpsc::unbounded_channel();
            let app = Router::new().fallback(move || {
                let arrived = arrived.clone();
                async move {
                    let (release, status) = oneshot::channel::<StatusCode>();
                    arrived.send(release).unwrap();
                    (
                        status.await.unwrap(),
                        [("content-type", "application/json")],
                        r#"{"code":"invalid_argument","message":"invalid chunk"}"#,
                    )
                }
            });
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let physical = writer_store_client(&url, None).unwrap();
            let client = PrefixedStoreClient::empty(physical.clone());
            let metrics = super::super::StoreCommitMetrics::new(&context);
            let mut batch = StoreWriteBatch::new();
            batch.push(&client, &Key::from(vec![1]), vec![1]).unwrap();
            let commit = context.spawn(move |context| async move {
                commit_chunks(
                    context,
                    &physical,
                    &metrics,
                    vec![batch; MAX_CONCURRENT_CHUNKS + 1],
                )
                .await
            });

            let mut held = Vec::new();
            for _ in 0..MAX_CONCURRENT_CHUNKS {
                held.push(
                    tokio::time::timeout(Duration::from_secs(5), requests.recv())
                        .await
                        .expect("chunk starts")
                        .unwrap(),
                );
            }
            held.pop().unwrap().send(StatusCode::BAD_REQUEST).unwrap();
            let error = tokio::time::timeout(Duration::from_secs(5), commit)
                .await
                .expect("rejection does not wait for blocked chunks")
                .expect("commit task succeeds")
                .expect_err("rejected chunk fails the block");
            assert_eq!(
                error.rpc_code(),
                Some(exoware_sdk::ErrorCode::InvalidArgument)
            );
            assert!(requests.try_recv().is_err());
            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn delayed_publication_allows_bounded_data_progress_and_coalesces_completions() {
        commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::default().with_worker_threads(1),
        )
        .start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open_gating_ingest(1)
                .await
                .expect("open Store");
            let physical = writer_store_client(&store.url, None).expect("build Store client");
            let targets = publication_target_client(&physical).expect("target namespace");
            let metrics = super::super::PublisherMetrics::new(&context.child("publisher"));
            let publisher = Publisher::connect(
                context.child("publisher_task"),
                &store.url,
                None,
                3,
                metrics.clone(),
            )
            .await
            .expect("connect publisher");
            let state_operations = encode_operations(
                &(0..=4)
                    .map(|height| StateOperation::CommitFloor(None, Location::new(height)))
                    .collect::<Vec<_>>(),
            );
            let transaction_operations = encode_operations(
                &(0..=4)
                    .map(|height| {
                        TransactionOperation::<Sha256>::Commit(None, Location::new(height))
                    })
                    .collect::<Vec<_>>(),
            );
            let finalized_ts_micros = i64::try_from(
                (SystemTime::now() - std::time::Duration::from_secs(60))
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_micros(),
            )
            .unwrap();
            let upload = |height| {
                let mut upload = queued_upload(
                    height,
                    queued_range(&state_operations, height, height + 1),
                    queued_range(&transaction_operations, height, height + 1),
                );
                upload.finalized_ts_micros = finalized_ts_micros;
                upload
            };

            let mut first = publisher.enqueue_queued_finalized(upload(1)).await.unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                store.wait_for_first_ingest(),
            )
            .await
            .expect("first publication reaches Store");
            first.persisted().await.unwrap();
            let mut second = publisher.enqueue_queued_finalized(upload(2)).await.unwrap();
            let mut third = publisher.enqueue_queued_finalized(upload(3)).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                second.persisted().await.unwrap();
                third.persisted().await.unwrap();
            })
            .await
            .expect("later data persists while publication is delayed");
            let encoded_metrics = context.encode();
            assert!(has_metric_value(&encoded_metrics, "chunk_commits_total", 3));
            assert!(has_metric_value(
                &encoded_metrics,
                "finalization_to_publication_duration_count",
                0
            ));
            for height in 1..=3 {
                assert!(target(&targets, height).await.is_none());
            }

            let mut fourth = publisher.enqueue_queued_finalized(upload(4)).await.unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), fourth.persisted())
                    .await
                    .is_err(),
                "unpublished work remains bounded"
            );
            let mut shutdown = Box::pin(publisher.shutdown());
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), &mut shutdown)
                    .await
                    .is_err(),
                "shutdown waits for publication"
            );

            store.release_first_ingest();
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let first = first.published().await.unwrap();
                let second = second.published().await.unwrap();
                let third = third.published().await.unwrap();
                fourth.persisted().await.unwrap();
                let fourth = fourth.published().await.unwrap();
                assert!(first.store_sequence_number < second.store_sequence_number);
                assert_eq!(second.store_sequence_number, third.store_sequence_number);
                assert!(third.store_sequence_number < fourth.store_sequence_number);
                shutdown.await;
            })
            .await
            .expect("publisher drains after the barrier succeeds");
            let encoded_metrics = context.encode();
            assert!(
                has_metric_value(&encoded_metrics, "chunk_commits_total", 4),
                "{encoded_metrics}"
            );
            for metric in [
                "expansion_duration_count",
                "staging_duration_count",
                "prepare_wait_duration_count",
                "prepare_duration_count",
                "prepare_cpu_duration_count",
                "chunking_duration_count",
                "chunks_per_block_count",
                "transactions_per_block_count",
                "persist_duration_count",
                "finalization_to_publication_duration_count",
            ] {
                assert!(has_metric_value(&encoded_metrics, metric, 4));
            }
            let metric_sum = |name: &str| {
                encoded_metrics
                    .lines()
                    .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                    .unwrap_or_else(|| panic!("missing metric {name}"))
                    .parse::<f64>()
                    .expect("numeric metric sum")
            };
            assert_eq!(metric_sum("publisher_chunks_per_block_sum"), 4.0);

            // The fourth upload cannot begin preparation while the barrier is held.
            let wait_sum = metric_sum("publisher_prepare_wait_duration_sum");
            assert!(
                wait_sum >= 0.05,
                "publisher queue waiting is included in {wait_sum}"
            );

            // Each recorded block already waited a minute before publisher admission.
            let lag_sum = metric_sum("publisher_finalization_to_publication_duration_sum");
            assert!(lag_sum >= 240.0, "queue waiting is included in {lag_sum}");
            store.shutdown().await;
        });
    }

    #[test]
    fn publication_does_not_cross_an_out_of_order_gap() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (store, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let physical = writer_store_client(&url, None).expect("build Store client");
            let clients = WorkerClients {
                state: state_qmdb_client(&physical).expect("state namespace"),
                transactions: transactions_qmdb_client(&physical).expect("transaction namespace"),
                targets: publication_target_client(&physical).expect("target namespace"),
                sql_schema: Arc::new(
                    build_meta_schema(sql_meta_client(&physical).expect("SQL metadata namespace"))
                        .expect("build SQL schema"),
                ),
                store: physical,
            };
            let metrics = super::super::PublisherMetrics::new(&context.child("publisher"));
            let first_digest = Sha256Digest::from([1; Sha256Digest::SIZE]);
            let second_digest = Sha256Digest::from([2; Sha256Digest::SIZE]);
            let (first_tx, first_rx) = oneshot::channel();
            let (second_tx, second_rx) = oneshot::channel();
            let state_operations = encode_operations(&[
                StateOperation::CommitFloor(None, Location::new(0)),
                StateOperation::CommitFloor(None, Location::new(1)),
                StateOperation::Delete(
                    AccountKey::try_from(&[7u8; 32][..]).expect("account key has fixed width"),
                ),
                StateOperation::CommitFloor(None, Location::new(2)),
            ]);
            let transaction_operations = encode_operations(&[
                TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
                TransactionOperation::<Sha256>::Commit(None, Location::new(1)),
                TransactionOperation::<Sha256>::Commit(None, Location::new(2)),
            ]);
            let mut pending = VecDeque::from([
                PendingPublication {
                    height: 1,
                    block_digest: first_digest,
                    finalized_ts_micros: 1,
                    published: first_tx,
                },
                PendingPublication {
                    height: 2,
                    block_digest: second_digest,
                    finalized_ts_micros: 2,
                    published: second_tx,
                },
            ]);
            let second_data = persisted_test_upload(
                &clients,
                2,
                queued_range(&state_operations, 2, 4),
                queued_range(&transaction_operations, 2, 3),
            )
            .await;
            let mut persisted = BTreeMap::from([(2, second_data)]);

            assert!(
                publish_ready_prefix::<Sha256>(&clients, &metrics, &pending, &persisted).is_none()
            );

            assert!(target(&clients.targets, 1).await.is_none());
            assert!(target(&clients.targets, 2).await.is_none());
            assert_eq!(pending.len(), 2);
            assert_eq!(persisted.len(), 1);

            let first_data = persisted_test_upload(
                &clients,
                1,
                queued_range(&state_operations, 1, 2),
                queued_range(&transaction_operations, 1, 2),
            )
            .await;
            persisted.insert(1, first_data);
            let (ready, sequence) =
                publish_ready_prefix::<Sha256>(&clients, &metrics, &pending, &persisted)
                    .expect("both blocks are ready")
                    .await;
            complete_publication(ready, sequence, &metrics, &mut pending, &mut persisted);

            let first = first_rx.await.expect("first publication completes");
            let second = second_rx.await.expect("second publication completes");
            assert_eq!(first.block_digest, first_digest);
            assert_eq!(second.block_digest, second_digest);
            assert_eq!(first.store_sequence_number, second.store_sequence_number);
            assert_eq!(target(&clients.targets, 1).await, Some(first_digest));
            assert_eq!(target(&clients.targets, 2).await, Some(second_digest));
            assert!(pending.is_empty());
            assert!(persisted.is_empty());

            store.abort();
            let _ = store.await;
        });
    }

    #[test]
    fn fresh_connect_rejects_existing_remote_rows() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (store, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let physical = writer_store_client(&url, None).expect("build Store client");
            let targets = publication_target_client(&physical).expect("target namespace");
            let key = Key::from(Bytes::copy_from_slice(&1u64.to_be_bytes()));
            targets
                .ingest()
                .put(&[(&key, &[1; Sha256Digest::SIZE])])
                .await
                .expect("seed stale target");
            let metrics = super::super::PublisherMetrics::new(&context.child("publisher"));

            let error = Publisher::<Sha256, ed25519::PublicKey>::connect_fresh_with_strategy(
                context.child("publisher_task"),
                &url,
                None,
                1,
                metrics,
                Sequential,
            )
            .await
            .expect_err("fresh connect rejects existing rows");

            assert!(matches!(
                error,
                PublishError::NonFreshNamespace {
                    family: "publication target"
                }
            ));
            store.abort();
            let _ = store.await;
        });
    }

    #[test]
    fn pin_omission_preserves_every_other_prepared_row() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = StoreClient::new("http://localhost:1");
            let schema = Arc::new(build_meta_schema(sql_meta_client(&store).unwrap()).unwrap());
            let metrics = super::super::PublisherMetrics::new(&context);
            let state_operations = encode_operations(
                &(0..=16)
                    .map(|location| StateOperation::CommitFloor(None, Location::new(location)))
                    .collect::<Vec<_>>(),
            );
            let transaction_operations = encode_operations(
                &(0..=16)
                    .map(|location| {
                        TransactionOperation::<Sha256>::Commit(None, Location::new(location))
                    })
                    .collect::<Vec<_>>(),
            );

            for start in 1..=16 {
                let state = queued_range(&state_operations, start, start + 1);
                let transactions = queued_range(&transaction_operations, start, start + 1);
                let expected_removed = state.pinned_nodes.len() + transactions.pinned_nodes.len();
                let prepare = |omit_pinned_nodes| {
                    prepare_data_batch(
                        state_qmdb_client(&store).unwrap(),
                        transactions_qmdb_client(&store).unwrap(),
                        schema.clone(),
                        Sequential,
                        PendingUpload {
                            enqueued_at: Instant::now(),
                            height: start,
                            block: test_block(start, &state, &transactions),
                            finalized_ts_micros: 1,
                            state: state.clone(),
                            transactions: transactions.clone(),
                            omit_pinned_nodes,
                            has_durable_range: Arc::new(AtomicBool::new(false)),
                            persisted: None,
                            published: None,
                        },
                        &metrics,
                    )
                    .expect("prepare data")
                };
                let (full, state_end, transaction_end) = prepare(false);
                let (trimmed, trimmed_state_end, trimmed_transaction_end) = prepare(true);
                let full: BTreeMap<_, _> = full.entries().iter().cloned().collect();
                let trimmed: BTreeMap<_, _> = trimmed.entries().iter().cloned().collect();
                assert_eq!(state_end, trimmed_state_end);
                assert_eq!(transaction_end, trimmed_transaction_end);
                assert_eq!(full.len() - trimmed.len(), expected_removed);
                for (key, value) in &trimmed {
                    assert_eq!(full.get(key), Some(value));
                }
                for (key, value) in full.iter().filter(|(key, _)| !trimmed.contains_key(*key)) {
                    let pins = match key[0] {
                        crate::namespaces::STATE_QMDB_PREFIX_VALUE => &state.pinned_nodes,
                        crate::namespaces::TRANSACTIONS_QMDB_PREFIX_VALUE => {
                            &transactions.pinned_nodes
                        }
                        _ => panic!("only QMDB pins may be removed"),
                    };
                    assert!(pins.iter().any(|pin| pin.as_ref() == value.as_ref()));
                }
            }
        });
    }

    #[test]
    fn omitted_pins_wait_for_predecessors_and_reset_after_restart() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open_gating_ingest(2)
                .await
                .expect("open Store");
            let physical = writer_store_client(&store.url, None).unwrap();
            let targets = publication_target_client(&physical).unwrap();
            let publisher = Publisher::connect(
                context.child("publisher_task"),
                &store.url,
                None,
                3,
                super::super::PublisherMetrics::new(&context.child("publisher")),
            )
            .await
            .unwrap();
            let state_operations = encode_operations(
                &(0..=10)
                    .map(|location| StateOperation::CommitFloor(None, Location::new(location)))
                    .collect::<Vec<_>>(),
            );
            let transaction_operations = encode_operations(
                &(0..=10)
                    .map(|location| {
                        TransactionOperation::<Sha256>::Commit(None, Location::new(location))
                    })
                    .collect::<Vec<_>>(),
            );
            let upload = |height| {
                let start = height + 6;
                queued_upload(
                    height,
                    queued_range(&state_operations, start, start + 1),
                    queued_range(&transaction_operations, start, start + 1),
                )
            };

            assert!(!publisher.has_durable_range.load(Ordering::Relaxed));
            let mut first = publisher.enqueue_queued_finalized(upload(1)).await.unwrap();
            first.persisted().await.unwrap();
            assert!(publisher.has_durable_range.load(Ordering::Relaxed));
            first.published().await.unwrap();

            let second = publisher.enqueue_queued_finalized(upload(2)).await.unwrap();
            store.wait_for_first_ingest().await;
            let mut third = publisher.enqueue_queued_finalized(upload(3)).await.unwrap();
            third.persisted().await.unwrap();
            assert!(target(&targets, 2).await.is_none());
            assert!(target(&targets, 3).await.is_none());
            store.release_first_ingest();
            second.published().await.unwrap();
            third.published().await.unwrap();

            let state = UnorderedClient::<
                QmdbFamily,
                Sha256,
                AccountKey,
                AccountValue,
                StateEncoding,
            >::new(state_qmdb_client(&physical).unwrap(), ());
            let transactions = KeylessClient::<
                QmdbFamily,
                Sha256,
                Sha256Digest,
                TransactionEncoding<Sha256>,
            >::new(transactions_qmdb_client(&physical).unwrap(), ());
            let expected = upload(3);
            let state_proof =
                Box::pin(state.operation_range_checkpoint(Location::new(9), Location::new(9), 1))
                    .await
                    .unwrap();
            let transaction_proof = Box::pin(transactions.operation_range_checkpoint(
                Location::new(9),
                Location::new(9),
                1,
            ))
            .await
            .unwrap();
            assert_eq!(state_proof.root, expected.block.header.state_root);
            assert_eq!(
                transaction_proof.root,
                expected.block.header.transactions_root
            );
            assert!(state_proof.verify::<Sha256>());
            assert!(transaction_proof.verify::<Sha256>());
            publisher.shutdown().await;

            let restarted = Publisher::connect(
                context.child("restarted_task"),
                &store.url,
                None,
                1,
                super::super::PublisherMetrics::new(&context.child("restarted")),
            )
            .await
            .unwrap();
            assert!(!restarted.has_durable_range.load(Ordering::Relaxed));
            restarted
                .enqueue_queued_finalized(upload(4))
                .await
                .unwrap()
                .published()
                .await
                .unwrap();
            let proof = Box::pin(transactions.operation_range_checkpoint(
                Location::new(10),
                Location::new(10),
                1,
            ))
            .await
            .unwrap();
            assert!(proof.verify::<Sha256>());
            restarted.shutdown().await;
            store.shutdown().await;
        });
    }

    #[test]
    fn data_preparation_authenticates_before_metadata_decoding() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = StoreClient::new("http://localhost:1");
            let schema = Arc::new(build_meta_schema(sql_meta_client(&store).unwrap()).unwrap());
            let metrics = super::super::PublisherMetrics::new(&context);
            let state_operations = encode_operations(&[
                StateOperation::CommitFloor(None, Location::new(0)),
                StateOperation::CommitFloor(None, Location::new(1)),
            ]);
            let transaction_operations = encode_operations(&[
                TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
                TransactionOperation::<Sha256>::Commit(None, Location::new(1)),
            ]);

            for corrupt_state in [true, false] {
                let mut state = queued_range(&state_operations, 1, 2);
                let mut transactions = queued_range(&transaction_operations, 1, 2);
                let block = test_block(1, &state, &transactions);

                // Invalid bytes must fail authentication before metadata tries to decode them.
                let range = if corrupt_state {
                    &mut state
                } else {
                    &mut transactions
                };
                range.operations[0].clear();

                let error = prepare_data_batch(
                    state_qmdb_client(&store).unwrap(),
                    transactions_qmdb_client(&store).unwrap(),
                    schema.clone(),
                    Sequential,
                    PendingUpload {
                        enqueued_at: Instant::now(),
                        height: 1,
                        block,
                        finalized_ts_micros: 1,
                        state,
                        transactions,
                        omit_pinned_nodes: false,
                        has_durable_range: Arc::new(AtomicBool::new(false)),
                        persisted: None,
                        published: None,
                    },
                    &metrics,
                )
                .unwrap_err();

                assert!(matches!(
                    error,
                    PublishError::Qmdb(QmdbError::ProofVerification { .. })
                ));
            }
        });
    }

    #[test]
    fn data_requests_preserve_rows_and_respect_byte_budget() {
        let store = StoreClient::new("http://localhost:1");
        let client = state_qmdb_client(&store).unwrap();
        let mut batch = StoreWriteBatch::new();
        for index in 0..3u8 {
            let key = Key::from(vec![index; 32]);
            batch
                .push(&client, &key, Bytes::from(vec![index; 64]))
                .unwrap();
        }
        let expected = batch.entries().to_vec();
        let row_size = batch.encoded_len() / batch.len();
        let requests = batch
            .clone()
            .split(DATA_REQUEST_ROWS, row_size * 2)
            .unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].len(), 2);
        assert_eq!(requests[1].len(), 1);
        assert_eq!(
            requests
                .iter()
                .flat_map(|batch| batch.entries().iter())
                .collect::<Vec<_>>(),
            expected.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            batch
                .clone()
                .split(DATA_REQUEST_ROWS, row_size * 3)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            batch.split(DATA_REQUEST_ROWS, row_size - 1).unwrap_err(),
            exoware_sdk::SplitError::EntryTooLarge {
                index: 0,
                encoded_bytes: row_size,
                max_encoded_bytes: row_size - 1,
            }
        );
    }

    #[test]
    fn data_requests_bound_rows_independently_of_bytes() {
        let store = StoreClient::new("http://localhost:1");
        let client = PrefixedStoreClient::empty(store);
        let key = Key::from(vec![0; 32]);
        let mut batch = StoreWriteBatch::new();
        for _ in 0..=DATA_REQUEST_ROWS {
            batch.push(&client, &key, Bytes::new()).unwrap();
        }
        let batches = batch.split(DATA_REQUEST_ROWS, DATA_REQUEST_BYTES).unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), DATA_REQUEST_ROWS);
        assert_eq!(batches[1].len(), 1);
    }

    #[test]
    #[ignore = "builds and uploads a deployment-sized block"]
    fn large_block_data_uploads_with_bounded_requests() {
        use constantinople_primitives::{Nonce, Transaction, TransactionPublicKey};
        use std::num::NonZeroU64;

        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let proposal_mib = std::env::var("CONSTANTINOPLE_TEST_PROPOSAL_MIB")
                .map(|value| value.parse::<usize>().expect("proposal MiB is numeric"))
                .unwrap_or(32);
            let limit = proposal_mib * 1024 * 1024;
            let mut body = Vec::new();
            let mut body_bytes = 0;
            let mut state_ops = vec![StateOperation::CommitFloor(None, Location::new(0))];
            let mut transaction_ops = vec![TransactionOperation::<Sha256>::Commit(
                None,
                Location::new(0),
            )];
            for index in 0u64.. {
                let sender = ed25519::PrivateKey::from_seed(index * 2);
                let receiver = ed25519::PrivateKey::from_seed(index * 2 + 1);
                let sender_key = TransactionPublicKey::ed25519(sender.public_key());
                let receiver_key = TransactionPublicKey::ed25519(receiver.public_key());
                let transaction = Transaction::<Sha256Digest>::new(
                    sender_key.clone(),
                    receiver_key.clone(),
                    NonZeroU64::new(1).unwrap(),
                    0,
                )
                .seal_and_sign(
                    &sender,
                    b"request-size-test",
                    &mut Sha256::default(),
                );
                if body_bytes + transaction.encode_size() > limit {
                    break;
                }
                body_bytes += transaction.encode_size();
                for (key, balance, nonce) in [(&sender_key, 99, 1), (&receiver_key, 101, 0)] {
                    let account = Account {
                        balance,
                        nonce: Nonce {
                            base: nonce,
                            bitmap: 0,
                        },
                    };
                    state_ops.push(StateOperation::Update(UnorderedUpdate(
                        AccountKey::from_public_key(key),
                        AccountValue::try_from(account.encode().as_ref())
                            .expect("fixed account value"),
                    )));
                }
                transaction_ops.push(TransactionOperation::<Sha256>::Append(
                    *transaction.message_digest(),
                ));
                body.push(transaction);
            }
            state_ops.push(StateOperation::CommitFloor(None, Location::new(1)));
            transaction_ops.push(TransactionOperation::<Sha256>::Commit(
                None,
                Location::new(1),
            ));
            let state = queued_range(&encode_operations(&state_ops), 1, state_ops.len() as u64);
            let transactions = queued_range(
                &encode_operations(&transaction_ops),
                1,
                transaction_ops.len() as u64,
            );
            drop((state_ops, transaction_ops));
            let header = test_block(1, &state, &transactions).header.clone();
            let block = Block::new(header, body).seal(&mut Sha256::default()).into();
            let (server, url) = exoware_simulator::open_temp().await.expect("open Store");
            let physical = writer_store_client(&url, None).expect("Store client");
            let schema = Arc::new(build_meta_schema(sql_meta_client(&physical).unwrap()).unwrap());
            let (batch, _, _) = prepare_data_batch(
                state_qmdb_client(&physical).unwrap(),
                transactions_qmdb_client(&physical).unwrap(),
                schema,
                Sequential,
                PendingUpload {
                    enqueued_at: Instant::now(),
                    height: 1,
                    block,
                    finalized_ts_micros: 1,
                    state,
                    transactions,
                    omit_pinned_nodes: false,
                    has_durable_range: Arc::new(AtomicBool::new(false)),
                    persisted: None,
                    published: None,
                },
                &super::super::PublisherMetrics::new(&context.child("publisher")),
            )
            .expect("prepare full block data");
            let materialized_bytes: usize = batch
                .entries()
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum();
            eprintln!(
                "proposal_bytes={body_bytes} rows={} materialized_bytes={materialized_bytes}",
                batch.len()
            );
            let batches = batch.split(DATA_REQUEST_ROWS, DATA_REQUEST_BYTES).unwrap();
            eprintln!("data_requests={}", batches.len());
            if proposal_mib == 32 {
                assert!(batches.len() > 1);
            }
            for batch in batches {
                batch.commit(&physical).await.expect("bounded data request");
            }
            server.abort();
            let _ = server.await;
        });
    }

    #[test]
    fn queued_uploads_publish_both_ranges_and_targets() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (store, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let physical = writer_store_client(&url, None).expect("build Store client");
            let state_client = state_qmdb_client(&physical).expect("state namespace");
            let transaction_client =
                transactions_qmdb_client(&physical).expect("transaction namespace");
            let target_client = publication_target_client(&physical).expect("target namespace");
            let metrics = super::super::PublisherMetrics::new(&context.child("publisher"));
            let publisher =
                Publisher::connect(context.child("publisher_task"), &url, None, 2, metrics)
                    .await
                    .expect("connect publisher");

            let state_operations = [
                StateOperation::CommitFloor(None, Location::new(0)),
                StateOperation::CommitFloor(None, Location::new(1)),
                StateOperation::CommitFloor(None, Location::new(2)),
            ];
            let transaction_operations = [
                TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
                TransactionOperation::<Sha256>::Commit(None, Location::new(1)),
                TransactionOperation::<Sha256>::Commit(None, Location::new(2)),
            ];
            let state_encoded = encode_operations(&state_operations);
            let transaction_encoded = encode_operations(&transaction_operations);
            let first_state = queued_range(&state_encoded, 1, 2);
            let first_transactions = queued_range(&transaction_encoded, 1, 2);
            let second_state = queued_range(&state_encoded, 2, 3);
            let second_transactions = queued_range(&transaction_encoded, 2, 3);
            let first = queued_upload(1, first_state, first_transactions);
            let first_digest = *first.block.seal();
            let second = queued_upload(2, second_state, second_transactions);
            let second_digest = *second.block.seal();

            let mut first = publisher
                .enqueue_queued_finalized(first)
                .await
                .expect("enqueue first upload");
            let mut second = publisher
                .enqueue_queued_finalized(second)
                .await
                .expect("enqueue second upload");
            first.persisted().await.expect("persist first upload");
            second.persisted().await.expect("persist second upload");
            let first_receipt = first.published().await.expect("publish first upload");
            let second_receipt = second.published().await.expect("publish second upload");

            assert!(first_receipt.store_sequence_number <= second_receipt.store_sequence_number);
            assert_eq!(target(&target_client, 1).await, Some(first_digest));
            assert_eq!(target(&target_client, 2).await, Some(second_digest));
            let state = UnorderedClient::<
                QmdbFamily,
                Sha256,
                AccountKey,
                AccountValue,
                StateEncoding,
            >::new(state_client, ());
            let transactions = KeylessClient::<
                QmdbFamily,
                Sha256,
                Sha256Digest,
                TransactionEncoding<Sha256>,
            >::new(transaction_client, ());
            assert_eq!(
                state
                    .writer_location_watermark()
                    .await
                    .expect("read state watermark"),
                Some(Location::new(2))
            );
            assert_eq!(
                transactions
                    .writer_location_watermark()
                    .await
                    .expect("read transaction watermark"),
                Some(Location::new(2))
            );

            publisher.shutdown().await;
            store.abort();
            let _ = store.await;
        });
    }

    async fn target(client: &PrefixedStoreClient, height: u64) -> Option<Sha256Digest> {
        let key = Key::from(Bytes::copy_from_slice(&height.to_be_bytes()));
        let value = client
            .query()
            .get(&key)
            .await
            .expect("read publication target")?;
        Sha256Digest::decode(value).ok()
    }

    async fn persisted_test_upload(
        clients: &WorkerClients,
        height: u64,
        state: QueuedAuthenticatedRange<Sha256Digest>,
        transactions: QueuedAuthenticatedRange<Sha256Digest>,
    ) -> PersistedUpload {
        let state_root = queued_range_root(&state);
        let transactions_root = queued_range_root(&transactions);
        let state = prepare_authenticated_range::<QmdbFamily, Sha256, StateOperation, Sequential>(
            &as_authenticated_range(&state),
            &state_root,
            &(),
            &Sequential,
        )
        .expect("prepare state range");
        let transactions = prepare_authenticated_range::<
            QmdbFamily,
            Sha256,
            TransactionOperation<Sha256>,
            Sequential,
        >(
            &as_authenticated_range(&transactions),
            &transactions_root,
            &(),
            &Sequential,
        )
        .expect("prepare transaction range");
        let mut batch = StoreWriteBatch::new();
        let state_end = state.latest_location();
        let transaction_end = transactions.latest_location();
        stage_authenticated_range(&clients.state, state, &mut batch).expect("stage state range");
        stage_authenticated_range(&clients.transactions, transactions, &mut batch)
            .expect("stage transaction range");
        batch
            .commit(&clients.store)
            .await
            .expect("commit test data");
        PersistedUpload {
            height,
            state: state_end,
            transactions: transaction_end,
            persisted_at: Instant::now(),
        }
    }

    fn encode_operations<T: Encode>(operations: &[T]) -> Vec<Vec<u8>> {
        operations
            .iter()
            .map(|operation| operation.encode().to_vec())
            .collect()
    }

    fn queued_range(
        all_operations: &[Vec<u8>],
        start: u64,
        end: u64,
    ) -> QueuedAuthenticatedRange<Sha256Digest> {
        let hasher = commonware_storage::qmdb::hasher::<Sha256>();
        let mut memory = Mem::<QmdbFamily, _>::new();
        let mut batch = memory.new_batch();
        for operation in &all_operations[..usize::try_from(end).expect("range end fits usize")] {
            batch = batch.add(&hasher, operation);
        }
        let batch = batch.merkleize(&memory, &hasher);
        memory.apply_batch(&batch).expect("apply test operations");
        let start = Location::new(start);
        let end = Location::new(end);
        let inactive_peaks = QmdbFamily::inactive_peaks(end, start);
        let proof = memory
            .range_proof(&hasher, start..end, inactive_peaks)
            .expect("build range proof");
        let pinned_nodes = QmdbFamily::nodes_to_pin(start)
            .map(|position| memory.get_node(position).expect("pinned node exists"))
            .collect();
        QueuedAuthenticatedRange {
            start: start.as_u64(),
            end: end.as_u64(),
            proof,
            pinned_nodes,
            operations: all_operations[usize::try_from(start.as_u64())
                .expect("range start fits usize")
                ..usize::try_from(end.as_u64()).expect("range end fits usize")]
                .to_vec(),
        }
    }

    fn queued_upload(
        height: u64,
        state: QueuedAuthenticatedRange<Sha256Digest>,
        transactions: QueuedAuthenticatedRange<Sha256Digest>,
    ) -> QueuedFinalizedUpload<Sha256, ed25519::PublicKey, MinSig> {
        let block = test_block(height, &state, &transactions);
        let finalization = test_finalization(&block);
        queued_upload_from(block, finalization, state, transactions)
    }

    fn queued_upload_from(
        block: EngineBlock<Sha256, ed25519::PublicKey>,
        finalization: TestFinalization,
        state: QueuedAuthenticatedRange<Sha256Digest>,
        transactions: QueuedAuthenticatedRange<Sha256Digest>,
    ) -> QueuedFinalizedUpload<Sha256, ed25519::PublicKey, MinSig> {
        let upload = QueuedFinalizedUpload {
            finalized_ts_micros: i64::try_from(block.header.height).expect("height fits timestamp"),
            block,
            finalization,
            state,
            transactions,
        };
        upload.validate().expect("test upload validates");
        upload
    }

    fn test_block(
        height: u64,
        state: &QueuedAuthenticatedRange<Sha256Digest>,
        transactions: &QueuedAuthenticatedRange<Sha256Digest>,
    ) -> EngineBlock<Sha256, ed25519::PublicKey> {
        let state_root = queued_range_root(state);
        let transactions_root = queued_range_root(transactions);
        let leader = ed25519::PrivateKey::from_seed(height).public_key();
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), test_commitment(Sha256Digest::EMPTY)),
            },
            parent: Sha256Digest::EMPTY,
            height,
            timestamp: height,
            state_root,
            state_range: non_empty_range!(state.start, state.end),
            transactions_root,
            transactions_range: non_empty_range!(transactions.start, transactions.end),
        };
        EngineBlock::from(
            Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
                .seal(&mut Sha256::default()),
        )
    }

    fn captured_range<Op>(
        range: &QueuedAuthenticatedRange<Sha256Digest>,
        root: Sha256Digest,
        operations: Vec<Op>,
    ) -> FinalizedRange<Sha256Digest, Op> {
        let start = usize::try_from(range.start).expect("range start fits usize");
        let end = usize::try_from(range.end).expect("range end fits usize");
        FinalizedRange {
            start: Location::new(range.start),
            end: Location::new(range.end),
            root,
            proof: range.proof.clone(),
            pinned_nodes: range.pinned_nodes.clone(),
            operations: Arc::new(operations.into_iter().take(end).skip(start).collect()),
        }
    }

    fn queued_range_root(range: &QueuedAuthenticatedRange<Sha256Digest>) -> Sha256Digest {
        range
            .proof
            .reconstruct_root(
                &commonware_storage::qmdb::hasher::<Sha256>(),
                &range.operations,
                Location::new(range.start),
            )
            .expect("reconstruct queued range root")
    }

    fn test_finalization(block: &EngineBlock<Sha256, ed25519::PublicKey>) -> TestFinalization {
        let mut rng = StdRng::from_seed([7; 32]);
        let fixture = standard::fixture::<MinSig, _>(&mut rng, b"qmdb-test", 4);
        let commitment = test_commitment(*block.seal());
        let proposal = Proposal::new(block.header.context.round, View::zero(), commitment);
        let finalizes = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalization"))
            .collect::<Vec<_>>();
        let finalizes = commonware_utils::iter::NonEmpty::try_new(finalizes.iter())
            .expect("test finalizations are non-empty");
        Finalization::from_finalizes(&fixture.verifier, finalizes, &Sequential)
            .expect("assemble finalization")
    }

    fn test_commitment(block: Sha256Digest) -> TestCommitment {
        TestCommitment::from((
            block,
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            commonware_coding::Config {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(1),
            },
        ))
    }
}
