//! Stateless finalized SQL and QMDB publication.

use super::{
    block::{encode_block_meta_only_at, encode_bulk_block_rows},
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
use bytes::{Buf as _, Bytes};
use commonware_codec::{
    Codec, Decode, DecodeExt as _, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg,
    Read, ReadExt, Write,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant, sha256::Sha256,
};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::Spawner;
use commonware_storage::{
    merkle::{Location, Proof, mmr},
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
use constantinople_application::consensus::{FinalizedArtifacts, FinalizedRange};
use constantinople_engine::types::{EngineBlock, EngineFinalization};
use constantinople_primitives::{Account, AccountKey, BlockCfg};
use exoware_qmdb::{
    AuthenticatedOperationRange, PreparedAuthenticatedWatermark, QmdbError,
    prepare_keyless_authenticated_range_with_strategy,
    prepare_unordered_authenticated_range_with_strategy, stage_authenticated_range,
    stage_authenticated_watermark,
};
use exoware_sdk::{ClientError, PrefixedStoreClient, StoreClient, StoreWriteBatch, keys::Key};
use exoware_sql::{BatchWriter, KvSchema};
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::debug;

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
const STORE_CHUNK_MAX_ROWS: usize = 100_000;
const STORE_CHUNK_MAX_MATERIALIZED_BYTES: usize = 32 * 1024 * 1024;

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

/// Completion signal for a queued finalized-block upload.
pub struct UploadCompletion<D: Digest> {
    height: u64,
    rx: oneshot::Receiver<PublicationReceipt<D>>,
}

impl<D: Digest> UploadCompletion<D> {
    /// Wait until all rows are durable and the contiguous prefix is published.
    pub async fn wait(self) -> Result<PublicationReceipt<D>, PublishError> {
        self.rx.await.map_err(|_| PublishError::CommitterStopped {
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

impl Default for QueuedAuthenticatedRangeCfg {
    fn default() -> Self {
        Self {
            proof_digests: 512,
            pinned_nodes: RangeCfg::from(0..=256),
            operations: RangeCfg::from(1..=1_000_000),
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

/// Exact half-open operation range captured from a finalized batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedAuthenticatedRange<D: Digest> {
    pub start: u64,
    pub end: u64,
    pub proof: Proof<QmdbFamily, D>,
    pub pinned_nodes: Vec<D>,
    pub encoded_operations: Vec<Vec<u8>>,
}

impl<D: Digest> QueuedAuthenticatedRange<D> {
    fn from_finalized_range<Op: Encode>(range: FinalizedRange<D, Op>) -> Self {
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
            encoded_operations: operations
                .iter()
                .map(|operation| operation.encode().to_vec())
                .collect(),
        }
    }
}

impl<D: Digest> EncodeSize for QueuedAuthenticatedRange<D> {
    fn encode_size(&self) -> usize {
        self.start.encode_size()
            + self.end.encode_size()
            + self.proof.encode_size()
            + self.pinned_nodes.encode_size()
            + self.encoded_operations.encode_size()
    }
}

impl<D: Digest> Write for QueuedAuthenticatedRange<D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.start.write(buf);
        self.end.write(buf);
        self.proof.write(buf);
        self.pinned_nodes.write(buf);
        self.encoded_operations.write(buf);
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
            encoded_operations: Vec::<Vec<u8>>::read_cfg(
                buf,
                &(cfg.operations, (cfg.operation_bytes, ())),
            )?,
        })
    }
}

/// Self-contained durable queue payload.
pub struct QueuedFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    block: EngineBlock<H, P>,
    finalization: EngineFinalization<P, V, H>,
    finalized_ts_micros: i64,
    metadata_encoder_version: u16,
    state: QueuedAuthenticatedRange<H::Digest>,
    transactions: QueuedAuthenticatedRange<H::Digest>,
}

impl<H, P, V> Clone for QueuedFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    EngineFinalization<P, V, H>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            block: self.block.clone(),
            finalization: self.finalization.clone(),
            finalized_ts_micros: self.finalized_ts_micros,
            metadata_encoder_version: self.metadata_encoder_version,
            state: self.state.clone(),
            transactions: self.transactions.clone(),
        }
    }
}

impl<H, P, V> QueuedFinalizedUpload<H, P, V>
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
            metadata_encoder_version: METADATA_ENCODER_VERSION,
            state,
            transactions,
        };
        upload.validate()?;
        Ok(upload)
    }

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
        if self.metadata_encoder_version != METADATA_ENCODER_VERSION {
            return Err(PublishError::UnsupportedMetadataEncoder {
                version: self.metadata_encoder_version,
            });
        }
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

fn validate_range<D: Digest>(
    range: &QueuedAuthenticatedRange<D>,
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
    if count != Some(range.encoded_operations.len()) {
        return Err(PublishError::InvalidQueuedUpload {
            reason: "authenticated operation count does not match the range",
        });
    }
    Ok(())
}

impl<P, V> EncodeSize for QueuedFinalizedUpload<Sha256, P, V>
where
    P: PublicKey,
    V: Variant,
    EngineBlock<Sha256, P>: EncodeSize,
    EngineFinalization<P, V, Sha256>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        QUEUE_MAGIC.encode_size()
            + QUEUE_FORMAT_VERSION.encode_size()
            + ROW_LAYOUT_VERSION.encode_size()
            + self.metadata_encoder_version.encode_size()
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

impl<P, V> Write for QueuedFinalizedUpload<Sha256, P, V>
where
    P: PublicKey,
    V: Variant,
    EngineBlock<Sha256, P>: Write,
    EngineFinalization<P, V, Sha256>: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        QUEUE_MAGIC.write(buf);
        QUEUE_FORMAT_VERSION.write(buf);
        ROW_LAYOUT_VERSION.write(buf);
        self.metadata_encoder_version.write(buf);
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
            metadata_encoder_version,
            state: QueuedAuthenticatedRange::read_cfg(buf, &cfg.state)?,
            transactions: QueuedAuthenticatedRange::read_cfg(buf, &cfg.transactions)?,
        };
        upload.validate().map_err(|_| {
            CodecError::Invalid("QueuedFinalizedUpload", "invalid finalized upload payload")
        })?;
        Ok(upload)
    }
}

/// Queue representation that defers structured decoding until admission.
pub struct StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    inner: StoredFinalizedUploadInner<H, P, V>,
}

enum StoredFinalizedUploadInner<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    Decoded(QueuedFinalizedUpload<H, P, V>),
    Encoded {
        bytes: Bytes,
        cfg: QueuedFinalizedUploadCfg,
    },
}

impl<H, P, V> From<QueuedFinalizedUpload<H, P, V>> for StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    fn from(upload: QueuedFinalizedUpload<H, P, V>) -> Self {
        Self {
            inner: StoredFinalizedUploadInner::Decoded(upload),
        }
    }
}

impl<H, P, V> StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    QueuedFinalizedUpload<H, P, V>: EncodeSize,
{
    pub fn encoded_len(&self) -> usize {
        match &self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => upload.encode_size(),
            StoredFinalizedUploadInner::Encoded { bytes, .. } => bytes.len(),
        }
    }
}

impl<H, P, V> StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    QueuedFinalizedUpload<H, P, V>: Read<Cfg = QueuedFinalizedUploadCfg>,
{
    pub fn into_decoded(self) -> Result<QueuedFinalizedUpload<H, P, V>, CodecError> {
        match self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => Ok(upload),
            StoredFinalizedUploadInner::Encoded { bytes, cfg } => {
                QueuedFinalizedUpload::decode_cfg(bytes, &cfg)
            }
        }
    }
}

impl<H, P, V> EncodeSize for StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    QueuedFinalizedUpload<H, P, V>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.encoded_len()
    }
}

impl<H, P, V> Write for StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    QueuedFinalizedUpload<H, P, V>: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match &self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => upload.write(buf),
            StoredFinalizedUploadInner::Encoded { bytes, .. } => buf.put_slice(bytes),
        }
    }
}

impl<H, P, V> Read for StoredFinalizedUpload<H, P, V>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    type Cfg = QueuedFinalizedUploadCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            inner: StoredFinalizedUploadInner::Encoded {
                bytes: buf.copy_to_bytes(buf.remaining()),
                cfg: cfg.clone(),
            },
        })
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
    #[error("failed to chunk Store batch due to {0}")]
    StoreBatchChunk(#[from] exoware_sdk::StoreWriteBatchChunkError),
    #[error("failed to configure SQL metadata schema due to {0}")]
    SqlSchema(String),
    #[error("failed to stage SQL metadata rows due to {0}")]
    Sql(#[from] datafusion::error::DataFusionError),
    #[error("failed to encode SQL metadata row due to {0}")]
    SqlRow(String),
    #[error("unsupported metadata encoder version {version}")]
    UnsupportedMetadataEncoder { version: u16 },
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
    join: Option<JoinHandle<()>>,
    _marker: PhantomData<P>,
}

struct PendingUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    height: u64,
    block: EngineBlock<H, P>,
    finalized_ts_micros: i64,
    metadata_encoder_version: u16,
    state: QueuedAuthenticatedRange<H::Digest>,
    transactions: QueuedAuthenticatedRange<H::Digest>,
    completion: Option<oneshot::Sender<PublicationReceipt<H::Digest>>>,
}

struct PendingPublication<D: Digest> {
    height: u64,
    block_digest: D,
    completion: oneshot::Sender<PublicationReceipt<D>>,
}

struct PersistedUpload {
    height: u64,
    state: PreparedAuthenticatedWatermark,
    transactions: PreparedAuthenticatedWatermark,
}

struct WorkerClients {
    store: StoreClient,
    state: PrefixedStoreClient,
    transactions: PrefixedStoreClient,
    targets: PrefixedStoreClient,
    sql_schema: KvSchema,
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
            sql_schema: build_meta_schema(sql_meta_client(&store)?)
                .map_err(PublishError::SqlSchema)?,
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
        *admission = Some(Admission {
            next_height: height
                .checked_add(1)
                .ok_or(PublishError::InvalidQueuedUpload {
                    reason: "finalized height overflows",
                })?,
            state_next: upload.state.end,
            transaction_next: upload.transactions.end,
        });
        let (completion, rx) = oneshot::channel();
        let pending = PendingUpload {
            height,
            block: upload.block,
            finalized_ts_micros: upload.finalized_ts_micros,
            metadata_encoder_version: upload.metadata_encoder_version,
            state: upload.state,
            transactions: upload.transactions,
            completion: Some(completion),
        };
        self.tx
            .as_ref()
            .ok_or(PublishError::CommitterStopped { height })?
            .send(pending)
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        Ok(UploadCompletion { height, rx })
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
    let mut commits = JoinSet::new();
    let mut pending = VecDeque::new();
    let mut persisted = BTreeMap::new();
    loop {
        if rx_closed && commits.is_empty() {
            publish_ready_prefix::<H>(&clients, &metrics, &mut pending, &mut persisted).await;
            assert!(
                pending.is_empty(),
                "publisher stopped with an unpublished gap"
            );
            break;
        }

        tokio::select! {
            upload = rx.recv(), if !rx_closed && commits.len() < max_in_flight => {
                match upload {
                    Some(mut upload) => {
                        let publication = PendingPublication {
                            height: upload.height,
                            block_digest: *upload.block.seal(),
                            completion: upload
                                .completion
                                .take()
                                .expect("pending upload completion must be present"),
                        };
                        pending.push_back(publication);
                        spawn_data_commit(
                            &mut commits,
                            context.child("data"),
                            &clients,
                            strategy.clone(),
                            metrics.commit.clone(),
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
                publish_ready_prefix::<H>(
                    &clients,
                    &metrics,
                    &mut pending,
                    &mut persisted,
                )
                .await;
            }
        }
    }
    debug!("stateless finalized publisher task exiting after channel closure");
}

fn spawn_data_commit<Cx, H, P, S>(
    commits: &mut JoinSet<Result<PersistedUpload, PublishError>>,
    _context: Cx,
    clients: &WorkerClients,
    strategy: S,
    metrics: super::StoreCommitMetrics,
    upload: PendingUpload<H, P>,
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
    commits.spawn(async move {
        let height = upload.height;
        let (batches, state, transactions) = prepare_data_batch::<H, P, S>(
            state_client,
            transaction_client,
            sql_schema,
            strategy,
            upload,
        )?;
        for batch in batches {
            super::commit_with_retry(&store, &batch, "finalized index data", &metrics).await?;
        }
        Ok(PersistedUpload {
            height,
            state,
            transactions,
        })
    });
}

fn prepare_data_batch<H, P, S>(
    state_client: PrefixedStoreClient,
    transaction_client: PrefixedStoreClient,
    sql_schema: KvSchema,
    strategy: S,
    upload: PendingUpload<H, P>,
) -> Result<
    (
        Vec<StoreWriteBatch>,
        PreparedAuthenticatedWatermark,
        PreparedAuthenticatedWatermark,
    ),
    PublishError,
>
where
    H: Hasher,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
    S: Strategy,
{
    let metadata_rows = encode_metadata_rows::<H, P>(
        upload.metadata_encoder_version,
        &upload.block,
        upload.finalized_ts_micros,
        &upload.state,
        &upload.transactions,
    )?;
    let state = prepare_unordered_authenticated_range_with_strategy::<
        QmdbFamily,
        H,
        AccountKey,
        AccountValue,
        StateEncoding,
        S,
    >(
        &as_authenticated_range(&upload.state),
        &upload.block.header.state_root,
        &(),
        &strategy,
    )?;
    let transactions = prepare_keyless_authenticated_range_with_strategy::<
        QmdbFamily,
        H,
        H::Digest,
        TransactionEncoding<H>,
        S,
    >(
        &as_authenticated_range(&upload.transactions),
        &upload.block.header.transactions_root,
        &(),
        &strategy,
    )?;
    let mut sql_writer = sql_schema.batch_writer();
    let sql = prepare_sql(&mut sql_writer, metadata_rows)?;
    let mut batch = StoreWriteBatch::new();
    sql_writer.stage_flush(&sql, &mut batch)?;
    let state = stage_authenticated_range(&state_client, state, &mut batch)?;
    let transactions = stage_authenticated_range(&transaction_client, transactions, &mut batch)?;
    let batches = batch.into_chunks(STORE_CHUNK_MAX_ROWS, STORE_CHUNK_MAX_MATERIALIZED_BYTES)?;
    Ok((batches, state, transactions))
}

fn as_authenticated_range<D: Digest>(
    range: &QueuedAuthenticatedRange<D>,
) -> AuthenticatedOperationRange<'_, D, QmdbFamily> {
    AuthenticatedOperationRange {
        start_location: Location::new(range.start),
        proof: &range.proof,
        pinned_nodes: &range.pinned_nodes,
        encoded_operations: &range.encoded_operations,
    }
}

fn encode_metadata_rows<H, P>(
    version: u16,
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
    if version != METADATA_ENCODER_VERSION {
        return Err(PublishError::UnsupportedMetadataEncoder { version });
    }
    let block_rows = encode_bulk_block_rows(block);
    validate_transaction_metadata_ops::<H>(&block_rows.transaction_digests, transactions)?;
    let mut rows = vec![encode_block_meta_only_at(block, finalized_ts_micros)];
    rows.extend(block_rows.sql);
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
    let mut actual = Vec::with_capacity(expected.len());
    for encoded in &range.encoded_operations {
        let operation = TransactionOperation::<H>::decode(encoded.as_slice()).map_err(|_| {
            PublishError::InvalidQueuedUpload {
                reason: "transaction operation bytes do not decode",
            }
        })?;
        if let keyless::Operation::Append(digest) = operation {
            actual.push(digest);
        }
    }
    if actual != expected {
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
    for (offset, encoded) in range.encoded_operations.iter().enumerate() {
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

async fn publish_ready_prefix<H>(
    clients: &WorkerClients,
    metrics: &super::PublisherMetrics,
    pending: &mut VecDeque<PendingPublication<H::Digest>>,
    persisted: &mut BTreeMap<u64, PersistedUpload>,
) where
    H: Hasher,
    H::Digest: Codec,
{
    let ready = pending
        .iter()
        .take_while(|publication| persisted.contains_key(&publication.height))
        .count();
    if ready == 0 {
        return;
    }
    let last = pending
        .get(ready - 1)
        .expect("ready publication prefix is nonempty");
    let last_data = persisted
        .get(&last.height)
        .expect("ready publication data must remain present");
    let mut batch = StoreWriteBatch::new();
    stage_authenticated_watermark(&clients.state, &last_data.state, &mut batch)
        .expect("validated state range has a watermark");
    stage_authenticated_watermark(&clients.transactions, &last_data.transactions, &mut batch)
        .expect("validated transaction range has a watermark");
    for publication in pending.iter().take(ready) {
        let key = Key::from(Bytes::copy_from_slice(&publication.height.to_be_bytes()));
        batch
            .push(&clients.targets, &key, publication.block_digest.as_ref())
            .expect("publication target row must stage");
    }
    let barrier_sequence = super::commit_with_retry(
        &clients.store,
        &batch,
        "contiguous publication barrier",
        &metrics.commit,
    )
    .await
    .expect("contiguous publication barrier was rejected");
    for _ in 0..ready {
        let publication = pending
            .pop_front()
            .expect("ready publication prefix must remain present");
        persisted
            .remove(&publication.height)
            .expect("ready publication data must remain present");
        debug!(
            height = publication.height,
            barrier_sequence, "published finalized index prefix"
        );
        let _ = publication.completion.send(PublicationReceipt {
            height: publication.height,
            block_digest: publication.block_digest,
            store_sequence_number: barrier_sequence,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    use commonware_runtime::{Runner as _, Supervisor as _};
    use commonware_storage::merkle::{Family as _, mem::Mem};
    use commonware_utils::{NZU16, non_empty_range};
    use constantinople_engine::{ThresholdScheme, types::EngineCommitment};
    use constantinople_primitives::{Block, Header, Sealable, SignedTransaction};
    use exoware_qmdb::{KeylessClient, UnorderedClient};
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
                sql_schema: build_meta_schema(
                    sql_meta_client(&physical).expect("SQL metadata namespace"),
                )
                .expect("build SQL schema"),
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
                    completion: first_tx,
                },
                PendingPublication {
                    height: 2,
                    block_digest: second_digest,
                    completion: second_tx,
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

            publish_ready_prefix::<Sha256>(&clients, &metrics, &mut pending, &mut persisted).await;

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
            publish_ready_prefix::<Sha256>(&clients, &metrics, &mut pending, &mut persisted).await;

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

            let first = publisher
                .enqueue_queued_finalized(first)
                .await
                .expect("enqueue first upload");
            let second = publisher
                .enqueue_queued_finalized(second)
                .await
                .expect("enqueue second upload");
            let first_receipt = first.wait().await.expect("publish first upload");
            let second_receipt = second.wait().await.expect("publish second upload");

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
        let state = prepare_unordered_authenticated_range_with_strategy::<
            QmdbFamily,
            Sha256,
            AccountKey,
            AccountValue,
            StateEncoding,
            Sequential,
        >(
            &as_authenticated_range(&state),
            &state_root,
            &(),
            &Sequential,
        )
        .expect("prepare state range");
        let transactions = prepare_keyless_authenticated_range_with_strategy::<
            QmdbFamily,
            Sha256,
            Sha256Digest,
            TransactionEncoding<Sha256>,
            Sequential,
        >(
            &as_authenticated_range(&transactions),
            &transactions_root,
            &(),
            &Sequential,
        )
        .expect("prepare transaction range");
        let mut batch = StoreWriteBatch::new();
        let state = stage_authenticated_range(&clients.state, state, &mut batch)
            .expect("stage state range");
        let transactions =
            stage_authenticated_range(&clients.transactions, transactions, &mut batch)
                .expect("stage transaction range");
        batch
            .commit(&clients.store)
            .await
            .expect("commit test data");
        PersistedUpload {
            height,
            state,
            transactions,
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
            encoded_operations: all_operations[usize::try_from(start.as_u64())
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
        let state_root = queued_range_root(&state);
        let transactions_root = queued_range_root(&transactions);
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
        let block = EngineBlock::from(
            Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
                .seal(&mut Sha256::default()),
        );
        let finalization = test_finalization(&block);
        let upload = QueuedFinalizedUpload {
            block,
            finalization,
            finalized_ts_micros: i64::try_from(height).expect("height fits timestamp"),
            metadata_encoder_version: METADATA_ENCODER_VERSION,
            state,
            transactions,
        };
        upload.validate().expect("test upload validates");
        upload
    }

    fn queued_range_root(range: &QueuedAuthenticatedRange<Sha256Digest>) -> Sha256Digest {
        range
            .proof
            .reconstruct_root(
                &commonware_storage::qmdb::hasher::<Sha256>(),
                &range.encoded_operations,
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
