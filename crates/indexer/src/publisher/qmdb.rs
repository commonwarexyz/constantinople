//! Combined publisher for finalized SQL metadata and QMDB rows.

use super::{
    block::{BulkBlockRows, encode_block_meta_only_at, encode_bulk_block_rows},
    sql::{AccountMetaRow, encode_account_meta_row},
};
use crate::{
    namespaces::{
        provable_target_client, sql_meta_client, state_qmdb_client, transactions_qmdb_client,
    },
    sql_schema::build_meta_schema,
    store::writer_store_clients,
};
use bytes::{Buf as _, Bytes};
use commonware_codec::{
    Codec, Decode, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt,
    Write,
};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::metrics::Histogram,
};
use commonware_storage::{
    merkle::{Location, mmr},
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
use constantinople_application::consensus::DatabaseReaders;
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{Account, AccountKey, BlockCfg};
use exoware_qmdb::{
    KeylessClient, KeylessWriter, PreparedUpload, PreparedWatermark, QmdbError, UnorderedClient,
    UnorderedWriter, WriterState,
};
use exoware_sdk::{ClientError, PrefixedStoreClient, StoreClient, StoreWriteBatch};
use exoware_sql::{BatchWriter, PreparedBatch};
use std::{
    collections::VecDeque,
    marker::PhantomData,
    num::NonZeroU64,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tracing::debug;

/// Durable queued uploads are self-contained and comparatively cheap to admit.
const MAX_BUFFERED_QMDB_UPLOADS: usize = 64;

type QmdbFamily = mmr::Family;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateEncoding = FixedEncoding<AccountValue>;
type LocalStateOperation = UnorderedOperation<QmdbFamily, AccountKey, FixedEncoding<Account>>;
type StateOperation = UnorderedOperation<QmdbFamily, AccountKey, StateEncoding>;
type TransactionEncoding<H> = FixedEncoding<<H as Hasher>::Digest>;
type TransactionOperation<H> = keyless::Operation<QmdbFamily, TransactionEncoding<H>>;
type StateWriter<H, S = Sequential> =
    UnorderedWriter<QmdbFamily, H, AccountKey, AccountValue, StateEncoding, S>;
type TransactionWriter<H, S = Sequential> =
    KeylessWriter<QmdbFamily, H, <H as Hasher>::Digest, TransactionEncoding<H>, S>;

/// Next QMDB locations used to reconstruct both writer frontiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterNextLocations {
    state: u64,
    transactions: u64,
}

impl WriterNextLocations {
    /// Construct paired state and transaction writer locations.
    pub const fn new(state: u64, transactions: u64) -> Self {
        Self {
            state,
            transactions,
        }
    }
}

/// Completion signal for a queued finalized-block upload.
pub struct UploadCompletion {
    height: u64,
    rx: oneshot::Receiver<()>,
}

impl UploadCompletion {
    fn completed(height: u64) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(());
        Self { height, rx }
    }

    /// Waits until the upload has been marked persisted.
    pub async fn wait(self) -> Result<(), PublishError> {
        self.rx.await.map_err(|_| PublishError::CommitterStopped {
            height: self.height,
        })
    }
}

/// Codec configuration for a durable finalized upload queue entry.
#[derive(Clone, Debug)]
pub struct QueuedFinalizedUploadCfg {
    pub block: BlockCfg,
    pub state_ops: RangeCfg<usize>,
}

impl Default for QueuedFinalizedUploadCfg {
    fn default() -> Self {
        Self {
            block: BlockCfg::default(),
            state_ops: RangeCfg::from(0..),
        }
    }
}

/// Finalized-block data that must be captured before application pruning.
///
/// The durable queue intentionally stores the narrow pre-prune boundary, not a
/// fully staged Store upload. The state delta must be read while the local QMDB
/// can still prove the finalized range. The block, timestamp, and writer start
/// cursors are enough to deterministically derive SQL metadata, transaction
/// QMDB operations, account metadata SQL rows, and writer end cursors
/// later in the uploader.
///
/// Keeping those derived rows out of the queue reduces queue write size and
/// keeps finalized-block processing independent from remote Store latency.
pub struct QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    block: Arc<EngineBlock<H, P>>,
    finalized_ts_micros: i64,
    state_start: u64,
    transaction_start: u64,
    state_delta: Arc<Vec<StateOperation>>,
}

impl<H, P> Clone for QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            block: Arc::clone(&self.block),
            finalized_ts_micros: self.finalized_ts_micros,
            state_start: self.state_start,
            transaction_start: self.transaction_start,
            state_delta: Arc::clone(&self.state_delta),
        }
    }
}

impl<H, P> QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    pub fn height(&self) -> u64 {
        self.block.header.height
    }

    pub const fn state_start(&self) -> u64 {
        self.state_start
    }

    pub fn state_end(&self) -> u64 {
        self.block.header.state_range.end()
    }

    pub const fn transaction_start(&self) -> u64 {
        self.transaction_start
    }

    pub fn transaction_end(&self) -> u64 {
        transaction_upload_end(self.transaction_start, &self.block)
            .expect("queued finalized upload stores a validated transaction cursor")
    }

    pub fn block(&self) -> Arc<EngineBlock<H, P>> {
        Arc::clone(&self.block)
    }
}

impl<H, P> EncodeSize for QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    EngineBlock<H, P>: EncodeSize,
    StateOperation: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.block.encode_size()
            + self.finalized_ts_micros.encode_size()
            + self.state_start.encode_size()
            + self.transaction_start.encode_size()
            + self.state_delta.encode_size()
    }
}

impl<H, P> Write for QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    EngineBlock<H, P>: Write,
    StateOperation: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.block.write(buf);
        self.finalized_ts_micros.write(buf);
        self.state_start.write(buf);
        self.transaction_start.write(buf);
        self.state_delta.write(buf);
    }
}

impl<H, P> Read for QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    EngineBlock<H, P>: Read<Cfg = BlockCfg>,
    StateOperation: Read<Cfg = ()>,
{
    type Cfg = QueuedFinalizedUploadCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            block: Arc::new(EngineBlock::<H, P>::read_cfg(buf, &cfg.block)?),
            finalized_ts_micros: i64::read(buf)?,
            state_start: u64::read(buf)?,
            transaction_start: u64::read(buf)?,
            state_delta: Arc::new(Vec::<StateOperation>::read_cfg(buf, &(cfg.state_ops, ()))?),
        })
    }
}

/// Queue representation that defers finalized upload decoding until admission.
pub struct StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    inner: StoredFinalizedUploadInner<H, P>,
}

enum StoredFinalizedUploadInner<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    Decoded(QueuedFinalizedUpload<H, P>),
    Encoded {
        bytes: Bytes,
        cfg: QueuedFinalizedUploadCfg,
    },
}

impl<H, P> From<QueuedFinalizedUpload<H, P>> for StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn from(upload: QueuedFinalizedUpload<H, P>) -> Self {
        Self {
            inner: StoredFinalizedUploadInner::Decoded(upload),
        }
    }
}

impl<H, P> StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    QueuedFinalizedUpload<H, P>: EncodeSize,
{
    /// Reports the admission cost without materializing the structured upload.
    pub fn encoded_len(&self) -> usize {
        match &self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => upload.encode_size(),
            StoredFinalizedUploadInner::Encoded { bytes, .. } => bytes.len(),
        }
    }
}

impl<H, P> StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    QueuedFinalizedUpload<H, P>: Read<Cfg = QueuedFinalizedUploadCfg>,
{
    /// Materializes an admitted upload while preserving full-buffer validation.
    pub fn into_decoded(self) -> Result<QueuedFinalizedUpload<H, P>, CodecError> {
        match self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => Ok(upload),
            StoredFinalizedUploadInner::Encoded { bytes, cfg } => {
                QueuedFinalizedUpload::decode_cfg(bytes, &cfg)
            }
        }
    }
}

impl<H, P> EncodeSize for StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    QueuedFinalizedUpload<H, P>: EncodeSize,
{
    fn encode_size(&self) -> usize {
        self.encoded_len()
    }
}

impl<H, P> Write for StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    QueuedFinalizedUpload<H, P>: Write,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match &self.inner {
            StoredFinalizedUploadInner::Decoded(upload) => upload.write(buf),
            StoredFinalizedUploadInner::Encoded { bytes, .. } => buf.put_slice(bytes),
        }
    }
}

impl<H, P> Read for StoredFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
    QueuedFinalizedUpload<H, P>: Read<Cfg = QueuedFinalizedUploadCfg>,
{
    type Cfg = QueuedFinalizedUploadCfg;

    fn read_cfg(buf: &mut impl bytes::Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let bytes = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            inner: StoredFinalizedUploadInner::Encoded {
                bytes,
                cfg: cfg.clone(),
            },
        })
    }
}

/// QMDB upload failure.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("failed to configure Store client due to {0}")]
    ClientBuild(#[from] crate::StoreClientBuildError),
    #[error("failed to configure QMDB Store prefix: {0}")]
    Prefix(#[from] exoware_sdk::StoreKeyPrefixError),
    #[error("QMDB writer error: {0}")]
    Qmdb(#[from] QmdbError),
    #[error("Store client error: {0}")]
    Store(#[from] ClientError),
    #[error("failed to configure SQL metadata schema: {0}")]
    SqlSchema(String),
    #[error("failed to stage SQL metadata rows: {0}")]
    Sql(#[from] datafusion::error::DataFusionError),
    #[error("failed to encode SQL metadata row: {0}")]
    SqlRow(String),
    #[error("QMDB Store is empty but finalized block height {height} needs historical backfill")]
    StoreEmptyPastGenesis { height: u64 },
    #[error(
        "QMDB writer is at operation {writer_next}, but finalized block starts at {block_start}"
    )]
    WriterOutOfSync { writer_next: u64, block_start: u64 },
    #[error("QMDB commit worker stopped before accepting height {height}")]
    CommitterStopped { height: u64 },
}

/// Owns the combined finalized-block index upload path.
#[derive(Debug)]
pub struct Publisher<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    state_next_location: Mutex<u64>,
    transaction_next_location: Mutex<u64>,
    prepare_tx: Option<mpsc::Sender<PendingQueuedFinalizedUpload<H, P>>>,
    metadata_tx: Option<mpsc::Sender<PendingBlockMetadata<H, P>>>,
    prepare_join: Option<JoinHandle<()>>,
    commit_join: Option<JoinHandle<()>>,
    metadata_join: Option<JoinHandle<()>>,
    _marker: PhantomData<P>,
}

/// Metadata fast-lane job.
///
/// The worker commits one block_meta row per finalized block and signals when
/// its gated bulk commit may proceed.
struct PendingBlockMetadata<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    height: u64,
    block: Arc<EngineBlock<H, P>>,
    finalized_ts_micros: i64,
    persisted: oneshot::Sender<()>,
}

struct PendingPreparedQmdbUpload<H>
where
    H: Hasher,
{
    height: u64,
    target: ProvableTarget,
    block_rows: BulkBlockRows<H::Digest>,
    state_delta: Vec<StateOperation>,
    account_rows: Vec<super::SqlRow>,
    transaction_ops: Vec<TransactionOperation<H>>,
    completion: oneshot::Sender<()>,
    metadata_persisted: oneshot::Receiver<()>,
}

struct PendingQueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    height: u64,
    upload: QueuedFinalizedUpload<H, P>,
    completion: oneshot::Sender<()>,
    metadata_persisted: oneshot::Receiver<()>,
}

struct PreparedQmdbUpload {
    height: u64,
    target: ProvableTarget,
    sql_rows: Vec<super::SqlRow>,
    state: PreparedUpload<QmdbFamily>,
    transactions: PreparedUpload<QmdbFamily>,
    completion: oneshot::Sender<()>,
    metadata_persisted: oneshot::Receiver<()>,
}

struct StagedQmdbUpload {
    height: u64,
    target: ProvableTarget,
    state: PreparedUpload<QmdbFamily>,
    transactions: PreparedUpload<QmdbFamily>,
    completion: oneshot::Sender<()>,
}

struct QmdbCommitBatch {
    upload: StagedQmdbUpload,
    sql: Option<PreparedBatch>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_batch: StoreWriteBatch,
    rows: usize,
    metadata_persisted: oneshot::Receiver<()>,
}

struct CommitBatchStage<H, S>
where
    H: Hasher,
    S: Strategy,
{
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    sql_upload: SqlUpload,
    state_upload: PreparedUpload<QmdbFamily>,
    transaction_upload: PreparedUpload<QmdbFamily>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    provable_target_client: PrefixedStoreClient,
    provable_target: Option<ProvableTarget>,
}

struct CommitPipeline<'a, H, S>
where
    H: Hasher,
    S: Strategy,
{
    commits: &'a mut JoinSet<CommittedQmdbBatch>,
    commit_client: &'a StoreClient,
    commit_metrics: &'a super::StoreCommitMetrics,
    metadata_gate_wait: &'a Histogram,
    staging: &'a Histogram,
    state_writer: &'a Arc<StateWriter<H, S>>,
    transaction_writer: &'a Arc<TransactionWriter<H, S>>,
    provable_target_client: &'a PrefixedStoreClient,
}

struct WatermarkPipeline<'a, H, S>
where
    H: Hasher,
    S: Strategy,
{
    commit_client: &'a StoreClient,
    commit_metrics: &'a super::StoreCommitMetrics,
    state_writer: &'a StateWriter<H, S>,
    transaction_writer: &'a TransactionWriter<H, S>,
    provable_target_client: &'a PrefixedStoreClient,
    watermark_wait: &'a Histogram,
}

struct StagedCommitBatch {
    sql_writer: BatchWriter,
    sql: Option<PreparedBatch>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_batch: StoreWriteBatch,
    state_upload: PreparedUpload<QmdbFamily>,
    transaction_upload: PreparedUpload<QmdbFamily>,
}

struct CommittedQmdbBatch {
    upload: StagedQmdbUpload,
    sql: Option<PreparedBatch>,
    rows: usize,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_seq: u64,
    committed_at: Instant,
}

struct PendingUploadCompletion {
    target: ProvableTarget,
    state_latest: Location<QmdbFamily>,
    transaction_latest: Location<QmdbFamily>,
    completion: oneshot::Sender<()>,
    committed_at: Instant,
}

impl PendingUploadCompletion {
    fn target_boundary(&self) -> ProvableTargetBoundary {
        ProvableTargetBoundary {
            target: self.target.clone(),
            state_latest: self.state_latest,
            transaction_latest: self.transaction_latest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProvableTarget {
    height: u64,
    block_digest: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProvableTargetBoundary {
    target: ProvableTarget,
    state_latest: Location<QmdbFamily>,
    transaction_latest: Location<QmdbFamily>,
}

impl<H, P> Publisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    /// Construct writers over the two QMDB Store namespaces.
    #[commonware_macros::boxed]
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

    /// Construct writers at explicit next locations.
    #[commonware_macros::boxed]
    pub async fn connect_at<Cx>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        next_locations: WriterNextLocations,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
    {
        Self::connect_with_strategy_at(
            context,
            store_url,
            api_key,
            buffer,
            metrics,
            next_locations,
            Sequential,
        )
        .await
    }

    /// Construct writers that use `strategy` for Merkle construction and recovery.
    #[commonware_macros::boxed]
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
        Self::connect_with_strategy_inner(
            context, store_url, api_key, buffer, metrics, None, strategy,
        )
        .await
    }

    /// Construct writers at explicit next locations using `strategy`.
    #[commonware_macros::boxed]
    pub async fn connect_with_strategy_at<Cx, S>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        next_locations: WriterNextLocations,
        strategy: S,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
        S: Strategy,
    {
        Self::connect_with_strategy_inner(
            context,
            store_url,
            api_key,
            buffer,
            metrics,
            Some(next_locations),
            strategy,
        )
        .await
    }

    async fn connect_with_strategy_inner<Cx, S>(
        context: Cx,
        store_url: &str,
        api_key: Option<&str>,
        buffer: usize,
        metrics: super::PublisherMetrics,
        next_locations: Option<WriterNextLocations>,
        strategy: S,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
        S: Strategy,
    {
        let (commit_client, metadata_commit_client) = writer_store_clients(store_url, api_key)?;
        let state_client = state_qmdb_client(&commit_client)?;
        let transaction_client = transactions_qmdb_client(&commit_client)?;
        let provable_target_client = provable_target_client(&commit_client)?;
        // Two independent writers over one schema. The bulk committer and the
        // metadata fast lane each own their whole flush lifecycle, so neither
        // holds shared mutable writer state across network I/O.
        let sql_schema =
            build_meta_schema(sql_meta_client(&commit_client)?).map_err(PublishError::SqlSchema)?;
        let sql_writer = sql_schema.batch_writer();
        let metadata_writer = build_meta_schema(sql_meta_client(&metadata_commit_client)?)
            .map_err(PublishError::SqlSchema)?
            .batch_writer();
        let (state, transactions) = match next_locations {
            Some(next_locations) => {
                let state = recover_state_writer_state_at::<H, S>(
                    state_client.clone(),
                    next_locations.state,
                    &strategy,
                )
                .await?;
                let transactions = recover_transaction_writer_state_at::<H, S>(
                    transaction_client.clone(),
                    next_locations.transactions,
                    &strategy,
                )
                .await?;
                (state, transactions)
            }
            None => {
                let state =
                    recover_state_writer_state::<H, S>(state_client.clone(), &strategy).await?;
                let transactions =
                    recover_transaction_writer_state::<H, S>(transaction_client.clone(), &strategy)
                        .await?;
                (state, transactions)
            }
        };
        let state_writer = Arc::new(StateWriter::new_with_strategy(
            state_client,
            state,
            strategy.clone(),
        ));
        let transaction_writer = Arc::new(TransactionWriter::new_with_strategy(
            transaction_client,
            transactions,
            strategy,
        ));
        let state_next_location =
            next_writer_location(state_writer.latest_published_watermark().await);
        let transaction_next_location =
            next_writer_location(transaction_writer.latest_published_watermark().await);
        let buffer = buffer.clamp(1, MAX_BUFFERED_QMDB_UPLOADS);
        let (commit_tx, commit_rx) = mpsc::channel(buffer);
        let (prepare_tx, prepare_rx) = mpsc::channel(buffer);
        // Bounded so a stalled metadata lane backpressures upload admission
        // instead of accumulating unpersisted block rows.
        let (metadata_tx, metadata_rx) = mpsc::channel(buffer);
        let max_in_flight_commits = buffer;
        let commit_context = context.child("commit");
        let prepare_context = context.child("prepare");
        let metadata_context = context.child("metadata");
        let commit_join = tokio::spawn(run_qmdb_committer(
            commit_context,
            commit_client.clone(),
            metrics.clone(),
            sql_writer,
            state_writer.clone(),
            transaction_writer.clone(),
            provable_target_client,
            commit_rx,
            max_in_flight_commits,
        ));
        let prepare_join = tokio::spawn(run_qmdb_preparer(
            prepare_context,
            metrics.expansion.clone(),
            state_writer.clone(),
            transaction_writer.clone(),
            prepare_rx,
            commit_tx,
        ));
        let metadata_join = tokio::spawn(run_metadata_committer(
            metadata_context,
            metadata_commit_client,
            metrics,
            metadata_writer,
            metadata_rx,
        ));

        Ok(Self {
            state_next_location: Mutex::new(state_next_location),
            transaction_next_location: Mutex::new(transaction_next_location),
            prepare_tx: Some(prepare_tx),
            metadata_tx: Some(metadata_tx),
            prepare_join: Some(prepare_join),
            commit_join: Some(commit_join),
            metadata_join: Some(metadata_join),
            _marker: PhantomData,
        })
    }

    /// Stop the background workers after all queued uploads finish.
    pub async fn shutdown(mut self) {
        drop(self.prepare_tx.take());
        if let Some(prepare_join) = self.prepare_join.take() {
            await_qmdb_worker(prepare_join, "preparer").await;
        }
        if let Some(commit_join) = self.commit_join.take() {
            await_qmdb_worker(commit_join, "committer").await;
        }
        // The metadata worker drains only after the committer joins because
        // in-flight bulk commits hold gates the worker must still answer.
        drop(self.metadata_tx.take());
        if let Some(metadata_join) = self.metadata_join.take() {
            await_qmdb_worker(metadata_join, "metadata").await;
        }
    }

    /// Return the next state and transaction writer locations recovered by this publisher.
    pub async fn next_locations(&self) -> (u64, u64) {
        (
            *self.state_next_location.lock().await,
            *self.transaction_next_location.lock().await,
        )
    }

    /// Capture the finalized-block upload material that must survive local pruning.
    ///
    /// Returns `None` when both writer cursors sit at or past the block's
    /// operation ranges. Crash recovery redelivers finalized blocks whose
    /// uploads already committed, and each block's operations live at
    /// consensus-assigned locations, so a fully covered block has nothing left
    /// to capture. Appending its operations again would place duplicates at
    /// locations owned by later blocks.
    ///
    /// This deliberately stops at the durable local payload boundary. Remote
    /// Store staging and upload are handled later by the queue consumer:
    ///
    /// - captured here: block, finalized timestamp, QMDB writer start cursors,
    ///   and the state operation delta that can be lost after local pruning;
    /// - derived later: SQL metadata rows, transaction QMDB ops, account SQL
    ///   rows, watermarks, and the final Store batch.
    pub async fn build_queued_finalized_upload<E, S>(
        state_writer_next: u64,
        transaction_writer_next: u64,
        block: &EngineBlock<H, P>,
        databases: &DatabaseReaders<E, H, commonware_storage::translator::EightCap, S>,
    ) -> Result<Option<QueuedFinalizedUpload<H, P>>, PublishError>
    where
        E: BufferPooler + Storage + Clock + Metrics + Send + Sync + 'static,
        S: Strategy + Send + Sync + 'static,
    {
        let state_end = block.header.state_range.end();
        let transaction_end = block.header.transactions_range.end();
        if state_writer_next >= state_end && transaction_writer_next >= transaction_end {
            return Ok(None);
        }

        validate_writer_range(state_writer_next, state_end, block.header.height)?;
        transaction_upload_end(transaction_writer_next, block)?;
        let block = Arc::new(block.clone());
        let state_delta =
            build_state_delta::<E, H, P, S>(state_writer_next, &block, databases).await?;

        Ok(Some(QueuedFinalizedUpload {
            block,
            finalized_ts_micros: current_time_micros(),
            state_start: state_writer_next,
            transaction_start: transaction_writer_next,
            state_delta: Arc::new(state_delta),
        }))
    }

    /// Queue a previously durable finalized-block payload for remote upload.
    pub async fn enqueue_queued_finalized(
        &self,
        upload: QueuedFinalizedUpload<H, P>,
    ) -> Result<UploadCompletion, PublishError> {
        let mut state_next = self.state_next_location.lock().await;
        let mut transaction_next = self.transaction_next_location.lock().await;

        let height = upload.height();
        let state_end = upload.state_end();
        let transaction_end = upload.transaction_end();
        if *state_next >= state_end && *transaction_next >= transaction_end {
            return Ok(UploadCompletion::completed(height));
        }
        if *state_next != upload.state_start {
            return Err(PublishError::WriterOutOfSync {
                writer_next: *state_next,
                block_start: upload.state_start,
            });
        }
        if *transaction_next != upload.transaction_start {
            return Err(PublishError::WriterOutOfSync {
                writer_next: *transaction_next,
                block_start: upload.transaction_start,
            });
        }

        let (completion, rx) = oneshot::channel();
        // The metadata fast lane commits the block_meta row ahead of the bulk
        // upload. Jobs land in durable queue order because the queue consumer
        // calls this method serially, which keeps the live block feed ordered
        // by height.
        let (metadata_persisted_tx, metadata_persisted) = oneshot::channel();
        let metadata_tx = self
            .metadata_tx
            .as_ref()
            .expect("publisher send channel is open until shutdown");
        metadata_tx
            .send(PendingBlockMetadata {
                height,
                block: upload.block(),
                finalized_ts_micros: upload.finalized_ts_micros,
                persisted: metadata_persisted_tx,
            })
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        let prepare_tx = self
            .prepare_tx
            .as_ref()
            .expect("publisher send channel is open until shutdown");
        prepare_tx
            .send(PendingQueuedFinalizedUpload {
                height,
                upload,
                completion,
                metadata_persisted,
            })
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        *state_next = state_end;
        *transaction_next = transaction_end;
        Ok(UploadCompletion { height, rx })
    }
}

impl<H, P> Drop for Publisher<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    fn drop(&mut self) {
        if let Some(prepare_join) = self.prepare_join.take() {
            prepare_join.abort();
        }
        if let Some(commit_join) = self.commit_join.take() {
            commit_join.abort();
        }
        if let Some(metadata_join) = self.metadata_join.take() {
            metadata_join.abort();
        }
    }
}

async fn await_qmdb_worker(join: JoinHandle<()>, name: &str) {
    if let Err(error) = join.await {
        if error.is_cancelled() {
            return;
        }
        panic!("QMDB {name} worker task failed: {error}");
    }
}

fn transaction_upload_end<H, P>(
    writer_next: u64,
    block: &EngineBlock<H, P>,
) -> Result<u64, PublishError>
where
    H: Hasher,
    P: PublicKey,
{
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let tx_count = u64::try_from(block.body.len()).expect("transaction count fits u64");
    let mut op_count = tx_count
        .checked_add(1)
        .expect("transaction operation count does not overflow");
    if writer_next == 0 {
        op_count = op_count
            .checked_add(1)
            .expect("genesis transaction operation count does not overflow");
    }
    let block_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(op_count)
        .expect("block transaction range must include this batch");
    if writer_next != block_start {
        return Err(PublishError::WriterOutOfSync {
            writer_next,
            block_start,
        });
    }

    Ok(writer_next
        .checked_add(op_count)
        .expect("transaction writer reservation does not overflow"))
}

async fn run_qmdb_preparer<Cx, H, P, S>(
    context: Cx,
    expansion: Histogram,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    mut rx: mpsc::Receiver<PendingQueuedFinalizedUpload<H, P>>,
    commit_tx: mpsc::Sender<PreparedQmdbUpload>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy,
{
    while let Some(upload) = rx.recv().await {
        let height = upload.height;
        let started = Instant::now();
        let prepared = prepare_qmdb_upload(
            context
                .child("prepare_upload")
                .with_attribute("height", height),
            state_writer.clone(),
            transaction_writer.clone(),
            upload,
        )
        .await
        .unwrap_or_else(|error| panic!("QMDB prepare worker failed at height {height}: {error}"));
        expansion.observe(started.elapsed().as_secs_f64());
        commit_tx
            .send(prepared)
            .await
            .map_err(|upload| PublishError::CommitterStopped {
                height: upload.0.height,
            })
            .expect("QMDB committer stopped");
    }
    debug!("indexer QMDB preparer task exiting: channel closed");
}

/// Serial metadata fast lane.
///
/// Commits one block_meta row per finalized block, ahead of the bulk upload.
/// The bulk commit for the same block gates on the `persisted` signal so a
/// published QMDB watermark always implies durable block metadata, which is
/// what keeps crash recovery's covered-block skip from leaving block_meta
/// holes. A worker panic drops pending gate senders, which fails the gated
/// commits and stops publication instead of advancing past missing metadata.
async fn run_metadata_committer<Cx, H, P>(
    context: Cx,
    commit_client: StoreClient,
    metrics: super::PublisherMetrics,
    mut sql_writer: BatchWriter,
    mut rx: mpsc::Receiver<PendingBlockMetadata<H, P>>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    P: PublicKey + Send + Sync + 'static,
{
    while let Some(job) = rx.recv().await {
        let height = job.height;
        let row = encode_block_meta_only_at(&job.block, job.finalized_ts_micros);
        sql_writer
            .insert(row.table, row.values)
            .unwrap_or_else(|error| panic!("metadata worker failed at height {height}: {error}"));
        let prepared = sql_writer
            .prepare_flush()
            .unwrap_or_else(|error| panic!("metadata worker failed at height {height}: {error}"))
            .expect("metadata flush stages the block_meta row");
        let mut store_batch = StoreWriteBatch::new();
        sql_writer
            .stage_flush(&prepared, &mut store_batch)
            .unwrap_or_else(|error| panic!("metadata worker failed at height {height}: {error}"));
        let store_seq = commit_required_batch_blocking(
            context
                .child("metadata_commit")
                .with_attribute("height", height),
            commit_client.clone(),
            metrics.metadata_commit.clone(),
            store_batch,
        )
        .await;
        let receipt = sql_writer.mark_flush_persisted(prepared, store_seq);
        metrics.metadata_finalized_lag.observe(
            current_time_micros()
                .saturating_sub(job.finalized_ts_micros)
                .max(0) as f64
                / 1e6,
        );
        // A redelivered block can lose its gate receiver when the bulk upload
        // already completed, so an unreceived signal is not an error.
        let _ = job.persisted.send(());
        debug!(
            height,
            request_id = receipt.writer_request_id,
            store_sequence = store_seq,
            "indexer persisted block metadata"
        );
    }
    debug!("indexer metadata committer task exiting: channel closed");
}

async fn prepare_qmdb_upload<Cx, H, P, S>(
    context: Cx,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    upload: PendingQueuedFinalizedUpload<H, P>,
) -> Result<PreparedQmdbUpload, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
    S: Strategy,
{
    let prepared = expand_queued_finalized_upload(upload)?;
    prepare_prepared_qmdb_upload(context, state_writer, transaction_writer, prepared).await
}

fn expand_queued_finalized_upload<H, P>(
    upload: PendingQueuedFinalizedUpload<H, P>,
) -> Result<PendingPreparedQmdbUpload<H>, PublishError>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
{
    let PendingQueuedFinalizedUpload {
        height,
        upload,
        completion,
        metadata_persisted,
    } = upload;
    let QueuedFinalizedUpload {
        block,
        finalized_ts_micros: _,
        state_start,
        transaction_start,
        state_delta,
    } = upload;
    let target = ProvableTarget {
        height,
        block_digest: Bytes::copy_from_slice(block.seal().as_ref()),
    };
    // This is the upload-time half of the durable queue contract: only data
    // that had to survive prune is persisted in the queue. Everything below is
    // deterministic from the queued block, cursors, and state delta. The
    // block_meta row is absent by design because the metadata fast lane owns
    // it.
    let block_rows = encode_bulk_block_rows(&block);
    let transaction_ops = build_transaction_upload_from_digests(
        &block,
        transaction_start,
        &block_rows.transaction_digests,
    )?
    .ops;
    let account_rows = account_rows(&state_delta, state_start);
    let state_delta = Arc::unwrap_or_clone(state_delta);
    Ok(PendingPreparedQmdbUpload {
        height,
        target,
        block_rows,
        state_delta,
        account_rows,
        transaction_ops,
        completion,
        metadata_persisted,
    })
}

async fn prepare_prepared_qmdb_upload<Cx, H, S>(
    context: Cx,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    upload: PendingPreparedQmdbUpload<H>,
) -> Result<PreparedQmdbUpload, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let PendingPreparedQmdbUpload {
        height,
        target,
        block_rows,
        state_delta,
        account_rows,
        transaction_ops,
        completion,
        metadata_persisted,
    } = upload;
    let BulkBlockRows {
        sql,
        transaction_digests: _,
    } = block_rows;
    let mut sql = sql;
    sql.extend(account_rows);

    let state_prepare = context
        .child("state")
        .shared(true)
        .spawn(move |_| async move { state_writer.prepare_upload(state_delta).await });
    let transaction_prepare = context
        .child("transactions")
        .shared(true)
        .spawn(move |_| async move { transaction_writer.prepare_upload(transaction_ops).await });
    let (state, transactions) = tokio::join!(state_prepare, transaction_prepare);
    let state = state.expect("QMDB state prepare task exited")?;
    let transactions = transactions.expect("QMDB transaction prepare task exited")?;

    Ok(PreparedQmdbUpload {
        height,
        target,
        sql_rows: sql,
        state,
        transactions,
        completion,
        metadata_persisted,
    })
}

#[expect(clippy::too_many_arguments, reason = "single spawn site in connect")]
async fn run_qmdb_committer<Cx, H, S>(
    context: Cx,
    commit_client: StoreClient,
    metrics: super::PublisherMetrics,
    mut sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    provable_target_client: PrefixedStoreClient,
    mut rx: mpsc::Receiver<PreparedQmdbUpload>,
    max_in_flight_commits: usize,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let mut rx_closed = false;
    let mut commits = JoinSet::new();
    let mut pending_completions = VecDeque::new();
    loop {
        while commits.len() < max_in_flight_commits {
            let upload = match rx.try_recv() {
                Ok(upload) => upload,
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    rx_closed = true;
                    break;
                }
            };
            let inline_watermarks = commits.is_empty();
            sql_writer = stage_and_spawn_commit(
                context
                    .child("upload")
                    .with_attribute("height", upload.height),
                CommitPipeline {
                    commits: &mut commits,
                    commit_client: &commit_client,
                    commit_metrics: &metrics.commit,
                    metadata_gate_wait: &metrics.metadata_gate_wait,
                    staging: &metrics.staging,
                    state_writer: &state_writer,
                    transaction_writer: &transaction_writer,
                    provable_target_client: &provable_target_client,
                },
                sql_writer,
                upload,
                &pending_completions,
                inline_watermarks,
            )
            .await;
        }

        if rx_closed && commits.is_empty() {
            flush_and_complete_published_uploads(
                context.child("watermarks"),
                &mut pending_completions,
                WatermarkPipeline {
                    commit_client: &commit_client,
                    commit_metrics: &metrics.commit,
                    state_writer: &state_writer,
                    transaction_writer: &transaction_writer,
                    provable_target_client: &provable_target_client,
                    watermark_wait: &metrics.watermark_wait,
                },
            )
            .await;
            assert!(
                pending_completions.is_empty(),
                "QMDB uploads persisted without a publishable watermark"
            );
            break;
        }

        tokio::select! {
            maybe_upload = rx.recv(), if !rx_closed && commits.len() < max_in_flight_commits => {
                match maybe_upload {
                    Some(upload) => {
                        let inline_watermarks = commits.is_empty();
                        sql_writer = stage_and_spawn_commit(
                            context
                                .child("upload")
                                .with_attribute("height", upload.height),
                            CommitPipeline {
                                commits: &mut commits,
                                commit_client: &commit_client,
                                commit_metrics: &metrics.commit,
                                metadata_gate_wait: &metrics.metadata_gate_wait,
                                staging: &metrics.staging,
                                state_writer: &state_writer,
                                transaction_writer: &transaction_writer,
                                provable_target_client: &provable_target_client,
                            },
                            sql_writer,
                            upload,
                            &pending_completions,
                            inline_watermarks,
                        )
                        .await;
                    }
                    None => rx_closed = true,
                }
            }
            maybe_done = commits.join_next(), if !commits.is_empty() => {
                let batch = maybe_done
                    .expect("QMDB commit set not empty")
                    .expect("QMDB commit task panicked");
                let completion = mark_committed_batch(
                    batch,
                    &mut sql_writer,
                    &state_writer,
                    &transaction_writer,
                )
                .await;
                pending_completions.push_back(completion);
                while let Some(batch) = commits.try_join_next() {
                    let batch = batch.expect("QMDB commit task panicked");
                    let completion = mark_committed_batch(
                        batch,
                        &mut sql_writer,
                        &state_writer,
                        &transaction_writer,
                    )
                    .await;
                    pending_completions.push_back(completion);
                }
                flush_and_complete_published_uploads(
                    context.child("watermarks"),
                    &mut pending_completions,
                    WatermarkPipeline {
                        commit_client: &commit_client,
                        commit_metrics: &metrics.commit,
                        state_writer: &state_writer,
                        transaction_writer: &transaction_writer,
                        provable_target_client: &provable_target_client,
                        watermark_wait: &metrics.watermark_wait,
                    },
                )
                .await;
            }
        }
    }
    debug!("indexer QMDB committer task exiting: channel closed");
}

async fn stage_and_spawn_commit<Cx, H, S>(
    context: Cx,
    pipeline: CommitPipeline<'_, H, S>,
    sql_writer: BatchWriter,
    upload: PreparedQmdbUpload,
    pending: &VecDeque<PendingUploadCompletion>,
    inline_watermarks: bool,
) -> BatchWriter
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let staging_started = Instant::now();
    let prepared = prepare_commit_batch_blocking(
        context.child("stage_commit_batch"),
        sql_writer,
        pipeline.state_writer.clone(),
        pipeline.transaction_writer.clone(),
        pipeline.provable_target_client.clone(),
        upload,
        pending,
        inline_watermarks,
    )
    .await
    .expect("prepared QMDB commit batch must stage");
    pipeline
        .staging
        .observe(staging_started.elapsed().as_secs_f64());
    let sql_writer = prepared.0;
    let batch = prepared.1;
    spawn_commit(
        pipeline.commits,
        context.child("store_commit"),
        pipeline.commit_client.clone(),
        pipeline.commit_metrics.clone(),
        pipeline.metadata_gate_wait.clone(),
        batch,
    );
    sql_writer
}

#[expect(
    clippy::too_many_arguments,
    reason = "publisher resources and target candidates stay explicit"
)]
async fn prepare_commit_batch_blocking<Cx, H, S>(
    context: Cx,
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H, S>>,
    transaction_writer: Arc<TransactionWriter<H, S>>,
    provable_target_client: PrefixedStoreClient,
    upload: PreparedQmdbUpload,
    pending: &VecDeque<PendingUploadCompletion>,
    inline_watermarks: bool,
) -> Result<(BatchWriter, QmdbCommitBatch), PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let mut target_boundaries = pending
        .iter()
        .map(PendingUploadCompletion::target_boundary)
        .collect::<Vec<_>>();
    target_boundaries.push(ProvableTargetBoundary {
        target: upload.target.clone(),
        state_latest: upload.state.latest_location(),
        transaction_latest: upload.transactions.latest_location(),
    });

    let metadata = StagedQmdbUploadMetadata {
        height: upload.height,
        target: upload.target,
        completion: upload.completion,
    };
    let metadata_persisted = upload.metadata_persisted;
    let sql_upload = SqlUpload {
        sql_rows: upload.sql_rows,
    };
    let state_upload = upload.state;
    let transaction_upload = upload.transactions;

    let (state_watermark, transaction_watermark) = if inline_watermarks {
        tokio::try_join!(
            state_writer.prepare_flush_for_uploads(std::slice::from_ref(&state_upload)),
            transaction_writer.prepare_flush_for_uploads(std::slice::from_ref(&transaction_upload))
        )?
    } else {
        (None, None)
    };

    let state_upload_watermark = state_upload.writer_location_watermark();
    let transaction_upload_watermark = transaction_upload.writer_location_watermark();
    let publishes_watermark = state_upload_watermark.is_some()
        || transaction_upload_watermark.is_some()
        || state_watermark.is_some()
        || transaction_watermark.is_some();
    let state_coverage = [
        state_writer.latest_published_watermark().await,
        state_upload_watermark,
        state_watermark.as_ref().map(PreparedWatermark::location),
    ]
    .into_iter()
    .flatten()
    .max();
    let transaction_coverage = [
        transaction_writer.latest_published_watermark().await,
        transaction_upload_watermark,
        transaction_watermark
            .as_ref()
            .map(PreparedWatermark::location),
    ]
    .into_iter()
    .flatten()
    .max();
    let provable_target = publishes_watermark
        .then(|| newest_covered_target(&target_boundaries, state_coverage, transaction_coverage))
        .flatten()
        .cloned();

    let staged = stage_commit_batch_blocking(
        context.child("stage_store_batch"),
        CommitBatchStage {
            sql_writer,
            state_writer,
            transaction_writer,
            sql_upload,
            state_upload,
            transaction_upload,
            state_watermark,
            transaction_watermark,
            provable_target_client,
            provable_target,
        },
    )
    .await?;
    let StagedCommitBatch {
        sql_writer,
        sql,
        state_watermark,
        transaction_watermark,
        store_batch,
        state_upload,
        transaction_upload,
    } = staged;

    let rows = store_batch.len();
    let upload = StagedQmdbUpload {
        height: metadata.height,
        target: metadata.target,
        state: state_upload,
        transactions: transaction_upload,
        completion: metadata.completion,
    };
    let batch = QmdbCommitBatch {
        rows,
        upload,
        sql,
        state_watermark,
        transaction_watermark,
        store_batch,
        metadata_persisted,
    };
    Ok((sql_writer, batch))
}

struct StagedQmdbUploadMetadata {
    height: u64,
    target: ProvableTarget,
    completion: oneshot::Sender<()>,
}

struct SqlUpload {
    sql_rows: Vec<super::SqlRow>,
}

async fn stage_commit_batch_blocking<Cx, H, S>(
    context: Cx,
    stage: CommitBatchStage<H, S>,
) -> Result<StagedCommitBatch, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    context
        .shared(true)
        .spawn(move |_| async move {
            let CommitBatchStage {
                mut sql_writer,
                state_writer,
                transaction_writer,
                mut sql_upload,
                state_upload,
                transaction_upload,
                state_watermark,
                transaction_watermark,
                provable_target_client,
                provable_target,
            } = stage;
            let sql = prepare_sql_upload(&mut sql_writer, &mut sql_upload)?;
            let mut store_batch = StoreWriteBatch::new();
            let mut sql = sql;
            if let Some(prepared) = &mut sql {
                sql_writer.stage_flush(prepared, &mut store_batch)?;
            }
            let mut state_upload = state_upload;
            state_writer.stage_upload(&mut state_upload, &mut store_batch)?;
            let mut transaction_upload = transaction_upload;
            transaction_writer.stage_upload(&mut transaction_upload, &mut store_batch)?;
            if let Some(prepared) = &state_watermark {
                state_writer.stage_flush(prepared, &mut store_batch)?;
            }
            if let Some(prepared) = &transaction_watermark {
                transaction_writer.stage_flush(prepared, &mut store_batch)?;
            }
            if let Some(target) = &provable_target {
                stage_provable_target(&provable_target_client, target, &mut store_batch)?;
            }
            Ok(StagedCommitBatch {
                sql_writer,
                sql,
                state_watermark,
                transaction_watermark,
                store_batch,
                state_upload,
                transaction_upload,
            })
        })
        .await
        .expect("QMDB commit batch staging task exited")
}

fn spawn_commit<Cx>(
    commits: &mut JoinSet<CommittedQmdbBatch>,
    context: Cx,
    commit_client: StoreClient,
    commit_metrics: super::StoreCommitMetrics,
    metadata_gate_wait: Histogram,
    commit: QmdbCommitBatch,
) where
    Cx: Spawner,
{
    commits.spawn(async move {
        let QmdbCommitBatch {
            upload,
            sql,
            state_watermark,
            transaction_watermark,
            store_batch,
            rows,
            metadata_persisted,
        } = commit;
        // This batch may carry an in-band QMDB watermark, and a published
        // watermark covering a block must imply that block's block_meta row
        // is already durable. Crash recovery skips covered blocks entirely,
        // so committing ahead of the metadata row would leave a permanent
        // block_meta hole. Gating here, before the Store commit, upholds the
        // implication for in-band and grouped watermarks alike.
        let gate_start = Instant::now();
        metadata_persisted
            .await
            .expect("metadata worker stopped before persisting block_meta");
        metadata_gate_wait.observe(gate_start.elapsed().as_secs_f64());
        let store_seq = commit_required_batch_blocking(
            context.child("finalized_upload"),
            commit_client,
            commit_metrics,
            store_batch,
        )
        .await;
        debug!(
            store_sequence = store_seq,
            "indexer persisted finalized index batch"
        );
        CommittedQmdbBatch {
            upload,
            sql,
            rows,
            state_watermark,
            transaction_watermark,
            store_seq,
            committed_at: Instant::now(),
        }
    });
}

async fn mark_committed_batch<H, S>(
    batch: CommittedQmdbBatch,
    sql_writer: &mut BatchWriter,
    state_writer: &StateWriter<H, S>,
    transaction_writer: &TransactionWriter<H, S>,
) -> PendingUploadCompletion
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let committed_at = batch.committed_at;
    if let Some(prepared) = batch.sql {
        let receipt = sql_writer.mark_flush_persisted(prepared, batch.store_seq);
        debug!(
            request_id = receipt.writer_request_id,
            rows = receipt.entry_count,
            store_sequence = receipt.store_sequence_number,
            "indexer marked sql metadata upload persisted"
        );
    }
    let upload = batch.upload;
    let height = upload.height;
    let state_latest = upload.state.latest_location();
    let transaction_latest = upload.transactions.latest_location();
    let state_receipt = state_writer
        .mark_upload_persisted(upload.state, batch.store_seq)
        .await;
    let transaction_receipt = transaction_writer
        .mark_upload_persisted(upload.transactions, batch.store_seq)
        .await;
    debug!(
        height,
        state_location = %state_receipt.latest_location,
        transaction_location = %transaction_receipt.latest_location,
        store_sequence = batch.store_seq,
        "indexer marked QMDB upload persisted"
    );
    if let Some(prepared) = batch.state_watermark {
        state_writer
            .mark_flush_persisted(prepared, batch.store_seq)
            .await;
    }
    if let Some(prepared) = batch.transaction_watermark {
        transaction_writer
            .mark_flush_persisted(prepared, batch.store_seq)
            .await;
    }
    debug!(
        height,
        rows = batch.rows,
        store_sequence = batch.store_seq,
        "indexer uploaded finalized index data"
    );
    PendingUploadCompletion {
        target: upload.target,
        state_latest,
        transaction_latest,
        completion: upload.completion,
        committed_at,
    }
}

fn stage_provable_target(
    client: &PrefixedStoreClient,
    target: &ProvableTarget,
    batch: &mut StoreWriteBatch,
) -> Result<(), ClientError> {
    let key = Bytes::copy_from_slice(&target.height.to_be_bytes());
    batch.push(client, &key, &target.block_digest)?;
    Ok(())
}

fn newest_covered_target(
    targets: &[ProvableTargetBoundary],
    state_coverage: Option<Location<QmdbFamily>>,
    transaction_coverage: Option<Location<QmdbFamily>>,
) -> Option<&ProvableTarget> {
    targets
        .iter()
        .filter(|upload| {
            state_coverage.is_some_and(|watermark| watermark >= upload.state_latest)
                && transaction_coverage
                    .is_some_and(|watermark| watermark >= upload.transaction_latest)
        })
        .max_by_key(|upload| upload.target.height)
        .map(|upload| &upload.target)
}

async fn flush_qmdb_watermarks<Cx, H, S>(
    context: Cx,
    pending: &VecDeque<PendingUploadCompletion>,
    commit_client: &StoreClient,
    commit_metrics: &super::StoreCommitMetrics,
    state_writer: &StateWriter<H, S>,
    transaction_writer: &TransactionWriter<H, S>,
    provable_target_client: &PrefixedStoreClient,
) -> Option<u64>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let state = state_writer
        .prepare_flush()
        .await
        .expect("QMDB state watermark flush must prepare");
    let transactions = transaction_writer
        .prepare_flush()
        .await
        .expect("QMDB transaction watermark flush must prepare");
    if state.is_none() && transactions.is_none() {
        return None;
    }

    let mut batch = StoreWriteBatch::new();
    if let Some(prepared) = &state {
        state_writer
            .stage_flush(prepared, &mut batch)
            .expect("QMDB state watermark flush must stage");
    }
    if let Some(prepared) = &transactions {
        transaction_writer
            .stage_flush(prepared, &mut batch)
            .expect("QMDB transaction watermark flush must stage");
    }

    let state_coverage = match &state {
        Some(prepared) => Some(prepared.location()),
        None => state_writer.latest_published_watermark().await,
    };
    let transaction_coverage = match &transactions {
        Some(prepared) => Some(prepared.location()),
        None => transaction_writer.latest_published_watermark().await,
    };
    let targets = pending
        .iter()
        .map(PendingUploadCompletion::target_boundary)
        .collect::<Vec<_>>();
    if let Some(target) = newest_covered_target(&targets, state_coverage, transaction_coverage) {
        stage_provable_target(provable_target_client, target, &mut batch)
            .expect("provable target must stage");
    }

    let seq = commit_required_batch_blocking(
        context.child("watermark_store_commit"),
        commit_client.clone(),
        commit_metrics.clone(),
        batch,
    )
    .await;
    if let Some(prepared) = state {
        state_writer.mark_flush_persisted(prepared, seq).await;
    }
    if let Some(prepared) = transactions {
        transaction_writer.mark_flush_persisted(prepared, seq).await;
    }
    Some(seq)
}

async fn flush_and_complete_published_uploads<Cx, H, S>(
    context: Cx,
    pending: &mut VecDeque<PendingUploadCompletion>,
    pipeline: WatermarkPipeline<'_, H, S>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let already_published = complete_published_uploads(
        pending,
        pipeline.state_writer,
        pipeline.transaction_writer,
        pipeline.watermark_wait,
    )
    .await;
    if pending.is_empty() {
        if already_published > 0 {
            debug!(
                completed_uploads = already_published,
                "indexer completed finalized uploads with in-band QMDB watermarks"
            );
        }
        return;
    }

    let watermark_seq = flush_qmdb_watermarks(
        context,
        pending,
        pipeline.commit_client,
        pipeline.commit_metrics,
        pipeline.state_writer,
        pipeline.transaction_writer,
        pipeline.provable_target_client,
    )
    .await;
    let completed = complete_published_uploads(
        pending,
        pipeline.state_writer,
        pipeline.transaction_writer,
        pipeline.watermark_wait,
    )
    .await;
    if completed > 0 || watermark_seq.is_some() {
        debug!(
            completed_uploads = completed,
            watermark_sequence = watermark_seq,
            pending_uploads = pending.len(),
            "indexer published QMDB watermark"
        );
    }
}

async fn complete_published_uploads<H, S>(
    pending: &mut VecDeque<PendingUploadCompletion>,
    state_writer: &StateWriter<H, S>,
    transaction_writer: &TransactionWriter<H, S>,
    watermark_wait: &Histogram,
) -> usize
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let state = state_writer.latest_published_watermark().await;
    let transactions = transaction_writer.latest_published_watermark().await;
    let mut completed = 0usize;
    let mut retained = VecDeque::with_capacity(pending.len());
    while let Some(upload) = pending.pop_front() {
        let state_ready = state.is_some_and(|watermark| watermark >= upload.state_latest);
        let transactions_ready =
            transactions.is_some_and(|watermark| watermark >= upload.transaction_latest);
        if state_ready && transactions_ready {
            watermark_wait.observe(upload.committed_at.elapsed().as_secs_f64());
            let _ = upload.completion.send(());
            completed += 1;
        } else {
            retained.push_back(upload);
        }
    }
    *pending = retained;
    completed
}

fn prepare_sql_upload(
    writer: &mut BatchWriter,
    upload: &mut SqlUpload,
) -> Result<Option<PreparedBatch>, PublishError> {
    for row in upload.sql_rows.drain(..) {
        writer
            .insert(row.table, row.values)
            .map_err(PublishError::SqlRow)?;
    }
    Ok(writer.prepare_flush()?)
}

#[cfg(test)]
fn prepare_sql_rows<'a>(
    writer: &mut BatchWriter,
    rows: impl Iterator<Item = &'a super::SqlRow>,
) -> Result<Option<PreparedBatch>, PublishError> {
    for row in rows {
        writer
            .insert(row.table, row.values.clone())
            .map_err(PublishError::SqlRow)?;
    }
    Ok(writer.prepare_flush()?)
}

async fn recover_state_writer_state<H, S>(
    client: PrefixedStoreClient,
    strategy: &S,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let reader =
        UnorderedClient::<QmdbFamily, H, AccountKey, AccountValue, StateEncoding>::new(client, ());
    Ok(reader.recover_writer_state_with_strategy(strategy).await?)
}

async fn recover_state_writer_state_at<H, S>(
    client: PrefixedStoreClient,
    next_location: u64,
    strategy: &S,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    if next_location == 0 {
        return Ok(WriterState::empty());
    }

    let reader =
        UnorderedClient::<QmdbFamily, H, AccountKey, AccountValue, StateEncoding>::new(client, ());
    let watermark = Location::new(next_location - 1);
    let checkpoint = reader
        .operation_range_checkpoint(watermark, watermark, 1)
        .await?;
    Ok(WriterState::from_checkpoint_with_strategy::<H, S>(
        &checkpoint,
        strategy,
    )?)
}

async fn recover_transaction_writer_state<H, S>(
    client: PrefixedStoreClient,
    strategy: &S,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    let reader = KeylessClient::<QmdbFamily, H, H::Digest, TransactionEncoding<H>>::new(client, ());
    Ok(reader.recover_writer_state_with_strategy(strategy).await?)
}

async fn recover_transaction_writer_state_at<H, S>(
    client: PrefixedStoreClient,
    next_location: u64,
    strategy: &S,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    S: Strategy,
{
    if next_location == 0 {
        return Ok(WriterState::empty());
    }

    let reader = KeylessClient::<QmdbFamily, H, H::Digest, TransactionEncoding<H>>::new(client, ());
    let watermark = Location::new(next_location - 1);
    let checkpoint = reader
        .operation_range_checkpoint(watermark, watermark, 1)
        .await?;
    Ok(WriterState::from_checkpoint_with_strategy::<H, S>(
        &checkpoint,
        strategy,
    )?)
}

struct PendingTransactionUpload<H>
where
    H: Hasher,
{
    ops: Vec<TransactionOperation<H>>,
}

async fn build_state_delta<E, H, P, S>(
    writer_next: u64,
    block: &EngineBlock<H, P>,
    databases: &DatabaseReaders<E, H, commonware_storage::translator::EightCap, S>,
) -> Result<Vec<StateOperation>, PublishError>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let state = databases.0.read().await;
    let end = block.header.state_range.end();
    load_state_ops::<E, H, S>(&state, writer_next, end).await
}

const fn validate_writer_range(
    writer_next: u64,
    block_end: u64,
    height: u64,
) -> Result<(), PublishError> {
    if writer_next == 0 && height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis { height });
    }
    if writer_next > block_end {
        return Err(PublishError::WriterOutOfSync {
            writer_next,
            block_start: block_end,
        });
    }
    Ok(())
}

fn account_rows(delta: &[StateOperation], start_location: u64) -> Vec<super::SqlRow> {
    let mut rows = Vec::new();
    for (offset, operation) in delta.iter().enumerate() {
        let AnyOperation::Update(UnorderedUpdate(key, account)) = operation else {
            continue;
        };
        let location = start_location + u64::try_from(offset).expect("state op offset fits u64");
        rows.push(encode_account_meta_row(AccountMetaRow {
            account: account_key_array(key),
            balance: account_value_balance(account),
            nonce_base: account_value_nonce_base(account),
            nonce_bitmap: account_value_nonce_bitmap(account),
            qmdb_location: location,
        }));
    }
    rows
}

fn account_key_array(key: &AccountKey) -> [u8; AccountKey::SIZE] {
    key.as_ref()
        .try_into()
        .expect("account key has fixed width")
}

fn account_value_balance(account: &AccountValue) -> u64 {
    let bytes: [u8; 8] = account.as_ref()[..8]
        .try_into()
        .expect("account balance has fixed width");
    u64::from_be_bytes(bytes)
}

fn account_value_nonce_base(account: &AccountValue) -> u64 {
    let bytes: [u8; 8] = account.as_ref()[8..16]
        .try_into()
        .expect("account nonce base has fixed width");
    u64::from_be_bytes(bytes)
}

fn account_value_nonce_bitmap(account: &AccountValue) -> u64 {
    let bytes: [u8; 8] = account.as_ref()[16..24]
        .try_into()
        .expect("account nonce bitmap has fixed width");
    u64::from_be_bytes(bytes)
}

async fn load_state_ops<E, H, S>(
    state: &commonware_storage::qmdb::any::unordered::fixed::Db<
        QmdbFamily,
        E,
        AccountKey,
        Account,
        H,
        commonware_storage::translator::EightCap,
        S,
    >,
    start: u64,
    end: u64,
) -> Result<Vec<StateOperation>, PublishError>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let count = end
        .checked_sub(start)
        .and_then(NonZeroU64::new)
        .ok_or(QmdbError::EmptyBatch)?;
    let (_, operations) = state
        .historical_proof(Location::new(end), Location::new(start), count)
        .await
        .map_err(|err| QmdbError::CorruptData(format!("local state op proof: {err}")))?;
    Ok(operations
        .into_iter()
        .map(encode_account_operation)
        .collect())
}

fn encode_account_operation(operation: LocalStateOperation) -> StateOperation {
    match operation {
        AnyOperation::Delete(key) => AnyOperation::Delete(key),
        AnyOperation::Update(UnorderedUpdate(key, account)) => {
            AnyOperation::Update(UnorderedUpdate(key, encode_account(account)))
        }
        AnyOperation::CommitFloor(account, floor) => {
            AnyOperation::CommitFloor(account.map(encode_account), floor)
        }
    }
}

fn encode_account(account: Account) -> AccountValue {
    let bytes = account.encode();
    let mut out = [0u8; Account::SIZE];
    out.copy_from_slice(&bytes);
    FixedBytes::new(out)
}

fn current_time_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn build_transaction_upload_from_digests<H, P>(
    block: &EngineBlock<H, P>,
    writer_next: u64,
    digests: &[H::Digest],
) -> Result<PendingTransactionUpload<H>, PublishError>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
{
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let ops = transaction_ops_from_digests(block, writer_next, digests)?;
    Ok(PendingTransactionUpload { ops })
}

fn transaction_ops_from_digests<H, P>(
    block: &EngineBlock<H, P>,
    writer_next: u64,
    digests: &[H::Digest],
) -> Result<Vec<TransactionOperation<H>>, PublishError>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
{
    let mut ops = Vec::with_capacity(digests.len() + 2);
    if writer_next == 0 {
        ops.push(TransactionOperation::<H>::Commit(None, Location::new(0)));
    }

    for digest in digests {
        ops.push(TransactionOperation::<H>::Append(*digest));
    }
    ops.push(TransactionOperation::<H>::Commit(
        None,
        Location::new(block.header.transactions_range.start()),
    ));

    let block_start = block
        .header
        .transactions_range
        .end()
        .checked_sub(u64::try_from(ops.len()).expect("operation count fits u64"))
        .expect("block transaction range must include this batch");
    if writer_next != block_start {
        return Err(PublishError::WriterOutOfSync {
            writer_next,
            block_start,
        });
    }

    Ok(ops)
}

const fn next_writer_location(watermark: Option<Location<QmdbFamily>>) -> u64 {
    match watermark {
        Some(location) => location.as_u64() + 1,
        None => 0,
    }
}

async fn commit_required_batch(
    client: StoreClient,
    metrics: super::StoreCommitMetrics,
    batch: StoreWriteBatch,
) -> u64 {
    assert!(
        !batch.is_empty(),
        "QMDB component batches must contain at least one row"
    );
    super::commit_with_retry(&client, &batch, "finalized index upload", &metrics).await
}

async fn commit_required_batch_blocking<Cx>(
    context: Cx,
    client: StoreClient,
    metrics: super::StoreCommitMetrics,
    batch: StoreWriteBatch,
) -> u64
where
    Cx: Spawner,
{
    context
        .shared(true)
        .spawn(move |_| async move { commit_required_batch(client, metrics, batch).await })
        .await
        .expect("QMDB Store commit task exited")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_schema::{BLOCK_META_TABLE, TX_META_TABLE};
    use commonware_consensus::{
        marshal::coding::types::coding_config_for_participants,
        simplex::types::Context as SimplexContext,
        types::{Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Signer as _, ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Strategizer as _, Supervisor,
        buffer::paged::CacheRef,
        telemetry::metrics::{MetricsExt as _, has_metric_value},
    };
    use commonware_storage::{
        journal::contiguous::{
            fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
        },
        merkle::full::Config as MmrConfig,
        qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
        translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
    use constantinople_application::consensus::Databases;
    use constantinople_primitives::{
        Block, Header, Nonce, Sealable, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
        TransactionPublicKey,
    };
    use exoware_sdk::{RangeMode, RetryConfig};
    use exoware_sql::CellValue;
    use std::num::NonZeroU64 as StdNonZeroU64;

    fn metadata_ready() -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        tx.send(()).expect("receiver held");
        rx
    }

    fn test_watermark_wait(context: &impl Metrics) -> Histogram {
        context.histogram(
            "test_watermark_wait_duration",
            "Test watermark wait duration (s)",
            [0.001, 1.0],
        )
    }

    const TEST_ITEMS_PER_BLOB: std::num::NonZero<u64> = NZU64!(1024);
    const TEST_WRITE_BUFFER: std::num::NonZero<usize> = NZUsize!(1024 * 1024);
    const TEST_PAGE_CACHE_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4096);
    const TEST_PAGE_CACHE_CAPACITY: std::num::NonZero<usize> = NZUsize!(1024);

    #[test]
    fn stored_upload_reads_existing_queue_payload() {
        let cfg = QueuedFinalizedUploadCfg::default();
        let upload = test_queued_upload();
        let existing = upload.encode();

        let stored =
            StoredFinalizedUpload::<Sha256, ed25519::PublicKey>::decode_cfg(existing.clone(), &cfg)
                .expect("stored upload accepts existing payload");
        assert_eq!(stored.encoded_len(), existing.len());
        assert_eq!(stored.encode(), existing);

        let decoded = stored.into_decoded().expect("stored upload decodes");
        assert_eq!(decoded.encode(), existing);
    }

    #[test]
    fn stored_upload_writes_existing_queue_payload() {
        let cfg = QueuedFinalizedUploadCfg::default();
        let upload = test_queued_upload();
        let existing = upload.encode();
        let encoded = StoredFinalizedUpload::from(upload).encode();

        assert_eq!(encoded, existing);
        let decoded =
            QueuedFinalizedUpload::<Sha256, ed25519::PublicKey>::decode_cfg(encoded, &cfg)
                .expect("existing codec decodes stored upload");
        assert_eq!(decoded.height(), 1);
    }

    #[test]
    fn stored_upload_defers_malformed_payload_error() {
        let cfg = QueuedFinalizedUploadCfg::default();
        let mut encoded = test_queued_upload().encode().to_vec();
        encoded.push(0);

        let stored = StoredFinalizedUpload::<Sha256, ed25519::PublicKey>::decode_cfg(
            Bytes::from(encoded),
            &cfg,
        )
        .expect("stored upload defers structured decoding");
        assert!(stored.into_decoded().is_err());
    }

    #[test]
    fn sql_rows_stage_into_store_batch() {
        let client = StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
        let mut batch = StoreWriteBatch::new();

        let schema = build_meta_schema(sql_meta_client(&client).expect("sql metadata client"))
            .expect("schema");
        let mut writer = schema.batch_writer();
        let rows = [
            super::super::SqlRow {
                table: BLOCK_META_TABLE,
                values: vec![
                    CellValue::UInt64(1),
                    CellValue::FixedBinary(vec![1u8; 32]),
                    CellValue::UInt64(1),
                    CellValue::FixedBinary(vec![2u8; 32]),
                    CellValue::UInt64(2),
                    CellValue::UInt64(0),
                    CellValue::Timestamp(1_000),
                ],
            },
            super::super::SqlRow {
                table: TX_META_TABLE,
                values: vec![
                    CellValue::FixedBinary(vec![3u8; 32]),
                    CellValue::UInt64(1),
                    CellValue::Binary(vec![0x01, 0x02, 0x03]),
                ],
            },
        ];
        let prepared = prepare_sql_rows(&mut writer, rows.iter())
            .expect("sql rows prepare")
            .expect("sql rows are present");
        writer
            .stage_flush(&prepared, &mut batch)
            .expect("sql rows stage");

        // One Store entry per staged row and no secondary index entries.
        assert_eq!(batch.len(), 2);
        assert_eq!(prepared.entry_count(), 2);
    }

    #[test]
    fn inline_watermark_publishes_single_upload() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let client =
                StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
            let state_writer = Arc::new(StateWriter::<Sha256>::fresh(
                state_qmdb_client(&client).expect("state client"),
            ));
            let transaction_writer = Arc::new(TransactionWriter::<Sha256>::fresh(
                transactions_qmdb_client(&client).expect("transaction client"),
            ));
            let schema = build_meta_schema(sql_meta_client(&client).expect("sql metadata client"))
                .expect("schema");
            let sql_writer = schema.batch_writer();

            let seed = 1u8;
            let key = AccountKey::from([seed; AccountKey::SIZE]);
            let state_ops = vec![
                StateOperation::Update(UnorderedUpdate(
                    key,
                    encode_account(Account {
                        balance: u64::from(seed),
                        nonce: Nonce::default(),
                    }),
                )),
                StateOperation::CommitFloor(None, Location::new(0)),
            ];
            let transaction_ops = vec![
                TransactionOperation::<Sha256>::Append(Sha256::hash(&[&[seed]])),
                TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
            ];
            let (completion, _rx) = oneshot::channel();
            let state = state_writer
                .prepare_upload(state_ops)
                .await
                .expect("state upload");
            let transactions = transaction_writer
                .prepare_upload(transaction_ops)
                .await
                .expect("transaction upload");
            let expected_state_watermark = Some(state.latest_location());
            let expected_transaction_watermark = Some(transactions.latest_location());
            let target = test_provable_target(u64::from(seed));
            let target_client = provable_target_client(&client).expect("provable target client");
            let upload = PreparedQmdbUpload {
                height: u64::from(seed),
                target: target.clone(),
                sql_rows: Vec::new(),
                state,
                transactions,
                completion,
                metadata_persisted: metadata_ready(),
            };
            let pending = VecDeque::new();

            let (_sql_writer, batch) = prepare_commit_batch_blocking(
                context,
                sql_writer,
                state_writer,
                transaction_writer,
                target_client.clone(),
                upload,
                &pending,
                true,
            )
            .await
            .expect("batch stages");

            assert_eq!(batch.upload.height, u64::from(seed));
            assert_eq!(
                batch.upload.state.writer_location_watermark(),
                expected_state_watermark
            );
            assert_eq!(
                batch.upload.transactions.writer_location_watermark(),
                expected_transaction_watermark
            );
            assert!(batch.state_watermark.is_none());
            assert!(batch.transaction_watermark.is_none());
            let target_key = Bytes::copy_from_slice(&target.height.to_be_bytes());
            let physical_target_key = target_client
                .encode_store_key(&target_key)
                .expect("provable target key encodes");
            assert!(batch.store_batch.entries().iter().any(|(key, value)| {
                key == &physical_target_key && value == &target.block_digest
            }));
        });
    }

    #[test]
    fn non_inline_upload_publishes_target_for_embedded_watermarks() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let state_writer = Arc::new(StateWriter::<Sha256>::fresh(
                state_qmdb_client(&client).expect("state client"),
            ));
            let transaction_writer = Arc::new(TransactionWriter::<Sha256>::fresh(
                transactions_qmdb_client(&client).expect("transaction client"),
            ));

            let mut first_state = state_writer
                .prepare_upload(state_ops(1))
                .await
                .expect("first state upload");
            let mut first_transactions = transaction_writer
                .prepare_upload(transaction_ops(1))
                .await
                .expect("first transaction upload");
            let mut second_state = state_writer
                .prepare_upload(state_ops(2))
                .await
                .expect("second state upload");
            let second_state_latest = second_state.latest_location();
            let mut second_transactions = transaction_writer
                .prepare_upload(transaction_ops(2))
                .await
                .expect("second transaction upload");
            let second_transaction_latest = second_transactions.latest_location();
            let third_state = state_writer
                .prepare_upload(state_ops(3))
                .await
                .expect("third state upload");
            let third_transactions = transaction_writer
                .prepare_upload(transaction_ops(3))
                .await
                .expect("third transaction upload");

            let first_seq = commit_staged_upload_pair(
                &client,
                &state_writer,
                &transaction_writer,
                &mut first_state,
                &mut first_transactions,
            )
            .await;
            state_writer
                .mark_upload_persisted(first_state, first_seq)
                .await;
            transaction_writer
                .mark_upload_persisted(first_transactions, first_seq)
                .await;

            let second_seq = commit_staged_upload_pair(
                &client,
                &state_writer,
                &transaction_writer,
                &mut second_state,
                &mut second_transactions,
            )
            .await;
            state_writer
                .mark_upload_persisted(second_state, second_seq)
                .await;
            transaction_writer
                .mark_upload_persisted(second_transactions, second_seq)
                .await;

            assert!(third_state.writer_location_watermark().is_none());
            assert!(third_transactions.writer_location_watermark().is_none());

            let fourth_state = state_writer
                .prepare_upload(state_ops(4))
                .await
                .expect("fourth state upload");
            let fourth_transactions = transaction_writer
                .prepare_upload(transaction_ops(4))
                .await
                .expect("fourth transaction upload");
            assert_eq!(
                fourth_state.writer_location_watermark(),
                Some(second_state_latest),
            );
            assert_eq!(
                fourth_transactions.writer_location_watermark(),
                Some(second_transaction_latest),
            );
            assert!(
                state_writer
                    .prepare_flush()
                    .await
                    .expect("state flush prepares")
                    .is_none(),
            );
            assert!(
                transaction_writer
                    .prepare_flush()
                    .await
                    .expect("transaction flush prepares")
                    .is_none(),
            );

            let (pending_completion, _pending_rx) = oneshot::channel();
            let pending = VecDeque::from([PendingUploadCompletion {
                target: test_provable_target(2),
                state_latest: second_state_latest,
                transaction_latest: second_transaction_latest,
                completion: pending_completion,
                committed_at: Instant::now(),
            }]);
            let (completion, _rx) = oneshot::channel();
            let upload = PreparedQmdbUpload {
                height: 4,
                target: test_provable_target(4),
                sql_rows: Vec::new(),
                state: fourth_state,
                transactions: fourth_transactions,
                completion,
                metadata_persisted: metadata_ready(),
            };
            let schema = build_meta_schema(sql_meta_client(&client).expect("sql metadata client"))
                .expect("schema");
            let target_client = provable_target_client(&client).expect("provable target client");
            let (_sql_writer, batch) = prepare_commit_batch_blocking(
                context,
                schema.batch_writer(),
                state_writer,
                transaction_writer,
                target_client.clone(),
                upload,
                &pending,
                false,
            )
            .await
            .expect("batch stages");

            let expected = test_provable_target(2);
            let expected_key = Bytes::copy_from_slice(&expected.height.to_be_bytes());
            let expected_key = target_client
                .encode_store_key(&expected_key)
                .expect("provable target key encodes");
            assert!(
                batch.store_batch.entries().iter().any(|(key, value)| {
                    key == &expected_key && value == &expected.block_digest
                })
            );
            handle.abort();
        });
    }

    #[test]
    fn grouped_watermark_flush_completes_multiple_uploads() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let state_writer =
                StateWriter::<Sha256>::fresh(state_qmdb_client(&client).expect("state client"));
            let transaction_writer = TransactionWriter::<Sha256>::fresh(
                transactions_qmdb_client(&client).expect("transaction client"),
            );

            let mut first_state = state_writer
                .prepare_upload(state_ops(1))
                .await
                .expect("first state upload");
            let first_state_latest = first_state.latest_location();
            let mut first_transactions = transaction_writer
                .prepare_upload(transaction_ops(1))
                .await
                .expect("first transaction upload");
            let first_transaction_latest = first_transactions.latest_location();
            let mut second_state = state_writer
                .prepare_upload(state_ops(2))
                .await
                .expect("second state upload");
            let second_state_latest = second_state.latest_location();
            let mut second_transactions = transaction_writer
                .prepare_upload(transaction_ops(2))
                .await
                .expect("second transaction upload");
            let second_transaction_latest = second_transactions.latest_location();

            let first_seq = commit_staged_upload_pair(
                &client,
                &state_writer,
                &transaction_writer,
                &mut first_state,
                &mut first_transactions,
            )
            .await;
            let second_seq = commit_staged_upload_pair(
                &client,
                &state_writer,
                &transaction_writer,
                &mut second_state,
                &mut second_transactions,
            )
            .await;

            state_writer
                .mark_upload_persisted(first_state, first_seq)
                .await;
            transaction_writer
                .mark_upload_persisted(first_transactions, first_seq)
                .await;
            state_writer
                .mark_upload_persisted(second_state, second_seq)
                .await;
            transaction_writer
                .mark_upload_persisted(second_transactions, second_seq)
                .await;

            let (first_completion, first_rx) = oneshot::channel();
            let (second_completion, mut second_rx) = oneshot::channel();
            let watermark_wait = test_watermark_wait(&context);
            let mut pending = VecDeque::from([
                PendingUploadCompletion {
                    target: test_provable_target(1),
                    state_latest: first_state_latest,
                    transaction_latest: first_transaction_latest,
                    completion: first_completion,
                    committed_at: Instant::now(),
                },
                PendingUploadCompletion {
                    target: test_provable_target(2),
                    state_latest: second_state_latest,
                    transaction_latest: second_transaction_latest,
                    completion: second_completion,
                    committed_at: Instant::now(),
                },
            ]);

            assert_eq!(
                complete_published_uploads(
                    &mut pending,
                    &state_writer,
                    &transaction_writer,
                    &watermark_wait,
                )
                .await,
                1,
                "the in-band first watermark should complete only the first upload",
            );
            first_rx.await.expect("first upload completed");
            assert!(
                second_rx.try_recv().is_err(),
                "second upload must wait for the grouped catch-up watermark",
            );

            flush_and_complete_published_uploads(
                context.child("grouped_watermark"),
                &mut pending,
                WatermarkPipeline {
                    commit_client: &client,
                    commit_metrics: &crate::publisher::StoreCommitMetrics::new(&context),
                    state_writer: &state_writer,
                    transaction_writer: &transaction_writer,
                    provable_target_client: &provable_target_client(&client)
                        .expect("provable target client"),
                    watermark_wait: &watermark_wait,
                },
            )
            .await;

            assert!(pending.is_empty());
            second_rx.await.expect("second upload completed");
            assert_eq!(
                state_writer.latest_published_watermark().await,
                Some(second_state_latest),
            );
            assert_eq!(
                transaction_writer.latest_published_watermark().await,
                Some(second_transaction_latest),
            );
            assert_eq!(
                latest_provable_target(&client).await,
                Some(test_provable_target(2)),
            );
            handle.abort();
        });
    }

    #[test]
    fn out_of_order_store_commits_do_not_publish_past_prefix_holes() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let state_writer = Arc::new(StateWriter::<Sha256>::fresh(
                state_qmdb_client(&client).expect("state client"),
            ));
            let transaction_writer = Arc::new(TransactionWriter::<Sha256>::fresh(
                transactions_qmdb_client(&client).expect("transaction client"),
            ));
            let schema = build_meta_schema(sql_meta_client(&client).expect("sql metadata client"))
                .expect("schema");
            let mut sql_writer = schema.batch_writer();

            let (first_completion, mut first_rx) = oneshot::channel();
            let first_upload = PreparedQmdbUpload {
                height: 1,
                target: test_provable_target(1),
                sql_rows: Vec::new(),
                state: state_writer
                    .prepare_upload(state_ops(1))
                    .await
                    .expect("first state upload"),
                transactions: transaction_writer
                    .prepare_upload(transaction_ops(1))
                    .await
                    .expect("first transaction upload"),
                completion: first_completion,
                metadata_persisted: metadata_ready(),
            };
            let no_pending = VecDeque::new();
            let (next_sql_writer, first_batch) = prepare_commit_batch_blocking(
                context.child("first"),
                sql_writer,
                state_writer.clone(),
                transaction_writer.clone(),
                provable_target_client(&client).expect("provable target client"),
                first_upload,
                &no_pending,
                true,
            )
            .await
            .expect("first batch stages");
            sql_writer = next_sql_writer;

            let (second_completion, mut second_rx) = oneshot::channel();
            let second_upload = PreparedQmdbUpload {
                height: 2,
                target: test_provable_target(2),
                sql_rows: Vec::new(),
                state: state_writer
                    .prepare_upload(state_ops(2))
                    .await
                    .expect("second state upload"),
                transactions: transaction_writer
                    .prepare_upload(transaction_ops(2))
                    .await
                    .expect("second transaction upload"),
                completion: second_completion,
                metadata_persisted: metadata_ready(),
            };
            let (next_sql_writer, second_batch) = prepare_commit_batch_blocking(
                context.child("second"),
                sql_writer,
                state_writer.clone(),
                transaction_writer.clone(),
                provable_target_client(&client).expect("provable target client"),
                second_upload,
                &no_pending,
                false,
            )
            .await
            .expect("second batch stages");
            sql_writer = next_sql_writer;
            let second_seq = second_batch
                .store_batch
                .commit(&client)
                .await
                .expect("second batch commits");
            let first_seq = first_batch
                .store_batch
                .commit(&client)
                .await
                .expect("first batch commits");

            let mut pending = VecDeque::new();
            let watermark_wait = test_watermark_wait(&context);
            pending.push_back(
                mark_committed_batch(
                    committed_batch(second_batch, second_seq),
                    &mut sql_writer,
                    &state_writer,
                    &transaction_writer,
                )
                .await,
            );
            assert_eq!(
                complete_published_uploads(
                    &mut pending,
                    &state_writer,
                    &transaction_writer,
                    &watermark_wait,
                )
                .await,
                0,
                "a later commit cannot publish while the first batch is still unacked",
            );
            assert!(first_rx.try_recv().is_err());
            assert!(second_rx.try_recv().is_err());

            pending.push_back(
                mark_committed_batch(
                    committed_batch(first_batch, first_seq),
                    &mut sql_writer,
                    &state_writer,
                    &transaction_writer,
                )
                .await,
            );
            flush_and_complete_published_uploads(
                context.child("watermarks"),
                &mut pending,
                WatermarkPipeline {
                    commit_client: &client,
                    commit_metrics: &crate::publisher::StoreCommitMetrics::new(&context),
                    state_writer: &state_writer,
                    transaction_writer: &transaction_writer,
                    provable_target_client: &provable_target_client(&client)
                        .expect("provable target client"),
                    watermark_wait: &watermark_wait,
                },
            )
            .await;

            assert!(pending.is_empty());
            first_rx.try_recv().expect("first upload completed");
            second_rx.try_recv().expect("second upload completed");
            assert_eq!(
                latest_provable_target(&client).await,
                Some(test_provable_target(2)),
            );
            handle.abort();
        });
    }

    #[test]
    fn queued_upload_completes_through_publisher() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect(
                context.child("qmdb_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context),
            )
            .await
            .expect("publisher connects");

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload())
                .await
                .expect("queued upload accepted");
            completion.wait().await.expect("queued upload completes");

            let encoded_metrics = context.encode();
            for metric in [
                "expansion_duration_count",
                "staging_duration_count",
                "watermark_wait_duration_count",
            ] {
                assert!(has_metric_value(&encoded_metrics, metric, 1));
            }

            publisher.shutdown().await;
            handle.abort();
        });
    }

    #[test]
    fn bulk_upload_waits_for_metadata_persistence() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::GatedIngestStore::open()
                .await
                .expect("spawn gated Store");
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect(
                context.child("qmdb_publisher"),
                &store.url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context),
            )
            .await
            .expect("publisher connects");

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload())
                .await
                .expect("queued upload accepted");
            store.wait_for_first_ingest().await;
            let bulk_overtook = store
                .later_ingest_arrives_within(std::time::Duration::from_millis(250))
                .await;
            store.release_first_ingest();
            completion.wait().await.expect("queued upload completes");

            let encoded_metrics = context.encode();
            assert!(has_metric_value(
                &encoded_metrics,
                "metadata_finalized_lag_count",
                1
            ));
            assert!(has_metric_value(
                &encoded_metrics,
                "metadata_gate_wait_duration_count",
                1
            ));
            publisher.shutdown().await;
            store.shutdown().await;

            assert!(
                !bulk_overtook,
                "bulk upload reached Store before block metadata persisted"
            );
        });
    }

    #[test]
    fn publisher_sends_configured_credentials() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let store = crate::test_store::ObservedStore::open("writer-key")
                .await
                .expect("spawn observed Store");
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect(
                context.child("qmdb_publisher"),
                &store.url,
                Some("writer-key"),
                2,
                crate::publisher::PublisherMetrics::new(&context),
            )
            .await
            .expect("publisher connects");

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload())
                .await
                .expect("queued upload accepted");
            completion.wait().await.expect("queued upload completes");

            let requests = store.requests();
            assert!(!requests.is_empty());
            assert!(requests.iter().all(|request| request.authorized));
            assert!(
                requests
                    .iter()
                    .any(|request| request.path.starts_with("/store.query.v1.Service/")),
                "recovery should reach Store query. Observed RPCs were {requests:?}",
            );
            assert!(
                requests
                    .iter()
                    .any(|request| request.path.starts_with("/log.ingest.v1.Service/")),
                "commits should reach Store ingest. Observed RPCs were {requests:?}",
            );

            publisher.shutdown().await;
            store.shutdown().await;
        });
    }

    #[tokio::test]
    async fn upload_completion_reports_worker_exit() {
        let (tx, rx) = oneshot::channel();
        drop(tx);
        let completion = UploadCompletion { height: 7, rx };

        assert!(matches!(
            completion.wait().await,
            Err(PublishError::CommitterStopped { height: 7 })
        ));
    }

    #[test]
    fn publisher_rejects_unpublished_recovery_frontier() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let result = Publisher::<Sha256, ed25519::PublicKey>::connect_at(
                context.child("publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context),
                WriterNextLocations::new(1, 0),
            )
            .await;

            assert!(matches!(
                result,
                Err(PublishError::Qmdb(QmdbError::WatermarkTooLow {
                    requested: 0,
                    available: 0,
                }))
            ));
            handle.abort();
        });
    }

    #[test]
    fn parallel_publisher_recovers_writer_state_on_reconnect() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let strategy = context.strategy(NZUsize!(2)).manual();

            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect_with_strategy(
                context.child("first_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context.child("first_metrics")),
                strategy.clone(),
            )
            .await
            .expect("publisher connects to empty store");
            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload())
                .await
                .expect("first upload accepted");
            completion.wait().await.expect("first upload completes");
            let replay_locations = publisher.next_locations().await;
            publisher.shutdown().await;

            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect_at(
                context.child("empty_replay_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context.child("empty_replay_metrics")),
                WriterNextLocations::new(0, 0),
            )
            .await
            .expect("publisher reconnects at the empty frontier");
            assert_eq!(publisher.next_locations().await, (0, 0));
            publisher.shutdown().await;

            // Reconnecting rebuilds writer state from a bounded checkpoint
            // ending at the published watermark rather than the full
            // operation history.
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect_with_strategy(
                context.child("second_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context.child("second_metrics")),
                strategy.clone(),
            )
            .await
            .expect("publisher reconnects to populated store");
            assert_eq!(publisher.next_locations().await, replay_locations);

            // The recovered peaks must support further uploads end to end.
            let (state_start, transaction_start) = replay_locations;
            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload_at(2, state_start, transaction_start))
                .await
                .expect("follow-up upload accepted");
            completion.wait().await.expect("follow-up upload completes");
            let remote_locations = publisher.next_locations().await;
            publisher.shutdown().await;

            // Durable queue replay deliberately recovers behind Store when a
            // remote upload completed before its local queue entry was pruned.
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect_with_strategy_at(
                context.child("third_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context.child("third_metrics")),
                WriterNextLocations::new(replay_locations.0, replay_locations.1),
                strategy,
            )
            .await
            .expect("publisher reconnects at retained queue frontier");
            assert_eq!(publisher.next_locations().await, replay_locations);

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload_at(
                    2,
                    replay_locations.0,
                    replay_locations.1,
                ))
                .await
                .expect("retained upload replay accepted");
            completion.wait().await.expect("retained upload replays");
            assert_eq!(publisher.next_locations().await, remote_locations);

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload_at(
                    3,
                    remote_locations.0,
                    remote_locations.1,
                ))
                .await
                .expect("post-replay upload accepted");
            completion
                .wait()
                .await
                .expect("post-replay upload completes");

            publisher.shutdown().await;
            handle.abort();
        });
    }

    #[test]
    fn queued_upload_roots_match_application_roots() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let strategy = context.strategy(NZUsize!(2)).manual();
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect_with_strategy(
                context.child("qmdb_publisher"),
                &url,
                None,
                2,
                crate::publisher::PublisherMetrics::new(&context),
                strategy,
            )
            .await
            .expect("publisher connects");
            let databases =
                test_application_databases(context.child("application"), "root-match").await;

            let first = build_and_commit_application_block(
                &databases,
                None,
                1,
                vec![
                    (
                        account_key(1),
                        Account {
                            balance: 10,
                            nonce: Nonce::default(),
                        },
                    ),
                    (
                        account_key(2),
                        Account {
                            balance: 20,
                            nonce: Nonce::default(),
                        },
                    ),
                ],
                vec![signed_transaction(1, 0), signed_transaction(2, 0)],
            )
            .await;
            Box::pin(publish_block_and_assert_roots(
                &publisher, &client, &databases, &first,
            ))
            .await;
            assert_transaction_append_locations_match_block(&client, &first).await;

            let second = build_and_commit_application_block(
                &databases,
                Some(&first),
                2,
                vec![
                    (
                        account_key(1),
                        Account {
                            balance: 9,
                            nonce: Nonce::new(1, 0),
                        },
                    ),
                    (
                        account_key(3),
                        Account {
                            balance: 30,
                            nonce: Nonce::default(),
                        },
                    ),
                ],
                vec![signed_transaction(3, 1)],
            )
            .await;
            Box::pin(publish_block_and_assert_roots(
                &publisher, &client, &databases, &second,
            ))
            .await;
            assert_transaction_append_locations_match_block(&client, &second).await;

            // Crash recovery redelivers finalized blocks whose uploads already
            // committed. A fully covered block must skip capture instead of
            // failing writer validation.
            let (state_next, transaction_next) = publisher.next_locations().await;
            let redelivered = Publisher::build_queued_finalized_upload(
                state_next,
                transaction_next,
                &second,
                &databases.readers(),
            )
            .await
            .expect("redelivered block builds");
            assert!(
                redelivered.is_none(),
                "fully uploaded block must skip capture"
            );

            // Cursors covering only one namespace indicate real divergence and
            // must still fail loudly.
            let partial = Publisher::build_queued_finalized_upload(
                state_next,
                second.header.transactions_range.end() - 1,
                &second,
                &databases.readers(),
            )
            .await;
            assert!(matches!(partial, Err(PublishError::WriterOutOfSync { .. })));

            publisher.shutdown().await;
            handle.abort();
        });
    }

    #[test]
    fn qmdb_publisher_shutdown_joins_background_workers() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let (handle, url) = exoware_simulator::open_temp()
                .await
                .expect("spawn simulator");
            let publisher = Publisher::<
                commonware_cryptography::sha256::Sha256,
                commonware_cryptography::ed25519::PublicKey,
            >::connect(
                context.child("qmdb_publisher"),
                &url,
                None,
                1,
                crate::publisher::PublisherMetrics::new(&context),
            )
            .await
            .expect("publisher connects");

            publisher.shutdown().await;
            handle.abort();
        });
    }

    async fn test_application_databases<E>(
        context: E,
        prefix: &str,
    ) -> Databases<E, Sha256, EightCap, Sequential>
    where
        E: BufferPooler + Clock + Metrics + Spawner + Storage + Supervisor + Send + Sync + 'static,
    {
        let page_cache = CacheRef::from_pooler(
            &context,
            TEST_PAGE_CACHE_PAGE_SIZE,
            TEST_PAGE_CACHE_CAPACITY,
        );
        let config = (
            test_state_db_config(&page_cache, prefix),
            test_transaction_db_config(&page_cache, prefix),
        );
        Databases::init(context, config).await
    }

    fn test_state_db_config(
        page_cache: &CacheRef,
        prefix: &str,
    ) -> FixedConfig<EightCap, Sequential> {
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("{prefix}-state-journal"),
                metadata_partition: format!("{prefix}-state-metadata"),
                items_per_blob: TEST_ITEMS_PER_BLOB,
                write_buffer: TEST_WRITE_BUFFER,
                strategy: Sequential,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: format!("{prefix}-state-log"),
                items_per_blob: TEST_ITEMS_PER_BLOB,
                page_cache: page_cache.clone(),
                write_buffer: TEST_WRITE_BUFFER,
            },
            translator: EightCap,
            init_cache_size: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: (),
        }
    }

    fn test_transaction_db_config(
        page_cache: &CacheRef,
        prefix: &str,
    ) -> keyless_fixed::CompactConfig<Sequential> {
        keyless_fixed::CompactConfig {
            strategy: Sequential,
            witness: VariableJournalConfig {
                partition: format!("{prefix}-transactions-witness"),
                items_per_section: TEST_ITEMS_PER_BLOB,
                compression: None,
                codec_config: (),
                page_cache: page_cache.clone(),
                write_buffer: TEST_WRITE_BUFFER,
            },
            commit_codec_config: (),
        }
    }

    async fn build_and_commit_application_block<E>(
        databases: &Databases<E, Sha256, EightCap, Sequential>,
        parent: Option<&EngineBlock<Sha256, ed25519::PublicKey>>,
        height: u64,
        state_updates: Vec<(AccountKey, Account)>,
        transactions: Vec<SignedTransaction<Sha256>>,
    ) -> EngineBlock<Sha256, ed25519::PublicKey>
    where
        E: BufferPooler + Storage + Clock + Metrics + Spawner + Send + Sync + 'static,
    {
        let (state_batch, transaction_batch) = databases.new_batches().await;
        let state_batch = state_updates
            .into_iter()
            .fold(state_batch, |batch, (key, account)| {
                batch.write(key, Some(account))
            });
        let transaction_batch = transactions
            .iter()
            .fold(transaction_batch, |batch, transaction| {
                batch.append(*transaction.message_digest())
            });
        let transaction_batch = match parent {
            Some(parent) => {
                transaction_batch.with_inactivity_floor(parent_transaction_floor(parent))
            }
            None => transaction_batch,
        };
        let (state, transaction_history) =
            futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
        let state = state.expect("state merkleization should succeed");
        let transaction_history =
            transaction_history.expect("transaction merkleization should succeed");
        let state_root = state.root();
        let state_range =
            non_empty_range!(*state.bounds().inactivity_floor, *state.bounds().tip.size);
        let transactions_root = transaction_history.root();
        let transactions_range = non_empty_range!(
            *transaction_history.bounds().inactivity_floor,
            *transaction_history.bounds().tip.size
        );
        databases.apply((state, transaction_history)).await;
        assert!(databases.finalize().await.durable().await);

        let leader = ed25519::PrivateKey::from_seed(height).public_key();
        let parent_digest = parent.map_or(Sha256Digest::EMPTY, |block| block.digest());
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), Commitment::EMPTY),
            },
            parent: parent_digest,
            height,
            timestamp: height,
            state_root,
            state_range,
            transactions_root,
            transactions_range,
        };
        Block::new(header, transactions).seal(&mut Sha256::default())
    }

    async fn publish_block_and_assert_roots<E>(
        publisher: &Publisher<Sha256, ed25519::PublicKey>,
        client: &StoreClient,
        databases: &Databases<E, Sha256, EightCap, Sequential>,
        block: &EngineBlock<Sha256, ed25519::PublicKey>,
    ) where
        E: BufferPooler + Storage + Clock + Metrics + Spawner + Send + Sync + 'static,
    {
        let (state_next, transaction_next) = publisher.next_locations().await;
        let upload = Publisher::build_queued_finalized_upload(
            state_next,
            transaction_next,
            block,
            &databases.readers(),
        )
        .await
        .expect("queued upload builds")
        .expect("block is not yet uploaded");
        let state_start = upload.state_start();
        let transaction_start = upload.transaction_start();
        let completion = publisher
            .enqueue_queued_finalized(upload)
            .await
            .expect("queued upload accepted");
        completion.wait().await.expect("queued upload completes");

        let state_reader =
            UnorderedClient::<QmdbFamily, Sha256, AccountKey, AccountValue, StateEncoding>::new(
                state_qmdb_client(client).expect("state client"),
                (),
            );
        let transaction_reader =
            KeylessClient::<QmdbFamily, Sha256, Sha256Digest, TransactionEncoding<Sha256>>::new(
                transactions_qmdb_client(client).expect("transaction client"),
                (),
            );
        let state_tip = Location::new(block.header.state_range.end() - 1);
        let transaction_tip = Location::new(block.header.transactions_range.end() - 1);

        assert_eq!(
            state_reader.root_at(state_tip).await.expect("state root"),
            block.header.state_root,
            "published state QMDB root must match certified application root"
        );
        assert_eq!(
            transaction_reader
                .root_at(transaction_tip)
                .await
                .expect("transaction root"),
            block.header.transactions_root,
            "published transaction QMDB root must match certified application root"
        );

        for location in state_start..block.header.state_range.end() {
            let proof = state_reader
                .operation_range_proof(state_tip, Location::new(location), 1)
                .await
                .expect("state operation proof");
            assert_eq!(
                proof.root, block.header.state_root,
                "state operation proof root at {location} must match certified application root"
            );
            assert_eq!(proof.start_location, Location::new(location));
            assert_eq!(proof.operations.len(), 1);
        }

        for location in transaction_start..block.header.transactions_range.end() {
            let proof = transaction_reader
                .operation_range_proof(transaction_tip, Location::new(location), 1)
                .await
                .expect("transaction operation proof");
            assert_eq!(
                proof.root, block.header.transactions_root,
                "transaction operation proof root at {location} must match certified application root"
            );
            assert_eq!(proof.start_location, Location::new(location));
            assert_eq!(proof.operations.len(), 1);
        }
    }

    async fn assert_transaction_append_locations_match_block(
        client: &StoreClient,
        block: &EngineBlock<Sha256, ed25519::PublicKey>,
    ) {
        let reader =
            KeylessClient::<QmdbFamily, Sha256, Sha256Digest, TransactionEncoding<Sha256>>::new(
                transactions_qmdb_client(client).expect("transaction client"),
                (),
            );
        let rows = encode_bulk_block_rows(block);
        let tx_count =
            u64::try_from(rows.transaction_digests.len()).expect("transaction count fits u64");
        let append_start = block
            .header
            .transactions_range
            .end()
            .checked_sub(tx_count + 1)
            .expect("transaction range includes append operations plus commit");
        let tip = Location::new(block.header.transactions_range.end() - 1);

        for (offset, digest) in rows.transaction_digests.into_iter().enumerate() {
            let location =
                append_start + u64::try_from(offset).expect("transaction index fits u64");
            let proof = reader
                .operation_range_proof(tip, Location::new(location), 1)
                .await
                .expect("transaction operation proof");
            assert_eq!(
                proof.operations,
                vec![TransactionOperation::<Sha256>::Append(digest)],
                "transaction row location {location} must prove its own digest",
            );
        }
    }

    fn parent_transaction_floor(
        parent: &EngineBlock<Sha256, ed25519::PublicKey>,
    ) -> Location<QmdbFamily> {
        let parent_body_len = u64::try_from(parent.body.len()).expect("transaction count fits u64");
        let floor = parent
            .header
            .transactions_range
            .end()
            .checked_sub(parent_body_len)
            .and_then(|end| end.checked_sub(1))
            .expect("parent transaction range includes commit");
        Location::new(floor)
    }

    fn account_key(seed: u64) -> AccountKey {
        AccountKey::from([seed as u8; AccountKey::SIZE])
    }

    fn signed_transaction(seed: u64, nonce: u64) -> SignedTransaction<Sha256> {
        let sender = ed25519::PrivateKey::from_seed(seed);
        let recipient = ed25519::PrivateKey::from_seed(seed + 100).public_key();
        Transaction::new(
            TransactionPublicKey::ed25519(sender.public_key()),
            TransactionPublicKey::ed25519(recipient),
            StdNonZeroU64::new(1).expect("test value is non-zero"),
            nonce,
        )
        .seal_and_sign(&sender, TRANSACTION_NAMESPACE, &mut Sha256::default())
    }

    async fn commit_staged_upload_pair(
        client: &StoreClient,
        state_writer: &StateWriter<Sha256>,
        transaction_writer: &TransactionWriter<Sha256>,
        state: &mut PreparedUpload<QmdbFamily>,
        transactions: &mut PreparedUpload<QmdbFamily>,
    ) -> u64 {
        let mut batch = StoreWriteBatch::new();
        state_writer
            .stage_upload(state, &mut batch)
            .expect("state rows stage");
        transaction_writer
            .stage_upload(transactions, &mut batch)
            .expect("transaction rows stage");
        batch.commit(client).await.expect("upload batch commits")
    }

    fn committed_batch(batch: QmdbCommitBatch, store_seq: u64) -> CommittedQmdbBatch {
        CommittedQmdbBatch {
            upload: batch.upload,
            sql: batch.sql,
            rows: batch.rows,
            state_watermark: batch.state_watermark,
            transaction_watermark: batch.transaction_watermark,
            store_seq,
            committed_at: Instant::now(),
        }
    }

    fn state_ops(seed: u8) -> Vec<StateOperation> {
        let key = AccountKey::from([seed; AccountKey::SIZE]);
        vec![
            StateOperation::Update(UnorderedUpdate(
                key,
                encode_account(Account {
                    balance: u64::from(seed),
                    nonce: Nonce::default(),
                }),
            )),
            StateOperation::CommitFloor(None, Location::new(0)),
        ]
    }

    fn transaction_ops(seed: u8) -> Vec<TransactionOperation<Sha256>> {
        vec![
            TransactionOperation::<Sha256>::Append(Sha256::hash(&[&[seed]])),
            TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
        ]
    }

    fn test_provable_target(height: u64) -> ProvableTarget {
        ProvableTarget {
            height,
            block_digest: Bytes::from(vec![height as u8; 32]),
        }
    }

    async fn latest_provable_target(client: &StoreClient) -> Option<ProvableTarget> {
        let client = provable_target_client(client).expect("provable target client");
        let rows = client
            .query()
            .range_with_mode(&Bytes::new(), &Bytes::new(), 1, RangeMode::Reverse)
            .await
            .expect("provable target query succeeds");
        rows.into_iter().next().map(|(key, block_digest)| {
            let height = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .expect("provable target key is a u64"),
            );
            ProvableTarget {
                height,
                block_digest,
            }
        })
    }

    fn test_queued_upload() -> QueuedFinalizedUpload<Sha256, ed25519::PublicKey> {
        test_queued_upload_at(1, 0, 0)
    }

    fn test_queued_upload_at(
        height: u64,
        state_start: u64,
        transaction_start: u64,
    ) -> QueuedFinalizedUpload<Sha256, ed25519::PublicKey> {
        let leader = ed25519::PrivateKey::from_seed(7).public_key();

        // An empty block body appends one transaction commit operation, plus
        // the genesis commit when the store starts empty.
        let transaction_ops = if transaction_start == 0 { 2 } else { 1 };
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (
                    View::zero(),
                    Commitment::from((
                        Sha256Digest::EMPTY,
                        Sha256Digest::EMPTY,
                        Sha256Digest::EMPTY,
                        coding_config_for_participants(4),
                    )),
                ),
            },
            parent: Sha256Digest::EMPTY,
            height,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(state_start, state_start + 2),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(
                transaction_start,
                transaction_start + transaction_ops
            ),
        };
        let block = Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
            .seal(&mut Sha256::default());
        let account_key = AccountKey::from([1u8; AccountKey::SIZE]);
        let state_delta = vec![
            StateOperation::Update(UnorderedUpdate(
                account_key,
                encode_account(Account {
                    balance: height,
                    nonce: Nonce::default(),
                }),
            )),
            StateOperation::CommitFloor(None, Location::new(0)),
        ];

        QueuedFinalizedUpload {
            block: Arc::new(block),
            finalized_ts_micros: 1_000,
            state_start,
            transaction_start,
            state_delta: Arc::new(state_delta),
        }
    }
}
