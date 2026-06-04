//! Combined publisher for finalized SQL metadata and QMDB rows.

use super::{
    block::{IndexedBlockRows, encode_indexed_block_rows_at},
    sql::{AccountMetaRow, encode_account_meta_row},
};
use crate::sql_schema::build_meta_schema;
use commonware_codec::{
    Codec, Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
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
use constantinople_application::consensus::{Databases, StateDatabase};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{Account, AccountKey, BlockCfg};
use exoware_qmdb::{
    KeylessClient, KeylessWriter, PreparedUpload, PreparedWatermark, QmdbError, UnorderedClient,
    UnorderedWriter, WriterState,
};
use exoware_sdk::{ClientError, StoreClient, StoreKeyPrefix, StoreWriteBatch};
use exoware_sql::{BatchWriter, PreparedBatch};
use std::{
    collections::VecDeque,
    marker::PhantomData,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::sleep,
};
use tracing::{debug, warn};

/// Store namespace for QMDB account-state rows.
pub const STATE_QMDB_PREFIX_VALUE: u16 = 0x8;
/// Store namespace for QMDB transaction-hash rows.
pub const TRANSACTIONS_QMDB_PREFIX_VALUE: u16 = 0x9;
/// Number of high-order Store key bits used for QMDB operation-log namespaces.
pub const STORE_PREFIX_RESERVED_BITS: u8 = 4;
/// Durable queued uploads are self-contained and comparatively cheap to admit.
const MAX_BUFFERED_QMDB_UPLOADS: usize = 64;

type QmdbFamily = mmr::Family;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateEncoding = FixedEncoding<AccountValue>;
type LocalStateOperation = UnorderedOperation<QmdbFamily, AccountKey, FixedEncoding<Account>>;
type StateOperation = UnorderedOperation<QmdbFamily, AccountKey, StateEncoding>;
type TransactionEncoding<H> = FixedEncoding<<H as Hasher>::Digest>;
type TransactionOperation<H> = keyless::Operation<QmdbFamily, TransactionEncoding<H>>;
type StateWriter<H> = UnorderedWriter<QmdbFamily, H, AccountKey, AccountValue, StateEncoding>;
type TransactionWriter<H> =
    KeylessWriter<QmdbFamily, H, <H as Hasher>::Digest, TransactionEncoding<H>>;

/// Completion signal for a queued finalized-block upload.
pub struct UploadCompletion {
    rx: oneshot::Receiver<()>,
}

impl UploadCompletion {
    fn completed() -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(());
        Self { rx }
    }

    /// Waits until the upload has been marked persisted.
    ///
    /// Returns `false` if the uploader task exits before reporting success.
    pub async fn wait(self) -> bool {
        self.rx.await.is_ok()
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
#[derive(Clone)]
pub struct QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    block: EngineBlock<H, P>,
    finalized_ts_micros: i64,
    state_start: u64,
    transaction_start: u64,
    state_delta: Vec<StateOperation>,
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

    pub const fn block(&self) -> &EngineBlock<H, P> {
        &self.block
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
            block: EngineBlock::<H, P>::read_cfg(buf, &cfg.block)?,
            finalized_ts_micros: i64::read(buf)?,
            state_start: u64::read(buf)?,
            transaction_start: u64::read(buf)?,
            state_delta: Vec::<StateOperation>::read_cfg(buf, &(cfg.state_ops, ()))?,
        })
    }
}

/// QMDB upload failure.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
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
    #[error("cannot initialize QMDB writer from {locations} operation locations")]
    CheckpointTooLarge { locations: u64 },
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
    prepare_join: Option<JoinHandle<()>>,
    commit_join: Option<JoinHandle<()>>,
    _marker: PhantomData<P>,
}

struct PendingPreparedQmdbUpload<H>
where
    H: Hasher,
{
    height: u64,
    block_rows: IndexedBlockRows<H::Digest>,
    state_delta: Vec<StateOperation>,
    account_rows: Vec<super::SqlRow>,
    transaction_ops: Vec<TransactionOperation<H>>,
    completion: oneshot::Sender<()>,
}

struct PendingQueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    height: u64,
    upload: QueuedFinalizedUpload<H, P>,
    completion: oneshot::Sender<()>,
}

struct PreparedQmdbUpload {
    height: u64,
    sql_rows: Vec<super::SqlRow>,
    state: PreparedUpload<QmdbFamily>,
    transactions: PreparedUpload<QmdbFamily>,
    completion: oneshot::Sender<()>,
}

struct StagedQmdbUpload {
    height: u64,
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
}

struct CommitBatchStage<H>
where
    H: Hasher,
{
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    sql_upload: SqlUpload,
    state_upload: PreparedUpload<QmdbFamily>,
    transaction_upload: PreparedUpload<QmdbFamily>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
}

struct CommitPipeline<'a, H>
where
    H: Hasher,
{
    commits: &'a mut JoinSet<CommittedQmdbBatch>,
    commit_client: &'a StoreClient,
    state_writer: &'a Arc<StateWriter<H>>,
    transaction_writer: &'a Arc<TransactionWriter<H>>,
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
}

struct PendingUploadCompletion {
    state_latest: Location<QmdbFamily>,
    transaction_latest: Location<QmdbFamily>,
    completion: oneshot::Sender<()>,
}

impl<H, P> Publisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    /// Construct writers over the two QMDB Store namespaces.
    pub async fn connect<Cx>(
        context: Cx,
        store_url: &str,
        buffer: usize,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
    {
        let commit_client = StoreClient::new(store_url);
        let state_client = state_qmdb_client(&commit_client)?;
        let transaction_client = transactions_qmdb_client(&commit_client)?;
        let sql_writer = build_meta_schema(commit_client.clone())
            .map_err(PublishError::SqlSchema)?
            .batch_writer();
        let state = recover_state_writer_state::<H>(state_client.clone()).await?;
        let transactions =
            recover_transaction_writer_state::<H>(transaction_client.clone()).await?;
        let state_writer = Arc::new(StateWriter::new(state_client, state));
        let transaction_writer = Arc::new(TransactionWriter::new(transaction_client, transactions));
        let state_next_location =
            next_writer_location(state_writer.latest_published_watermark().await);
        let transaction_next_location =
            next_writer_location(transaction_writer.latest_published_watermark().await);
        let buffer = buffer.clamp(1, MAX_BUFFERED_QMDB_UPLOADS);
        let (commit_tx, commit_rx) = mpsc::channel(buffer);
        let (prepare_tx, prepare_rx) = mpsc::channel(buffer);
        let max_in_flight_commits = buffer;
        let commit_context = context.child("commit");
        let prepare_context = context.child("prepare");
        let commit_join = tokio::spawn(run_qmdb_committer(
            commit_context,
            commit_client.clone(),
            sql_writer,
            state_writer.clone(),
            transaction_writer.clone(),
            commit_rx,
            max_in_flight_commits,
        ));
        let prepare_join = tokio::spawn(run_qmdb_preparer(
            prepare_context,
            state_writer.clone(),
            transaction_writer.clone(),
            prepare_rx,
            commit_tx,
        ));

        Ok(Self {
            state_next_location: Mutex::new(state_next_location),
            transaction_next_location: Mutex::new(transaction_next_location),
            prepare_tx: Some(prepare_tx),
            prepare_join: Some(prepare_join),
            commit_join: Some(commit_join),
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
    /// This deliberately stops at the durable local payload boundary. Remote
    /// Store staging and upload are handled later by the queue consumer:
    ///
    /// - captured here: block, finalized timestamp, QMDB writer start cursors,
    ///   and the state operation delta that can be lost after local pruning;
    /// - derived later: SQL metadata rows, transaction QMDB ops, account SQL
    ///   rows, watermarks, and the final Store batch.
    pub async fn build_queued_finalized_upload_with_context<Cx, E, S>(
        context: Cx,
        state_writer_next: u64,
        transaction_writer_next: u64,
        block: &EngineBlock<H, P>,
        databases: &Databases<E, H, commonware_storage::translator::EightCap, S>,
    ) -> Result<QueuedFinalizedUpload<H, P>, PublishError>
    where
        Cx: Spawner,
        E: Storage + Clock + Metrics + Send + Sync + 'static,
        S: Strategy + Send + Sync + 'static,
    {
        let state_end = block.header.state_range.end();
        validate_writer_range(state_writer_next, state_end, block.header.height)?;
        transaction_upload_end(transaction_writer_next, block)?;
        let block = block.clone();
        let state_block = block.clone();
        let state_db = databases.0.clone();
        let state_delta = context
            .child("state_delta")
            .shared(true)
            .spawn(move |_| async move {
                build_state_delta::<E, H, P, S>(state_writer_next, &state_block, &state_db).await
            })
            .await
            .expect("QMDB state queue task exited")?;

        Ok(QueuedFinalizedUpload {
            block,
            finalized_ts_micros: current_time_micros(),
            state_start: state_writer_next,
            transaction_start: transaction_writer_next,
            state_delta,
        })
    }

    /// Queue a previously durable finalized-block payload for remote upload.
    pub async fn enqueue_queued_finalized(
        &self,
        upload: QueuedFinalizedUpload<H, P>,
    ) -> Result<UploadCompletion, PublishError> {
        let mut state_next = self.state_next_location.lock().await;
        let mut transaction_next = self.transaction_next_location.lock().await;

        let state_end = upload.state_end();
        let transaction_end = upload.transaction_end();
        if *state_next >= state_end && *transaction_next >= transaction_end {
            return Ok(UploadCompletion::completed());
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

        let height = upload.height();
        let (completion, rx) = oneshot::channel();
        let prepare_tx = self
            .prepare_tx
            .as_ref()
            .expect("publisher send channel is open until shutdown");
        prepare_tx
            .send(PendingQueuedFinalizedUpload {
                height,
                upload,
                completion,
            })
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        *state_next = state_end;
        *transaction_next = transaction_end;
        Ok(UploadCompletion { rx })
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

async fn run_qmdb_preparer<Cx, H, P>(
    context: Cx,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    mut rx: mpsc::Receiver<PendingQueuedFinalizedUpload<H, P>>,
    commit_tx: mpsc::Sender<PreparedQmdbUpload>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    while let Some(upload) = rx.recv().await {
        let height = upload.height;
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

async fn prepare_qmdb_upload<Cx, H, P>(
    context: Cx,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    upload: PendingQueuedFinalizedUpload<H, P>,
) -> Result<PreparedQmdbUpload, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
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
    } = upload;
    let QueuedFinalizedUpload {
        block,
        finalized_ts_micros,
        state_start,
        transaction_start,
        state_delta,
    } = upload;
    // This is the upload-time half of the durable queue contract: only data
    // that had to survive prune is persisted in the queue. Everything below is
    // deterministic from the queued block, timestamp, cursors, and state delta.
    let block_rows = encode_indexed_block_rows_at(&block, finalized_ts_micros);
    let transaction_ops = build_transaction_upload_from_digests(
        &block,
        transaction_start,
        &block_rows.transaction_digests,
    )?
    .ops;
    let account_rows = account_rows(&state_delta, state_start);
    Ok(PendingPreparedQmdbUpload {
        height,
        block_rows,
        state_delta,
        account_rows,
        transaction_ops,
        completion,
    })
}

async fn prepare_prepared_qmdb_upload<Cx, H>(
    context: Cx,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    upload: PendingPreparedQmdbUpload<H>,
) -> Result<PreparedQmdbUpload, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let PendingPreparedQmdbUpload {
        height,
        block_rows,
        state_delta,
        account_rows,
        transaction_ops,
        completion,
    } = upload;
    let IndexedBlockRows {
        sql,
        transaction_digests: _,
    } = block_rows;
    let mut sql = sql;
    sql.extend(account_rows);

    let state_prepare = context
        .child("state")
        .shared(true)
        .spawn(move |_| async move { state_writer.prepare_upload(&state_delta).await });
    let transaction_prepare = context
        .child("transactions")
        .shared(true)
        .spawn(move |_| async move { transaction_writer.prepare_upload(&transaction_ops).await });
    let (state, transactions) = tokio::join!(state_prepare, transaction_prepare);
    let state = state.expect("QMDB state prepare task exited")?;
    let transactions = transactions.expect("QMDB transaction prepare task exited")?;

    Ok(PreparedQmdbUpload {
        height,
        sql_rows: sql,
        state,
        transactions,
        completion,
    })
}

async fn run_qmdb_committer<Cx, H>(
    context: Cx,
    commit_client: StoreClient,
    mut sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    mut rx: mpsc::Receiver<PreparedQmdbUpload>,
    max_in_flight_commits: usize,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
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
                    state_writer: &state_writer,
                    transaction_writer: &transaction_writer,
                },
                sql_writer,
                upload,
                inline_watermarks,
            )
            .await;
        }

        if rx_closed && commits.is_empty() {
            flush_and_complete_published_uploads(
                context.child("watermarks"),
                &mut pending_completions,
                &commit_client,
                &state_writer,
                &transaction_writer,
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
                                state_writer: &state_writer,
                                transaction_writer: &transaction_writer,
                            },
                            sql_writer,
                            upload,
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
                    &commit_client,
                    &state_writer,
                    &transaction_writer,
                )
                .await;
            }
        }
    }
    debug!("indexer QMDB committer task exiting: channel closed");
}

async fn stage_and_spawn_commit<Cx, H>(
    context: Cx,
    pipeline: CommitPipeline<'_, H>,
    sql_writer: BatchWriter,
    upload: PreparedQmdbUpload,
    inline_watermarks: bool,
) -> BatchWriter
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let prepared = prepare_commit_batch_blocking(
        context.child("stage_commit_batch"),
        sql_writer,
        pipeline.state_writer.clone(),
        pipeline.transaction_writer.clone(),
        upload,
        inline_watermarks,
    )
    .await
    .expect("prepared QMDB commit batch must stage");
    let sql_writer = prepared.0;
    let batch = prepared.1;
    spawn_commit(
        pipeline.commits,
        context.child("store_commit"),
        pipeline.commit_client.clone(),
        batch,
    );
    sql_writer
}

async fn prepare_commit_batch_blocking<Cx, H>(
    context: Cx,
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    upload: PreparedQmdbUpload,
    inline_watermarks: bool,
) -> Result<(BatchWriter, QmdbCommitBatch), PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let metadata = StagedQmdbUploadMetadata {
        height: upload.height,
        completion: upload.completion,
    };
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
    };
    Ok((sql_writer, batch))
}

struct StagedQmdbUploadMetadata {
    height: u64,
    completion: oneshot::Sender<()>,
}

struct SqlUpload {
    sql_rows: Vec<super::SqlRow>,
}

async fn stage_commit_batch_blocking<Cx, H>(
    context: Cx,
    stage: CommitBatchStage<H>,
) -> Result<StagedCommitBatch, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
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
    commit: QmdbCommitBatch,
) where
    Cx: Spawner,
{
    commits.spawn(async move {
        let store_seq = commit_required_batch_blocking(
            context.child("finalized_upload"),
            commit_client,
            commit.store_batch,
        )
        .await;
        debug!(
            store_sequence = store_seq,
            "indexer persisted finalized index batch"
        );
        CommittedQmdbBatch {
            upload: commit.upload,
            sql: commit.sql,
            rows: commit.rows,
            state_watermark: commit.state_watermark,
            transaction_watermark: commit.transaction_watermark,
            store_seq,
        }
    });
}

async fn mark_committed_batch<H>(
    batch: CommittedQmdbBatch,
    sql_writer: &mut BatchWriter,
    state_writer: &StateWriter<H>,
    transaction_writer: &TransactionWriter<H>,
) -> PendingUploadCompletion
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
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
        state_latest,
        transaction_latest,
        completion: upload.completion,
    }
}

async fn flush_qmdb_watermarks<Cx, H>(
    context: Cx,
    commit_client: &StoreClient,
    state_writer: &StateWriter<H>,
    transaction_writer: &TransactionWriter<H>,
) -> Option<u64>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
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

    let seq = commit_required_batch_blocking(
        context.child("watermark_store_commit"),
        commit_client.clone(),
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

async fn flush_and_complete_published_uploads<Cx, H>(
    context: Cx,
    pending: &mut VecDeque<PendingUploadCompletion>,
    commit_client: &StoreClient,
    state_writer: &StateWriter<H>,
    transaction_writer: &TransactionWriter<H>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let already_published =
        complete_published_uploads(pending, state_writer, transaction_writer).await;
    if pending.is_empty() {
        if already_published > 0 {
            debug!(
                completed_uploads = already_published,
                "indexer completed finalized uploads with in-band QMDB watermarks"
            );
        }
        return;
    }

    let watermark_seq =
        flush_qmdb_watermarks(context, commit_client, state_writer, transaction_writer).await;
    let completed = complete_published_uploads(pending, state_writer, transaction_writer).await;
    if completed > 0 || watermark_seq.is_some() {
        debug!(
            completed_uploads = completed,
            watermark_sequence = watermark_seq,
            pending_uploads = pending.len(),
            "indexer published QMDB watermark"
        );
    }
}

async fn complete_published_uploads<H>(
    pending: &mut VecDeque<PendingUploadCompletion>,
    state_writer: &StateWriter<H>,
    transaction_writer: &TransactionWriter<H>,
) -> usize
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
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

/// Store namespace prefix for account-state QMDB rows.
pub fn state_qmdb_prefix() -> Result<StoreKeyPrefix, exoware_sdk::StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, STATE_QMDB_PREFIX_VALUE)
}

/// Store namespace prefix for transaction-history QMDB rows.
pub fn transactions_qmdb_prefix() -> Result<StoreKeyPrefix, exoware_sdk::StoreKeyPrefixError> {
    StoreKeyPrefix::new(STORE_PREFIX_RESERVED_BITS, TRANSACTIONS_QMDB_PREFIX_VALUE)
}

/// Clone `client` into the account-state QMDB namespace.
pub fn state_qmdb_client(client: &StoreClient) -> Result<StoreClient, PublishError> {
    Ok(client.with_key_prefix(state_qmdb_prefix()?))
}

/// Clone `client` into the transaction-history QMDB namespace.
pub fn transactions_qmdb_client(client: &StoreClient) -> Result<StoreClient, PublishError> {
    Ok(client.with_key_prefix(transactions_qmdb_prefix()?))
}

async fn recover_state_writer_state<H>(
    client: StoreClient,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let reader =
        UnorderedClient::<QmdbFamily, H, AccountKey, AccountValue, StateEncoding>::from_client(
            client,
            (),
        );
    recover_writer_state::<H, _, _>(
        reader.writer_location_watermark().await?,
        |watermark, max| {
            let reader = reader.clone();
            async move {
                reader
                    .operation_range_checkpoint(watermark, Location::new(0), max)
                    .await
            }
        },
    )
    .await
}

async fn recover_transaction_writer_state<H>(
    client: StoreClient,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let reader =
        KeylessClient::<QmdbFamily, H, H::Digest, TransactionEncoding<H>>::from_client(client, ());
    recover_writer_state::<H, _, _>(
        reader.writer_location_watermark().await?,
        |watermark, max| {
            let reader = reader.clone();
            async move {
                reader
                    .operation_range_checkpoint(watermark, Location::new(0), max)
                    .await
            }
        },
    )
    .await
}

async fn recover_writer_state<H, Fetch, Fut>(
    watermark: Option<Location<QmdbFamily>>,
    fetch: Fetch,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher,
    Fetch: FnOnce(Location<QmdbFamily>, u32) -> Fut,
    Fut: std::future::Future<
            Output = Result<
                exoware_qmdb::OperationRangeCheckpoint<H::Digest, QmdbFamily>,
                QmdbError,
            >,
        >,
{
    let Some(watermark) = watermark else {
        return Ok(WriterState::empty());
    };
    let locations = watermark
        .as_u64()
        .checked_add(1)
        .ok_or(PublishError::CheckpointTooLarge {
            locations: u64::MAX,
        })?;
    let max =
        u32::try_from(locations).map_err(|_| PublishError::CheckpointTooLarge { locations })?;
    let checkpoint = fetch(watermark, max).await?;
    Ok(WriterState::from_checkpoint::<H>(&checkpoint)?)
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
    state_db: &StateDatabase<E, H, commonware_storage::translator::EightCap, S>,
) -> Result<Vec<StateOperation>, PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let state = state_db.read().await;
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
            nonce: account_value_nonce(account),
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

fn account_value_nonce(account: &AccountValue) -> u64 {
    let bytes: [u8; 8] = account.as_ref()[8..16]
        .try_into()
        .expect("account nonce has fixed width");
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
    E: Storage + Clock + Metrics,
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

async fn commit_with_retry(client: &StoreClient, batch: &StoreWriteBatch) -> u64 {
    let mut attempt = 0u32;
    loop {
        match batch.commit(client).await {
            Ok(seq) => return seq,
            Err(error) => {
                attempt = attempt.saturating_add(1);
                warn!(
                    ?error,
                    attempt,
                    rows = batch.len(),
                    "indexer finalized index upload failed, retrying"
                );
                sleep(retry_backoff(attempt)).await;
            }
        }
    }
}

async fn commit_required_batch(client: StoreClient, batch: StoreWriteBatch) -> u64 {
    assert!(
        !batch.is_empty(),
        "QMDB component batches must contain at least one row"
    );
    commit_with_retry(&client, &batch).await
}

async fn commit_required_batch_blocking<Cx>(
    context: Cx,
    client: StoreClient,
    batch: StoreWriteBatch,
) -> u64
where
    Cx: Spawner,
{
    context
        .shared(true)
        .spawn(move |_| async move { commit_required_batch(client, batch).await })
        .await
        .expect("QMDB Store commit task exited")
}

fn retry_backoff(attempt: u32) -> Duration {
    const INITIAL: Duration = Duration::from_millis(100);
    const MAX: Duration = Duration::from_secs(2);
    let factor = 1u32 << attempt.min(5);
    INITIAL.saturating_mul(factor).min(MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_schema::{BLOCK_META_TABLE, TX_META_TABLE};
    use bytes::Bytes;
    use commonware_consensus::{
        simplex::types::Context as SimplexContext,
        types::{Round, View, coding::Commitment},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Signer as _, ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
    use commonware_parallel::Sequential;
    use commonware_runtime::{BufferPooler, Runner as _, Supervisor, buffer::paged::CacheRef};
    use commonware_storage::{
        journal::contiguous::fixed::Config as FixedJournalConfig,
        merkle::{compact::Config as CompactMerkleConfig, full::Config as MmrConfig},
        qmdb::{any::FixedConfig, keyless::fixed as keyless_fixed},
        translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};
    use constantinople_primitives::{
        Block, Header, Sealable, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
        TransactionPublicKey,
    };
    use exoware_sdk::RetryConfig;
    use exoware_sql::CellValue;
    use std::num::NonZeroU64 as StdNonZeroU64;

    const TEST_ITEMS_PER_BLOB: std::num::NonZero<u64> = NZU64!(1024);
    const TEST_WRITE_BUFFER: std::num::NonZero<usize> = NZUsize!(1024 * 1024);
    const TEST_PAGE_CACHE_PAGE_SIZE: std::num::NonZeroU16 = NZU16!(4096);
    const TEST_PAGE_CACHE_CAPACITY: std::num::NonZero<usize> = NZUsize!(1024);

    #[test]
    fn qmdb_operation_logs_use_distinct_store_namespaces() {
        let state = state_qmdb_prefix().expect("state prefix");
        let transactions = transactions_qmdb_prefix().expect("transaction prefix");

        assert_eq!(state.reserved_bits(), STORE_PREFIX_RESERVED_BITS);
        assert_eq!(state.prefix(), STATE_QMDB_PREFIX_VALUE);
        assert_eq!(transactions.reserved_bits(), STORE_PREFIX_RESERVED_BITS);
        assert_eq!(transactions.prefix(), TRANSACTIONS_QMDB_PREFIX_VALUE);
        assert_ne!(state.prefix(), transactions.prefix());
    }

    #[test]
    fn sql_rows_stage_into_store_batch() {
        let client = StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
        let mut batch = StoreWriteBatch::new();

        let schema = build_meta_schema(client).expect("schema");
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
                    CellValue::UInt64(1),
                    CellValue::UInt64(0),
                    CellValue::FixedBinary(vec![3u8; 32]),
                    CellValue::FixedBinary(vec![4u8; 32]),
                    CellValue::FixedBinary(vec![5u8; 32]),
                    CellValue::UInt64(7),
                    CellValue::UInt64(8),
                    CellValue::UInt64(1),
                    CellValue::Utf8("010203".to_string()),
                ],
            },
        ];
        let prepared = prepare_sql_rows(&mut writer, rows.iter())
            .expect("sql rows prepare")
            .expect("sql rows are present");
        writer
            .stage_flush(&prepared, &mut batch)
            .expect("sql rows stage");

        // One block_meta row and tx_meta base + digest index rows.
        assert_eq!(batch.len(), 3);
        assert_eq!(prepared.entry_count(), 3);
    }

    #[test]
    fn inline_watermark_publishes_single_upload() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let client =
                StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
            let state_writer = Arc::new(StateWriter::<Sha256>::empty(
                state_qmdb_client(&client).expect("state client"),
            ));
            let transaction_writer = Arc::new(TransactionWriter::<Sha256>::empty(
                transactions_qmdb_client(&client).expect("transaction client"),
            ));
            let schema = build_meta_schema(client.clone()).expect("schema");
            let sql_writer = schema.batch_writer();

            let seed = 1u8;
            let key = AccountKey::from_bytes(Bytes::from(vec![seed; AccountKey::SIZE])).unwrap();
            let state_ops = [
                StateOperation::Update(UnorderedUpdate(
                    key,
                    encode_account(Account {
                        balance: u64::from(seed),
                        nonce: 0,
                    }),
                )),
                StateOperation::CommitFloor(None, Location::new(0)),
            ];
            let transaction_ops = [
                TransactionOperation::<Sha256>::Append(Sha256::hash(&[seed])),
                TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
            ];
            let (completion, _rx) = oneshot::channel();
            let state = state_writer
                .prepare_upload(&state_ops)
                .await
                .expect("state upload");
            let transactions = transaction_writer
                .prepare_upload(&transaction_ops)
                .await
                .expect("transaction upload");
            let expected_state_watermark = Some(state.latest_location());
            let expected_transaction_watermark = Some(transactions.latest_location());
            let upload = PreparedQmdbUpload {
                height: u64::from(seed),
                sql_rows: Vec::new(),
                state,
                transactions,
                completion,
            };

            let (_sql_writer, batch) = prepare_commit_batch_blocking(
                context,
                sql_writer,
                state_writer,
                transaction_writer,
                upload,
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
        });
    }

    #[test]
    fn grouped_watermark_flush_completes_multiple_uploads() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let state_writer =
                StateWriter::<Sha256>::empty(state_qmdb_client(&client).expect("state client"));
            let transaction_writer = TransactionWriter::<Sha256>::empty(
                transactions_qmdb_client(&client).expect("transaction client"),
            );

            let mut first_state = state_writer
                .prepare_upload(&state_ops(1))
                .await
                .expect("first state upload");
            let first_state_latest = first_state.latest_location();
            let mut first_transactions = transaction_writer
                .prepare_upload(&transaction_ops(1))
                .await
                .expect("first transaction upload");
            let first_transaction_latest = first_transactions.latest_location();
            let mut second_state = state_writer
                .prepare_upload(&state_ops(2))
                .await
                .expect("second state upload");
            let second_state_latest = second_state.latest_location();
            let mut second_transactions = transaction_writer
                .prepare_upload(&transaction_ops(2))
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
            let mut pending = VecDeque::from([
                PendingUploadCompletion {
                    state_latest: first_state_latest,
                    transaction_latest: first_transaction_latest,
                    completion: first_completion,
                },
                PendingUploadCompletion {
                    state_latest: second_state_latest,
                    transaction_latest: second_transaction_latest,
                    completion: second_completion,
                },
            ]);

            assert_eq!(
                complete_published_uploads(&mut pending, &state_writer, &transaction_writer).await,
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
                &client,
                &state_writer,
                &transaction_writer,
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
            handle.abort();
        });
    }

    #[test]
    fn out_of_order_store_commits_do_not_publish_past_prefix_holes() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let state_writer = Arc::new(StateWriter::<Sha256>::empty(
                state_qmdb_client(&client).expect("state client"),
            ));
            let transaction_writer = Arc::new(TransactionWriter::<Sha256>::empty(
                transactions_qmdb_client(&client).expect("transaction client"),
            ));
            let schema = build_meta_schema(client.clone()).expect("schema");
            let mut sql_writer = schema.batch_writer();

            let (first_completion, mut first_rx) = oneshot::channel();
            let first_upload = PreparedQmdbUpload {
                height: 1,
                sql_rows: Vec::new(),
                state: state_writer
                    .prepare_upload(&state_ops(1))
                    .await
                    .expect("first state upload"),
                transactions: transaction_writer
                    .prepare_upload(&transaction_ops(1))
                    .await
                    .expect("first transaction upload"),
                completion: first_completion,
            };
            let (next_sql_writer, first_batch) = prepare_commit_batch_blocking(
                context.child("first"),
                sql_writer,
                state_writer.clone(),
                transaction_writer.clone(),
                first_upload,
                true,
            )
            .await
            .expect("first batch stages");
            sql_writer = next_sql_writer;

            let (second_completion, mut second_rx) = oneshot::channel();
            let second_upload = PreparedQmdbUpload {
                height: 2,
                sql_rows: Vec::new(),
                state: state_writer
                    .prepare_upload(&state_ops(2))
                    .await
                    .expect("second state upload"),
                transactions: transaction_writer
                    .prepare_upload(&transaction_ops(2))
                    .await
                    .expect("second transaction upload"),
                completion: second_completion,
            };
            let (next_sql_writer, second_batch) = prepare_commit_batch_blocking(
                context.child("second"),
                sql_writer,
                state_writer.clone(),
                transaction_writer.clone(),
                second_upload,
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
                complete_published_uploads(&mut pending, &state_writer, &transaction_writer).await,
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
                &client,
                &state_writer,
                &transaction_writer,
            )
            .await;

            assert!(pending.is_empty());
            first_rx.try_recv().expect("first upload completed");
            second_rx.try_recv().expect("second upload completed");
            handle.abort();
        });
    }

    #[test]
    fn queued_upload_completes_through_publisher() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect(
                context.child("qmdb_publisher"),
                &url,
                2,
            )
            .await
            .expect("publisher connects");

            let completion = publisher
                .enqueue_queued_finalized(test_queued_upload())
                .await
                .expect("queued upload accepted");
            assert!(completion.wait().await);

            publisher.shutdown().await;
            handle.abort();
        });
    }

    #[test]
    fn queued_upload_roots_match_application_roots() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let client = StoreClient::new(&url);
            let publisher = Publisher::<Sha256, ed25519::PublicKey>::connect(
                context.child("qmdb_publisher"),
                &url,
                2,
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
                            nonce: 0,
                        },
                    ),
                    (
                        account_key(2),
                        Account {
                            balance: 20,
                            nonce: 0,
                        },
                    ),
                ],
                vec![signed_transaction(1, 0), signed_transaction(2, 0)],
            )
            .await;
            publish_block_and_assert_roots(
                context.child("first"),
                &publisher,
                &client,
                &databases,
                &first,
            )
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
                            nonce: 1,
                        },
                    ),
                    (
                        account_key(3),
                        Account {
                            balance: 30,
                            nonce: 0,
                        },
                    ),
                ],
                vec![signed_transaction(3, 1)],
            )
            .await;
            publish_block_and_assert_roots(
                context.child("second"),
                &publisher,
                &client,
                &databases,
                &second,
            )
            .await;
            assert_transaction_append_locations_match_block(&client, &second).await;

            publisher.shutdown().await;
            handle.abort();
        });
    }

    #[test]
    fn qmdb_publisher_shutdown_joins_background_workers() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let publisher = Publisher::<
                commonware_cryptography::sha256::Sha256,
                commonware_cryptography::ed25519::PublicKey,
            >::connect(context.child("qmdb_publisher"), &url, 1)
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
        E: BufferPooler + Clock + Metrics + Storage + Supervisor + Send + Sync + 'static,
    {
        let config = (
            test_state_db_config(&context, prefix),
            test_transaction_db_config(prefix),
        );
        Databases::init(context, config).await
    }

    fn test_state_db_config<E>(context: &E, prefix: &str) -> FixedConfig<EightCap, Sequential>
    where
        E: BufferPooler + Supervisor,
    {
        let page_cache = CacheRef::from_pooler(
            &context.child("state_page_cache"),
            TEST_PAGE_CACHE_PAGE_SIZE,
            TEST_PAGE_CACHE_CAPACITY,
        );

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
                page_cache,
                write_buffer: TEST_WRITE_BUFFER,
            },
            translator: EightCap,
        }
    }

    fn test_transaction_db_config(prefix: &str) -> keyless_fixed::CompactConfig<Sequential> {
        keyless_fixed::CompactConfig {
            merkle: CompactMerkleConfig {
                partition: format!("{prefix}-transactions-merkle"),
                strategy: Sequential,
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
        E: Storage + Clock + Metrics + Send + Sync + 'static,
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
            non_empty_range!(*state.bounds().inactivity_floor, state.bounds().total_size);
        let transactions_root = transaction_history.root();
        let transactions_range = non_empty_range!(
            *transaction_history.bounds().inactivity_floor,
            transaction_history.bounds().total_size
        );
        databases.finalize((state, transaction_history)).await;

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

    async fn publish_block_and_assert_roots<E, Cx>(
        context: Cx,
        publisher: &Publisher<Sha256, ed25519::PublicKey>,
        client: &StoreClient,
        databases: &Databases<E, Sha256, EightCap, Sequential>,
        block: &EngineBlock<Sha256, ed25519::PublicKey>,
    ) where
        Cx: Spawner,
        E: Storage + Clock + Metrics + Send + Sync + 'static,
    {
        let (state_next, transaction_next) = publisher.next_locations().await;
        let upload = Publisher::build_queued_finalized_upload_with_context(
            context,
            state_next,
            transaction_next,
            block,
            databases,
        )
        .await
        .expect("queued upload builds");
        let state_start = upload.state_start();
        let transaction_start = upload.transaction_start();
        let completion = publisher
            .enqueue_queued_finalized(upload)
            .await
            .expect("queued upload accepted");
        assert!(completion.wait().await, "queued upload completed");

        let state_reader = UnorderedClient::<
            QmdbFamily,
            Sha256,
            AccountKey,
            AccountValue,
            StateEncoding,
        >::from_client(
            state_qmdb_client(client).expect("state client"), ()
        );
        let transaction_reader = KeylessClient::<
            QmdbFamily,
            Sha256,
            Sha256Digest,
            TransactionEncoding<Sha256>,
        >::from_client(
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
        let reader = KeylessClient::<
            QmdbFamily,
            Sha256,
            Sha256Digest,
            TransactionEncoding<Sha256>,
        >::from_client(
            transactions_qmdb_client(client).expect("transaction client"),
            (),
        );
        let rows = encode_indexed_block_rows_at(block, 0);
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
        AccountKey::from_bytes(Bytes::from(vec![seed as u8; AccountKey::SIZE])).unwrap()
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
        }
    }

    fn state_ops(seed: u8) -> Vec<StateOperation> {
        let key = AccountKey::from_bytes(Bytes::from(vec![seed; AccountKey::SIZE])).unwrap();
        vec![
            StateOperation::Update(UnorderedUpdate(
                key,
                encode_account(Account {
                    balance: u64::from(seed),
                    nonce: 0,
                }),
            )),
            StateOperation::CommitFloor(None, Location::new(0)),
        ]
    }

    fn transaction_ops(seed: u8) -> Vec<TransactionOperation<Sha256>> {
        vec![
            TransactionOperation::<Sha256>::Append(Sha256::hash(&[seed])),
            TransactionOperation::<Sha256>::Commit(None, Location::new(0)),
        ]
    }

    fn test_queued_upload() -> QueuedFinalizedUpload<Sha256, ed25519::PublicKey> {
        let leader = ed25519::PrivateKey::from_seed(7).public_key();
        let header = Header {
            context: SimplexContext {
                round: Round::zero(),
                leader,
                parent: (View::zero(), Commitment::EMPTY),
            },
            parent: Sha256Digest::EMPTY,
            height: 1,
            timestamp: 0,
            state_root: Sha256Digest::EMPTY,
            state_range: non_empty_range!(0, 2),
            transactions_root: Sha256Digest::EMPTY,
            transactions_range: non_empty_range!(0, 2),
        };
        let block = Block::new(header, Vec::<SignedTransaction<Sha256>>::new())
            .seal(&mut Sha256::default());
        let account_key = AccountKey::from_bytes(Bytes::from(vec![1u8; AccountKey::SIZE])).unwrap();
        let state_delta = vec![
            StateOperation::Update(UnorderedUpdate(
                account_key,
                encode_account(Account {
                    balance: 1,
                    nonce: 0,
                }),
            )),
            StateOperation::CommitFloor(None, Location::new(0)),
        ];

        QueuedFinalizedUpload {
            block,
            finalized_ts_micros: 1_000,
            state_start: 0,
            transaction_start: 0,
            state_delta,
        }
    }
}
