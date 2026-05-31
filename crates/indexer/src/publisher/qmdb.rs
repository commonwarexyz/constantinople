//! Combined publisher for finalized raw KV, SQL metadata, and QMDB rows.

use super::block::{IndexedBlockRows, encode_indexed_block_rows, encode_indexed_block_rows_at};
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
    collections::BTreeMap,
    marker::PhantomData,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{Mutex, Semaphore, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::sleep,
};
use tracing::{debug, warn};

/// Store prefix reserved for QMDB account-state rows.
pub const STATE_QMDB_PREFIX_VALUE: u16 = 0x8;
/// Store prefix reserved for QMDB transaction-hash rows.
pub const TRANSACTIONS_QMDB_PREFIX_VALUE: u16 = 0x9;
/// Keep each QMDB commit group comfortably below exoware's 256 MiB Connect limit.
const MAX_COMMIT_STORE_BYTES: usize = 192 * 1024 * 1024;
const ESTIMATED_SQL_STORE_ROW_BYTES: usize = 256;
const ESTIMATED_QMDB_STORE_ROW_BYTES: usize = 256;
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
#[derive(Clone)]
pub struct QueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    block: EngineBlock<H, P>,
    finalized_ts_micros: i64,
    state_start: u64,
    state_end: u64,
    transaction_start: u64,
    transaction_end: u64,
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

    pub const fn state_end(&self) -> u64 {
        self.state_end
    }

    pub const fn transaction_start(&self) -> u64 {
        self.transaction_start
    }

    pub const fn transaction_end(&self) -> u64 {
        self.transaction_end
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
            + self.state_end.encode_size()
            + self.transaction_start.encode_size()
            + self.transaction_end.encode_size()
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
        self.state_end.write(buf);
        self.transaction_start.write(buf);
        self.transaction_end.write(buf);
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
            state_end: u64::read(buf)?,
            transaction_start: u64::read(buf)?,
            transaction_end: u64::read(buf)?,
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
    next_upload_order: AtomicU64,
    prepare_tx: Option<mpsc::Sender<PendingQmdbUpload<H, P>>>,
    prepare_join: Option<JoinHandle<()>>,
    commit_join: Option<JoinHandle<()>>,
    _marker: PhantomData<P>,
}

enum PendingQmdbUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    Prepared(PendingPreparedQmdbUpload<H>),
    Queued(PendingQueuedFinalizedUpload<H, P>),
}

impl<H, P> PendingQmdbUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    const fn height(&self) -> u64 {
        match self {
            Self::Prepared(upload) => upload.height,
            Self::Queued(upload) => upload.height,
        }
    }
}

struct PendingPreparedQmdbUpload<H>
where
    H: Hasher,
{
    order: u64,
    height: u64,
    block_rows: IndexedBlockRows<H::Digest>,
    state_delta: Vec<StateOperation>,
    account_rows: Vec<(exoware_sdk::keys::Key, bytes::Bytes)>,
    transaction_ops: Vec<TransactionOperation<H>>,
    completion: oneshot::Sender<()>,
}

struct PendingQueuedFinalizedUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    order: u64,
    height: u64,
    upload: QueuedFinalizedUpload<H, P>,
    completion: oneshot::Sender<()>,
}

struct PreparedQmdbUpload {
    order: u64,
    height: u64,
    raw_rows: Vec<(exoware_sdk::keys::Key, bytes::Bytes)>,
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
    uploads: Vec<StagedQmdbUpload>,
    sql: Option<PreparedBatch>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_batch: StoreWriteBatch,
    first_height: u64,
    last_height: u64,
    rows: usize,
}

struct CommitBatchStage<H>
where
    H: Hasher,
{
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    raw_sql_uploads: Vec<RawSqlUpload>,
    state_uploads: Vec<PreparedUpload<QmdbFamily>>,
    transaction_uploads: Vec<PreparedUpload<QmdbFamily>>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
}

struct StagedCommitBatch {
    sql_writer: BatchWriter,
    sql: Option<PreparedBatch>,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_batch: StoreWriteBatch,
    state_uploads: Vec<PreparedUpload<QmdbFamily>>,
    transaction_uploads: Vec<PreparedUpload<QmdbFamily>>,
}

struct CommittedQmdbBatch {
    uploads: Vec<StagedQmdbUpload>,
    sql: Option<PreparedBatch>,
    first_height: u64,
    last_height: u64,
    count: usize,
    rows: usize,
    state_watermark: Option<PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<PreparedWatermark<QmdbFamily>>,
    store_seq: u64,
}

impl PreparedQmdbUpload {
    fn estimated_store_bytes(&self) -> usize {
        self.raw_rows
            .iter()
            .map(|(key, value)| estimated_store_entry_bytes(key, value.as_ref()))
            .sum::<usize>()
            .saturating_add(
                self.sql_rows
                    .len()
                    .saturating_mul(ESTIMATED_SQL_STORE_ROW_BYTES),
            )
            .saturating_add(
                self.state
                    .row_count()
                    .saturating_mul(ESTIMATED_QMDB_STORE_ROW_BYTES),
            )
            .saturating_add(
                self.transactions
                    .row_count()
                    .saturating_mul(ESTIMATED_QMDB_STORE_ROW_BYTES),
            )
    }
}

impl<H, P> Publisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    /// Construct writers over the two reserved QMDB Store prefixes.
    pub async fn connect<Cx>(
        context: Cx,
        store_url: &str,
        buffer: usize,
    ) -> Result<Self, PublishError>
    where
        Cx: Spawner,
    {
        let commit_client = super::standard_store_client(store_url);
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
        let prepare_limit = Arc::new(Semaphore::new(buffer));
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
            prepare_limit,
        ));

        Ok(Self {
            state_next_location: Mutex::new(state_next_location),
            transaction_next_location: Mutex::new(transaction_next_location),
            next_upload_order: AtomicU64::new(0),
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

    /// Queue all finalized-block index rows for upload.
    pub async fn upload_finalized<E, S>(
        &self,
        block: &EngineBlock<H, P>,
        databases: &Databases<E, H, commonware_storage::translator::EightCap, S>,
    ) -> Result<(), PublishError>
    where
        E: Storage + Clock + Metrics,
        S: Strategy + Send + Sync + 'static,
    {
        let _ = self.enqueue_finalized(block, databases).await?;
        Ok(())
    }

    /// Queue all finalized-block index rows and return a completion signal.
    pub async fn enqueue_finalized<E, S>(
        &self,
        block: &EngineBlock<H, P>,
        databases: &Databases<E, H, commonware_storage::translator::EightCap, S>,
    ) -> Result<UploadCompletion, PublishError>
    where
        E: Storage + Clock + Metrics,
        S: Strategy + Send + Sync + 'static,
    {
        let mut state_next = self.state_next_location.lock().await;
        let mut transaction_next = self.transaction_next_location.lock().await;

        let state_writer_next = *state_next;
        let state_end = block.header.state_range.end();
        validate_writer_range(state_writer_next, state_end, block.header.height)?;

        let transaction_writer_next = *transaction_next;
        let transaction_end = transaction_upload_end(transaction_writer_next, block)?;

        let block_rows = encode_indexed_block_rows(block);
        let state =
            build_state_upload::<E, H, P, S>(state_writer_next, block, &databases.0).await?;
        let completion = self
            .enqueue_ordered_finalized(block, block_rows, state, transaction_writer_next)
            .await?;
        *state_next = state_end;
        *transaction_next = transaction_end;
        Ok(completion)
    }

    /// Queue all finalized-block index rows and return a completion signal.
    ///
    /// Row encoding is offloaded to the supplied context.
    pub async fn enqueue_finalized_with_context<Cx, E, S>(
        &self,
        context: Cx,
        block: &EngineBlock<H, P>,
        databases: &Databases<E, H, commonware_storage::translator::EightCap, S>,
    ) -> Result<UploadCompletion, PublishError>
    where
        Cx: Spawner,
        E: Storage + Clock + Metrics,
        S: Strategy + Send + Sync + 'static,
    {
        let mut state_next = self.state_next_location.lock().await;
        let mut transaction_next = self.transaction_next_location.lock().await;

        let state_writer_next = *state_next;
        let state_end = block.header.state_range.end();
        validate_writer_range(state_writer_next, state_end, block.header.height)?;

        let transaction_writer_next = *transaction_next;
        let transaction_end = transaction_upload_end(transaction_writer_next, block)?;

        let rows_block = block.clone();
        let rows = context
            .child("encode_rows")
            .shared(true)
            .spawn(move |_| async move { encode_indexed_block_rows(&rows_block) });
        let state = build_state_upload::<E, H, P, S>(state_writer_next, block, &databases.0).await;
        let block_rows = rows.await.expect("QMDB row encoding task exited");
        let state = state?;
        let completion = self
            .enqueue_ordered_finalized(block, block_rows, state, transaction_writer_next)
            .await?;
        *state_next = state_end;
        *transaction_next = transaction_end;
        Ok(completion)
    }

    /// Capture the finalized-block upload material that must survive local pruning.
    ///
    /// This deliberately stops at the durable local payload boundary. Remote Store
    /// staging and upload are handled later by the queue consumer.
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
        let transaction_end = transaction_upload_end(transaction_writer_next, block)?;
        let block = block.clone();
        let state_block = block.clone();
        let state_db = databases.0.clone();
        let state = context
            .child("state_delta")
            .shared(true)
            .spawn(move |_| async move {
                build_state_upload::<E, H, P, S>(state_writer_next, &state_block, &state_db).await
            })
            .await
            .expect("QMDB state queue task exited")?;

        Ok(QueuedFinalizedUpload {
            block,
            finalized_ts_micros: current_time_micros(),
            state_start: state_writer_next,
            state_end,
            transaction_start: transaction_writer_next,
            transaction_end,
            state_delta: state.delta,
        })
    }

    /// Queue a previously durable finalized-block payload for remote upload.
    pub async fn enqueue_queued_finalized(
        &self,
        upload: QueuedFinalizedUpload<H, P>,
    ) -> Result<UploadCompletion, PublishError> {
        let mut state_next = self.state_next_location.lock().await;
        let mut transaction_next = self.transaction_next_location.lock().await;

        if *state_next >= upload.state_end && *transaction_next >= upload.transaction_end {
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
        let state_end = upload.state_end;
        let transaction_end = upload.transaction_end;
        let (completion, rx) = oneshot::channel();
        let prepare_tx = self
            .prepare_tx
            .as_ref()
            .expect("publisher send channel is open until shutdown");
        let order = self.next_upload_order.fetch_add(1, Ordering::Relaxed);
        prepare_tx
            .send(PendingQmdbUpload::Queued(PendingQueuedFinalizedUpload {
                order,
                height,
                upload,
                completion,
            }))
            .await
            .map_err(|_| PublishError::CommitterStopped { height })?;
        *state_next = state_end;
        *transaction_next = transaction_end;
        Ok(UploadCompletion { rx })
    }

    async fn enqueue_ordered_finalized(
        &self,
        block: &EngineBlock<H, P>,
        block_rows: IndexedBlockRows<H::Digest>,
        state: PendingStateUpload,
        transaction_writer_next: u64,
    ) -> Result<UploadCompletion, PublishError> {
        let transactions = build_transaction_upload_from_digests(
            block,
            transaction_writer_next,
            &block_rows.transaction_digests,
        )?;
        let (completion, rx) = oneshot::channel();
        let prepare_tx = self
            .prepare_tx
            .as_ref()
            .expect("publisher send channel is open until shutdown");
        let order = self.next_upload_order.fetch_add(1, Ordering::Relaxed);
        prepare_tx
            .send(PendingQmdbUpload::Prepared(PendingPreparedQmdbUpload {
                order,
                height: block.header.height,
                block_rows,
                state_delta: state.delta,
                account_rows: state.account_rows,
                transaction_ops: transactions.ops,
                completion,
            }))
            .await
            .map_err(|_| PublishError::CommitterStopped {
                height: block.header.height,
            })?;
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
    mut rx: mpsc::Receiver<PendingQmdbUpload<H, P>>,
    commit_tx: mpsc::Sender<PreparedQmdbUpload>,
    prepare_limit: Arc<Semaphore>,
) where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    let (done_tx, mut done_rx) = mpsc::channel(prepare_limit.available_permits().max(1));
    let mut completed = BTreeMap::new();
    let mut next_order = 0u64;
    let mut in_flight = 0usize;
    let mut rx_closed = false;

    loop {
        tokio::select! {
            maybe_upload = rx.recv(), if !rx_closed && prepare_limit.available_permits() > 0 => {
                let Some(upload) = maybe_upload else {
                    rx_closed = true;
                    continue;
                };
                let permit = prepare_limit
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("qmd prepare semaphore is never closed");
                in_flight += 1;
                let state_writer = state_writer.clone();
                let transaction_writer = transaction_writer.clone();
                let done_tx = done_tx.clone();
                let _handle = context.child("prepare_upload").shared(true).spawn(move |context| async move {
                    let _permit = permit;
                    let height = upload.height();
                    let result = prepare_qmdb_upload(context, state_writer, transaction_writer, upload)
                        .await
                        .map_err(|error| (height, error));
                    let _ = done_tx.send(result).await;
                });
            }
            maybe_result = done_rx.recv(), if in_flight > 0 => {
                in_flight -= 1;
                match maybe_result {
                    Some(Ok(upload)) => {
                        completed.insert(upload.order, upload);
                    }
                    Some(Err((height, error))) => {
                        panic!("qmd prepare worker failed at height {height}: {error}");
                    }
                    None => {
                        panic!("qmd prepare worker result channel closed with {in_flight} uploads in flight");
                    }
                }
            }
            else => break,
        }

        loop {
            let Some(upload) = completed.remove(&next_order) else {
                break;
            };
            next_order = next_order
                .checked_add(1)
                .expect("qmd upload order does not overflow");
            commit_tx
                .send(upload)
                .await
                .map_err(|upload| PublishError::CommitterStopped {
                    height: upload.0.height,
                })
                .expect("qmd committer stopped");
        }

        if rx_closed && in_flight == 0 && completed.is_empty() {
            break;
        }
    }
    debug!("indexer qmd preparer task exiting: channel closed");
}

async fn prepare_qmdb_upload<Cx, H, P>(
    context: Cx,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    upload: PendingQmdbUpload<H, P>,
) -> Result<PreparedQmdbUpload, PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
{
    let prepared = match upload {
        PendingQmdbUpload::Prepared(upload) => upload,
        PendingQmdbUpload::Queued(upload) => expand_queued_finalized_upload(upload)?,
    };
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
        order,
        height,
        upload,
        completion,
    } = upload;
    let QueuedFinalizedUpload {
        block,
        finalized_ts_micros,
        state_start,
        state_end: _,
        transaction_start,
        transaction_end: _,
        state_delta,
    } = upload;
    let block_rows = encode_indexed_block_rows_at(&block, finalized_ts_micros);
    let transaction_ops = build_transaction_upload_from_digests(
        &block,
        transaction_start,
        &block_rows.transaction_digests,
    )?
    .ops;
    let account_rows = account_rows(&state_delta, state_start);
    Ok(PendingPreparedQmdbUpload {
        order,
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
        order,
        height,
        block_rows,
        state_delta,
        account_rows,
        transaction_ops,
        completion,
    } = upload;
    let IndexedBlockRows {
        raw,
        sql,
        transaction_digests: _,
    } = block_rows;
    let mut raw = raw;
    raw.extend(account_rows);

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
        order,
        height,
        raw_rows: raw,
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
    let mut next = None;
    let mut rx_closed = false;
    let mut commits = JoinSet::new();
    loop {
        while commits.len() < max_in_flight_commits {
            let first = match next.take() {
                Some(upload) => upload,
                None if rx_closed => break,
                None => match rx.try_recv() {
                    Ok(upload) => upload,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        rx_closed = true;
                        break;
                    }
                },
            };
            let (uploads, deferred) =
                next_commit_uploads(first, &mut rx, PreparedQmdbUpload::estimated_store_bytes);
            next = deferred;
            let inline_watermarks = commits.is_empty();
            let prepared = prepare_commit_batch_blocking(
                context.child("stage_commit_batch"),
                sql_writer,
                state_writer.clone(),
                transaction_writer.clone(),
                uploads,
                inline_watermarks,
            )
            .await
            .expect("prepared QMDB commit batch must stage");
            sql_writer = prepared.0;
            let batch = prepared.1;
            spawn_commit(
                &mut commits,
                context.child("store_commit"),
                commit_client.clone(),
                batch,
            );
        }

        if rx_closed && commits.is_empty() && next.is_none() {
            break;
        }

        tokio::select! {
            maybe_upload = rx.recv(), if !rx_closed && commits.len() < max_in_flight_commits && next.is_none() => {
                match maybe_upload {
                    Some(upload) => next = Some(upload),
                    None => rx_closed = true,
                }
            }
            maybe_done = commits.join_next(), if !commits.is_empty() => {
                let batch = maybe_done
                    .expect("qmd commit set not empty")
                    .expect("qmd commit task panicked");
                mark_committed_batch(
                    &context,
                    batch,
                    &mut sql_writer,
                    &state_writer,
                    &transaction_writer,
                    &commit_client,
                )
                .await;
            }
        }
    }
    debug!("indexer qmd committer task exiting: channel closed");
}

async fn prepare_commit_batch_blocking<Cx, H>(
    context: Cx,
    sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    uploads: Vec<PreparedQmdbUpload>,
    inline_watermarks: bool,
) -> Result<(BatchWriter, QmdbCommitBatch), PublishError>
where
    Cx: Spawner,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
{
    let count = uploads.len();
    let first_height = uploads[0].height;
    let last_height = uploads[count - 1].height;
    let mut metadata = Vec::with_capacity(count);
    let mut raw_sql_uploads = Vec::with_capacity(count);
    let mut state_uploads = Vec::with_capacity(count);
    let mut transaction_uploads = Vec::with_capacity(count);
    for upload in uploads {
        metadata.push(StagedQmdbUploadMetadata {
            height: upload.height,
            completion: upload.completion,
        });
        raw_sql_uploads.push(RawSqlUpload {
            raw_rows: upload.raw_rows,
            sql_rows: upload.sql_rows,
        });
        state_uploads.push(upload.state);
        transaction_uploads.push(upload.transactions);
    }

    let (state_watermark, transaction_watermark) = if inline_watermarks {
        tokio::try_join!(
            state_writer.prepare_flush(),
            transaction_writer.prepare_flush()
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
            raw_sql_uploads,
            state_uploads,
            transaction_uploads,
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
        state_uploads,
        transaction_uploads,
    } = staged;

    let rows = store_batch.len();
    let uploads = metadata
        .into_iter()
        .zip(state_uploads)
        .zip(transaction_uploads)
        .map(|((metadata, state), transactions)| StagedQmdbUpload {
            height: metadata.height,
            state,
            transactions,
            completion: metadata.completion,
        })
        .collect();
    let batch = QmdbCommitBatch {
        first_height,
        last_height,
        rows,
        uploads,
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

struct RawSqlUpload {
    raw_rows: Vec<(exoware_sdk::keys::Key, bytes::Bytes)>,
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
                mut raw_sql_uploads,
                state_uploads,
                transaction_uploads,
                state_watermark,
                transaction_watermark,
            } = stage;
            let sql = prepare_raw_sql_upload(&mut sql_writer, &mut raw_sql_uploads)?;
            let additional_staged_row_count = estimated_additional_staged_row_count(
                sql.as_ref(),
                &state_uploads,
                &transaction_uploads,
                state_watermark.as_ref(),
                transaction_watermark.as_ref(),
            );
            let mut store_batch = StoreWriteBatch::from_physical_entry_groups(
                raw_sql_uploads.into_iter().map(|upload| upload.raw_rows),
                additional_staged_row_count,
            );
            let mut sql = sql;
            if let Some(prepared) = &mut sql {
                sql_writer.stage_flush_owned(prepared, &mut store_batch)?;
            }
            let mut state_uploads = state_uploads;
            for upload in &mut state_uploads {
                state_writer.stage_upload_owned(upload, &mut store_batch)?;
            }
            let mut transaction_uploads = transaction_uploads;
            for upload in &mut transaction_uploads {
                transaction_writer.stage_upload_owned(upload, &mut store_batch)?;
            }
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
                state_uploads,
                transaction_uploads,
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
            context.child("combined"),
            commit_client,
            commit.store_batch,
        )
        .await;
        debug!(
            store_sequence = store_seq,
            "indexer persisted finalized index batch"
        );
        CommittedQmdbBatch {
            count: commit.uploads.len(),
            uploads: commit.uploads,
            sql: commit.sql,
            first_height: commit.first_height,
            last_height: commit.last_height,
            rows: commit.rows,
            state_watermark: commit.state_watermark,
            transaction_watermark: commit.transaction_watermark,
            store_seq,
        }
    });
}

async fn mark_committed_batch<Cx, H>(
    context: &Cx,
    batch: CommittedQmdbBatch,
    sql_writer: &mut BatchWriter,
    state_writer: &StateWriter<H>,
    transaction_writer: &TransactionWriter<H>,
    commit_client: &StoreClient,
) where
    Cx: Spawner,
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
    let mut completions = Vec::with_capacity(batch.uploads.len());
    for upload in batch.uploads {
        let state_receipt = state_writer
            .mark_upload_persisted(upload.state, batch.store_seq)
            .await;
        let transaction_receipt = transaction_writer
            .mark_upload_persisted(upload.transactions, batch.store_seq)
            .await;
        debug!(
            height = upload.height,
            state_location = %state_receipt.latest_location,
            transaction_location = %transaction_receipt.latest_location,
            store_sequence = batch.store_seq,
            "indexer marked qmd upload persisted"
        );
        completions.push(upload.completion);
    }
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
    let watermark_seq =
        flush_qmdb_watermarks(context, commit_client, state_writer, transaction_writer).await;
    for completion in completions {
        let _ = completion.send(());
    }
    debug!(
        first_height = batch.first_height,
        last_height = batch.last_height,
        count = batch.count,
        rows = batch.rows,
        store_sequence = batch.store_seq,
        watermark_sequence = watermark_seq,
        "indexer uploaded finalized index batch"
    );
}

fn next_commit_uploads<T>(
    first: T,
    rx: &mut mpsc::Receiver<T>,
    estimated_store_bytes: impl Fn(&T) -> usize,
) -> (Vec<T>, Option<T>) {
    let mut bytes = estimated_store_bytes(&first);
    let mut uploads = Vec::new();
    uploads.push(first);
    while bytes < MAX_COMMIT_STORE_BYTES {
        let Ok(upload) = rx.try_recv() else {
            break;
        };
        let upload_bytes = estimated_store_bytes(&upload);
        if bytes.saturating_add(upload_bytes) > MAX_COMMIT_STORE_BYTES {
            return (uploads, Some(upload));
        }
        bytes += upload_bytes;
        uploads.push(upload);
    }
    (uploads, None)
}

const fn estimated_store_entry_bytes(key: &exoware_sdk::keys::Key, value: &[u8]) -> usize {
    const KV_ENTRY_PROTO_OVERHEAD_BYTES: usize = 16;
    key.len()
        .saturating_add(value.len())
        .saturating_add(KV_ENTRY_PROTO_OVERHEAD_BYTES)
}

async fn flush_qmdb_watermarks<Cx, H>(
    context: &Cx,
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
        .expect("qmd state watermark flush must prepare");
    let transactions = transaction_writer
        .prepare_flush()
        .await
        .expect("qmd transaction watermark flush must prepare");
    if state.is_none() && transactions.is_none() {
        return None;
    }

    let mut batch = StoreWriteBatch::new();
    if let Some(prepared) = &state {
        state_writer
            .stage_flush(prepared, &mut batch)
            .expect("qmd state watermark flush must stage");
    }
    if let Some(prepared) = &transactions {
        transaction_writer
            .stage_flush(prepared, &mut batch)
            .expect("qmd transaction watermark flush must stage");
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

fn estimated_additional_staged_row_count(
    sql: Option<&PreparedBatch>,
    state_uploads: &[PreparedUpload<QmdbFamily>],
    transaction_uploads: &[PreparedUpload<QmdbFamily>],
    state_watermark: Option<&PreparedWatermark<QmdbFamily>>,
    transaction_watermark: Option<&PreparedWatermark<QmdbFamily>>,
) -> usize {
    sql.map_or(0, PreparedBatch::entry_count)
        .saturating_add(
            state_uploads
                .iter()
                .map(PreparedUpload::row_count)
                .sum::<usize>(),
        )
        .saturating_add(
            transaction_uploads
                .iter()
                .map(PreparedUpload::row_count)
                .sum::<usize>(),
        )
        .saturating_add(usize::from(state_watermark.is_some()))
        .saturating_add(usize::from(transaction_watermark.is_some()))
}

fn prepare_raw_sql_upload(
    writer: &mut BatchWriter,
    uploads: &mut [RawSqlUpload],
) -> Result<Option<PreparedBatch>, PublishError> {
    for upload in uploads {
        for row in upload.sql_rows.drain(..) {
            writer
                .insert(row.table, row.values)
                .map_err(PublishError::SqlRow)?;
        }
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

/// Store prefix for account-state QMDB rows.
pub fn state_qmdb_prefix() -> Result<StoreKeyPrefix, exoware_sdk::StoreKeyPrefixError> {
    StoreKeyPrefix::new(crate::keys::RESERVED_BITS, STATE_QMDB_PREFIX_VALUE)
}

/// Store prefix for transaction-history QMDB rows.
pub fn transactions_qmdb_prefix() -> Result<StoreKeyPrefix, exoware_sdk::StoreKeyPrefixError> {
    StoreKeyPrefix::new(crate::keys::RESERVED_BITS, TRANSACTIONS_QMDB_PREFIX_VALUE)
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
            ((), ()),
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

struct PendingStateUpload {
    delta: Vec<StateOperation>,
    account_rows: Vec<(exoware_sdk::keys::Key, bytes::Bytes)>,
}

struct PendingTransactionUpload<H>
where
    H: Hasher,
{
    ops: Vec<TransactionOperation<H>>,
}

async fn build_state_upload<E, H, P, S>(
    writer_next: u64,
    block: &EngineBlock<H, P>,
    state_db: &StateDatabase<E, H, commonware_storage::translator::EightCap, S>,
) -> Result<PendingStateUpload, PublishError>
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
    let delta = load_state_ops::<E, H, S>(&state, writer_next, end).await?;
    let account_rows = account_rows(&delta, writer_next);
    Ok(PendingStateUpload {
        delta,
        account_rows,
    })
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

fn account_rows(
    delta: &[StateOperation],
    start_location: u64,
) -> Vec<(exoware_sdk::keys::Key, bytes::Bytes)> {
    let mut rows = Vec::new();
    for (offset, operation) in delta.iter().enumerate() {
        let AnyOperation::Update(UnorderedUpdate(key, account)) = operation else {
            continue;
        };
        let location = start_location + u64::try_from(offset).expect("state op offset fits u64");
        rows.push((
            crate::keys::account(key.as_ref()).expect("account key fits family payload"),
            encode_account_row(account, location),
        ));
    }
    rows
}

fn encode_account_row(account: &AccountValue, location: u64) -> bytes::Bytes {
    let mut row = Vec::with_capacity(Account::SIZE + u64::SIZE);
    row.extend_from_slice(account.as_ref());
    row.extend_from_slice(&location.to_be_bytes());
    bytes::Bytes::from(row)
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
    use commonware_cryptography::sha256::Sha256;
    use commonware_runtime::{Runner as _, Supervisor as _};
    use exoware_sdk::RetryConfig;
    use exoware_sql::CellValue;

    #[test]
    fn qmdb_store_prefixes_are_reserved_and_distinct() {
        let state = state_qmdb_prefix().expect("state prefix");
        let transactions = transactions_qmdb_prefix().expect("transaction prefix");

        assert_eq!(state.reserved_bits(), crate::keys::RESERVED_BITS);
        assert_eq!(state.prefix(), STATE_QMDB_PREFIX_VALUE);
        assert_eq!(transactions.prefix(), TRANSACTIONS_QMDB_PREFIX_VALUE);
        for prefix in [
            crate::keys::BLOCK.prefix(),
            crate::keys::BLOCK_BY_H.prefix(),
            crate::keys::FINALIZED.prefix(),
            crate::keys::NOTARIZED.prefix(),
            crate::keys::TX.prefix(),
            crate::keys::TX_BY_H.prefix(),
        ] {
            assert_ne!(STATE_QMDB_PREFIX_VALUE, prefix);
            assert_ne!(TRANSACTIONS_QMDB_PREFIX_VALUE, prefix);
        }
    }

    #[test]
    fn raw_and_sql_rows_stage_into_one_store_batch() {
        let client = StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
        let raw = vec![(
            crate::keys::block(&[7u8; 32]).expect("block key"),
            Bytes::from_static(b"block"),
        )];
        let mut batch = StoreWriteBatch::from_physical_entry_groups([raw], 0);

        let schema = build_meta_schema(client.clone()).expect("schema");
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
                    CellValue::UInt64(1),
                ],
            },
        ];
        let prepared = prepare_sql_rows(&mut writer, rows.iter())
            .expect("sql rows prepare")
            .expect("sql rows are present");
        writer
            .stage_flush(&prepared, &mut batch)
            .expect("sql rows stage");

        // One raw row, one block_meta row, and tx_meta base + digest index rows.
        assert_eq!(batch.len(), 4);
        assert_eq!(prepared.entry_count(), 3);
    }

    #[test]
    fn inline_watermark_publishes_coalesced_upload_tail() {
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

            let mut uploads = Vec::new();
            let mut expected_state_watermark = None;
            let mut expected_transaction_watermark = None;
            for seed in [1u8, 2] {
                let key =
                    AccountKey::from_bytes(Bytes::from(vec![seed; AccountKey::SIZE])).unwrap();
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
                expected_state_watermark = Some(state.latest_location());
                expected_transaction_watermark = Some(transactions.latest_location());
                uploads.push(PreparedQmdbUpload {
                    order: u64::from(seed),
                    height: u64::from(seed),
                    raw_rows: Vec::new(),
                    sql_rows: Vec::new(),
                    state,
                    transactions,
                    completion,
                });
            }

            let (_sql_writer, batch) = prepare_commit_batch_blocking(
                context,
                sql_writer,
                state_writer,
                transaction_writer,
                uploads,
                true,
            )
            .await
            .expect("batch stages");

            assert_eq!(batch.uploads.len(), 2);
            assert_eq!(
                batch
                    .state_watermark
                    .as_ref()
                    .map(PreparedWatermark::location),
                expected_state_watermark
            );
            assert_eq!(
                batch
                    .transaction_watermark
                    .as_ref()
                    .map(PreparedWatermark::location),
                expected_transaction_watermark
            );
        });
    }

    #[tokio::test]
    async fn qmd_coalesces_queued_uploads_without_row_limit() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(50_000usize).await.expect("send queued upload");
        tx.send(50_000).await.expect("send queued upload");
        tx.send(50_000).await.expect("send queued upload");

        let (uploads, deferred) = next_commit_uploads(50_000, &mut rx, |_| 1_000);

        assert_eq!(uploads, vec![50_000, 50_000, 50_000, 50_000]);
        assert_eq!(deferred, None);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn qmd_commit_group_allows_large_row_counts_when_bytes_fit() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(75_000usize).await.expect("send queued upload");

        let (uploads, deferred) = next_commit_uploads(100_000, &mut rx, |_| 1_000);

        assert_eq!(uploads, vec![100_000, 75_000]);
        assert_eq!(deferred, None);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn qmd_commit_group_drains_ready_uploads_until_byte_limit() {
        let queued = 24usize;
        let (tx, mut rx) = mpsc::channel(queued);
        for _ in 0..queued {
            tx.send(1_000usize).await.expect("send queued upload");
        }

        let (uploads, deferred) = next_commit_uploads(1_000, &mut rx, |_| 1_000);

        assert_eq!(uploads.len(), queued + 1);
        assert_eq!(deferred, None);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn qmd_commit_group_defers_byte_limit_overflow() {
        let (tx, mut rx) = mpsc::channel(8);
        tx.send(2usize).await.expect("send queued upload");

        let (uploads, deferred) = next_commit_uploads(1usize, &mut rx, |bytes| {
            bytes.saturating_mul(MAX_COMMIT_STORE_BYTES / 2)
        });

        assert_eq!(uploads, vec![1]);
        assert_eq!(deferred, Some(2));
    }

    #[test]
    fn qmd_publisher_shutdown_joins_background_workers() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            let dir = tempfile::TempDir::new().expect("tempdir");
            let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
                .await
                .expect("spawn simulator");
            let publisher = Publisher::<
                commonware_cryptography::sha256::Sha256,
                commonware_cryptography::ed25519::PublicKey,
            >::connect(context.child("qmd_publisher"), &url, 1)
            .await
            .expect("publisher connects");

            publisher.shutdown().await;
            handle.abort();
        });
    }
}
