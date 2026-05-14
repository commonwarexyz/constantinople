//! Combined publisher for finalized raw KV, SQL metadata, and QMDB rows.

use super::block::{IndexedBlockRows, encode_indexed_block_rows};
use crate::sql_schema::build_meta_schema;
use commonware_codec::{Codec, Encode, FixedSize};
use commonware_cryptography::{Hasher, PublicKey};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{
    merkle::{Location, mmr},
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate},
            value::FixedEncoding,
        },
        current::proof::RangeProof,
        keyless,
    },
};
use commonware_utils::sequence::FixedBytes;
use constantinople_application::consensus::{Databases, STATE_BITMAP_CHUNK_BYTES, StateDatabase};
use constantinople_engine::types::EngineBlock;
use constantinople_primitives::{Account, AccountKey};
use exoware_qmdb::{
    CurrentBoundaryState, KeylessClient, KeylessWriter, PreparedUpload, QmdbError, UnorderedClient,
    UnorderedWriter, WriterState, recover_boundary_state,
};
use exoware_sdk::{ClientError, StoreClient, StoreKeyPrefix, StoreWriteBatch};
use exoware_sql::{BatchWriter, PreparedBatch};
use std::{num::NonZeroU64, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tracing::{debug, warn};

/// Store prefix reserved for QMDB account-state rows.
pub const STATE_QMDB_PREFIX_VALUE: u16 = 0x8;
/// Store prefix reserved for QMDB transaction-hash rows.
pub const TRANSACTIONS_QMDB_PREFIX_VALUE: u16 = 0x9;

type QmdbFamily = mmr::Family;
type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateEncoding = FixedEncoding<AccountValue>;
type LocalStateOperation<P> = UnorderedOperation<QmdbFamily, AccountKey<P>, FixedEncoding<Account>>;
type StateOperation<P> = UnorderedOperation<QmdbFamily, AccountKey<P>, StateEncoding>;
type TransactionEncoding<H> = FixedEncoding<<H as Hasher>::Digest>;
type TransactionOperation<H> = keyless::Operation<QmdbFamily, TransactionEncoding<H>>;
type StateWriter<H, P> = UnorderedWriter<QmdbFamily, H, AccountKey<P>, AccountValue, StateEncoding>;
type TransactionWriter<H> =
    KeylessWriter<QmdbFamily, H, <H as Hasher>::Digest, TransactionEncoding<H>>;

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
pub struct QmdbPublisher<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    state_operations: Mutex<Vec<StateOperation<P>>>,
    state_next_location: Mutex<u64>,
    transaction_next_location: Mutex<u64>,
    prepare_tx: mpsc::Sender<PendingQmdbUpload<H, P>>,
    _prepare_join: JoinHandle<()>,
    _commit_join: JoinHandle<()>,
}

struct PendingQmdbUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    height: u64,
    block_rows: IndexedBlockRows,
    state_delta: Vec<StateOperation<P>>,
    state_boundary: CurrentBoundaryState<H::Digest, { STATE_BITMAP_CHUNK_BYTES }, QmdbFamily>,
    transaction_ops: Vec<TransactionOperation<H>>,
}

struct PreparedQmdbUpload {
    height: u64,
    raw_rows: Vec<(exoware_sdk::keys::Key, bytes::Bytes)>,
    sql_rows: Vec<super::SqlRow>,
    state: PreparedUpload<QmdbFamily>,
    transactions: PreparedUpload<QmdbFamily>,
}

impl<H, P> QmdbPublisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    /// Construct writers over the two reserved QMDB Store prefixes.
    pub async fn connect(store_url: &str, buffer: usize) -> Result<Self, PublishError> {
        let commit_client = super::standard_store_client(store_url);
        let state_client = state_qmdb_client(&commit_client)?;
        let transaction_client = transactions_qmdb_client(&commit_client)?;
        let sql_writer = build_meta_schema(commit_client.clone())
            .map_err(PublishError::SqlSchema)?
            .batch_writer();
        let state = recover_state_writer_state::<H, P>(state_client.clone()).await?;
        let transactions =
            recover_transaction_writer_state::<H>(transaction_client.clone()).await?;
        let state_writer = Arc::new(StateWriter::new(state_client, state));
        let transaction_writer = Arc::new(TransactionWriter::new(transaction_client, transactions));
        let state_next_location =
            next_writer_location(state_writer.latest_published_watermark().await);
        let transaction_next_location =
            next_writer_location(transaction_writer.latest_published_watermark().await);
        let (commit_tx, commit_rx) = mpsc::channel(buffer);
        let (prepare_tx, prepare_rx) = mpsc::channel(buffer);
        let commit_join = tokio::spawn(run_qmdb_committer(
            commit_client.clone(),
            sql_writer,
            state_writer.clone(),
            transaction_writer.clone(),
            commit_rx,
        ));
        let prepare_join = tokio::spawn(run_qmdb_preparer(
            state_writer.clone(),
            transaction_writer.clone(),
            prepare_rx,
            commit_tx,
        ));

        Ok(Self {
            state_operations: Mutex::new(Vec::new()),
            state_next_location: Mutex::new(state_next_location),
            transaction_next_location: Mutex::new(transaction_next_location),
            prepare_tx,
            _prepare_join: prepare_join,
            _commit_join: commit_join,
        })
    }

    /// Upload all finalized-block index rows in one Store commit.
    pub async fn upload_finalized<E, S>(
        &self,
        block: &EngineBlock<H, P>,
        databases: &Databases<E, H, P, commonware_storage::translator::EightCap, S>,
    ) -> Result<(), PublishError>
    where
        E: Storage + Clock + Metrics,
        S: Strategy + Send + Sync + 'static,
        AccountKey<P>: Send + Sync,
    {
        let block_rows = encode_indexed_block_rows(block);
        let state = self.build_state_upload::<E, S>(block, &databases.0).await?;
        let transactions = self.build_transaction_upload(block).await?;
        self.prepare_tx
            .send(PendingQmdbUpload {
                height: block.header.height,
                block_rows,
                state_delta: state.delta,
                state_boundary: state.boundary,
                transaction_ops: transactions.ops,
            })
            .await
            .map_err(|_| PublishError::CommitterStopped {
                height: block.header.height,
            })?;
        Ok(())
    }

    async fn build_state_upload<E, S>(
        &self,
        block: &EngineBlock<H, P>,
        state_db: &StateDatabase<E, H, P, commonware_storage::translator::EightCap, S>,
    ) -> Result<PendingStateUpload<H, P>, PublishError>
    where
        E: Storage + Clock + Metrics,
        S: Strategy + Send + Sync + 'static,
        AccountKey<P>: Send + Sync,
    {
        let mut next = self.state_next_location.lock().await;
        let pending =
            build_state_upload::<E, H, P, S>(&self.state_operations, *next, block, state_db)
                .await?;
        *next = pending.next_location;
        Ok(pending)
    }

    async fn build_transaction_upload(
        &self,
        block: &EngineBlock<H, P>,
    ) -> Result<PendingTransactionUpload<H>, PublishError> {
        let mut next = self.transaction_next_location.lock().await;
        let pending = build_transaction_upload(block, *next)?;
        *next = pending.next_location;
        Ok(pending)
    }
}

async fn run_qmdb_preparer<H, P>(
    state_writer: Arc<StateWriter<H, P>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    mut rx: mpsc::Receiver<PendingQmdbUpload<H, P>>,
    commit_tx: mpsc::Sender<PreparedQmdbUpload>,
) where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    while let Some(upload) = rx.recv().await {
        let state_writer = state_writer.clone();
        let transaction_writer = transaction_writer.clone();
        let commit_tx = commit_tx.clone();
        tokio::spawn(async move {
            let height = upload.height;
            if let Err(error) =
                prepare_and_queue_upload(state_writer, transaction_writer, commit_tx, upload).await
            {
                panic!("qmd prepare worker failed at height {height}: {error}");
            }
        });
    }
    debug!("indexer qmd preparer task exiting: channel closed");
}

async fn prepare_and_queue_upload<H, P>(
    state_writer: Arc<StateWriter<H, P>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    commit_tx: mpsc::Sender<PreparedQmdbUpload>,
    upload: PendingQmdbUpload<H, P>,
) -> Result<(), PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    let height = upload.height;
    let IndexedBlockRows { raw, sql } = upload.block_rows;
    let (state, transactions) = tokio::try_join!(
        state_writer.prepare_current_upload(&upload.state_delta, &upload.state_boundary),
        transaction_writer.prepare_upload(&upload.transaction_ops),
    )?;
    commit_tx
        .send(PreparedQmdbUpload {
            height,
            raw_rows: raw,
            sql_rows: sql,
            state,
            transactions,
        })
        .await
        .map_err(|_| PublishError::CommitterStopped { height })?;
    Ok(())
}

async fn run_qmdb_committer<H, P>(
    commit_client: StoreClient,
    mut sql_writer: BatchWriter,
    state_writer: Arc<StateWriter<H, P>>,
    transaction_writer: Arc<TransactionWriter<H>>,
    mut rx: mpsc::Receiver<PreparedQmdbUpload>,
) where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    while let Some(first) = rx.recv().await {
        let mut uploads = vec![first];
        while let Ok(upload) = rx.try_recv() {
            uploads.push(upload);
        }

        let mut batch = StoreWriteBatch::new();
        for upload in &uploads {
            stage_raw_rows(&commit_client, &mut batch, &upload.raw_rows)
                .expect("prepared raw KV rows must stage");
        }
        let sql = prepare_sql_upload(&mut sql_writer, &uploads)
            .expect("prepared SQL metadata upload must stage");
        for upload in &uploads {
            state_writer
                .stage_upload(&upload.state, &mut batch)
                .expect("prepared QMDB state upload must stage");
            transaction_writer
                .stage_upload(&upload.transactions, &mut batch)
                .expect("prepared QMDB transaction upload must stage");
        }
        if let Some(prepared) = &sql {
            sql_writer
                .stage_flush(prepared, &mut batch)
                .expect("prepared SQL metadata upload must stage");
        }

        let seq = commit_with_retry(&commit_client, &batch).await;
        let count = uploads.len();
        let first_height = uploads[0].height;
        let last_height = uploads[count - 1].height;
        let rows = batch.len();
        if let Some(prepared) = sql {
            let receipt = sql_writer.mark_flush_persisted(prepared, seq);
            debug!(
                request_id = receipt.writer_request_id,
                rows = receipt.entry_count,
                store_sequence = receipt.store_sequence_number,
                "indexer marked sql metadata upload persisted"
            );
        }
        for upload in uploads {
            let state_receipt = state_writer.mark_upload_persisted(upload.state, seq).await;
            let transaction_receipt = transaction_writer
                .mark_upload_persisted(upload.transactions, seq)
                .await;
            debug!(
                height = upload.height,
                state_location = %state_receipt.latest_location,
                transaction_location = %transaction_receipt.latest_location,
                store_sequence = seq,
                "indexer marked qmd upload persisted"
            );
        }
        debug!(
            first_height,
            last_height,
            count,
            rows,
            store_sequence = seq,
            "indexer uploaded coalesced finalized index batch"
        );
    }
    debug!("indexer qmd committer task exiting: channel closed");
}

fn stage_raw_rows(
    client: &StoreClient,
    batch: &mut StoreWriteBatch,
    rows: &[(exoware_sdk::keys::Key, bytes::Bytes)],
) -> Result<(), PublishError> {
    for (key, value) in rows {
        batch.push(client, key, value)?;
    }
    Ok(())
}

fn prepare_sql_upload(
    writer: &mut BatchWriter,
    uploads: &[PreparedQmdbUpload],
) -> Result<Option<PreparedBatch>, PublishError> {
    prepare_sql_rows(
        writer,
        uploads.iter().flat_map(|upload| upload.sql_rows.iter()),
    )
}

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

async fn recover_state_writer_state<H, P>(
    client: StoreClient,
) -> Result<WriterState<H::Digest, QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    let reader =
        UnorderedClient::<QmdbFamily, H, AccountKey<P>, AccountValue, StateEncoding>::from_client(
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

struct PendingStateUpload<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    delta: Vec<StateOperation<P>>,
    boundary: CurrentBoundaryState<H::Digest, { STATE_BITMAP_CHUNK_BYTES }, QmdbFamily>,
    next_location: u64,
}

struct PendingTransactionUpload<H>
where
    H: Hasher,
{
    ops: Vec<TransactionOperation<H>>,
    next_location: u64,
}

async fn build_state_upload<E, H, P, S>(
    operation_cache: &Mutex<Vec<StateOperation<P>>>,
    writer_next: u64,
    block: &EngineBlock<H, P>,
    state_db: &StateDatabase<E, H, P, commonware_storage::translator::EightCap, S>,
) -> Result<PendingStateUpload<H, P>, PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy + Send + Sync + 'static,
    AccountKey<P>: Send + Sync,
{
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let state = state_db.read().await;
    let historical_size = Location::<QmdbFamily>::new(block.header.state_range.end());
    let end = historical_size.as_u64();
    if writer_next > end {
        return Err(PublishError::WriterOutOfSync {
            writer_next,
            block_start: end,
        });
    }
    let mut operations = operation_cache.lock().await;
    extend_state_ops::<E, H, P, S>(&state, &mut operations, end).await?;
    let previous_operations = if writer_next == 0 {
        None
    } else {
        Some(&operations[..writer_next as usize])
    };
    let delta = operations[writer_next as usize..].to_vec();
    let boundary = state_boundary::<E, H, P, S>(&state, previous_operations, &operations).await?;
    Ok(PendingStateUpload {
        delta,
        boundary,
        next_location: end,
    })
}

async fn extend_state_ops<E, H, P, S>(
    state: &commonware_storage::qmdb::current::unordered::fixed::Db<
        QmdbFamily,
        E,
        AccountKey<P>,
        Account,
        H,
        commonware_storage::translator::EightCap,
        { STATE_BITMAP_CHUNK_BYTES },
        S,
    >,
    operations: &mut Vec<StateOperation<P>>,
    end: u64,
) -> Result<(), PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let start = u64::try_from(operations.len()).expect("state operation cache length fits u64");
    if start > end {
        return Err(PublishError::WriterOutOfSync {
            writer_next: start,
            block_start: end,
        });
    }
    if start == end {
        return Ok(());
    }

    operations.extend(load_state_ops::<E, H, P, S>(state, start, end).await?);
    Ok(())
}

async fn load_state_ops<E, H, P, S>(
    state: &commonware_storage::qmdb::current::unordered::fixed::Db<
        QmdbFamily,
        E,
        AccountKey<P>,
        Account,
        H,
        commonware_storage::translator::EightCap,
        { STATE_BITMAP_CHUNK_BYTES },
        S,
    >,
    start: u64,
    end: u64,
) -> Result<Vec<StateOperation<P>>, PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let count = end
        .checked_sub(start)
        .and_then(NonZeroU64::new)
        .ok_or(QmdbError::EmptyBatch)?;
    let (_, operations) = state
        .ops_historical_proof(Location::new(end), Location::new(start), count)
        .await
        .map_err(|err| QmdbError::CorruptData(format!("local state op proof: {err}")))?;
    Ok(operations
        .into_iter()
        .map(encode_account_operation)
        .collect())
}

fn encode_account_operation<P>(operation: LocalStateOperation<P>) -> StateOperation<P>
where
    P: PublicKey,
{
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

async fn state_boundary<E, H, P, S>(
    state: &commonware_storage::qmdb::current::unordered::fixed::Db<
        QmdbFamily,
        E,
        AccountKey<P>,
        Account,
        H,
        commonware_storage::translator::EightCap,
        { STATE_BITMAP_CHUNK_BYTES },
        S,
    >,
    previous_operations: Option<&[StateOperation<P>]>,
    operations: &[StateOperation<P>],
) -> Result<CurrentBoundaryState<H::Digest, { STATE_BITMAP_CHUNK_BYTES }, QmdbFamily>, PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy + Send + Sync + 'static,
    AccountKey<P>: Send + Sync,
{
    let ops_root_hasher = commonware_storage::qmdb::hasher::<H>();
    let ops_root_witness = state
        .ops_root_witness(&ops_root_hasher)
        .await
        .map_err(|err| QmdbError::CorruptData(format!("local state ops root witness: {err}")))?;
    let pruned_chunks = state.sync_boundary().as_u64() / (STATE_BITMAP_CHUNK_BYTES as u64 * 8);
    recover_boundary_state::<QmdbFamily, H, _, { STATE_BITMAP_CHUNK_BYTES }, _, _>(
        previous_operations,
        operations,
        state.root(),
        pruned_chunks,
        ops_root_witness,
        |location| async move { current_range_proof::<E, H, P, S>(state, location).await },
    )
    .await
    .map_err(Into::into)
}

async fn current_range_proof<E, H, P, S>(
    state: &commonware_storage::qmdb::current::unordered::fixed::Db<
        QmdbFamily,
        E,
        AccountKey<P>,
        Account,
        H,
        commonware_storage::translator::EightCap,
        { STATE_BITMAP_CHUNK_BYTES },
        S,
    >,
    location: Location<QmdbFamily>,
) -> Result<
    (
        RangeProof<QmdbFamily, H::Digest>,
        [u8; STATE_BITMAP_CHUNK_BYTES],
    ),
    QmdbError,
>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let (proof, mut proof_ops, mut chunks) = state
        .range_proof(&hasher, location, NonZeroU64::MIN)
        .await
        .map_err(|err| QmdbError::CorruptData(format!("local state range proof: {err}")))?;
    proof_ops.pop().ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "local state range proof at {location} returned no operations"
        ))
    })?;
    let chunk = chunks.pop().ok_or_else(|| {
        QmdbError::CorruptData(format!(
            "local state range proof at {location} returned no chunks"
        ))
    })?;
    Ok((proof, chunk))
}

fn build_transaction_upload<H, P>(
    block: &EngineBlock<H, P>,
    writer_next: u64,
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

    let ops = transaction_ops(block, writer_next)?;
    let next_location = writer_next
        .checked_add(u64::try_from(ops.len()).expect("operation count fits u64"))
        .expect("transaction operation range does not overflow");
    Ok(PendingTransactionUpload { ops, next_location })
}

fn transaction_ops<H, P>(
    block: &EngineBlock<H, P>,
    writer_next: u64,
) -> Result<Vec<TransactionOperation<H>>, PublishError>
where
    H: Hasher,
    H::Digest: Codec,
    P: PublicKey,
{
    let mut ops = Vec::with_capacity(block.body.len() + 2);
    if writer_next == 0 {
        ops.push(TransactionOperation::<H>::Commit(None, Location::new(0)));
    }

    for lazy in &block.body {
        let Some(tx) = lazy.get() else {
            continue;
        };
        ops.push(TransactionOperation::<H>::Append(*tx.message_digest()));
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
        let mut batch = StoreWriteBatch::new();
        let raw = vec![(
            crate::keys::block(&[7u8; 32]).expect("block key"),
            Bytes::from_static(b"block"),
        )];
        stage_raw_rows(&client, &mut batch, &raw).expect("raw rows stage");

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
}
