//! QMDB publisher for finalized state and transaction hashes.

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
use std::{num::NonZeroU64, time::Duration};
use tokio::{sync::Mutex, time::sleep};
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
    #[error("cannot initialize QMDB writer from {locations} operation locations")]
    CheckpointTooLarge { locations: u64 },
    #[error("QMDB Store is empty but finalized block height {height} needs historical backfill")]
    StoreEmptyPastGenesis { height: u64 },
    #[error(
        "QMDB writer is at operation {writer_next}, but finalized block starts at {block_start}"
    )]
    WriterOutOfSync { writer_next: u64, block_start: u64 },
}

/// Owns QMDB writers for the two Store-prefixed indexer namespaces.
#[derive(Debug)]
pub struct QmdbPublisher<H, P>
where
    H: Hasher,
    P: PublicKey,
{
    commit_client: StoreClient,
    state_writer: StateWriter<H, P>,
    state_operations: Mutex<Vec<StateOperation<P>>>,
    transaction_writer: TransactionWriter<H>,
}

impl<H, P> QmdbPublisher<H, P>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
{
    /// Construct writers over the two reserved QMDB Store prefixes.
    pub async fn connect(store_url: &str) -> Result<Self, PublishError> {
        let commit_client = super::standard_store_client(store_url);
        let state_client = state_qmdb_client(&commit_client)?;
        let transaction_client = transactions_qmdb_client(&commit_client)?;
        let state = recover_state_writer_state::<H, P>(state_client.clone()).await?;
        let transactions =
            recover_transaction_writer_state::<H>(transaction_client.clone()).await?;

        Ok(Self {
            commit_client,
            state_writer: StateWriter::new(state_client, state),
            state_operations: Mutex::new(Vec::new()),
            transaction_writer: TransactionWriter::new(transaction_client, transactions),
        })
    }

    /// Upload QMDB rows for one finalized block and current state boundary.
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
        let state = prepare_state_upload::<E, H, P, S>(
            &self.state_writer,
            &self.state_operations,
            block,
            &databases.0,
        )
        .await?;
        let transactions = prepare_transaction_upload(&self.transaction_writer, block).await?;

        let mut batch = StoreWriteBatch::new();
        self.state_writer.stage_upload(&state, &mut batch)?;
        self.transaction_writer
            .stage_upload(&transactions, &mut batch)?;

        let seq = commit_with_retry(&self.commit_client, &batch).await;
        let state_receipt = self.state_writer.mark_upload_persisted(state, seq).await;
        let transaction_receipt = self
            .transaction_writer
            .mark_upload_persisted(transactions, seq)
            .await;
        debug!(
            height = block.header.height,
            state_location = %state_receipt.latest_location,
            transaction_location = %transaction_receipt.latest_location,
            store_sequence = seq,
            "indexer uploaded qmd batch"
        );
        Ok(())
    }
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

async fn prepare_state_upload<E, H, P, S>(
    writer: &StateWriter<H, P>,
    operation_cache: &Mutex<Vec<StateOperation<P>>>,
    block: &EngineBlock<H, P>,
    state_db: &StateDatabase<E, H, P, commonware_storage::translator::EightCap, S>,
) -> Result<PreparedUpload<QmdbFamily>, PublishError>
where
    E: Storage + Clock + Metrics,
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey + Send + Sync + 'static,
    S: Strategy + Send + Sync + 'static,
    AccountKey<P>: Send + Sync,
{
    let writer_next = next_writer_location(writer.latest_published_watermark().await);
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
    drop(operations);

    writer
        .prepare_current_upload(&delta, &boundary)
        .await
        .map_err(Into::into)
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

async fn prepare_transaction_upload<H, P>(
    writer: &TransactionWriter<H>,
    block: &EngineBlock<H, P>,
) -> Result<PreparedUpload<QmdbFamily>, PublishError>
where
    H: Hasher + Send + Sync + 'static,
    H::Digest: Codec + Send + Sync,
    P: PublicKey,
{
    let writer_next = next_writer_location(writer.latest_published_watermark().await);
    if writer_next == 0 && block.header.height > 1 {
        return Err(PublishError::StoreEmptyPastGenesis {
            height: block.header.height,
        });
    }

    let ops = transaction_ops(block, writer_next)?;
    writer.prepare_upload(&ops).await.map_err(Into::into)
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
                    "indexer qmd upload failed, retrying"
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
}
