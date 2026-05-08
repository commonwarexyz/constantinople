//! Execution and commitment checks for consensus blocks.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, TransactionBatch, apply_changeset, apply_transaction_digests},
    history::{child_transactions_range, parent_transactions_inactivity_floor},
    telemetry::reject_verify,
};
use crate::executor::{self, PreparedTransfer, State};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{mmr, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Header, SealedBlock, SignedTransaction};
use hashbrown::HashSet;
use std::time::Instant;

pub(super) struct ProposalExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, P, S>,
    pub(super) body: Vec<SignedTransaction<P, H>>,
}

pub(super) struct BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    pub(super) state: db::StateMerkleized<E, H, P, EightCap, S>,
    pub(super) transactions: db::TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
    pub(super) timings: Timings,
}

impl<E, H, P, S> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, P, S> {
        (self.state, self.transactions)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Timings {
    pub(super) prepare_ms: u128,
    pub(super) load_state_ms: u128,
    pub(super) execute_ms: u128,
    pub(super) finalize_ms: u128,
}

impl Timings {
    const fn before_finalize(prepare_ms: u128, load_state_ms: u128, execute_ms: u128) -> Self {
        Self {
            prepare_ms,
            load_state_ms,
            execute_ms,
            finalize_ms: 0,
        }
    }

    const fn with_finalize_ms(mut self, finalize_ms: u128) -> Self {
        self.finalize_ms = finalize_ms;
        self
    }
}

pub(super) async fn execute_proposal<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    input: executor::ProposalInput<P, H>,
    candidate_transfers: &[PreparedTransfer<P, H>],
) -> ProposalExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    let load_started_at = Instant::now();
    let state = load_state(&state_batch, candidate_transfers)
        .await
        .expect("proposal state loading must succeed");
    let load_state_ms = load_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let output = executor::propose_prepared(&state, input);
    let execute_ms = execute_started_at.elapsed().as_millis();
    let transfers = output
        .valid
        .iter()
        .map(executor::prepare_transfer)
        .collect::<Option<Vec<_>>>()
        .expect("included proposal transactions were already prepared");
    let digests = transfer_digests(&transfers);
    let state_sync_range = child_state_sync_range(parent, state_sync_start, output.changeset.len());
    let state_batch = apply_changeset(state_batch, &output.changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
    let timings = Timings::before_finalize(0, load_state_ms, execute_ms);

    ProposalExecution {
        block: finalize_child(
            state_batch,
            transaction_batch,
            parent,
            state_sync_range,
            output.valid.len(),
            timings,
            "database merkleization must succeed",
        )
        .await,
        body: output.valid,
    }
}

pub(super) async fn execute_body<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    body: PreparedBody<P, H>,
) -> Result<BlockExecution<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let prepare_started_at = Instant::now();
    let transfers = body
        .iter()
        .map(|transaction| executor::prepare_transfer(transaction.get()?))
        .collect::<Option<Vec<_>>>()
        .ok_or(MALFORMED_TRANSACTION)?;
    let prepare_ms = prepare_started_at.elapsed().as_millis();

    execute_prepared_child(
        state_batch,
        transaction_batch,
        parent,
        state_sync_start,
        &transfers,
        prepare_ms,
    )
    .await
}

pub(super) async fn apply_prepared_body<E, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: &[PreparedTransfer<P, H>],
) -> Result<db::MerkleizedDatabases<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let state = load_state(&state_batch, transfers)
        .await
        .expect("state loading must succeed for certified apply");
    let changeset = executor::execute(&state, transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let digests = transfer_digests(transfers);
    let state_batch = apply_changeset(state_batch, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests)
        .with_inactivity_floor(transaction_floor);

    db::finalize_execution(state_batch, transaction_batch)
        .await
        .map_err(|_| STATIC_INVALID_TRANSACTION)
}

pub(super) fn commitments_match<E, C, P, H, S>(
    header: &Header<C, H::Digest, P>,
    execution: &BlockExecution<E, H, P, S>,
) -> bool
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    if execution.state.root() != header.state_root {
        reject_verify(header.height, "state_root_mismatch");
        return false;
    }
    if execution.state.sync_root() != header.state_sync_root {
        reject_verify(header.height, "state_sync_root_mismatch");
        return false;
    }
    if execution.state_sync_range != header.state_range {
        reject_verify(header.height, "state_range_mismatch");
        return false;
    }
    if execution.transactions.root() != header.transactions_root {
        reject_verify(header.height, "transaction_root_mismatch");
        return false;
    }
    if execution.transactions_range != header.transactions_range {
        reject_verify(header.height, "transaction_range_mismatch");
        return false;
    }

    true
}

async fn execute_prepared_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    transfers: &[PreparedTransfer<P, H>],
    prepare_ms: u128,
) -> Result<BlockExecution<E, H, P, S>>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let load_started_at = Instant::now();
    let state = load_state(&state_batch, transfers)
        .await
        .expect("block state loading must succeed");
    let load_state_ms = load_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = executor::execute(&state, transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();
    let state_sync_range = child_state_sync_range(parent, state_sync_start, changeset.len());
    let digests = transfer_digests(transfers);
    let state_batch = apply_changeset(state_batch, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
    let timings = Timings::before_finalize(prepare_ms, load_state_ms, execute_ms);

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        state_sync_range,
        transfers.len(),
        timings,
        "database merkleization during verification must succeed",
    )
    .await)
}

async fn load_state<E, H, P, S>(
    batch: &StateBatch<E, H, P, EightCap, S>,
    transfers: &[PreparedTransfer<P, H>],
) -> core::result::Result<State<P>, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
    S: Strategy,
{
    if transfers.is_empty() {
        return Ok(State::new());
    }

    let mut account_keys = HashSet::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        account_keys.insert(transfer.sender.clone());
        account_keys.insert(transfer.recipient.clone());
    }

    let account_keys = account_keys.into_iter().collect::<Vec<_>>();
    let keys = account_keys.iter().collect::<Vec<_>>();
    let values = batch.get_many(&keys).await?;
    Ok(account_keys
        .into_iter()
        .zip(values)
        .map(|(account_key, account)| (account_key, account.unwrap_or_default()))
        .collect())
}

async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, P, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    transaction_count: usize,
    timings: Timings,
    expect_message: &'static str,
) -> BlockExecution<E, H, P, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let transactions_range = child_transactions_range(parent, transaction_count);
    let finalize_started_at = Instant::now();
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let finalize_ms = finalize_started_at.elapsed().as_millis();

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
        timings: timings.with_finalize_ms(finalize_ms),
    }
}

fn child_state_sync_range<C, P, H>(
    parent: &SealedBlock<C, P, H>,
    state_sync_start: u64,
    state_write_count: usize,
) -> commonware_utils::range::NonEmptyRange<u64>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let state_ops = u64::try_from(state_write_count)
        .expect("state write count must fit into u64")
        .checked_add(1)
        .expect("state batch commit must not overflow u64");
    let state_sync_end = parent
        .header
        .state_range
        .end()
        .checked_add(state_ops)
        .expect("state sync range end must not overflow u64");
    non_empty_range!(state_sync_start, state_sync_end)
}

fn transfer_digests<P, H>(transfers: &[PreparedTransfer<P, H>]) -> Vec<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    transfers.iter().map(|transfer| transfer.digest).collect()
}
