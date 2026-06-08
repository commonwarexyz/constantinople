//! Execution and commitment checks for consensus blocks.

use super::{
    MALFORMED_TRANSACTION, Result, STATIC_INVALID_TRANSACTION,
    body::PreparedBody,
    db::{self, StateBatch, TransactionBatch, apply_changeset, apply_transaction_digests},
    history::parent_transactions_inactivity_floor,
    reject_verify,
};
use crate::executor::{self, PreparedTransfer, State};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_glue::stateful::db::Merkleized as _;
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_storage::{merkle::Family, mmr, qmdb::batch_chain::Bounds, translator::EightCap};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Account, AccountKey, Header, SealedBlock, SignedTransaction};
use hashbrown::HashSet;
use std::time::Instant;

pub(super) struct ProposalExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) block: BlockExecution<E, H, S>,
    pub(super) body: Vec<SignedTransaction<H>>,
}

pub(super) struct BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) state: db::StateMerkleized<E, H, EightCap, S>,
    pub(super) transactions: db::TransactionMerkleized<E, H, S>,
    pub(super) state_sync_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transactions_range: commonware_utils::range::NonEmptyRange<u64>,
    pub(super) transaction_count: usize,
    pub(super) timings: Timings,
}

enum LoadedState {
    Unique(Vec<Account>),
    Shared(State),
}

impl<E, H, S> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    pub(super) fn into_merkleized(self) -> db::MerkleizedDatabases<E, H, EightCap, S> {
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
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    input: executor::ProposalInput<H>,
    candidate_transfers: &[PreparedTransfer<H>],
) -> ProposalExecution<E, H, S>
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
    let digests = transfer_digests(&output.transfers);
    let state_batch = apply_changeset(state_batch, &output.changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
    let timings = Timings::before_finalize(0, load_state_ms, execute_ms);

    ProposalExecution {
        block: finalize_child(
            state_batch,
            transaction_batch,
            parent,
            output.valid.len(),
            timings,
            "database merkleization must succeed",
        )
        .await,
        body: output.valid,
    }
}

pub(super) async fn execute_body<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    body: PreparedBody<H>,
) -> Result<BlockExecution<E, H, S>>
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

    let load_started_at = Instant::now();
    let state = load_execution_state(&state_batch, &transfers)
        .await
        .expect("block state loading must succeed");
    let load_state_ms = load_started_at.elapsed().as_millis();

    let execute_started_at = Instant::now();
    let changeset = execute_loaded(&state, &transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
    let execute_ms = execute_started_at.elapsed().as_millis();
    let digests = transfer_digests(&transfers);
    let state_batch = apply_changeset(state_batch, &changeset);
    let transaction_batch = apply_transaction_digests(transaction_batch, &digests);
    let timings = Timings::before_finalize(prepare_ms, load_state_ms, execute_ms);

    Ok(finalize_child(
        state_batch,
        transaction_batch,
        parent,
        transfers.len(),
        timings,
        "database merkleization during verification must succeed",
    )
    .await)
}

pub(super) async fn apply_prepared_body<E, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    transaction_floor: mmr::Location,
    transfers: &[PreparedTransfer<H>],
) -> Result<db::MerkleizedDatabases<E, H, EightCap, S>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    let state = load_execution_state(&state_batch, transfers)
        .await
        .expect("state loading must succeed for certified apply");
    let changeset = execute_loaded(&state, transfers).ok_or(STATIC_INVALID_TRANSACTION)?;
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
    execution: &BlockExecution<E, H, S>,
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

async fn load_state<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    transfers: &[PreparedTransfer<H>],
) -> core::result::Result<State, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
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

    load_accounts(batch, account_keys.into_iter().collect()).await
}

async fn load_execution_state<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    transfers: &[PreparedTransfer<H>],
) -> core::result::Result<LoadedState, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if transfers.is_empty() {
        return Ok(LoadedState::Unique(Vec::new()));
    }

    let mut account_keys = Vec::with_capacity(transfers.len().saturating_mul(2));
    let mut unique = HashSet::with_capacity(transfers.len().saturating_mul(2));
    for transfer in transfers {
        account_keys.push(&transfer.sender);
        account_keys.push(&transfer.recipient);
        unique.insert(&transfer.sender);
        unique.insert(&transfer.recipient);
    }

    if unique.len() == account_keys.len() {
        let values = batch.get_many(&account_keys).await?;
        let accounts = values
            .into_iter()
            .map(|account| account.unwrap_or_default())
            .collect();
        return Ok(LoadedState::Unique(accounts));
    }

    load_accounts(batch, unique.into_iter().cloned().collect())
        .await
        .map(LoadedState::Shared)
}

async fn load_accounts<E, H, S>(
    batch: &StateBatch<E, H, EightCap, S>,
    account_keys: Vec<AccountKey>,
) -> core::result::Result<State, commonware_storage::qmdb::Error<mmr::Family>>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    S: Strategy,
{
    if account_keys.is_empty() {
        return Ok(State::new());
    }

    let keys = account_keys.iter().collect::<Vec<_>>();
    let values = batch.get_many(&keys).await?;
    Ok(account_keys
        .into_iter()
        .zip(values)
        .map(|(account_key, account)| (account_key, account.unwrap_or_default()))
        .collect())
}

fn execute_loaded<H>(
    state: &LoadedState,
    transfers: &[PreparedTransfer<H>],
) -> Option<executor::Changeset>
where
    H: Hasher,
{
    match state {
        LoadedState::Unique(accounts) => executor::execute_unique(transfers, accounts),
        LoadedState::Shared(accounts) => executor::execute(accounts, transfers),
    }
}

async fn finalize_child<E, C, P, H, S>(
    state_batch: StateBatch<E, H, EightCap, S>,
    transaction_batch: TransactionBatch<E, H, S>,
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
    timings: Timings,
    expect_message: &'static str,
) -> BlockExecution<E, H, S>
where
    E: Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    H: Hasher,
    S: Strategy,
{
    let transaction_batch =
        transaction_batch.with_inactivity_floor(parent_transactions_inactivity_floor(parent));
    let finalize_started_at = Instant::now();
    let (state, transactions) = db::finalize_execution(state_batch, transaction_batch)
        .await
        .expect(expect_message);
    let finalize_ms = finalize_started_at.elapsed().as_millis();
    let state_sync_range = range_from_bounds(state.bounds());
    let transactions_range = range_from_bounds(transactions.bounds());

    BlockExecution {
        state,
        transactions,
        state_sync_range,
        transactions_range,
        transaction_count,
        timings: timings.with_finalize_ms(finalize_ms),
    }
}

fn range_from_bounds<F>(bounds: &Bounds<F>) -> commonware_utils::range::NonEmptyRange<u64>
where
    F: Family,
{
    non_empty_range!(*bounds.inactivity_floor, bounds.total_size)
}

fn transfer_digests<H>(transfers: &[PreparedTransfer<H>]) -> Vec<H::Digest>
where
    H: Hasher,
{
    transfers.iter().map(|transfer| transfer.digest).collect()
}

#[cfg(test)]
mod tests {
    use super::range_from_bounds;
    use commonware_storage::{mmr, qmdb::batch_chain::Bounds};
    use commonware_utils::non_empty_range;

    #[test]
    fn range_comes_from_qmdb_bounds() {
        let bounds = Bounds {
            base_size: 7,
            db_size: 9,
            total_size: 15,
            ancestors: Vec::new(),
            inactivity_floor: mmr::Location::new(11),
        };

        assert_eq!(range_from_bounds(&bounds), non_empty_range!(11, 15));
    }
}
