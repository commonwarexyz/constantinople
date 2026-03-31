//! Consensus-facing application integration.
//!
//! This module bridges consensus, the mempool, the processor, and the backing
//! databases. It is responsible for:
//!
//! - proposing blocks from mempool transactions
//! - filtering or rejecting invalid signatures before execution
//! - loading processor state from speculative database batches
//! - executing transaction slices against that loaded state
//! - finalizing state roots, transaction roots, and receipt roots
//! - verifying and applying certified blocks
//!
//! The execution boundary is intentionally narrow: the [`Application`] owns
//! the precompile registry, parallel strategy, and QMDB integration, while
//! the processor owns the in-memory state transition logic.

use crate::processor::{
    Precompiles,
    executor::{Processor, VerificationError},
    keys::{account_key, storage_key},
    state::{DiscoveryState, State, StateReader},
};
use commonware_codec::Encode;
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{Digest, Digestible, Hasher, PublicKey, certificate::Scheme};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{
        DatabaseSet, Merkleized as _, Unmerkleized, any::AnyUnmerkleized,
        immutable::ImmutableUnmerkleized,
    },
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    bmt,
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        Error as StorageError,
        any::{
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        immutable::Immutable,
        sync::Target,
    },
    translator::{EightCap, Translator},
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Access, Account, Address, Block, BlockAccessList, Header, Receipt, Sealable, Sealed,
    SignedBlock, SignedTransaction, Slot, StateValue, VerifiedBlock, VerifiedTransaction,
};
use core::fmt;
use futures::{StreamExt, executor::block_on};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::warn;

/// Shared QMDB handle for the application state database.
pub(crate) type StateDatabase<E, H, T> =
    Arc<AsyncRwLock<fixed::Db<mmr::Family, E, Slot, StateValue, H, T>>>;
/// Signed transaction carried by the wire block format.
type WireTransaction<H, P> = SignedTransaction<P, H>;
/// Sealed block carried across the wire and through consensus.
type WireBlock<C, P, H> = Sealed<SignedBlock<C, P, H>, H>;
/// In-memory verified block used during execution.
type ExecutionBlock<C, P, H> = VerifiedBlock<C, P, H>;
/// Shared immutable transaction database handle.
type TransactionDatabase<E, H> =
    Arc<AsyncRwLock<Immutable<mmr::Family, E, <H as Hasher>::Digest, (), H, EightCap>>>;
/// The pair of backing databases owned by the application.
type Databases<E, H, T> = (StateDatabase<E, H, T>, TransactionDatabase<E, H>);
/// Merkleized state database produced after finalization.
type StateMerkleized<E, H, T> = <StateBatch<E, H, T> as Unmerkleized>::Merkleized;
/// Merkleized transaction database produced after finalization.
type TransactionsMerkleized<E, H> = <TransactionBatch<E, H> as Unmerkleized>::Merkleized;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Unmerkleized application state batch used for processor read-through.
pub type StateBatch<E, H, T> = AnyUnmerkleized<
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<Slot, FixedEncoding<StateValue>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<Slot, FixedEncoding<StateValue>>,
>;

/// Unmerkleized transaction batch used for append-only transaction storage.
pub type TransactionBatch<E, H> = ImmutableUnmerkleized<E, <H as Hasher>::Digest, (), H, EightCap>;

/// Unmerkleized batch tuple passed to application execution.
pub type ApplicationBatches<E, H, T> = (StateBatch<E, H, T>, TransactionBatch<E, H>);

/// Errors raised while preparing processor state from the backing database.
#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("state database access failed")]
    Database(#[from] StorageError<mmr::Family>),
    #[error("loaded value has wrong type for its key")]
    MalformedState,
}

/// Hashes the encoded block access list.
///
/// The header commits to the exact BAL bytes so proposers and verifiers agree
/// on both transaction access declarations and final writes.
fn block_access_list_hash<H: Hasher>(access_list: &BlockAccessList) -> H::Digest {
    H::hash(access_list.encode().as_ref())
}

/// Loads the declared processor state for `access_list` from `batch`.
///
/// The loader gathers every declared account and storage access across the
/// block access list, reads each value at most once, and builds an in-memory
/// [`State`] snapshot for verification.
pub async fn load_state<E, H, T>(
    batch: &StateBatch<E, H, T>,
    access_list: &BlockAccessList,
) -> Result<State, ProcessorError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
{
    let (accounts, storage) = collect_preload_keys(access_list);

    // Build all database keys up front so loads can run concurrently.
    let account_keys: Vec<_> = accounts
        .iter()
        .map(|address| (account_key(*address), *address))
        .collect();
    let mut hasher = H::default();
    let storage_keys: Vec<_> = storage
        .iter()
        .map(|(address, slot)| (storage_key(&mut hasher, *address, *slot), *address, *slot))
        .collect();

    // Load all accounts and storage slots in parallel.
    let (account_results, storage_results) = futures::future::try_join(
        futures::future::try_join_all(
            account_keys
                .iter()
                .map(|(key, _)| async move { batch.get(key).await }),
        ),
        futures::future::try_join_all(
            storage_keys
                .iter()
                .map(|(key, _, _)| async move { batch.get(key).await }),
        ),
    )
    .await?;

    // Assemble the account map.
    let mut base_accounts = HashMap::with_capacity(accounts.len());
    for ((_, address), result) in account_keys.iter().zip(account_results) {
        let Some(value) = result else { continue };
        let StateValue::Account(account) = value else {
            return Err(ProcessorError::MalformedState);
        };
        base_accounts.insert(*address, account);
    }

    // Assemble the storage map.
    let mut base_storage = HashMap::with_capacity(storage.len());
    for ((_, address, slot), result) in storage_keys.iter().zip(storage_results) {
        let Some(value) = result else { continue };
        let StateValue::Storage(storage_value) = value else {
            return Err(ProcessorError::MalformedState);
        };
        base_storage.insert((*address, *slot), storage_value);
    }

    Ok(State::new(base_accounts, base_storage))
}

/// Collects the accounts and storage keys that must be loaded for execution.
///
/// The result is de-duplicated across the whole block so state is loaded once
/// before execution starts.
fn collect_preload_keys(
    access_list: &BlockAccessList,
) -> (HashSet<Address>, HashSet<(Address, Slot)>) {
    let mut accounts = HashSet::with_capacity(access_list.tx_accesses.len());
    let mut storage = HashSet::with_capacity(access_list.tx_accesses.len());

    for access in &access_list.tx_accesses {
        match access {
            Access::Account(address, _) => {
                accounts.insert(*address);
            }
            Access::Storage(address, slot, _) => {
                storage.insert((*address, *slot));
            }
        }
    }

    (accounts, storage)
}

/// Proposal-time state reader backed by a speculative database batch.
///
/// Discovery runs sequentially, so this adapter keeps the API simple and
/// performs individual batch lookups on demand.
struct BatchStateReader<'a, E, H, T>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
{
    batch: &'a StateBatch<E, H, T>,
}

impl<'a, E, H, T> BatchStateReader<'a, E, H, T>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
{
    const fn new(batch: &'a StateBatch<E, H, T>) -> Self {
        Self { batch }
    }
}

impl<E, H, T> StateReader for BatchStateReader<'_, E, H, T>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
{
    fn account(&self, address: Address) -> Account {
        let loaded = block_on(self.batch.get(&account_key(address)))
            .expect("proposal account load must succeed");

        match loaded {
            Some(StateValue::Account(account)) => account,
            Some(_) => {
                warn!("proposal account load returned malformed state");
                Account::default()
            }
            None => Account::default(),
        }
    }

    fn storage(&self, address: Address, slot: Slot) -> Slot {
        let mut hasher = H::default();
        let key = storage_key(&mut hasher, address, slot);
        let loaded = block_on(self.batch.get(&key)).expect("proposal storage load must succeed");

        match loaded {
            Some(StateValue::Storage(value)) => value,
            Some(_) => {
                warn!("proposal storage load returned malformed state");
                Slot::default()
            }
            None => Slot::default(),
        }
    }
}

/// Core constantinople application.
///
/// This type implements the consensus application trait on top of the
/// processor and the managed state databases.
/// Type-erased callback for receipt notifications.
pub type ReceiptCallback<D> = Arc<dyn Fn(u64, Vec<Receipt<D>>) + Send + Sync>;

/// Callback invoked with tx hashes that were filtered out during proposal.
pub type RejectionCallback<D> = Arc<dyn Fn(Vec<D>) + Send + Sync>;

pub struct Application<H: Hasher, C, S, P, I, R, St> {
    precompiles: R,
    strategy: St,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    genesis_allocations: Vec<(Address, Account)>,
    receipt_callback: Option<ReceiptCallback<H::Digest>>,
    rejection_callback: Option<RejectionCallback<H::Digest>>,
    _marker: PhantomData<(C, S, I)>,
}

impl<H: Hasher, C, S, P, I, R: Clone, St: Clone> Clone for Application<H, C, S, P, I, R, St>
where
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            precompiles: self.precompiles.clone(),
            strategy: self.strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            transaction_namespace: self.transaction_namespace,
            genesis_allocations: self.genesis_allocations.clone(),
            receipt_callback: self.receipt_callback.clone(),
            rejection_callback: self.rejection_callback.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H: Hasher, C, S, P, I, R, St> fmt::Debug for Application<H, C, S, P, I, R, St> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Application").finish_non_exhaustive()
    }
}

impl<H: Hasher, C, S, P, I, R, St> Application<H, C, S, P, I, R, St> {
    /// Creates an application.
    ///
    /// The application keeps the precompile registry, execution strategy,
    /// genesis leader, and transaction signing namespace for all later block
    /// proposal, verification, and application.
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(
        precompiles: R,
        strategy: St,
        genesis_leader: P,
        transaction_namespace: &'static [u8],
        genesis_allocations: Vec<(Address, Account)>,
    ) -> Self {
        Self {
            precompiles,
            strategy,
            genesis_leader,
            transaction_namespace,
            genesis_allocations,
            receipt_callback: None,
            rejection_callback: None,
            _marker: PhantomData,
        }
    }

    /// Sets a callback that receives receipts after each finalized block.
    pub fn with_receipt_callback(mut self, callback: ReceiptCallback<H::Digest>) -> Self {
        self.receipt_callback = Some(callback);
        self
    }

    /// Sets a callback invoked with tx hashes filtered out during proposal.
    pub fn with_rejection_callback(mut self, callback: RejectionCallback<H::Digest>) -> Self {
        self.rejection_callback = Some(callback);
        self
    }

    /// Returns the configured precompile registry.
    pub const fn precompiles(&self) -> &R {
        &self.precompiles
    }

    /// Returns the configured execution strategy.
    pub const fn strategy(&self) -> &St {
        &self.strategy
    }

    /// Returns the transaction signing namespace.
    pub const fn transaction_namespace(&self) -> &'static [u8] {
        self.transaction_namespace
    }
}

impl<H, C, S, P, I, R, St> Application<H, C, S, P, I, R, St>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    R: Precompiles,
    St: Strategy,
{
    /// Writes genesis allocations to the state batch (called once at height 1).
    fn apply_genesis_allocations<E>(
        &self,
        batch: StateBatch<E, H, EightCap>,
    ) -> StateBatch<E, H, EightCap>
    where
        E: Storage + Clock + Metrics,
    {
        self.genesis_allocations
            .iter()
            .fold(batch, |batch, (address, account)| {
                batch.write(account_key(*address), Some(StateValue::Account(*account)))
            })
    }

    /// Verifies signed wire transactions and returns verified execution transactions.
    fn verify_transactions(
        &self,
        transactions: impl IntoIterator<Item = WireTransaction<H, P>>,
    ) -> Option<Vec<VerifiedTransaction<P, H>>> {
        transactions
            .into_iter()
            .map(|transaction| transaction.into_verified(self.transaction_namespace()).ok())
            .collect()
    }

    /// Verifies a signed wire block into an in-memory verified execution block.
    ///
    /// Decoding never trusts a prior verification step. Wire bytes always
    /// re-enter the application as [`SignedTransaction`] values, and this
    /// method re-verifies each signature before exposing
    /// [`VerifiedTransaction`] values to execution.
    fn verify_block(&self, block: &WireBlock<C, P, H>) -> Option<ExecutionBlock<C, P, H>>
    where
        WireTransaction<H, P>: Clone,
    {
        if block.header.block_access_list_hash != block_access_list_hash::<H>(&block.access_list) {
            return None;
        }

        let body = self.verify_transactions(block.body.iter().cloned())?;
        Some(ExecutionBlock::new(
            block.header.clone(),
            block.access_list.clone(),
            body,
        ))
    }

    /// Returns the current Unix timestamp in milliseconds.
    fn timestamp<E>(&self, runtime: &E) -> u64
    where
        E: Clock,
    {
        let timestamp_ms = runtime
            .current()
            .duration_since(UNIX_EPOCH)
            .expect("clock moved before unix epoch")
            .as_millis();
        u64::try_from(timestamp_ms).expect("timestamp milliseconds exceeded u64")
    }

    /// Returns the binary Merkle root of `receipts`.
    ///
    /// Each receipt is first encoded and hashed into a leaf digest, then the
    /// receipt root is derived from a binary Merkle tree over those leaves.
    fn receipts_root(&self, receipts: &[Receipt<H::Digest>]) -> H::Digest {
        if receipts.is_empty() {
            return H::Digest::EMPTY;
        }

        let mut builder = bmt::Builder::<H>::new(receipts.len());
        for receipt in receipts {
            let leaf = H::hash(receipt.encode().as_ref());
            builder.add(&leaf);
        }

        builder.build().root()
    }

    /// Returns the absolute wakeup time for `block_timestamp_ms`.
    ///
    /// # Panics
    ///
    /// Panics if `block_timestamp_ms` cannot be represented as a
    /// [`SystemTime`] offset from the Unix epoch.
    fn block_deadline(&self, block_timestamp_ms: u64) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_millis(block_timestamp_ms))
            .expect("block timestamp exceeded maximum")
    }

    /// Merkleizes the updated databases and computes the receipts root together.
    ///
    /// This runs the independent finalization work in parallel so proposal,
    /// verification, and application all share the same finalization path.
    ///
    /// # Errors
    ///
    /// Returns any storage error from database merkleization.
    async fn finalize_execution<E>(
        &self,
        state_batch: StateBatch<E, H, EightCap>,
        transaction_batch: TransactionBatch<E, H>,
        receipts: &[Receipt<H::Digest>],
    ) -> Result<
        (
            StateMerkleized<E, H, EightCap>,
            TransactionsMerkleized<E, H>,
            H::Digest,
        ),
        StorageError<mmr::Family>,
    >
    where
        E: Storage + Clock + Metrics,
    {
        futures::try_join!(
            state_batch.merkleize(),
            transaction_batch.merkleize(),
            async { Ok::<H::Digest, StorageError<mmr::Family>>(self.receipts_root(receipts)) },
        )
    }
}

fn apply_final_writes<E, H>(
    mut batch: StateBatch<E, H, EightCap>,
    access_list: &BlockAccessList,
) -> StateBatch<E, H, EightCap>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    for write in &access_list.account_writes {
        batch = batch.write(
            account_key(write.address),
            Some(StateValue::Account(write.account)),
        );
    }

    for write in &access_list.storage_writes {
        let mut hasher = H::default();
        let key = storage_key(&mut hasher, write.address, write.slot);
        batch = batch.write(key, Some(StateValue::Storage(write.value)));
    }

    batch
}

impl<E, H, C, S, P, I, R, St> CApplication<E> for Application<H, C, S, P, I, R, St>
where
    E: Rng + Spawner + Storage + Metrics + Clock,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    R: Precompiles + Clone + Send + Sync + 'static,
    St: Strategy + Clone + Send + Sync + 'static,
    I: TransactionSource<C, P, H> + Sync,
{
    type SigningScheme = S;
    type Context = Context<C, P>;
    type Block = WireBlock<C, P, H>;
    type Databases = Databases<E, H, EightCap>;
    type InputProvider = I;

    /// Returns the sync targets required to fetch the block's state.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        let state_target = Target {
            root: block.header.state_root,
            range: non_empty_range!(
                mmr::Location::new(block.header.state_range.start()),
                mmr::Location::new(block.header.state_range.end())
            ),
        };
        let transactions_target = Target {
            root: block.header.transactions_root,
            range: non_empty_range!(
                mmr::Location::new(block.header.transactions_range.start()),
                mmr::Location::new(block.header.transactions_range.end())
            ),
        };

        (state_target, transactions_target)
    }

    /// Builds the genesis block.
    ///
    /// The genesis block always uses timestamp `0` and the configured genesis
    /// leader.
    async fn genesis(&mut self) -> Self::Block {
        genesis_block(&mut H::default(), self.genesis_leader.clone(), 0)
    }

    /// Proposes the next block from the mempool and current ancestry.
    ///
    /// Proposal consumes already-verified mempool transactions and filters
    /// out transactions that fail static processor validation before block
    /// construction. The surviving transactions, including any that later
    /// revert at runtime, are executed against speculative batches and
    /// finalized into the proposed block header.
    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (runtime, context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let parent = ancestry.next().await?;
        let all_proposed = input.propose(&parent.header, &context).await;
        let (mut state_batch, transaction_batch) = batches;
        if parent.header.height == 0 {
            state_batch = self.apply_genesis_allocations(state_batch);
        }
        let processor = Processor::new(self.strategy(), self.precompiles());
        let mut discovery_state = DiscoveryState::new(BatchStateReader::new(&state_batch));
        let result = processor.validate(&discovery_state, all_proposed);

        // Notify rejected transaction waiters.
        if let Some(ref callback) = self.rejection_callback
            && !result.invalid.is_empty()
        {
            let rejected: Vec<_> = result
                .invalid
                .iter()
                .map(|tx| *tx.message_digest())
                .collect();
            callback(rejected);
        }

        let transaction_batch = result
            .valid
            .iter()
            .fold(transaction_batch, |batch, transaction| {
                batch.set(*transaction.message_digest(), ())
            });
        let output = processor.propose(&mut discovery_state, &result.valid);
        let state_batch = output
            .changeset
            .iter()
            .fold(state_batch, |batch, (key, value)| {
                batch.write(*key, Some(value.clone()))
            });
        if let Some(ref callback) = self.receipt_callback {
            callback(parent.header.height + 1, output.receipts.clone());
        }
        let (state_merkleized, transaction_merkleized, receipts_root) = self
            .finalize_execution(state_batch, transaction_batch, &output.receipts)
            .await
            .expect("database merkleization must succeed");
        let transactions_end =
            parent.header.transactions_range.end() + result.valid.len() as u64 + 1;

        let header = Header {
            context,
            parent: parent.digest(),
            height: parent.header.height + 1,
            timestamp: self.timestamp(&runtime),
            state_root: state_merkleized.root(),
            state_range: non_empty_range!(
                *state_merkleized.inactivity_floor(),
                *state_merkleized.size()
            ),
            transactions_root: transaction_merkleized.root(),
            transactions_range: non_empty_range!(
                parent.header.transactions_range.start(),
                transactions_end
            ),
            receipts_root,
            block_access_list_hash: block_access_list_hash::<H>(&output.access_list),
        };
        let block = Block::new(
            header,
            output.access_list,
            result
                .valid
                .into_iter()
                .map(VerifiedTransaction::into_inner)
                .collect(),
        )
        .seal(&mut H::default());

        Some(Proposed {
            block,
            merkleized: (state_merkleized, transaction_merkleized),
        })
    }

    /// Verifies a proposed block against speculative execution.
    ///
    /// Verification rejects invalid transaction signatures and invalid
    /// timestamps, then waits until the block timestamp has passed to
    /// account for clock skew. After the wait, it re-executes the block
    /// and compares all derived roots and ranges.
    async fn verify<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (runtime, _context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let block = ancestry.next().await?;
        let parent = ancestry.next().await?;

        let Some(verified_block) = self.verify_block(&block) else {
            warn!(
                height = block.header.height,
                "verify rejected: invalid signature"
            );
            return None;
        };

        if block.header.timestamp <= parent.header.timestamp
            || block.header.timestamp > MAX_BLOCK_TIMESTAMP_MS
        {
            warn!(
                height = block.header.height,
                block_ts = block.header.timestamp,
                parent_ts = parent.header.timestamp,
                "verify rejected: invalid timestamp"
            );
            return None;
        }

        // Wait until the block timestamp has passed to vote in case of skew.
        let deadline = self.block_deadline(block.header.timestamp);
        runtime.sleep_until(deadline).await;

        let (mut state_batch, transaction_batch) = batches;
        if parent.header.height == 0 {
            state_batch = self.apply_genesis_allocations(state_batch);
        }
        if !verified_block
            .access_list
            .is_well_formed(verified_block.body.len())
        {
            warn!(
                height = block.header.height,
                "verify rejected: malformed block access list"
            );
            return None;
        }

        let state = load_state(&state_batch, &verified_block.access_list)
            .await
            .expect("block state loading during verification must succeed");
        let processor = Processor::new(self.strategy(), self.precompiles());
        let body_len = verified_block.body.len();
        let Block {
            access_list, body, ..
        } = verified_block;
        let validation = processor.validate(&state, body);
        if !validation.invalid.is_empty() {
            warn!(
                height = block.header.height,
                "verify rejected: statically invalid transaction"
            );
            return None;
        }

        let transaction_batch = validation
            .valid
            .iter()
            .fold(transaction_batch, |batch, transaction| {
                batch.set(*transaction.message_digest(), ())
            });
        let output = match processor.verify(state, &validation.valid, &access_list) {
            Ok(output) => output,
            Err(VerificationError::MalformedBlockAccessList) => {
                warn!(
                    height = block.header.height,
                    "verify rejected: malformed block access list"
                );
                return None;
            }
            Err(VerificationError::AccessListMismatch { transaction_index }) => {
                warn!(
                    height = block.header.height,
                    transaction_index, "verify rejected: block access list mismatch"
                );
                return None;
            }
            Err(VerificationError::FinalStateMismatch) => {
                warn!(
                    height = block.header.height,
                    "verify rejected: final state mismatch"
                );
                return None;
            }
        };
        let state_batch = output
            .changeset
            .iter()
            .fold(state_batch, |batch, (key, value)| {
                batch.write(*key, Some(value.clone()))
            });
        let (state_merkleized, transaction_merkleized, receipts_root) = self
            .finalize_execution(state_batch, transaction_batch, &output.receipts)
            .await
            .expect("database merkleization during verification must succeed");
        let transactions_end = parent.header.transactions_range.end() + body_len as u64 + 1;

        let state_range = non_empty_range!(
            *state_merkleized.inactivity_floor(),
            *state_merkleized.size()
        );
        let transactions_range =
            non_empty_range!(parent.header.transactions_range.start(), transactions_end);

        if state_merkleized.root() != block.header.state_root {
            warn!(
                height = block.header.height,
                "verify rejected: state root mismatch"
            );
            return None;
        }
        if state_range != block.header.state_range {
            warn!(
                height = block.header.height,
                "verify rejected: state range mismatch"
            );
            return None;
        }
        if transaction_merkleized.root() != block.header.transactions_root {
            warn!(
                height = block.header.height,
                "verify rejected: transactions root mismatch"
            );
            return None;
        }
        if transactions_range != block.header.transactions_range {
            warn!(
                height = block.header.height,
                "verify rejected: transactions range mismatch"
            );
            return None;
        }
        if receipts_root != block.header.receipts_root {
            warn!(
                height = block.header.height,
                "verify rejected: receipts root mismatch"
            );
            return None;
        }

        if let Some(ref callback) = self.receipt_callback {
            callback(block.header.height, output.receipts.clone());
        }

        Some((state_merkleized, transaction_merkleized))
    }

    /// Applies a certified block to speculative batches and returns merkleized state.
    ///
    /// Unlike verification, application assumes consensus has already
    /// certified the block. It reconstitutes verified execution transactions
    /// from the signed wire block and deterministically replays them to
    /// derive the merkleized database pair.
    ///
    /// # Panics
    ///
    /// Panics if the certified block contains an invalid signature or if
    /// execution or database finalization fails.
    async fn apply(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let verified_block = self
            .verify_block(block)
            .expect("certified block contained an invalid signature");

        let (mut state_batch, transaction_batch) = batches;
        if block.header.height == 1 {
            state_batch = self.apply_genesis_allocations(state_batch);
        }
        assert!(
            verified_block
                .access_list
                .is_well_formed(verified_block.body.len()),
            "certified block contained a malformed block access list"
        );

        let transaction_batch = verified_block
            .body
            .iter()
            .fold(transaction_batch, |batch, transaction| {
                batch.set(*transaction.message_digest(), ())
            });
        let state_batch = apply_final_writes(state_batch, &verified_block.access_list);
        let (state_merkleized, transaction_merkleized) =
            futures::try_join!(state_batch.merkleize(), transaction_batch.merkleize(),)
                .expect("database merkleization must succeed");
        (state_merkleized, transaction_merkleized)
    }
}

/// Creates the genesis block.
///
/// The genesis block starts with empty state, empty transactions, and the
/// provided leader and timestamp.
pub fn genesis_block<C, P, H>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
) -> Sealed<Block<C, P, H>, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let access_list = BlockAccessList::default();
    let header = Header {
        context: Context {
            round: Round::zero(),
            leader,
            parent: (View::zero(), C::EMPTY),
        },
        parent: H::Digest::EMPTY,
        height: 0,
        timestamp,
        state_root: H::Digest::EMPTY,
        state_range: non_empty_range!(0, 1),
        transactions_root: H::Digest::EMPTY,
        transactions_range: non_empty_range!(0, 1),
        receipts_root: H::Digest::EMPTY,
        block_access_list_hash: block_access_list_hash::<H>(&access_list),
    };

    Block::<C, P, H>::new(header, access_list, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{
        Application, ProcessorError, StateDatabase, WireBlock, block_access_list_hash, load_state,
    };
    use crate::processor::{
        Precompiles,
        executor::Processor,
        frame::{Frame, FrameError},
        keys::{account_key, storage_key},
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt, Encode, FixedSize};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Round, View},
    };
    use commonware_cryptography::{Digest, Signer, blake3, ed25519, secp256r1::recoverable};
    use commonware_glue::stateful::db::ManagedDb;
    use commonware_parallel::{Sequential, Strategy};
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::{
            fixed::Config as FixedJournalConfig, variable::Config as VariableJournalConfig,
        },
        mmr,
        mmr::journaled::Config as MmrConfig,
        qmdb::{
            any::{FixedConfig, unordered::fixed},
            immutable::{Config as ImmutableConfig, Immutable},
        },
        translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sync::AsyncRwLock};
    use constantinople_primitives::{
        Access, AccessMode, Address, Block, BlockAccessList, BlockCfg, Header, Sealable,
        SignedTransaction, Slot, StateValue, Transaction, VerifiedTransaction,
    };
    use core::marker::PhantomData;
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"application-test";

    type TestContext = deterministic::Context;
    type TestHasher = blake3::Blake3;
    type TestPublicKey = recoverable::PublicKey;
    type TestTransaction = VerifiedTransaction<TestPublicKey, TestHasher>;
    type TestTransactionDb = Arc<
        AsyncRwLock<Immutable<mmr::Family, TestContext, blake3::Digest, (), TestHasher, EightCap>>,
    >;
    type TestStateDb = StateDatabase<TestContext, TestHasher, EightCap>;
    type VerifyTestPublicKey = ed25519::PublicKey;
    type VerifyTestSignedTransaction = SignedTransaction<VerifyTestPublicKey, TestHasher>;
    type VerifyTestTransaction = VerifiedTransaction<VerifyTestPublicKey, TestHasher>;
    type VerifyTestWireBlock = WireBlock<blake3::Digest, VerifyTestPublicKey, TestHasher>;

    #[derive(Clone, Debug, Default)]
    struct NoopPrecompiles;

    impl Precompiles for NoopPrecompiles {
        fn is_precompile(&self, _address: Address) -> bool {
            false
        }

        fn execute<S, R>(
            &self,
            _address: Address,
            _frame: &mut Frame<'_, R>,
            _processor: &Processor<'_, S, Self>,
        ) -> Result<Bytes, FrameError>
        where
            S: Strategy,
            R: crate::processor::state::StateReader,
        {
            Err(FrameError::InvalidTransactionTarget)
        }
    }

    fn transaction_db_config(suffix: &str, context: &TestContext) -> ImmutableConfig<EightCap, ()> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        ImmutableConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("tx-journal-{suffix}"),
                metadata_partition: format!("tx-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            log: VariableJournalConfig {
                partition: format!("tx-log-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: (),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: EightCap,
        }
    }

    fn state_db_config(suffix: &str, context: &TestContext) -> FixedConfig<EightCap> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        FixedConfig {
            merkle_config: MmrConfig {
                journal_partition: format!("state-journal-{suffix}"),
                metadata_partition: format!("state-metadata-{suffix}"),
                items_per_blob: NZU64!(11),
                write_buffer: NZUsize!(1024),
                thread_pool: None,
                page_cache: page_cache.clone(),
            },
            journal_config: FixedJournalConfig {
                partition: format!("state-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
            },
            translator: EightCap,
        }
    }

    async fn open_transaction_db(context: TestContext, suffix: &str) -> TestTransactionDb {
        let db = Immutable::init(context.clone(), transaction_db_config(suffix, &context))
            .await
            .expect("transaction db init should succeed");
        Arc::new(AsyncRwLock::new(db))
    }

    async fn open_state_db(context: TestContext, suffix: &str) -> TestStateDb {
        let db = fixed::Db::init(context.clone(), state_db_config(suffix, &context))
            .await
            .expect("state db init should succeed");
        Arc::new(AsyncRwLock::new(db))
    }

    async fn write_state(db: &TestStateDb, writes: impl IntoIterator<Item = (Slot, StateValue)>) {
        let mut db = db.write().await;
        let mut batch = db.new_batch();
        for (key, value) in writes {
            batch = batch.write(key, Some(value));
        }
        let finalized = batch
            .merkleize(None, &db)
            .await
            .expect("state merkleization should succeed")
            .finalize();
        db.apply_batch(finalized)
            .await
            .expect("state batch apply should succeed");
    }

    fn address(byte: u8) -> Address {
        Address::decode(&[byte; Address::SIZE][..]).expect("address bytes should decode")
    }

    fn slot(byte: u8) -> Slot {
        Slot::from([byte; Slot::SIZE])
    }

    fn signed_transaction(nonce: u64) -> TestTransaction {
        let private_key = recoverable::PrivateKey::from_seed(7);
        Transaction {
            sender: private_key.public_key(),
            to: Address::EMPTY,
            input: Bytes::new(),
            value: 0,
            nonce,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&private_key, NAMESPACE, &mut TestHasher::default())
    }

    fn verify_test_application() -> Application<
        TestHasher,
        blake3::Digest,
        (),
        VerifyTestPublicKey,
        (),
        NoopPrecompiles,
        Sequential,
    > {
        let genesis_leader = ed25519::PrivateKey::from_seed(1).public_key();
        Application::new(
            NoopPrecompiles,
            Sequential,
            genesis_leader,
            NAMESPACE,
            Vec::new(),
        )
    }

    fn verified_wire_transaction() -> VerifyTestTransaction {
        let private_key = ed25519::PrivateKey::from_seed(11);
        Transaction {
            sender: private_key.public_key(),
            to: Address::EMPTY,
            input: Bytes::new(),
            value: 0,
            nonce: 0,
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&private_key, NAMESPACE, &mut TestHasher::default())
    }

    fn verify_test_header(
        leader: VerifyTestPublicKey,
        transactions: usize,
    ) -> Header<blake3::Digest, blake3::Digest, VerifyTestPublicKey> {
        let access_list = BlockAccessList::default();
        Header {
            context: Context {
                round: Round::zero(),
                leader,
                parent: (View::zero(), blake3::Digest::EMPTY),
            },
            parent: blake3::Digest::EMPTY,
            height: 1,
            timestamp: 1,
            state_root: blake3::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: blake3::Digest::EMPTY,
            transactions_range: non_empty_range!(0, transactions as u64 + 1),
            receipts_root: blake3::Digest::EMPTY,
            block_access_list_hash: block_access_list_hash::<TestHasher>(&access_list),
        }
    }

    #[test]
    fn transactions_end_uses_post_commit_location() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_transaction_db(context, "transactions-end").await;
            let mut db = db.write().await;
            let transaction = signed_transaction(0);
            let finalized = db
                .new_batch()
                .set(*transaction.message_digest(), ())
                .merkleize(None)
                .finalize();
            db.apply_batch(finalized)
                .await
                .expect("batch apply should succeed");
            db.commit().await.expect("commit should succeed");

            assert_eq!(*db.size().await, 3);
        });
    }

    #[test]
    fn decoded_verified_bytes_are_reverified_before_execution() {
        let application = verify_test_application();
        let transaction = verified_wire_transaction();
        let block =
            Block::<blake3::Digest, VerifyTestPublicKey, TestHasher, VerifyTestTransaction>::new(
                verify_test_header(transaction.value().sender.clone(), 1),
                BlockAccessList::default(),
                vec![transaction.clone()],
            )
            .seal(&mut TestHasher::default());

        let encoded = block.encode();
        let decoded = VerifyTestWireBlock::decode_cfg(&mut &encoded[..], &BlockCfg::default())
            .expect("wire block decoding should succeed");

        let verified = application
            .verify_block(&decoded)
            .expect("decoded block should be re-verified");

        assert_eq!(verified.body.len(), 1);
        assert_eq!(
            *verified.body[0].message_digest(),
            *transaction.message_digest()
        );
        assert_eq!(verified.body[0].signer(), transaction.signer());
    }

    #[test]
    fn decoded_block_with_tampered_signature_is_rejected() {
        let application = verify_test_application();
        let transaction = verified_wire_transaction();
        let block = Block::<
            blake3::Digest,
            VerifyTestPublicKey,
            TestHasher,
            VerifyTestSignedTransaction,
        >::new(
            verify_test_header(transaction.value().sender.clone(), 1),
            BlockAccessList::default(),
            vec![transaction.into_inner()],
        )
        .seal(&mut TestHasher::default());

        let mut encoded = block.encode().to_vec();
        let byte = encoded
            .last_mut()
            .expect("encoded block should include signature bytes");
        *byte ^= 0x01;

        let decoded = VerifyTestWireBlock::decode_cfg(&mut &encoded[..], &BlockCfg::default())
            .expect("tampered block should still decode");

        assert!(application.verify_block(&decoded).is_none());
    }

    #[test]
    fn malformed_loaded_account_value_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_state_db(context, "malformed-account-value").await;
            let sender = address(0x90);

            write_state(
                &db,
                [(account_key(sender), StateValue::Storage(slot(0x01)))],
            )
            .await;

            let batch = ManagedDb::new_batch(&db).await;
            let access_list = BlockAccessList::from_transactions(
                [vec![Access::Account(sender, AccessMode::Write)]],
                Vec::new(),
                Vec::new(),
            );

            let result = load_state(&batch, &access_list).await;
            assert!(matches!(result, Err(ProcessorError::MalformedState)));
        });
    }

    #[test]
    fn malformed_loaded_storage_value_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_state_db(context, "malformed-storage-value").await;
            let owner = address(0x95);
            let storage_slot = slot(0x96);
            let mut hasher = TestHasher::default();
            let key = storage_key(&mut hasher, owner, storage_slot);

            write_state(&db, [(key, StateValue::Account(Default::default()))]).await;

            let batch = ManagedDb::new_batch(&db).await;
            let access_list = BlockAccessList::from_transactions(
                [vec![Access::Storage(owner, storage_slot, AccessMode::Read)]],
                Vec::new(),
                Vec::new(),
            );

            let result = load_state(&batch, &access_list).await;
            assert!(matches!(result, Err(ProcessorError::MalformedState)));
        });
    }
}
