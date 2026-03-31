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
    Precompiles, Processor, ProcessorOutput, State,
    state::{account_key, storage_key},
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
    mmr::Location,
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
    Access, Account, Address, Block, Header, Receipt, Sealable, Sealed, SignedBlock,
    SignedTransaction, Slot, StateValue, VerifiedBlock, VerifiedTransaction,
};
use core::fmt;
use futures::StreamExt;
use rand::Rng;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::warn;

/// Shared QMDB handle for the application state database.
pub(crate) type StateDatabase<E, H, T> = Arc<AsyncRwLock<fixed::Db<E, Slot, StateValue, H, T>>>;
/// Signed transaction carried by the wire block format.
type WireTransaction<H, P> = SignedTransaction<P, H>;
/// Sealed block carried across the wire and through consensus.
type WireBlock<C, P, H> = Sealed<SignedBlock<C, P, H>, H>;
/// In-memory verified block used during execution.
type ExecutionBlock<C, P, H> = VerifiedBlock<C, P, H>;
/// Shared immutable transaction database handle.
type TransactionDatabase<E, H> =
    Arc<AsyncRwLock<Immutable<E, <H as Hasher>::Digest, (), H, EightCap>>>;
/// The pair of backing databases owned by the application.
type Databases<E, H, T> = (StateDatabase<E, H, T>, TransactionDatabase<E, H>);
/// Merkleized state database produced after finalization.
type StateMerkleized<E, H, T> = <StateBatch<E, H, T> as Unmerkleized>::Merkleized;
/// Merkleized transaction database produced after finalization.
type TransactionsMerkleized<E, H> = <TransactionBatch<E, H> as Unmerkleized>::Merkleized;

/// Maximum accepted block timestamp in milliseconds since the Unix epoch.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 253_402_300_799_999;


/// Unmerkleized application state batch used for processor read-through.
pub type StateBatch<E, H, T> = AnyUnmerkleized<
    E,
    FixedJournal<E, AnyOperation<UnorderedUpdate<Slot, FixedEncoding<StateValue>>>>,
    UnorderedIndex<T, Location>,
    H,
    UnorderedUpdate<Slot, FixedEncoding<StateValue>>,
>;

/// Unmerkleized transaction batch used for append-only transaction storage.
pub type TransactionBatch<E, H> = ImmutableUnmerkleized<E, <H as Hasher>::Digest, (), H, EightCap>;

/// Unmerkleized batch tuple passed to application execution.
pub type ApplicationBatches<E, H, T> = (StateBatch<E, H, T>, TransactionBatch<E, H>);

/// The result of executing a block's transactions against application batches.
#[derive(Debug)]
pub struct ExecutedTransactions<B, D: Digest> {
    /// Updated application batches after applying the processor output.
    pub batches: B,
    /// Receipts and state writes emitted by the processor.
    pub output: ProcessorOutput<D>,
}

/// Errors raised while preparing processor state from the backing database.
#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("state database access failed")]
    Database(#[from] StorageError),
}

/// Receipts emitted after a block is finalized.
#[derive(Debug, Clone)]
pub struct BlockReceipts<D: Digest> {
    pub height: u64,
    pub tx_hashes: Vec<D>,
    pub receipts: Vec<Receipt<D>>,
}

/// Loads the declared processor state for `transactions` from `batch`.
///
/// The loader gathers every sender, top-level recipient, and explicitly
/// declared account or storage access across the transaction slice, reads each
/// value at most once, and builds an in-memory [`State`] snapshot for later
/// execution.
///
/// Missing accounts and storage values are omitted from the snapshot and later
/// read as defaults during execution. If a loaded key resolves to the wrong
/// value kind, the key is marked invalid and any transaction that declares it
/// will revert during execution rather than panicking the processor.
///
/// # Errors
///
/// Returns [`ProcessorError::Database`] if any batch read fails.
pub async fn load_state<E, H, T, PK>(
    batch: &StateBatch<E, H, T>,
    transactions: &[VerifiedTransaction<PK, H>],
) -> Result<State, ProcessorError>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    T: Translator,
    PK: PublicKey,
{
    let (accounts, storage) = collect_preload_keys(transactions);
    let mut base_accounts = HashMap::with_capacity(accounts.len());
    let mut invalid_accounts = BTreeSet::new();
    for address in accounts {
        let key = account_key(address);
        let Some(value) = batch.get(&key).await? else {
            continue;
        };

        let StateValue::Account(account) = value else {
            invalid_accounts.insert(address);
            continue;
        };

        base_accounts.insert(address, account);
    }

    let mut base_storage = HashMap::with_capacity(storage.len());
    let mut invalid_storage = BTreeSet::new();
    let mut hasher = H::default();
    for (address, slot) in storage {
        let key = storage_key(&mut hasher, address, slot);
        let Some(value) = batch.get(&key).await? else {
            continue;
        };

        let StateValue::Storage(storage_value) = value else {
            invalid_storage.insert((address, slot));
            continue;
        };

        base_storage.insert((address, slot), storage_value);
    }

    Ok(State::with_invalid(
        base_accounts,
        base_storage,
        invalid_accounts,
        invalid_storage,
    ))
}

/// Collects the accounts and storage keys that must be loaded for execution.
///
/// Every transaction contributes its sender, top-level recipient, and all
/// explicitly declared accesses. The result is de-duplicated across the whole
/// slice so state is loaded once before execution starts.
fn collect_preload_keys<H, PK>(
    transactions: &[VerifiedTransaction<PK, H>],
) -> (HashSet<Address>, HashSet<(Address, Slot)>)
where
    H: Hasher,
    PK: PublicKey,
{
    let mut accounts = HashSet::new();
    let mut storage = HashSet::new();

    for transaction in transactions {
        let sender = transaction.signer();
        let tx = transaction.value();

        accounts.insert(sender);
        accounts.insert(tx.to);

        for access in &tx.access_list {
            match access {
                Access::Account(address, _) => {
                    accounts.insert(*address);
                }
                Access::Storage(address, slot, _) => {
                    storage.insert((*address, *slot));
                }
            }
        }
    }

    (accounts, storage)
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

    /// Executes `transactions` against `state` and applies writes to `batches`.
    fn execute_loaded_transactions<E>(
        &self,
        batches: ApplicationBatches<E, H, EightCap>,
        state: State,
        transactions: &[VerifiedTransaction<P, H>],
    ) -> ExecutedTransactions<ApplicationBatches<E, H, EightCap>, H::Digest>
    where
        E: Storage + Clock + Metrics,
    {
        let (state_batch, transaction_batch) = batches;
        let processor = Processor::new(self.strategy(), self.precompiles());
        let output = processor.process(state, transactions);

        let state_batch = output
            .changeset
            .iter()
            .fold(state_batch, |batch, (key, value)| {
                batch.write(*key, Some(value.clone()))
            });
        let transaction_batch = transactions
            .iter()
            .fold(transaction_batch, |batch, transaction| {
                batch.set(*transaction.message_digest(), ())
            });

        ExecutedTransactions {
            batches: (state_batch, transaction_batch),
            output,
        }
    }

    /// Loads state, executes transactions, and applies writes to `batches`.
    pub async fn execute_transactions<E>(
        &self,
        batches: ApplicationBatches<E, H, EightCap>,
        transactions: &[VerifiedTransaction<P, H>],
    ) -> Result<ExecutedTransactions<ApplicationBatches<E, H, EightCap>, H::Digest>, ProcessorError>
    where
        E: Storage + Clock + Metrics,
    {
        let (state_batch, transaction_batch) = batches;
        let state = load_state(&state_batch, transactions).await?;
        Ok(self.execute_loaded_transactions((state_batch, transaction_batch), state, transactions))
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
        let body = self.verify_transactions(block.body.iter().cloned())?;
        Some(ExecutionBlock::new(block.header.clone(), body))
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
        StorageError,
    >
    where
        E: Storage + Clock + Metrics,
    {
        futures::try_join!(
            state_batch.merkleize(),
            transaction_batch.merkleize(),
            async { Ok::<H::Digest, StorageError>(self.receipts_root(receipts)) },
        )
    }
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
                Location::new(block.header.state_range.start()),
                Location::new(block.header.state_range.end())
            ),
        };
        let transactions_target = Target {
            root: block.header.transactions_root,
            range: non_empty_range!(
                Location::new(block.header.transactions_range.start()),
                Location::new(block.header.transactions_range.end())
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
        let state = load_state(&state_batch, &all_proposed)
            .await
            .expect("proposed state loading must succeed");
        let processor = Processor::new(self.strategy(), self.precompiles());
        let transactions = processor.filter_invalid(state.clone(), &all_proposed);

        // Notify rejected transaction waiters.
        if let Some(ref callback) = self.rejection_callback {
            let included: HashSet<_> = transactions
                .iter()
                .map(|tx| tx.message_digest().as_ref().to_vec())
                .collect();
            let rejected: Vec<_> = all_proposed
                .iter()
                .filter(|tx| !included.contains(tx.message_digest().as_ref()))
                .map(|tx| *tx.message_digest())
                .collect();
            if !rejected.is_empty() {
                callback(rejected);
            }
        }
        let executed = self.execute_loaded_transactions(
            (state_batch, transaction_batch),
            state,
            &transactions,
        );
        let ExecutedTransactions {
            batches: (sb, tb),
            output,
        } = executed;
        if let Some(ref callback) = self.receipt_callback {
            callback(parent.header.height + 1, output.receipts.clone());
        }
        let (state_merkleized, transaction_merkleized, receipts_root) = self
            .finalize_execution(sb, tb, &output.receipts)
            .await
            .expect("database merkleization must succeed");
        let transactions_end =
            parent.header.transactions_range.end() + transactions.len() as u64 + 1;

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
        };
        let block = Block::new(
            header,
            transactions
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
    /// account for clock skew. After the wait, it rejects any block that
    /// contains a static-invalid transaction, re-executes the block, and
    /// compares all derived roots and ranges.
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
        let state = load_state(&state_batch, &verified_block.body)
            .await
            .expect("block state loading during verification must succeed");
        let processor = Processor::new(self.strategy(), self.precompiles());
        if !processor.all_statically_valid(state.clone(), &verified_block.body) {
            warn!(
                height = block.header.height,
                "verify rejected: static validation failed"
            );
            return None;
        }
        let executed = self.execute_loaded_transactions(
            (state_batch, transaction_batch),
            state,
            &verified_block.body,
        );
        let ExecutedTransactions {
            batches: (sb, tb),
            output,
        } = executed;
        let (state_merkleized, transaction_merkleized, receipts_root) = self
            .finalize_execution(sb, tb, &output.receipts)
            .await
            .expect("database merkleization during verification must succeed");
        let transactions_end = parent.header.transactions_range.end() + block.body.len() as u64 + 1;

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
        let state = load_state(&state_batch, &verified_block.body)
            .await
            .expect("certified block state loading must succeed");
        let executed = self.execute_loaded_transactions(
            (state_batch, transaction_batch),
            state,
            &verified_block.body,
        );
        let ExecutedTransactions {
            batches: (sb, tb),
            output,
        } = executed;
        if let Some(ref callback) = self.receipt_callback {
            callback(block.header.height, output.receipts.clone());
        }
        let (state_merkleized, transaction_merkleized, _) = self
            .finalize_execution(sb, tb, &output.receipts)
            .await
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
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{Application, WireBlock};
    use crate::processor::{Frame, FrameError, Precompiles, Processor};
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Round, View},
    };
    use commonware_cryptography::{Digest, Signer, blake3, ed25519, secp256r1::recoverable};
    use commonware_parallel::{Sequential, Strategy};
    use commonware_runtime::{Runner as _, buffer::paged::CacheRef, deterministic};
    use commonware_storage::{
        journal::contiguous::variable::Config as VariableJournalConfig,
        mmr::journaled::Config as MmrConfig,
        qmdb::immutable::{Config as ImmutableConfig, Immutable},
        translator::EightCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sync::AsyncRwLock};
    use constantinople_primitives::{
        Address, Block, BlockCfg, Header, Sealable, SignedTransaction, Transaction,
        VerifiedTransaction,
    };
    use core::marker::PhantomData;
    use std::sync::Arc;

    const NAMESPACE: &[u8] = b"application-test";

    type TestContext = deterministic::Context;
    type TestHasher = blake3::Blake3;
    type TestPublicKey = recoverable::PublicKey;
    type TestTransaction = VerifiedTransaction<TestPublicKey, TestHasher>;
    type TestTransactionDb =
        Arc<AsyncRwLock<Immutable<TestContext, blake3::Digest, (), TestHasher, EightCap>>>;
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

        fn execute<S>(
            &self,
            _address: Address,
            _frame: &mut Frame<'_>,
            _processor: &Processor<'_, S, Self>,
        ) -> Result<Bytes, FrameError>
        where
            S: Strategy,
        {
            Err(FrameError::InvalidTransactionTarget)
        }
    }

    fn transaction_db_config(suffix: &str, context: &TestContext) -> ImmutableConfig<EightCap, ()> {
        let page_cache = CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11));
        ImmutableConfig {
            mmr: MmrConfig {
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

    async fn open_transaction_db(context: TestContext, suffix: &str) -> TestTransactionDb {
        let db = Immutable::init(context.clone(), transaction_db_config(suffix, &context))
            .await
            .expect("transaction db init should succeed");
        Arc::new(AsyncRwLock::new(db))
    }

    fn signed_transaction(nonce: u64) -> TestTransaction {
        let private_key = recoverable::PrivateKey::from_seed(7);
        Transaction {
            sender: private_key.public_key(),
            to: Address::EMPTY,
            input: Bytes::new(),
            value: 0,
            nonce,
            access_list: Vec::new(),
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
            access_list: Vec::new(),
            _digest: PhantomData,
        }
        .seal_and_sign_verified(&private_key, NAMESPACE, &mut TestHasher::default())
    }

    fn verify_test_header(
        leader: VerifyTestPublicKey,
        transactions: usize,
    ) -> Header<blake3::Digest, blake3::Digest, VerifyTestPublicKey> {
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
}
