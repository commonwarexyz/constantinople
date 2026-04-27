//! Consensus-facing application integration.
//!
//! This module bridges consensus, the mempool, the processor, and the backing
//! databases. It is responsible for:
//!
//! - proposing blocks from mempool transactions
//! - filtering or rejecting invalid signatures before execution
//! - loading processor state from speculative database batches
//! - executing transaction slices against that loaded state
//! - finalizing state and transaction-history roots together
//! - verifying and applying certified blocks
//!
//! The execution boundary is intentionally narrow: the [`Application`] owns
//! the execution strategy and QMDB integration, while the processor owns the
//! in-memory state transition logic.

use crate::processor::executor::{self, Changeset, ProposalOutput};
use commonware_consensus::{
    marshal::ancestry::{AncestorStream, BlockProvider},
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{
    BatchVerifier, Digest, Digestible, Hasher, PublicKey, certificate::Scheme,
};
use commonware_glue::stateful::{
    Application as CApplication, Proposed,
    db::{DatabaseSet, Merkleized as _, Unmerkleized, any::AnyUnmerkleized},
};
use commonware_parallel::Strategy;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    index::unordered::Index as UnorderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr,
    qmdb::{
        any::{
            operation::Operation as AnyOperation,
            unordered::{Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        keyless::fixed as keyless_fixed,
        sync::{Target, compact::Target as CompactTarget},
    },
    translator::EightCap,
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Account, Address, Block, Header, Sealable, SealedBlock, SignedTransaction,
};
use futures::StreamExt;
use prometheus_client::metrics::counter::Counter;
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{
    marker::PhantomData,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

mod utils;
mod verification;
use constantinople_primitives::transaction_senders;
pub use utils::load_state;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Shared QMDB handle for the application state database.
type StateDatabase<E, H, T> = Arc<AsyncRwLock<fixed::Db<mmr::Family, E, Address, Account, H, T>>>;

pub type TransactionHistoryDb<E, H> =
    keyless_fixed::CompactDb<mmr::Family, E, <H as Hasher>::Digest, H>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type TransactionHistoryTarget<D> = CompactTarget<mmr::Family, D>;

/// Shared QMDB handle for the append-only transaction history database.
type TransactionDatabase<E, H> = Arc<AsyncRwLock<TransactionHistoryDb<E, H>>>;

/// The backing databases owned by the application.
type Databases<E, H, T> = (StateDatabase<E, H, T>, TransactionDatabase<E, H>);

/// Unmerkleized application state batch used for processor read-through.
type StateBatch<E, H, T> = AnyUnmerkleized<
    mmr::Family,
    E,
    FixedJournal<E, AnyOperation<mmr::Family, UnorderedUpdate<Address, FixedEncoding<Account>>>>,
    UnorderedIndex<T, mmr::Location>,
    H,
    UnorderedUpdate<Address, FixedEncoding<Account>>,
>;

type TransactionBatch<E, H> = <TransactionDatabase<E, H> as DatabaseSet<E>>::Unmerkleized;

type StateMerkleized<E, H, T> = <StateBatch<E, H, T> as Unmerkleized>::Merkleized;

type TransactionMerkleized<E, H> = <TransactionBatch<E, H> as Unmerkleized>::Merkleized;

/// Writes a changeset of account updates to a state batch.
fn apply_changeset<E, H>(
    batch: StateBatch<E, H, EightCap>,
    changeset: &Changeset,
) -> StateBatch<E, H, EightCap>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    changeset.iter().fold(batch, |batch, (address, account)| {
        batch.write(*address, Some(*account))
    })
}

fn apply_transaction_digests<E, H, P>(
    batch: TransactionBatch<E, H>,
    transactions: &[SignedTransaction<P, H>],
) -> TransactionBatch<E, H>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
    P: PublicKey,
{
    transactions.iter().fold(batch, |batch, transaction| {
        batch.append(*transaction.message_digest())
    })
}

const fn header_range_to_target<D>(
    root: D,
    range: commonware_utils::range::NonEmptyRange<u64>,
) -> TransactionHistoryTarget<D>
where
    D: Digest,
{
    TransactionHistoryTarget {
        root,
        leaf_count: mmr::Location::new(range.end()),
    }
}

fn parent_transactions_inactivity_floor<C, P, H>(parent: &SealedBlock<C, P, H>) -> mmr::Location
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let parent_body_len = u64::try_from(parent.body.len()).expect("transaction count exceeded u64");
    let floor = parent
        .header
        .transactions_range
        .end()
        .checked_sub(parent_body_len)
        .and_then(|end| end.checked_sub(1))
        .expect("parent transaction range must include the parent commit");
    mmr::Location::new(floor)
}

fn child_transactions_range<C, P, H>(
    parent: &SealedBlock<C, P, H>,
    transaction_count: usize,
) -> commonware_utils::range::NonEmptyRange<u64>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    let transaction_count =
        u64::try_from(transaction_count).expect("transaction count exceeded u64");
    let end = parent
        .header
        .transactions_range
        .end()
        .checked_add(transaction_count)
        .and_then(|end| end.checked_add(1))
        .expect("transaction history size exceeded u64");
    non_empty_range!(*parent_transactions_inactivity_floor(parent), end)
}

async fn finalize_execution<E, H>(
    state_batch: StateBatch<E, H, EightCap>,
    transaction_batch: TransactionBatch<E, H>,
) -> Result<
    (StateMerkleized<E, H, EightCap>, TransactionMerkleized<E, H>),
    commonware_storage::qmdb::Error<mmr::Family>,
>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    let (state_merkleized, transaction_merkleized) =
        futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
    Ok((state_merkleized?, transaction_merkleized?))
}

/// Core constantinople application.
///
/// This type implements the consensus application trait on top of the
/// processor and the managed state databases.
pub struct Application<H, C, S, P, I, B, St>
where
    H: Hasher,
{
    strategy: St,
    genesis_leader: P,
    transaction_namespace: &'static [u8],
    genesis_transactions_target: TransactionHistoryTarget<<H as Hasher>::Digest>,
    transaction_history_prune_cadence: Option<NonZeroU64>,
    proposed_transactions: Counter,
    _marker: PhantomData<(H, C, S, I, B)>,
}

impl<H, C, S, P, I, B, St> Clone for Application<H, C, S, P, I, B, St>
where
    H: Hasher,
    P: Clone,
    St: Clone,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            transaction_namespace: self.transaction_namespace,
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            transaction_history_prune_cadence: self.transaction_history_prune_cadence,
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<H, C, S, P, I, B, St> Application<H, C, S, P, I, B, St>
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
    B: BatchVerifier<PublicKey = P>,
    St: Strategy,
{
    /// Creates an application.
    ///
    /// The application keeps the execution strategy, genesis leader, and
    /// transaction signing namespace for all later block proposal,
    /// verification, and application.
    pub fn new(
        context: impl Metrics,
        strategy: St,
        genesis_leader: P,
        transaction_namespace: &'static [u8],
        genesis_transactions_target: TransactionHistoryTarget<<H as Hasher>::Digest>,
        transaction_history_prune_cadence: Option<NonZeroU64>,
    ) -> Self {
        let proposed_transactions = Counter::default();
        context.register(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
            proposed_transactions.clone(),
        );

        Self {
            strategy,
            genesis_leader,
            transaction_namespace,
            genesis_transactions_target,
            transaction_history_prune_cadence,
            proposed_transactions,
            _marker: PhantomData,
        }
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
}

impl<E, H, C, S, P, I, B, St> CApplication<E> for Application<H, C, S, P, I, B, St>
where
    E: Rng + Spawner + Storage + Metrics + Clock + CryptoRngCore,
    H: Hasher,
    C: Digest,
    S: Scheme<PublicKey = P>,
    P: PublicKey,
    I: TransactionSource<C, P, H> + Sync,
    B: BatchVerifier<PublicKey = P> + Send + Sync + 'static,
    St: Strategy + Clone + Send + Sync + 'static,
{
    type SigningScheme = S;
    type Context = Context<C, P>;
    type Block = SealedBlock<C, P, H>;
    type Databases = Databases<E, H, EightCap>;
    type InputProvider = I;

    /// Returns the sync targets required to fetch the block's state.
    fn sync_targets(block: &Self::Block) -> <Self::Databases as DatabaseSet<E>>::SyncTargets {
        (
            Target {
                root: block.header.state_root,
                range: non_empty_range!(
                    mmr::Location::new(block.header.state_range.start()),
                    mmr::Location::new(block.header.state_range.end())
                ),
            },
            header_range_to_target(
                block.header.transactions_root,
                block.header.transactions_range.clone(),
            ),
        )
    }

    /// Builds the genesis block.
    ///
    /// The genesis block always uses timestamp `0` and the configured genesis
    /// leader.
    async fn genesis(&mut self) -> Self::Block {
        genesis_block(
            &mut H::default(),
            self.genesis_leader.clone(),
            0,
            self.genesis_transactions_target.clone(),
        )
    }

    /// Proposes the next block from the mempool and current ancestry.
    ///
    /// Proposal consumes already-verified mempool transactions, preloads the
    /// touched accounts, filters out statically invalid transfers, and
    /// executes the survivors against in-memory state before block
    /// construction.
    async fn propose<A: BlockProvider<Block = Self::Block>>(
        &mut self,
        (runtime, context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
        input: &mut Self::InputProvider,
    ) -> Option<Proposed<Self, E>> {
        let propose_started_at = Instant::now();
        let parent = ancestry.next().await?;

        let input_started_at = Instant::now();
        let body = input.propose(&parent.header, &context).await;
        let input_ms = input_started_at.elapsed().as_millis();

        let sender_started_at = Instant::now();
        let senders = transaction_senders(&self.strategy, &body)
            .expect("proposal transactions must have decodable senders");
        let sender_ms = sender_started_at.elapsed().as_millis();

        let (state_batches, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(&state_batches, &body, &senders)
            .await
            .expect("proposal state loading must succeed");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(&state, body, senders);
        let execute_ms = execute_started_at.elapsed().as_millis();

        self.proposed_transactions.inc_by(valid.len() as u64);

        let state_batch = apply_changeset(state_batches, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &valid)
            .with_inactivity_floor(parent_transactions_inactivity_floor(&parent));
        let transactions_range = child_transactions_range(&parent, valid.len());

        let finalize_started_at = Instant::now();
        let (state_merkleized, transaction_merkleized) =
            finalize_execution(state_batch, transaction_batch)
                .await
                .expect("database merkleization must succeed");
        let finalize_ms = finalize_started_at.elapsed().as_millis();

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
            transactions_range,
        };
        let block = Block::new(header, valid).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = block.body.len(),
            timestamp = block.header.timestamp,
            input_ms,
            sender_ms,
            load_state_ms,
            execute_ms,
            finalize_ms,
            total_ms = propose_started_at.elapsed().as_millis(),
            "proposed block"
        );

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
        let verify_started_at = Instant::now();
        let Block { header, body } = ancestry.next().await?.into_inner();
        let parent = ancestry.next().await?;

        if header.timestamp <= parent.header.timestamp || header.timestamp > MAX_BLOCK_TIMESTAMP_MS
        {
            warn!(
                height = header.height,
                block_ts = header.timestamp,
                parent_ts = parent.header.timestamp,
                "verify rejected: invalid timestamp"
            );
            return None;
        }

        let deadline = self.block_deadline(header.timestamp);
        let prepare_started_at = Instant::now();
        let prepared = match verification::prepare_transactions(&self.strategy, body) {
            Ok(prepared) => Arc::new(prepared),
            Err(reason) => {
                verification::reject(header.height, reason);
                return None;
            }
        };
        let prepare_ms = prepare_started_at.elapsed().as_millis();

        let (state_batches, transaction_batch) = batches;
        let signature = verification::verify_signatures::<E, P, H, B, St>(
            runtime.clone(),
            self.strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&prepared),
        );
        let execution = verification::execute_block(
            state_batches,
            transaction_batch,
            &parent,
            prepared.as_ref(),
            prepare_ms,
        );
        let sleep = verification::wait_for_timestamp(runtime, deadline);

        let (signature_ms, execution, sleep_ms) =
            match futures::try_join!(signature, execution, sleep) {
                Ok(result) => result,
                Err(reason) => {
                    verification::reject(header.height, reason);
                    return None;
                }
            };

        if !verification::commitments_match(&header, &execution) {
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            txs = execution.transaction_count,
            timestamp = header.timestamp,
            signature_ms,
            sleep_ms,
            prepare_ms = execution.timings.prepare_ms,
            load_state_ms = execution.timings.load_state_ms,
            execute_ms = execution.timings.execute_ms,
            finalize_ms = execution.timings.finalize_ms,
            total_ms = verify_started_at.elapsed().as_millis(),
            "verified block"
        );
        Some(execution.into_merkleized())
    }

    /// Applies a certified block to speculative batches and returns merkleized state.
    ///
    /// Unlike verification, application assumes consensus has already
    /// certified the block. It reconstitutes verified execution transactions
    /// from the signed wire block and deterministically replays them to
    /// derive the merkleized state batch.
    ///
    /// # Panics
    ///
    /// Panics if the certified block contains an invalid signature or if
    /// execution or database finalization fails.
    async fn apply(
        &mut self,
        (runtime, _): (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let prepared = Arc::new(
            verification::prepare_transactions(&self.strategy, block.body.clone())
                .unwrap_or_else(|reason| panic!("certified block contained {reason}")),
        );
        let signature = verification::verify_signatures::<E, P, H, B, St>(
            runtime,
            self.strategy.clone(),
            self.transaction_namespace,
            Arc::clone(&prepared),
        );
        let (state_batches, transaction_batch) = batches;
        let execution = verification::apply_block(
            state_batches,
            transaction_batch,
            mmr::Location::new(block.header.transactions_range.start()),
            prepared.as_ref(),
        );

        match futures::try_join!(signature, execution) {
            Ok((_signature_ms, merkleized)) => merkleized,
            Err(reason) => panic!("certified block contained {reason}"),
        }
    }
}

/// Creates the genesis block.
///
/// The genesis block starts with empty state, the initialized transaction
/// history target, and the provided leader and timestamp.
pub fn genesis_block<C, P, H>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
    transactions_target: TransactionHistoryTarget<H::Digest>,
) -> SealedBlock<C, P, H>
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
        transactions_root: transactions_target.root,
        transactions_range: non_empty_range!(0, *transactions_target.leaf_count),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{TransactionHistoryTarget, genesis_block, parent_transactions_inactivity_floor};
    use commonware_cryptography::{Digest as _, Hasher as _, Signer as _, ed25519, sha256};
    use commonware_utils::non_empty_range;
    use constantinople_primitives::{Address, Block, Sealable, Signable, Transaction};
    use std::num::NonZeroU64;

    #[test]
    fn parent_inactivity_floor_skips_the_parent_commit() {
        let leader = ed25519::PrivateKey::from_seed(7);
        let recipient = ed25519::PrivateKey::from_seed(8);
        let genesis_target = TransactionHistoryTarget {
            root: sha256::Digest::EMPTY,
            leaf_count: commonware_storage::mmr::Location::new(1),
        };
        let mut header = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader.public_key(),
            0,
            genesis_target,
        )
        .into_inner()
        .header;
        header.transactions_range = non_empty_range!(5, 10);

        let to = Address::from_public_key(&mut sha256::Sha256::default(), &recipient.public_key());
        let parent = Block::<sha256::Digest, _, sha256::Sha256>::new(
            header,
            (0..3)
                .map(|nonce| {
                    Transaction::new(
                        leader.public_key(),
                        to,
                        NonZeroU64::new(nonce + 1).expect("test value should be non-zero"),
                        nonce,
                    )
                    .seal_and_sign(
                        &leader,
                        constantinople_primitives::TRANSACTION_NAMESPACE,
                        &mut sha256::Sha256::default(),
                    )
                })
                .collect(),
        )
        .seal(&mut sha256::Sha256::default());

        assert_eq!(
            parent_transactions_inactivity_floor(&parent),
            commonware_storage::mmr::Location::new(6)
        );
    }

    #[test]
    fn genesis_block_uses_the_initialized_transaction_target() {
        let leader = ed25519::PrivateKey::from_seed(11).public_key();
        let target = TransactionHistoryTarget {
            root: sha256::Sha256::hash(b"genesis"),
            leaf_count: commonware_storage::mmr::Location::new(1),
        };

        let block = genesis_block::<sha256::Digest, _, sha256::Sha256>(
            &mut sha256::Sha256::default(),
            leader,
            0,
            target.clone(),
        );

        assert_eq!(block.header.transactions_root, target.root);
        assert_eq!(block.header.transactions_range, non_empty_range!(0, 1));
    }
}
