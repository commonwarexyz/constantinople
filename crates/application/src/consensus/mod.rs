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
use commonware_codec::types::lazy::Lazy;
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
    db::{DatabaseSet, Merkleized as _, Unmerkleized, any::AnyUnmerkleized, p2p},
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
        sync::Target,
    },
    translator::EightCap,
};
use commonware_utils::{non_empty_range, sync::AsyncRwLock};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{
    Account, Address, Block, Header, Sealable, SealedBlock, SignedTransaction, VerifiedTransaction,
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
use constantinople_primitives::{verify_transaction_batch, verify_transaction_chunks};
pub use utils::load_state;

/// Fixed consensus cutoff for block timestamps: 2200-01-01T00:00:00Z.
///
/// Different platforms have different `SystemTime` limits, so we use a fixed
/// timestamp to ensure consistent application of block validity rules.
const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Shared QMDB handle for the application state database.
type StateDatabase<E, H, T> = Arc<AsyncRwLock<fixed::Db<mmr::Family, E, Address, Account, H, T>>>;

pub type TransactionHistoryDb<E, H> = keyless_fixed::Db<mmr::Family, E, <H as Hasher>::Digest, H>;

pub type TransactionHistoryOperation<H> =
    keyless_fixed::Operation<mmr::Family, <H as Hasher>::Digest>;

pub type TransactionHistoryTarget<D> = Target<mmr::Family, D>;

pub type TransactionHistoryResolverMailbox<E, H> = p2p::Mailbox<
    TransactionHistoryDb<E, H>,
    mmr::Family,
    TransactionHistoryOperation<H>,
    <H as Hasher>::Digest,
>;

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
    transactions: &[VerifiedTransaction<P, H>],
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

fn transaction_range_to_header(
    range: commonware_utils::range::NonEmptyRange<mmr::Location>,
) -> commonware_utils::range::NonEmptyRange<u64> {
    non_empty_range!(*range.start(), *range.end())
}

fn header_range_to_target<D>(
    root: D,
    range: commonware_utils::range::NonEmptyRange<u64>,
) -> TransactionHistoryTarget<D>
where
    D: Digest,
{
    TransactionHistoryTarget {
        root,
        range: non_empty_range!(
            mmr::Location::new(range.start()),
            mmr::Location::new(range.end())
        ),
    }
}

fn block_transaction_prune_due(height: u64, cadence: Option<NonZeroU64>) -> bool {
    cadence.is_some_and(|cadence| height % cadence.get() == 0)
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

    /// Verifies lazily-encoded signed transactions and returns verified
    /// execution transactions.
    ///
    /// Forcing each [`Lazy`] materializes the underlying
    /// [`SignedTransaction`] (including recomputing its seal digest); the
    /// chunked path spreads that cost across the configured
    /// [`Strategy`]'s worker threads.
    fn verify_transactions(
        &self,
        rng: &mut impl CryptoRngCore,
        transactions: Vec<Lazy<SignedTransaction<P, H>>>,
    ) -> Option<Vec<VerifiedTransaction<P, H>>> {
        let parallelism = self.strategy.parallelism_hint();
        if parallelism <= 1 || transactions.len() <= parallelism {
            if !verify_transaction_batch::<P, H, B>(self.transaction_namespace, rng, &transactions)
            {
                return None;
            }
            return transactions
                .into_iter()
                .map(|lazy| lazy.get().cloned().map(Into::into))
                .collect();
        }

        verify_transaction_chunks::<P, H, B, _>(
            &self.strategy,
            self.transaction_namespace,
            rng,
            transactions,
        )
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

    async fn finalize_execution<E>(
        &self,
        state_batch: StateBatch<E, H, EightCap>,
        transaction_batch: TransactionBatch<E, H>,
    ) -> Result<
        (StateMerkleized<E, H, EightCap>, TransactionMerkleized<E, H>),
        commonware_storage::qmdb::Error<mmr::Family>,
    >
    where
        E: Storage + Clock + Metrics,
    {
        let (state_merkleized, transaction_merkleized) =
            futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
        Ok((state_merkleized?, transaction_merkleized?))
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

        let (state_batches, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(&state_batches, &body)
            .await
            .expect("proposal state loading must succeed");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let ProposalOutput {
            valid,
            invalid: _,
            changeset,
        } = executor::propose(&state, body);
        let execute_ms = execute_started_at.elapsed().as_millis();

        self.proposed_transactions.inc_by(valid.len() as u64);

        let state_batch = apply_changeset(state_batches, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &valid)
            .with_inactivity_floor(parent_transactions_inactivity_floor(&parent));

        let finalize_started_at = Instant::now();
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
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
            transactions_range: transaction_range_to_header(non_empty_range!(
                transaction_merkleized.inactivity_floor(),
                transaction_merkleized.size()
            )),
        };
        let body = valid
            .into_iter()
            .map(VerifiedTransaction::into_inner)
            .collect();
        let block = Block::new(header, body).seal(&mut H::default());

        info!(
            epoch = block.header.context.round.epoch().get(),
            view = block.header.context.round.view().get(),
            height = block.header.height,
            txs = block.body.len(),
            timestamp = block.header.timestamp,
            input_ms,
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
        (mut runtime, _context): (E, Self::Context),
        mut ancestry: AncestorStream<A, Self::Block>,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> Option<<Self::Databases as DatabaseSet<E>>::Merkleized> {
        let verify_started_at = Instant::now();
        let Block { header, body } = ancestry.next().await?.into_inner();
        let parent = ancestry.next().await?;

        let signature_started_at = Instant::now();
        let Some(verified_body) = self.verify_transactions(&mut runtime, body) else {
            warn!(height = header.height, "verify rejected: invalid signature");
            return None;
        };
        let signature_ms = signature_started_at.elapsed().as_millis();

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

        // Wait until the block timestamp has passed to vote in case of skew.
        let deadline = self.block_deadline(header.timestamp);
        let sleep_started_at = Instant::now();
        runtime.sleep_until(deadline).await;
        let sleep_ms = sleep_started_at.elapsed().as_millis();

        let (state_batches, transaction_batch) = batches;

        let load_state_started_at = Instant::now();
        let state = load_state(&state_batches, &verified_body)
            .await
            .expect("block state loading during verification must succeed");
        let load_state_ms = load_state_started_at.elapsed().as_millis();

        let execute_started_at = Instant::now();
        let Some(changeset) = executor::execute(&state, &verified_body) else {
            warn!(
                height = header.height,
                "verify rejected: statically invalid transaction"
            );
            return None;
        };
        let execute_ms = execute_started_at.elapsed().as_millis();

        let state_batch = apply_changeset(state_batches, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &verified_body)
            .with_inactivity_floor(parent_transactions_inactivity_floor(&parent));

        let finalize_started_at = Instant::now();
        let (state_merkleized, transaction_merkleized) = self
            .finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization during verification must succeed");
        let finalize_ms = finalize_started_at.elapsed().as_millis();

        let state_range = non_empty_range!(
            *state_merkleized.inactivity_floor(),
            *state_merkleized.size()
        );

        if state_merkleized.root() != header.state_root {
            warn!(
                height = header.height,
                "verify rejected: state root mismatch"
            );
            return None;
        }
        if state_range != header.state_range {
            warn!(
                height = header.height,
                "verify rejected: state range mismatch"
            );
            return None;
        }
        if transaction_merkleized.root() != header.transactions_root {
            warn!(
                height = header.height,
                "verify rejected: transaction root mismatch"
            );
            return None;
        }
        if transaction_range_to_header(non_empty_range!(
            transaction_merkleized.inactivity_floor(),
            transaction_merkleized.size()
        )) != header.transactions_range
        {
            warn!(
                height = header.height,
                "verify rejected: transaction range mismatch"
            );
            return None;
        }

        info!(
            epoch = header.context.round.epoch().get(),
            view = header.context.round.view().get(),
            height = header.height,
            txs = verified_body.len(),
            timestamp = header.timestamp,
            signature_ms,
            sleep_ms,
            load_state_ms,
            execute_ms,
            finalize_ms,
            total_ms = verify_started_at.elapsed().as_millis(),
            "verified block"
        );
        Some((state_merkleized, transaction_merkleized))
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
        (mut runtime, _): (E, Self::Context),
        block: &Self::Block,
        batches: <Self::Databases as DatabaseSet<E>>::Unmerkleized,
    ) -> <Self::Databases as DatabaseSet<E>>::Merkleized {
        let verified_body = self
            .verify_transactions(&mut runtime, block.body.clone())
            .expect("certified block contained an invalid signature");

        let (state_batches, transaction_batch) = batches;

        let state = load_state(&state_batches, &verified_body)
            .await
            .expect("state loading must succeed for certified apply");
        let changeset = executor::execute(&state, &verified_body)
            .expect("certified block contained a statically invalid transaction");
        let state_batch = apply_changeset(state_batches, &changeset);
        let transaction_batch = apply_transaction_digests(transaction_batch, &verified_body)
            .with_inactivity_floor(mmr::Location::new(block.header.transactions_range.start()));
        self.finalize_execution(state_batch, transaction_batch)
            .await
            .expect("database merkleization must succeed")
    }

    async fn finalized(
        &mut self,
        _context: (E, Self::Context),
        block: &Self::Block,
        databases: &Self::Databases,
    ) {
        if !block_transaction_prune_due(block.header.height, self.transaction_history_prune_cadence)
        {
            return;
        }

        let mut transaction_db = databases.1.write().await;
        let prune_to = transaction_db.inactivity_floor_loc();
        transaction_db
            .prune(prune_to)
            .await
            .expect("transaction history prune must succeed");
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
        transactions_range: transaction_range_to_header(transactions_target.range),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}

#[cfg(test)]
mod tests {
    use super::{
        TransactionHistoryTarget, block_transaction_prune_due, genesis_block,
        parent_transactions_inactivity_floor,
    };
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
            range: non_empty_range!(
                commonware_storage::mmr::Location::new(0),
                commonware_storage::mmr::Location::new(1)
            ),
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
    fn block_prune_due_respects_the_configured_cadence() {
        let cadence = NonZeroU64::new(4);
        assert!(!block_transaction_prune_due(3, cadence));
        assert!(block_transaction_prune_due(4, cadence));
        assert!(!block_transaction_prune_due(5, cadence));
        assert!(!block_transaction_prune_due(4, None));
    }

    #[test]
    fn genesis_block_uses_the_initialized_transaction_target() {
        let leader = ed25519::PrivateKey::from_seed(11).public_key();
        let target = TransactionHistoryTarget {
            root: sha256::Sha256::hash(b"genesis"),
            range: non_empty_range!(
                commonware_storage::mmr::Location::new(0),
                commonware_storage::mmr::Location::new(1)
            ),
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
