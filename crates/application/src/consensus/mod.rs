//! Consensus-facing application integration.
//!
//! This module is the boundary between consensus and the application state
//! transition. Consensus supplies candidate or certified block bodies; the
//! application prepares those bodies into account transfers, executes them
//! against QMDB-backed state, appends transaction-history entries, and returns
//! the commitments consensus proposes, verifies, or applies.
//!
//! Account execution is based on block-start state. A sender spends only the
//! balance it had at the start of the block, and credits created by the same
//! block cannot fund later debits in that block. The executor therefore builds
//! deterministic account effects first, then applies those effects to loaded
//! accounts all or nothing.
//!
//! The executor builds one account-touch plan for each block. Transfers whose
//! non-self sender/recipient accounts are unique in the block stay on a discrete
//! lane and can write their sender and recipient accounts directly. Transfers
//! that touch contended accounts go through the general account-owned lane: each
//! affected account is loaded once, receives its accumulated nonce/debit/credit
//! effect, and writes once. If any lane fails a nonce check, balance check, or
//! checked credit addition, the whole block body is invalid and no partial state
//! is applied.
//!
//! Touched accounts are staged out of the unordered state QMDB in one read,
//! and final account values are recorded against the staged read indices, so
//! merkleization reuses each key's resolved location. The state commitment
//! depends on the final key/value set. Transaction history is append-only, so
//! transaction digests are still appended in block order.

use commonware_cryptography::{Digest, Hasher, PublicKey, ed25519};
use commonware_glue::dkg::types::Payload;
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Storage,
    telemetry::metrics::{Counter, MetricsExt},
};
use commonware_utils::ordered::Map;
use constantinople_primitives::{PublicKeyCache, SealedBlock};
use std::{
    future::Future, marker::PhantomData, net::SocketAddr, num::NonZeroU64, pin::Pin, sync::Arc,
};

mod body;
mod committee;
mod db;
mod execution;
mod genesis;
mod glue;
mod history;
mod lifecycle;
#[cfg(test)]
mod tests;
mod time;

pub use committee::{
    BLOCKS_PER_EPOCH, Committee, MAX_COMMITTEE_SIZE, committee_for_epoch, seed_committees,
};
pub use db::{
    CommitteeBatch, CommitteeDatabase, CommitteeDb, CommitteeOperation, CommitteeSyncTarget,
    Databases, StateBatch, StateDatabase, StateStaged, StateSyncTarget, StateUpdates,
    TransactionDatabase, TransactionHistoryDb, TransactionHistoryOperation,
    TransactionHistoryTarget,
};
pub use execution::{compute, prepare_signed};
pub use genesis::{genesis_block, genesis_block_with_parent};

type FinalizedHookFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
pub type FinalizedHookFn<E, C, H, P, R, St> = Arc<
    dyn for<'a> Fn(
            &'a SealedBlock<C, P, H, R>,
            &'a Databases<E, H, commonware_storage::translator::EightCap, St>,
        ) -> FinalizedHookFuture<'a>
        + Send
        + Sync,
>;
type Result<T> = core::result::Result<T, &'static str>;

const INVALID_SIGNATURE: &str = "invalid signature";
const MALFORMED_TRANSACTION: &str = "malformed transaction";
const STATIC_INVALID_TRANSACTION: &str = "statically invalid transaction";

/// Core Constantinople application.
pub struct Application<E, H, C, S, P, I, R, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    St: Strategy,
{
    strategy: St,
    genesis_leader: P,
    genesis_parent: C,
    transaction_namespace: &'static [u8],
    public_key_cache: PublicKeyCache,
    genesis_state_target: StateSyncTarget<H::Digest>,
    genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
    genesis_committee_target: CommitteeSyncTarget<H::Digest>,
    genesis_payload: R,
    eligible_peers_root: H::Digest,
    blocks_per_epoch: NonZeroU64,
    initial_committee: Committee,
    initial_next_committee: Committee,
    finalized_hook: Option<FinalizedHookFn<E, C, H, P, R, St>>,
    proposed_transactions: Counter,
    _marker: PhantomData<(E, C, S, I)>,
}

impl<E, H, C, S, P, I, R, St> Clone for Application<E, H, C, S, P, I, R, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    P: Clone,
    R: Clone,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            strategy: self.strategy.clone(),
            genesis_leader: self.genesis_leader.clone(),
            genesis_parent: self.genesis_parent,
            transaction_namespace: self.transaction_namespace,
            public_key_cache: self.public_key_cache.clone(),
            genesis_state_target: self.genesis_state_target.clone(),
            genesis_transactions_target: self.genesis_transactions_target.clone(),
            genesis_committee_target: self.genesis_committee_target.clone(),
            genesis_payload: self.genesis_payload.clone(),
            eligible_peers_root: self.eligible_peers_root,
            blocks_per_epoch: self.blocks_per_epoch,
            initial_committee: self.initial_committee.clone(),
            initial_next_committee: self.initial_next_committee.clone(),
            finalized_hook: self.finalized_hook.clone(),
            proposed_transactions: self.proposed_transactions.clone(),
            _marker: PhantomData,
        }
    }
}

impl<E, H, C, S, P, I, V, D, Dir, St> Application<E, H, C, S, P, I, Payload<V, D, Dir>, St>
where
    H: Hasher,
    E: BufferPooler + Storage + Clock + Metrics,
    C: Digest,
    P: PublicKey,
    V: commonware_cryptography::bls12381::primitives::variant::Variant,
    D: commonware_cryptography::Signer<PublicKey = ed25519::PublicKey>,
    Dir: commonware_glue::dkg::network::Directory<ed25519::PublicKey>,
    St: Strategy,
{
    /// Creates an application.
    #[expect(
        clippy::too_many_arguments,
        clippy::type_complexity,
        reason = "the engine constructs the application from already grouped config"
    )]
    pub fn new(
        context: impl Metrics,
        strategy: St,
        genesis_leader: P,
        genesis_parent: C,
        transaction_namespace: &'static [u8],
        public_key_cache: PublicKeyCache,
        genesis_state_target: StateSyncTarget<H::Digest>,
        genesis_transactions_target: TransactionHistoryTarget<H::Digest>,
        genesis_committee_target: CommitteeSyncTarget<H::Digest>,
        genesis_info: commonware_glue::dkg::types::EpochInfo<V, ed25519::PublicKey, Dir>,
        eligible_peers_root: H::Digest,
        blocks_per_epoch: NonZeroU64,
        initial_peer_addresses: Map<ed25519::PublicKey, SocketAddr>,
        finalized_hook: Option<FinalizedHookFn<E, C, H, P, Payload<V, D, Dir>, St>>,
    ) -> Self {
        let proposed_transactions = context.counter(
            "proposed_transactions",
            "The number of transactions proposed into blocks",
        );
        let initial_committee = Committee::new(Map::from_iter_dedup(
            genesis_info.players.iter().map(|peer| {
                (
                    peer.clone(),
                    *initial_peer_addresses
                        .get_value(peer)
                        .expect("genesis player must have an initial address"),
                )
            }),
        ))
        .expect("genesis players must form a valid committee");
        let initial_next_committee = Committee::new(Map::from_iter_dedup(
            genesis_info.next_players.iter().map(|peer| {
                (
                    peer.clone(),
                    *initial_peer_addresses
                        .get_value(peer)
                        .expect("genesis next player must have an initial address"),
                )
            }),
        ))
        .expect("genesis next players must form a valid committee");

        Self {
            strategy,
            genesis_leader,
            genesis_parent,
            transaction_namespace,
            public_key_cache,
            genesis_state_target,
            genesis_transactions_target,
            genesis_committee_target,
            genesis_payload: Payload::EpochInfo(genesis_info),
            eligible_peers_root,
            blocks_per_epoch,
            initial_committee,
            initial_next_committee,
            finalized_hook,
            proposed_transactions,
            _marker: PhantomData,
        }
    }
}

fn reject_verify(height: u64, reason: &'static str) {
    tracing::warn!(height, reason, "application.verify.reject");
}
