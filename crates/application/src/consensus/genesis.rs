//! Genesis block construction.

use super::db::{CommitteeSyncTarget, StateSyncTarget, TransactionHistoryTarget};
use commonware_consensus::{
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};

/// Creates the genesis block.
pub fn genesis_block<C, P, H, R>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
    state_target: StateSyncTarget<H::Digest>,
    transactions_target: TransactionHistoryTarget<H::Digest>,
    committee_target: CommitteeSyncTarget<H::Digest>,
    payload: R,
) -> SealedBlock<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: commonware_codec::Write + commonware_codec::EncodeSize,
{
    genesis_block_with_parent(
        hasher,
        leader,
        (View::zero(), C::EMPTY),
        timestamp,
        state_target,
        transactions_target,
        committee_target,
        payload,
    )
}

/// Creates the genesis block with an explicit consensus parent.
pub fn genesis_block_with_parent<C, P, H, R>(
    hasher: &mut H,
    leader: P,
    parent: (View, C),
    timestamp: u64,
    state_target: StateSyncTarget<H::Digest>,
    transactions_target: TransactionHistoryTarget<H::Digest>,
    committee_target: CommitteeSyncTarget<H::Digest>,
    payload: R,
) -> SealedBlock<C, P, H, R>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
    R: commonware_codec::Write + commonware_codec::EncodeSize,
{
    let header = Header {
        context: Context {
            round: Round::zero(),
            leader,
            parent,
        },
        parent: H::Digest::EMPTY,
        height: 0,
        timestamp,
        state_root: state_target.root,
        state_range: non_empty_range!(*state_target.range.start(), *state_target.range.end()),
        transactions_root: transactions_target.root,
        transactions_range: non_empty_range!(0, *transactions_target.leaf_count),
        committee_root: committee_target.root,
        committee_range: non_empty_range!(
            *committee_target.range.start(),
            *committee_target.range.end()
        ),
        payload: Some(payload),
    };

    Block::<C, P, H, R>::new(header, Vec::new()).seal(hasher)
}
