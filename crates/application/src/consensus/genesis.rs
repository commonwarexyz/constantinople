//! Genesis block construction.

use super::db::{StateSyncTarget, TransactionHistoryTarget};
use commonware_consensus::{
    simplex::types::Context,
    types::{Round, View},
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::non_empty_range;
use constantinople_primitives::{Block, Header, Sealable, SealedBlock};

/// Creates the genesis block.
pub fn genesis_block<C, P, H>(
    hasher: &mut H,
    leader: P,
    timestamp: u64,
    state_target: StateSyncTarget<H::Digest>,
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
        state_root: state_target.root,
        state_range: non_empty_range!(*state_target.range.start(), *state_target.range.end()),
        transactions_root: transactions_target.root,
        transactions_range: non_empty_range!(0, *transactions_target.leaf_count),
    };

    Block::<C, P, H>::new(header, Vec::new()).seal(hasher)
}
