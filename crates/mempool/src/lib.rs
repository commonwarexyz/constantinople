#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use commonware_consensus::{Reporter, marshal::Update, types::Round};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use std::future::Future;

/// Supplies transactions for block proposals and finalized block updates.
pub trait TransactionSource<C, P, H>:
    Reporter<Activity = Update<SealedBlock<C, P, H>>> + Send + 'static
where
    C: Digest,
    H: Hasher,
    P: PublicKey,
{
    /// Returns the transactions to include in the next proposal.
    ///
    /// `round` is the consensus round the proposal targets. Speculative
    /// pre-builds call this before the round is entered, so implementations
    /// must not assume the round is live.
    ///
    /// `filled` is the encoded size of the transactions the proposal already
    /// holds: the implementation serves at most its proposal budget minus
    /// `filled`. A refill for a partially built block (`filled > 0`) must
    /// never overshoot that headroom; an initial selection (`filled == 0`)
    /// may overshoot by one entry so an oversized head entry cannot wedge
    /// the queue.
    fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        round: Round,
        filled: usize,
    ) -> impl Future<Output = Vec<VerifiedTransaction<H>>> + Send;
}

#[cfg(feature = "mocks")]
pub mod mocks;

pub mod webserver;
