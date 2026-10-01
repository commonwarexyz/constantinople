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
    /// `filled` is the sum of encoded signed transaction sizes already in the
    /// proposal. The implementation must stay within its transaction byte
    /// budget minus `filled`, including for an empty proposal. This budget
    /// excludes block framing, which callers must reserve separately.
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
