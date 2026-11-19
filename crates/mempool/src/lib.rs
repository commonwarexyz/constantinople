#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use commonware_consensus::{Reporter, marshal::Update, types::Round};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_auth::Tags;
use constantinople_primitives::{Header, SealedBlock, VerifiedTransaction};
use std::future::Future;

/// A transaction a proposer may put in its block.
#[derive(Debug)]
pub struct Candidate<H: Hasher> {
    /// The transaction. If it carries a signature, the signature was verified.
    pub transaction: VerifiedTransaction<H>,
    /// For a transaction of an X25519 account, the authenticator its sender
    /// submitted to this validator: one tag per validator. The proposer sends
    /// each validator its tag when it proposes the transaction.
    pub authenticator: Option<Tags>,
}

impl<H: Hasher> Clone for Candidate<H> {
    fn clone(&self) -> Self {
        Self {
            transaction: self.transaction.clone(),
            authenticator: self.authenticator.clone(),
        }
    }
}

impl<H: Hasher> From<VerifiedTransaction<H>> for Candidate<H> {
    fn from(transaction: VerifiedTransaction<H>) -> Self {
        Self {
            transaction,
            authenticator: None,
        }
    }
}

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
    /// `filled` is the number of bytes of the transaction byte budget that the
    /// proposal already uses. The implementation must stay within its budget
    /// minus `filled`, including for an empty proposal. This budget excludes
    /// block framing, which callers must reserve separately.
    fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        round: Round,
        filled: usize,
    ) -> impl Future<Output = Vec<Candidate<H>>> + Send;
}

#[cfg(feature = "mocks")]
pub mod mocks;

pub mod webserver;
