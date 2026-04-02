#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
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
    fn propose(
        &mut self,
        parent: &Header<C, H::Digest, P>,
        context: &Context<C, P>,
    ) -> impl Future<Output = Vec<VerifiedTransaction<P, H>>> + Send;
}

#[cfg(feature = "mocks")]
pub mod mocks;
