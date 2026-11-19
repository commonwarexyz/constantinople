//! What the application needs from the consensus engine around it.

use commonware_consensus::types::Round;
use commonware_cryptography::{Digest, Hasher, PublicKey};
use constantinople_auth::Tags;
use constantinople_primitives::{ParentNotarization, SealedBlock};
use std::{future::Future, sync::Arc};

/// The application's view of the chain beyond the blocks it is handed.
///
/// Executing a block needs two things the block's ancestry does not supply. A
/// proposer puts a notarization of the parent in its block, and only the
/// consensus engine sees notarizations. Replaying a finalized block applies the
/// parent's transactions, and the replay is handed the block alone.
///
/// A proposer also learns the tags of the transactions it includes, which travel
/// outside the block: it hands them back through [`Chain::built`].
pub trait Chain<C, P, H>: Clone + Send + Sync + 'static
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// A notarization of the block with commitment `payload` that was proposed
    /// in `round`, if this node holds one.
    fn notarization(
        &self,
        round: Round,
        payload: C,
    ) -> impl Future<Output = Option<ParentNotarization<C>>> + Send;

    /// Records the authenticators of the transactions authenticated by tags in
    /// the block with digest `block`, which this node just built. They are in
    /// the order of those transactions in the block.
    fn built(&self, block: H::Digest, authenticators: Vec<Tags>);

    /// The parent of `block`, a finalized block that is being replayed.
    ///
    /// Resolves to `None` if the parent can never be supplied.
    fn parent(
        &self,
        block: &SealedBlock<C, P, H>,
    ) -> impl Future<Output = Option<Arc<SealedBlock<C, P, H>>>> + Send;
}
