//! Mock transaction sources for tests.

use crate::TransactionSource;
use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_utils::Acknowledgement;
use constantinople_primitives::{Header, VerifiedTransaction};
use core::{
    future::{Future, ready},
    marker::PhantomData,
};
use std::collections::VecDeque;

/// A queue-backed transaction source for deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct StaticTransactionSource<C, P, H>
where
    P: PublicKey,
    H: Hasher,
{
    proposals: VecDeque<Vec<VerifiedTransaction<P, H>>>,
    _marker: PhantomData<C>,
}

impl<C, P, H> StaticTransactionSource<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    /// Creates a new static source from queued proposal batches.
    pub fn new(proposals: Vec<Vec<VerifiedTransaction<P, H>>>) -> Self {
        Self {
            proposals: proposals.into(),
            _marker: PhantomData,
        }
    }

    /// Appends another proposal batch to the queue.
    pub fn push(&mut self, transactions: Vec<VerifiedTransaction<P, H>>) {
        self.proposals.push_back(transactions);
    }
}

impl<C, P, H> TransactionSource<C, P, H> for StaticTransactionSource<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher + Send + 'static,
    H::Digest: Send,
{
    fn propose(
        &mut self,
        _parent: &Header<C, H::Digest, P>,
        _context: &Context<C, P>,
    ) -> impl Future<Output = Vec<VerifiedTransaction<P, H>>> + Send {
        ready(self.proposals.pop_front().unwrap_or_default())
    }
}

impl<C, P, H> Reporter for StaticTransactionSource<C, P, H>
where
    C: Digest + Send + 'static,
    P: PublicKey + Send + 'static,
    H: Hasher + Send + 'static,
{
    type Activity = Update<crate::SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Update::Block(_, acknowledgement) = activity {
            acknowledgement.acknowledge();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StaticTransactionSource;
    use crate::TransactionSource;
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest, Signer, blake3, ed25519};
    use commonware_utils::non_empty_range;
    use constantinople_primitives::{Address, Header, Transaction, VerifiedTransaction};
    use core::num::NonZeroU64;

    const NAMESPACE: &[u8] = b"mempool-test";

    fn sign_tx(
        key: &ed25519::PrivateKey,
        nonce: u64,
    ) -> VerifiedTransaction<ed25519::PublicKey, blake3::Blake3> {
        let hasher = &mut blake3::Blake3::default();
        Transaction::new(
            key.public_key(),
            Address::EMPTY,
            NonZeroU64::new(1).expect("test value should be non-zero"),
            nonce,
        )
        .seal_and_sign_verified(key, NAMESPACE, hasher)
    }

    fn test_context() -> Context<blake3::Digest, ed25519::PublicKey> {
        use commonware_math::algebra::Random;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::from_seed([3; 32]);
        let leader = ed25519::PrivateKey::random(&mut rng).public_key();
        Context {
            round: Round::new(Epoch::zero(), View::zero()),
            leader,
            parent: (View::zero(), blake3::Digest::EMPTY),
        }
    }

    #[test]
    fn static_source_drains_batches_in_order() {
        use commonware_math::algebra::Random;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::from_seed([9; 32]);
        let key = ed25519::PrivateKey::random(&mut rng);
        let tx1 = sign_tx(&key, 0);
        let tx2 = sign_tx(&key, 1);
        let mut source =
            StaticTransactionSource::<blake3::Digest, ed25519::PublicKey, blake3::Blake3>::new(
                vec![vec![tx1.clone()], vec![tx2]],
            );
        let parent = Header {
            context: test_context(),
            parent: blake3::Digest::EMPTY,
            height: 0,
            timestamp: 0,
            state_root: blake3::Digest::EMPTY,
            state_range: non_empty_range!(0, 1),
            transactions_root: blake3::Digest::EMPTY,
            transactions_range: non_empty_range!(0, 1),
        };

        let first = futures::executor::block_on(source.propose(&parent, &test_context()));
        let second = futures::executor::block_on(source.propose(&parent, &test_context()));
        let third = futures::executor::block_on(source.propose(&parent, &test_context()));

        assert_eq!(first.len(), 1);
        assert_eq!(first[0].value().nonce, tx1.value().nonce);
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].value().nonce, 1);
        assert!(third.is_empty());
    }
}
