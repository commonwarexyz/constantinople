use commonware_consensus::{Reporter, marshal::Update, simplex::types::Context};
use commonware_cryptography::{Digest, Hasher, PublicKey, Signer};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    Acknowledgement, NZU64,
    channel::fallible::{AsyncFallibleExt, OneshotExt},
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::{Address, Header, SealedBlock, Transaction, VerifiedTransaction};
use rand_core::CryptoRngCore;
use std::marker::PhantomData;
use tokio::sync::{mpsc, oneshot};

pub struct TransactionGenerator<E, C, P, H, S>
where
    E: Spawner,
    C: Digest,
    P: Signer,
    H: Hasher,
    S: Strategy,
{
    context: ContextCell<E>,
    mailbox: mpsc::Receiver<Message<P::PublicKey, H>>,
    keys: Vec<(P, Address)>,
    strategy: S,
    _marker: PhantomData<C>,
}

impl<E, C, P, H, S> TransactionGenerator<E, C, P, H, S>
where
    E: Spawner + CryptoRngCore,
    C: Digest,
    P: Signer,
    H: Hasher,
    S: Strategy,
{
    pub fn new(mut context: E, n_keys: usize, strategy: S) -> (Self, Mailbox<C, P::PublicKey, H>) {
        let mut hasher = H::default();
        let keys = (0..n_keys)
            .into_iter()
            .map(|_| {
                let signer = P::random(&mut context);
                let address = Address::from_public_key(&mut hasher, &signer.public_key());
                (signer, address)
            })
            .collect();
        let (sender, mailbox) = mpsc::channel(1024);

        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                keys,
                strategy,
                _marker: PhantomData,
            },
            Mailbox {
                sender,
                _marker: PhantomData,
            },
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(mut self) {
        let mut cached_transactions = Vec::with_capacity(self.keys.len());
        let mut generation = 0;

        select_loop! {
            self.context,
            on_stopped => {},
            Some(Message::GetTransactions { response }) = self.mailbox.recv() else break => {
                response.send_lossy(cached_transactions.drain(..).collect());
                self.generate_transactions(generation, &mut cached_transactions);
                generation += 1;
            }
        }
    }

    fn generate_transactions(
        &self,
        generation: u64,
        txs: &mut Vec<VerifiedTransaction<P::PublicKey, H>>,
    ) {
        let v = self.strategy.map_init_collect_vec(
            self.keys.iter().enumerate(),
            H::default,
            |hasher, (i, (signer, _))| {
                let to = self.keys[(i + 1) % self.keys.len()].1;
                Transaction::new(signer.public_key(), to, NZU64!(1), generation)
                    .seal_and_sign_verified(signer, b"constantinople-tx", hasher)
            },
        );

        *txs = v;
    }
}

pub enum Message<P, H>
where
    P: PublicKey,
    H: Hasher,
{
    GetTransactions {
        response: oneshot::Sender<Vec<VerifiedTransaction<P, H>>>,
    },
}

#[derive(Clone)]
pub struct Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    sender: mpsc::Sender<Message<P, H>>,
    _marker: PhantomData<(C, P, H)>,
}

impl<C, P, H> TransactionSource<C, P, H> for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    async fn propose(
        &mut self,
        _: &Header<C, H::Digest, P>,
        _: &Context<C, P>,
    ) -> Vec<VerifiedTransaction<P, H>> {
        self.sender
            .request(|response| Message::GetTransactions { response })
            .await
            .expect("mailbox closed")
    }
}

impl<C, P, H> Reporter for Mailbox<C, P, H>
where
    C: Digest,
    P: PublicKey,
    H: Hasher,
{
    type Activity = Update<SealedBlock<C, P, H>>;

    async fn report(&mut self, activity: Self::Activity) {
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
    }
}
