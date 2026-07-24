//! Compatibility bridge from ordered marshal updates to simplex activity.

use commonware_actor::{
    Feedback,
    mailbox::{self as actor_mailbox, Policy, Receiver, Sender},
};
use commonware_consensus::{
    Heightable, Reporter,
    marshal::{
        Update,
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    simplex::{scheme::Scheme, types::Activity},
};
use commonware_cryptography::certificate::Scheme as CertificateScheme;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};

/// An ordered finalized block awaiting conversion to simplex activity.
enum Message<B>
where
    B: commonware_consensus::Block,
{
    Finalized {
        block: Arc<B>,
        acknowledgement: Exact,
    },
}

impl<B> Policy for Message<B>
where
    B: commonware_consensus::Block,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // Marshal delivers blocks in order, so preserve every overflowed update.
        overflow.push_back(message);
    }
}

/// Cloneable marshal reporter feeding the observer actor.
#[derive(Clone)]
pub(crate) struct Mailbox<B>
where
    B: commonware_consensus::Block,
{
    sender: Sender<Message<B>>,
}

impl<B> Mailbox<B>
where
    B: commonware_consensus::Block,
{
    const fn new(sender: Sender<Message<B>>) -> Self {
        Self { sender }
    }
}

impl<B> Reporter for Mailbox<B>
where
    B: commonware_consensus::Block,
{
    type Activity = Update<B>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };

        self.sender.enqueue(Message::Finalized {
            block,
            acknowledgement,
        })
    }
}

/// Resolves each finalized block's certificate and recreates the legacy
/// simplex finalization stream.
pub(crate) struct Actor<E, S, V, O>
where
    E: Spawner + Metrics,
    S: CertificateScheme + Scheme<V::Commitment>,
    V: MarshalVariant,
    O: Reporter<Activity = Activity<S, V::Commitment>>,
{
    context: ContextCell<E>,
    receiver: Receiver<Message<V::ApplicationBlock>>,
    marshal: MarshalMailbox<S, V>,
    observer: O,
}

impl<E, S, V, O> Actor<E, S, V, O>
where
    E: Spawner + Metrics,
    S: CertificateScheme + Scheme<V::Commitment>,
    V: MarshalVariant,
    O: Reporter<Activity = Activity<S, V::Commitment>>,
{
    /// Create a compatibility actor and its bounded ingress mailbox.
    pub(crate) fn new(
        context: E,
        marshal: MarshalMailbox<S, V>,
        observer: O,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Mailbox<V::ApplicationBlock>) {
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                receiver,
                marshal,
                observer,
            },
            Mailbox::new(sender),
        )
    }

    /// Start recreating simplex finalization reports from marshal delivery.
    pub(crate) fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(Message::Finalized {
            block,
            acknowledgement,
        }) = self.receiver.recv().await
        {
            let height = block.height();
            let finalization = self
                .marshal
                .get_finalization(height)
                .await
                .unwrap_or_else(|| panic!("marshal finalization missing at height {height}"));
            let _ = self.observer.report(Activity::Finalization(finalization));
            acknowledgement.acknowledge();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BufMut};
    use commonware_codec::{EncodeSize, Error, Read, ReadExt as _, Write};
    use commonware_consensus::types::Height;
    use commonware_cryptography::{Digest, Digestible, sha256};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZUsize;
    use futures::FutureExt as _;

    #[derive(Clone, Debug)]
    struct TestBlock(Height);

    impl Write for TestBlock {
        fn write(&self, writer: &mut impl BufMut) {
            self.0.write(writer);
        }
    }

    impl EncodeSize for TestBlock {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Read for TestBlock {
        type Cfg = ();

        fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
            Ok(Self(Height::read(reader)?))
        }
    }

    impl Digestible for TestBlock {
        type Digest = sha256::Digest;

        fn digest(&self) -> Self::Digest {
            sha256::Digest::EMPTY
        }
    }

    impl Heightable for TestBlock {
        fn height(&self) -> Height {
            self.0
        }
    }

    impl commonware_consensus::Block for TestBlock {
        fn parent(&self) -> Self::Digest {
            sha256::Digest::EMPTY
        }
    }

    #[test]
    fn mailbox_preserves_order_and_acknowledgements() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, mut receiver) = actor_mailbox::new(context, NZUsize!(1));
            let mut mailbox = Mailbox::new(sender);

            let (first_ack, mut first_waiter) = Exact::handle();
            let first_sibling = first_ack.clone();
            assert_eq!(
                mailbox.report(Update::Block(
                    Arc::new(TestBlock(Height::new(1))),
                    first_ack,
                )),
                Feedback::Ok,
            );

            let (second_ack, mut second_waiter) = Exact::handle();
            let second_sibling = second_ack.clone();
            assert_eq!(
                mailbox.report(Update::Block(
                    Arc::new(TestBlock(Height::new(2))),
                    second_ack,
                )),
                Feedback::Backoff,
            );

            // Simulate the other Reporters branch handling its cloned acknowledgements.
            first_sibling.acknowledge();
            second_sibling.acknowledge();
            assert!((&mut first_waiter).now_or_never().is_none());
            assert!((&mut second_waiter).now_or_never().is_none());

            let Message::Finalized {
                block,
                acknowledgement,
            } = receiver.recv().await.expect("first block must be queued");
            assert_eq!(block.height(), Height::new(1));
            acknowledgement.acknowledge();
            first_waiter
                .await
                .expect("first update must be acknowledged");

            let Message::Finalized {
                block,
                acknowledgement,
            } = receiver.recv().await.expect("second block must be queued");
            assert_eq!(block.height(), Height::new(2));
            acknowledgement.acknowledge();
            second_waiter
                .await
                .expect("second update must be acknowledged");
        });
    }
}
