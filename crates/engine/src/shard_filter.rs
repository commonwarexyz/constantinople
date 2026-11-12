//! Marshal shard admission for the fixed validator set.

use crate::types::EngineCommitment;
use commonware_codec::{Copying, ReadExt as _};
use commonware_coding::Config as CodingConfig;
use commonware_cryptography::Hasher;
use commonware_p2p::{Blocker, Message, Receiver};
use std::{fmt, marker::PhantomData, num::NonZeroUsize};

/// Blocks peers that send marshal shards coded for a different validator set.
///
/// The shards engine sizes each incoming shard by the coding config its commitment claims, and it
/// buffers shards before consensus confirms that commitment. A peer claiming a single minimum
/// shard could otherwise make every node buffer shards as wide as a whole block. The validator set
/// is fixed, so every honest shard carries the same config and any other config can be rejected
/// before the shards engine decodes it. Supporting validator set changes would require replacing
/// this filter, because honest shards near an epoch boundary may carry either set's config.
pub(crate) struct ShardFilter<R, B, H> {
    receiver: R,
    blocker: B,
    config: CodingConfig,
    _hasher: PhantomData<fn() -> H>,
}

impl<R, B, H> ShardFilter<R, B, H> {
    pub(crate) const fn new(receiver: R, blocker: B, config: CodingConfig) -> Self {
        Self {
            receiver,
            blocker,
            config,
            _hasher: PhantomData,
        }
    }
}

impl<R: fmt::Debug, B, H> fmt::Debug for ShardFilter<R, B, H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShardFilter")
            .field("receiver", &self.receiver)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<R, B, H> Receiver for ShardFilter<R, B, H>
where
    R: Receiver,
    B: Blocker<PublicKey = R::PublicKey>,
    H: Hasher,
{
    type Error = R::Error;
    type PublicKey = R::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let (peer, message) = self.receiver.recv().await?;

            // A shard starts with its commitment. A message too short or malformed to hold one
            // also fails the shards engine's full decode, which blocks its sender there.
            let claimed = EngineCommitment::<H, R::PublicKey>::read(&mut Copying(message.as_ref()))
                .map(|commitment| commitment.config());
            match claimed {
                Ok(config) if config != self.config => {
                    commonware_p2p::block!(
                        self.blocker,
                        peer,
                        ?config,
                        "shard coded for a different validator set"
                    );
                }
                _ => return Ok((peer, message)),
            }
        }
    }

    /// The filter holds no messages of its own, so it reports the wrapped receiver's capacity.
    fn capacity(&self) -> NonZeroUsize {
        self.receiver.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::ShardFilter;
    use crate::types::{EngineBlock, EngineCommitment};
    use bytes::Bytes;
    use commonware_codec::Encode as _;
    use commonware_coding::{Config as CodingConfig, ReedSolomon, Scheme as _};
    use commonware_consensus::marshal::coding::types::{Shard, coding_config_for_participants};
    use commonware_cryptography::{
        Digest as _, Signer as _,
        sha256::{self, Sha256},
    };
    use commonware_cryptography_curve25519::signing as ed25519;
    use commonware_macros::test_traced;
    use commonware_p2p::{
        Manager as _, Receiver as _, Recipients, Sender as _,
        simulated::{self, Link},
    };
    use commonware_parallel::Sequential;
    use commonware_runtime::{Clock as _, Quota, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZU16, NZU32, NZUsize, ordered::Set, probability};
    use std::{num::NonZeroU32, time::Duration};

    type TestShard = Shard<EngineBlock<Sha256, ed25519::VerifyingKey>, ReedSolomon<Sha256>, Sha256>;

    const LINK: Link = Link {
        latency: Duration::from_millis(1),
        jitter: Duration::ZERO,
        success_rate: probability!(1.0),
    };

    const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX).allow_burst(NZU32!(1_024));

    fn shard(config: CodingConfig) -> Bytes {
        let (root, shards) = ReedSolomon::<Sha256>::encode(&config, &b"block"[..], &Sequential)
            .expect("payload should encode");
        let commitment = EngineCommitment::<Sha256, ed25519::VerifyingKey>::from((
            sha256::Digest::EMPTY,
            root,
            sha256::Digest::EMPTY,
            config,
        ));
        TestShard::new(commitment, 0, shards[0].clone()).encode()
    }

    #[test_traced]
    fn blocks_peers_that_claim_another_coding_config() {
        deterministic::Runner::default().start(|context| async move {
            let (network, oracle) = simulated::Network::new(
                context.child("network"),
                simulated::Config {
                    max_size: 1024 * 1024,
                    max_peers_per_set: NZUsize!(3),
                    disconnect_on_block: true,
                    tracked_peer_sets: NZUsize!(1),
                },
            );
            network.start();

            let [local, attacker, honest] =
                [0, 1, 2].map(|seed| ed25519::SigningKey::from_seed(seed).public_key());
            oracle.manager().track(
                0,
                Set::from_iter_dedup([local.clone(), attacker.clone(), honest.clone()]),
            );
            for peer in [&attacker, &honest] {
                oracle
                    .add_link(peer.clone(), local.clone(), LINK)
                    .await
                    .expect("link should be added");
            }
            let control = oracle.control(local.clone());
            let (_, receiver) = control.register(0, QUOTA).await.expect("register local");
            let (mut attacker_sender, _) = oracle
                .control(attacker.clone())
                .register(0, QUOTA)
                .await
                .expect("register attacker");
            let (mut honest_sender, _) = oracle
                .control(honest.clone())
                .register(0, QUOTA)
                .await
                .expect("register honest");
            let config = coding_config_for_participants(4);
            let mut filter = ShardFilter::<_, _, Sha256>::new(receiver, control, config);

            // One minimum shard is the widest config a peer can claim.
            let widest = CodingConfig {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(3),
            };
            let _ = attacker_sender.send(Recipients::One(local.clone()), shard(widest), true);
            context.sleep(LINK.latency * 2).await;
            let _ = honest_sender.send(Recipients::One(local.clone()), shard(config), true);

            let (from, message) = filter.recv().await.expect("honest shard should arrive");
            assert_eq!(from, honest);
            assert_eq!(message.as_ref(), shard(config).as_ref());
            loop {
                let blocked = oracle.blocked().await.expect("blocked peers should load");
                if blocked.contains(&(local.clone(), attacker.clone())) {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
        });
    }
}
