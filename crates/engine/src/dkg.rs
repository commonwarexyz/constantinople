//! DKG scheme registration and committee integration.

use crate::ThresholdScheme;
use commonware_consensus::types::{Epoch, Epocher as _, FixedEpocher, Height};
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::variant::Variant,
    certificate::{Provider, Scoped},
    ed25519,
};
use commonware_glue::dkg::{
    ParticipantsProvider, Registrar as RegistrarTrait, network::Addresses, types::SchemeInfo,
};
use commonware_p2p::Address;
use commonware_parallel::Strategy;
use commonware_runtime::{BufferPooler, Clock, Metrics, Storage};
use commonware_storage::translator::EightCap;
use commonware_utils::{
    ordered::{Map, Set},
    sequence::U64,
    sync::Mutex,
};
use constantinople_application::consensus::{CommitteeDatabase, committee_for_epoch};
use futures::{
    FutureExt as _,
    future::{BoxFuture, Shared},
};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::SocketAddr,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

type SchemeRegistry<P, V> = Arc<Mutex<HashMap<Epoch, Arc<ThresholdScheme<P, V>>>>>;

/// Encodes an optional applied height for storage in an atomic watermark.
///
/// Zero means no block has been applied; applied heights are shifted by one so
/// genesis (height zero) remains distinguishable from that state.
pub(crate) fn encode_finalized_application_height(height: Option<Height>) -> u64 {
    height.map_or(0, |height| height.next().get())
}

fn application_finalized_through(watermark: &AtomicU64, cutoff: Height) -> bool {
    watermark.load(Ordering::Acquire) > cutoff.get()
}

fn committed_committee_cutoff(epocher: &FixedEpocher, requested: Epoch) -> Option<Height> {
    let source = requested.previous()?.previous()?;
    let boundary = epocher
        .last(source)
        .expect("fixed epocher must cover the requested committee epoch");
    // Committee mutations are frozen for the source epoch's final two blocks.
    // Waiting only through the last mutable block also avoids depending on a
    // finalized notification that the calling reshare actor must acknowledge.
    Some(Height::new(boundary.get().saturating_sub(2)))
}

/// Epoch-scoped threshold schemes installed by the reshare actor.
///
/// The provider starts with epoch zero and is extended by [`Registrar`] before
/// the orchestrator enters each later epoch. Clones share the same registry.
pub struct DynamicProvider<P, V>
where
    P: PublicKey,
    V: Variant,
{
    schemes: SchemeRegistry<P, V>,
}

impl<P, V> Default for DynamicProvider<P, V>
where
    P: PublicKey,
    V: Variant,
{
    fn default() -> Self {
        Self {
            schemes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<P, V> Clone for DynamicProvider<P, V>
where
    P: PublicKey,
    V: Variant,
{
    fn clone(&self) -> Self {
        Self {
            schemes: self.schemes.clone(),
        }
    }
}

impl<P, V> DynamicProvider<P, V>
where
    P: PublicKey,
    V: Variant,
{
    /// Installs `scheme` for `epoch`, replacing an identical recovery-time
    /// registration if one already exists.
    pub fn register(&self, epoch: Epoch, scheme: ThresholdScheme<P, V>) {
        self.schemes.lock().insert(epoch, Arc::new(scheme));
    }
}

impl<P, V> Provider for DynamicProvider<P, V>
where
    P: PublicKey,
    V: Variant,
{
    type Scope = Epoch;
    type Scheme = ThresholdScheme<P, V>;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned().map(Scoped::scheme)
    }

    fn scheme(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.schemes.lock().get(&scope).cloned()
    }
}

/// Installs signer or verifier schemes produced by continuous reshare.
#[derive(Clone)]
pub struct Registrar<P, V>
where
    P: PublicKey,
    V: Variant,
{
    namespace: Arc<[u8]>,
    provider: DynamicProvider<P, V>,
}

impl<P, V> Registrar<P, V>
where
    P: PublicKey,
    V: Variant,
{
    /// Creates a registrar backed by `provider`.
    pub fn new(namespace: impl Into<Arc<[u8]>>, provider: DynamicProvider<P, V>) -> Self {
        Self {
            namespace: namespace.into(),
            provider,
        }
    }
}

impl<P, V> RegistrarTrait for Registrar<P, V>
where
    P: PublicKey,
    V: Variant,
{
    type Variant = V;
    type PublicKey = P;

    async fn register(&self, epoch: Epoch, info: SchemeInfo<V, P>) {
        let scheme = match info {
            SchemeInfo::Verifier {
                participants,
                sharing,
            } => ThresholdScheme::verifier(&self.namespace, participants, sharing),
            SchemeInfo::Signer {
                participants,
                sharing,
                share,
            } => ThresholdScheme::signer(&self.namespace, participants, sharing, share)
                .expect("registered DKG share must match its participant set"),
        };
        self.provider.register(epoch, scheme);
    }
}

/// Reads committees from finalized application state and resolves their exact
/// lookup address directories.
pub struct CommitteeParticipants<E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: commonware_cryptography::Hasher,
    St: Strategy,
{
    context: E,
    database: Shared<BoxFuture<'static, CommitteeDatabase<E, H, EightCap, St>>>,
    genesis_players: Set<ed25519::PublicKey>,
    genesis_next_players: Set<ed25519::PublicKey>,
    bootstrap_addresses: Arc<Map<ed25519::PublicKey, SocketAddr>>,
    finalized_application_height: Arc<AtomicU64>,
    epocher: FixedEpocher,
}

impl<E, H, St> CommitteeParticipants<E, H, St>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: commonware_cryptography::Hasher,
    St: Strategy,
{
    /// Creates a committed-state participant provider.
    pub fn new<F>(
        context: E,
        database: F,
        genesis_players: Set<ed25519::PublicKey>,
        genesis_next_players: Set<ed25519::PublicKey>,
        bootstrap_addresses: Map<ed25519::PublicKey, SocketAddr>,
        finalized_application_height: Arc<AtomicU64>,
        blocks_per_epoch: NonZeroU64,
    ) -> Self
    where
        F: Future<Output = CommitteeDatabase<E, H, EightCap, St>> + Send + 'static,
    {
        Self {
            context,
            database: database.boxed().shared(),
            genesis_players,
            genesis_next_players,
            bootstrap_addresses: Arc::new(bootstrap_addresses),
            finalized_application_height,
            epocher: FixedEpocher::new(blocks_per_epoch),
        }
    }

    fn committed_cutoff(&self, requested: Epoch) -> Option<Height> {
        committed_committee_cutoff(&self.epocher, requested)
    }

    async fn wait_until_committed(&self, requested: Epoch) {
        let Some(cutoff) = self.committed_cutoff(requested) else {
            return;
        };
        while !application_finalized_through(&self.finalized_application_height, cutoff) {
            self.context.sleep(Duration::from_millis(10)).await;
        }
    }
}

fn resolve_snapshot_directory<'a>(
    peers: &Set<ed25519::PublicKey>,
    snapshots: impl IntoIterator<Item = (Epoch, &'a Map<ed25519::PublicKey, SocketAddr>)>,
) -> Addresses<ed25519::PublicKey> {
    let mut available = BTreeMap::<ed25519::PublicKey, (Epoch, SocketAddr)>::new();
    for (epoch, addresses) in snapshots {
        for (peer, address) in addresses.iter_pairs() {
            if let Some((previous_epoch, previous_address)) = available.get(peer) {
                assert_eq!(
                    previous_address, address,
                    "committee peer {peer:?} has conflicting addresses in epochs {previous_epoch} and {epoch}"
                );
                continue;
            }
            available.insert(peer.clone(), (epoch, *address));
        }
    }

    peers
        .iter()
        .map(|peer| {
            let (_, address) = available.get(peer).unwrap_or_else(|| {
                panic!(
                    "requested committee peer {peer:?} is absent from the finalized epoch window"
                )
            });
            (peer.clone(), Address::Symmetric(*address))
        })
        .collect()
}

impl<E, H, St> ParticipantsProvider for CommitteeParticipants<E, H, St>
where
    E: BufferPooler + Storage + Metrics + Clock,
    H: commonware_cryptography::Hasher,
    St: Strategy,
{
    type PublicKey = ed25519::PublicKey;
    type Directory = Addresses<ed25519::PublicKey>;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        self.wait_until_committed(epoch).await;
        let database = self.database.clone().await;
        let initialized = database
            .read()
            .await
            .get(&U64::new(0))
            .await
            .expect("genesis committee state read must succeed")
            .is_some();
        if !initialized {
            return if epoch == Epoch::zero() {
                self.genesis_players.clone()
            } else {
                self.genesis_next_players.clone()
            };
        }
        committee_for_epoch(&database, epoch)
            .await
            .members()
            .clone()
    }

    async fn directory(&mut self, epoch: Epoch, peers: Set<Self::PublicKey>) -> Self::Directory {
        // The directory for E commits the union of E-1, E, and E+1. The E+1
        // committee freezes at E-1's last mutable block.
        self.wait_until_committed(epoch.next()).await;
        let database = self.database.clone().await;
        let initialized = database
            .read()
            .await
            .get(&U64::new(0))
            .await
            .expect("genesis committee state read must succeed")
            .is_some();
        if !initialized {
            return resolve_snapshot_directory(
                &peers,
                [(Epoch::zero(), self.bootstrap_addresses.as_ref())],
            );
        }

        let previous = if epoch.is_zero() {
            None
        } else {
            Some((
                epoch.previous().expect("non-zero epoch has a predecessor"),
                committee_for_epoch(
                    &database,
                    epoch.previous().expect("non-zero epoch has a predecessor"),
                )
                .await,
            ))
        };
        let current = committee_for_epoch(&database, epoch).await;
        let next = committee_for_epoch(&database, epoch.next()).await;
        resolve_snapshot_directory(
            &peers,
            previous
                .iter()
                .map(|(epoch, committee)| (*epoch, committee.addresses()))
                .chain([
                    (epoch, current.addresses()),
                    (epoch.next(), next.addresses()),
                ]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        application_finalized_through, committed_committee_cutoff,
        encode_finalized_application_height, resolve_snapshot_directory,
    };
    use commonware_consensus::types::{Epoch, FixedEpocher, Height};
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_p2p::Address;
    use commonware_utils::ordered::{Map, Set};
    use std::{
        net::SocketAddr,
        num::NonZeroU64,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn key(seed: u64) -> ed25519::PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    fn socket(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn committed_committee_cutoff_precedes_final_two_blocks() {
        let epocher = FixedEpocher::new(NonZeroU64::new(8).expect("epoch length is non-zero"));

        assert_eq!(committed_committee_cutoff(&epocher, Epoch::zero()), None);
        assert_eq!(committed_committee_cutoff(&epocher, Epoch::new(1)), None);
        assert_eq!(
            committed_committee_cutoff(&epocher, Epoch::new(2)),
            Some(Height::new(5))
        );
        assert_eq!(
            committed_committee_cutoff(&epocher, Epoch::new(3)),
            Some(Height::new(13))
        );
    }

    #[test]
    fn finalized_application_watermark_distinguishes_none_and_genesis() {
        let watermark = AtomicU64::new(encode_finalized_application_height(None));
        assert!(!application_finalized_through(&watermark, Height::zero()));

        watermark.store(
            encode_finalized_application_height(Some(Height::zero())),
            Ordering::Release,
        );
        assert!(application_finalized_through(&watermark, Height::zero()));
        assert!(!application_finalized_through(&watermark, Height::new(1)));

        watermark.store(
            encode_finalized_application_height(Some(Height::new(1))),
            Ordering::Release,
        );
        assert!(application_finalized_through(&watermark, Height::new(1)));
    }

    #[test]
    fn snapshot_directory_resolves_exact_requested_union_in_key_order() {
        let old = key(1);
        let continuing = key(2);
        let newly_added = key(3);
        let previous = Map::from_iter_dedup([
            (old.clone(), socket(1001)),
            (continuing.clone(), socket(1002)),
        ]);
        let current = Map::from_iter_dedup([(continuing.clone(), socket(1002))]);
        let next = Map::from_iter_dedup([
            (continuing.clone(), socket(1002)),
            (newly_added.clone(), socket(1003)),
        ]);
        let requested = Set::from_iter_dedup([newly_added.clone(), old.clone()]);

        let directory = resolve_snapshot_directory(
            &requested,
            [
                (Epoch::new(4), &previous),
                (Epoch::new(5), &current),
                (Epoch::new(6), &next),
            ],
        )
        .into_inner();

        assert_eq!(directory.keys(), &requested);
        assert_eq!(
            directory.get_value(&old),
            Some(&Address::Symmetric(socket(1001)))
        );
        assert_eq!(
            directory.get_value(&newly_added),
            Some(&Address::Symmetric(socket(1003)))
        );
        assert!(directory.get_value(&continuing).is_none());
    }

    #[test]
    #[should_panic(expected = "absent from the finalized epoch window")]
    fn snapshot_directory_rejects_newly_added_unknown_peer() {
        let known = key(1);
        let unknown = key(2);
        let snapshot = Map::from_iter_dedup([(known, socket(1001))]);

        let _ = resolve_snapshot_directory(
            &Set::from_iter_dedup([unknown]),
            [(Epoch::new(5), &snapshot)],
        );
    }

    #[test]
    #[should_panic(expected = "conflicting addresses in epochs 5 and 6")]
    fn snapshot_directory_rejects_conflicting_addresses_across_epochs() {
        let peer = key(1);
        let current = Map::from_iter_dedup([(peer.clone(), socket(1001))]);
        let next = Map::from_iter_dedup([(peer.clone(), socket(1002))]);

        let _ = resolve_snapshot_directory(
            &Set::from_iter_dedup([peer]),
            [(Epoch::new(5), &current), (Epoch::new(6), &next)],
        );
    }
}
