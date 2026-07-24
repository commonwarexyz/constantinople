//! DKG scheme registration and committee integration.

use crate::ThresholdScheme;
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    types::{Epoch, Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{
    PublicKey,
    bls12381::primitives::variant::Variant,
    certificate::{Provider, Scheme, Scoped},
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
use std::{collections::HashMap, future::Future, num::NonZeroU64, sync::Arc, time::Duration};

type SchemeRegistry<P, V> = Arc<Mutex<HashMap<Epoch, Arc<ThresholdScheme<P, V>>>>>;

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
pub struct CommitteeParticipants<E, H, St, S, MV>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: commonware_cryptography::Hasher,
    St: Strategy,
    S: Scheme,
    MV: MarshalVariant,
{
    context: E,
    database: Shared<BoxFuture<'static, CommitteeDatabase<E, H, EightCap, St>>>,
    genesis_players: Set<ed25519::PublicKey>,
    genesis_next_players: Set<ed25519::PublicKey>,
    addresses: Arc<Map<ed25519::PublicKey, Address>>,
    marshal: MarshalMailbox<S, MV>,
    epocher: FixedEpocher,
}

impl<E, H, St, S, MV> CommitteeParticipants<E, H, St, S, MV>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: commonware_cryptography::Hasher,
    St: Strategy,
    S: Scheme,
    MV: MarshalVariant,
{
    /// Creates a committed-state participant provider.
    pub fn new<F>(
        context: E,
        database: F,
        genesis_players: Set<ed25519::PublicKey>,
        genesis_next_players: Set<ed25519::PublicKey>,
        addresses: Map<ed25519::PublicKey, Address>,
        marshal: MarshalMailbox<S, MV>,
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
            addresses: Arc::new(addresses),
            marshal,
            epocher: FixedEpocher::new(blocks_per_epoch),
        }
    }

    fn committed_cutoff(&self, requested: Epoch) -> Option<Height> {
        let source = requested.previous()?.previous()?;
        let boundary = self
            .epocher
            .last(source)
            .expect("fixed epocher must cover the requested committee epoch");
        Some(Height::new(boundary.get().saturating_sub(1)))
    }
}

impl<E, H, St, S, MV> ParticipantsProvider for CommitteeParticipants<E, H, St, S, MV>
where
    E: BufferPooler + Storage + Metrics + Clock,
    H: commonware_cryptography::Hasher,
    St: Strategy,
    S: Scheme<PublicKey = ed25519::PublicKey>,
    MV: MarshalVariant,
{
    type PublicKey = ed25519::PublicKey;
    type Directory = Addresses<ed25519::PublicKey>;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        if let Some(cutoff) = self.committed_cutoff(epoch) {
            loop {
                if self
                    .marshal
                    .get_processed_height()
                    .await
                    .is_some_and(|processed| processed >= cutoff)
                {
                    break;
                }
                self.context.sleep(Duration::from_millis(10)).await;
            }
        }
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
        committee_for_epoch(&database, epoch).await.into_members()
    }

    async fn directory(&mut self, _: Epoch, peers: Set<Self::PublicKey>) -> Self::Directory {
        peers
            .iter()
            .map(|peer| {
                let address = self
                    .addresses
                    .get_value(peer)
                    .unwrap_or_else(|| panic!("committee peer {peer:?} is not eligible"));
                (peer.clone(), address.clone())
            })
            .collect()
    }
}
