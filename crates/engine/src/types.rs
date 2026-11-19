//! Shared type aliases for the engine crate.
//!
//! These canonical aliases give a single definition to the core block,
//! coding, marshal, probe, and finalization types that appear throughout the
//! engine and test modules.

pub use crate::block::{EngineBlock, EngineCommitment};
use crate::{
    Scheme,
    application::{EngineApplication, EngineReporter},
    tags::{EngineChain, Gated},
};
use commonware_actor::Feedback;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{
        coding::{
            Coding, Marshaled, shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::Mailbox as MarshalMailbox,
    },
    simplex::{self, types::Finalization},
    types::{Epoch, FixedEpocher, Height},
};
use commonware_cryptography::{Hasher, PublicKey, certificate::ConstantProvider};
use commonware_glue::stateful::{Stateful, db::Shared};
use commonware_storage::{
    mmr,
    qmdb::{any::unordered::fixed, sync::Database},
    translator::EightCap,
};
use constantinople_application::consensus::{FinalizedHookFn, TransactionHistoryDb};
use constantinople_primitives::{Account, AccountKey, Header, Sealed};
use std::marker::PhantomData;

/// The digestible execution header portion of an [`EngineBlock`].
pub type EngineHeader<H, P> = Sealed<Header<EngineCommitment<H, P>, <H as Hasher>::Digest, P>, H>;

/// The erasure-coding variant used by the marshal for block availability.
pub type EngineVariant<H, P> = Coding<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// A marshal-coded engine block.
pub type EngineCodedBlock<H, P> = CodedBlock<EngineBlock<H, P>, ReedSolomon<H>, H>;

/// Marshal mailbox parameterized over the engine's threshold scheme.
pub type EngineMarshalMailbox<H, P> = MarshalMailbox<Scheme, EngineVariant<H, P>>;

/// Read-only access to the finalization certificates marshal has stored.
pub struct FinalizationReader<H: Hasher, P: PublicKey>(EngineMarshalMailbox<H, P>);

impl<H: Hasher, P: PublicKey> FinalizationReader<H, P> {
    pub(crate) const fn new(mailbox: EngineMarshalMailbox<H, P>) -> Self {
        Self(mailbox)
    }

    /// Returns the finalization stored locally for `height`, if any. This never fetches from peers.
    pub async fn get(&self, height: Height) -> Option<EngineFinalization<P, H>> {
        self.0.get_finalization(height).await
    }
}

/// Probe mailbox parameterized over the engine's threshold scheme.
pub type EngineProbeMailbox<H, P> =
    commonware_glue::stateful::probe::Mailbox<Scheme, EngineVariant<H, P>>;

/// A finalization certificate over the engine's threshold scheme.
pub type EngineFinalization<P, H = commonware_cryptography::sha256::Sha256> =
    Finalization<Scheme, EngineCommitment<H, P>>;

/// Simplex activity stream observed by the engine, used by the optional
/// `simplex_observer` reporter slot in [`crate::Config`].
pub type EngineActivity<P, H = commonware_cryptography::sha256::Sha256> =
    simplex::types::Activity<Scheme, EngineCommitment<H, P>>;

type NoopReporterMarker<P, H> = fn() -> (P, H);

pub(crate) type EngineFinalizedHook<H, P> = FinalizedHookFn<EngineCommitment<H, P>, H, P>;

/// A no-op [`Reporter`] over [`EngineActivity`].
///
/// Pass `None::<NoopActivityReporter<P>>` to [`crate::Config::simplex_observer`]
/// when no external observer is wired in. The type parameter exists only to
/// pin the activity type; the reporter never forwards anything.
pub struct NoopActivityReporter<P, H = commonware_cryptography::sha256::Sha256>(
    PhantomData<NoopReporterMarker<P, H>>,
);

impl<P, H> Default for NoopActivityReporter<P, H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P, H> Clone for NoopActivityReporter<P, H> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<P, H> std::fmt::Debug for NoopActivityReporter<P, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopActivityReporter").finish()
    }
}

impl<P, H> Reporter for NoopActivityReporter<P, H>
where
    P: PublicKey,
    H: Hasher,
{
    type Activity = EngineActivity<P, H>;

    fn report(&mut self, _: Self::Activity) -> Feedback {
        Feedback::Ok
    }
}

pub(crate) type CodingBlock<H, P> = StoredCodedBlock<EngineBlock<H, P>, ReedSolomon<H>, H>;

pub type StateDb<E, H, T> = fixed::Db<mmr::Family, E, AccountKey, Account, H, EightCap, T>;

pub type StateSyncDb<E, H, T> = Shared<StateDb<E, H, T>>;

pub(crate) type StateResolverMailbox<E, H, T> = commonware_glue::stateful::db::p2p::Mailbox<
    StateDb<E, H, T>,
    mmr::Family,
    <StateDb<E, H, T> as Database>::Op,
    <StateDb<E, H, T> as Database>::Digest,
>;

pub(crate) type StateResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::Actor<E, P, M, B, mmr::Family, StateDb<E, H, T>>;

pub type TransactionDb<E, H, T> = TransactionHistoryDb<E, H, T>;

pub type TransactionSyncDb<E, H, T> = Shared<TransactionDb<E, H, T>>;

pub(crate) type TransactionResolverMailbox<E, H, T> = commonware_glue::stateful::db::p2p::Mailbox<
    TransactionDb<E, H, T>,
    mmr::Family,
    <TransactionDb<E, H, T> as Database>::Op,
    <TransactionDb<E, H, T> as Database>::Digest,
>;

pub(crate) type TransactionResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::Actor<E, P, M, B, mmr::Family, TransactionDb<E, H, T>>;

pub(crate) type App<E, H, P, I, St> = EngineApplication<E, H, P, EngineChain<H>, I, St>;

pub(crate) type AppMailbox<E, H, P, I, St> =
    commonware_glue::stateful::Mailbox<E, App<E, H, P, I, St>>;

pub(crate) type EngineMarshalReporters<E, H, P, I, St, R> =
    Reporters<AppMailbox<E, H, P, I, St>, EngineReporter<R, H, P>>;

pub(crate) type SchemeProvider = ConstantProvider<Scheme, Epoch>;

pub(crate) type StatefulApp<E, H, P, I, St> = Stateful<
    E,
    App<E, H, P, I, St>,
    Scheme,
    EngineVariant<H, P>,
    (
        StateResolverMailbox<E, H, St>,
        TransactionResolverMailbox<E, H, St>,
    ),
    St,
>;

pub(crate) type MarshaledApp<E, H, P, I, St> = Marshaled<
    E,
    AppMailbox<E, H, P, I, St>,
    EngineBlock<H, P>,
    ReedSolomon<H>,
    H,
    SchemeProvider,
    St,
    FixedEpocher,
>;

pub(crate) type ShardsEngine<E, B, M, H, P, T> =
    shards::Engine<E, SchemeProvider, B, M, ReedSolomon<H>, H, EngineBlock<H, P>, P, T>;

pub(crate) type ShardsMailbox<H, P> = shards::Mailbox<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// Reporter combinator that fans simplex activity to the marshaled
/// application and an optional external observer.
pub(crate) type SimplexReporter<E, H, I, St, O> = Reporters<Gated<E, H, I, St>, O>;

pub(crate) type SimplexEngine<E, B, H, P, L, St, I, O> = simplex::Engine<
    E,
    Scheme,
    L,
    B,
    EngineCommitment<H, P>,
    Gated<E, H, I, St>,
    Gated<E, H, I, St>,
    SimplexReporter<E, H, I, St, O>,
    St,
>;
