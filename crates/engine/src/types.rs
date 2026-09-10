//! Shared type aliases for the engine crate.
//!
//! These canonical aliases give a single definition to the core block,
//! coding, marshal, probe, and finalization types that appear throughout the
//! engine and test modules.

pub use crate::block::{EngineBlock, EngineCommitment};
use crate::{
    ThresholdScheme,
    application::{EngineApplication, EngineReporter},
};
use commonware_actor::Feedback;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    Reporter, Reporters,
    marshal::{
        Update,
        coding::{
            Coding, Marshaled, shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::Mailbox as MarshalMailbox,
    },
    simplex::{self, types::Finalization},
    types::{Epoch, FixedEpocher},
};
use commonware_cryptography::{
    Hasher, PublicKey, bls12381::primitives::variant::Variant, certificate::ConstantProvider,
};
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
pub type EngineMarshalMailbox<H, P, V> = MarshalMailbox<ThresholdScheme<P, V>, EngineVariant<H, P>>;

/// Probe mailbox parameterized over the engine's threshold scheme.
pub type EngineProbeMailbox<H, P, V> =
    commonware_glue::stateful::probe::Mailbox<ThresholdScheme<P, V>, EngineVariant<H, P>>;

/// A finalization certificate over the engine's threshold scheme.
pub type EngineFinalization<P, V, H = commonware_cryptography::sha256::Sha256> =
    Finalization<ThresholdScheme<P, V>, EngineCommitment<H, P>>;

/// Simplex activity stream observed by the engine, used by the optional
/// `simplex_observer` reporter slot in [`crate::Config`].
pub type EngineActivity<P, V, H = commonware_cryptography::sha256::Sha256> =
    simplex::types::Activity<ThresholdScheme<P, V>, EngineCommitment<H, P>>;

type NoopReporterMarker<P, V, H> = fn() -> (P, V, H);

pub(crate) type EngineFinalizedHook<H, P> = FinalizedHookFn<EngineCommitment<H, P>, H, P>;

/// A no-op [`Reporter`] over [`EngineActivity`].
///
/// Pass `None::<NoopActivityReporter<P, V>>` to [`crate::Config::simplex_observer`]
/// when no external observer is wired in. The type parameter exists only to
/// pin the activity type; the reporter never forwards anything.
pub struct NoopActivityReporter<P, V, H = commonware_cryptography::sha256::Sha256>(
    PhantomData<NoopReporterMarker<P, V, H>>,
);

impl<P, V, H> Default for NoopActivityReporter<P, V, H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P, V, H> Clone for NoopActivityReporter<P, V, H> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<P, V, H> std::fmt::Debug for NoopActivityReporter<P, V, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopActivityReporter").finish()
    }
}

impl<P, V, H> Reporter for NoopActivityReporter<P, V, H>
where
    P: PublicKey,
    V: Variant,
    H: Hasher,
{
    type Activity = EngineActivity<P, V, H>;

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

pub(crate) type App<E, H, P, V, I, B, St> = EngineApplication<E, H, P, V, I, B, St>;

pub(crate) type AppMailbox<E, H, P, V, I, B, St> =
    commonware_glue::stateful::Mailbox<E, App<E, H, P, V, I, B, St>>;

pub(crate) type EngineMarshalReporters<E, H, P, V, I, B, St, R> =
    Reporters<Update<EngineBlock<H, P>>, AppMailbox<E, H, P, V, I, B, St>, EngineReporter<R, H, P>>;

pub(crate) type SchemeProvider<P, V> = ConstantProvider<ThresholdScheme<P, V>, Epoch>;

pub(crate) type StatefulApp<E, H, P, V, I, B, St> = Stateful<
    E,
    App<E, H, P, V, I, B, St>,
    ThresholdScheme<P, V>,
    EngineVariant<H, P>,
    (
        StateResolverMailbox<E, H, St>,
        TransactionResolverMailbox<E, H, St>,
    ),
>;

pub(crate) type MarshaledApp<E, H, P, V, I, B, St> = Marshaled<
    E,
    AppMailbox<E, H, P, V, I, B, St>,
    EngineBlock<H, P>,
    ReedSolomon<H>,
    H,
    SchemeProvider<P, V>,
    St,
    FixedEpocher,
>;

pub(crate) type ShardsEngine<E, B, M, H, P, V, T> =
    shards::Engine<E, SchemeProvider<P, V>, B, M, ReedSolomon<H>, H, EngineBlock<H, P>, P, T>;

pub(crate) type ShardsMailbox<H, P> = shards::Mailbox<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// Reporter combinator that fans simplex activity to the marshal mailbox and
/// an optional external observer (e.g. the indexer's certificate publisher).
pub(crate) type SimplexReporter<H, P, V, O> =
    Reporters<EngineActivity<P, V, H>, EngineMarshalMailbox<H, P, V>, O>;

pub(crate) type SimplexEngine<E, B, H, P, V, L, St, I, BV, O> = simplex::Engine<
    E,
    ThresholdScheme<P, V>,
    L,
    B,
    EngineCommitment<H, P>,
    MarshaledApp<E, H, P, V, I, BV, St>,
    MarshaledApp<E, H, P, V, I, BV, St>,
    SimplexReporter<H, P, V, O>,
    St,
>;
