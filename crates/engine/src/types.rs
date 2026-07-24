//! Shared type aliases for the engine crate.
//!
//! These canonical aliases give a single definition to the core block,
//! coding, marshal, probe, and finalization types that appear throughout the
//! engine and test modules.

use crate::{
    CommitteeParticipants, DynamicProvider, Registrar, ThresholdScheme,
    secret_store::FileSecretStore,
};
use commonware_actor::Feedback;
use commonware_codec::Read;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    Reporter,
    marshal::{
        coding::{
            Coding, Marshaled, shards,
            types::{CodedBlock, StoredCodedBlock},
        },
        core::Mailbox as MarshalMailbox,
    },
    simplex::{self, types::Finalization},
    types::{FixedEpocher, coding::Commitment},
};
use commonware_cryptography::{Hasher, PublicKey, Signer, bls12381::primitives::variant::Variant};
use commonware_glue::{
    dkg::{network, orchestrator, reshare, types::Payload},
    stateful::{Stateful, db::Shared},
};
use commonware_storage::{mmr, qmdb::any::unordered::fixed, translator::EightCap};
use constantinople_application::consensus::{
    Application, CommitteeDatabase, CommitteeDb, CommitteeOperation, TransactionHistoryDb,
    TransactionHistoryOperation,
};
use constantinople_primitives::{Account, AccountKey, Block, BlockCfg, Header, Sealed};
use std::marker::PhantomData;

/// A finalized block with its seal (commitment-based).
pub type EngineBlock<H, C, V> = Sealed<
    Block<
        Commitment,
        <C as Signer>::PublicKey,
        H,
        Payload<V, C, network::Addresses<<C as Signer>::PublicKey>>,
    >,
    H,
>;

/// The digestible execution header portion of an [`EngineBlock`].
pub type EngineHeader<H, C, V> = Sealed<
    Header<
        Commitment,
        <H as Hasher>::Digest,
        <C as Signer>::PublicKey,
        Payload<V, C, network::Addresses<<C as Signer>::PublicKey>>,
    >,
    H,
>;

/// The erasure-coding variant used by the marshal for block availability.
pub type EngineVariant<H, C, V> =
    Coding<EngineBlock<H, C, V>, ReedSolomon<H>, H, <C as Signer>::PublicKey>;

/// A marshal-coded engine block.
pub type EngineCodedBlock<H, C, V> = CodedBlock<EngineBlock<H, C, V>, ReedSolomon<H>, H>;

/// Codec configuration for a block carrying DKG reshare payloads.
pub type EngineBlockCfg<C, V> =
    BlockCfg<<Payload<V, C, network::Addresses<<C as Signer>::PublicKey>> as Read>::Cfg>;

/// Marshal mailbox parameterized over the engine's threshold scheme.
pub type EngineMarshalMailbox<H, C, V> =
    MarshalMailbox<ThresholdScheme<<C as Signer>::PublicKey, V>, EngineVariant<H, C, V>>;

/// Probe mailbox parameterized over the engine's threshold scheme.
pub type EngineProbeMailbox<H, C, V> = commonware_glue::stateful::probe::Mailbox<
    ThresholdScheme<<C as Signer>::PublicKey, V>,
    EngineVariant<H, C, V>,
>;

/// A finalization certificate over the engine's threshold scheme.
pub type EngineFinalization<P, V> = Finalization<ThresholdScheme<P, V>, Commitment>;

/// Simplex activity stream observed by the engine, used by the optional
/// `simplex_observer` reporter slot in [`crate::Config`].
pub type EngineActivity<P, V> = simplex::types::Activity<ThresholdScheme<P, V>, Commitment>;

/// A no-op [`Reporter`] over [`EngineActivity`].
///
/// Pass `None::<NoopActivityReporter<P, V>>` to [`crate::Config::simplex_observer`]
/// when no external observer is wired in. The type parameter exists only to
/// pin the activity type; the reporter never forwards anything.
pub struct NoopActivityReporter<P, V>(PhantomData<fn() -> (P, V)>);

impl<P, V> Default for NoopActivityReporter<P, V> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<P, V> Clone for NoopActivityReporter<P, V> {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl<P, V> std::fmt::Debug for NoopActivityReporter<P, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopActivityReporter").finish()
    }
}

impl<P, V> Reporter for NoopActivityReporter<P, V>
where
    P: PublicKey,
    V: Variant,
{
    type Activity = EngineActivity<P, V>;

    fn report(&mut self, _: Self::Activity) -> Feedback {
        Feedback::Ok
    }
}

pub(crate) type CodingBlock<H, C, V> = StoredCodedBlock<EngineBlock<H, C, V>, ReedSolomon<H>, H>;

pub type StateDb<E, H, T> = fixed::Db<mmr::Family, E, AccountKey, Account, H, EightCap, T>;

pub type StateSyncDb<E, H, T> = Shared<StateDb<E, H, T>>;

pub(crate) type StateResolverMailbox<E, H, T> =
    commonware_glue::stateful::db::p2p::standard::Mailbox<
        StateDb<E, H, T>,
        mmr::Family,
        <StateSyncDb<E, H, T> as commonware_storage::qmdb::sync::resolver::Resolver>::Op,
        <StateSyncDb<E, H, T> as commonware_storage::qmdb::sync::resolver::Resolver>::Digest,
    >;

pub(crate) type StateResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::standard::Actor<E, P, M, B, mmr::Family, StateDb<E, H, T>>;

pub type TransactionDb<E, H, T> = TransactionHistoryDb<E, H, T>;

pub type TransactionSyncDb<E, H, T> = Shared<TransactionDb<E, H, T>>;

pub(crate) type TransactionResolverMailbox<E, H, T> =
    commonware_glue::stateful::db::p2p::compact::Mailbox<
        TransactionDb<E, H, T>,
        mmr::Family,
        TransactionHistoryOperation<H>,
        H,
    >;

pub(crate) type TransactionResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::compact::Actor<
        E,
        P,
        M,
        B,
        mmr::Family,
        TransactionDb<E, H, T>,
        H,
    >;

pub type CommitteeSyncDb<E, H, T> = CommitteeDatabase<E, H, EightCap, T>;

pub(crate) type CommitteeResolverMailbox<E, H, T> =
    commonware_glue::stateful::db::p2p::standard::Mailbox<
        CommitteeDb<E, H, EightCap, T>,
        mmr::Family,
        CommitteeOperation,
        <H as Hasher>::Digest,
    >;

pub(crate) type CommitteeResolverActor<E, P, M, B, H, T> =
    commonware_glue::stateful::db::p2p::standard::Actor<
        E,
        P,
        M,
        B,
        mmr::Family,
        CommitteeDb<E, H, EightCap, T>,
    >;

pub(crate) type App<E, H, C, V, I, St> = Application<
    E,
    H,
    Commitment,
    ThresholdScheme<<C as Signer>::PublicKey, V>,
    <C as Signer>::PublicKey,
    I,
    Payload<V, C, network::Addresses<<C as Signer>::PublicKey>>,
    St,
>;

pub(crate) type AppMailbox<E, H, C, V, I, St> =
    commonware_glue::stateful::Mailbox<E, App<E, H, C, V, I, St>>;

pub(crate) type SchemeProvider<P, V> = DynamicProvider<P, V>;

pub(crate) type StatefulApp<E, H, C, V, I, St> = Stateful<
    E,
    App<E, H, C, V, I, St>,
    ThresholdScheme<<C as Signer>::PublicKey, V>,
    EngineVariant<H, C, V>,
    (
        StateResolverMailbox<E, H, St>,
        TransactionResolverMailbox<E, H, St>,
        CommitteeResolverMailbox<E, H, St>,
    ),
>;

pub(crate) type ReshareApp<E, H, C, V, I, St> =
    reshare::Application<AppMailbox<E, H, C, V, I, St>, EngineBlock<H, C, V>, V, C>;

pub(crate) type MarshaledApp<E, H, C, V, I, St> = Marshaled<
    E,
    ReshareApp<E, H, C, V, I, St>,
    EngineBlock<H, C, V>,
    ReedSolomon<H>,
    H,
    SchemeProvider<<C as Signer>::PublicKey, V>,
    St,
    FixedEpocher,
>;

pub(crate) type ShardsEngine<E, B, M, H, C, V, T> = shards::Engine<
    E,
    SchemeProvider<<C as Signer>::PublicKey, V>,
    B,
    M,
    ReedSolomon<H>,
    H,
    EngineBlock<H, C, V>,
    <C as Signer>::PublicKey,
    T,
>;

pub(crate) type ShardsMailbox<H, C, V> =
    shards::Mailbox<EngineBlock<H, C, V>, ReedSolomon<H>, H, <C as Signer>::PublicKey>;

pub(crate) type DkgManager<M> = network::AddressableManager<M>;

pub(crate) type DkgReshareActor<E, M, B, H, V, C, St, BV> = reshare::Actor<
    E,
    EngineBlock<H, C, V>,
    V,
    C,
    DkgManager<M>,
    B,
    CommitteeParticipants<
        E,
        H,
        St,
        ThresholdScheme<<C as Signer>::PublicKey, V>,
        EngineVariant<H, C, V>,
    >,
    FileSecretStore,
    St,
    BV,
    ThresholdScheme<<C as Signer>::PublicKey, V>,
    EngineVariant<H, C, V>,
    Registrar<<C as Signer>::PublicKey, V>,
>;

pub(crate) type DkgOrchestratorActor<E, M, B, H, V, C, L, St, I> = orchestrator::Actor<
    E,
    B,
    DkgManager<M>,
    SchemeProvider<<C as Signer>::PublicKey, V>,
    EngineVariant<H, C, V>,
    V,
    C,
    MarshaledApp<E, H, C, V, I, St>,
    L,
    St,
>;
