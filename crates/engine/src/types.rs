//! Shared type aliases for the engine crate.
//!
//! These canonical aliases give a single definition to the core block,
//! coding, marshal, and finalization types that appear throughout the
//! engine, bootstrapper, and test modules.

use crate::ThresholdScheme;
use commonware_coding::ReedSolomon;
use commonware_consensus::{
    marshal::{
        coding::{Coding, Marshaled, shards, types::StoredCodedBlock},
        core::Mailbox as MarshalMailbox,
    },
    simplex::{self, types::Finalization},
    types::{Epoch, FixedEpocher, coding::Commitment},
};
use commonware_cryptography::certificate::ConstantProvider;
use commonware_glue::stateful::Stateful;
use commonware_storage::{
    mmr,
    qmdb::{any::unordered::fixed, sync::resolver::Resolver as SyncResolver},
    translator::EightCap,
};
use commonware_utils::sync::AsyncRwLock;
use constantinople_application::consensus::Application;
use constantinople_primitives::{Account, Address, Block, Sealed};
use std::sync::Arc;

/// A finalized block with its seal (commitment-based).
pub type EngineBlock<H, P> = Sealed<Block<Commitment, P, H>, H>;

/// The erasure-coding variant used by the marshal for block availability.
pub type EngineVariant<H, P> = Coding<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

/// Marshal mailbox parameterized over the engine's threshold scheme.
pub type EngineMarshalMailbox<H, P, V> = MarshalMailbox<ThresholdScheme<P, V>, EngineVariant<H, P>>;

/// A finalization certificate over the engine's threshold scheme.
pub type EngineFinalization<P, V> = Finalization<ThresholdScheme<P, V>, Commitment>;

pub(crate) type CodingBlock<H, P> = StoredCodedBlock<EngineBlock<H, P>, ReedSolomon<H>, H>;

pub type StateDb<E, H> = fixed::Db<mmr::Family, E, Address, Account, H, EightCap>;

pub type StateSyncDb<E, H> = Arc<AsyncRwLock<StateDb<E, H>>>;

pub(crate) type StateResolverMailbox<E, H> = commonware_glue::stateful::db::p2p::Mailbox<
    StateDb<E, H>,
    mmr::Family,
    <StateSyncDb<E, H> as SyncResolver>::Op,
    <StateSyncDb<E, H> as SyncResolver>::Digest,
>;

pub(crate) type App<H, P, V, I, B, T> =
    Application<H, Commitment, ThresholdScheme<P, V>, P, I, B, T>;

pub(crate) type AppMailbox<E, H, P, V, I, B, T> =
    commonware_glue::stateful::Mailbox<E, App<H, P, V, I, B, T>>;

pub(crate) type SchemeProvider<P, V> = ConstantProvider<ThresholdScheme<P, V>, Epoch>;

pub(crate) type StatefulApp<E, H, P, V, I, B, T> =
    Stateful<E, App<H, P, V, I, B, T>, EngineMarshalMailbox<H, P, V>, StateResolverMailbox<E, H>>;

pub(crate) type MarshaledApp<E, H, P, V, I, B, T> = Marshaled<
    E,
    AppMailbox<E, H, P, V, I, B, T>,
    EngineBlock<H, P>,
    ReedSolomon<H>,
    H,
    SchemeProvider<P, V>,
    T,
    FixedEpocher,
>;

pub(crate) type ShardsEngine<E, B, M, H, P, V, T> =
    shards::Engine<E, SchemeProvider<P, V>, B, M, ReedSolomon<H>, H, EngineBlock<H, P>, P, T>;

pub(crate) type ShardsMailbox<H, P> = shards::Mailbox<EngineBlock<H, P>, ReedSolomon<H>, H, P>;

pub(crate) type SimplexEngine<E, B, H, P, V, L, T, I, BV> = simplex::Engine<
    E,
    ThresholdScheme<P, V>,
    L,
    B,
    Commitment,
    MarshaledApp<E, H, P, V, I, BV, T>,
    MarshaledApp<E, H, P, V, I, BV, T>,
    EngineMarshalMailbox<H, P, V>,
    T,
>;
