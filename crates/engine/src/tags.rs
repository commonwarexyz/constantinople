//! What travels outside blocks for transactions authenticated by tags.
//!
//! A transaction of an X25519 account is in a block without a signature. Its
//! sender gave the block's proposer one tag per validator, and the proposer
//! sends each validator its tags, one per such transaction of the block: a
//! *column*. A validator compares the tags of its column with its own and
//! signs the result, its *report*, with its vote for the block.
//!
//! This module holds the engine's side of that:
//!
//! - [`Gated`] wraps the marshaled application as consensus sees it. It lets
//!   consensus vote for a block only once the block is rebuilt from its shards,
//!   the proposer's column has arrived and the report is recorded for the vote
//!   scheme to sign. A missing column or block means no vote, and the view
//!   times out. As relay it sends the columns of the blocks this node proposes,
//!   and as reporter it keeps the notarizations consensus forms.
//! - [`EngineChain`] is the application's view of the chain: the notarization
//!   of a parent for the next proposal, the tags of a block it built, and the
//!   parent of a block it replays.
//! - [`receive`] and [`send`] move columns over their p2p channel.

use crate::{
    Scheme,
    types::{EngineBlock, EngineCommitment, EngineMarshalMailbox, MarshaledApp, ShardsMailbox},
};
use bytes::{BufMut, Bytes};
use commonware_actor::Feedback;
use commonware_codec::{Buf, Decode as _, Encode as _, EncodeSize, Error, RangeCfg, Read, Write};
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Handoff, Relay, Reporter,
    marshal::core::CommitmentFallback,
    simplex::{
        Plan,
        types::{Activity, Context, Notarization},
    },
    types::{Height, Round},
};
use commonware_cryptography::{
    Digestible, Hasher, certificate::Scheme as _, ed25519::PublicKey as P,
};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Recipients, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Spawner, Storage, telemetry::traces::TracedExt as _,
};
use commonware_utils::{
    Participant,
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    ordered::{Quorum as _, Set},
    sync::{AsyncMutex, Mutex},
};
use constantinople_application::consensus::Chain;
use constantinople_auth::{
    MAX_ENTRIES, PrivateKey, Report, SharedKeys, Tags, Verdicts, VerdictsConfig, tag_bits,
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::SealedBlock;
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};
use tracing::{Instrument as _, Span, debug, info_span, warn};

/// Notarizations are kept for this many of the latest rounds.
const RETAINED_NOTARIZATIONS: usize = 256;

/// The tags of this many of the latest blocks this node built are kept.
const RETAINED_BLOCKS: usize = 8;

/// Columns from one peer are kept for this many of its latest blocks. A column
/// can arrive before consensus asks about its block.
const RETAINED_COLUMNS: usize = 2;

/// A validator that holds a block and not the proposer's column for it asks
/// the proposer again this often.
const COLUMN_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

type Commitment<H> = EngineCommitment<H, P>;
type InnerBlock<H> = SealedBlock<Commitment<H>, P, H>;

/// A proposer's message to one validator: its tags for a block.
struct Column<H: Hasher> {
    commitment: Commitment<H>,
    tags: Tags,
}

impl<H: Hasher> Write for Column<H> {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.tags.write(buf);
    }
}

impl<H: Hasher> EncodeSize for Column<H> {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.tags.encode_size()
    }
}

impl<H: Hasher> Read for Column<H> {
    /// The tag length in bits.
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, bits: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            commitment: Commitment::<H>::read_cfg(buf, &())?,
            tags: Tags::read_cfg(buf, &(*bits, RangeCfg::new(..=MAX_ENTRIES)))?,
        })
    }
}

/// What validators say to each other on the column channel.
enum Message<H: Hasher> {
    /// A proposer's tags for one validator.
    Column(Column<H>),
    /// A validator that holds a block of the recipient and not its column asks
    /// for the column again. The network may drop a message, and without the
    /// column the validator cannot vote for the block.
    Request(Commitment<H>),
}

impl<H: Hasher> Write for Message<H> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Column(column) => {
                0u8.write(buf);
                column.write(buf);
            }
            Self::Request(commitment) => {
                1u8.write(buf);
                commitment.write(buf);
            }
        }
    }
}

impl<H: Hasher> EncodeSize for Message<H> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Column(column) => column.encode_size(),
            Self::Request(commitment) => commitment.encode_size(),
        }
    }
}

impl<H: Hasher> Read for Message<H> {
    /// The tag length in bits.
    type Cfg = u32;

    fn read_cfg(buf: &mut impl Buf, bits: &Self::Cfg) -> Result<Self, Error> {
        match u8::read_cfg(buf, &())? {
            0 => Ok(Self::Column(Column::read_cfg(buf, bits)?)),
            1 => Ok(Self::Request(Commitment::<H>::read_cfg(buf, &())?)),
            kind => Err(Error::InvalidEnum(kind)),
        }
    }
}

/// A transaction authenticated by tags: its digest and its sender's key.
type Tagged<H> = (
    <H as Hasher>::Digest,
    Option<constantinople_auth::PublicKey>,
);

/// The transactions of `block` that are authenticated by tags, in order.
fn tagged<H: Hasher>(block: &InnerBlock<H>) -> Vec<Tagged<H>> {
    block
        .body
        .iter()
        .filter_map(|lazy| lazy.get().filter(|transaction| transaction.is_mac()))
        .map(|transaction| {
            let sender = transaction.value().sender().and_then(|key| key.as_x25519());
            (*transaction.message_digest(), sender)
        })
        .collect()
}

/// What this node keeps of a block it built: its tagged transactions and the
/// authenticator of each.
struct Built<H: Hasher> {
    tagged: Vec<Tagged<H>>,
    authenticators: Vec<Tags>,
}

impl<H: Hasher> Clone for Built<H> {
    fn clone(&self) -> Self {
        Self {
            tagged: self.tagged.clone(),
            authenticators: self.authenticators.clone(),
        }
    }
}

struct Book<H: Hasher> {
    /// Blocks this node built, by block digest, oldest first.
    built: VecDeque<(H::Digest, Built<H>)>,
    /// Columns received from each peer, oldest first.
    received: HashMap<P, VecDeque<(Commitment<H>, Tags)>>,
    /// Requests for a column that has not arrived.
    waiting: Vec<(P, Commitment<H>, oneshot::Sender<Tags>)>,
    /// Notarizations that consensus formed or received.
    notarizations: BTreeMap<Round, Notarization<Scheme, Commitment<H>>>,
}

/// State shared by the gate, the application's chain view and the column
/// tasks.
pub(crate) struct Shared<H: Hasher>(Arc<Mutex<Book<H>>>);

impl<H: Hasher> Clone for Shared<H> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<H: Hasher> Shared<H> {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(Book {
            built: VecDeque::new(),
            received: HashMap::new(),
            waiting: Vec::new(),
            notarizations: BTreeMap::new(),
        })))
    }

    fn built(&self, block: H::Digest, built: Built<H>) {
        let mut book = self.0.lock();
        book.built.push_back((block, built));
        while book.built.len() > RETAINED_BLOCKS {
            book.built.pop_front();
        }
    }

    fn own(&self, block: &H::Digest) -> Option<Built<H>> {
        let book = self.0.lock();
        book.built
            .iter()
            .rev()
            .find(|(digest, _)| digest == block)
            .map(|(_, built)| built.clone())
    }

    fn received(&self, peer: P, commitment: Commitment<H>, tags: Tags) {
        let mut book = self.0.lock();

        // Hand the column to whoever waits for it, and keep it for a request
        // that comes later.
        let mut index = 0;
        while index < book.waiting.len() {
            let (from, wanted, _) = &book.waiting[index];
            if *from == peer && *wanted == commitment {
                let (_, _, waiter) = book.waiting.swap_remove(index);
                waiter.send_lossy(tags.clone());
            } else {
                index += 1;
            }
        }
        book.waiting.retain(|(_, _, waiter)| !waiter.is_closed());

        let columns = book.received.entry(peer).or_default();
        columns.retain(|(held, _)| *held != commitment);
        columns.push_back((commitment, tags));
        while columns.len() > RETAINED_COLUMNS {
            columns.pop_front();
        }
    }

    /// The column `peer` sent for the block with `commitment`, once it arrives.
    fn column(&self, peer: P, commitment: Commitment<H>) -> oneshot::Receiver<Tags> {
        let (sender, receiver) = oneshot::channel();
        let mut book = self.0.lock();
        let held = book.received.get(&peer).and_then(|columns| {
            columns
                .iter()
                .find(|(held, _)| *held == commitment)
                .map(|(_, tags)| tags.clone())
        });
        match held {
            Some(tags) => {
                sender.send_lossy(tags);
            }
            None => book.waiting.push((peer, commitment, sender)),
        }
        receiver
    }

    fn notarized(&self, notarization: Notarization<Scheme, Commitment<H>>) {
        let mut book = self.0.lock();
        book.notarizations
            .insert(notarization.proposal.round, notarization);
        while book.notarizations.len() > RETAINED_NOTARIZATIONS {
            book.notarizations.pop_first();
        }
    }

    fn notarization(
        &self,
        round: Round,
        payload: &Commitment<H>,
    ) -> Option<Notarization<Scheme, Commitment<H>>> {
        self.0
            .lock()
            .notarizations
            .get(&round)
            .filter(|notarization| notarization.proposal.payload == *payload)
            .cloned()
    }
}

/// The application's view of the chain, backed by the engine.
pub struct EngineChain<H: Hasher> {
    shared: Shared<H>,
    marshal: EngineMarshalMailbox<H, P>,
}

impl<H: Hasher> EngineChain<H> {
    pub(crate) const fn new(shared: Shared<H>, marshal: EngineMarshalMailbox<H, P>) -> Self {
        Self { shared, marshal }
    }
}

impl<H: Hasher> Clone for EngineChain<H> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            marshal: self.marshal.clone(),
        }
    }
}

impl<H: Hasher> Chain<Commitment<H>, P, H> for EngineChain<H> {
    async fn notarization(
        &self,
        round: Round,
        payload: Commitment<H>,
    ) -> Option<Notarization<Scheme, Commitment<H>>> {
        self.shared.notarization(round, &payload)
    }

    fn built(&self, block: &InnerBlock<H>, authenticators: Vec<Tags>) {
        let built = Built {
            tagged: tagged(block),
            authenticators,
        };
        self.shared.built(block.digest(), built);
    }

    async fn parent(&self, block: &InnerBlock<H>) -> Option<Arc<InnerBlock<H>>> {
        // A block that is replayed is finalized, so marshal holds its parent
        // unless it pruned it. It then asks peers that still serve it.
        let height = block.header.height.checked_sub(1)?;
        if let Some(parent) = self.marshal.get_block(Height::new(height)).await
            && parent.digest() == block.header.parent
        {
            return Some(parent.inner().inner_shared());
        }
        let context = &block.header.context;
        let round = Round::new(context.round.epoch(), context.parent.0);
        debug!(height, %round, "parent of replayed block is not stored: fetching it");
        self.marshal
            .subscribe_by_commitment(context.parent.1, CommitmentFallback::FetchByRound { round })
            .await
            .ok()
            .map(|parent| parent.inner().inner_shared())
    }
}

/// Turns a block and the column its proposer sent into this validator's report.
pub(crate) struct Tagger<E, H>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
{
    /// Namespace of the keys users share with validators.
    namespace: &'static [u8],
    /// `K(u, i)` for the senders seen lately. A miss costs one Diffie-Hellman.
    keys: SharedKeys,
    verdicts: AsyncMutex<Verdicts<E, H::Digest>>,
    /// Length of a tag in bits.
    bits: u32,
}

impl<E, H> Tagger<E, H>
where
    E: BufferPooler + Storage + Clock + Metrics,
    H: Hasher,
{
    pub(crate) async fn new(
        context: E,
        namespace: &'static [u8],
        secret: PrivateKey,
        validators: usize,
        key_cache: NonZeroUsize,
        verdicts: VerdictsConfig,
    ) -> Self {
        let verdicts = Verdicts::init(context, verdicts)
            .await
            .expect("verdict store must open");
        Self {
            namespace,
            keys: SharedKeys::new(secret, key_cache),
            verdicts: AsyncMutex::new(verdicts),
            bits: tag_bits(u32::try_from(validators).expect("validator count fits in u32")),
        }
    }

    /// This validator's report on a block by `proposer` with the tagged
    /// transactions `tagged`, given the column the proposer sent it.
    ///
    /// A column that does not hold one tag per tagged transaction of the block
    /// matches nothing.
    async fn report(
        &self,
        strategy: &impl Strategy,
        proposer: Participant,
        tagged: Vec<Tagged<H>>,
        column: &Tags,
    ) -> Report {
        if tagged.is_empty() {
            return Report::empty();
        }
        let shaped = column.len() == tagged.len() && column.bits() == self.bits;

        // The keys of all the block's senders are looked up at once. A lookup
        // for each transaction, from every thread that compares tags, would
        // have the threads queue on the cache (see [`SharedKeys`]).
        let senders: Vec<_> = tagged.iter().filter_map(|(_, sender)| *sender).collect();
        let mut keys = {
            let _span = info_span!("engine.tags.keys", senders = senders.len().traced()).entered();
            self.keys
                .resolve(self.namespace, &senders, strategy)
                .into_iter()
        };
        let work: Vec<_> = tagged
            .into_iter()
            .enumerate()
            .map(|(position, (digest, sender))| {
                // `keys` has one entry for each transaction that names a
                // sender, in block order.
                let key = sender.and_then(|_| keys.next().flatten());
                (position, digest, key)
            })
            .collect();
        let entries = {
            let _span = info_span!("engine.tags.compare", txs = work.len().traced()).entered();
            strategy.map_collect_vec(work, |(position, digest, key)| {
                let own = key.map(|key| key.tag.tag(proposer, digest.as_ref(), self.bits));
                let matches = shaped && own.is_some() && own == column.get(position);
                (digest, matches)
            })
        };
        let verdicts: Vec<bool> = async {
            self.verdicts
                .lock()
                .await
                .check(proposer, entries)
                .await
                .expect("verdict store must record rejections")
        }
        .instrument(info_span!("engine.tags.verdicts"))
        .await;
        Report::new(&verdicts)
    }
}

/// The marshaled application as consensus sees it (see the module docs).
pub(crate) struct Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    context: Arc<E>,
    inner: MarshaledApp<E, H, P, I, St>,
    shards: ShardsMailbox<H, P>,
    shared: Shared<H>,
    tagger: Arc<Tagger<E, H>>,
    scheme: Scheme,
    strategy: St,
    /// Columns for the task that sends them to peers.
    columns: mpsc::UnboundedSender<(P, Bytes)>,
}

impl<E, H, I, St> Clone for Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    fn clone(&self) -> Self {
        Self {
            context: Arc::clone(&self.context),
            inner: self.inner.clone(),
            shards: self.shards.clone(),
            shared: self.shared.clone(),
            tagger: Arc::clone(&self.tagger),
            scheme: self.scheme.clone(),
            strategy: self.strategy.clone(),
            columns: self.columns.clone(),
        }
    }
}

impl<E, H, I, St> Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        context: E,
        inner: MarshaledApp<E, H, P, I, St>,
        shards: ShardsMailbox<H, P>,
        shared: Shared<H>,
        tagger: Tagger<E, H>,
        scheme: Scheme,
        strategy: St,
        columns: mpsc::UnboundedSender<(P, Bytes)>,
    ) -> Self {
        Self {
            context: Arc::new(context),
            inner,
            shards,
            shared,
            tagger: Arc::new(tagger),
            scheme,
            strategy,
            columns,
        }
    }

    /// Records this validator's report on the block with `commitment`, proposed
    /// by `leader` in `round`, so that the vote scheme can sign a vote for it.
    ///
    /// For a block of another validator this waits for the block to be rebuilt
    /// from its shards and, if the block has tagged transactions, for the
    /// leader's column. Returns `false` if the report can never be made.
    async fn record(&self, round: Round, commitment: Commitment<H>, leader: &P) -> bool {
        // A node that does not vote has nothing to report.
        let Some(me) = self.scheme.me() else {
            return true;
        };
        let Some(proposer) = self.scheme.participants().index(leader) else {
            return false;
        };

        let (tagged, column) = if proposer == me {
            // This node built the block: it knows the block's tagged
            // transactions, and their tags never left it.
            let Some(built) = self.shared.own(&commitment.block()) else {
                warn!(%round, "tags of own block are gone");
                return false;
            };
            let column = column_for(&built.authenticators, me, self.tagger.bits);
            (built.tagged, column)
        } else {
            let rebuilt = self
                .shards
                .subscribe(commitment)
                .instrument(info_span!("engine.tags.block_wait"))
                .await;
            let Ok(block) = rebuilt else {
                return false;
            };
            let block: &EngineBlock<H, P> = block.inner();
            let tagged = tagged(block);
            let column = if tagged.is_empty() {
                Tags::new(self.tagger.bits)
            } else {
                // The leader sends the column right after the block's shards,
                // so it normally arrives before the block is rebuilt. If the
                // network dropped it, the leader sends it again on request,
                // for as long as consensus waits for this verdict.
                let mut column = self.shared.column(leader.clone(), commitment);
                let arrived = async {
                    loop {
                        select! {
                            column = &mut column => break column.ok(),
                            _ = self.context.sleep(COLUMN_REQUEST_INTERVAL) => {
                                let request = Message::<H>::Request(commitment).encode();
                                if self.columns.send((leader.clone(), request)).is_err() {
                                    break None;
                                }
                            },
                        }
                    }
                }
                .instrument(info_span!("engine.tags.column_wait"))
                .await;
                let Some(column) = arrived else {
                    return false;
                };
                column
            };
            (tagged, column)
        };
        let report = self
            .tagger
            .report(&self.strategy, proposer, tagged, &column)
            .await;
        self.scheme
            .reports()
            .insert(round, commitment.as_ref(), report);
        true
    }

    /// Sends every other validator its column for the block with `commitment`,
    /// which this node built.
    ///
    /// A column takes a pass over the block's authenticators, and there is one
    /// for each validator. They are built together on the pool, in a task of
    /// their own, so that the caller is not held up for them.
    fn send_columns(&self, commitment: Commitment<H>) {
        let Some(Built { authenticators, .. }) = self.shared.own(&commitment.block()) else {
            return;
        };
        if authenticators.is_empty() {
            return;
        }
        let me = self.scheme.me();
        let peers: Vec<_> = self
            .scheme
            .participants()
            .iter()
            .enumerate()
            .map(|(index, peer)| (Participant::from_usize(index), peer.clone()))
            .filter(|(validator, _)| Some(*validator) != me)
            .collect();
        let span = info_span!(
            "engine.tags.columns",
            txs = authenticators.len().traced(),
            validators = peers.len().traced(),
        );
        let strategy = self.strategy.clone();
        let columns = self.columns.clone();
        let bits = self.tagger.bits;
        self.context.child("columns").spawn(move |_| async move {
            let built = {
                let _span = span.entered();
                strategy.map_collect_vec(peers, |(validator, peer)| {
                    let column = Message::Column(Column::<H> {
                        commitment,
                        tags: column_for(&authenticators, validator, bits),
                    });
                    (peer, column.encode())
                })
            };
            for column in built {
                if columns.send(column).is_err() {
                    debug!("column sender stopped");
                    return;
                }
            }
        });
    }
}

/// The tags for `validator` out of the authenticators of a block's tagged
/// transactions.
fn column_for(authenticators: &[Tags], validator: Participant, bits: u32) -> Tags {
    let mut column = Tags::with_capacity(bits, authenticators.len());
    column.extend(
        authenticators
            .iter()
            .filter_map(|authenticator| authenticator.get(usize::from(validator))),
    );
    column
}

impl<E, H, I, St> Automaton for Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    type Context = Context<Commitment<H>, P>;
    type Digest = Commitment<H>;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let built = self.inner.propose(context.clone()).await;
        let (mut sender, receiver) = oneshot::channel();
        let this = self.clone();
        let parent = Span::current();
        self.context.child("report_own").spawn(move |_| async move {
            select! {
                _ = sender.closed() => {},
                recorded = async {
                    let commitment = built.await.ok()?;
                    // The proposal is not released before this node's own
                    // report on it is recorded.
                    let span = info_span!(
                        parent: &parent,
                        "engine.tags.report_own",
                        view = context.round.view().get().traced(),
                    );
                    this.record(context.round, commitment, &context.leader)
                        .instrument(span)
                        .await
                        .then_some(commitment)
                } => {
                    // Without a report there is no vote, so there is no proposal.
                    if let Some(commitment) = recorded {
                        sender.send_lossy(commitment);
                    }
                },
            }
        });
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let verified = self.inner.verify(context.clone(), payload).await;
        let (mut sender, receiver) = oneshot::channel();
        let this = self.clone();
        let parent = Span::current();
        self.context.child("report").spawn(move |_| async move {
            select! {
                _ = sender.closed() => {},
                recorded = async {
                    // The shard assigned to this validator is valid.
                    if !verified.await.ok()? {
                        return Some(false);
                    }
                    // No column or no block means no vote: the view times out.
                    let span = info_span!(
                        parent: &parent,
                        "engine.tags.report",
                        view = context.round.view().get().traced(),
                    );
                    this.record(context.round, payload, &context.leader)
                        .instrument(span)
                        .await
                        .then_some(true)
                } => {
                    if let Some(verdict) = recorded {
                        sender.send_lossy(verdict);
                    }
                },
            }
        });
        receiver
    }
}

impl<E, H, I, St> CertifiableAutomaton for Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    async fn prepare(
        &mut self,
        context: Self::Context,
    ) -> oneshot::Receiver<Handoff<Self::Digest>> {
        self.inner.prepare(context).await
    }

    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        self.inner.certify(round, payload).await
    }
}

impl<E, H, I, St> Relay for Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    type Digest = Commitment<H>;
    type PublicKey = P;
    type Plan = Plan<P>;

    fn broadcast(&mut self, commitment: Self::Digest, plan: Self::Plan) -> Feedback {
        // The block goes out first. A validator can do nothing with its column
        // before it has rebuilt the block, which takes longer than the column
        // takes to follow.
        let propose = matches!(plan, Plan::Propose { .. });
        let feedback = self.inner.broadcast(commitment, plan);
        if propose {
            self.send_columns(commitment);
        }
        feedback
    }
}

impl<E, H, I, St> Reporter for Gated<E, H, I, St>
where
    E: BufferPooler + Storage + Clock + Metrics + Rng + Spawner + CryptoRng,
    H: Hasher,
    I: TransactionSource<Commitment<H>, P, H> + Clone + Sync,
    St: Strategy,
{
    type Activity = Activity<Scheme, Commitment<H>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // The next proposer puts a notarization of its parent in its block.
        if let Activity::Notarization(notarization) | Activity::Certification(notarization) =
            &activity
        {
            self.shared.notarized(notarization.clone());
        }
        self.inner.report(activity)
    }
}

/// Receives columns and requests for columns from peers until the channel
/// closes. `replies` takes the columns this node sends again on request.
pub(crate) async fn receive<H: Hasher>(
    shared: Shared<H>,
    bits: u32,
    participants: Set<P>,
    replies: mpsc::UnboundedSender<(P, Bytes)>,
    mut receiver: impl Receiver<PublicKey = P>,
    mut blocker: impl Blocker<PublicKey = P>,
) {
    while let Ok((peer, message)) = receiver.recv().await {
        match Message::<H>::decode_cfg(message, &bits) {
            Ok(Message::Column(column)) => shared.received(peer, column.commitment, column.tags),
            Ok(Message::Request(commitment)) => {
                // Only a validator has a column, and only for a block this
                // node built and still holds.
                let Some(validator) = participants.index(&peer) else {
                    continue;
                };
                let Some(Built { authenticators, .. }) = shared.own(&commitment.block()) else {
                    continue;
                };
                let column = Message::Column(Column::<H> {
                    commitment,
                    tags: column_for(&authenticators, validator, bits),
                });
                if replies.send((peer, column.encode())).is_err() {
                    debug!("column sender stopped");
                    return;
                }
            }
            Err(error) => {
                commonware_p2p::block!(blocker, peer, ?error, "malformed column message");
            }
        }
    }
}

/// Sends the columns of blocks this node proposes.
pub(crate) async fn send(
    mut columns: mpsc::UnboundedReceiver<(P, Bytes)>,
    mut sender: impl Sender<PublicKey = P>,
) {
    while let Some((peer, column)) = columns.recv().await {
        if sender
            .send(Recipients::One(peer.clone()), column, true)
            .is_empty()
        {
            debug!(%peer, "column not sent");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, test_rng};
    use constantinople_auth::PublicKey as TagPublicKey;

    const NAMESPACE: &[u8] = b"chain";
    const VALIDATORS: usize = 6;

    /// A validator says yes to exactly the transactions whose tag in its
    /// column is the one it computes with their own sender's key. That holds
    /// when some transactions name no sender or a sender with no key, when a
    /// sender has several transactions, and when the block has more senders
    /// than the validator keeps keys for.
    #[test]
    fn report_checks_each_transaction_under_its_own_senders_key() {
        deterministic::Runner::default().start(|context| async move {
            let secret = PrivateKey::from([7; 32]);
            let tagger = Tagger::<_, Sha256>::new(
                context.child("tagger"),
                NAMESPACE,
                secret.clone(),
                VALIDATORS,
                NZUsize!(4),
                VerdictsConfig {
                    partition: "verdicts".into(),
                    items_per_blob: NZU64!(64),
                    page_cache: CacheRef::from_pooler(
                        &context.child("cache"),
                        NZU16!(64),
                        NZUsize!(16),
                    ),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                },
            )
            .await;
            let bits = tagger.bits;
            let proposer = Participant::new(4);

            let mut rng = test_rng();
            let users: Vec<_> = (0..12).map(|_| PrivateKey::random(&mut rng)).collect();
            let low_order = TagPublicKey::from([0; 32]);
            let digest = |byte: u8| <Sha256 as Hasher>::Digest::from([byte; 32]);

            // Sixty transactions by twelve users, in turn. Some name no sender,
            // some a sender whose key is a low-order point, and some carry the
            // tag of another transaction.
            let mut tagged = Vec::new();
            let mut column = Tags::new(bits);
            let mut expected = Vec::new();
            for position in 0..60u8 {
                let user = &users[position as usize % users.len()];
                let own = user
                    .with_validator(NAMESPACE, &secret.public_key())
                    .expect("validator key is not low order");
                let (sender, approved) = match position % 5 {
                    0 => (None, false),
                    1 => (Some(low_order), false),
                    _ => (Some(user.public_key()), position % 3 != 0),
                };
                let tag_of = if position % 3 == 0 {
                    position + 100
                } else {
                    position
                };
                column.push(&own.tag.tag(proposer, digest(tag_of).as_ref(), bits));
                tagged.push((digest(position), sender));
                expected.push(approved);
            }
            assert!(expected.iter().any(|approved| *approved));
            assert!(expected.iter().any(|approved| !*approved));

            // From one thread and from a pool, twice each: the second time
            // some keys are cached.
            let pool = Rayon::new(NZUsize!(3)).expect("pool starts");
            for _ in 0..2 {
                let one = tagger
                    .report(&Sequential, proposer, tagged.clone(), &column)
                    .await;
                assert_eq!(one, Report::new(&expected));
                let many = tagger
                    .report(&pool, proposer, tagged.clone(), &column)
                    .await;
                assert_eq!(many, Report::new(&expected));
            }

            // A column of another length matches nothing.
            let mut short = Tags::new(bits);
            short.push(&column.get(0).expect("column has tags"));
            let none = tagger
                .report(&Sequential, proposer, tagged.clone(), &short)
                .await;
            assert_eq!(none, Report::new(&vec![false; tagged.len()]));
        });
    }
}
