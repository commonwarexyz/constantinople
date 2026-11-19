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
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_utils::{
    Participant,
    cache::Cache,
    channel::{fallible::OneshotExt as _, mpsc, oneshot},
    ordered::Quorum as _,
    sync::{AsyncMutex, Mutex},
};
use constantinople_application::consensus::Chain;
use constantinople_auth::{
    MAX_ENTRIES, PrivateKey, Report, SharedKey, Tags, Verdicts, VerdictsConfig, tag_bits,
};
use constantinople_mempool::TransactionSource;
use constantinople_primitives::SealedBlock;
use rand::{CryptoRng, Rng};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
};
use tracing::{debug, warn};

/// Notarizations are kept for this many of the latest rounds.
const RETAINED_NOTARIZATIONS: usize = 256;

/// The tags of this many of the latest blocks this node built are kept.
const RETAINED_BLOCKS: usize = 8;

/// Columns from one peer are kept for this many of its latest blocks. A column
/// can arrive before consensus asks about its block.
const RETAINED_COLUMNS: usize = 2;

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

/// A transaction authenticated by tags: its digest and its sender's key.
type Tagged<H> = (<H as Hasher>::Digest, Option<constantinople_auth::PublicKey>);

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
    /// This validator's X25519 secret.
    secret: PrivateKey,
    /// `K(u, i)` for the senders seen lately. A miss costs one Diffie-Hellman.
    keys: Mutex<Cache<constantinople_auth::PublicKey, SharedKey>>,
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
            secret,
            keys: Mutex::new(Cache::new(key_cache)),
            verdicts: AsyncMutex::new(verdicts),
            bits: tag_bits(u32::try_from(validators).expect("validator count fits in u32")),
        }
    }

    /// The key this validator shares with `user`.
    fn key(&self, user: &constantinople_auth::PublicKey) -> Option<SharedKey> {
        if let Some(key) = self.keys.lock().get(user) {
            return Some(key.clone());
        }
        let key = self.secret.with_user(self.namespace, user)?;
        self.keys.lock().put(*user, key.clone());
        Some(key)
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
        let work: Vec<_> = tagged.into_iter().enumerate().collect();
        let entries = strategy.map_collect_vec(work, |(position, (digest, sender))| {
            let own = sender
                .and_then(|sender| self.key(&sender))
                .map(|key| key.tag.tag(proposer, digest.as_ref(), self.bits));
            let matches = shaped && own.is_some() && own == column.get(position);
            (digest, matches)
        });
        let verdicts = self
            .verdicts
            .lock()
            .await
            .check(proposer, entries)
            .await
            .expect("verdict store must record rejections");
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
            let Ok(block) = self.shards.subscribe(commitment).await else {
                return false;
            };
            let block: &EngineBlock<H, P> = block.inner();
            let tagged = tagged(block);
            let column = if tagged.is_empty() {
                Tags::new(self.tagger.bits)
            } else {
                match self.shared.column(leader.clone(), commitment).await {
                    Ok(column) => column,
                    Err(_) => return false,
                }
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
    fn send_columns(&self, commitment: Commitment<H>) {
        let Some(Built { authenticators, .. }) = self.shared.own(&commitment.block()) else {
            return;
        };
        if authenticators.is_empty() {
            return;
        }
        let me = self.scheme.me();
        for (index, peer) in self.scheme.participants().iter().enumerate() {
            let validator = Participant::from_usize(index);
            if Some(validator) == me {
                continue;
            }
            let column = Column::<H> {
                commitment,
                tags: column_for(&authenticators, validator, self.tagger.bits),
            };
            if self.columns.send((peer.clone(), column.encode())).is_err() {
                debug!("column sender stopped");
                return;
            }
        }
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
        self.context.child("report_own").spawn(move |_| async move {
            select! {
                _ = sender.closed() => {},
                recorded = async {
                    let commitment = built.await.ok()?;
                    this.record(context.round, commitment, &context.leader)
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
        self.context.child("report").spawn(move |_| async move {
            select! {
                _ = sender.closed() => {},
                recorded = async {
                    // The shard assigned to this validator is valid.
                    if !verified.await.ok()? {
                        return Some(false);
                    }
                    // No column or no block means no vote: the view times out.
                    this.record(context.round, payload, &context.leader)
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
        if matches!(plan, Plan::Propose { .. }) {
            self.send_columns(commitment);
        }
        self.inner.broadcast(commitment, plan)
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

/// Receives columns from peers until the channel closes.
pub(crate) async fn receive<H: Hasher>(
    shared: Shared<H>,
    bits: u32,
    mut receiver: impl Receiver<PublicKey = P>,
    mut blocker: impl Blocker<PublicKey = P>,
) {
    while let Ok((peer, message)) = receiver.recv().await {
        match Column::<H>::decode_cfg(message, &bits) {
            Ok(column) => shared.received(peer, column.commitment, column.tags),
            Err(error) => {
                commonware_p2p::block!(blocker, peer, ?error, "malformed column");
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
        if sender.send(Recipients::One(peer.clone()), column, true).is_empty() {
            debug!(%peer, "column not sent");
        }
    }
}
