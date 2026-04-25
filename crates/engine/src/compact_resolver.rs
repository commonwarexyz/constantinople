//! P2P resolver for compact QMDB state sync.

use commonware_codec::{
    Codec, DecodeExt as _, Encode, EncodeSize, Error as CodecError, Read, ReadExt as _,
    ReadRangeExt as _, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_macros::select_loop;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{Resolver as _, p2p};
use commonware_runtime::{BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_storage::{
    merkle::{
        Family, Location, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof, hasher::Standard as StandardHasher,
    },
    qmdb::{
        self,
        sync::{compact, compact::Resolver as _},
    },
};
use commonware_utils::{
    Span,
    channel::{
        fallible::{AsyncFallibleExt, OneshotExt},
        mpsc, oneshot,
    },
    sync::AsyncRwLock,
};
use futures::future::{self, Either};
use rand::Rng;
use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher as StdHasher},
    marker::PhantomData,
    sync::Arc,
    time::Duration,
};
use tracing::info;

const MAX_PINNED_NODES: usize = 64;

type DbResolver<DB> = Arc<AsyncRwLock<DB>>;
type DbOp<DB> = <DbResolver<DB> as compact::Resolver>::Op;
type Pending<F, Op, D> = oneshot::Sender<Result<compact::State<F, Op, D>, ResponseDropped>>;
type PendingSubs<F, Op, D> = BTreeMap<Request<F, D>, Vec<Pending<F, Op, D>>>;

/// The resolver actor dropped the response before completion.
#[derive(Debug, thiserror::Error)]
#[error("response dropped before completion")]
pub struct ResponseDropped;

enum Message<DB, F, Op, H>
where
    F: Family,
    H: Hasher,
{
    AttachDatabase(DbResolver<DB>),
    GetState {
        target: compact::Target<F, H::Digest>,
        response: Pending<F, Op, H::Digest>,
    },
}

/// Client-facing resolver mailbox used by compact QMDB sync.
pub struct Mailbox<DB, F, Op, H>
where
    F: Family,
    H: Hasher,
{
    sender: mpsc::Sender<Message<DB, F, Op, H>>,
}

impl<DB, F, Op, H> Clone for Mailbox<DB, F, Op, H>
where
    F: Family,
    H: Hasher,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<DB, F, Op, H> Mailbox<DB, F, Op, H>
where
    F: Family,
    H: Hasher,
{
    fn new(sender: mpsc::Sender<Message<DB, F, Op, H>>) -> Self {
        Self { sender }
    }
}

impl<DB, F, Op, H> Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    async fn attach_database(&self, db: DbResolver<DB>) {
        self.sender.send_lossy(Message::AttachDatabase(db)).await;
    }
}

impl<DB, F, Op, H> compact::Resolver for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    type Digest = H::Digest;
    type Error = ResponseDropped;
    type Family = F;
    type Op = Op;

    async fn get_compact_state(
        &self,
        target: compact::Target<Self::Family, Self::Digest>,
    ) -> Result<compact::State<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        self.sender
            .request(|response| Message::GetState { target, response })
            .await
            .ok_or(ResponseDropped)?
    }
}

impl<DB, F, Op, H> commonware_glue::stateful::db::AttachableResolver<DB> for Mailbox<DB, F, Op, H>
where
    DB: Send + Sync + 'static,
    F: Family,
    Op: Send + Sync + Clone + 'static,
    H: Hasher,
{
    async fn attach_database(&self, db: DbResolver<DB>) {
        self.attach_database(db).await;
    }
}

/// Configuration for [`Actor`].
pub struct Config<P, D, B, DB>
where
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
{
    /// Provider for the current peer set.
    pub peer_provider: D,
    /// Blocker used when peers send invalid data.
    pub blocker: B,
    /// Local database used to serve incoming requests when available.
    pub database: Option<DbResolver<DB>>,
    /// Maximum size of resolver mailbox backlogs.
    pub mailbox_size: usize,
    /// Local node identity if available.
    pub me: Option<P>,
    /// Initial expected performance for new peers.
    pub initial: Duration,
    /// Request timeout.
    pub timeout: Duration,
    /// Retry cadence for pending fetches.
    pub fetch_retry_timeout: Duration,
    /// Send fetch requests with network priority.
    pub priority_requests: bool,
    /// Send responses with network priority.
    pub priority_responses: bool,
}

enum State<DB> {
    NoDb,
    HasDb(DbResolver<DB>),
}

enum MailboxAction<F: Family, D: Digest> {
    None,
    Fetch(Request<F, D>),
}

/// Runs a compact QMDB sync resolver service over P2P.
pub struct Actor<E, P, D, B, F, DB, H>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    H: Hasher,
    DbResolver<DB>: compact::Resolver<Family = F, Digest = H::Digest>,
    DbOp<DB>: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    context: ContextCell<E>,
    config: Config<P, D, B, DB>,
    mailbox_rx: mpsc::Receiver<Message<DB, F, DbOp<DB>, H>>,
    state: State<DB>,
    pending: PendingSubs<F, DbOp<DB>, H::Digest>,
    _hasher: PhantomData<H>,
}

impl<E, P, D, B, F, DB, H> Actor<E, P, D, B, F, DB, H>
where
    E: BufferPooler + Clock + Spawner + Rng + Metrics,
    P: PublicKey,
    D: Provider<PublicKey = P>,
    B: Blocker<PublicKey = P>,
    F: Family,
    H: Hasher,
    DbResolver<DB>: compact::Resolver<Family = F, Digest = H::Digest>,
    DbOp<DB>: Codec<Cfg = ()> + Clone + Send + Sync + 'static,
{
    /// Create a new compact resolver actor and mailbox.
    pub fn new(context: E, mut config: Config<P, D, B, DB>) -> (Self, Mailbox<DB, F, DbOp<DB>, H>) {
        let state = config.database.take().map_or(State::NoDb, State::HasDb);
        let (mailbox_tx, mailbox_rx) = mpsc::channel(config.mailbox_size);
        let mailbox = Mailbox::new(mailbox_tx);
        let actor = Self {
            context: ContextCell::new(context),
            config,
            mailbox_rx,
            state,
            pending: BTreeMap::new(),
            _hasher: PhantomData,
        };
        (actor, mailbox)
    }

    /// Start the resolver service.
    pub fn start(
        mut self,
        net: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(net))
    }

    async fn run(
        mut self,
        (sender, receiver): (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        let (handler_tx, mut handler_rx) = mpsc::channel(self.config.mailbox_size);
        let handler = Handler::<F, H::Digest>::new(handler_tx);
        let (engine, mut resolver_mailbox) = p2p::Engine::new(
            self.context.clone().into_present().with_label("resolver"),
            p2p::Config {
                peer_provider: self.config.peer_provider.clone(),
                blocker: self.config.blocker.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.config.mailbox_size,
                me: self.config.me.clone(),
                initial: self.config.initial,
                timeout: self.config.timeout,
                fetch_retry_timeout: self.config.fetch_retry_timeout,
                priority_requests: self.config.priority_requests,
                priority_responses: self.config.priority_responses,
            },
        );
        let mut resolver_task = engine.start((sender, receiver));

        select_loop! {
            self.context,
            on_start => {
                self.pending.retain(|_, subscribers| {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    !subscribers.is_empty()
                });
                let mailbox_message = if !(self.mailbox_rx.is_closed() && self.mailbox_rx.is_empty()) {
                    Either::Left(self.mailbox_rx.recv())
                } else {
                    Either::Right(future::pending())
                };
            },
            on_stopped => {
                return;
            },
            _ = &mut resolver_task => {
                return;
            },
            Some(message) = mailbox_message else continue => {
                match self.handle_mailbox_message(message) {
                    MailboxAction::None => {}
                    MailboxAction::Fetch(request) => {
                        resolver_mailbox.fetch(request).await;
                    }
                }
            },
            Some(message) = handler_rx.recv() else {
                return;
            } => {
                match message {
                    EngineMessage::Deliver { key, value, response } => {
                        self.handle_deliver(key, value, response).await;
                    }
                    EngineMessage::Produce { key, response } => {
                        self.handle_produce(key, response).await;
                    }
                }
            },
        }
    }

    fn handle_mailbox_message(
        &mut self,
        message: Message<DB, F, DbOp<DB>, H>,
    ) -> MailboxAction<F, H::Digest> {
        match message {
            Message::AttachDatabase(db) => {
                let replacing_existing = matches!(self.state, State::HasDb(_));
                info!(replacing_existing, "attached compact resolver database");
                self.state = State::HasDb(db);
                MailboxAction::None
            }
            Message::GetState { target, response } => {
                let request = Request::from_target(target);
                if let Some(subscribers) = self.pending.get_mut(&request) {
                    subscribers.retain(|subscriber| !subscriber.is_closed());
                    if !subscribers.is_empty() {
                        subscribers.push(response);
                        return MailboxAction::None;
                    }
                }
                self.pending.insert(request.clone(), vec![response]);
                MailboxAction::Fetch(request)
            }
        }
    }

    async fn handle_deliver(
        &mut self,
        key: Request<F, H::Digest>,
        value: bytes::Bytes,
        response: oneshot::Sender<bool>,
    ) {
        let Some(subscribers) = self.pending.remove(&key) else {
            response.send_lossy(true);
            return;
        };

        let decoded = match Response::<F, DbOp<DB>, H::Digest>::decode(value) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.pending.insert(key, subscribers);
                response.send_lossy(false);
                return;
            }
        };

        let state = compact::State {
            leaf_count: decoded.leaf_count,
            pinned_nodes: decoded.pinned_nodes,
            last_commit_op: decoded.last_commit_op,
            last_commit_proof: decoded.last_commit_proof,
        };

        if !Self::valid_state_response(&key, &state) {
            self.pending.insert(key, subscribers);
            response.send_lossy(false);
            return;
        }

        for subscriber in subscribers {
            let _ = subscriber.send(Ok(state.clone()));
        }
        response.send_lossy(true);
    }

    fn valid_state_response(
        key: &Request<F, H::Digest>,
        state: &compact::State<F, DbOp<DB>, H::Digest>,
    ) -> bool {
        if state.leaf_count != key.leaf_count || state.leaf_count == Location::new(0) {
            return false;
        }

        let hasher = StandardHasher::<H>::new();
        qmdb::verify_proof(
            &hasher,
            &state.last_commit_proof,
            Location::new(*state.leaf_count - 1),
            std::slice::from_ref(&state.last_commit_op),
            &key.root,
        )
    }

    async fn handle_produce(
        &mut self,
        key: Request<F, H::Digest>,
        response: oneshot::Sender<bytes::Bytes>,
    ) {
        let State::HasDb(database) = &self.state else {
            return;
        };
        let Ok(state) = database.get_compact_state(key.to_target()).await else {
            return;
        };
        response.send_lossy(
            Response {
                leaf_count: state.leaf_count,
                pinned_nodes: state.pinned_nodes,
                last_commit_op: state.last_commit_op,
                last_commit_proof: state.last_commit_proof,
            }
            .encode(),
        );
    }
}

#[derive(Clone, Debug)]
struct Request<F: Family, D: Digest> {
    root: D,
    leaf_count: Location<F>,
}

impl<F: Family, D: Digest> Request<F, D> {
    fn from_target(target: compact::Target<F, D>) -> Self {
        Self {
            root: target.root,
            leaf_count: target.leaf_count,
        }
    }

    fn to_target(&self) -> compact::Target<F, D> {
        compact::Target {
            root: self.root,
            leaf_count: self.leaf_count,
        }
    }
}

impl<F: Family, D: Digest> PartialEq for Request<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root && self.leaf_count == other.leaf_count
    }
}

impl<F: Family, D: Digest> Eq for Request<F, D> {}

impl<F: Family, D: Digest> PartialOrd for Request<F, D> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: Family, D: Digest> Ord for Request<F, D> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.root
            .cmp(&other.root)
            .then_with(|| self.leaf_count.cmp(&other.leaf_count))
    }
}

impl<F: Family, D: Digest> Hash for Request<F, D> {
    fn hash<S: StdHasher>(&self, state: &mut S) {
        self.root.hash(state);
        self.leaf_count.hash(state);
    }
}

impl<F: Family, D: Digest> fmt::Display for Request<F, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CompactRequest(root={}, leaf_count={})",
            self.root, self.leaf_count
        )
    }
}

impl<F: Family, D: Digest> Write for Request<F, D> {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.root.write(buf);
        self.leaf_count.write(buf);
    }
}

impl<F: Family, D: Digest> EncodeSize for Request<F, D> {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.leaf_count.encode_size()
    }
}

impl<F: Family, D: Digest> Read for Request<F, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, CodecError> {
        let root = D::read(buf)?;
        let leaf_count = Location::<F>::read(buf)?;
        if !leaf_count.is_valid() {
            return Err(CodecError::Invalid(
                "constantinople_engine::compact_resolver::Request",
                "leaf_count out of valid range",
            ));
        }
        Ok(Self { root, leaf_count })
    }
}

impl<F: Family, D: Digest> Span for Request<F, D> {}

struct Response<F: Family, Op, D: Digest> {
    leaf_count: Location<F>,
    pinned_nodes: Vec<D>,
    last_commit_op: Op,
    last_commit_proof: Proof<F, D>,
}

impl<F, Op, D> Write for Response<F, Op, D>
where
    F: Family,
    Op: Write,
    D: Digest,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.leaf_count.write(buf);
        self.pinned_nodes.write(buf);
        self.last_commit_op.write(buf);
        self.last_commit_proof.write(buf);
    }
}

impl<F, Op, D> EncodeSize for Response<F, Op, D>
where
    F: Family,
    Op: EncodeSize,
    D: Digest,
{
    fn encode_size(&self) -> usize {
        self.leaf_count.encode_size()
            + self.pinned_nodes.encode_size()
            + self.last_commit_op.encode_size()
            + self.last_commit_proof.encode_size()
    }
}

impl<F, Op, D> Read for Response<F, Op, D>
where
    F: Family,
    Op: Read<Cfg = ()>,
    D: Digest,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, CodecError> {
        let leaf_count = Location::<F>::read(buf)?;
        if !leaf_count.is_valid() {
            return Err(CodecError::Invalid(
                "constantinople_engine::compact_resolver::Response",
                "leaf_count out of valid range",
            ));
        }
        Ok(Self {
            leaf_count,
            pinned_nodes: Vec::<D>::read_range(buf, ..=MAX_PINNED_NODES)?,
            last_commit_op: Op::read(buf)?,
            last_commit_proof: Proof::<F, D>::read_cfg(buf, &MAX_PROOF_DIGESTS_PER_ELEMENT)?,
        })
    }
}

enum EngineMessage<F: Family, D: Digest> {
    Deliver {
        key: Request<F, D>,
        value: bytes::Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: Request<F, D>,
        response: oneshot::Sender<bytes::Bytes>,
    },
}

#[derive(Clone)]
struct Handler<F: Family, D: Digest> {
    sender: mpsc::Sender<EngineMessage<F, D>>,
}

impl<F: Family, D: Digest> Handler<F, D> {
    fn new(sender: mpsc::Sender<EngineMessage<F, D>>) -> Self {
        Self { sender }
    }
}

impl<F: Family, D: Digest> commonware_resolver::Consumer for Handler<F, D> {
    type Failure = ();
    type Key = Request<F, D>;
    type Value = bytes::Bytes;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        self.sender
            .request_or(
                |response| EngineMessage::Deliver {
                    key,
                    value,
                    response,
                },
                false,
            )
            .await
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {}
}

impl<F: Family, D: Digest> p2p::Producer for Handler<F, D> {
    type Key = Request<F, D>;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<bytes::Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(EngineMessage::Produce { key, response })
            .await;
        receiver
    }
}
