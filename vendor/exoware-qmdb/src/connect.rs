#![allow(refining_impl_trait)]

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::{
            ordered, unordered,
            value::{ValueEncoding, VariableEncoding},
        },
        immutable, keyless,
    },
};

use crate::proto::qmdb::v1::{
    CurrentOperationService, CurrentOperationServiceServer, GetCurrentOperationRangeRequest,
    GetCurrentOperationRangeResponse, GetManyRequest, GetManyResponse, GetOperationRangeRequest,
    GetOperationRangeResponse, GetRangeRequest, GetRangeResponse, GetRequest, GetResponse,
    KeyLookupService, KeyLookupServiceServer, OperationLogService, OperationLogServiceServer,
    OrderedKeyRangeService, OrderedKeyRangeServiceServer, SubscribeRequest, SubscribeResponse,
};
use connectrpc::{
    Chain, ConnectError, ConnectRpcService, ErrorCode, Limits, PreEncoded,
    RequestContext as Context, ServiceRequest,
};
use exoware_sdk::common::kv::v1::filter::KindView as ProtoFilterKindView;
use exoware_sdk::stream_filter::{CompiledFilters, Filter};
use futures::future::BoxFuture;
use futures::{FutureExt, Stream};

use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
};
use crate::subscription::{self as sub, RowClassifier};
use crate::{ImmutableClient, KeylessClient, OrderedClient, QmdbError, UnorderedClient};

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Decoded (key, value) payload for a QMDB operation. Either element is `None`
/// when the operation's logical key or value is absent (e.g. keyless ops).
pub struct OperationKv {
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
}

fn connect_limits() -> Limits {
    Limits::default()
        .with_max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
        .with_max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

fn qmdb_error_to_connect(err: QmdbError) -> ConnectError {
    match err {
        QmdbError::Client(client_err) => {
            if let Some(rpc) = client_err.rpc_error() {
                ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
            } else {
                ConnectError::internal(client_err.to_string())
            }
        }
        QmdbError::EmptyBatch
        | QmdbError::EmptyProofRequest
        | QmdbError::InvalidRangeLength
        | QmdbError::InvalidKeyRange { .. }
        | QmdbError::DuplicateRequestedKey { .. }
        | QmdbError::RangeStartOutOfBounds { .. }
        | QmdbError::EncodedValueTooLarge { .. }
        | QmdbError::SortableKeyTooLarge { .. } => ConnectError::invalid_argument(err.to_string()),
        QmdbError::WatermarkTooLow { .. } => ConnectError::out_of_range(err.to_string()),
        QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. } => {
            ConnectError::not_found(err.to_string())
        }
        QmdbError::CurrentProofRequiresBatchBoundary { .. }
        | QmdbError::CurrentBoundaryStateMissing { .. } => {
            ConnectError::failed_precondition(err.to_string())
        }
        QmdbError::Stream(_) => ConnectError::unavailable(err.to_string()),
        QmdbError::ProofVerification { .. }
        | QmdbError::RangeMismatch(_)
        | QmdbError::CorruptData(_)
        | QmdbError::CommonwareMerkle(_) => ConnectError::internal(err.to_string()),
    }
}

#[derive(Clone)]
pub struct OrderedConnect<
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    client: Arc<OrderedClient<F, H, K, V, N, E>>,
}

#[derive(Clone)]
pub struct UnorderedConnect<
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    client: Arc<UnorderedClient<F, H, K, V, E>>,
    key_cfg: Arc<K::Cfg>,
}

impl<F, H, K, V, const N: usize, E> UnorderedConnect<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    pub fn new(client: Arc<UnorderedClient<F, H, K, V, E>>, key_cfg: K::Cfg) -> Self {
        Self {
            client,
            key_cfg: Arc::new(key_cfg),
        }
    }
}

impl<F, H, K, V, const N: usize, E> OrderedConnect<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    pub fn new(client: Arc<OrderedClient<F, H, K, V, N, E>>) -> Self {
        Self { client }
    }
}

/// Implemented by each QMDB backend client (`Arc<OrderedClient<...>>`,
/// `Arc<UnorderedClient<...>>`, etc.) to expose just the surface the generic
/// `OperationLogService` path needs.
trait OperationLogBackend: Clone + Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    /// Reject `key_filters` at subscribe time (set true for keyless, whose
    /// ops have no logical key).
    const REJECTS_KEY_FILTERS: bool = false;

    fn store_client(&self) -> &exoware_sdk::PrefixedStoreClient;
    fn extract_operation_kv(
        &self,
        location: Location<Self::Family>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>;
    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<Self::Family>,
        operations: Vec<(Location<Self::Family>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, Self::Family>, QmdbError>> + Send;
    fn operation_range_checkpoint(
        &self,
        read_floor_sequence: u64,
        watermark: Location<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<(OperationRangeCheckpoint<Self::Digest, Self::Family>, u64), QmdbError>,
    > + Send;
}

/// Wrapper that bridges any `OperationLogBackend` into a concrete
/// `OperationLogService` implementation usable with `OperationLogServiceServer`.
#[derive(Clone)]
struct OperationLogConnect<B: OperationLogBackend> {
    backend: B,
}

impl<B: OperationLogBackend> OperationLogConnect<B> {
    fn new(backend: B) -> Self {
        Self { backend }
    }
}

trait CurrentOperationRangeBackend<const N: usize>: Clone + Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    type Operation: commonware_codec::Codec;

    fn current_operation_range_proof(
        &self,
        watermark: Location<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, Self::Family>,
            QmdbError,
        >,
    > + Send;
}

#[derive(Clone)]
struct CurrentOperationConnect<B, const N: usize>
where
    B: CurrentOperationRangeBackend<N>,
{
    backend: B,
}

impl<B, const N: usize> CurrentOperationConnect<B, N>
where
    B: CurrentOperationRangeBackend<N>,
{
    fn new(backend: B) -> Self {
        Self { backend }
    }
}

impl<F, H, K, V, const N: usize, E> OperationLogBackend for Arc<OrderedClient<F, H, K, V, N, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::PrefixedStoreClient {
        OrderedClient::store_client(self)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        OrderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        OrderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<(OperationRangeCheckpoint<Self::Digest, F>, u64), QmdbError>> + Send
    {
        OrderedClient::operation_range_checkpoint_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, K, V, E> OperationLogBackend for Arc<UnorderedClient<F, H, K, V, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::PrefixedStoreClient {
        UnorderedClient::store_client(self)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        UnorderedClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        UnorderedClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<(OperationRangeCheckpoint<Self::Digest, F>, u64), QmdbError>> + Send
    {
        UnorderedClient::operation_range_checkpoint_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, K, V, E> OperationLogBackend for Arc<ImmutableClient<F, H, K, V, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    immutable::Operation<F, K, E>: Encode + commonware_codec::Decode + Clone,
{
    type Family = F;
    type Digest = H::Digest;

    fn store_client(&self) -> &exoware_sdk::PrefixedStoreClient {
        ImmutableClient::store_client(self)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        ImmutableClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        ImmutableClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<(OperationRangeCheckpoint<Self::Digest, F>, u64), QmdbError>> + Send
    {
        ImmutableClient::operation_range_checkpoint_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, V, E> OperationLogBackend for Arc<KeylessClient<F, H, V, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    keyless::Operation<F, E>: Encode + commonware_codec::Decode + Clone,
{
    type Family = F;
    type Digest = H::Digest;
    const REJECTS_KEY_FILTERS: bool = true;

    fn store_client(&self) -> &exoware_sdk::PrefixedStoreClient {
        KeylessClient::store_client(self)
    }

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        KeylessClient::extract_operation_kv(self, location, bytes)
    }

    fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        KeylessClient::batch_multi_proof_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            operations,
        )
    }

    fn operation_range_checkpoint(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<(OperationRangeCheckpoint<Self::Digest, F>, u64), QmdbError>> + Send
    {
        KeylessClient::operation_range_checkpoint_with_read_floor(
            self,
            read_floor_sequence,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, K, V, const N: usize, E> CurrentOperationRangeBackend<N>
    for Arc<OrderedClient<F, H, K, V, N, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = ordered::Operation<F, K, E>;

    fn current_operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, F>,
            QmdbError,
        >,
    > + Send {
        OrderedClient::current_operation_range_proof_raw_at(
            self,
            watermark,
            start_location,
            max_locations,
        )
    }
}

impl<F, H, K, V, const N: usize, E> CurrentOperationRangeBackend<N>
    for Arc<UnorderedClient<F, H, K, V, E>>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = unordered::Operation<F, K, E>;

    fn current_operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, F>,
            QmdbError,
        >,
    > + Send {
        UnorderedClient::current_operation_range_proof_raw_at::<N>(
            self,
            watermark,
            start_location,
            max_locations,
        )
    }
}

#[derive(Clone, Debug)]
struct PendingBatch<F: Family> {
    latest: Location<F>,
    sequence_number: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

struct PendingBatches<F: Family> {
    batches: VecDeque<PendingBatch<F>>,

    // Tips can arrive out of order, but batches drain only from the front. Keep
    // each tip no greater than any later tip, including duplicates, so the next
    // minimum is available when the current one drains.
    minimums: VecDeque<Location<F>>,
}

impl<F: Family> PendingBatches<F> {
    fn new() -> Self {
        Self {
            batches: VecDeque::new(),
            minimums: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.batches.len()
    }

    fn push_back(&mut self, batch: PendingBatch<F>) {
        while self.minimums.back().is_some_and(|&tip| tip > batch.latest) {
            self.minimums.pop_back();
        }
        self.minimums.push_back(batch.latest);
        self.batches.push_back(batch);
    }

    fn drain_ready(
        &mut self,
        watermarks: &mut BTreeMap<Location<F>, u64>,
        ready: &mut VecDeque<ReadyBatch<F>>,
    ) {
        // Preserve Store order so a resume cursor cannot skip an unpublished frame.
        while let Some(batch) = self.batches.front() {
            let Some((&watermark, &watermark_sequence)) = watermarks.range(batch.latest..).next()
            else {
                break;
            };
            let batch = self.batches.pop_front().expect("pending is not empty");
            if self.minimums.front() == Some(&batch.latest) {
                self.minimums.pop_front();
            }
            ready.push_back(ReadyBatch {
                watermark,
                batch_sequence: batch.sequence_number,
                read_floor_sequence: batch.sequence_number.max(watermark_sequence),
                matched: batch.matched,
            });
        }

        if let Some(floor) = self
            .minimums
            .front()
            .copied()
            .or_else(|| watermarks.keys().next_back().copied())
        {
            *watermarks = watermarks.split_off(&floor);
        }
    }
}

#[derive(Clone, Debug)]
struct ReadyBatch<F: Family> {
    watermark: Location<F>,
    /// Store sequence of this batch's ops frame. Emitted as
    /// `resume_sequence_number`. It is unique per batch, so a client reconnecting
    /// at `resume + 1` skips only this batch. When multiple pending batches
    /// share a single authorizing watermark, each must carry its own
    /// per-batch sequence here or the reconnect cursor would jump past
    /// unread siblings.
    batch_sequence: u64,
    /// Minimum store sequence for the read session that builds the proof.
    /// Must be at least the watermark's publication sequence so the session
    /// observes the watermark row.
    read_floor_sequence: u64,
    matched: Vec<(Location<F>, Vec<u8>)>,
}

fn parse_filters<'a, 'b, I>(filters: I, label: &str) -> Result<Option<CompiledFilters>, String>
where
    I: IntoIterator<Item = &'b exoware_sdk::common::kv::v1::FilterView<'a>>,
    'a: 'b,
{
    let mut domain = Vec::new();
    for filter in filters {
        domain.push(match filter.kind {
            Some(ProtoFilterKindView::Exact(exact)) => Filter::Exact(Bytes::copy_from_slice(exact)),
            Some(ProtoFilterKindView::Prefix(prefix)) => {
                Filter::Prefix(Bytes::copy_from_slice(prefix))
            }
            Some(ProtoFilterKindView::Regex(pattern)) => Filter::Regex(pattern.to_string()),
            None => {
                return Err(format!(
                    "each {label} filter must set exactly one of exact, prefix, or regex"
                ));
            }
        });
    }
    CompiledFilters::compile(&domain).map_err(|e| format!("invalid {label} filter: {e}"))
}

fn matcher_passes(matcher: &Option<CompiledFilters>, bytes: Option<&[u8]>) -> bool {
    match matcher {
        None => true,
        Some(m) => bytes.map(|b| m.matches(b)).unwrap_or(false),
    }
}

struct BatchSubscribeStream<D: commonware_cryptography::Digest, F: Graftable> {
    key_matcher: Option<CompiledFilters>,
    value_matcher: Option<CompiledFilters>,
    classify: RowClassifier<F>,
    extract_kv: Arc<
        dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
            + Send
            + Sync
            + 'static,
    >,
    build_proof: Arc<
        dyn Fn(
                u64,
                Location<F>,
                Vec<(Location<F>, Vec<u8>)>,
            ) -> BoxFuture<'static, Result<RawBatchMultiProof<D, F>, QmdbError>>
            + Send
            + Sync
            + 'static,
    >,
    sub: exoware_sdk::StreamSubscription,
    pending: PendingBatches<F>,
    watermarks: BTreeMap<Location<F>, u64>,
    ready: VecDeque<ReadyBatch<F>>,
    building: Option<BoxFuture<'static, Result<PreEncoded<SubscribeResponse>, ConnectError>>>,
    // Terminal upstream event observed while a proof was still building. It is
    // delivered after the staged batches drain.
    staged_terminal: Option<StagedTerminal>,
}

// Bound on batches staged (pending plus ready) while a proof builds. Staging
// keeps demand flowing to the store subscription so the server-side lookahead
// stays occupied during proof construction, and the bound keeps the staged
// queues finite when the subscriber outruns proof throughput.
const SUBSCRIBE_STAGED_BATCHES: usize = 8;

enum StagedTerminal {
    End,
    Error(ConnectError),
}

impl<D: commonware_cryptography::Digest, F: Graftable> Unpin for BatchSubscribeStream<D, F> {}

impl<D: commonware_cryptography::Digest, F: Graftable> BatchSubscribeStream<D, F> {
    fn new(
        key_matcher: Option<CompiledFilters>,
        value_matcher: Option<CompiledFilters>,
        classify: RowClassifier<F>,
        extract_kv: Arc<
            dyn for<'a> Fn(Location<F>, &'a [u8]) -> Result<OperationKv, QmdbError>
                + Send
                + Sync
                + 'static,
        >,
        build_proof: Arc<
            dyn Fn(
                    u64,
                    Location<F>,
                    Vec<(Location<F>, Vec<u8>)>,
                )
                    -> BoxFuture<'static, Result<RawBatchMultiProof<D, F>, QmdbError>>
                + Send
                + Sync
                + 'static,
        >,
        sub: exoware_sdk::StreamSubscription,
    ) -> Self {
        Self {
            key_matcher,
            value_matcher,
            classify,
            extract_kv,
            build_proof,
            sub,
            pending: PendingBatches::new(),
            watermarks: BTreeMap::new(),
            ready: VecDeque::new(),
            building: None,
            staged_terminal: None,
        }
    }

    fn poll_frame(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<exoware_sdk::StreamSubscriptionFrame>, ConnectError>> {
        let next_fut = self.sub.next();
        tokio::pin!(next_fut);
        next_fut.as_mut().poll(cx).map_err(|err| {
            if let Some(rpc) = err.rpc_error() {
                ConnectError::new(rpc.code, rpc.message.clone().unwrap_or_default())
            } else {
                ConnectError::new(ErrorCode::Internal, err.to_string())
            }
        })
    }

    fn ingest_frame(
        &mut self,
        frame: &exoware_sdk::StreamSubscriptionFrame,
    ) -> Result<(), Box<ConnectError>> {
        let mut latest: Option<Location<F>> = None;
        let mut matched: Vec<(Location<F>, Vec<u8>)> = Vec::new();
        let needs_decode = self.key_matcher.is_some() || self.value_matcher.is_some();

        for entry in &frame.entries {
            let Some((family, location)) = self.classify.classify(&entry.key, entry.value.as_ref())
            else {
                continue;
            };
            match family {
                sub::RowFamily::Op => {
                    latest = latest.max(Some(location));
                    let include = if needs_decode {
                        let OperationKv { key, value } =
                            (self.extract_kv)(location, entry.value.as_ref())
                                .map_err(qmdb_error_to_connect)?;
                        matcher_passes(&self.key_matcher, key.as_deref())
                            && matcher_passes(&self.value_matcher, value.as_deref())
                    } else {
                        true
                    };
                    if include {
                        matched.push((location, entry.value.to_vec()));
                    }
                }
                sub::RowFamily::Watermark => {
                    self.watermarks
                        .entry(location)
                        .or_insert(frame.sequence_number);
                }
            }
        }

        if !matched.is_empty() {
            let latest = latest.expect("matched operations determine the frame tip");
            matched.sort_by_key(|(loc, _)| *loc);
            if matched
                .windows(2)
                .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
            {
                return Err(Box::new(ConnectError::internal(
                    "conflicting QMDB operations at one location",
                )));
            }
            matched.dedup();
            self.pending.push_back(PendingBatch {
                latest,
                sequence_number: frame.sequence_number,
                matched,
            });
        }

        self.pending
            .drain_ready(&mut self.watermarks, &mut self.ready);
        Ok(())
    }
}

impl<D: commonware_cryptography::Digest, F: Graftable> Stream for BatchSubscribeStream<D, F> {
    type Item = Result<PreEncoded<SubscribeResponse>, ConnectError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(fut) = this.building.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        this.building = None;
                        return Poll::Ready(Some(result));
                    }
                    Poll::Pending => {
                        // Keep pulling upstream frames while the proof builds
                        // so demand reaches the store subscription, up to the
                        // staged-batch bound.
                        while this.staged_terminal.is_none()
                            && this.pending.len() + this.ready.len() < SUBSCRIBE_STAGED_BATCHES
                        {
                            match this.poll_frame(cx) {
                                Poll::Ready(Ok(Some(frame))) => {
                                    if let Err(err) = this.ingest_frame(&frame) {
                                        this.staged_terminal = Some(StagedTerminal::Error(*err));
                                    }
                                }
                                Poll::Ready(Ok(None)) => {
                                    this.staged_terminal = Some(StagedTerminal::End);
                                }
                                Poll::Ready(Err(err)) => {
                                    this.staged_terminal = Some(StagedTerminal::Error(err));
                                }
                                Poll::Pending => break,
                            }
                        }
                        return Poll::Pending;
                    }
                }
            }

            if let Some(batch) = this.ready.pop_front() {
                let build = this.build_proof.clone();
                let fut = async move {
                    let proof = (build)(batch.read_floor_sequence, batch.watermark, batch.matched)
                        .await
                        .map_err(qmdb_error_to_connect)?;
                    Ok(crate::proto::subscribe_response(
                        batch.batch_sequence,
                        &proof,
                    ))
                }
                .boxed();
                this.building = Some(fut);
                continue;
            }

            if let Some(terminal) = this.staged_terminal.take() {
                return Poll::Ready(match terminal {
                    StagedTerminal::End => None,
                    StagedTerminal::Error(err) => Some(Err(err)),
                });
            }

            match this.poll_frame(cx) {
                Poll::Ready(Ok(Some(frame))) => {
                    if let Err(err) = this.ingest_frame(&frame) {
                        return Poll::Ready(Some(Err(*err)));
                    }
                }
                Poll::Ready(Ok(None)) => return Poll::Ready(None),
                Poll::Ready(Err(err)) => return Poll::Ready(Some(Err(err))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn decode_since(since: Option<u64>) -> Option<u64> {
    match since {
        Some(0) | None => None,
        Some(value) => Some(value),
    }
}

impl<F, H, K, V, const N: usize, E> KeyLookupService for OrderedConnect<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F,
        K,
        E,
        H::Digest,
        N,
    >: Encode,
{
    fn get(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetResponse>>> + Send {
        let client = self.client.clone();
        async move {
            let key = client.decode_key(request.key).map_err(|error| {
                ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
            })?;
            let tip = Location::new(request.tip);
            let proof = client
                .key_value_proof_raw_at(tip, key.as_ref())
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::get_response(&proof))
        }
    }

    fn get_many(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetManyRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetManyResponse>>> + Send {
        let client = self.client.clone();
        async move {
            let tip = Location::new(request.tip);
            let decoded_keys = request
                .keys
                .iter()
                .map(|key| client.decode_key(key))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
                })?;
            let proofs = client
                .key_lookup_proofs_raw_at(tip, &decoded_keys)
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::ordered_get_many_response(&proofs))
        }
    }
}

impl<F, H, K, V, const N: usize, E> KeyLookupService for UnorderedConnect<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    fn get(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetResponse>>> + Send {
        let client = self.client.clone();
        let key_cfg = self.key_cfg.clone();
        async move {
            let key = K::decode_cfg(commonware_codec::Copying(request.key), &key_cfg).map_err(|error| {
                ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
            })?;
            let tip = Location::new(request.tip);
            let proof = client
                .key_value_proof_raw_at::<N, _>(tip, key.as_ref())
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::get_response(&proof))
        }
    }

    fn get_many(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetManyRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetManyResponse>>> + Send {
        let client = self.client.clone();
        let key_cfg = self.key_cfg.clone();
        async move {
            let tip = Location::new(request.tip);
            let keys = request
                .keys
                .iter()
                .map(|key| K::decode_cfg(commonware_codec::Copying(*key), &key_cfg))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
                })?;
            let proofs = client
                .key_lookup_proofs_raw_at::<N, _>(tip, &keys)
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::unordered_get_many_response(&proofs))
        }
    }
}

impl<F, H, K, V, const N: usize, E> OrderedKeyRangeService for OrderedConnect<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F,
        K,
        E,
        H::Digest,
        N,
    >: Encode,
{
    fn get_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetRangeResponse>>> + Send {
        let client = self.client.clone();
        async move {
            let tip = Location::new(request.tip);
            let start_key = client.decode_key(request.start_key).map_err(|error| {
                ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
            })?;
            let end_key = request
                .end_key
                .map(|key| client.decode_key(key))
                .transpose()
                .map_err(|error| {
                    ConnectError::invalid_argument(format!("invalid QMDB key: {error}"))
                })?;
            let proof = client
                .key_range_proof_raw_at(tip, start_key, end_key, request.limit)
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::get_range_response(&proof))
        }
    }
}

impl<B: OperationLogBackend> OperationLogService for OperationLogConnect<B> {
    fn get_operation_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetOperationRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetOperationRangeResponse>>> + Send
    {
        let backend = self.backend.clone();
        async move {
            let (proof, sequence_number) = backend
                .operation_range_checkpoint(
                    request.min_sequence_number.unwrap_or_default(),
                    Location::new(request.tip),
                    Location::new(request.start_location),
                    request.max_locations,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::get_operation_range_response(
                &proof,
                sequence_number,
            ))
        }
    }

    fn subscribe(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, SubscribeRequest>,
    ) -> impl Future<
        Output = connectrpc::ServiceResult<
            connectrpc::ServiceStream<PreEncoded<SubscribeResponse>>,
        >,
    > + Send {
        let backend = self.backend.clone();
        async move {
            if B::REJECTS_KEY_FILTERS && !request.key_filters.is_empty() {
                return Err(ConnectError::invalid_argument(
                    "this OperationLogService endpoint does not accept key_filters",
                ));
            }
            let key_matcher = parse_filters(request.key_filters.iter(), "key")
                .map_err(ConnectError::invalid_argument)?;
            let value_matcher = parse_filters(request.value_filters.iter(), "value")
                .map_err(ConnectError::invalid_argument)?;
            let since = decode_since(request.since_sequence_number);
            let (classify, filter) = sub::classify_and_filter::<B::Family>();
            let sub = sub::open_store_subscription(backend.store_client(), filter, since)
                .await
                .map_err(qmdb_error_to_connect)?;
            let extract_kv: Arc<
                dyn for<'a> Fn(Location<B::Family>, &'a [u8]) -> Result<OperationKv, QmdbError>
                    + Send
                    + Sync
                    + 'static,
            > = {
                let backend = backend.clone();
                Arc::new(move |location, bytes| backend.extract_operation_kv(location, bytes))
            };
            let build_proof = {
                let backend = backend.clone();
                Arc::new(move |seq, watermark, matched| {
                    let backend = backend.clone();
                    async move {
                        backend
                            .batch_multi_proof_with_read_floor(seq, watermark, matched)
                            .await
                    }
                    .boxed()
                })
            };
            let stream: Pin<
                Box<dyn Stream<Item = Result<PreEncoded<SubscribeResponse>, ConnectError>> + Send>,
            > = Box::pin(BatchSubscribeStream::new(
                key_matcher,
                value_matcher,
                classify,
                extract_kv,
                build_proof,
                sub,
            ));
            Ok(connectrpc::Response::stream(stream))
        }
    }
}

impl<B, const N: usize> CurrentOperationService for CurrentOperationConnect<B, N>
where
    B: CurrentOperationRangeBackend<N>,
    B::Operation: Encode,
{
    fn get_current_operation_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetCurrentOperationRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetCurrentOperationRangeResponse>>>
           + Send {
        let backend = self.backend.clone();
        async move {
            let proof = backend
                .current_operation_range_proof(
                    Location::new(request.tip),
                    Location::new(request.start_location),
                    request.max_locations,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(crate::proto::get_current_operation_range_response(&proof))
        }
    }
}

fn wrap_stack<D: ::connectrpc::Dispatcher>(dispatcher: D) -> ConnectRpcService<D> {
    ConnectRpcService::new(dispatcher)
        .with_limits(connect_limits())
        .with_compression(exoware_sdk::connect_compression_registry())
}

/// Mount key lookup, ordered key range, and operation subscription services on
/// one endpoint, so a single HTTP URL serves the full ordered-QMDB surface.
pub fn ordered_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<OrderedClient<F, H, K, V, N, E>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
    commonware_storage::qmdb::current::ordered::proof::constant::ExclusionProof<
        F,
        K,
        E,
        H::Digest,
        N,
    >: Encode,
{
    wrap_stack(Chain(
        KeyLookupServiceServer::new(OrderedConnect::new(client.clone())),
        Chain(
            OrderedKeyRangeServiceServer::new(OrderedConnect::new(client.clone())),
            Chain(
                CurrentOperationServiceServer::new(CurrentOperationConnect::<_, N>::new(
                    client.clone(),
                )),
                OperationLogServiceServer::new(OperationLogConnect::new(client)),
            ),
        ),
    ))
}

/// Mount current key lookup and operation subscription services on one
/// unordered-QMDB endpoint. Unordered supports hit proofs for explicit keys
/// but does not expose key-space range or missing-key exclusion proofs.
pub fn unordered_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<UnorderedClient<F, H, K, V, E>>,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    unordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    wrap_stack(Chain(
        KeyLookupServiceServer::new(UnorderedConnect::<F, H, K, V, N, E>::new(
            client.clone(),
            key_cfg,
        )),
        Chain(
            CurrentOperationServiceServer::new(CurrentOperationConnect::<_, N>::new(
                client.clone(),
            )),
            OperationLogServiceServer::new(OperationLogConnect::new(client)),
        ),
    ))
}

pub fn ordered_operation_log_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<OrderedClient<F, H, K, V, N, E>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

pub fn unordered_operation_log_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<UnorderedClient<F, H, K, V, E>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    unordered::Operation<F, K, E>: Encode + commonware_codec::Decode,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

pub fn immutable_operation_log_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: commonware_storage::qmdb::operation::Key + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<ImmutableClient<F, H, K, V, E>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    immutable::Operation<F, K, E>: Encode + commonware_codec::Decode + Clone,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

pub fn keyless_operation_log_connect_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    client: Arc<KeylessClient<F, H, V, E>>,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    keyless::Operation<F, E>: Encode + commonware_codec::Decode + Clone,
{
    wrap_stack(OperationLogServiceServer::new(OperationLogConnect::new(
        client,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(
        latest: u64,
        sequence_number: u64,
    ) -> PendingBatch<commonware_storage::merkle::mmr::Family> {
        PendingBatch {
            latest: Location::new(latest),
            sequence_number,
            matched: vec![(
                Location::<commonware_storage::merkle::mmr::Family>::new(sequence_number),
                vec![sequence_number as u8],
            )],
        }
    }

    #[test]
    fn test_subscribe_multi_proof_proto_includes_ops_root_without_witness() {
        use buffa::Message as _;
        use commonware_cryptography::{sha256::Digest as Sha256Digest, Sha256};
        use commonware_storage::merkle::{mmr, Proof};
        use connectrpc::Encodable as _;

        let root = Sha256::fill(0x42);
        let raw = RawBatchMultiProof::<Sha256Digest, mmr::Family> {
            watermark: Location::new(0),
            root,
            ops_root_witness: None,
            proof: Proof {
                leaves: Location::new(1),
                inactive_peaks: 0,
                digests: Vec::new(),
            },
            operations: vec![(Location::new(0), vec![0xAA])],
        };

        let encoded = crate::proto::subscribe_response(0, &raw)
            .encode(connectrpc::CodecFormat::Proto)
            .expect("encode response");
        let proto = SubscribeResponse::decode_from_slice(&encoded).expect("decode response");
        let proof = proto.proof.as_option().expect("proof");

        assert_eq!(proof.ops_root, root.encode());
        assert!(proof.ops_root_witness.is_empty());
    }

    #[test]
    fn test_shared_watermark_preserves_per_batch_resume_cursor() {
        // Three batches (ops at locations 10, 11, 12) authorized by a single
        // watermark at location 12 (published at store seq 15). If they all
        // emitted the same resume cursor, a client that received only the
        // first batch and reconnected at resume+1 would skip the other two.
        let mut batches = PendingBatches::new();
        for sequence in 10..=12 {
            batches.push_back(pending(sequence, sequence));
        }
        let mut watermarks = BTreeMap::from([(
            Location::<commonware_storage::merkle::mmr::Family>::new(12),
            15u64,
        )]);
        let mut ready = VecDeque::new();

        batches.drain_ready(&mut watermarks, &mut ready);

        assert_eq!(ready.len(), 3);
        let cursors: Vec<u64> = ready.iter().map(|b| b.batch_sequence).collect();
        assert_eq!(cursors, vec![10, 11, 12]);
        for b in &ready {
            assert_eq!(b.read_floor_sequence, 15);
            assert_eq!(
                b.watermark,
                Location::<commonware_storage::merkle::mmr::Family>::new(12)
            );
        }

        // Simulate a reconnect after only the first batch was delivered:
        // the client would request since = cursors[0] + 1 = 11. After that
        // replay the server must still be able to hand the client batches 2
        // and 3 (their batch_sequence values 11 and 12 are both >= 11).
        let next_since = cursors[0] + 1;
        let not_yet_delivered: Vec<u64> = cursors
            .iter()
            .copied()
            .filter(|&seq| seq >= next_since)
            .collect();
        assert_eq!(not_yet_delivered, vec![11, 12]);
    }

    #[test]
    fn test_out_of_order_uploads_preserve_subscription_replay_order() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        batches.push_back(pending(20, 10));
        batches.push_back(pending(10, 11));
        let mut watermarks = BTreeMap::from([(Location::<F>::new(20), 12)]);
        let mut ready = VecDeque::new();
        batches.drain_ready(&mut watermarks, &mut ready);
        let cursors = ready
            .iter()
            .map(|batch| batch.batch_sequence)
            .collect::<Vec<_>>();
        assert_eq!(cursors, [10, 11]);
        let resume = cursors[0] + 1;
        assert!(cursors[1..].iter().all(|cursor| *cursor >= resume));
        assert!(ready.iter().all(|batch| batch.read_floor_sequence == 12));
    }

    #[test]
    fn test_subscription_waits_for_earlier_store_sequence_to_be_published() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        batches.push_back(pending(20, 10));
        batches.push_back(pending(10, 11));
        let mut watermarks = BTreeMap::from([(Location::<F>::new(10), 11)]);
        let mut ready = VecDeque::new();
        batches.drain_ready(&mut watermarks, &mut ready);
        assert!(
            ready.is_empty(),
            "a cursor must not skip an unpublished earlier Store frame"
        );
        watermarks.insert(Location::new(20), 12);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(
            ready
                .iter()
                .map(|batch| batch.batch_sequence)
                .collect::<Vec<_>>(),
            [10, 11]
        );
    }

    #[test]
    fn test_subscription_prunes_watermarks_after_partial_drains() {
        type F = commonware_storage::merkle::mmr::Family;
        let mut batches = PendingBatches::new();
        for (sequence, latest) in [5, 20, 5, 30, 10, 10, 40].into_iter().enumerate() {
            batches.push_back(pending(latest, sequence as u64));
        }
        let mut watermarks = BTreeMap::from([
            (Location::<F>::new(4), 7),
            (Location::new(5), 8),
            (Location::new(10), 9),
        ]);
        let mut ready = VecDeque::new();

        // The later batch at tip 5 still needs its watermark after the first drains.
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 6);
        assert_eq!(
            watermarks.keys().copied().collect::<Vec<_>>(),
            [Location::new(5), Location::new(10)]
        );

        watermarks.insert(Location::new(20), 10);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 4);
        assert_eq!(
            watermarks.keys().copied().collect::<Vec<_>>(),
            [Location::new(10), Location::new(20)]
        );

        watermarks.insert(Location::new(30), 11);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 1);
        assert!(watermarks.is_empty());

        watermarks.insert(Location::new(40), 12);
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 0);
        assert_eq!(watermarks, BTreeMap::from([(Location::new(40), 12)]));
        assert_eq!(
            ready
                .iter()
                .map(|batch| (
                    batch.batch_sequence,
                    *batch.watermark,
                    batch.read_floor_sequence
                ))
                .collect::<Vec<_>>(),
            [
                (0, 5, 8),
                (1, 20, 10),
                (2, 5, 8),
                (3, 30, 11),
                (4, 10, 9),
                (5, 10, 9),
                (6, 40, 12)
            ]
        );

        batches.push_back(pending(50, 13));
        batches.drain_ready(&mut watermarks, &mut ready);
        assert_eq!(batches.len(), 1);
        assert!(watermarks.is_empty());
    }
}

#[cfg(test)]
mod authenticated_upload_subscription_tests {
    use super::*;
    use commonware_cryptography::sha256::Digest;
    use commonware_storage::merkle::mmr;
    use exoware_sdk::{StreamSubscriptionEntry, StreamSubscriptionFrame};

    type F = mmr::Family;

    async fn stream() -> BatchSubscribeStream<Digest, F> {
        let (_task, url) = exoware_simulator::open_temp().await.expect("simulator");
        let client = exoware_sdk::PrefixedStoreClient::empty(exoware_sdk::StoreClient::new(&url));
        let (classifier, filter) = sub::classify_and_filter::<F>();
        let subscription = client.stream().subscribe(filter, None).await.unwrap();
        BatchSubscribeStream::new(
            None,
            None,
            classifier,
            Arc::new(|_, bytes| {
                Ok(OperationKv {
                    key: None,
                    value: Some(bytes.to_vec()),
                })
            }),
            Arc::new(|_, _, _| async { unreachable!("ingestion does not build proofs") }.boxed()),
            subscription,
        )
    }

    fn operation(location: u64, value: &'static [u8]) -> StreamSubscriptionEntry {
        StreamSubscriptionEntry {
            key: crate::codec::encode_operation_key(Location::<F>::new(location)),
            value: Bytes::from_static(value),
        }
    }

    fn watermark(location: u64) -> StreamSubscriptionEntry {
        StreamSubscriptionEntry {
            key: crate::codec::encode_watermark_key(Location::<F>::new(location)),
            value: Bytes::new(),
        }
    }

    #[tokio::test]
    async fn test_data_only_frames_wait_for_publication_and_keep_store_order() {
        let mut stream = stream().await;
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 10,
                entries: vec![operation(4, b"four"), operation(5, b"five")],
            })
            .expect("authenticated data frames must not require a presence row");
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 11,
                entries: vec![operation(0, b"zero"), operation(1, b"one")],
            })
            .unwrap();
        assert_eq!(stream.pending.len(), 2);
        assert!(stream.ready.is_empty());

        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 12,
                entries: vec![watermark(1)],
            })
            .unwrap();
        assert!(
            stream.ready.is_empty(),
            "an earlier Store frame must not be skipped"
        );
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 13,
                entries: vec![watermark(5)],
            })
            .unwrap();
        assert_eq!(stream.pending.len(), 0);
        assert_eq!(stream.ready.len(), 2);
        assert_eq!(
            stream
                .ready
                .iter()
                .map(|batch| (
                    batch.batch_sequence,
                    *batch.watermark,
                    batch.read_floor_sequence
                ))
                .collect::<Vec<_>>(),
            [(10, 5, 13), (11, 1, 12)]
        );
        assert_eq!(
            stream.ready[0].matched,
            [
                (Location::new(4), b"four".to_vec()),
                (Location::new(5), b"five".to_vec())
            ]
        );
        assert_eq!(
            stream.ready[1].matched,
            [
                (Location::new(0), b"zero".to_vec()),
                (Location::new(1), b"one".to_vec())
            ]
        );
    }

    #[tokio::test]
    async fn test_filtered_out_operations_still_determine_the_data_frame_tip() {
        let mut stream = stream().await;
        stream.value_matcher =
            CompiledFilters::compile(&[Filter::Exact(Bytes::from_static(b"keep"))]).unwrap();
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 10,
                entries: vec![operation(4, b"keep"), operation(5, b"skip")],
            })
            .unwrap();
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 11,
                entries: vec![watermark(4)],
            })
            .unwrap();
        assert!(
            stream.ready.is_empty(),
            "filtering must not lower the required publication tip"
        );
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 12,
                entries: vec![watermark(5)],
            })
            .unwrap();
        assert_eq!(stream.ready.len(), 1);
        assert_eq!(
            stream.ready[0].matched,
            [(Location::new(4), b"keep".to_vec())]
        );
        assert_eq!(stream.ready[0].read_floor_sequence, 12);
    }

    #[tokio::test]
    async fn test_overlapping_atomic_ranges_emit_each_operation_once() {
        let mut stream = stream().await;
        stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 10,
                entries: vec![
                    operation(0, b"zero"),
                    operation(1, b"one"),
                    operation(0, b"zero"),
                    watermark(1),
                ],
            })
            .unwrap();
        assert_eq!(stream.ready.len(), 1);
        assert_eq!(
            stream.ready[0].matched,
            [
                (Location::new(0), b"zero".to_vec()),
                (Location::new(1), b"one".to_vec())
            ]
        );
    }

    #[tokio::test]
    async fn test_conflicting_operation_rows_in_one_frame_are_rejected() {
        let mut stream = stream().await;
        assert!(stream
            .ingest_frame(&StreamSubscriptionFrame {
                sequence_number: 10,
                entries: vec![
                    operation(0, b"zero"),
                    operation(0, b"different"),
                    watermark(0)
                ],
            })
            .is_err());
    }
}
