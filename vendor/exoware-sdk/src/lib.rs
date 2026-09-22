//! Store Rust SDK Client.
//!
//! Provides typed access to the store put/get/query APIs plus
//! HTTP health/readiness probes.
//!
//! ## Errors
//!
//! RPC failures surface as [`ClientError::Rpc`] carrying a native [`ConnectError`]. Use
//! [`ClientError::decoded_rpc_error`] or [`StoreClient::decode_error_details`] to unpack
//! protobuf `google.rpc` details (and `store.query.v1.Detail` on query RPC errors), not string parsing.
//! Idempotent reads honor `google.rpc.RetryInfo` when deciding backoff (see `retry_delay_for_error`).

mod credential;
pub mod keys;
pub mod kv_codec;
pub mod proto;
pub mod prune_policy;
pub mod retention;
pub mod selector;
pub mod stream_filter;
pub use credential::API_KEY_ENV;
pub use keys::{Key, KeyMut, KeyValidationError, Prefix, PrefixError, Value, MAX_KEY_LEN};
pub use proto::*;
extern crate self as exoware_proto;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ServerStream as ConnectServerStream};
pub use connectrpc::{ConnectError, ErrorCode};
use credential::{client_error_from_connect, ApiKey, Credential, UnusableEnvKey};
use exoware_proto::ingest::ServiceClient as IngestServiceClient;
use exoware_proto::log::ingest::v1::PutRequest as ProtoPutRequest;
use exoware_proto::prune::ServiceClient as PruneServiceClient;
use exoware_proto::query as proto_query;
use exoware_proto::query::ServiceClient as QueryServiceClient;
use exoware_proto::store::prune::v1::PruneRequest as ProtoPruneRequest;
use exoware_proto::store::query::v1::{
    GetManyRequest as ProtoGetManyRequest, GetRequest as ProtoGetRequest,
    RangeRequest as ProtoRangeRequest, ReduceRequest as ProtoWireReduceRequest,
};
use exoware_proto::RangeReduceRequest as DomainRangeReduceRequest;
use exoware_proto::{
    connect_compression_registry as proto_connect_compression_registry,
    decode_connect_error as proto_decode_connect_error,
    to_domain_reduce_response as proto_to_domain_reduce_response,
    to_proto_reduce_params as proto_to_proto_reduce_params,
    PreferZstdHttpClient as ProtoPreferZstdHttpClient,
};
use futures::future::BoxFuture;
use futures::{stream::BoxStream, StreamExt};
use keys::is_valid_key_size;
use kv_codec::{KvExpr, KvFieldRef, KvReducedValue};
use rustls_platform_verifier::ConfigVerifierExt;
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use crate::proto::transport::{
    BalancedHttp2Config as ProtoBalancedHttp2Config,
    BalancedHttp2Transport as ProtoBalancedHttp2Transport,
    ErasedClientTransport as ProtoErasedClientTransport,
    ErasedResponseBody as ProtoErasedResponseBody,
};

const DEFAULT_RETRY_MAX_ATTEMPTS: usize = 3;
const DEFAULT_RETRY_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_RETRY_MAX_BACKOFF_MS: u64 = 2_000;

/// Converts caller-provided write values into the byte owner stored by
/// [`StoreWriteBatch`].
pub trait IntoStoreWriteValue {
    fn into_store_write_value(self) -> Bytes;
}

impl IntoStoreWriteValue for Bytes {
    fn into_store_write_value(self) -> Bytes {
        self
    }
}

impl IntoStoreWriteValue for &Bytes {
    fn into_store_write_value(self) -> Bytes {
        self.clone()
    }
}

impl IntoStoreWriteValue for Vec<u8> {
    fn into_store_write_value(self) -> Bytes {
        self.into()
    }
}

impl IntoStoreWriteValue for &Vec<u8> {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl IntoStoreWriteValue for &[u8] {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl<const N: usize> IntoStoreWriteValue for &[u8; N] {
    fn into_store_write_value(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

/// Codec used to compress **outgoing** RPC request bodies when compression applies.
///
/// Request compression is disabled by default because large ingest batches are
/// often CPU-bound before they are network-bound. Use [`Zstd`](Self::Zstd) when
/// upload bandwidth matters more than client CPU, or [`Gzip`](Self::Gzip) when
/// talking to a peer that only accepts gzip-compressed requests. Response
/// decompression still follows [`PreferZstdHttpClient`] and the shared
/// [`connect_compression_registry`].
///
/// To drive this from configuration or environment variables, map your setting to this enum and
/// pass it to [`StoreClientBuilder::connect_request_compression`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectRequestCompression {
    /// Do not compress outgoing request bodies.
    #[default]
    None,
    /// `compress_requests("zstd")`.
    Zstd,
    /// `compress_requests("gzip")`.
    Gzip,
}

impl ConnectRequestCompression {
    fn wire_name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Zstd => Some("zstd"),
            Self::Gzip => Some("gzip"),
        }
    }
}

/// Default max decompressed RPC message size for client decode (matches the query worker).
///
/// The underlying client uses 4 MiB unless configured; large `Range` frames need headroom.
/// The store simulator uses the same 256 MiB cap for large `Range` frames.
const STORE_CLIENT_MAX_MESSAGE_BYTES: usize = 256 * 1024 * 1024;

/// Store client defaults: [`connect_compression_registry`] for codecs;
/// [`PreferZstdHttpClient`] sets `Accept-Encoding: zstd, gzip` on responses.
///
/// Request body compression uses [`ConnectRequestCompression`] (default none);
/// connectrpc only supports one request encoding per config (see
/// [`ConnectRequestCompression`]).
fn store_connect_client_config(
    base_uri: http::Uri,
    request_compression: ConnectRequestCompression,
    timeout: Option<Duration>,
) -> ClientConfig {
    let config = ClientConfig::new(base_uri)
        .with_compression(proto_connect_compression_registry())
        .with_default_max_message_size(STORE_CLIENT_MAX_MESSAGE_BYTES);
    let config = match timeout {
        Some(timeout) => config.with_default_timeout(timeout),
        None => config,
    };
    match request_compression.wire_name() {
        Some(name) => config.compress_requests(name),
        None => config,
    }
}

/// Store client error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("RPC error ({0})")]
    Rpc(Box<ConnectError>),
    #[error("store key prefix error: {0}")]
    Prefix(#[from] StoreKeyPrefixError),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("wire format error: {0}")]
    WireFormat(String),
}

impl ClientError {
    pub fn rpc_error(&self) -> Option<&ConnectError> {
        match self {
            Self::Rpc(err) => Some(err.as_ref()),
            _ => None,
        }
    }

    pub fn rpc_code(&self) -> Option<ErrorCode> {
        self.rpc_error().map(|err| err.code)
    }

    pub fn decoded_rpc_error(
        &self,
    ) -> Result<Option<exoware_proto::DecodedConnectError>, buffa::DecodeError> {
        self.rpc_error().map(proto_decode_connect_error).transpose()
    }
}

/// Errors returned by [`StoreKeyPrefix`] when a logical key cannot be mapped
/// into the prefixed physical keyspace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreKeyPrefixError {
    #[error("key does not belong to this store prefix")]
    PrefixMismatch,
    #[error("key offset {offset} plus store prefix shift {shift} exceeds u16")]
    KeyOffsetOverflow { offset: u16, shift: u16 },
    #[error("key prefix error: {0}")]
    Prefix(#[from] PrefixError),
}

/// A client-side namespace layered over raw Store keys.
///
/// The prefix prepends a fixed byte string to each physical Store key and
/// stores the caller's logical key in the remaining bytes. QMDB, SQL, and
/// other higher-level instances continue to build their own logical keys as
/// before; a prefixed [`StoreClient`] maps those keys on the wire and maps
/// returned keys back before callers see them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct StoreKeyPrefix {
    inner: Prefix,
}

impl StoreKeyPrefix {
    pub fn new(prefix: impl Into<Bytes>) -> Result<Self, StoreKeyPrefixError> {
        Ok(Self {
            inner: Prefix::new(prefix)?,
        })
    }

    /// The zero-width identity prefix: maps every logical key to itself, so
    /// encode/decode/range/match are all no-ops and keys pass through
    /// un-namespaced.
    pub const fn identity() -> Self {
        Self {
            inner: Prefix::empty(),
        }
    }

    /// The raw prefix bytes.
    #[inline]
    pub fn prefix(&self) -> &Bytes {
        self.inner.as_bytes()
    }

    /// True when `key` starts with this prefix. The identity prefix matches
    /// every key.
    #[inline]
    pub fn matches(&self, key: &[u8]) -> bool {
        self.inner.matches(key)
    }

    /// Maximum logical key bytes available under this prefix.
    #[inline]
    pub fn max_logical_key_len(&self) -> usize {
        self.inner.max_payload_len()
    }

    /// Encode a logical key into the physical Store keyspace. The identity
    /// prefix returns a refcount-only clone of `key`.
    pub fn encode_key(&self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        Ok(self.inner.encode_key(key)?)
    }

    /// Decode a physical Store key back into the logical keyspace as a
    /// zero-copy slice of `key`'s backing storage.
    pub fn decode_key(&self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        self.inner
            .strip(key)
            .map_err(|_| StoreKeyPrefixError::PrefixMismatch)
    }

    /// Return the smallest valid logical key strictly greater than `key`, or
    /// `None` when no later key remains under this prefix.
    pub fn next_key(&self, key: &Key) -> Result<Option<Key>, StoreKeyPrefixError> {
        let physical = self.encode_key(key)?;
        Ok(crate::keys::next_key(&physical).and_then(|next| self.decode_key(&next).ok()))
    }

    /// Encode an inclusive logical range into the physical Store keyspace.
    ///
    /// Empty `end` means unbounded in the logical keyspace and is narrowed to
    /// this prefix's physical upper bound. Long logical upper bounds are
    /// clamped to the maximum logical key length representable under this
    /// prefix; this keeps scans over full-width prefix bounds (whose upper
    /// bound is intentionally `MAX_KEY_LEN` bytes) working.
    pub fn encode_range(&self, start: &Key, end: &Key) -> Result<(Key, Key), StoreKeyPrefixError> {
        let start = self.encode_key(start)?;
        let end = if end.is_empty() {
            self.inner.bounds().1
        } else {
            let max_len = self.max_logical_key_len();
            if end.len() > max_len {
                self.encode_key(&end.slice(..max_len))?
            } else {
                self.encode_key(end)?
            }
        };
        Ok((start, end))
    }

    fn prefix_selector(
        &self,
        selector: &crate::selector::Selector,
    ) -> Result<crate::selector::Selector, StoreKeyPrefixError> {
        let prefix = self.inner.join(&Prefix::new(selector.prefix.clone())?)?;
        Ok(crate::selector::Selector {
            prefix: prefix.as_bytes().clone(),
            payload_regex: selector.payload_regex.clone(),
        })
    }
}

/// A physical [`StoreClient`] paired with a [`StoreKeyPrefix`] that namespaces
/// every key on the wire. The prefix can be the zero-width
/// [`StoreKeyPrefix::identity`], representing the un-namespaced case.
#[derive(Clone, Debug)]
pub struct PrefixedStoreClient {
    client: StoreClient,
    prefix: StoreKeyPrefix,
}

impl PrefixedStoreClient {
    /// Pair a physical client with an explicit namespace prefix.
    pub fn new(client: StoreClient, prefix: StoreKeyPrefix) -> Self {
        Self { client, prefix }
    }

    /// Pair a physical client with the zero-width [`StoreKeyPrefix::identity`],
    /// so keys pass through untranslated.
    pub fn empty(client: StoreClient) -> Self {
        Self::new(client, StoreKeyPrefix::identity())
    }

    /// The configured key prefix.
    pub fn key_prefix(&self) -> &StoreKeyPrefix {
        &self.prefix
    }

    /// Borrow the underlying physical transport. Operations performed directly
    /// on it are *not* namespaced; prefer the methods on this type.
    pub fn client(&self) -> &StoreClient {
        &self.client
    }

    // --- key translation -----------------------------------------------------

    /// Encode a logical key as it will appear in the physical Store.
    pub fn encode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        Ok(self.prefix.encode_key(key)?)
    }

    /// Decode a physical Store key into this client's logical keyspace.
    pub fn decode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        Ok(self.prefix.decode_key(key)?)
    }

    fn encode_store_range(&self, start: &Key, end: &Key) -> Result<(Key, Key), ClientError> {
        Ok(self.prefix.encode_range(start, end)?)
    }

    fn prefix_prune_policies(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<Vec<crate::prune_policy::PrunePolicy>, ClientError> {
        policies
            .iter()
            .map(|policy| {
                use crate::prune_policy::PrunePolicy;
                let mut scope = policy.scope.clone();
                scope.selector = self.prefix.prefix_selector(&scope.selector)?;
                Ok(PrunePolicy {
                    scope,
                    retain: policy.retain.clone(),
                })
            })
            .collect::<Result<Vec<_>, StoreKeyPrefixError>>()
            .map_err(ClientError::from)
    }

    fn prefix_stream_filter(
        &self,
        filter: crate::stream_filter::StreamFilter,
    ) -> Result<crate::stream_filter::StreamFilter, ClientError> {
        let selectors = filter
            .selectors
            .iter()
            .map(|mk| self.prefix.prefix_selector(mk))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::stream_filter::StreamFilter {
            selectors,
            value_filters: filter.value_filters,
        })
    }

    fn prefix_reduce_request(
        &self,
        request: &DomainRangeReduceRequest,
    ) -> Result<DomainRangeReduceRequest, ClientError> {
        let mut request = request.clone();
        shift_reduce_request_key_offsets(self.prefix.prefix().len(), &mut request)?;
        Ok(request)
    }

    // --- service-grouped accessors -------------------------------------------

    /// Typed access to the `log.ingest.v1` service.
    pub fn ingest(&self) -> Ingest<'_> {
        Ingest { c: self }
    }

    /// Typed access to the `store.query.v1` service.
    pub fn query(&self) -> Query<'_> {
        Query { c: self }
    }

    /// Typed access to the `store.prune.v1` service.
    pub fn prune(&self) -> Prune<'_> {
        Prune { c: self }
    }

    /// Typed access to the `log.retention.v1` service.
    pub fn retention(&self) -> Retention<'_> {
        Retention { c: self }
    }

    /// Typed access to the `log.stream.v1` service.
    pub fn stream(&self) -> Stream<'_> {
        Stream { c: self }
    }

    /// Create a serializable read session with no initial floor over this namespace.
    pub fn create_session(&self) -> SerializableReadSession {
        self.create_session_with_sequence(0)
    }

    /// Create a serializable read session whose read floor starts at `sequence`.
    pub fn create_session_with_sequence(&self, sequence: u64) -> SerializableReadSession {
        SerializableReadSession {
            client: self.clone(),
            state: Arc::new(SessionState {
                minimum_sequence: sequence,
                sequence: Arc::new(AtomicU64::new(0)),
                init_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    // --- writes --------------------------------------------------------------

    pub(crate) async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        let keys = kvs
            .iter()
            .map(|(key, _)| self.encode_store_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        let prefixed: Vec<(&Key, &[u8])> = keys
            .iter()
            .zip(kvs.iter())
            .map(|(key, (_, value))| (key, *value))
            .collect();
        self.client.put_physical(&prefixed).await
    }

    // --- reads ---------------------------------------------------------------

    pub(crate) async fn send_get(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::GetResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        self.client
            .send_get(&self.encode_store_key(key)?, min_sequence_number)
            .await
    }

    pub(crate) async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.client.get(&self.encode_store_key(key)?).await
    }

    pub(crate) async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.client
            .get_with_min_sequence_number(&self.encode_store_key(key)?, min_sequence_number)
            .await
    }

    pub(crate) async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, None, None).await
    }

    pub(crate) async fn get_many_with_min_sequence_number(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: u64,
    ) -> Result<GetManyStream, ClientError> {
        self.get_many_internal(keys, batch_size, Some(min_sequence_number), None)
            .await
    }

    pub(crate) async fn get_many_internal(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        let mut proto_keys: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        for key in keys {
            let encoded = self.encode_store_key(key)?;
            if !is_valid_key_size(encoded.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    encoded.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
            proto_keys.push(encoded.to_vec());
        }
        let mut stream = self
            .client
            .get_many_internal(
                proto_keys,
                batch_size,
                min_sequence_number,
                observed_sequence,
            )
            .await?;
        stream.key_prefix = Some(self.prefix.clone());
        Ok(stream)
    }

    pub(crate) async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, RangeMode::Forward, None)
            .await
    }

    pub(crate) async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, mode, None).await
    }

    pub(crate) async fn range_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(
            start,
            end,
            limit,
            RangeMode::Forward,
            Some(min_sequence_number),
        )
        .await
    }

    pub(crate) async fn range_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, mode, Some(min_sequence_number))
            .await
    }

    async fn range_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            limit.max(1),
            mode,
            QueryStreamReadOptions {
                min_sequence_number,
                observed_sequence: None,
            },
        )
        .await?
        .collect()
        .await
    }

    pub(crate) async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            RangeMode::Forward,
            QueryStreamReadOptions::default(),
        )
        .await
    }

    pub(crate) async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(start, end, limit, batch_size, mode, Default::default())
            .await
    }

    pub(crate) async fn range_stream_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            RangeMode::Forward,
            QueryStreamReadOptions {
                min_sequence_number: Some(min_sequence_number),
                observed_sequence: None,
            },
        )
        .await
    }

    pub(crate) async fn range_stream_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_internal(
            start,
            end,
            limit,
            batch_size,
            mode,
            QueryStreamReadOptions {
                min_sequence_number: Some(min_sequence_number),
                observed_sequence: None,
            },
        )
        .await
    }

    pub(crate) async fn range_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        options: QueryStreamReadOptions,
    ) -> Result<RangeStream, ClientError> {
        let (start, end) = self.encode_store_range(start, end)?;
        let mut stream = self
            .client
            .range_stream_internal(&start, &end, limit, batch_size, mode, options)
            .await?;
        stream.key_prefix = Some(self.prefix.clone());
        Ok(stream)
    }

    pub(crate) async fn range_reduce_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        options: QueryStreamReadOptions,
    ) -> Result<ReduceStream, ClientError> {
        let (start, end) = self.encode_store_range(start, end)?;
        let request = self.prefix_reduce_request(request)?;
        self.client
            .range_reduce_stream_internal(&start, &end, &request, options)
            .await
    }

    pub(crate) async fn apply_prune_policies(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        let policies = self.prefix_prune_policies(policies)?;
        self.client.prune(&policies).await
    }

    pub(crate) async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        // Byte-aligned payloads let the server apply the caller's payload_regex
        // exactly against the post-prefix payload, so there is no client-side
        // re-filter: the prefix only namespaces keys on the wire.
        let filter = self.prefix_stream_filter(filter)?;
        let mut sub = self
            .client
            .subscribe_physical(filter, since_sequence_number)
            .await?;
        sub.key_prefix = Some(self.prefix.clone());
        Ok(sub)
    }

    pub(crate) async fn stream_get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        let Some(owned) = self.client.stream_get_physical(sequence_number).await? else {
            return Ok(None);
        };
        let mut out = Vec::with_capacity(owned.entries.len());
        for entry in owned.entries {
            let key = Bytes::from(entry.key);
            if !self.prefix.matches(&key) {
                continue;
            }
            out.push((self.decode_store_key(&key)?, entry.value));
        }
        Ok(Some(out))
    }

    pub(crate) async fn set_retention(
        &self,
        policy: Option<crate::retention::RetentionPolicy>,
    ) -> Result<Option<u64>, ClientError> {
        // Retention operates on sequence numbers, not keys, so there is no
        // per-namespace prefixing to apply here.
        self.client.set_retention(policy).await
    }
}

/// Returns the sole scalar frame after validating its shape and consuming the final status.
pub async fn scalar_reduce_response(
    mut stream: ReduceStream,
    request: &DomainRangeReduceRequest,
) -> Result<connectrpc::StreamMessage<proto_query::ReduceResponse>, ClientError> {
    if !request.group_by.is_empty() {
        return Err(ClientError::WireFormat(
            "grouped reductions require range_reduce_stream".to_string(),
        ));
    }
    let response = stream.next().await.transpose()?.ok_or_else(|| {
        ClientError::WireFormat("scalar reduction stream returned no results".to_string())
    })?;
    let view = response.view();
    if !view.groups.is_empty() || view.results.len() != request.reducers.len() {
        return Err(ClientError::WireFormat(
            "scalar reduction returned an invalid result shape".to_string(),
        ));
    }
    if stream.next().await.transpose()?.is_some() {
        return Err(ClientError::WireFormat(
            "scalar reduction returned more than one frame".to_string(),
        ));
    }
    Ok(response)
}

async fn scalar_reduce_results(
    stream: ReduceStream,
    request: &DomainRangeReduceRequest,
) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
    let response = scalar_reduce_response(stream, request).await?;
    let decoded =
        proto_to_domain_reduce_response(response.view()).map_err(ClientError::WireFormat)?;
    Ok(decoded
        .results
        .into_iter()
        .map(|result| result.value)
        .collect())
}

/// A physical Store write batch assembled from one or more logical clients.
///
/// Use [`Self::push`] with the specific prefixed client that produced each
/// logical key, then [`Self::commit`] once to submit all rows in one atomic
/// Store `Put`.
#[derive(Clone, Debug, Default)]
pub struct StoreWriteBatch {
    entries: Vec<(Key, Bytes)>,
}

impl StoreWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    /// Stage a logical row under `client`'s namespace.
    ///
    /// The key is encoded as it is staged, so rows from several namespaces
    /// can share one batch; [`Self::commit`] writes the encoded rows
    /// verbatim through the physical client.
    pub fn push(
        &mut self,
        client: &PrefixedStoreClient,
        key: &Key,
        value: impl IntoStoreWriteValue,
    ) -> Result<&mut Self, ClientError> {
        self.entries.push((
            client.encode_store_key(key)?,
            value.into_store_write_value(),
        ));
        Ok(self)
    }

    /// The staged physical entries, in staging order.
    pub fn entries(&self) -> &[(Key, Bytes)] {
        &self.entries
    }

    pub async fn commit(&self, client: &StoreClient) -> Result<u64, ClientError> {
        client.put_prepared_physical(&self.entries).await
    }
}

/// A writer that can stage an already-prepared upload into a shared Store
/// write batch and then be notified of the batch outcome.
///
/// Implementations should keep `prepare_*` methods as inherent APIs because
/// each writer's input shape differs. Once a caller has a prepared handle,
/// this trait provides the common lifecycle:
///
/// 1. stage rows into a [`StoreWriteBatch`], consuming staged payloads if useful
/// 2. commit that batch
/// 3. mark the prepared handle persisted with the returned Store sequence
///    number, or failed if staging/commit does not complete
pub trait StoreBatchUpload {
    type Prepared: Send;
    type Receipt: Send;
    type Error: std::fmt::Display + Send;

    fn store_client(&self) -> &PrefixedStoreClient;

    fn stage_upload(
        &self,
        prepared: &mut Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error>;

    fn commit_error(&self, error: ClientError) -> Self::Error;

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a;

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a;

    fn commit_upload<'a>(
        &'a self,
        prepared: Self::Prepared,
    ) -> BoxFuture<'a, Result<Self::Receipt, Self::Error>>
    where
        Self: Sync + Sized + 'a,
        Self::Prepared: 'a,
        Self::Receipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move {
            let mut prepared = prepared;
            let mut batch = StoreWriteBatch::new();
            if let Err(err) = self.stage_upload(&mut prepared, &mut batch) {
                let message = err.to_string();
                self.mark_upload_failed(prepared, message).await;
                return Err(err);
            }
            match batch.commit(self.store_client().client()).await {
                Ok(sequence_number) => {
                    Ok(self.mark_upload_persisted(prepared, sequence_number).await)
                }
                Err(err) => {
                    let message = err.to_string();
                    self.mark_upload_failed(prepared, message).await;
                    Err(self.commit_error(err))
                }
            }
        })
    }
}

/// Traversal mode for range queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Forward,
    Reverse,
}

#[derive(Clone, Debug)]
pub struct RangeChunk {
    /// Rows returned in this stream frame.
    pub rows: Vec<(Key, Bytes)>,
    /// Query detail reported after reading this chunk.
    pub detail: Option<proto_query::Detail>,
}

#[derive(Clone, Debug)]
pub struct GetManyChunk {
    /// Lookup entries returned in this stream frame.
    pub entries: Vec<(Key, Option<Bytes>)>,
    /// Query detail reported after reading this chunk.
    pub detail: Option<proto_query::Detail>,
}

/// Iterator-like async range stream.
pub struct RangeStream {
    stream:
        ConnectServerStream<ProtoErasedResponseBody, exoware_proto::query::RangeFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::RangeFrame>,
    rows_seen: usize,
    final_count: Option<usize>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
    credential: Credential,
}

impl RangeStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            ProtoErasedResponseBody,
            exoware_proto::query::RangeFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
        credential: Credential,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            rows_seen: 0,
            final_count: None,
            finished: false,
            observed_sequence,
            key_prefix,
            credential,
        }
    }

    pub fn final_count(&self) -> Option<usize> {
        self.final_count
    }

    async fn prefetch_first_frame(&mut self) -> Result<(), ConnectError> {
        if self.pending_frame.is_some() || self.finished {
            return Ok(());
        }
        match self.stream.message().await? {
            Some(frame) => {
                let frame = frame.to_owned_message();
                if let (Some(sequence_store), Some(detail)) =
                    (&self.observed_sequence, frame.detail.as_option())
                {
                    sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
                }
                self.pending_frame = Some(frame);
                Ok(())
            }
            None => {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    Err(err.clone())
                } else {
                    self.final_count = Some(self.rows_seen);
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<RangeChunk>, ClientError> {
        loop {
            if self.finished {
                return Ok(None);
            }

            let frame = if let Some(frame) = self.pending_frame.take() {
                frame
            } else {
                let Some(frame) = self
                    .stream
                    .message()
                    .await
                    .map_err(|err| client_error_from_connect(err, self.credential))?
                else {
                    self.finished = true;
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone(), self.credential));
                    }
                    self.final_count = Some(self.rows_seen);
                    return Ok(None);
                };
                let frame = frame.to_owned_message();
                if let (Some(sequence_store), Some(detail)) =
                    (&self.observed_sequence, frame.detail.as_option())
                {
                    sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
                }
                frame
            };

            let detail = frame.detail.as_option().cloned();
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in frame.results {
                let key = Bytes::from(entry.key);
                let key = match &self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                out.push((key, entry.value));
            }
            self.rows_seen += n;
            return Ok(Some(RangeChunk { rows: out, detail }));
        }
    }

    pub async fn collect(mut self) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let mut entries = Vec::new();
        while let Some(chunk) = self.next_chunk().await? {
            entries.extend(chunk.rows);
        }
        Ok(entries)
    }
}

/// Final reduction results, delivered in bounded frames without collecting all groups.
///
/// Each item retains its wire buffer and exposes a borrowed response through `view()`.
/// Dropping the stream cancels the request. Only opening the stream and receiving
/// its first frame may be retried. Errors after that frame are returned to the caller.
pub type ReduceStream =
    BoxStream<'static, Result<connectrpc::StreamMessage<proto_query::ReduceResponse>, ClientError>>;

pub struct GetManyStream {
    stream: ConnectServerStream<
        ProtoErasedResponseBody,
        exoware_proto::query::GetManyFrameView<'static>,
    >,
    pending_frame: Option<exoware_proto::query::GetManyFrame>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
    credential: Credential,
}

impl GetManyStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            ProtoErasedResponseBody,
            exoware_proto::query::GetManyFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
        credential: Credential,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            finished: false,
            observed_sequence,
            key_prefix,
            credential,
        }
    }

    async fn prefetch_first_frame(&mut self) -> Result<(), ConnectError> {
        if self.pending_frame.is_some() || self.finished {
            return Ok(());
        }
        match self.stream.message().await? {
            Some(frame) => {
                let frame = frame.to_owned_message();
                if let (Some(sequence_store), Some(detail)) =
                    (&self.observed_sequence, frame.detail.as_option())
                {
                    sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
                }
                self.pending_frame = Some(frame);
                Ok(())
            }
            None => {
                self.finished = true;
                if let Some(err) = self.stream.error() {
                    Err(err.clone())
                } else {
                    Ok(())
                }
            }
        }
    }

    pub async fn next_chunk(&mut self) -> Result<Option<GetManyChunk>, ClientError> {
        loop {
            if self.finished {
                return Ok(None);
            }
            let frame = if let Some(frame) = self.pending_frame.take() {
                frame
            } else {
                let Some(frame) = self
                    .stream
                    .message()
                    .await
                    .map_err(|err| client_error_from_connect(err, self.credential))?
                else {
                    self.finished = true;
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone(), self.credential));
                    }
                    return Ok(None);
                };
                let frame = frame.to_owned_message();
                if let (Some(sequence_store), Some(detail)) =
                    (&self.observed_sequence, frame.detail.as_option())
                {
                    sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
                }
                frame
            };

            let detail = frame.detail.as_option().cloned();
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in frame.results {
                let key = Bytes::from(entry.key);
                let key = match &self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                out.push((key, entry.value));
            }
            return Ok(Some(GetManyChunk {
                entries: out,
                detail,
            }));
        }
    }

    pub async fn collect(mut self) -> Result<HashMap<Key, Bytes>, ClientError> {
        let mut map = HashMap::new();
        while let Some(chunk) = self.next_chunk().await? {
            for (key, value) in chunk.entries {
                if let Some(v) = value {
                    map.insert(key, v);
                }
            }
        }
        Ok(map)
    }
}

impl RangeMode {
    fn to_proto(self) -> proto_query::TraversalMode {
        match self {
            Self::Forward => proto_query::TraversalMode::TRAVERSAL_MODE_FORWARD,
            Self::Reverse => proto_query::TraversalMode::TRAVERSAL_MODE_REVERSE,
        }
    }
}

/// One delivered (key, value) row from a stream subscription. The client
/// reapplies its own filter if it needs to know which selector matched —
/// the wire frame doesn't carry the index.
#[derive(Clone, Debug)]
pub struct StreamSubscriptionEntry {
    pub key: Key,
    pub value: Bytes,
}

/// One atomic Put batch delivered to a subscriber.
#[derive(Clone, Debug)]
pub struct StreamSubscriptionFrame {
    pub sequence_number: u64,
    pub entries: Vec<StreamSubscriptionEntry>,
}

/// Async stream of `StreamSubscriptionFrame`. Backed by the generated
/// connectrpc server stream.
pub struct StreamSubscription {
    stream: ConnectServerStream<
        ProtoErasedResponseBody,
        exoware_proto::log::stream::v1::SubscribeResponseView<'static>,
    >,
    key_prefix: Option<StoreKeyPrefix>,
    credential: Credential,
}

impl std::fmt::Debug for StreamSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSubscription").finish_non_exhaustive()
    }
}

impl StreamSubscription {
    /// Pull the next frame. `Ok(None)` = server closed the stream cleanly.
    pub async fn next(&mut self) -> Result<Option<StreamSubscriptionFrame>, ClientError> {
        loop {
            match self
                .stream
                .message()
                .await
                .map_err(|err| client_error_from_connect(err, self.credential))?
            {
                Some(view) => {
                    let owned = view.to_owned_message();
                    let mut entries = Vec::with_capacity(owned.entries.len());
                    for entry in owned.entries {
                        let key = Bytes::from(entry.key);
                        let key = match &self.key_prefix {
                            Some(prefix) => prefix.decode_key(&key)?,
                            None => key,
                        };
                        entries.push(StreamSubscriptionEntry {
                            key,
                            value: entry.value,
                        });
                    }
                    if entries.is_empty() {
                        continue;
                    }
                    let frame = StreamSubscriptionFrame {
                        sequence_number: owned.sequence_number,
                        entries,
                    };
                    return Ok(Some(frame));
                }
                None => {
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone(), self.credential));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

/// Inspect a Connect error for `log.stream.BATCH_EVICTED` / `BATCH_NOT_FOUND`
/// `ErrorInfo` details. Used by `get_batch` to collapse both into `Ok(None)`.
fn is_batch_missing_error(err: &ConnectError) -> bool {
    match proto_decode_connect_error(err) {
        Ok(decoded) => decoded.error_info.is_some_and(|info| {
            info.domain == "log.stream"
                && matches!(info.reason.as_str(), "BATCH_EVICTED" | "BATCH_NOT_FOUND")
        }),
        Err(_) => false,
    }
}

/// Retry policy for idempotent read operations.
#[derive(Clone, Copy, Debug)]
pub struct RetryConfig {
    max_attempts: usize,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryConfig {
    pub fn standard() -> Self {
        Self {
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            initial_backoff: Duration::from_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MS),
            max_backoff: Duration::from_millis(DEFAULT_RETRY_MAX_BACKOFF_MS),
        }
    }

    pub fn disabled() -> Self {
        Self::standard().with_max_attempts(1)
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    pub fn with_max_backoff(mut self, max_backoff: Duration) -> Self {
        self.max_backoff = max_backoff;
        self
    }

    pub(crate) fn sanitized(self) -> Self {
        let max_attempts = self.max_attempts.max(1);
        let max_backoff = self.max_backoff.max(self.initial_backoff);
        Self {
            max_attempts,
            initial_backoff: self.initial_backoff,
            max_backoff,
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self::standard()
    }
}

fn trim_connect_base(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}

fn parse_connect_uri(url: &str) -> Result<http::Uri, ClientBuildError> {
    let uri: http::Uri = url.parse().map_err(|source| ClientBuildError::InvalidUrl {
        url: url.to_string(),
        source,
    })?;
    if uri.authority().is_none() || !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(ClientBuildError::InvalidEndpointUrl {
            url: url.to_string(),
        });
    }
    Ok(uri)
}

fn new_health_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

/// Error returned while building a [`StoreClient`].
#[derive(Debug, thiserror::Error)]
pub enum ClientBuildError {
    #[error("StoreClientBuilder: missing health URL (set health_url or url)")]
    MissingHealthUrl,
    #[error("StoreClientBuilder: missing ingest URL (set ingest_url or url)")]
    MissingIngestUrl,
    #[error("StoreClientBuilder: missing query URL (set query_url or url)")]
    MissingQueryUrl,
    #[error("StoreClientBuilder: missing prune URL (set prune_url or url)")]
    MissingPruneUrl,
    #[error("StoreClientBuilder: missing retention URL (set retention_url or url)")]
    MissingRetentionUrl,
    #[error("StoreClientBuilder: missing stream URL (set stream_url or url)")]
    MissingStreamUrl,
    #[error("StoreClientBuilder: invalid URL \"{url}\": {source}")]
    InvalidUrl {
        url: String,
        source: http::uri::InvalidUri,
    },
    #[error(
        "StoreClientBuilder: invalid endpoint URL \"{url}\" (expected absolute HTTP or HTTPS URL)"
    )]
    InvalidEndpointUrl { url: String },
    #[error("StoreClientBuilder: failed to configure platform TLS verifier: {0}")]
    TlsConfig(#[source] connectrpc::rustls::Error),
    #[error(
        "StoreClientBuilder: API key is not valid in an HTTP header (check for control or non-ASCII characters)"
    )]
    InvalidApiKey,
    #[error(
        "{API_KEY_ENV} is set to a value that cannot be an HTTP header. Remove any control or non-ASCII characters from it"
    )]
    InvalidApiKeyEnv,
}

#[derive(Debug)]
enum RpcTransportChoice {
    Custom(ProtoErasedClientTransport),
    BalancedHttp2(ProtoBalancedHttp2Config),
}

/// Configures a [`StoreClient`] with explicit bases for health probes and store services.
///
/// Use [`StoreClient::builder()`] to construct. Call [`Self::url`] to point every
/// service at the same origin, or set each base separately. Finish with [`Self::build`].
/// HTTP and HTTPS service URLs may be mixed. HTTPS uses the platform certificate verifier.
#[derive(Debug, Default)]
pub struct StoreClientBuilder {
    health_url: Option<String>,
    ingest_url: Option<String>,
    query_url: Option<String>,
    prune_url: Option<String>,
    retention_url: Option<String>,
    stream_url: Option<String>,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
    api_key: Option<ApiKey>,
    rpc_transport: Option<RpcTransportChoice>,
}

impl StoreClientBuilder {
    /// Sets the same base URL for all services (health, ingest, query, prune,
    /// retention, stream).
    pub fn url(mut self, url: &str) -> Self {
        let u = trim_connect_base(url);
        self.health_url = Some(u.clone());
        self.ingest_url = Some(u.clone());
        self.query_url = Some(u.clone());
        self.prune_url = Some(u.clone());
        self.retention_url = Some(u.clone());
        self.stream_url = Some(u);
        self
    }

    /// Base URL for `GET /health` and `GET /ready` (often the query worker).
    pub fn health_url(mut self, url: &str) -> Self {
        self.health_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the ingest service (`log.ingest.v1.Service`).
    pub fn ingest_url(mut self, url: &str) -> Self {
        self.ingest_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the query service (`store.query.v1.Service`).
    pub fn query_url(mut self, url: &str) -> Self {
        self.query_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the prune service (`store.prune.v1.Service`).
    pub fn prune_url(mut self, url: &str) -> Self {
        self.prune_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the retention service (`log.retention.v1.Service`).
    pub fn retention_url(mut self, url: &str) -> Self {
        self.retention_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the stream service (`log.stream.v1.Service`).
    pub fn stream_url(mut self, url: &str) -> Self {
        self.stream_url = Some(trim_connect_base(url));
        self
    }

    /// API key sent as `Authorization: Bearer <key>` on every RPC.
    ///
    /// Leaving this unset falls back to the `EXOWARE_API_KEY` environment variable, if present.
    ///
    /// Ignored for [`StoreClient::health`] and [`StoreClient::ready`].
    pub fn api_key(mut self, key: &str) -> Self {
        self.api_key = Some(ApiKey(key.to_string()));
        self
    }

    /// Retry policy for idempotent read operations (get / range / reduce).
    pub fn retry_config(mut self, retry: RetryConfig) -> Self {
        self.retry_config = retry.sanitized();
        self
    }

    /// Codec for compressing **outgoing** RPC request bodies (default [`ConnectRequestCompression::None`]).
    pub fn connect_request_compression(mut self, compression: ConnectRequestCompression) -> Self {
        self.connect_request_compression = compression;
        self
    }

    /// Uses a consumer-supplied raw connectrpc transport for every Store RPC.
    ///
    /// The transport must route absolute request URIs to the configured service origins. The SDK
    /// applies authentication, cookies, compression preferences, and request compression.
    /// Health and readiness probes are unaffected. [`crate::transport`] re-exports the exact trait
    /// and body types. Tower middleware that exposes `tower::BoxError` must map it into a concrete
    /// [`std::error::Error`] before constructing [`crate::transport::ServiceTransport`].
    /// connectrpc reports transport failures as `unavailable`.
    pub fn client_transport<T>(mut self, transport: T) -> Self
    where
        T: connectrpc::client::ClientTransport,
        <T::ResponseBody as http_body::Body>::Error: std::fmt::Display,
    {
        self.rpc_transport = Some(RpcTransportChoice::Custom(ProtoErasedClientTransport::new(
            transport,
        )));
        self
    }

    /// Uses independent HTTP/2 connection pools for each distinct Store RPC origin.
    ///
    /// HTTP origins must accept prior-knowledge h2c. HTTPS origins require HTTP/2 through ALPN.
    /// The configured request timeout bounds complete unary calls. It also bounds query streams
    /// through their first frame and subscriptions through their response headers. It does not stop
    /// a streaming response after the call returns.
    pub fn balanced_http2_transport(mut self, config: ProtoBalancedHttp2Config) -> Self {
        self.rpc_transport = Some(RpcTransportChoice::BalancedHttp2(config));
        self
    }

    /// Build the client, or return an error if any required URL was not set.
    /// Takes the API key from [`API_KEY_ENV`] unless [`Self::api_key`] set one, and fails if
    /// either cannot be an HTTP header.
    pub fn build(self) -> Result<StoreClient, ClientBuildError> {
        self.build_with(std::env::var(API_KEY_ENV).ok(), UnusableEnvKey::Reject)
    }

    /// Takes the environment lookup as an argument, so a test can cover every credential case
    /// without mutating a variable that the rest of the process is reading.
    fn build_with(
        self,
        env_api_key: Option<String>,
        unusable_env_key: UnusableEnvKey,
    ) -> Result<StoreClient, ClientBuildError> {
        let health_url = self.health_url.ok_or(ClientBuildError::MissingHealthUrl)?;
        let ingest_url = self.ingest_url.ok_or(ClientBuildError::MissingIngestUrl)?;
        let query_url = self.query_url.ok_or(ClientBuildError::MissingQueryUrl)?;
        let prune_url = self.prune_url.ok_or(ClientBuildError::MissingPruneUrl)?;
        let retention_url = self
            .retention_url
            .ok_or(ClientBuildError::MissingRetentionUrl)?;
        let stream_url = self.stream_url.ok_or(ClientBuildError::MissingStreamUrl)?;
        let ingest_uri = parse_connect_uri(&ingest_url)?;
        let query_uri = parse_connect_uri(&query_url)?;
        let prune_uri = parse_connect_uri(&prune_url)?;
        let retention_uri = parse_connect_uri(&retention_url)?;
        let stream_uri = parse_connect_uri(&stream_url)?;
        let rpc_uris = [
            &ingest_uri,
            &query_uri,
            &prune_uri,
            &retention_uri,
            &stream_uri,
        ];
        let uses_tls = rpc_uris
            .into_iter()
            .any(|uri| uri.scheme_str() == Some("https"));

        let resolved =
            credential::resolve(self.api_key.map(|key| key.0), env_api_key, unusable_env_key)?;
        let credential = resolved.credential;
        let (connect_http, rpc_timeout) = match self.rpc_transport {
            None => {
                let connect_http = if uses_tls {
                    let tls_config = connectrpc::rustls::ClientConfig::with_platform_verifier()
                        .map_err(ClientBuildError::TlsConfig)?;
                    ProtoPreferZstdHttpClient::with_tls(Arc::new(tls_config))
                } else {
                    ProtoPreferZstdHttpClient::plaintext()
                };
                let connect_http = match resolved.header {
                    Some(value) => connect_http.with_authorization(value),
                    None => connect_http,
                };
                (ProtoErasedClientTransport::new(connect_http), None)
            }
            Some(RpcTransportChoice::Custom(transport)) => {
                (transport.with_metadata(resolved.header), None)
            }
            Some(RpcTransportChoice::BalancedHttp2(mut config)) => {
                let rpc_timeout = config.request_timeout;
                if uses_tls && config.tls_config.is_none() {
                    config = config.with_tls_config(Arc::new(
                        connectrpc::rustls::ClientConfig::with_platform_verifier()
                            .map_err(ClientBuildError::TlsConfig)?,
                    ));
                }
                let transport =
                    ProtoBalancedHttp2Transport::new(rpc_uris.into_iter().cloned(), config);
                (
                    ProtoErasedClientTransport::new(transport).with_metadata(resolved.header),
                    Some(rpc_timeout),
                )
            }
        };
        Ok(StoreClient {
            health_url,
            ingest_uri,
            query_uri,
            prune_uri,
            retention_uri,
            stream_uri,
            health_http: new_health_client(),
            connect_http,
            rpc_timeout,
            retry_config: self.retry_config,
            connect_request_compression: self.connect_request_compression,
            credential,
        })
    }
}

/// Typed Rust client for Store.
#[derive(Clone, Debug)]
pub struct StoreClient {
    /// Base URL for `health()` / `ready()` (typically the query worker).
    pub(crate) health_url: String,
    ingest_uri: http::Uri,
    query_uri: http::Uri,
    prune_uri: http::Uri,
    retention_uri: http::Uri,
    stream_uri: http::Uri,
    health_http: reqwest::Client,
    connect_http: ProtoErasedClientTransport,
    rpc_timeout: Option<Duration>,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
    credential: Credential,
}

/// A session whose read floor advances to the highest Store sequence observed.
///
/// An explicit initial floor constrains reads without claiming that any read has
/// evaluated at that sequence. Reads started after a response is observed use
/// at least its sequence. Clones share the floor, including updates from streams.
///
/// Streamed reads record response sequences as frames arrive, including the
/// first frame fetched before the stream is returned to the caller.
#[derive(Clone, Debug)]
pub struct SerializableReadSession {
    client: PrefixedStoreClient,
    state: Arc<SessionState>,
}

#[derive(Debug)]
struct SessionState {
    minimum_sequence: u64,
    sequence: Arc<AtomicU64>,
    init_gate: tokio::sync::Mutex<()>,
}

impl SessionState {
    fn fixed_sequence(&self) -> Option<u64> {
        let sequence = self.sequence.load(Ordering::Acquire);
        let floor = self.minimum_sequence.max(sequence);
        (floor > 0).then_some(floor)
    }

    fn evaluated_sequence(&self) -> Option<u64> {
        let sequence = self.sequence.load(Ordering::Acquire);
        (sequence > 0).then_some(sequence)
    }
}

#[derive(Default)]
struct QueryStreamReadOptions {
    min_sequence_number: Option<u64>,
    observed_sequence: Option<Arc<AtomicU64>>,
}

impl StoreClient {
    /// Start building a client with per-service base URLs.
    pub fn builder() -> StoreClientBuilder {
        StoreClientBuilder::default()
    }

    pub fn new(url: &str) -> Self {
        Self::with_retry_config(url, RetryConfig::standard())
    }

    /// Panics if `url` is not a valid endpoint. A malformed [`API_KEY_ENV`] is ignored rather
    /// than panicking, so use [`Self::builder`] to have it rejected.
    pub fn with_retry_config(url: &str, retry_config: RetryConfig) -> Self {
        Self::builder()
            .url(url)
            .retry_config(retry_config)
            .build_with(std::env::var(API_KEY_ENV).ok(), UnusableEnvKey::Tolerate)
            .expect("failed to configure Store client")
    }

    /// Pair this physical client with `prefix`, yielding the logical
    /// [`PrefixedStoreClient`] that namespaces every operation.
    pub fn prefixed(&self, prefix: StoreKeyPrefix) -> PrefixedStoreClient {
        PrefixedStoreClient::new(self.clone(), prefix)
    }

    /// Outgoing Connect request body compression (see [`ConnectRequestCompression`]).
    pub fn connect_request_compression(&self) -> ConnectRequestCompression {
        self.connect_request_compression
    }

    fn unary_client_config(&self, base_uri: http::Uri) -> ClientConfig {
        store_connect_client_config(base_uri, self.connect_request_compression, self.rpc_timeout)
    }

    fn streaming_client_config(&self, base_uri: http::Uri) -> ClientConfig {
        store_connect_client_config(base_uri, self.connect_request_compression, None)
    }

    async fn with_streaming_timeout<T>(
        &self,
        future: impl std::future::Future<Output = Result<T, ConnectError>>,
    ) -> Result<T, ConnectError> {
        match self.rpc_timeout {
            Some(timeout) => tokio::time::timeout(timeout, future)
                .await
                .map_err(|_| ConnectError::deadline_exceeded("client-side deadline exceeded"))?,
            None => future.await,
        }
    }

    pub fn decode_error_details(
        err: &ConnectError,
    ) -> Result<exoware_proto::DecodedConnectError, buffa::DecodeError> {
        proto_decode_connect_error(err)
    }

    /// Submit a KV batch via Connect `Put`.
    ///
    /// On success returns the **store sequence number** from the response. Use it for immediate
    /// `get_with_min_sequence_number` / range calls or as the initial floor for
    /// [`PrefixedStoreClient::create_session_with_sequence`].
    /// If the request succeeds, the server accepts the full batch (count is `kvs.len()`).
    pub(crate) async fn put_physical(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        let mut proto_kvs = Vec::with_capacity(kvs.len());
        for (key, value) in kvs {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
            proto_kvs.push(exoware_proto::common::Entry {
                key: key.to_vec(),
                value: Bytes::copy_from_slice(value),
                ..Default::default()
            });
        }
        self.send_put(proto_kvs).await
    }

    async fn put_prepared_physical(&self, kvs: &[(Key, Bytes)]) -> Result<u64, ClientError> {
        let mut proto_kvs = Vec::with_capacity(kvs.len());
        for (key, value) in kvs {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
            proto_kvs.push(exoware_proto::common::Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            });
        }
        self.send_put(proto_kvs).await
    }

    async fn send_put(&self, kvs: Vec<exoware_proto::common::Entry>) -> Result<u64, ClientError> {
        let config = self.unary_client_config(self.ingest_uri.clone());
        let client = IngestServiceClient::new(self.connect_http.clone(), config);
        let response = client
            .put(ProtoPutRequest {
                kvs,
                ..Default::default()
            })
            .await
            .map_err(|err| client_error_from_connect(err, self.credential))?;
        Ok(response.into_owned().sequence_number)
    }

    pub(crate) async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.get_internal(key, None).await
    }

    pub(crate) async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.get_internal(key, Some(min_sequence_number)).await
    }

    async fn get_internal(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<Option<Bytes>, ClientError> {
        let (response, _detail) = self
            .send_get(key, self.normalize_min_sequence_number(min_sequence_number))
            .await?;
        Ok(response.value)
    }

    /// Physical `get_many` over already-encoded wire keys. The
    /// [`PrefixedStoreClient`] wrapper encodes + validates and attaches the
    /// prefix to the returned stream for decoding.
    pub(crate) async fn get_many_internal(
        &self,
        proto_keys: Vec<Vec<u8>>,
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        let config = self.streaming_client_config(self.query_uri.clone());
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let effective_min = self.normalize_min_sequence_number(min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            let result = self
                .with_streaming_timeout(async {
                    let response = client
                        .get_many(ProtoGetManyRequest {
                            keys: proto_keys.clone(),
                            min_sequence_number: effective_min,
                            batch_size,
                            ..Default::default()
                        })
                        .await?;
                    let mut stream = GetManyStream::from_connect_stream(
                        response,
                        observed_sequence.clone(),
                        None,
                        self.credential,
                    );
                    stream.prefetch_first_frame().await?;
                    Ok(stream)
                })
                .await;
            match result {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err, self.credential));
                }
            }
        }
    }

    pub(crate) async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        let config = self.unary_client_config(self.prune_uri.clone());
        let client = PruneServiceClient::new(self.connect_http.clone(), config);
        client
            .prune(ProtoPruneRequest {
                policies: exoware_proto::prune_policies_to_proto(policies),
                ..Default::default()
            })
            .await
            .map_err(|err| client_error_from_connect(err, self.credential))?;
        Ok(())
    }

    /// Open a physical subscription over an already-encoded `filter`. The
    /// returned [`StreamSubscription`] carries no prefix; the logical
    /// [`PrefixedStoreClient`] wrapper attaches one for decoding.
    async fn subscribe_physical(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        crate::stream_filter::validate_filter(&filter)
            .map_err(|e| ClientError::WireFormat(e.to_string()))?;
        let selectors = filter
            .selectors
            .into_iter()
            .map(|mk| exoware_proto::common::kv::v1::Selector {
                prefix: mk.prefix,
                payload_regex: mk.payload_regex.0,
                ..Default::default()
            })
            .collect();
        let value_filters = filter
            .value_filters
            .into_iter()
            .map(|vf| {
                use crate::stream_filter::Filter;
                use exoware_proto::common::kv::v1::filter::Kind as ProtoKind;
                let kind = match vf {
                    Filter::Exact(bytes) => ProtoKind::Exact(bytes),
                    Filter::Prefix(bytes) => ProtoKind::Prefix(bytes),
                    Filter::Regex(pattern) => ProtoKind::Regex(pattern),
                };
                exoware_proto::common::kv::v1::Filter {
                    kind: Some(kind),
                    ..Default::default()
                }
            })
            .collect();
        let request = exoware_proto::log::stream::v1::SubscribeRequest {
            selectors,
            value_filters,
            since_sequence_number,
            ..Default::default()
        };
        let config = self.streaming_client_config(self.stream_uri.clone());
        let client =
            exoware_proto::log::stream::v1::ServiceClient::new(self.connect_http.clone(), config);
        let stream = self
            .with_streaming_timeout(client.subscribe(request))
            .await
            .map_err(|err| client_error_from_connect(err, self.credential))?;
        Ok(StreamSubscription {
            stream,
            key_prefix: None,
            credential: self.credential,
        })
    }

    /// Fetch a batch by sequence number, returning the raw owned response
    /// (physical keys, no decode). `None` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` errors. The [`PrefixedStoreClient`]
    /// wrapper consumes the entries in one pass to filter + decode.
    async fn stream_get_physical(
        &self,
        sequence_number: u64,
    ) -> Result<Option<exoware_proto::log::stream::v1::GetResponse>, ClientError> {
        let config = self.unary_client_config(self.stream_uri.clone());
        let client =
            exoware_proto::log::stream::v1::ServiceClient::new(self.connect_http.clone(), config);
        match client
            .get(exoware_proto::log::stream::v1::GetRequest {
                sequence_number,
                ..Default::default()
            })
            .await
        {
            Ok(resp) => Ok(Some(resp.into_owned())),
            Err(err) => {
                if is_batch_missing_error(&err) {
                    Ok(None)
                } else {
                    Err(client_error_from_connect(err, self.credential))
                }
            }
        }
    }

    /// Install (`Some`) or clear (`None`) the sequence-log retention rule via
    /// `log.retention.v1.SetRetention`. Returns the lowest retained sequence
    /// after one synchronous enforcement of the new rule (`None` when the log is
    /// empty / no floor exists yet).
    async fn set_retention(
        &self,
        policy: Option<crate::retention::RetentionPolicy>,
    ) -> Result<Option<u64>, ClientError> {
        let request = exoware_proto::log::retention::v1::SetRetentionRequest {
            policy: policy
                .as_ref()
                .map(exoware_proto::retention_policy_to_proto)
                .into(),
            ..Default::default()
        };
        let config = self.unary_client_config(self.retention_uri.clone());
        let client = exoware_proto::log::retention::v1::ServiceClient::new(
            self.connect_http.clone(),
            config,
        );
        let response = client
            .set_retention(request)
            .await
            .map_err(|err| client_error_from_connect(err, self.credential))?;
        Ok(response.into_owned().oldest_retained_sequence)
    }

    pub async fn health(&self) -> Result<bool, ClientError> {
        let resp = self
            .health_http
            .get(format!("{}/health", self.health_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn ready(&self) -> Result<bool, ClientError> {
        let resp = self
            .health_http
            .get(format!("{}/ready", self.health_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    fn normalize_min_sequence_number(&self, requested_sequence: Option<u64>) -> Option<u64> {
        requested_sequence.filter(|sequence| *sequence > 0)
    }

    async fn send_get(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::GetResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        if !is_valid_key_size(key.len()) {
            return Err(ClientError::WireFormat(format!(
                "key length {} is outside valid store key range ({}..={})",
                key.len(),
                keys::MIN_KEY_LEN,
                MAX_KEY_LEN
            )));
        }

        let config = self.unary_client_config(self.query_uri.clone());
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let response = self
            .send_with_retry(|| async {
                client
                    .get(ProtoGetRequest {
                        key: key.clone().into(),
                        min_sequence_number,
                        ..Default::default()
                    })
                    .await
            })
            .await?;
        let owned = response.into_owned();
        let detail = owned.detail.as_option().cloned();
        Ok((owned, detail))
    }

    #[cfg(test)]
    pub async fn send_get_for_tests(
        &self,
        key: &Key,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::GetResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        self.send_get(key, min_sequence_number).await
    }

    async fn range_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        options: QueryStreamReadOptions,
    ) -> Result<RangeStream, ClientError> {
        if !is_valid_key_size(start.len()) || !is_valid_key_size(end.len()) {
            return Err(ClientError::WireFormat(
                "range start/end key length is outside valid store key range".to_string(),
            ));
        }
        if batch_size == 0 {
            return Err(ClientError::WireFormat(
                "batch_size must be positive".to_string(),
            ));
        }

        let config = self.streaming_client_config(self.query_uri.clone());
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let min_sequence_number = self.normalize_min_sequence_number(options.min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            // Server-streaming RPCs cannot transparently recover mid-stream failures,
            // but retrying a transient error while opening the stream or before the
            // first frame arrives is still safe. Treat both phases as a single
            // attempt budget so range opens do not multiply retries quadratically.
            let result = self
                .with_streaming_timeout(async {
                    let response = client
                        .range(ProtoRangeRequest {
                            start: start.clone().into(),
                            end: end.clone().into(),
                            limit: (limit != usize::MAX)
                                .then(|| u32::try_from(limit).unwrap_or(u32::MAX)),
                            batch_size: u32::try_from(batch_size).unwrap_or(u32::MAX),
                            mode: mode.to_proto().into(),
                            min_sequence_number,
                            ..Default::default()
                        })
                        .await?;
                    let mut stream = RangeStream::from_connect_stream(
                        response,
                        options.observed_sequence.clone(),
                        None,
                        self.credential,
                    );
                    stream.prefetch_first_frame().await?;
                    Ok(stream)
                })
                .await;
            match result {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tracing::debug!(
                            attempt,
                            max_attempts,
                            code = err.code.as_str(),
                            delay_ms = delay.as_millis() as u64,
                            "store client retrying transient stream-open error",
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err, self.credential));
                }
            }
        }
    }

    async fn range_reduce_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        options: QueryStreamReadOptions,
    ) -> Result<ReduceStream, ClientError> {
        let config = self.streaming_client_config(self.query_uri.clone());
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_params = proto_to_proto_reduce_params(request.clone());
        let min_sequence_number = self.normalize_min_sequence_number(options.min_sequence_number);
        let (stream, first) = self
            .send_with_retry(|| {
                self.with_streaming_timeout(async {
                    let mut stream = client
                        .reduce(ProtoWireReduceRequest {
                            start: start.clone().into(),
                            end: end.clone().into(),
                            params: Some(proto_params.clone()).into(),
                            min_sequence_number,
                            ..Default::default()
                        })
                        .await?;
                    let first = stream
                        .message::<proto_query::ReduceResponse>()
                        .await?
                        .ok_or_else(|| {
                            ConnectError::new(
                                ErrorCode::Internal,
                                "reduction stream returned no frames",
                            )
                        })?;
                    Ok((stream, first))
                })
            })
            .await?;
        let observed_sequence = options.observed_sequence;
        if let (Some(sequence), Some(detail)) =
            (&observed_sequence, first.view().detail.as_option())
        {
            sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
        }
        let credential = self.credential;
        Ok(
            futures::stream::try_unfold((stream, Some(first)), move |(mut stream, first)| {
                let observed_sequence = observed_sequence.clone();
                async move {
                    let frame = if let Some(frame) = first {
                        frame
                    } else {
                        match stream
                            .message()
                            .await
                            .map_err(|err| client_error_from_connect(err, credential))?
                        {
                            Some(frame) => {
                                if let (Some(sequence), Some(detail)) =
                                    (&observed_sequence, frame.view().detail.as_option())
                                {
                                    sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                                }
                                frame
                            }
                            None => return Ok(None),
                        }
                    };
                    Ok(Some((frame, (stream, None))))
                }
            })
            .boxed(),
        )
    }

    async fn send_with_retry<F, Fut, T>(&self, mut make_request: F) -> Result<T, ClientError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, ConnectError>>,
    {
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            match make_request().await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tracing::debug!(
                            attempt,
                            max_attempts,
                            code = err.code.as_str(),
                            delay_ms = delay.as_millis() as u64,
                            "store client retrying transient RPC error",
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err, self.credential));
                }
            }
        }
    }
}

fn shift_reduce_request_key_offsets(
    prefix_len: usize,
    request: &mut DomainRangeReduceRequest,
) -> Result<(), StoreKeyPrefixError> {
    // A byte-aligned store prefix shifts every key field past its bytes.
    // `KeyField` offsets are byte-granular, so they shift by the whole prefix
    // length in bytes; `ZOrderKey` offsets remain bit-granular, so they shift
    // by `prefix_len * 8` bits. `prefix_len` comes from a validated
    // `StoreKeyPrefix`, so both shifts fit u16 (`MAX_KEY_LEN * 8` = 2032).
    debug_assert!(prefix_len <= MAX_KEY_LEN);
    let shift_bytes = prefix_len as u16;
    let shift_bits = shift_bytes * 8;
    for reducer in &mut request.reducers {
        if let Some(expr) = &mut reducer.expr {
            shift_expr_key_offsets(shift_bytes, shift_bits, expr)?;
        }
    }
    for expr in &mut request.group_by {
        shift_expr_key_offsets(shift_bytes, shift_bits, expr)?;
    }
    for filter in request.filter.iter_mut().chain(
        request
            .reducers
            .iter_mut()
            .filter_map(|reducer| reducer.filter.as_mut()),
    ) {
        for check in &mut filter.checks {
            shift_field_ref_key_offset(shift_bytes, shift_bits, &mut check.field)?;
        }
    }
    Ok(())
}

fn shift_expr_key_offsets(
    shift_bytes: u16,
    shift_bits: u16,
    expr: &mut KvExpr,
) -> Result<(), StoreKeyPrefixError> {
    match expr {
        KvExpr::Field(field) => shift_field_ref_key_offset(shift_bytes, shift_bits, field),
        KvExpr::Literal(_) => Ok(()),
        KvExpr::Add(left, right)
        | KvExpr::Sub(left, right)
        | KvExpr::Mul(left, right)
        | KvExpr::Div(left, right) => {
            shift_expr_key_offsets(shift_bytes, shift_bits, left)?;
            shift_expr_key_offsets(shift_bytes, shift_bits, right)
        }
        KvExpr::Lower(inner) | KvExpr::DateTruncDay(inner) | KvExpr::CastFloat64(inner) => {
            shift_expr_key_offsets(shift_bytes, shift_bits, inner)
        }
    }
}

fn shift_field_ref_key_offset(
    shift_bytes: u16,
    shift_bits: u16,
    field: &mut KvFieldRef,
) -> Result<(), StoreKeyPrefixError> {
    match field {
        KvFieldRef::Key { byte_offset, .. } => {
            *byte_offset = byte_offset.checked_add(shift_bytes).ok_or(
                StoreKeyPrefixError::KeyOffsetOverflow {
                    offset: *byte_offset,
                    shift: shift_bytes,
                },
            )?;
            Ok(())
        }
        KvFieldRef::ZOrderKey { bit_offset, .. } => {
            *bit_offset = bit_offset.checked_add(shift_bits).ok_or(
                StoreKeyPrefixError::KeyOffsetOverflow {
                    offset: *bit_offset,
                    shift: shift_bits,
                },
            )?;
            Ok(())
        }
        KvFieldRef::Value { .. } => Ok(()),
    }
}

// --- Service-grouped accessors ---------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Ingest<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Prune<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Retention<'a> {
    c: &'a PrefixedStoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Stream<'a> {
    c: &'a PrefixedStoreClient,
}

impl<'a> Ingest<'a> {
    pub async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        self.c.put(kvs).await
    }

    /// Submit a [`StoreWriteBatch`] that has already been encoded into the
    /// physical Store keyspace.
    pub async fn put_prepared(&self, batch: &StoreWriteBatch) -> Result<u64, ClientError> {
        batch.commit(self.c.client()).await
    }
}

impl<'a> Query<'a> {
    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.c.get(key).await
    }

    pub async fn get_with_min_sequence_number(
        &self,
        key: &Key,
        min_sequence_number: u64,
    ) -> Result<Option<Bytes>, ClientError> {
        self.c
            .get_with_min_sequence_number(key, min_sequence_number)
            .await
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.c.get_many(keys, batch_size).await
    }

    pub async fn get_many_with_min_sequence_number(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: u64,
    ) -> Result<GetManyStream, ClientError> {
        self.c
            .get_many_with_min_sequence_number(keys, batch_size, min_sequence_number)
            .await
    }

    /// Collect a `Range` into a `Vec`. Use `range_stream` for large scans.
    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c.range(start, end, limit).await
    }

    pub async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c.range_with_mode(start, end, limit, mode).await
    }

    pub async fn range_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c
            .range_with_min_sequence_number(start, end, limit, min_sequence_number)
            .await
    }

    pub async fn range_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.c
            .range_with_mode_and_min_sequence_number(start, end, limit, mode, min_sequence_number)
            .await
    }

    pub async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.c.range_stream(start, end, limit, batch_size).await
    }

    pub async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_mode(start, end, limit, batch_size, mode)
            .await
    }

    pub async fn range_stream_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_min_sequence_number(
                start,
                end,
                limit,
                batch_size,
                min_sequence_number,
            )
            .await
    }

    pub async fn range_stream_with_mode_and_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        min_sequence_number: u64,
    ) -> Result<RangeStream, ClientError> {
        self.c
            .range_stream_with_mode_and_min_sequence_number(
                start,
                end,
                limit,
                batch_size,
                mode,
                min_sequence_number,
            )
            .await
    }

    pub async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        scalar_reduce_results(
            self.range_reduce_stream(start, end, request).await?,
            request,
        )
        .await
    }

    pub async fn range_reduce_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        scalar_reduce_results(
            self.range_reduce_stream_with_min_sequence_number(
                start,
                end,
                request,
                min_sequence_number,
            )
            .await?,
            request,
        )
        .await
    }

    pub async fn range_reduce_stream(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<ReduceStream, ClientError> {
        self.c
            .range_reduce_stream_internal(start, end, request, QueryStreamReadOptions::default())
            .await
    }

    pub async fn range_reduce_stream_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<ReduceStream, ClientError> {
        self.c
            .range_reduce_stream_internal(
                start,
                end,
                request,
                QueryStreamReadOptions {
                    min_sequence_number: Some(min_sequence_number),
                    observed_sequence: None,
                },
            )
            .await
    }
}

impl<'a> Prune<'a> {
    /// `store.prune.v1.Service.Prune` — apply each policy in turn.
    pub async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        self.c.apply_prune_policies(policies).await
    }
}

impl<'a> Stream<'a> {
    /// `log.stream.v1.Service.Subscribe` — see `StreamSubscription::next`
    /// for consuming delivered frames. `since_sequence_number = None` starts
    /// live from the next Put; `Some(N)` replays retained batches before
    /// transitioning to live. An evicted `since` returns a
    /// `ConnectError::out_of_range` carrying `ErrorInfo.reason = "BATCH_EVICTED"`.
    pub async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        self.c.subscribe(filter, since_sequence_number).await
    }

    /// `log.stream.v1.Service.Get` — `Ok(None)` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` error details.
    pub async fn get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        self.c.stream_get(sequence_number).await
    }
}

impl<'a> Retention<'a> {
    /// `log.retention.v1.Service.SetRetention` — install (`Some`) or clear
    /// (`None`) the sequence-log retention rule. The rule is persistent and
    /// continuously enforced as the log grows; eviction surfaces to
    /// `log.stream.v1` subscribers as `BATCH_EVICTED`. Returns the lowest
    /// retained sequence after one synchronous enforcement (`None` when the log
    /// is empty / no floor exists yet).
    pub async fn set_retention(
        &self,
        policy: Option<crate::retention::RetentionPolicy>,
    ) -> Result<Option<u64>, ClientError> {
        self.c.set_retention(policy).await
    }
}

impl SerializableReadSession {
    /// Minimum Store sequence requested by subsequent reads.
    ///
    /// Before any response, this is the explicitly configured floor, if present.
    /// It advances as reads observe newer Store sequences.
    pub fn fixed_sequence(&self) -> Option<u64> {
        self.state.fixed_sequence()
    }

    /// Highest positive Store sequence reported by a read in this session.
    ///
    /// Returns `None` until a positive sequence is observed, including after reads that report zero.
    pub fn evaluated_sequence(&self) -> Option<u64> {
        self.state.evaluated_sequence()
    }

    /// Share this session's freshness state with another client for the same Store.
    pub fn with_client(&self, client: PrefixedStoreClient) -> Self {
        Self {
            client,
            state: self.state.clone(),
        }
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        self.run_read(|sequence, observed_sequence| async move {
            let (response, detail) = self.client.send_get(key, sequence).await?;
            if let Some(detail) = detail {
                observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
            }
            Ok(response.value)
        })
        .await
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        self.run_read(|sequence, observed_sequence| {
            self.client
                .get_many_internal(keys, batch_size, sequence, Some(observed_sequence))
        })
        .await
    }

    pub async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_with_mode(start, end, limit, RangeMode::Forward)
            .await
    }

    pub async fn range_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.run_read(|sequence, observed_sequence| async move {
            self.client
                .range_stream_internal(
                    start,
                    end,
                    limit,
                    limit.max(1),
                    mode,
                    QueryStreamReadOptions {
                        min_sequence_number: sequence,
                        observed_sequence: Some(observed_sequence),
                    },
                )
                .await?
                .collect()
                .await
        })
        .await
    }

    pub async fn range_stream(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
    ) -> Result<RangeStream, ClientError> {
        self.range_stream_with_mode(start, end, limit, batch_size, RangeMode::Forward)
            .await
    }

    pub async fn range_stream_with_mode(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
    ) -> Result<RangeStream, ClientError> {
        self.run_read(|sequence, observed_sequence| {
            self.client.range_stream_internal(
                start,
                end,
                limit,
                batch_size,
                mode,
                QueryStreamReadOptions {
                    min_sequence_number: sequence,
                    observed_sequence: Some(observed_sequence),
                },
            )
        })
        .await
    }

    pub async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        scalar_reduce_results(
            self.range_reduce_stream(start, end, request).await?,
            request,
        )
        .await
    }

    pub async fn range_reduce_stream(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<ReduceStream, ClientError> {
        self.run_read(|sequence, observed_sequence| {
            self.client.range_reduce_stream_internal(
                start,
                end,
                request,
                QueryStreamReadOptions {
                    min_sequence_number: sequence,
                    observed_sequence: Some(observed_sequence),
                },
            )
        })
        .await
    }

    async fn run_read<T, Call, Fut>(&self, call: Call) -> Result<T, ClientError>
    where
        Call: FnOnce(Option<u64>, Arc<AtomicU64>) -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        if let Some(sequence) = self.fixed_sequence() {
            return call(Some(sequence), self.state.sequence.clone()).await;
        }

        let gate = self.state.init_gate.lock().await;

        if let Some(sequence) = self.fixed_sequence() {
            drop(gate);
            return call(Some(sequence), self.state.sequence.clone()).await;
        }

        let result = call(None, self.state.sequence.clone()).await;
        drop(gate);
        result
    }
}

fn is_retryable_error(err: &ConnectError) -> bool {
    matches!(
        err.code,
        ErrorCode::Aborted
            | ErrorCode::ResourceExhausted
            | ErrorCode::Unavailable
            | ErrorCode::Unknown
            // Retrying `internal` is a trade-off: proxies and load balancers sometimes surface
            // transient faults this way; idempotent reads use a small attempt budget so we do not
            // spin forever. Prefer interpreting `google.rpc.RetryInfo` when present (see
            // `retry_delay_for_error`).
            | ErrorCode::Internal
    )
}

fn retry_delay_for_error(
    err: &ConnectError,
    attempt: usize,
    retry_config: RetryConfig,
) -> Duration {
    if let Ok(decoded) = proto_decode_connect_error(err) {
        if let Some(retry_info) = decoded.retry_info {
            if let Some(delay) = retry_info.retry_delay.as_option() {
                let secs = u64::try_from(delay.seconds).unwrap_or(0);
                let nanos = u32::try_from(delay.nanos.max(0)).unwrap_or(0);
                let hinted = Duration::new(secs, nanos);
                if !hinted.is_zero() {
                    return hinted.min(retry_config.max_backoff);
                }
            }
        }
    }
    retry_backoff_delay(attempt, retry_config)
}

fn retry_backoff_delay(attempt: usize, retry_config: RetryConfig) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = retry_config.initial_backoff.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(retry_config.max_backoff.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv_codec::{KvFieldKind, KvPredicate, KvPredicateCheck, KvPredicateConstraint};
    use buffa::Message as _;
    use exoware_proto::query::TraversalMode as ProtoTraversalMode;
    use http::header::{ACCEPT_ENCODING, AUTHORIZATION};

    #[derive(Clone, Debug, Default)]
    struct RecordingTransport {
        requests: Arc<std::sync::Mutex<Vec<(http::Uri, http::HeaderMap)>>>,
    }

    impl RecordingTransport {
        fn requests(&self) -> Vec<(http::Uri, http::HeaderMap)> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl connectrpc::client::ClientTransport for RecordingTransport {
        type ResponseBody =
            http_body_util::combinators::UnsyncBoxBody<Bytes, std::convert::Infallible>;
        type Error = ConnectError;

        fn send(
            &self,
            request: http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<http::Response<Self::ResponseBody>, Self::Error>,
        > {
            self.requests
                .lock()
                .unwrap()
                .push((request.uri().clone(), request.headers().clone()));
            Box::pin(async { Err(ConnectError::unavailable("recorded test request")) })
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct StalledStreamTransport;

    impl connectrpc::client::ClientTransport for StalledStreamTransport {
        type ResponseBody =
            http_body_util::combinators::UnsyncBoxBody<Bytes, std::convert::Infallible>;
        type Error = ConnectError;

        fn send(
            &self,
            _request: http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<http::Response<Self::ResponseBody>, Self::Error>,
        > {
            Box::pin(async {
                let frames = futures::stream::pending::<
                    Result<http_body::Frame<Bytes>, std::convert::Infallible>,
                >();
                let body =
                    http_body_util::BodyExt::boxed_unsync(http_body_util::StreamBody::new(frames));
                Ok(http::Response::new(body))
            })
        }
    }

    #[derive(Clone)]
    struct ReduceTransport {
        bodies: Arc<std::sync::Mutex<std::collections::VecDeque<Bytes>>>,
        requests: Arc<std::sync::Mutex<Vec<proto_query::ReduceRequest>>>,
    }

    impl ReduceTransport {
        fn new(bodies: impl IntoIterator<Item = Bytes>) -> Self {
            Self {
                bodies: Arc::new(std::sync::Mutex::new(bodies.into_iter().collect())),
                requests: Arc::default(),
            }
        }
    }

    impl connectrpc::client::ClientTransport for ReduceTransport {
        type ResponseBody = http_body_util::Full<Bytes>;
        type Error = ConnectError;

        fn send(
            &self,
            request: http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<http::Response<Self::ResponseBody>, Self::Error>,
        > {
            use buffa::Message;
            use http_body_util::BodyExt;

            let transport = self.clone();
            Box::pin(async move {
                assert_eq!(request.uri().path(), "/store.query.v1.Service/Reduce");
                let body = request.into_body().collect().await.unwrap().to_bytes();
                let mut body = bytes::BytesMut::from(body.as_ref());
                let envelope = connectrpc::envelope::Envelope::decode(&mut body)
                    .unwrap()
                    .unwrap();
                assert!(!envelope.is_compressed());
                assert!(body.is_empty());
                let request =
                    proto_query::ReduceRequest::decode_from_slice(&envelope.data).unwrap();
                transport.requests.lock().unwrap().push(request);
                let body = transport
                    .bodies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected retry");
                Ok(http::Response::builder()
                    .header("content-type", "application/connect+proto")
                    .body(http_body_util::Full::new(body))
                    .unwrap())
            })
        }
    }

    type ReduceBodyReceiver = futures::channel::mpsc::UnboundedReceiver<
        Result<http_body::Frame<Bytes>, std::convert::Infallible>,
    >;

    #[derive(Clone)]
    struct PendingReduceTransport {
        receiver: Arc<std::sync::Mutex<Option<ReduceBodyReceiver>>>,
    }

    impl connectrpc::client::ClientTransport for PendingReduceTransport {
        type ResponseBody =
            http_body_util::combinators::UnsyncBoxBody<Bytes, std::convert::Infallible>;
        type Error = ConnectError;

        fn send(
            &self,
            _request: http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<http::Response<Self::ResponseBody>, Self::Error>,
        > {
            use http_body_util::BodyExt;

            let receiver = self.receiver.lock().unwrap().take().unwrap();
            Box::pin(async move {
                Ok(http::Response::builder()
                    .header("content-type", "application/connect+proto")
                    .body(http_body_util::StreamBody::new(receiver).boxed_unsync())
                    .unwrap())
            })
        }
    }

    #[tokio::test]
    async fn reduce_delivers_a_frame_before_eof_and_drop_cancels_the_body() {
        let (sender, receiver) = futures::channel::mpsc::unbounded();
        let transport = PendingReduceTransport {
            receiver: Arc::new(std::sync::Mutex::new(Some(receiver))),
        };
        let client = StoreClient::builder()
            .url("http://query.internal")
            .retry_config(RetryConfig::disabled())
            .client_transport(transport)
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new("tenant/").unwrap());
        use buffa::Message;
        let first =
            connectrpc::envelope::Envelope::data(count_frame(None).encode_to_bytes()).encode();
        sender
            .unbounded_send(Ok(http_body::Frame::data(first)))
            .unwrap();
        let mut stream = client
            .query()
            .range_reduce_stream(
                &Bytes::from_static(b"a"),
                &Bytes::from_static(b"z"),
                &count_request(),
            )
            .await
            .unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().view().results.len(),
            1
        );
        assert!(!sender.is_closed());
        drop(stream);
        assert!(sender.is_closed());
    }

    fn reduce_body(frames: &[proto_query::ReduceResponse], final_status: &[u8]) -> Bytes {
        use buffa::Message;

        let mut body = Vec::new();
        for frame in frames {
            body.extend_from_slice(
                &connectrpc::envelope::Envelope::data(frame.encode_to_bytes()).encode(),
            );
        }
        body.extend_from_slice(
            &connectrpc::envelope::Envelope::end_stream(Bytes::copy_from_slice(final_status))
                .encode(),
        );
        body.into()
    }

    fn count_request() -> DomainRangeReduceRequest {
        DomainRangeReduceRequest {
            reducers: vec![RangeReducerSpec {
                filter: None,
                op: RangeReduceOp::CountAll,
                expr: None,
            }],
            group_by: Vec::new(),
            filter: None,
        }
    }

    fn count_frame(sequence: Option<u64>) -> proto_query::ReduceResponse {
        proto_query::ReduceResponse {
            results: vec![proto_query::RangeReduceResult {
                value: Some(to_proto_reduced_value(KvReducedValue::UInt64(3))).into(),
                ..Default::default()
            }],
            detail: sequence
                .map(|sequence_number| proto_query::Detail {
                    sequence_number,
                    ..Default::default()
                })
                .into(),
            ..Default::default()
        }
    }

    fn reduce_test_client(transport: ReduceTransport) -> PrefixedStoreClient {
        StoreClient::builder()
            .url("http://query.internal")
            .retry_config(RetryConfig {
                max_attempts: 2,
                initial_backoff: Duration::ZERO,
                max_backoff: Duration::ZERO,
            })
            .client_transport(transport)
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new("tenant/").unwrap())
    }

    #[tokio::test]
    async fn reduce_retries_before_first_frame_and_observes_response_details() {
        let transport = ReduceTransport::new([
            reduce_body(
                &[],
                br#"{"error":{"code":"unavailable","message":"retry open"}}"#,
            ),
            reduce_body(&[count_frame(None), count_frame(Some(47))], b"{}"),
            reduce_body(&[count_frame(Some(50))], b"{}"),
        ]);
        let session = reduce_test_client(transport.clone()).create_session();
        let start = Bytes::from_static(b"a");
        let end = Bytes::from_static(b"z");
        let request = count_request();
        let mut stream = session
            .range_reduce_stream(&start, &end, &request)
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().unwrap().len(), 2);
        assert_eq!(session.fixed_sequence(), None);
        assert!(stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .view()
            .detail
            .as_option()
            .is_none());
        assert_eq!(session.fixed_sequence(), None);
        assert_eq!(
            stream
                .next()
                .await
                .unwrap()
                .unwrap()
                .view()
                .detail
                .sequence_number,
            47
        );
        assert_eq!(session.fixed_sequence(), Some(47));
        assert!(stream.next().await.is_none());
        assert_eq!(
            session.range_reduce(&start, &end, &request).await.unwrap(),
            vec![Some(KvReducedValue::UInt64(3))]
        );
        assert_eq!(session.fixed_sequence(), Some(50));
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].min_sequence_number, None);
        assert_eq!(requests[1].min_sequence_number, None);
        assert_eq!(requests[2].min_sequence_number, Some(47));
        assert_eq!(requests[2].start.as_slice(), b"tenant/a");
        assert_eq!(requests[2].end.as_slice(), b"tenant/z");
    }

    #[tokio::test]
    async fn reduce_never_retries_after_a_result_frame() {
        let transport = ReduceTransport::new([reduce_body(
            &[count_frame(None)],
            br#"{"error":{"code":"unavailable","message":"failed after results"}}"#,
        )]);
        let client = reduce_test_client(transport.clone());
        let mut stream = client
            .query()
            .range_reduce_stream(
                &Bytes::from_static(b"a"),
                &Bytes::from_static(b"z"),
                &count_request(),
            )
            .await
            .unwrap();
        assert_eq!(
            stream.next().await.unwrap().unwrap().view().results.len(),
            1
        );
        assert_eq!(
            stream.next().await.unwrap().unwrap_err().rpc_code(),
            Some(ErrorCode::Unavailable)
        );
        assert!(stream.next().await.is_none());
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn scalar_reduce_validates_frame_count_shape_and_final_status() {
        let request = count_request();
        for frames in [
            vec![],
            vec![proto_query::ReduceResponse::default()],
            vec![count_frame(Some(1)), count_frame(Some(1))],
            vec![proto_query::ReduceResponse {
                groups: vec![proto_query::RangeReduceGroup::default()],
                ..count_frame(Some(1))
            }],
        ] {
            let stream = futures::stream::iter(
                frames
                    .into_iter()
                    .map(|frame| Ok(connectrpc::StreamMessage::from_message(&frame))),
            )
            .boxed();
            assert!(matches!(
                scalar_reduce_results(stream, &request).await,
                Err(ClientError::WireFormat(_))
            ));
        }
        let stream = futures::stream::iter([
            Ok(connectrpc::StreamMessage::from_message(&count_frame(Some(
                1,
            )))),
            Err(ClientError::Rpc(Box::new(ConnectError::unavailable(
                "final status",
            )))),
        ])
        .boxed();
        assert_eq!(
            scalar_reduce_results(stream, &request)
                .await
                .unwrap_err()
                .rpc_code(),
            Some(ErrorCode::Unavailable)
        );
    }

    #[derive(Clone, Debug, Default)]
    struct SessionSequenceTransport {
        requested_floors: Arc<std::sync::Mutex<Vec<Option<u64>>>>,
    }

    impl connectrpc::client::ClientTransport for SessionSequenceTransport {
        type ResponseBody =
            http_body_util::combinators::UnsyncBoxBody<Bytes, std::convert::Infallible>;
        type Error = ConnectError;

        fn send(
            &self,
            request: http::Request<connectrpc::client::ClientBody>,
        ) -> connectrpc::client::BoxFuture<
            'static,
            Result<http::Response<Self::ResponseBody>, Self::Error>,
        > {
            let requested_floors = self.requested_floors.clone();
            Box::pin(async move {
                let (parts, body) = request.into_parts();
                let body = http_body_util::BodyExt::collect(body)
                    .await
                    .unwrap()
                    .to_bytes();
                let path = parts.uri.path();
                let streaming = path.ends_with("/GetMany")
                    || path.ends_with("/Range")
                    || path.ends_with("/Reduce");
                let payload = if streaming { &body[5..] } else { &body[..] };
                let requested_floor = match path {
                    "/store.query.v1.Service/Get" => {
                        proto_query::GetRequest::decode_from_slice(payload)
                            .unwrap()
                            .min_sequence_number
                    }
                    "/store.query.v1.Service/GetMany" => {
                        proto_query::GetManyRequest::decode_from_slice(payload)
                            .unwrap()
                            .min_sequence_number
                    }
                    "/store.query.v1.Service/Range" => {
                        proto_query::RangeRequest::decode_from_slice(payload)
                            .unwrap()
                            .min_sequence_number
                    }
                    "/store.query.v1.Service/Reduce" => {
                        proto_query::ReduceRequest::decode_from_slice(payload)
                            .unwrap()
                            .min_sequence_number
                    }
                    path => {
                        return Err(ConnectError::unimplemented(format!(
                            "unexpected test request path {path}"
                        )));
                    }
                };
                let sequence_number = {
                    let mut floors = requested_floors.lock().unwrap();
                    floors.push(requested_floor);
                    40 + u64::try_from(floors.len()).unwrap()
                };
                let detail = proto_query::Detail {
                    sequence_number,
                    ..Default::default()
                };
                let payload = match path {
                    "/store.query.v1.Service/Get" => proto_query::GetResponse {
                        detail: detail.into(),
                        ..Default::default()
                    }
                    .encode_to_bytes(),
                    "/store.query.v1.Service/GetMany" => proto_query::GetManyFrame {
                        detail: detail.into(),
                        ..Default::default()
                    }
                    .encode_to_bytes(),
                    "/store.query.v1.Service/Range" => proto_query::RangeFrame {
                        detail: detail.into(),
                        ..Default::default()
                    }
                    .encode_to_bytes(),
                    "/store.query.v1.Service/Reduce" => {
                        count_frame(Some(sequence_number)).encode_to_bytes()
                    }
                    _ => unreachable!(),
                };
                let (body, content_type) = if streaming {
                    let mut envelope = Vec::with_capacity(payload.len() + 12);
                    envelope.push(0);
                    envelope
                        .extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
                    envelope.extend_from_slice(&payload);
                    envelope.extend_from_slice(&[2, 0, 0, 0, 2, b'{', b'}']);
                    (Bytes::from(envelope), "application/connect+proto")
                } else {
                    (payload, "application/proto")
                };
                let body = http_body_util::BodyExt::boxed_unsync(http_body_util::Full::new(body));
                Ok(http::Response::builder()
                    .header(http::header::CONTENT_TYPE, content_type)
                    .body(body)
                    .unwrap())
            })
        }
    }

    async fn assert_streaming_deadline<T>(
        future: impl std::future::Future<Output = Result<T, ClientError>>,
    ) {
        let result = tokio::time::timeout(Duration::from_secs(1), future)
            .await
            .expect("stream open did not honor the request timeout");
        assert_eq!(
            result.err().and_then(|err| err.rpc_code()),
            Some(ErrorCode::DeadlineExceeded)
        );
    }

    #[test]
    fn hex_round_trip() {
        let data = vec![0x00, 0x42, 0xFF, 0xAB];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "0042ffab");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn client_creation() {
        let client = StoreClient::new("http://localhost:10000");
        assert_eq!(client.health_url, "http://localhost:10000");
        assert_eq!(client.ingest_uri.to_string(), "http://localhost:10000/");
        assert_eq!(client.query_uri.to_string(), "http://localhost:10000/");
        assert_eq!(client.stream_uri.to_string(), "http://localhost:10000/");
    }

    #[test]
    fn an_explicit_key_records_that_one_will_be_sent() {
        assert_eq!(built_with_api_key("token").credential, Credential::Sent);
    }

    #[test]
    fn client_creation_enables_tls_for_https() {
        let client = StoreClient::new("https://store.example.com");
        assert_eq!(client.health_url, "https://store.example.com");
        assert_eq!(client.ingest_uri.to_string(), "https://store.example.com/");
        assert_eq!(client.query_uri.to_string(), "https://store.example.com/");
        assert_eq!(client.stream_uri.to_string(), "https://store.example.com/");
    }

    #[test]
    fn builder_supports_mixed_http_and_https_services() {
        let client = StoreClient::builder()
            .health_url("https://health.example.com")
            .ingest_url("http://ingest.internal")
            .query_url("https://query.example.com")
            .prune_url("http://prune.internal")
            .retention_url("http://retention.internal")
            .stream_url("https://stream.example.com")
            .build()
            .unwrap();

        assert_eq!(client.ingest_uri.scheme_str(), Some("http"));
        assert_eq!(client.query_uri.scheme_str(), Some("https"));
        assert_eq!(client.prune_uri.scheme_str(), Some("http"));
        assert_eq!(client.retention_uri.scheme_str(), Some("http"));
        assert_eq!(client.stream_uri.scheme_str(), Some("https"));
    }

    #[test]
    fn builder_rejects_non_http_connect_urls() {
        for url in ["store.example.com", "ftp://store.example.com", "/relative"] {
            assert!(matches!(
                StoreClient::builder().url(url).build(),
                Err(ClientBuildError::InvalidEndpointUrl { .. })
            ));
        }
    }

    #[tokio::test]
    async fn custom_transport_keeps_high_level_features_and_split_origins() {
        let transport = RecordingTransport::default();
        let client = StoreClient::builder()
            .health_url("http://health.internal")
            .ingest_url("http://ingest.internal/base")
            .query_url("http://query.internal/base")
            .prune_url("http://prune.internal/base")
            .retention_url("http://retention.internal/base")
            .stream_url("http://stream.internal/base")
            .api_key("token-abc")
            .retry_config(RetryConfig::disabled())
            .client_transport(transport.clone())
            .build()
            .unwrap();
        let prefixed = client.prefixed(StoreKeyPrefix::new("tenant/").unwrap());

        let _ = prefixed.put(&[]).await;
        let _ = prefixed
            .create_session()
            .get(&Bytes::from_static(b"key"))
            .await;
        let _ = prefixed.client().prune(&[]).await;
        let _ = prefixed.client().set_retention(None).await;
        let _ = prefixed.client().stream_get_physical(1).await;

        let requests = transport.requests();
        let origins = requests
            .iter()
            .map(|(uri, _)| uri.authority().unwrap().as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            origins,
            [
                "ingest.internal",
                "query.internal",
                "prune.internal",
                "retention.internal",
                "stream.internal",
            ]
        );
        for (_, headers) in requests {
            assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer token-abc");
            assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "zstd, gzip");
        }
    }

    #[tokio::test]
    async fn generated_reduce_stream_prefers_zstd() {
        let transport = RecordingTransport::default();
        let client = StoreClient::builder()
            .url("http://query.internal")
            .retry_config(RetryConfig::disabled())
            .client_transport(transport.clone())
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::identity());

        let _ = client
            .query()
            .range_reduce_stream(
                &Bytes::from_static(b"a"),
                &Bytes::from_static(b"z"),
                &count_request(),
            )
            .await;

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        let (uri, headers) = &requests[0];
        assert_eq!(uri.path(), "/store.query.v1.Service/Reduce");
        assert_eq!(
            headers.get("content-type").unwrap(),
            "application/connect+proto"
        );
        assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "zstd, gzip");
        let stream_encoding = connectrpc::Protocol::Connect.accept_encoding_header();
        assert_eq!(headers.get(stream_encoding).unwrap(), "zstd, gzip");
        assert_eq!(headers.get_all(stream_encoding).iter().count(), 1);
    }

    #[tokio::test]
    async fn streaming_timeout_includes_first_frame_prefetch() {
        let mut client = StoreClient::builder()
            .url("http://query.internal")
            .retry_config(RetryConfig::disabled())
            .client_transport(StalledStreamTransport)
            .build()
            .unwrap();
        client.rpc_timeout = Some(Duration::from_millis(25));
        let client = client.prefixed(StoreKeyPrefix::new("timeout/").unwrap());
        let key = Key::from(b"key".to_vec());
        let start = Key::from(b"a".to_vec());
        let end = Key::from(b"z".to_vec());

        assert_streaming_deadline(client.get_many(&[&key], 1)).await;
        assert_streaming_deadline(client.range_stream(&start, &end, 1, 1)).await;
        assert_streaming_deadline(client.query().range_reduce_stream(
            &start,
            &end,
            &count_request(),
        ))
        .await;
    }

    #[tokio::test]
    async fn session_stream_prefetch_records_sequence_before_returning() {
        let client = StoreClient::builder()
            .url("http://query.internal")
            .retry_config(RetryConfig::disabled())
            .client_transport(SessionSequenceTransport::default())
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new("prefetch/").unwrap());
        let key = Key::from(b"key".to_vec());
        let start = Key::from(b"a".to_vec());
        let end = Key::from(b"z".to_vec());

        let get_many_session = client.create_session();
        let _stream = get_many_session.get_many(&[&key], 1).await.unwrap();
        assert_eq!(get_many_session.fixed_sequence(), Some(41));
        assert_eq!(get_many_session.evaluated_sequence(), Some(41));

        let range_session = client.create_session();
        let _stream = range_session
            .range_stream(&start, &end, 1, 1)
            .await
            .unwrap();
        assert_eq!(range_session.fixed_sequence(), Some(42));
        assert_eq!(range_session.evaluated_sequence(), Some(42));

        let reduce_session = client.create_session();
        let _stream = reduce_session
            .range_reduce_stream(&start, &end, &count_request())
            .await
            .unwrap();
        assert_eq!(reduce_session.fixed_sequence(), Some(43));
        assert_eq!(reduce_session.evaluated_sequence(), Some(43));
    }

    #[tokio::test]
    async fn session_reads_advance_the_floor_across_all_read_methods() {
        for initial_sequence in [0, 27] {
            let transport = SessionSequenceTransport::default();
            let client = StoreClient::builder()
                .url("http://query.internal")
                .retry_config(RetryConfig::disabled())
                .client_transport(transport.clone())
                .build()
                .unwrap()
                .prefixed(StoreKeyPrefix::new("session/").unwrap());
            let session = client.create_session_with_sequence(initial_sequence);
            let shared_session = session.clone();
            let key = Key::from(b"key".to_vec());
            let start = Key::from(b"a".to_vec());
            let end = Key::from(b"z".to_vec());
            let reduction = count_request();

            assert_eq!(session.evaluated_sequence(), None);
            assert_eq!(session.get(&key).await.unwrap(), None);
            assert_eq!(session.evaluated_sequence(), Some(41));
            shared_session.get_many(&[&key], 1).await.unwrap();
            assert_eq!(session.evaluated_sequence(), Some(42));
            session.range_stream(&start, &end, 1, 1).await.unwrap();
            assert_eq!(session.evaluated_sequence(), Some(43));
            session.range(&start, &end, 1).await.unwrap();
            assert_eq!(session.evaluated_sequence(), Some(44));
            session
                .range_reduce(&start, &end, &reduction)
                .await
                .unwrap();
            assert_eq!(session.evaluated_sequence(), Some(45));
            let _stream = session
                .range_reduce_stream(&start, &end, &reduction)
                .await
                .unwrap();

            assert_eq!(session.fixed_sequence(), Some(46));
            assert_eq!(shared_session.evaluated_sequence(), Some(46));
            assert_eq!(
                *transport.requested_floors.lock().unwrap(),
                vec![
                    (initial_sequence > 0).then_some(initial_sequence),
                    Some(41),
                    Some(42),
                    Some(43),
                    Some(44),
                    Some(45),
                ]
            );
        }
    }

    #[test]
    fn public_streams_remain_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<RangeStream>();
        assert_send_sync::<GetManyStream>();
        assert_send_sync::<StreamSubscription>();
    }

    #[test]
    fn balanced_http2_builder_supports_mixed_service_schemes() {
        let timeout = Duration::from_millis(123);
        let client = StoreClient::builder()
            .health_url("https://health.example.com")
            .ingest_url("http://ingest.internal")
            .query_url("https://query.example.com")
            .prune_url("http://prune.internal")
            .retention_url("http://retention.internal")
            .stream_url("https://stream.example.com")
            .balanced_http2_transport(
                ProtoBalancedHttp2Config::default().with_request_timeout(timeout),
            )
            .build()
            .unwrap();

        assert_eq!(client.ingest_uri.scheme_str(), Some("http"));
        assert_eq!(client.query_uri.scheme_str(), Some("https"));
        assert_eq!(client.rpc_timeout, Some(timeout));
    }

    #[test]
    fn builder_fails_until_all_urls_set() {
        assert!(matches!(
            StoreClient::builder().health_url("http://h").build(),
            Err(ClientBuildError::MissingIngestUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .build(),
            Err(ClientBuildError::MissingQueryUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .build(),
            Err(ClientBuildError::MissingPruneUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .prune_url("http://p")
                .build(),
            Err(ClientBuildError::MissingRetentionUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .prune_url("http://p")
                .retention_url("http://r")
                .build(),
            Err(ClientBuildError::MissingStreamUrl)
        ));
    }

    fn built_with_api_key(key: &str) -> StoreClient {
        StoreClient::builder()
            .url("https://example.test")
            .api_key(key)
            .build()
            .expect("builder should accept this key")
    }

    #[test]
    fn api_key_becomes_a_bearer_header() {
        let client = built_with_api_key("token-abc");
        assert_eq!(client.credential, Credential::Sent);
    }

    #[test]
    fn api_key_is_redacted_in_debug_output() {
        let rendered = format!(
            "{:?}",
            StoreClient::builder()
                .url("https://example.test")
                .api_key("token-abc")
        );

        assert!(!rendered.contains("token-abc"), "builder leaked the key");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn a_bearer_header_never_renders_the_key() {
        let rendered = format!("{client:?}", client = built_with_api_key("token-abc"));

        assert!(!rendered.contains("token-abc"));
    }

    /// Builds with `key` standing in for the environment lookup, so nothing here depends on a
    /// variable another test could be changing. `credential.rs` covers which key wins.
    fn built_with_env_key(key: Option<&str>, unusable_env_key: UnusableEnvKey) -> StoreClient {
        StoreClient::builder()
            .url("https://example.test")
            .build_with(key.map(str::to_string), unusable_env_key)
            .expect("builder should accept this environment key")
    }

    #[test]
    fn no_api_key_sends_no_header() {
        // A deployment with no load balancer in front of it authenticates nothing, so local and
        // in-VPC clients must keep working with no credential configured.
        let client = built_with_env_key(None, UnusableEnvKey::Reject);

        assert_eq!(client.credential, Credential::Absent);
    }

    #[test]
    fn an_environment_key_reaches_the_transport() {
        let client = built_with_env_key(Some("from-env"), UnusableEnvKey::Reject);

        assert_eq!(client.credential, Credential::Sent);
    }

    #[test]
    fn a_key_that_cannot_be_a_header_fails_the_build() {
        assert!(matches!(
            StoreClient::builder()
                .url("https://example.test")
                .api_key("has\nnewline")
                .build(),
            Err(ClientBuildError::InvalidApiKey)
        ));
    }

    /// The infallible constructors would have to panic, so they build a client that carries no
    /// credential and says why when a request is rejected.
    #[test]
    fn a_tolerated_unusable_key_yields_a_client_that_explains_itself() {
        let client = built_with_env_key(Some("has\nnewline"), UnusableEnvKey::Tolerate);
        assert_eq!(client.credential, Credential::Unusable);

        let rendered = client_error_from_connect(
            ConnectError::new(ErrorCode::Unauthenticated, "HTTP error 401"),
            client.credential,
        )
        .to_string();
        assert!(rendered.contains(API_KEY_ENV), "{rendered}");
        assert!(rendered.contains("cannot be an HTTP header"), "{rendered}");
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.health_url, "http://localhost:10000");
    }

    #[test]
    fn create_session_starts_unseeded() {
        let client = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000/"));
        let session = client.create_session();
        assert_eq!(session.fixed_sequence(), None);
        assert_eq!(session.evaluated_sequence(), None);
    }

    #[test]
    fn range_mode_maps_to_proto_traversal() {
        assert_eq!(
            RangeMode::Forward.to_proto(),
            ProtoTraversalMode::TRAVERSAL_MODE_FORWARD
        );
        assert_eq!(
            RangeMode::Reverse.to_proto(),
            ProtoTraversalMode::TRAVERSAL_MODE_REVERSE
        );
    }

    #[test]
    fn retry_config_standard_defaults_match_expected() {
        let config = RetryConfig::standard();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
        assert_eq!(config.max_backoff, Duration::from_millis(2_000));
    }

    #[test]
    fn retry_config_clamps_attempts_and_backoff_bounds() {
        let config = RetryConfig::standard()
            .with_max_attempts(0)
            .with_initial_backoff(Duration::from_millis(250))
            .with_max_backoff(Duration::from_millis(50))
            .sanitized();
        assert_eq!(config.max_attempts, 1);
        assert_eq!(config.initial_backoff, Duration::from_millis(250));
        assert_eq!(config.max_backoff, Duration::from_millis(250));
    }

    #[test]
    fn retryable_codes_include_connect_transients() {
        assert!(is_retryable_error(&ConnectError::aborted("retry")));
        assert!(is_retryable_error(&ConnectError::resource_exhausted(
            "retry"
        )));
        assert!(is_retryable_error(&ConnectError::unavailable("retry")));
        assert!(is_retryable_error(&ConnectError::internal("retry")));
        assert!(!is_retryable_error(&ConnectError::invalid_argument(
            "no retry"
        )));
    }

    #[test]
    fn retry_backoff_delay_is_exponential_and_capped() {
        let config = RetryConfig::standard()
            .with_initial_backoff(Duration::from_millis(100))
            .with_max_backoff(Duration::from_millis(250));
        assert_eq!(retry_backoff_delay(1, config), Duration::from_millis(100));
        assert_eq!(retry_backoff_delay(2, config), Duration::from_millis(200));
        assert_eq!(retry_backoff_delay(3, config), Duration::from_millis(250));
        assert_eq!(retry_backoff_delay(4, config), Duration::from_millis(250));
    }

    #[test]
    fn create_session_with_sequence_pins_explicit_floor() {
        let client = PrefixedStoreClient::empty(StoreClient::new("http://localhost:10000/"));
        let session = client.create_session_with_sequence(27);
        assert_eq!(session.fixed_sequence(), Some(27));
        assert_eq!(session.evaluated_sequence(), None);
    }

    #[test]
    fn store_key_prefix_round_trips_logical_keys() {
        let prefix = StoreKeyPrefix::new(vec![0x0A]).unwrap();
        let logical = Bytes::from_static(b"hello");
        let physical = prefix.encode_key(&logical).unwrap();
        assert!(prefix.matches(&physical));
        assert_eq!(prefix.decode_key(&physical).unwrap(), logical);
    }

    #[test]
    fn store_key_prefix_next_key_respects_namespace_capacity() {
        for prefix in [
            StoreKeyPrefix::identity(),
            StoreKeyPrefix::new(Bytes::from_static(b"tenant/")).unwrap(),
        ] {
            assert_eq!(
                prefix.next_key(&Bytes::from_static(b"row")).unwrap(),
                Some(Bytes::from_static(b"row\0")),
            );
            let capacity = prefix.max_logical_key_len();
            let mut key = vec![0; capacity];
            key[capacity - 2] = 0x12;
            key[capacity - 1] = 0xFF;
            let next = prefix.next_key(&Bytes::from(key)).unwrap().unwrap();
            assert_eq!(next.len(), capacity - 1);
            assert_eq!(next[capacity - 2], 0x13);
            assert!(prefix.encode_key(&next).is_ok());
            assert_eq!(
                prefix.next_key(&Bytes::from(vec![0xFF; capacity])).unwrap(),
                None,
            );
            assert!(prefix
                .next_key(&Bytes::from(vec![0; capacity + 1]))
                .is_err());
        }
        let prefix = StoreKeyPrefix::new(vec![0; MAX_KEY_LEN]).unwrap();
        assert_eq!(prefix.next_key(&Bytes::new()).unwrap(), None);
    }

    #[test]
    fn identity_prefix_encode_decode_are_zero_copy() {
        let prefix = StoreKeyPrefix::identity();
        let logical = Bytes::from_static(b"passthrough-key");
        let physical = prefix.encode_key(&logical).unwrap();
        // The identity prefix copies no key bytes: encode/decode share backing.
        assert_eq!(physical.as_ptr(), logical.as_ptr());
        let decoded = prefix.decode_key(&physical).unwrap();
        assert_eq!(decoded.as_ptr(), logical.as_ptr());
        assert_eq!(decoded, logical);
    }

    #[test]
    fn uniform_width_prefixes_are_pairwise_disjoint() {
        // Six leaf prefixes sharing one uniform (1-byte) width.
        let all = [
            StoreKeyPrefix::new(vec![0]).unwrap(),
            StoreKeyPrefix::new(vec![1]).unwrap(),
            StoreKeyPrefix::new(vec![2]).unwrap(),
            StoreKeyPrefix::new(vec![3]).unwrap(),
            StoreKeyPrefix::new(vec![4]).unwrap(),
            StoreKeyPrefix::new(vec![5]).unwrap(),
        ];
        // A key encoded under one prefix never matches another's prefix, so a
        // prefix-bounded range scan in one can't observe another's keys (this is
        // the bug being fixed). Same-length prefixes are pairwise disjoint.
        let logical = Bytes::from_static(b"\x00\x10whatever-block-meta-or-op-log-key");
        for (i, pa) in all.iter().enumerate() {
            let physical = pa.encode_key(&logical).unwrap();
            assert!(pa.matches(&physical));
            assert_eq!(pa.decode_key(&physical).unwrap(), logical);
            for (j, pb) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !pb.matches(&physical),
                    "prefix {j} matched a key encoded under prefix {i}",
                );
            }
        }
    }

    #[test]
    fn prefixed_store_client_always_carries_its_prefix() {
        let base = StoreClient::new("http://localhost:8090");
        let prefix = StoreKeyPrefix::new(vec![0]).unwrap();
        let client = base.prefixed(prefix.clone());
        assert_eq!(client.key_prefix(), &prefix);
        // The logical client encodes through its prefix.
        let logical = Bytes::from_static(b"row");
        assert_eq!(
            client.encode_store_key(&logical).unwrap(),
            prefix.encode_key(&logical).unwrap(),
        );
    }

    #[test]
    fn store_key_prefix_clamps_long_logical_range_upper_bound() {
        let prefix = StoreKeyPrefix::new(vec![0x02]).unwrap();
        // A full-width logical upper bound (MAX_KEY_LEN bytes of 0xFF), as an
        // un-prefixed scan's inclusive end would be.
        let logical_start = Bytes::new();
        let logical_end = Bytes::from(vec![0xFFu8; MAX_KEY_LEN]);
        assert_eq!(logical_end.len(), MAX_KEY_LEN);

        let (physical_start, physical_end) =
            prefix.encode_range(&logical_start, &logical_end).unwrap();
        assert!(prefix.matches(&physical_start));
        assert!(prefix.matches(&physical_end));
        // The logical end clamps to max_logical_key_len (253) before prefixing,
        // so the physical end is exactly MAX_KEY_LEN bytes.
        assert_eq!(prefix.max_logical_key_len(), MAX_KEY_LEN - 1);
        assert_eq!(physical_end.len(), MAX_KEY_LEN);
        assert_eq!(prefix.decode_key(&physical_start).unwrap(), logical_start);
    }

    #[test]
    fn store_key_prefix_rewrites_selector_family() {
        let prefix = StoreKeyPrefix::new(vec![0x05]).unwrap();
        let logical = crate::selector::Selector {
            prefix: Bytes::copy_from_slice(&[0x06]),
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };
        let physical = prefix.prefix_selector(&logical).unwrap();
        assert_eq!(physical.prefix.as_ref(), &[0x05, 0x06]);
        assert_eq!(physical.payload_regex, logical.payload_regex);
    }

    #[test]
    fn store_key_prefix_composed_selector_reconstructs_and_strips_cleanly() {
        // Reproduces the selector-merge -> reconstruct-codec path that the old
        // bit-padding KeyCodec corrupted: a store namespace prefix is composed
        // onto a logical selector's prefix, and then a codec is rebuilt FROM the
        // merged selector prefix and used to strip keys. Under the old bit-packed
        // codec, composing two sub-byte prefixes and reconstructing a codec left a
        // spurious trailing 0x00 in the stripped payload; the byte-prefix design
        // must strip cleanly.

        // Multi-byte store namespace so the payload offset shift (= prefix length)
        // is genuinely exercised.
        let prefix = StoreKeyPrefix::new(vec![0x05, 0x06]).unwrap();
        let logical = crate::selector::Selector {
            prefix: Bytes::copy_from_slice(&[0x07]),
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };

        // Compose via the real SDK merge path (byte-concatenates the store prefix
        // onto the selector prefix).
        let merged = prefix.prefix_selector(&logical).unwrap();
        assert_eq!(merged.prefix.as_ref(), &[0x05, 0x06, 0x07]);

        // Reconstruct the codec EXACTLY as apply_key_prune_policy does.
        let codec = Prefix::new(merged.prefix.clone()).unwrap();

        // Round-trip a real key through the reconstructed codec.
        let payload = [0xAA, 0xBB, 0xCC];
        let key = codec.encode(&payload).unwrap();
        assert_eq!(key.as_ref(), &[0x05, 0x06, 0x07, 0xAA, 0xBB, 0xCC]);
        assert!(codec.matches(&key));
        // The assertion the old codec would fail: the stripped payload is exactly
        // the original bytes, with no trailing spurious 0x00 from 8-bit padding.
        assert_eq!(
            codec.strip(&key).unwrap(),
            Bytes::copy_from_slice(&[0xAA, 0xBB, 0xCC])
        );

        // The scan bounds bracket the key. bounds() are inclusive on both ends:
        // start is the bare prefix, end is the prefix padded with 0xFF.
        let (start, end) = codec.bounds();
        assert!(start <= key && key <= end);

        // A key under a DIFFERENT merged prefix must not match this codec.
        let sibling = Prefix::new(vec![0x05, 0x06, 0x08])
            .unwrap()
            .encode(&[0x11])
            .unwrap();
        assert!(!codec.matches(&sibling));
    }

    #[test]
    fn store_key_prefix_stream_filter_passes_payload_regex_through() {
        // The stream path no longer broadens the payload regex: byte-aligned
        // payloads let the server apply the caller's real regex to the
        // post-prefix payload, so it must pass through unchanged.
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new(vec![0x05]).unwrap());
        let filter = crate::stream_filter::StreamFilter {
            selectors: vec![crate::selector::Selector {
                prefix: Bytes::copy_from_slice(&[0x06]),
                payload_regex: crate::kv_codec::Utf8::from("(?s)foo.*"),
            }],
            value_filters: vec![],
        };
        let physical = client.prefix_stream_filter(filter.clone()).unwrap();
        assert_eq!(physical.selectors[0].prefix.as_ref(), &[0x05, 0x06]);
        assert_eq!(
            physical.selectors[0].payload_regex,
            filter.selectors[0].payload_regex
        );
    }

    #[test]
    fn prefixed_reduce_request_shifts_nested_cast_fields() {
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new(vec![1, 2, 3]).unwrap());
        let request_at = |byte_offset, bit_offset| DomainRangeReduceRequest {
            reducers: vec![crate::RangeReducerSpec {
                op: crate::RangeReduceOp::SumField,
                expr: Some(KvExpr::CastFloat64(Box::new(KvExpr::Add(
                    Box::new(KvExpr::Field(KvFieldRef::Key {
                        byte_offset,
                        kind: KvFieldKind::Int64,
                    })),
                    Box::new(KvExpr::CastFloat64(Box::new(KvExpr::Field(
                        KvFieldRef::Value {
                            index: 2,
                            kind: KvFieldKind::UInt64,
                            nullable: true,
                        },
                    )))),
                )))),
                filter: None,
            }],
            group_by: vec![KvExpr::CastFloat64(Box::new(KvExpr::Field(
                KvFieldRef::ZOrderKey {
                    bit_offset,
                    field_position: 0,
                    field_widths: vec![8],
                    kind: KvFieldKind::UInt64,
                },
            )))],
            filter: None,
        };
        let request = request_at(9, 12);
        assert_eq!(
            client.prefix_reduce_request(&request).unwrap(),
            request_at(12, 36)
        );
        assert_eq!(request, request_at(9, 12));
    }

    #[test]
    fn prefixed_reduce_request_shifts_key_field_offsets() {
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .build()
            .unwrap()
            .prefixed(StoreKeyPrefix::new(vec![0x01, 0x02, 0x03]).unwrap());
        let request = DomainRangeReduceRequest {
            reducers: vec![crate::RangeReducerSpec {
                filter: Some(KvPredicate {
                    checks: vec![
                        KvPredicateCheck {
                            field: KvFieldRef::Key {
                                byte_offset: 9,
                                kind: KvFieldKind::UInt64,
                            },
                            constraint: KvPredicateConstraint::IsNotNull,
                        },
                        KvPredicateCheck {
                            field: KvFieldRef::ZOrderKey {
                                bit_offset: 12,
                                field_position: 0,
                                field_widths: vec![8],
                                kind: KvFieldKind::UInt64,
                            },
                            constraint: KvPredicateConstraint::IsNotNull,
                        },
                        KvPredicateCheck {
                            field: KvFieldRef::Value {
                                index: 2,
                                kind: KvFieldKind::UInt64,
                                nullable: true,
                            },
                            constraint: KvPredicateConstraint::IsNotNull,
                        },
                    ],
                    contradiction: false,
                }),
                op: crate::RangeReduceOp::SumField,
                expr: Some(KvExpr::Field(KvFieldRef::Key {
                    byte_offset: 9,
                    kind: KvFieldKind::UInt64,
                })),
            }],
            group_by: vec![KvExpr::Field(KvFieldRef::ZOrderKey {
                bit_offset: 12,
                field_position: 0,
                field_widths: vec![8],
                kind: KvFieldKind::UInt64,
            })],
            filter: Some(KvPredicate {
                checks: vec![KvPredicateCheck {
                    field: KvFieldRef::Value {
                        index: 0,
                        kind: KvFieldKind::UInt64,
                        nullable: false,
                    },
                    constraint: KvPredicateConstraint::UInt64Range {
                        min: Some(1),
                        max: Some(9),
                    },
                }],
                contradiction: false,
            }),
        };

        let shifted = client.prefix_reduce_request(&request).unwrap();
        let Some(KvExpr::Field(KvFieldRef::Key { byte_offset, .. })) =
            shifted.reducers[0].expr.as_ref()
        else {
            panic!("expected key field reducer");
        };
        // KeyField offsets are byte-granular: a 3-byte prefix shifts by 3 bytes,
        // so 9 -> 12.
        assert_eq!(*byte_offset, 12);
        let KvExpr::Field(KvFieldRef::ZOrderKey { bit_offset, .. }) = &shifted.group_by[0] else {
            panic!("expected z-order group field");
        };
        // Z-order offsets stay bit-granular: a 3-byte prefix shifts by 3*8 = 24
        // bits, so 12 -> 36.
        assert_eq!(*bit_offset, 36);
        let checks = &shifted.reducers[0].filter.as_ref().unwrap().checks;
        assert_eq!(
            checks[0].field,
            KvFieldRef::Key {
                byte_offset: 12,
                kind: KvFieldKind::UInt64,
            }
        );
        assert_eq!(
            checks[1].field,
            KvFieldRef::ZOrderKey {
                bit_offset: 36,
                field_position: 0,
                field_widths: vec![8],
                kind: KvFieldKind::UInt64,
            }
        );
        let original_checks = &request.reducers[0].filter.as_ref().unwrap().checks;
        assert_eq!(checks[2], original_checks[2]);
        assert_eq!(shifted.filter, request.filter);
        assert_eq!(
            original_checks[0].field,
            KvFieldRef::Key {
                byte_offset: 9,
                kind: KvFieldKind::UInt64,
            }
        );
    }

    #[test]
    fn store_write_batch_uses_each_clients_prefix() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let b = base.prefixed(StoreKeyPrefix::new(vec![2]).unwrap());
        let key_a = Bytes::from_static(b"a");
        let key_b = Bytes::from_static(b"b");

        let mut batch = StoreWriteBatch::new();
        batch.push(&a, &key_a, b"va").unwrap();
        batch.push(&b, &key_b, b"vb").unwrap();

        assert_eq!(
            batch.entries[0].0,
            a.key_prefix().encode_key(&key_a).unwrap()
        );
        assert_eq!(
            batch.entries[1].0,
            b.key_prefix().encode_key(&key_b).unwrap()
        );
    }

    #[test]
    fn pushed_rows_round_trip_only_through_their_own_client() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let b = base.prefixed(StoreKeyPrefix::new(vec![2]).unwrap());
        let key = Bytes::from_static(b"shared-logical-key");

        let mut batch = StoreWriteBatch::new();
        batch.push(&a, &key, b"va").unwrap();
        batch.push(&b, &key, b"vb").unwrap();

        // The same logical key staged through two namespaces produces two
        // distinct physical rows, in staging order.
        let entries = batch.entries();
        assert_eq!(entries.len(), 2);
        assert_ne!(entries[0].0, entries[1].0);

        // Each physical key decodes back through its own namespace and is
        // rejected by the other.
        assert_eq!(a.decode_store_key(&entries[0].0).unwrap(), key);
        assert_eq!(b.decode_store_key(&entries[1].0).unwrap(), key);
        assert!(a.decode_store_key(&entries[1].0).is_err());
        assert!(b.decode_store_key(&entries[0].0).is_err());
    }

    #[test]
    fn identity_prefix_stages_keys_verbatim() {
        let base = StoreClient::new("http://localhost:10000");
        let plain = PrefixedStoreClient::empty(base);
        let key = Bytes::from_static(b"raw-key");

        let mut batch = StoreWriteBatch::new();
        batch.push(&plain, &key, b"v").unwrap();

        assert_eq!(batch.entries()[0].0, key);
    }

    #[test]
    fn push_rejects_keys_exceeding_prefixed_capacity() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.prefixed(StoreKeyPrefix::new(vec![1]).unwrap());
        let max = a.key_prefix().max_logical_key_len();

        let mut batch = StoreWriteBatch::new();
        let at_capacity = Key::from(vec![7u8; max]);
        batch.push(&a, &at_capacity, b"v").unwrap();

        let oversize = Key::from(vec![7u8; max + 1]);
        assert!(batch.push(&a, &oversize, b"v").is_err());
        assert_eq!(batch.len(), 1);
    }

    fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }
}
