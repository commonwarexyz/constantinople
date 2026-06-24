//! Store Rust SDK Client.
//!
//! Provides typed access to the store put/get/query APIs plus
//! plain HTTP health/readiness probes.
//!
//! ## Errors
//!
//! RPC failures surface as [`ClientError::Rpc`] carrying a native [`ConnectError`]. Use
//! [`ClientError::decoded_rpc_error`] or [`StoreClient::decode_error_details`] to unpack
//! protobuf `google.rpc` details (and `store.query.v1.Detail` on query RPC errors), not string parsing.
//! Idempotent reads honor `google.rpc.RetryInfo` when deciding backoff (see `retry_delay_for_error`).

pub mod keys;
pub mod kv_codec;
pub mod match_key;
pub mod proto;
pub mod prune_policy;
pub mod stream_filter;
pub use keys::{Key, KeyCodec, KeyCodecError, KeyMut, KeyValidationError, Value, MAX_KEY_LEN};
pub use proto::*;
extern crate self as exoware_proto;

use bytes::Bytes;
use connectrpc::client::{ClientConfig, ServerStream as ConnectServerStream};
use connectrpc::{ConnectError, ErrorCode};
use exoware_proto::compact::ServiceClient as CompactServiceClient;
use exoware_proto::ingest::ServiceClient as IngestServiceClient;
use exoware_proto::query as proto_query;
use exoware_proto::query::ServiceClient as QueryServiceClient;
use exoware_proto::store::compact::v1::PruneRequest as ProtoPruneRequest;
use exoware_proto::store::ingest::v1::PutRequest as ProtoPutRequest;
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
use keys::is_valid_key_size;
use kv_codec::{KvExpr, KvFieldRef, KvReducedValue};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

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
) -> ClientConfig {
    let config = ClientConfig::new(base_uri)
        .with_compression(proto_connect_compression_registry())
        .with_default_max_message_size(STORE_CLIENT_MAX_MESSAGE_BYTES);
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
    KeyPrefix(#[from] StoreKeyPrefixError),
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
    #[error("reserved_bits {reserved_bits} exceeds 16")]
    ReservedBitsTooLarge { reserved_bits: u8 },
    #[error("prefix {prefix} does not fit in {reserved_bits} reserved bits")]
    PrefixTooLarge { reserved_bits: u8, prefix: u16 },
    #[error(
        "combined reserved bits exceed 16: store prefix bits {prefix_bits} + logical bits {logical_bits}"
    )]
    CombinedReservedBitsTooLarge { prefix_bits: u8, logical_bits: u8 },
    #[error("key does not belong to this store prefix")]
    PrefixMismatch,
    #[error("key bit offset {offset} plus store prefix bits {prefix_bits} exceeds u16")]
    BitOffsetOverflow { offset: u16, prefix_bits: u8 },
    #[error("key codec error: {0}")]
    Codec(#[from] KeyCodecError),
}

/// A client-side namespace layered over raw Store keys.
///
/// The prefix consumes a small number of high bits in the physical Store key
/// and stores the caller's logical key in the remaining payload bits. QMDB,
/// SQL, and other higher-level instances continue to build their own logical
/// keys as before; a prefixed [`StoreClient`] maps those keys on the wire and
/// maps returned keys back before callers see them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StoreKeyPrefix {
    codec: KeyCodec,
}

impl StoreKeyPrefix {
    pub fn new(reserved_bits: u8, prefix: u16) -> Result<Self, StoreKeyPrefixError> {
        validate_prefix_bits(reserved_bits, prefix)?;
        Ok(Self {
            codec: KeyCodec::new(reserved_bits, prefix),
        })
    }

    #[inline]
    pub fn reserved_bits(self) -> u8 {
        self.codec.reserved_bits()
    }

    #[inline]
    pub fn prefix(self) -> u16 {
        self.codec.prefix()
    }

    /// Maximum logical key bytes available under this prefix.
    #[inline]
    pub fn max_logical_key_len(self) -> usize {
        self.codec.max_payload_capacity_bytes()
    }

    /// Encode a logical key into the physical Store keyspace.
    pub fn encode_key(self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        Ok(self.codec.encode(key)?)
    }

    /// Decode a physical Store key back into the logical keyspace.
    pub fn decode_key(self, key: &Key) -> Result<Key, StoreKeyPrefixError> {
        if !self.codec.matches(key) {
            return Err(StoreKeyPrefixError::PrefixMismatch);
        }
        let payload_len = self.codec.payload_capacity_bytes_for_key_len(key.len());
        Ok(Bytes::from(self.codec.read_payload(key, 0, payload_len)?))
    }

    /// Encode an inclusive logical range into the physical Store keyspace.
    ///
    /// Empty `end` means unbounded in the logical keyspace and is narrowed to
    /// this prefix's physical upper bound. Long logical upper bounds are
    /// clamped to the maximum logical key length representable under this
    /// prefix; this preserves scans over existing `KeyCodec::prefix_bounds`
    /// ranges, whose upper bound is intentionally `MAX_KEY_LEN` bytes.
    pub fn encode_range(self, start: &Key, end: &Key) -> Result<(Key, Key), StoreKeyPrefixError> {
        let start = self.encode_key(start)?;
        let end = if end.is_empty() {
            self.codec.prefix_bounds().1
        } else {
            let max_len = self.max_logical_key_len();
            let end = if end.len() > max_len {
                Bytes::copy_from_slice(&end[..max_len])
            } else {
                Bytes::copy_from_slice(end)
            };
            self.encode_key(&end)?
        };
        Ok((start, end))
    }

    fn prefix_match_key(
        self,
        match_key: &crate::match_key::MatchKey,
    ) -> Result<crate::match_key::MatchKey, StoreKeyPrefixError> {
        self.prefix_match_key_with_regex(match_key, match_key.payload_regex.clone())
    }

    fn prefix_stream_match_key(
        self,
        match_key: &crate::match_key::MatchKey,
    ) -> Result<crate::match_key::MatchKey, StoreKeyPrefixError> {
        self.prefix_match_key_with_regex(match_key, crate::kv_codec::Utf8::from("(?s-u).*"))
    }

    fn prefix_match_key_with_regex(
        self,
        match_key: &crate::match_key::MatchKey,
        payload_regex: crate::kv_codec::Utf8,
    ) -> Result<crate::match_key::MatchKey, StoreKeyPrefixError> {
        validate_prefix_bits(match_key.reserved_bits, match_key.prefix)?;
        let reserved_bits = self
            .reserved_bits()
            .checked_add(match_key.reserved_bits)
            .ok_or(StoreKeyPrefixError::CombinedReservedBitsTooLarge {
                prefix_bits: self.reserved_bits(),
                logical_bits: match_key.reserved_bits,
            })?;
        if reserved_bits > 16 {
            return Err(StoreKeyPrefixError::CombinedReservedBitsTooLarge {
                prefix_bits: self.reserved_bits(),
                logical_bits: match_key.reserved_bits,
            });
        }

        let prefix = (u32::from(self.prefix()) << u32::from(match_key.reserved_bits))
            | u32::from(match_key.prefix);
        let prefix = u16::try_from(prefix).map_err(|_| StoreKeyPrefixError::PrefixTooLarge {
            reserved_bits,
            prefix: u16::MAX,
        })?;
        validate_prefix_bits(reserved_bits, prefix)?;
        Ok(crate::match_key::MatchKey {
            reserved_bits,
            prefix,
            payload_regex,
        })
    }
}

/// Reserved high bits selecting the *subsystem* within a namespace prefix.
/// Three bits → up to eight subsystems.
pub const NAMESPACE_SLOT_BITS: u8 = 3;

/// Reserved high bits selecting the *instance* of a subsystem within a
/// namespace prefix. One bit → up to two instances per subsystem (e.g. QMDB's
/// account-state and transaction-history operation logs).
pub const NAMESPACE_INSTANCE_BITS: u8 = 1;

/// Total reserved high bits in *every* namespace key prefix (slot + instance).
///
/// The width is uniform across all namespaces and instances — that uniformity
/// is what makes the scheme footgun-free: every prefix is the same length, so
/// distinct prefixes are pairwise prefix-disjoint and no "bare" namespace can
/// ever be a bit-prefix of one of its own instances. These bits sit *above*
/// each subsystem's own internal reserved bits; the combined width stays within
/// the 16-bit budget the codec enforces.
pub const NAMESPACE_RESERVED_BITS: u8 = NAMESPACE_SLOT_BITS + NAMESPACE_INSTANCE_BITS;

/// Canonical key-prefix allocation for the SDK's built-in subsystems when they
/// co-tenant a single Store.
///
/// Co-tenancy is load-bearing: [`StoreWriteBatch`] commits rows from multiple
/// subsystems in one atomic Store `Put`, so they must share a keyspace to get
/// cross-subsystem atomicity. This enum is the single source of truth that
/// keeps their slots from colliding. It is deliberately *not* a runtime
/// registry — distinct variants of one fixed width are disjoint by construction.
///
/// Any subsystem can run more than one instance in a Store via [`Self::sub`];
/// the bare namespace is exactly [`Self::sub(0)`](Self::sub).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Namespace {
    Sql,
    Simplex,
    Qmdb,
}

impl Namespace {
    /// The subsystem slot stored in the high [`NAMESPACE_SLOT_BITS`].
    #[inline]
    const fn slot(self) -> u16 {
        match self {
            Namespace::Sql => 0,
            Namespace::Simplex => 1,
            Namespace::Qmdb => 2,
        }
    }

    /// The canonical [`StoreKeyPrefix`] for this subsystem — its default
    /// instance, i.e. [`Self::sub(0)`](Self::sub).
    #[inline]
    pub const fn key_prefix(self) -> StoreKeyPrefix {
        self.sub(0)
    }

    /// The [`StoreKeyPrefix`] for `instance` of this subsystem.
    ///
    /// For a consumer that co-locates more than one instance of a subsystem in
    /// one Store (e.g. QMDB's two operation logs). Every `sub` of every
    /// namespace is the same fixed width, so they are all pairwise
    /// prefix-disjoint — a prefix-bounded range scan in one can never observe
    /// another's keys. `instance` must be less than `2^NAMESPACE_INSTANCE_BITS`.
    #[inline]
    pub const fn sub(self, instance: u8) -> StoreKeyPrefix {
        assert!(
            (instance as u16) < (1 << NAMESPACE_INSTANCE_BITS),
            "namespace instance out of range",
        );
        let prefix = (self.slot() << NAMESPACE_INSTANCE_BITS) | instance as u16;
        StoreKeyPrefix {
            codec: KeyCodec::new(NAMESPACE_RESERVED_BITS, prefix),
        }
    }
}

/// A [`StoreClient`] guaranteed to carry a [`StoreKeyPrefix`].
///
/// Constructable only from a `(client, prefix)` pair, so a value of this type is
/// *always* namespaced. Subsystem constructors that must not silently share a
/// raw keyspace take this type instead of a bare [`StoreClient`], turning "did
/// you namespace?" into a compile-time fact.
///
/// Intentionally does **not** `Deref` to [`StoreClient`]: that would re-expose
/// [`StoreClient::without_key_prefix`] and let callers quietly drop the
/// guarantee.
#[derive(Clone, Debug)]
pub struct PrefixedStoreClient {
    client: StoreClient,
}

impl PrefixedStoreClient {
    /// Wrap a client with an explicit namespace prefix.
    pub fn new(mut client: StoreClient, prefix: StoreKeyPrefix) -> Self {
        // Owned, so set the prefix in place instead of cloning via `with_key_prefix`.
        client.key_prefix = Some(prefix);
        Self { client }
    }

    /// Wrap a client with the canonical prefix for a built-in [`Namespace`].
    pub fn for_namespace(client: StoreClient, namespace: Namespace) -> Self {
        Self::new(client, namespace.key_prefix())
    }

    /// The configured key prefix (always present).
    pub fn key_prefix(&self) -> StoreKeyPrefix {
        self.client
            .key_prefix()
            .expect("PrefixedStoreClient always carries a prefix")
    }

    /// Borrow the underlying prefixed client for read/write operations.
    pub fn client(&self) -> &StoreClient {
        &self.client
    }

    /// Consume into the underlying (prefixed) client.
    pub fn into_client(self) -> StoreClient {
        self.client
    }
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

    pub fn push(
        &mut self,
        client: &StoreClient,
        key: &Key,
        value: impl IntoStoreWriteValue,
    ) -> Result<&mut Self, ClientError> {
        self.entries.push((
            client.encode_store_key(key)?,
            value.into_store_write_value(),
        ));
        Ok(self)
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
        client: &'a StoreClient,
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
            match batch.commit(client).await {
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

/// A writer that can stage an already-prepared publication record into a
/// shared Store write batch and then be notified of the batch outcome.
///
/// This is the companion to [`StoreBatchUpload`] for metadata that publishes
/// already-staged data, such as QMDB watermarks. Implementations should keep
/// `prepare_*` methods as inherent APIs because each publisher decides when a
/// publication is needed.
pub trait StoreBatchPublication {
    type PreparedPublication: Send;
    type PublicationReceipt: Send;
    type Error: std::fmt::Display + Send;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error>;

    fn publication_commit_error(&self, error: ClientError) -> Self::Error;

    fn mark_publication_persisted<'a>(
        &'a self,
        prepared: Self::PreparedPublication,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::PublicationReceipt>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a;

    fn mark_publication_failed<'a>(
        &'a self,
        _prepared: Self::PreparedPublication,
        _error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
    {
        Box::pin(async {})
    }

    fn commit_publication<'a>(
        &'a self,
        client: &'a StoreClient,
        prepared: Self::PreparedPublication,
    ) -> BoxFuture<'a, Result<Self::PublicationReceipt, Self::Error>>
    where
        Self: Sync + Sized + 'a,
        Self::PreparedPublication: 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move {
            let mut batch = StoreWriteBatch::new();
            if let Err(err) = self.stage_publication(&prepared, &mut batch) {
                let message = err.to_string();
                self.mark_publication_failed(prepared, message).await;
                return Err(err);
            }
            match batch.commit(client).await {
                Ok(sequence_number) => Ok(self
                    .mark_publication_persisted(prepared, sequence_number)
                    .await),
                Err(err) => {
                    let message = err.to_string();
                    self.mark_publication_failed(prepared, message).await;
                    Err(self.publication_commit_error(err))
                }
            }
        })
    }
}

/// A stateful writer that owns a durable publication frontier.
///
/// This extends [`StoreBatchPublication`] with the pieces needed by writers
/// that can prepare a catch-up publication after pending uploads drain. The
/// associated prepared publication, receipt, and error types come from
/// [`StoreBatchPublication`], so databases can use this for watermarks,
/// checkpoints, catalog versions, or any similar publication record without
/// sharing QMDB-specific concepts.
pub trait StorePublicationFrontierWriter: StoreBatchPublication {
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<Self::PublicationReceipt>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a;

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<Self::PreparedPublication>, Self::Error>>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
        Self::Error: 'a;

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<Self::PublicationReceipt>, Self::Error>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a;

    fn flush_publication<'a>(&'a self) -> BoxFuture<'a, Result<(), Self::Error>>
    where
        Self: Sync + 'a,
        Self::PublicationReceipt: 'a,
        Self::Error: 'a,
    {
        Box::pin(async move { self.flush_publication_with_receipt().await.map(|_| ()) })
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
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::RangeFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::RangeFrame>,
    rows_seen: usize,
    final_count: Option<usize>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
}

impl RangeStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::RangeFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            rows_seen: 0,
            final_count: None,
            finished: false,
            observed_sequence,
            key_prefix,
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
                self.pending_frame = Some(frame.to_owned_message());
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
                    .map_err(client_error_from_connect)?
                else {
                    self.finished = true;
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone()));
                    }
                    self.final_count = Some(self.rows_seen);
                    return Ok(None);
                };
                frame.to_owned_message()
            };

            let detail = frame.detail.as_option().cloned();
            if let (Some(sequence_store), Some(detail)) = (&self.observed_sequence, detail.as_ref())
            {
                sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
            }
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in &frame.results {
                let key = Bytes::copy_from_slice(&entry.key);
                let key = match self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                out.push((key, Bytes::copy_from_slice(&entry.value)));
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

pub struct GetManyStream {
    stream:
        ConnectServerStream<hyper::body::Incoming, exoware_proto::query::GetManyFrameView<'static>>,
    pending_frame: Option<exoware_proto::query::GetManyFrame>,
    finished: bool,
    observed_sequence: Option<Arc<AtomicU64>>,
    key_prefix: Option<StoreKeyPrefix>,
}

impl GetManyStream {
    fn from_connect_stream(
        stream: ConnectServerStream<
            hyper::body::Incoming,
            exoware_proto::query::GetManyFrameView<'static>,
        >,
        observed_sequence: Option<Arc<AtomicU64>>,
        key_prefix: Option<StoreKeyPrefix>,
    ) -> Self {
        Self {
            stream,
            pending_frame: None,
            finished: false,
            observed_sequence,
            key_prefix,
        }
    }

    async fn prefetch_first_frame(&mut self) -> Result<(), ConnectError> {
        if self.pending_frame.is_some() || self.finished {
            return Ok(());
        }
        match self.stream.message().await? {
            Some(frame) => {
                self.pending_frame = Some(frame.to_owned_message());
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
                    .map_err(client_error_from_connect)?
                else {
                    self.finished = true;
                    if let Some(err) = self.stream.error() {
                        return Err(client_error_from_connect(err.clone()));
                    }
                    return Ok(None);
                };
                frame.to_owned_message()
            };

            let detail = frame.detail.as_option().cloned();
            if let (Some(sequence_store), Some(detail)) = (&self.observed_sequence, detail.as_ref())
            {
                sequence_store.fetch_max(detail.sequence_number, Ordering::SeqCst);
            }
            let n = frame.results.len();

            // Hide default/empty wire frames from the SDK's semantic chunk stream.
            if n == 0 && detail.is_none() {
                continue;
            }

            let mut out = Vec::with_capacity(n);
            for entry in &frame.results {
                let key = Bytes::copy_from_slice(&entry.key);
                let key = match self.key_prefix {
                    Some(prefix) => prefix.decode_key(&key)?,
                    None => key,
                };
                let value = entry.value.as_ref().map(|v| Bytes::copy_from_slice(v));
                out.push((key, value));
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

#[inline]
fn key_prefix_mask(bits: u8) -> Result<u16, StoreKeyPrefixError> {
    if bits > 16 {
        return Err(StoreKeyPrefixError::ReservedBitsTooLarge {
            reserved_bits: bits,
        });
    }
    Ok(if bits == 0 {
        0
    } else if bits == 16 {
        u16::MAX
    } else {
        (1u16 << bits) - 1
    })
}

fn validate_prefix_bits(reserved_bits: u8, prefix: u16) -> Result<(), StoreKeyPrefixError> {
    let mask = key_prefix_mask(reserved_bits)?;
    if prefix > mask {
        return Err(StoreKeyPrefixError::PrefixTooLarge {
            reserved_bits,
            prefix,
        });
    }
    Ok(())
}

/// One delivered (key, value) row from a stream subscription. The client
/// reapplies its own filter if it needs to know which match_key matched —
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
        hyper::body::Incoming,
        exoware_proto::store::stream::v1::SubscribeResponseView<'static>,
    >,
    key_prefix: Option<StoreKeyPrefix>,
    logical_filter: Option<ClientStreamFilter>,
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
                .map_err(client_error_from_connect)?
            {
                Some(view) => {
                    let owned = view.to_owned_message();
                    let mut entries = Vec::with_capacity(owned.entries.len());
                    for entry in owned.entries {
                        let key = Bytes::from(entry.key);
                        let key = match self.key_prefix {
                            Some(prefix) => prefix.decode_key(&key)?,
                            None => key,
                        };
                        let value = entry.value;
                        if self
                            .logical_filter
                            .as_ref()
                            .is_none_or(|filter| filter.matches(&key, value.as_ref()))
                        {
                            entries.push(StreamSubscriptionEntry { key, value });
                        }
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
                        return Err(client_error_from_connect(err.clone()));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct ClientKeyMatcher {
    codec: KeyCodec,
    regex: regex::bytes::Regex,
}

#[derive(Clone)]
struct ClientStreamFilter {
    keys: Vec<ClientKeyMatcher>,
    values: Option<crate::stream_filter::CompiledBytesFilters>,
}

impl ClientStreamFilter {
    fn compile(filter: &crate::stream_filter::StreamFilter) -> Result<Self, ClientError> {
        crate::stream_filter::validate_filter(filter)
            .map_err(|e| ClientError::WireFormat(e.to_string()))?;
        let keys = filter
            .match_keys
            .iter()
            .map(|mk| {
                let regex = crate::match_key::compile_payload_regex(&mk.payload_regex)
                    .map_err(|e| ClientError::WireFormat(e.to_string()))?;
                Ok(ClientKeyMatcher {
                    codec: KeyCodec::new(mk.reserved_bits, mk.prefix),
                    regex,
                })
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let values = crate::stream_filter::CompiledBytesFilters::compile(&filter.value_filters)
            .map_err(ClientError::WireFormat)?;
        Ok(Self { keys, values })
    }

    fn matches(&self, key: &Key, value: &[u8]) -> bool {
        if !self
            .values
            .as_ref()
            .is_none_or(|filter| filter.matches(value))
        {
            return false;
        }
        self.keys.iter().any(|matcher| {
            if !matcher.codec.matches(key) {
                return false;
            }
            let payload_len = matcher.codec.payload_capacity_bytes_for_key_len(key.len());
            matcher
                .codec
                .read_payload(key, 0, payload_len)
                .is_ok_and(|payload| matcher.regex.is_match(&payload))
        })
    }
}

/// Inspect a Connect error for `store.stream.BATCH_EVICTED` / `BATCH_NOT_FOUND`
/// `ErrorInfo` details. Used by `get_batch` to collapse both into `Ok(None)`.
fn is_batch_missing_error(err: &ConnectError) -> bool {
    match proto_decode_connect_error(err) {
        Ok(decoded) => decoded.error_info.is_some_and(|info| {
            info.domain == "store.stream"
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

fn new_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

/// Error returned when [`StoreClientBuilder`] is missing a required endpoint URL.
#[derive(Debug, thiserror::Error)]
pub enum ClientBuildError {
    #[error("StoreClientBuilder: missing health URL (set health_url or url)")]
    MissingHealthUrl,
    #[error("StoreClientBuilder: missing ingest URL (set ingest_url or url)")]
    MissingIngestUrl,
    #[error("StoreClientBuilder: missing query URL (set query_url or url)")]
    MissingQueryUrl,
    #[error("StoreClientBuilder: missing compact URL (set compact_url or url)")]
    MissingCompactUrl,
    #[error("StoreClientBuilder: missing stream URL (set stream_url or url)")]
    MissingStreamUrl,
    #[error("StoreClientBuilder: invalid URL \"{url}\": {source}")]
    InvalidUrl {
        url: String,
        source: http::uri::InvalidUri,
    },
}

/// Configures a [`StoreClient`] with explicit bases for health probes and store services.
///
/// Use [`StoreClient::builder()`] to construct. Call [`Self::url`] to point every
/// service at the same origin, or set each base separately. Finish with [`Self::build`].
#[derive(Debug, Default)]
pub struct StoreClientBuilder {
    health_url: Option<String>,
    ingest_url: Option<String>,
    query_url: Option<String>,
    compact_url: Option<String>,
    stream_url: Option<String>,
    key_prefix: Option<StoreKeyPrefix>,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
}

impl StoreClientBuilder {
    /// Sets the same base URL for all services (health, ingest, query, compact, stream).
    pub fn url(mut self, url: &str) -> Self {
        let u = trim_connect_base(url);
        self.health_url = Some(u.clone());
        self.ingest_url = Some(u.clone());
        self.query_url = Some(u.clone());
        self.compact_url = Some(u.clone());
        self.stream_url = Some(u);
        self
    }

    /// Base URL for plain HTTP `GET /health` and `GET /ready` (often the query worker).
    pub fn health_url(mut self, url: &str) -> Self {
        self.health_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the ingest service (`store.ingest.v1.Service`).
    pub fn ingest_url(mut self, url: &str) -> Self {
        self.ingest_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the query service (`store.query.v1.Service`).
    pub fn query_url(mut self, url: &str) -> Self {
        self.query_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the compact service (`store.compact.v1.Service`).
    pub fn compact_url(mut self, url: &str) -> Self {
        self.compact_url = Some(trim_connect_base(url));
        self
    }

    /// Base URL for the stream service (`store.stream.v1.Service`).
    pub fn stream_url(mut self, url: &str) -> Self {
        self.stream_url = Some(trim_connect_base(url));
        self
    }

    /// Client-side key namespace applied to all user-key operations.
    pub fn key_prefix(mut self, prefix: StoreKeyPrefix) -> Self {
        self.key_prefix = Some(prefix);
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

    /// Build the client, or return an error if any required URL was not set.
    pub fn build(self) -> Result<StoreClient, ClientBuildError> {
        let health_url = self.health_url.ok_or(ClientBuildError::MissingHealthUrl)?;
        let ingest_url = self.ingest_url.ok_or(ClientBuildError::MissingIngestUrl)?;
        let query_url = self.query_url.ok_or(ClientBuildError::MissingQueryUrl)?;
        let compact_url = self
            .compact_url
            .ok_or(ClientBuildError::MissingCompactUrl)?;
        let stream_url = self.stream_url.ok_or(ClientBuildError::MissingStreamUrl)?;
        let ingest_uri: http::Uri =
            ingest_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: ingest_url.clone(),
                    source: e,
                })?;
        let query_uri: http::Uri = query_url
            .parse()
            .map_err(|e| ClientBuildError::InvalidUrl {
                url: query_url.clone(),
                source: e,
            })?;
        let compact_uri: http::Uri =
            compact_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: compact_url.clone(),
                    source: e,
                })?;
        let stream_uri: http::Uri =
            stream_url
                .parse()
                .map_err(|e| ClientBuildError::InvalidUrl {
                    url: stream_url.clone(),
                    source: e,
                })?;
        Ok(StoreClient {
            health_url,
            ingest_uri,
            query_uri,
            compact_uri,
            stream_uri,
            http: new_http_client(),
            connect_http: ProtoPreferZstdHttpClient::plaintext(),
            retry_config: self.retry_config,
            connect_request_compression: self.connect_request_compression,
            key_prefix: self.key_prefix,
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
    compact_uri: http::Uri,
    stream_uri: http::Uri,
    http: reqwest::Client,
    connect_http: ProtoPreferZstdHttpClient,
    retry_config: RetryConfig,
    connect_request_compression: ConnectRequestCompression,
    key_prefix: Option<StoreKeyPrefix>,
}

/// A session that enforces monotonic read consistency via a fixed `min_sequence_number` floor.
///
/// `StoreClient` itself does not retain any client-global observed sequence.
/// Plain query reads are stateless unless the caller passes an explicit
/// `min_sequence_number`.
///
/// A `SerializableReadSession` is the explicit consistency mechanism. The first
/// successful unary read seeds the session from the server-reported sequence,
/// and every later read passes that fixed floor so the server guarantees all
/// responses reflect at least that point in the write log.
///
/// Streamed query reads (`get_many`, `range_stream`) expose their sequence in
/// each returned chunk's detail, so if one of those is the first successful
/// read, the session is pinned once the first detail-bearing chunk is consumed.
#[derive(Clone, Debug)]
pub struct SerializableReadSession {
    client: StoreClient,
    state: Arc<SessionState>,
}

#[derive(Debug)]
struct SessionState {
    sequence: Arc<AtomicU64>,
    init_gate: tokio::sync::Mutex<()>,
}

impl SessionState {
    fn fixed_sequence(&self) -> Option<u64> {
        let sequence = self.sequence.load(Ordering::Acquire);
        (sequence > 0).then_some(sequence)
    }
}

#[derive(Default)]
struct RangeStreamReadOptions {
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

    pub fn with_retry_config(url: &str, retry_config: RetryConfig) -> Self {
        Self::builder()
            .url(url)
            .retry_config(retry_config)
            .build()
            .expect("url sets all service URLs")
    }

    /// Return this client's configured Store key prefix, if any.
    pub fn key_prefix(&self) -> Option<StoreKeyPrefix> {
        self.key_prefix
    }

    /// Clone this client with a client-side Store key prefix.
    pub fn with_key_prefix(&self, prefix: StoreKeyPrefix) -> Self {
        let mut out = self.clone();
        out.key_prefix = Some(prefix);
        out
    }

    /// Clone this client without client-side key prefixing.
    pub fn without_key_prefix(&self) -> Self {
        let mut out = self.clone();
        out.key_prefix = None;
        out
    }

    /// Clone this client into a [`PrefixedStoreClient`] carrying `prefix`.
    pub fn prefixed(&self, prefix: StoreKeyPrefix) -> PrefixedStoreClient {
        PrefixedStoreClient::new(self.clone(), prefix)
    }

    /// Clone this client into a [`PrefixedStoreClient`] using the canonical
    /// prefix for a built-in [`Namespace`].
    pub fn for_namespace(&self, namespace: Namespace) -> PrefixedStoreClient {
        PrefixedStoreClient::for_namespace(self.clone(), namespace)
    }

    /// Encode a logical key as it will appear in the physical Store.
    pub fn encode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        match self.key_prefix {
            Some(prefix) => Ok(prefix.encode_key(key)?),
            None => Ok(key.clone()),
        }
    }

    /// Decode a physical Store key into this client's logical keyspace.
    pub fn decode_store_key(&self, key: &Key) -> Result<Key, ClientError> {
        match self.key_prefix {
            Some(prefix) => Ok(prefix.decode_key(key)?),
            None => Ok(key.clone()),
        }
    }

    fn encode_store_range(&self, start: &Key, end: &Key) -> Result<(Key, Key), ClientError> {
        match self.key_prefix {
            Some(prefix) => Ok(prefix.encode_range(start, end)?),
            None => Ok((start.clone(), end.clone())),
        }
    }

    /// Outgoing Connect request body compression (see [`ConnectRequestCompression`]).
    pub fn connect_request_compression(&self) -> ConnectRequestCompression {
        self.connect_request_compression
    }

    pub fn decode_error_details(
        err: &ConnectError,
    ) -> Result<exoware_proto::DecodedConnectError, buffa::DecodeError> {
        proto_decode_connect_error(err)
    }

    /// Create an unseeded serializable read session.
    ///
    /// The first successful unary read fixes the session's sequence floor from
    /// the server response. Streamed query reads fix that floor once a
    /// detail-bearing chunk is consumed.
    pub fn create_session(&self) -> SerializableReadSession {
        self.create_session_with_sequence(0)
    }

    /// Create a serializable read session pinned to at least `sequence`.
    ///
    /// This is intended for stream-driven read paths that already observed a
    /// concrete store batch sequence and need follow-up query/proof reads to
    /// see at least that sequence.
    pub fn create_session_with_sequence(&self, sequence: u64) -> SerializableReadSession {
        SerializableReadSession {
            client: self.clone(),
            state: Arc::new(SessionState {
                sequence: Arc::new(AtomicU64::new(sequence)),
                init_gate: tokio::sync::Mutex::new(()),
            }),
        }
    }

    /// Typed access to the `store.ingest.v1` service.
    pub fn ingest(&self) -> Ingest<'_> {
        Ingest { c: self }
    }

    /// Typed access to the `store.query.v1` service.
    pub fn query(&self) -> Query<'_> {
        Query { c: self }
    }

    /// Typed access to the `store.compact.v1` service.
    pub fn compact(&self) -> Compact<'_> {
        Compact { c: self }
    }

    /// Typed access to the `store.stream.v1` service.
    pub fn stream(&self) -> Stream<'_> {
        Stream { c: self }
    }

    /// Submit a KV batch via Connect `Put`.
    ///
    /// On success returns the **store sequence number** from the response. Use it for immediate
    /// `get_with_min_sequence_number` / range calls or to seed
    /// [`Self::create_session_with_sequence`].
    /// If the request succeeds, the server accepts the full batch (count is `kvs.len()`).
    pub(crate) async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        if self.key_prefix.is_none() {
            return self.put_physical(kvs).await;
        }
        let mut keys = Vec::with_capacity(kvs.len());
        for (key, _) in kvs {
            keys.push(self.encode_store_key(key)?);
        }
        let prefixed: Vec<(&Key, &[u8])> = keys
            .iter()
            .zip(kvs.iter())
            .map(|(key, (_, value))| (key, *value))
            .collect();
        self.put_physical(&prefixed).await
    }

    async fn put_physical(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
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
            proto_kvs.push(exoware_proto::common::KvEntry {
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
            proto_kvs.push(exoware_proto::common::KvEntry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            });
        }
        self.send_put(proto_kvs).await
    }

    async fn send_put(&self, kvs: Vec<exoware_proto::common::KvEntry>) -> Result<u64, ClientError> {
        let config =
            store_connect_client_config(self.ingest_uri.clone(), self.connect_request_compression);
        let client = IngestServiceClient::new(self.connect_http.clone(), config);
        let response = client
            .put(ProtoPutRequest {
                kvs,
                ..Default::default()
            })
            .await
            .map_err(client_error_from_connect)?;
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

    async fn get_many_internal(
        &self,
        keys: &[&Key],
        batch_size: u32,
        min_sequence_number: Option<u64>,
        observed_sequence: Option<Arc<AtomicU64>>,
    ) -> Result<GetManyStream, ClientError> {
        for key in keys {
            if !is_valid_key_size(key.len()) {
                return Err(ClientError::WireFormat(format!(
                    "key length {} is outside valid store key range ({}..={})",
                    key.len(),
                    keys::MIN_KEY_LEN,
                    MAX_KEY_LEN
                )));
            }
        }

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let proto_keys: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| match self.key_prefix {
                Some(_) => self.encode_store_key(k).map(|key| key.to_vec()),
                None => Ok(k.to_vec()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let effective_min = self.normalize_min_sequence_number(min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            match client
                .get_many(ProtoGetManyRequest {
                    keys: proto_keys.clone(),
                    min_sequence_number: effective_min,
                    batch_size,
                    ..Default::default()
                })
                .await
            {
                Ok(stream) => {
                    let mut gms = GetManyStream::from_connect_stream(
                        stream,
                        observed_sequence.clone(),
                        self.key_prefix,
                    );
                    if let Err(err) = gms.prefetch_first_frame().await {
                        if attempt < max_attempts && is_retryable_error(&err) {
                            let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                            tokio::time::sleep(delay).await;
                            attempt += 1;
                            continue;
                        }
                        return Err(client_error_from_connect(err));
                    }
                    return Ok(gms);
                }
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err));
                }
            }
        }
    }

    /// Key range is inclusive: `start <= key <= end` when `end` is non-empty; empty `end` is
    /// unbounded above (matches `store.query.v1.RangeRequest`).
    pub(crate) async fn range(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        self.range_internal(start, end, limit, RangeMode::Forward, None)
            .await
    }

    /// See [`StoreClient::range`] for `end` semantics.
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
            RangeStreamReadOptions::default(),
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
            RangeStreamReadOptions {
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
            RangeStreamReadOptions {
                min_sequence_number: Some(min_sequence_number),
                observed_sequence: None,
            },
        )
        .await
    }

    pub(crate) async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let (response, _) = self
            .range_reduce_response_internal(start, end, request, None)
            .await?;
        let decoded = proto_to_domain_reduce_response(response).map_err(ClientError::WireFormat)?;
        if !decoded.groups.is_empty() {
            return Err(ClientError::WireFormat(
                "grouped range reduction response returned for scalar request".to_string(),
            ));
        }
        Ok(decoded
            .results
            .iter()
            .map(|result| result.value.clone())
            .collect())
    }

    pub(crate) async fn range_reduce_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let (response, _) = self
            .range_reduce_response_internal(start, end, request, Some(min_sequence_number))
            .await?;
        let decoded = proto_to_domain_reduce_response(response).map_err(ClientError::WireFormat)?;
        if !decoded.groups.is_empty() {
            return Err(ClientError::WireFormat(
                "grouped range reduction response returned for scalar request".to_string(),
            ));
        }
        Ok(decoded
            .results
            .iter()
            .map(|result| result.value.clone())
            .collect())
    }

    pub(crate) async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let (body, _) = self
            .range_reduce_response_internal(start, end, request, None)
            .await?;
        Ok(body)
    }

    pub(crate) async fn range_reduce_response_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let (body, _) = self
            .range_reduce_response_internal(start, end, request, Some(min_sequence_number))
            .await?;
        Ok(body)
    }

    pub(crate) async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        let config =
            store_connect_client_config(self.compact_uri.clone(), self.connect_request_compression);
        let client = CompactServiceClient::new(self.connect_http.clone(), config);
        let policies = self.prefix_prune_policies(policies)?;
        client
            .prune(ProtoPruneRequest {
                policies: exoware_proto::prune_policies_to_proto(&policies),
                ..Default::default()
            })
            .await
            .map_err(client_error_from_connect)?;
        Ok(())
    }

    pub async fn health(&self) -> Result<bool, ClientError> {
        let resp = self
            .http
            .get(format!("{}/health", self.health_url))
            .send()
            .await?;
        Ok(resp.status().is_success())
    }

    pub async fn ready(&self) -> Result<bool, ClientError> {
        let resp = self
            .http
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
        let key = self.encode_store_key(key)?;

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
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

    async fn range_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        mode: RangeMode,
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<(Key, Bytes)>, ClientError> {
        let stream = self
            .range_stream_internal(
                start,
                end,
                limit,
                limit.max(1),
                mode,
                RangeStreamReadOptions {
                    min_sequence_number,
                    observed_sequence: None,
                },
            )
            .await?;
        stream.collect().await
    }

    async fn range_stream_internal(
        &self,
        start: &Key,
        end: &Key,
        limit: usize,
        batch_size: usize,
        mode: RangeMode,
        options: RangeStreamReadOptions,
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
        let (start, end) = self.encode_store_range(start, end)?;

        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let min_sequence_number = self.normalize_min_sequence_number(options.min_sequence_number);
        let max_attempts = self.retry_config.max_attempts.max(1);
        let mut attempt = 1usize;
        loop {
            // Server-streaming RPCs cannot transparently recover mid-stream failures,
            // but retrying a transient error while opening the stream or before the
            // first frame arrives is still safe. Treat both phases as a single
            // attempt budget so range opens do not multiply retries quadratically.
            let response = match client
                .range(ProtoRangeRequest {
                    start: start.clone().into(),
                    end: end.clone().into(),
                    limit: Some(u32::try_from(limit).unwrap_or(u32::MAX)),
                    batch_size: u32::try_from(batch_size).unwrap_or(u32::MAX),
                    mode: mode.to_proto().into(),
                    min_sequence_number,
                    ..Default::default()
                })
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    if attempt < max_attempts && is_retryable_error(&err) {
                        let delay = retry_delay_for_error(&err, attempt, self.retry_config);
                        tracing::debug!(
                            attempt,
                            max_attempts,
                            code = err.code.as_str(),
                            delay_ms = delay.as_millis() as u64,
                            "store client retrying transient range-open error",
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(client_error_from_connect(err));
                }
            };

            let mut stream = RangeStream::from_connect_stream(
                response,
                options.observed_sequence.clone(),
                self.key_prefix,
            );
            if let Err(err) = stream.prefetch_first_frame().await {
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
                return Err(client_error_from_connect(err));
            }
            return Ok(stream);
        }
    }

    async fn range_reduce_response_internal(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: Option<u64>,
    ) -> Result<
        (
            exoware_proto::query::ReduceResponse,
            Option<proto_query::Detail>,
        ),
        ClientError,
    > {
        let config =
            store_connect_client_config(self.query_uri.clone(), self.connect_request_compression);
        let client = QueryServiceClient::new(self.connect_http.clone(), config);
        let (start, end) = self.encode_store_range(start, end)?;
        let request = self.prefix_reduce_request(request)?;
        let proto_params = proto_to_proto_reduce_params(request);
        let min_sequence_number = self.normalize_min_sequence_number(min_sequence_number);
        let response = self
            .send_with_retry(|| async {
                client
                    .reduce(ProtoWireReduceRequest {
                        start: start.clone().into(),
                        end: end.clone().into(),
                        params: Some(proto_params.clone()).into(),
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

    fn prefix_prune_policies(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<Vec<crate::prune_policy::PrunePolicy>, ClientError> {
        let Some(prefix) = self.key_prefix else {
            return Ok(policies.to_vec());
        };
        policies
            .iter()
            .map(|policy| {
                use crate::prune_policy::{PolicyScope, PrunePolicy};
                let scope = match &policy.scope {
                    PolicyScope::Keys(scope) => {
                        let mut scope = scope.clone();
                        scope.match_key = prefix.prefix_match_key(&scope.match_key)?;
                        PolicyScope::Keys(scope)
                    }
                    PolicyScope::Sequence => PolicyScope::Sequence,
                };
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
        let Some(prefix) = self.key_prefix else {
            return Ok(filter);
        };
        let match_keys = filter
            .match_keys
            .iter()
            .map(|mk| prefix.prefix_stream_match_key(mk))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::stream_filter::StreamFilter {
            match_keys,
            value_filters: filter.value_filters,
        })
    }

    fn prefix_reduce_request(
        &self,
        request: &DomainRangeReduceRequest,
    ) -> Result<DomainRangeReduceRequest, ClientError> {
        let Some(prefix) = self.key_prefix else {
            return Ok(request.clone());
        };
        let mut request = request.clone();
        shift_reduce_request_key_offsets(prefix.reserved_bits(), &mut request)?;
        Ok(request)
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
                    return Err(client_error_from_connect(err));
                }
            }
        }
    }
}

fn shift_reduce_request_key_offsets(
    prefix_bits: u8,
    request: &mut DomainRangeReduceRequest,
) -> Result<(), StoreKeyPrefixError> {
    for reducer in &mut request.reducers {
        if let Some(expr) = &mut reducer.expr {
            shift_expr_key_offsets(prefix_bits, expr)?;
        }
    }
    for expr in &mut request.group_by {
        shift_expr_key_offsets(prefix_bits, expr)?;
    }
    if let Some(filter) = &mut request.filter {
        for check in &mut filter.checks {
            shift_field_ref_key_offset(prefix_bits, &mut check.field)?;
        }
    }
    Ok(())
}

fn shift_expr_key_offsets(prefix_bits: u8, expr: &mut KvExpr) -> Result<(), StoreKeyPrefixError> {
    match expr {
        KvExpr::Field(field) => shift_field_ref_key_offset(prefix_bits, field),
        KvExpr::Literal(_) => Ok(()),
        KvExpr::Add(left, right)
        | KvExpr::Sub(left, right)
        | KvExpr::Mul(left, right)
        | KvExpr::Div(left, right) => {
            shift_expr_key_offsets(prefix_bits, left)?;
            shift_expr_key_offsets(prefix_bits, right)
        }
        KvExpr::Lower(inner) | KvExpr::DateTruncDay(inner) => {
            shift_expr_key_offsets(prefix_bits, inner)
        }
    }
}

fn shift_field_ref_key_offset(
    prefix_bits: u8,
    field: &mut KvFieldRef,
) -> Result<(), StoreKeyPrefixError> {
    match field {
        KvFieldRef::Key { bit_offset, .. } | KvFieldRef::ZOrderKey { bit_offset, .. } => {
            *bit_offset = bit_offset.checked_add(u16::from(prefix_bits)).ok_or(
                StoreKeyPrefixError::BitOffsetOverflow {
                    offset: *bit_offset,
                    prefix_bits,
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
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Compact<'a> {
    c: &'a StoreClient,
}

#[derive(Clone, Copy, Debug)]
pub struct Stream<'a> {
    c: &'a StoreClient,
}

impl<'a> Ingest<'a> {
    pub async fn put(&self, kvs: &[(&Key, &[u8])]) -> Result<u64, ClientError> {
        self.c.put(kvs).await
    }

    /// Submit a [`StoreWriteBatch`] that has already been encoded into the
    /// physical Store keyspace.
    pub async fn put_prepared(&self, batch: &StoreWriteBatch) -> Result<u64, ClientError> {
        batch.commit(self.c).await
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
        self.c.range_reduce(start, end, request).await
    }

    pub async fn range_reduce_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        self.c
            .range_reduce_with_min_sequence_number(start, end, request, min_sequence_number)
            .await
    }

    pub async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        self.c.range_reduce_response(start, end, request).await
    }

    pub async fn range_reduce_response_with_min_sequence_number(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
        min_sequence_number: u64,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        self.c
            .range_reduce_response_with_min_sequence_number(
                start,
                end,
                request,
                min_sequence_number,
            )
            .await
    }
}

impl<'a> Compact<'a> {
    pub async fn prune(
        &self,
        policies: &[crate::prune_policy::PrunePolicy],
    ) -> Result<(), ClientError> {
        self.c.prune(policies).await
    }
}

impl<'a> Stream<'a> {
    /// `store.stream.v1.Service.Subscribe` — see `StreamSubscription::next`
    /// for consuming delivered frames. `since_sequence_number = None` starts
    /// live from the next Put; `Some(N)` replays retained batches before
    /// transitioning to live. An evicted `since` returns a
    /// `ConnectError::out_of_range` carrying `ErrorInfo.reason = "BATCH_EVICTED"`.
    pub async fn subscribe(
        &self,
        filter: crate::stream_filter::StreamFilter,
        since_sequence_number: Option<u64>,
    ) -> Result<StreamSubscription, ClientError> {
        let logical_filter = self
            .c
            .key_prefix
            .is_some()
            .then(|| ClientStreamFilter::compile(&filter))
            .transpose()?;
        let filter = self.c.prefix_stream_filter(filter)?;
        crate::stream_filter::validate_filter(&filter)
            .map_err(|e| ClientError::WireFormat(e.to_string()))?;
        let match_keys = filter
            .match_keys
            .into_iter()
            .map(|mk| exoware_proto::store::common::v1::MatchKey {
                reserved_bits: u32::from(mk.reserved_bits),
                prefix: u32::from(mk.prefix),
                payload_regex: mk.payload_regex.0,
                ..Default::default()
            })
            .collect();
        let value_filters = filter
            .value_filters
            .into_iter()
            .map(|vf| {
                use crate::stream_filter::BytesFilter;
                use exoware_proto::store::common::v1::bytes_filter::Kind as ProtoKind;
                let kind = match vf {
                    BytesFilter::Exact(bytes) => ProtoKind::Exact(bytes),
                    BytesFilter::Prefix(bytes) => ProtoKind::Prefix(bytes),
                    BytesFilter::Regex(pattern) => ProtoKind::Regex(pattern),
                };
                exoware_proto::store::common::v1::BytesFilter {
                    kind: Some(kind),
                    ..Default::default()
                }
            })
            .collect();
        let request = exoware_proto::store::stream::v1::SubscribeRequest {
            match_keys,
            value_filters,
            since_sequence_number,
            ..Default::default()
        };
        let config = store_connect_client_config(
            self.c.stream_uri.clone(),
            self.c.connect_request_compression,
        );
        let client = exoware_proto::store::stream::v1::ServiceClient::new(
            self.c.connect_http.clone(),
            config,
        );
        let stream = client
            .subscribe(request)
            .await
            .map_err(client_error_from_connect)?;
        Ok(StreamSubscription {
            stream,
            key_prefix: self.c.key_prefix,
            logical_filter,
        })
    }

    /// `store.stream.v1.Service.Get` — `Ok(None)` collapses the server's
    /// `BATCH_EVICTED` / `BATCH_NOT_FOUND` error details.
    pub async fn get(
        &self,
        sequence_number: u64,
    ) -> Result<Option<Vec<(Key, Bytes)>>, ClientError> {
        let config = store_connect_client_config(
            self.c.stream_uri.clone(),
            self.c.connect_request_compression,
        );
        let client = exoware_proto::store::stream::v1::ServiceClient::new(
            self.c.connect_http.clone(),
            config,
        );
        match client
            .get(exoware_proto::store::stream::v1::GetRequest {
                sequence_number,
                ..Default::default()
            })
            .await
        {
            Ok(resp) => {
                let owned = resp.into_owned();
                let mut entries = Vec::with_capacity(owned.entries.len());
                for entry in owned.entries {
                    let key = Bytes::from(entry.key);
                    match self.c.key_prefix {
                        Some(prefix) if !prefix.codec.matches(&key) => {}
                        Some(prefix) => entries.push((prefix.decode_key(&key)?, entry.value)),
                        None => entries.push((key, entry.value)),
                    }
                }
                Ok(Some(entries))
            }
            Err(err) => {
                if is_batch_missing_error(&err) {
                    Ok(None)
                } else {
                    Err(client_error_from_connect(err))
                }
            }
        }
    }
}

impl SerializableReadSession {
    /// Fixed sequence floor for this session, if one has been established yet.
    ///
    /// Fresh sessions start with `None` unless created via
    /// [`StoreClient::create_session_with_sequence`]. A first streamed query
    /// read (`get_many`, `range_stream`) sets this once a detail-bearing chunk
    /// is consumed.
    pub fn fixed_sequence(&self) -> Option<u64> {
        self.state.fixed_sequence()
    }

    pub async fn get(&self, key: &Key) -> Result<Option<Bytes>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move { client.get_with_min_sequence_number(key, sequence).await }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    let (response, detail) = client.send_get(key, None).await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    Ok(response.value)
                }
            },
        )
        .await
    }

    pub async fn get_many(
        &self,
        keys: &[&Key],
        batch_size: u32,
    ) -> Result<GetManyStream, ClientError> {
        let keys_owned: Vec<Key> = keys.iter().map(|k| Bytes::copy_from_slice(k)).collect();
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let keys_seeded = keys_owned.clone();
        let keys_unseeded = keys_owned;
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let keys = keys_seeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client
                        .get_many_with_min_sequence_number(&refs, batch_size, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let keys = keys_unseeded.clone();
                async move {
                    let refs: Vec<&Key> = keys.iter().collect();
                    client
                        .get_many_internal(&refs, batch_size, None, Some(observed_sequence))
                        .await
                }
            },
        )
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
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_with_mode_and_min_sequence_number(start, end, limit, mode, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    let stream = client
                        .range_stream_internal(
                            start,
                            end,
                            limit,
                            limit.max(1),
                            mode,
                            RangeStreamReadOptions {
                                min_sequence_number: None,
                                observed_sequence: Some(observed_sequence),
                            },
                        )
                        .await;
                    stream?.collect().await
                }
            },
        )
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
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                async move {
                    client
                        .range_stream_with_mode_and_min_sequence_number(
                            start, end, limit, batch_size, mode, sequence,
                        )
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                async move {
                    client
                        .range_stream_internal(
                            start,
                            end,
                            limit,
                            batch_size,
                            mode,
                            RangeStreamReadOptions {
                                min_sequence_number: None,
                                observed_sequence: Some(observed_sequence),
                            },
                        )
                        .await
                }
            },
        )
        .await
    }

    pub async fn range_reduce(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<Vec<Option<KvReducedValue>>, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let request_seeded = request.clone();
        let request_unseeded = request.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_with_min_sequence_number(start, end, &request, sequence)
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move {
                    let (response, detail) = client
                        .range_reduce_response_internal(start, end, &request, None)
                        .await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    let decoded = proto_to_domain_reduce_response(response)
                        .map_err(ClientError::WireFormat)?;
                    if !decoded.groups.is_empty() {
                        return Err(ClientError::WireFormat(
                            "grouped range reduction response returned for scalar request"
                                .to_string(),
                        ));
                    }
                    Ok(decoded
                        .results
                        .iter()
                        .map(|result| result.value.clone())
                        .collect())
                }
            },
        )
        .await
    }

    pub async fn range_reduce_response(
        &self,
        start: &Key,
        end: &Key,
        request: &DomainRangeReduceRequest,
    ) -> Result<exoware_proto::query::ReduceResponse, ClientError> {
        let seeded_client = self.client.clone();
        let unseeded_client = self.client.clone();
        let request_seeded = request.clone();
        let request_unseeded = request.clone();
        self.run_read(
            move |sequence| {
                let client = seeded_client.clone();
                let request = request_seeded.clone();
                async move {
                    client
                        .range_reduce_response_with_min_sequence_number(
                            start, end, &request, sequence,
                        )
                        .await
                }
            },
            move |observed_sequence| {
                let client = unseeded_client.clone();
                let request = request_unseeded.clone();
                async move {
                    let (response, detail) = client
                        .range_reduce_response_internal(start, end, &request, None)
                        .await?;
                    if let Some(detail) = detail {
                        observed_sequence.fetch_max(detail.sequence_number, Ordering::SeqCst);
                    }
                    Ok(response)
                }
            },
        )
        .await
    }

    async fn run_read<T, SeededCall, SeededFut, UnseededCall, UnseededFut>(
        &self,
        seeded_call: SeededCall,
        unseeded_call: UnseededCall,
    ) -> Result<T, ClientError>
    where
        SeededCall: Fn(u64) -> SeededFut,
        SeededFut: std::future::Future<Output = Result<T, ClientError>>,
        UnseededCall: Fn(Arc<AtomicU64>) -> UnseededFut,
        UnseededFut: std::future::Future<Output = Result<T, ClientError>>,
    {
        if let Some(sequence) = self.fixed_sequence() {
            return seeded_call(sequence).await;
        }

        let gate = self.state.init_gate.lock().await;

        if let Some(sequence) = self.fixed_sequence() {
            drop(gate);
            return seeded_call(sequence).await;
        }

        let result = unseeded_call(self.state.sequence.clone()).await;
        drop(gate);
        result
    }
}

fn client_error_from_connect(err: ConnectError) -> ClientError {
    ClientError::Rpc(Box::new(err))
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
    use exoware_proto::query::TraversalMode as ProtoTraversalMode;

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
            Err(ClientBuildError::MissingCompactUrl)
        ));
        assert!(matches!(
            StoreClient::builder()
                .health_url("http://h")
                .ingest_url("http://i")
                .query_url("http://q")
                .compact_url("http://c")
                .build(),
            Err(ClientBuildError::MissingStreamUrl)
        ));
    }

    #[test]
    fn client_trims_trailing_slash() {
        let client = StoreClient::new("http://localhost:10000/");
        assert_eq!(client.health_url, "http://localhost:10000");
    }

    #[test]
    fn create_session_starts_unseeded() {
        let client = StoreClient::new("http://localhost:10000/");
        let session = client.create_session();
        assert_eq!(session.fixed_sequence(), None);
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
        let client = StoreClient::new("http://localhost:10000/");
        let session = client.create_session_with_sequence(27);
        assert_eq!(session.fixed_sequence(), Some(27));
    }

    #[test]
    fn store_key_prefix_round_trips_logical_keys() {
        let prefix = StoreKeyPrefix::new(4, 0xA).unwrap();
        let logical = Bytes::from_static(b"hello");
        let physical = prefix.encode_key(&logical).unwrap();
        assert!(prefix.codec.matches(&physical));
        assert_eq!(prefix.decode_key(&physical).unwrap(), logical);
    }

    #[test]
    fn namespace_prefixes_are_pairwise_disjoint() {
        // Every leaf prefix: each subsystem's default and its other instance.
        let all = [
            Namespace::Sql.sub(0),
            Namespace::Sql.sub(1),
            Namespace::Simplex.sub(0),
            Namespace::Simplex.sub(1),
            Namespace::Qmdb.sub(0),
            Namespace::Qmdb.sub(1),
        ];
        // A key encoded under one prefix never matches another's codec — so a
        // prefix-bounded range scan in one can't observe another's keys (this is
        // the bug being fixed). Uniform width ⇒ no prefix is a bit-prefix of
        // another, including a subsystem's default vs its own sub(1).
        let logical = Bytes::from_static(b"\x00\x10whatever-block-meta-or-op-log-key");
        for (i, pa) in all.iter().enumerate() {
            let physical = pa.encode_key(&logical).unwrap();
            assert!(pa.codec.matches(&physical));
            assert_eq!(pa.decode_key(&physical).unwrap(), logical);
            for (j, pb) in all.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !pb.codec.matches(&physical),
                    "prefix {j} matched a key encoded under prefix {i}",
                );
            }
        }
    }

    #[test]
    fn namespace_default_is_instance_zero_and_all_widths_match() {
        for ns in [Namespace::Sql, Namespace::Simplex, Namespace::Qmdb] {
            assert_eq!(ns.key_prefix(), ns.sub(0));
            assert_eq!(ns.sub(0).reserved_bits(), NAMESPACE_RESERVED_BITS);
            assert_eq!(ns.sub(1).reserved_bits(), NAMESPACE_RESERVED_BITS);
            // The two instances differ only in the low instance bit.
            assert_eq!(ns.sub(0).prefix() ^ ns.sub(1).prefix(), 1);
        }
    }

    #[test]
    fn prefixed_store_client_always_carries_its_namespace_prefix() {
        let base = StoreClient::new("http://localhost:8090");
        assert!(base.key_prefix().is_none());
        let sql = base.for_namespace(Namespace::Sql);
        assert_eq!(sql.key_prefix(), Namespace::Sql.key_prefix());
        assert_eq!(
            sql.client().key_prefix(),
            Some(Namespace::Sql.key_prefix()),
            "underlying client carries the prefix for all reads/writes",
        );
        // A non-default sub instance also threads through.
        let explicit = base.prefixed(Namespace::Qmdb.sub(1));
        assert_eq!(explicit.key_prefix(), Namespace::Qmdb.sub(1));
    }

    #[test]
    fn store_key_prefix_clamps_long_logical_range_upper_bound() {
        let prefix = StoreKeyPrefix::new(4, 0x2).unwrap();
        let logical_codec = KeyCodec::new(4, 0x7);
        let (logical_start, logical_end) = logical_codec.prefix_bounds();
        assert_eq!(logical_end.len(), MAX_KEY_LEN);

        let (physical_start, physical_end) =
            prefix.encode_range(&logical_start, &logical_end).unwrap();
        assert!(prefix.codec.matches(&physical_start));
        assert!(prefix.codec.matches(&physical_end));
        assert_eq!(physical_end.len(), MAX_KEY_LEN);
        assert_eq!(prefix.decode_key(&physical_start).unwrap(), logical_start);
    }

    #[test]
    fn store_key_prefix_rewrites_match_key_family() {
        let prefix = StoreKeyPrefix::new(3, 0b101).unwrap();
        let logical = crate::match_key::MatchKey {
            reserved_bits: 4,
            prefix: 0b0110,
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };
        let physical = prefix.prefix_match_key(&logical).unwrap();
        assert_eq!(physical.reserved_bits, 7);
        assert_eq!(physical.prefix, 0b101_0110);
        assert_eq!(physical.payload_regex, logical.payload_regex);
    }

    #[test]
    fn store_key_prefix_broadens_stream_match_key_payload_regex() {
        let prefix = StoreKeyPrefix::new(3, 0b101).unwrap();
        let logical = crate::match_key::MatchKey {
            reserved_bits: 4,
            prefix: 0b0110,
            payload_regex: crate::kv_codec::Utf8::from("(?s).*"),
        };
        let physical = prefix.prefix_stream_match_key(&logical).unwrap();
        assert_eq!(physical.reserved_bits, 7);
        assert_eq!(physical.prefix, 0b101_0110);
        assert_eq!(&*physical.payload_regex, "(?s-u).*");
    }

    #[test]
    fn prefixed_reduce_request_shifts_key_field_offsets() {
        let client = StoreClient::builder()
            .url("http://localhost:10000")
            .key_prefix(StoreKeyPrefix::new(5, 0b10101).unwrap())
            .build()
            .unwrap();
        let request = DomainRangeReduceRequest {
            reducers: vec![crate::RangeReducerSpec {
                op: crate::RangeReduceOp::SumField,
                expr: Some(KvExpr::Field(KvFieldRef::Key {
                    bit_offset: 9,
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
        let Some(KvExpr::Field(KvFieldRef::Key { bit_offset, .. })) =
            shifted.reducers[0].expr.as_ref()
        else {
            panic!("expected key field reducer");
        };
        assert_eq!(*bit_offset, 14);
        let KvExpr::Field(KvFieldRef::ZOrderKey { bit_offset, .. }) = &shifted.group_by[0] else {
            panic!("expected z-order group field");
        };
        assert_eq!(*bit_offset, 17);
    }

    #[test]
    fn store_write_batch_uses_each_clients_prefix() {
        let base = StoreClient::new("http://localhost:10000");
        let a = base.with_key_prefix(StoreKeyPrefix::new(4, 1).unwrap());
        let b = base.with_key_prefix(StoreKeyPrefix::new(4, 2).unwrap());
        let key_a = Bytes::from_static(b"a");
        let key_b = Bytes::from_static(b"b");

        let mut batch = StoreWriteBatch::new();
        batch.push(&a, &key_a, b"va").unwrap();
        batch.push(&b, &key_b, b"vb").unwrap();

        assert_eq!(
            batch.entries[0].0,
            a.key_prefix().unwrap().encode_key(&key_a).unwrap()
        );
        assert_eq!(
            batch.entries[1].0,
            b.key_prefix().unwrap().encode_key(&key_b).unwrap()
        );
    }

    fn hex_encode(data: &[u8]) -> String {
        hex::encode(data)
    }

    fn hex_decode(s: &str) -> Option<Vec<u8>> {
        hex::decode(s).ok()
    }
}
