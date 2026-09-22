//! Connect transport helpers for the store API.
//!
//! ## Registry
//!
//! Servers register **gzip** and **zstd** via [`connect_compression_registry`] (same as
//! [`connectrpc::compression::CompressionRegistry::default`]) so callers without zstd
//! (including typical browsers) can still negotiate gzip.
//!
//! ## Rust client transport
//!
//! HTTP and HTTPS transport that prefers zstd for the default response codecs.
//!
//! [`connectrpc::compression::CompressionRegistry::default`] builds the header value in sorted
//! order (`gzip, zstd`), so servers negotiate **gzip** first. `Accept-Encoding` prefers zstd
//! over gzip. Streaming calls reorder the native `gzip, zstd` declaration; custom codec lists
//! retain their configured ordering and capabilities.
//!
//! **Request bodies** (client -> server) use a single codec from connectrpc `compress_requests`.
//!
//! ## HTTP cookies
//!
//! [`PreferZstdHttpClient`] stores `Set-Cookie` response headers in an RFC6265 cookie store and
//! replays matching cookies on later requests. This covers edge affinity cookies as well as normal
//! domain, path, expiry, and deletion semantics.

use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

pub use bytes::Bytes;
pub use connectrpc::client::{
    BoxFuture, ClientBody, ClientTransport, HttpClient, ServiceTransport,
};
use connectrpc::compression::CompressionRegistry;
pub use connectrpc::rustls::{self, ClientConfig};
use connectrpc::{ConnectError, Protocol};
use cookie_store::{Cookie, CookieDomain, CookieStore};
use http::header::{ACCEPT_ENCODING, AUTHORIZATION, COOKIE, SET_COOKIE};
pub use http::{Request, Response};
pub use http_body::Body;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnectorBuilder, MaybeHttpsStream};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Builder as HyperClientBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use reqwest::Url;
use tower::util::BoxCloneSyncService;
use tower::ServiceExt;

const DEFAULT_CONNECTIONS_PER_ORIGIN: usize = 4;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configures an opt-in pool of independent HTTP clients per RPC origin.
///
/// Plain HTTP uses prior-knowledge h2c. HTTPS requires HTTP/2 through ALPN. Requests favor the
/// client with the fewest response bodies still in progress.
#[derive(Clone, Debug)]
pub struct BalancedHttp2Config {
    pub(crate) connections_per_origin: NonZeroUsize,
    pub(crate) request_timeout: Duration,
    pub(crate) tls_config: Option<Arc<ClientConfig>>,
}

impl BalancedHttp2Config {
    /// Sets the number of independent clients created for each distinct RPC origin.
    #[must_use]
    pub const fn with_connections_per_origin(
        mut self,
        connections_per_origin: NonZeroUsize,
    ) -> Self {
        self.connections_per_origin = connections_per_origin;
        self
    }

    /// Sets the unary RPC deadline and the maximum wait for streaming response headers.
    #[must_use]
    pub const fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Uses an application-provided TLS configuration for HTTPS origins.
    ///
    /// The transport replaces any configured ALPN protocols with HTTP/2.
    #[must_use]
    pub fn with_tls_config(mut self, tls_config: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(tls_config);
        self
    }
}

impl Default for BalancedHttp2Config {
    fn default() -> Self {
        Self {
            connections_per_origin: NonZeroUsize::new(DEFAULT_CONNECTIONS_PER_ORIGIN).unwrap(),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            tls_config: None,
        }
    }
}

pub(crate) type ErasedTransportError = std::io::Error;

/// Response body used by the type-erased Store client transport.
pub(crate) type ErasedResponseBody = BoxBody<Bytes, ErasedTransportError>;

struct SyncResponseBody<B> {
    inner: Mutex<Pin<Box<B>>>,
}

impl<B> SyncResponseBody<B> {
    fn new(body: B) -> Self {
        Self {
            inner: Mutex::new(Box::pin(body)),
        }
    }
}

impl<B> Body for SyncResponseBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.inner.lock().unwrap().as_mut().poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.lock().unwrap().is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.lock().unwrap().size_hint()
    }
}

trait DynClientTransport: Send + Sync {
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<ErasedResponseBody>, ErasedTransportError>>;
}

struct ClientTransportAdapter<T> {
    inner: T,
}

impl<T> DynClientTransport for ClientTransportAdapter<T>
where
    T: ClientTransport,
    <T::ResponseBody as Body>::Error: fmt::Display,
{
    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<ErasedResponseBody>, ErasedTransportError>> {
        let future = self.inner.send(request);
        Box::pin(async move {
            let response = future.await.map_err(std::io::Error::other)?;
            Ok(response.map(|body| {
                SyncResponseBody::new(body)
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .boxed()
            }))
        })
    }
}

/// Cloneable type erasure for a compatible connectrpc client transport.
#[derive(Clone)]
pub(crate) struct ErasedClientTransport {
    inner: Arc<dyn DynClientTransport>,
    metadata: Option<ClientMetadata>,
}

impl ErasedClientTransport {
    pub(crate) fn new<T>(transport: T) -> Self
    where
        T: ClientTransport,
        <T::ResponseBody as Body>::Error: fmt::Display,
    {
        Self {
            inner: Arc::new(ClientTransportAdapter { inner: transport }),
            metadata: None,
        }
    }

    pub(crate) fn with_metadata(mut self, authorization: Option<http::HeaderValue>) -> Self {
        let metadata = ClientMetadata::default();
        self.metadata = Some(match authorization {
            Some(value) => metadata.with_authorization(value),
            None => metadata,
        });
        self
    }
}

impl fmt::Debug for ErasedClientTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedClientTransport").finish()
    }
}

impl ClientTransport for ErasedClientTransport {
    type ResponseBody = ErasedResponseBody;
    type Error = ErasedTransportError;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let metadata = self.metadata.clone();
        let url = metadata
            .as_ref()
            .and_then(|metadata| metadata.prepare_request(&mut request));
        let future = self.inner.send(request);
        Box::pin(async move {
            let response = future.await?;
            let (parts, body) = response.into_parts();
            if let (Some(metadata), Some(url)) = (metadata, url) {
                metadata.store_set_cookies(&url, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

#[derive(Clone, Debug, Default)]
struct ClientMetadata {
    cookies: Arc<Mutex<CookieStore>>,
    authorization: Option<http::HeaderValue>,
}

impl ClientMetadata {
    fn with_authorization(mut self, value: http::HeaderValue) -> Self {
        self.authorization = Some(value);
        self
    }

    fn prepare_request(&self, request: &mut Request<ClientBody>) -> Option<Url> {
        let url = request_url(request.uri());
        if let Some(ref url) = url {
            if let Some(header) = self.cookie_header_for(url) {
                merge_cookie_header(request.headers_mut(), &header);
            }
        }

        request.headers_mut().insert(
            ACCEPT_ENCODING,
            http::HeaderValue::from_static("zstd, gzip"),
        );
        let streaming_encoding = Protocol::Connect.accept_encoding_header();
        if let Some(encoding) = request
            .headers_mut()
            .get_mut(streaming_encoding)
            .filter(|encoding| encoding.as_bytes() == b"gzip, zstd")
        {
            *encoding = http::HeaderValue::from_static("zstd, gzip");
        }

        if let Some(ref authorization) = self.authorization {
            apply_authorization(request.headers_mut(), authorization);
        }
        url
    }

    fn cookie_header_for(&self, url: &Url) -> Option<String> {
        let jar = self.cookies.lock().ok()?;
        let header = jar
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        (!header.is_empty()).then_some(header)
    }

    fn store_set_cookies(&self, url: &Url, headers: &http::HeaderMap) {
        let Ok(mut jar) = self.cookies.lock() else {
            return;
        };
        for val in headers.get_all(SET_COOKIE) {
            if let Ok(s) = val.to_str() {
                if let Some(cookie) = parse_set_cookie(s, url) {
                    let _ = jar.insert(cookie, url);
                }
            }
        }
    }
}

type RpcOrigin = (http::uri::Scheme, http::uri::Authority);

fn rpc_origin(uri: &http::Uri) -> Option<RpcOrigin> {
    Some((uri.scheme().cloned()?, uri.authority().cloned()?))
}

#[derive(Clone)]
struct BalancedConnection {
    client: Http2Client,
    pending: Arc<AtomicUsize>,
}

impl BalancedConnection {
    fn load(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    fn track(&self) -> PendingRequest {
        self.pending.fetch_add(1, Ordering::Relaxed);
        PendingRequest(self.pending.clone())
    }
}

struct BalancedOrigin {
    connections: Vec<BalancedConnection>,
    next: AtomicUsize,
}

impl BalancedOrigin {
    fn select(&self) -> BalancedConnection {
        let len = self.connections.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % len;
        (0..len)
            .map(|offset| &self.connections[(start + offset) % len])
            .min_by_key(|connection| connection.load())
            .expect("balanced origin always has a connection")
            .clone()
    }
}

struct PendingRequest(Arc<AtomicUsize>);

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

type BoxError = Box<dyn Error + Send + Sync>;
type Http2Stream = MaybeHttpsStream<TokioIo<tokio::net::TcpStream>>;
type Http2Connector = BoxCloneSyncService<http::Uri, Http2Stream, BoxError>;
type Http2Client = HyperClient<Http2Connector, ClientBody>;

async fn require_http2_alpn(stream: Http2Stream) -> Result<Http2Stream, BoxError> {
    let negotiated_h2 = match &stream {
        MaybeHttpsStream::Https(stream) => {
            stream.inner().get_ref().1.alpn_protocol() == Some(b"h2")
        }
        MaybeHttpsStream::Http(_) => false,
    };
    negotiated_h2
        .then_some(stream)
        .ok_or_else(|| std::io::Error::other("HTTPS server did not negotiate h2 with ALPN").into())
}

fn http2_builder() -> HyperClientBuilder {
    let mut builder = HyperClient::builder(TokioExecutor::new());
    builder
        .http2_only(true)
        .timer(TokioTimer::new())
        .http2_keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .http2_keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true);
    builder
}

fn http_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector
}

fn http_error(error: impl Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::other(format!(
        "HTTP/2 request failed: {:#}",
        anyhow::Error::new(error)
    ))
}

fn plaintext_http2() -> Http2Client {
    let connector = http_connector()
        .map_response(MaybeHttpsStream::Http)
        .map_err(|error| -> BoxError { Box::new(error) });
    http2_builder().build(BoxCloneSyncService::new(connector))
}

fn tls_http2(tls_config: Arc<ClientConfig>) -> Http2Client {
    let mut http = http_connector();
    http.enforce_http(false);

    // The connector owns ALPN and rejects preconfigured values.
    let mut tls_config = (*tls_config).clone();
    tls_config.alpn_protocols.clear();

    // connectrpc permits HTTP/1.1 fallback, so strict ALPN needs a local connector.
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .wrap_connector(http)
        .and_then(require_http2_alpn);
    http2_builder().build(BoxCloneSyncService::new(connector))
}

pub(crate) struct PendingResponseBody<B> {
    body: Pin<Box<B>>,
    pending: Option<PendingRequest>,
}

impl<B> PendingResponseBody<B> {
    fn new(body: B, pending: PendingRequest) -> Self {
        Self {
            body: Box::pin(body),
            pending: Some(pending),
        }
    }
}

impl<B> Body for PendingResponseBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let result = this.body.as_mut().poll_frame(cx);
        let finished = match &result {
            Poll::Ready(None | Some(Err(_))) => true,
            Poll::Ready(Some(Ok(_))) => this.body.is_end_stream(),
            Poll::Pending => false,
        };
        if finished {
            this.pending.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

/// Routes requests to independent clients for each distinct RPC origin.
#[derive(Clone)]
pub(crate) struct BalancedHttp2Transport {
    origins: Arc<HashMap<RpcOrigin, BalancedOrigin>>,
}

impl BalancedHttp2Transport {
    pub(crate) fn new(
        uris: impl IntoIterator<Item = http::Uri>,
        config: BalancedHttp2Config,
    ) -> Self {
        let mut origins = HashMap::new();

        for uri in uris {
            let origin =
                rpc_origin(&uri).expect("StoreClientBuilder validates RPC endpoint origins");
            let Entry::Vacant(entry) = origins.entry(origin) else {
                continue;
            };

            let scheme = uri.scheme_str();
            let connections = (0..config.connections_per_origin.get())
                .map(|_| {
                    let client = match scheme {
                        Some("http") => plaintext_http2(),
                        Some("https") => tls_http2(
                            config
                                .tls_config
                                .clone()
                                .expect("HTTPS origins always receive a TLS configuration"),
                        ),
                        _ => unreachable!("StoreClientBuilder validates RPC endpoint schemes"),
                    };
                    BalancedConnection {
                        client,
                        pending: Arc::new(AtomicUsize::new(0)),
                    }
                })
                .collect();
            entry.insert(BalancedOrigin {
                connections,
                next: AtomicUsize::new(0),
            });
        }

        Self {
            origins: Arc::new(origins),
        }
    }
}

impl ClientTransport for BalancedHttp2Transport {
    type ResponseBody = PendingResponseBody<Incoming>;
    type Error = std::io::Error;

    fn send(
        &self,
        request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let origin = rpc_origin(request.uri()).expect("connectrpc sends absolute request URIs");
        let pool = self
            .origins
            .get(&origin)
            .expect("the builder registers every RPC origin");
        let connection = pool.select();
        let pending = connection.track();
        Box::pin(async move {
            let response = connection
                .client
                .request(request)
                .await
                .map_err(http_error)?;
            Ok(response.map(|body| PendingResponseBody::new(body, pending)))
        })
    }
}

/// gzip + zstd - used for [`connectrpc::ConnectRpcService::with_compression`] and
/// [`connectrpc::client::ClientConfig::compression`].
#[must_use]
pub fn connect_compression_registry() -> CompressionRegistry {
    CompressionRegistry::default()
}

/// Wraps [`HttpClient`] with zstd first for the default response codecs (see module docs).
///
/// Also persists HTTP cookies: every `Set-Cookie` response header is stored in an RFC6265 jar and
/// replayed as `Cookie` when it matches a later request URL.
///
/// Carries the optional bearer credential too, so one place authenticates every RPC service
/// rather than each generated client doing it.
#[derive(Clone, Debug)]
pub struct PreferZstdHttpClient {
    plaintext: HttpClient,
    tls: Option<HttpClient>,
    metadata: ClientMetadata,
}

impl PreferZstdHttpClient {
    /// Creates a transport for HTTP endpoints.
    pub fn plaintext() -> Self {
        Self {
            plaintext: HttpClient::plaintext(),
            tls: None,
            metadata: ClientMetadata::default(),
        }
    }

    /// Creates a transport for HTTP and HTTPS endpoints using the provided TLS configuration.
    pub fn with_tls(tls_config: Arc<ClientConfig>) -> Self {
        Self {
            plaintext: HttpClient::plaintext(),
            tls: Some(HttpClient::with_tls(tls_config)),
            metadata: ClientMetadata::default(),
        }
    }

    /// Send `value` as `Authorization` on every RPC.
    ///
    /// Mark the value sensitive before passing it here so it stays redacted in `Debug` output.
    #[must_use]
    pub fn with_authorization(mut self, value: http::HeaderValue) -> Self {
        self.metadata = self.metadata.with_authorization(value);
        self
    }

    /// Render the `Cookie` header value for `url` from the jar, or `None` if it holds none.
    #[cfg(test)]
    fn cookie_header_for(&self, url: &Url) -> Option<String> {
        self.metadata.cookie_header_for(url)
    }

    /// Store every `Set-Cookie` in `headers` under `url`.
    #[cfg(test)]
    fn store_set_cookies(&self, url: &Url, headers: &http::HeaderMap) {
        self.metadata.store_set_cookies(url, headers);
    }
}

/// Parse one `Set-Cookie` header and reject cookies scoped to a public suffix.
fn parse_set_cookie(set_cookie: &str, url: &Url) -> Option<Cookie<'static>> {
    let cookie = Cookie::parse(set_cookie, url).ok()?;
    if let CookieDomain::Suffix(domain) = &cookie.domain {
        // `cookie_store` needs a dynamic suffix list; `psl` supplies the compiled Mozilla list.
        if psl::suffix(domain.as_bytes())
            .is_some_and(|suffix| suffix.is_known() && suffix == domain.as_str())
        {
            return None;
        }
    }
    Some(cookie.into_owned())
}

/// Convert an absolute HTTP URI into a URL usable by the cookie store.
fn request_url(uri: &http::Uri) -> Option<Url> {
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    let path_and_query = uri.path_and_query().map_or("/", |pq| pq.as_str());
    Url::parse(&format!("{scheme}://{authority}{path_and_query}")).ok()
}

impl ClientTransport for PreferZstdHttpClient {
    type ResponseBody = hyper::body::Incoming;
    type Error = ConnectError;

    fn send(
        &self,
        mut request: Request<ClientBody>,
    ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
        let transport = match request.uri().scheme_str() {
            Some("http") => self.plaintext.clone(),
            Some("https") => match &self.tls {
                Some(tls) => tls.clone(),
                None => {
                    return Box::pin(async {
                        Err(ConnectError::invalid_argument(
                            "HTTPS endpoint requires a TLS transport",
                        ))
                    });
                }
            },
            scheme => {
                let message = format!("unsupported endpoint URL scheme {scheme:?}");
                return Box::pin(async move { Err(ConnectError::invalid_argument(message)) });
            }
        };
        let url = self.metadata.prepare_request(&mut request);

        let this = self.clone();
        Box::pin(async move {
            let response = transport.send(request).await?;
            let (parts, body) = response.into_parts();
            if let Some(url) = url {
                this.metadata.store_set_cookies(&url, &parts.headers);
            }
            Ok(Response::from_parts(parts, body))
        })
    }
}

/// Set the client's credential as `Authorization`, leaving any caller-supplied one alone.
///
/// Deferring to the caller matches how jar cookies defer to caller-supplied cookie names, and it
/// is what lets one client reach a deployment that expects a different credential on a specific
/// call.
fn apply_authorization(headers: &mut http::HeaderMap, value: &http::HeaderValue) {
    if !headers.contains_key(AUTHORIZATION) {
        headers.insert(AUTHORIZATION, value.clone());
    }
}

/// Add jar cookies to existing `Cookie` headers without overriding caller-supplied names.
fn merge_cookie_header(headers: &mut http::HeaderMap, jar_header: &str) {
    let mut readable = Vec::new();
    let mut has_opaque = false;
    for value in headers.get_all(COOKIE) {
        match value.to_str() {
            Ok(value) => readable.push(value.to_string()),
            Err(_) => has_opaque = true,
        }
    }

    // All existing cookies are readable: merge into a single clean Cookie header.
    if !has_opaque {
        let merged = if readable.is_empty() {
            jar_header.to_string()
        } else {
            merge_cookie_values(readable.iter().map(String::as_str), jar_header)
        };
        insert_cookie_header(headers, &merged);
        return;
    }

    // Some existing cookies have opaque values and cannot be merged into a string. Leave the
    // existing headers in place, but still read names from raw header bytes so jar cookies never
    // duplicate caller-supplied names.
    let existing_names = cookie_names_from_headers(headers);
    let additions = jar_cookies_excluding(&existing_names, jar_header);
    if !additions.is_empty() {
        append_cookie_header(headers, &additions);
    }
}

/// Replace all existing `Cookie` headers with one validated header value.
fn insert_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.insert(COOKIE, value);
    }
}

/// Append one validated `Cookie` header value without disturbing existing headers.
fn append_cookie_header(headers: &mut http::HeaderMap, value: &str) {
    if let Ok(value) = http::HeaderValue::from_str(value) {
        headers.append(COOKIE, value);
    }
}

/// Merge readable caller cookie values with jar cookies, preserving caller values on name collision.
fn merge_cookie_values<'a>(
    existing_values: impl IntoIterator<Item = &'a str>,
    jar_header: &str,
) -> String {
    let mut merged = Vec::new();
    let mut existing_names = BTreeSet::new();

    for value in existing_values {
        for cookie in split_cookies(value) {
            if let Some(name) = cookie_name(cookie) {
                existing_names.insert(name.as_bytes().to_vec());
            }
            merged.push(cookie.to_string());
        }
    }

    let additions = jar_cookies_excluding(&existing_names, jar_header);
    if !additions.is_empty() {
        merged.push(additions);
    }

    merged.join("; ")
}

/// Jar cookies whose names are not already present in `existing_names`, rendered as a `Cookie` line.
/// Jar names never override caller-supplied ones.
fn jar_cookies_excluding(existing_names: &BTreeSet<Vec<u8>>, jar_header: &str) -> String {
    split_cookies(jar_header)
        .filter(|cookie| match cookie_name(cookie) {
            Some(name) => !existing_names.contains(name.as_bytes()),
            None => true,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Collect cookie names from raw `Cookie` headers, including ones with opaque values.
fn cookie_names_from_headers(headers: &http::HeaderMap) -> BTreeSet<Vec<u8>> {
    let mut names = BTreeSet::new();
    for value in headers.get_all(COOKIE) {
        for cookie in split_cookie_bytes(value.as_bytes()) {
            if let Some(name) = cookie_name_bytes(cookie) {
                names.insert(name.to_vec());
            }
        }
    }
    names
}

/// Split a `Cookie` header body into non-empty `name=value` fragments.
fn split_cookies(value: &str) -> impl Iterator<Item = &str> {
    value.split(';').map(str::trim).filter(|s| !s.is_empty())
}

/// Split a raw `Cookie` header body into non-empty `name=value` fragments.
fn split_cookie_bytes(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|b| *b == b';')
        .map(trim_cookie_bytes)
        .filter(|s| !s.is_empty())
}

/// Return the non-empty name before the first `=` in a cookie fragment.
fn cookie_name(cookie: &str) -> Option<&str> {
    let (name, _) = cookie.split_once('=')?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Return the non-empty raw name before the first `=` in a cookie fragment.
fn cookie_name_bytes(cookie: &[u8]) -> Option<&[u8]> {
    let eq = cookie.iter().position(|b| *b == b'=')?;
    let name = trim_cookie_bytes(&cookie[..eq]);
    if name.is_empty() {
        return None;
    }
    Some(name)
}

/// Trim HTTP optional whitespace around cookie fragments.
fn trim_cookie_bytes(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| !matches!(*b, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| !matches!(*b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    &value[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Debug, Default)]
    struct ScriptedTransport {
        calls: Arc<AtomicUsize>,
        requests: Arc<Mutex<Vec<http::HeaderMap>>>,
    }

    impl ClientTransport for ScriptedTransport {
        type ResponseBody = http_body_util::Empty<Bytes>;
        type Error = ConnectError;

        fn send(
            &self,
            request: Request<ClientBody>,
        ) -> BoxFuture<'static, Result<Response<Self::ResponseBody>, Self::Error>> {
            self.requests
                .lock()
                .unwrap()
                .push(request.headers().clone());
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let mut response = Response::new(http_body_util::Empty::new());
                if call == 0 {
                    response
                        .headers_mut()
                        .insert(SET_COOKIE, "AWSALB=sticky; Path=/".parse().unwrap());
                }
                Ok(response)
            })
        }
    }

    fn request(uri: &str) -> Request<ClientBody> {
        Request::post(uri)
            .body(connectrpc::client::full_body(Bytes::new()))
            .unwrap()
    }

    /// Parse a test URL literal.
    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    /// Build a header map containing the supplied `Set-Cookie` values.
    fn set_cookie_headers(values: &[&str]) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        for v in values {
            headers.append(SET_COOKIE, v.parse().unwrap());
        }
        headers
    }

    #[test]
    fn transport_modes_report_tls_support() {
        let plaintext = PreferZstdHttpClient::plaintext();
        assert!(plaintext.tls.is_none());

        let tls_config = ClientConfig::builder()
            .with_root_certificates(connectrpc::rustls::RootCertStore::empty())
            .with_no_client_auth();
        let tls = PreferZstdHttpClient::with_tls(Arc::new(tls_config));
        assert!(tls.tls.is_some());
    }

    #[tokio::test]
    async fn metadata_wraps_a_supplied_transport_and_persists_cookies() {
        let raw = ScriptedTransport::default();
        let transport = ErasedClientTransport::new(raw.clone())
            .with_metadata(Some("Bearer token".parse().unwrap()));

        transport
            .send(request("http://query.internal/rpc/first"))
            .await
            .unwrap();
        transport
            .send(request("http://query.internal/rpc/second"))
            .await
            .unwrap();

        let requests = raw.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for headers in requests.iter() {
            assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer token");
            assert_eq!(headers.get(ACCEPT_ENCODING).unwrap(), "zstd, gzip");
        }
        assert_eq!(requests[1].get(COOKIE).unwrap(), "AWSALB=sticky");
    }

    #[test]
    fn balanced_transport_builds_one_pool_per_distinct_origin() {
        let transport = BalancedHttp2Transport::new(
            [
                "http://one.internal/a".parse().unwrap(),
                "http://one.internal/b".parse().unwrap(),
                "http://two.internal/a".parse().unwrap(),
            ],
            BalancedHttp2Config::default(),
        );

        assert_eq!(transport.origins.len(), 2);
    }

    #[tokio::test]
    async fn pending_load_ends_with_the_response_body() {
        let pending = Arc::new(AtomicUsize::new(0));
        pending.fetch_add(1, Ordering::Relaxed);
        let mut body = PendingResponseBody::new(
            http_body_util::Full::new(Bytes::from_static(b"frame")),
            PendingRequest(pending.clone()),
        );

        assert_eq!(pending.load(Ordering::Relaxed), 1);
        assert!(body.frame().await.unwrap().unwrap().is_data());
        assert_eq!(pending.load(Ordering::Relaxed), 0);
        assert!(body.frame().await.is_none());
    }

    #[test]
    fn host_only_cookies_are_scoped_per_host() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://query.internal:80/rpc"),
            &set_cookie_headers(&["AWSALB=hostA; Path=/"]),
        );
        client.store_set_cookies(
            &url("https://ingest.internal:80/rpc"),
            &set_cookie_headers(&["AWSALB=hostB; Path=/"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://query.internal:80/rpc"))
                .as_deref(),
            Some("AWSALB=hostA")
        );
        assert_eq!(
            client
                .cookie_header_for(&url("https://ingest.internal:80/rpc"))
                .as_deref(),
            Some("AWSALB=hostB")
        );
        assert_eq!(
            client.cookie_header_for(&url("https://other.internal:80/rpc")),
            None
        );
    }

    #[test]
    fn cookie_hosts_are_case_insensitive() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://API.example.com/rpc"),
            &set_cookie_headers(&["AWSALB=stick; Path=/"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://api.example.com/rpc"))
                .as_deref(),
            Some("AWSALB=stick")
        );
    }

    #[test]
    fn domain_and_path_matching_are_honored() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://api.example.com/rpc/create"),
            &set_cookie_headers(&["session=one; Domain=example.com; Path=/rpc"]),
        );

        assert_eq!(
            client
                .cookie_header_for(&url("https://query.example.com/rpc/read"))
                .as_deref(),
            Some("session=one")
        );
        assert_eq!(
            client.cookie_header_for(&url("https://query.example.com/other")),
            None
        );
    }

    #[test]
    fn public_suffix_domain_cookies_are_rejected() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://api.example.com/rpc"),
            &set_cookie_headers(&["leak=1; Domain=com; Path=/"]),
        );

        assert_eq!(
            client.cookie_header_for(&url("https://api.example.com/rpc")),
            None
        );
        assert_eq!(
            client.cookie_header_for(&url("https://other.com/rpc")),
            None
        );
    }

    #[test]
    fn expired_set_cookie_removes_cookie_from_jar() {
        let client = PreferZstdHttpClient::plaintext();

        client.store_set_cookies(
            &url("https://edge.internal/rpc"),
            &set_cookie_headers(&["AWSALB=abc; Path=/"]),
        );
        assert_eq!(
            client
                .cookie_header_for(&url("https://edge.internal/rpc"))
                .as_deref(),
            Some("AWSALB=abc")
        );

        client.store_set_cookies(
            &url("https://edge.internal/rpc"),
            &set_cookie_headers(&["AWSALB=; Max-Age=0; Path=/"]),
        );

        assert_eq!(
            client.cookie_header_for(&url("https://edge.internal/rpc")),
            None
        );
    }

    #[test]
    fn request_url_preserves_path_and_query() {
        assert_eq!(
            request_url(&"https://edge.internal/rpc?x=1".parse().unwrap()).as_ref(),
            Some(&url("https://edge.internal/rpc?x=1"))
        );
    }

    #[test]
    fn request_url_rejects_origin_form_uri() {
        assert_eq!(request_url(&"/rpc?x=1".parse().unwrap()), None);
    }

    #[test]
    fn merge_cookie_values_appends_jar_cookies_to_existing_cookies() {
        assert_eq!(
            merge_cookie_values(["caller=token"].into_iter(), "AWSALB=abc; AWSALBCORS=def"),
            "caller=token; AWSALB=abc; AWSALBCORS=def"
        );
    }

    #[test]
    fn merge_cookie_values_keeps_existing_cookie_on_name_collision() {
        assert_eq!(
            merge_cookie_values(
                ["AWSALB=caller; app=session"].into_iter(),
                "AWSALB=jar; AWSALBCORS=jarcors"
            ),
            "AWSALB=caller; app=session; AWSALBCORS=jarcors"
        );
    }

    #[test]
    fn merge_cookie_header_preserves_existing_call_options_cookie() {
        let mut headers = http::HeaderMap::new();
        headers.append(COOKIE, "caller=token".parse().unwrap());
        headers.append(COOKIE, "app=session".parse().unwrap());

        merge_cookie_header(&mut headers, "AWSALB=abc");

        assert_eq!(
            headers.get(COOKIE).and_then(|v| v.to_str().ok()),
            Some("caller=token; app=session; AWSALB=abc")
        );
        assert_eq!(headers.get_all(COOKIE).iter().count(), 1);
    }

    #[test]
    fn merge_cookie_header_checks_opaque_cookie_names_before_appending_jar() {
        let mut headers = http::HeaderMap::new();
        // A Cookie value with an opaque value cannot be merged into a string, but its ASCII name is
        // still available from the raw header bytes.
        headers.append(
            COOKIE,
            http::HeaderValue::from_bytes(b"opaque=\xff\xfe").unwrap(),
        );
        headers.append(COOKIE, "caller=token".parse().unwrap());

        merge_cookie_header(&mut headers, "AWSALB=abc; opaque=jar; caller=jar");

        // The opaque and readable existing headers survive, and only the jar cookie that does not
        // collide with either existing name is appended as a separate Cookie header.
        let values: Vec<_> = headers
            .get_all(COOKIE)
            .iter()
            .map(|v| v.as_bytes().to_vec())
            .collect();
        assert_eq!(values.len(), 3);
        assert!(values.contains(&b"opaque=\xff\xfe".to_vec()));
        assert!(values.contains(&b"caller=token".to_vec()));
        assert!(values.contains(&b"AWSALB=abc".to_vec()));
        assert!(!values.contains(&b"opaque=jar".to_vec()));
    }

    #[test]
    fn authorization_is_set_when_absent() {
        let mut headers = http::HeaderMap::new();

        apply_authorization(&mut headers, &"Bearer client".parse().unwrap());

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer client");
    }

    #[test]
    fn authorization_defers_to_the_caller() {
        let mut headers = http::HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer caller".parse().unwrap());

        apply_authorization(&mut headers, &"Bearer client".parse().unwrap());

        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer caller");
        assert_eq!(headers.get_all(AUTHORIZATION).iter().count(), 1);
    }

    #[test]
    fn no_credential_sends_no_authorization() {
        let client = PreferZstdHttpClient::plaintext();

        // A deployment with no load balancer in front of it must still be reachable.
        assert!(client.metadata.authorization.is_none());
    }
}
