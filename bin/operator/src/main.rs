//! Payment-channel operator process for load testing and the paid-stream
//! demo.
//!
//! The operator owns the settling key for payer-created channels, accepts
//! off-chain vouchers over HTTP, enforces monotonic/deposit accounting, and
//! submits the final close transaction through the relayer. Settlements pay
//! each channel's named receiver; the operator itself earns nothing (fees are
//! deliberately out of scope). All of that logic
//! lives in [`constantinople_application::operator::service::OperatorService`];
//! this binary is the HTTP surface plus the real relayer/indexer adapters.
//!
//! `GET /stream` is the demo's metered service (the x402 shape): it sells a
//! fixed essay token by token over SSE, streaming only while the channel's
//! debt stays under [`STREAM_DEBT_LIMIT`], pausing at the limit, and hanging
//! up if no voucher arrives within [`STREAM_GRACE`]. Requests without a
//! servable channel answer `402 Payment Required`; pricing is advertised on
//! `/public-key` next to the margins. Unpaid exposure is bounded at
//! [`STREAM_DEBT_LIMIT`] per channel, but nothing caps *connections*: one
//! registered channel may hold any number of concurrent streams (each is a
//! task plus a socket for at most the grace window once credit runs out).
//! Fine for demo infrastructure; a production deployment would cap
//! concurrent streams per channel and per peer.
//!
//! Known restart limitation: channel registrations (and their voucher
//! accounting) live only in memory. Registration verifies that the open
//! transaction finalized, not that the channel is still live, so after a
//! restart an already-settled channel can be re-registered and its old
//! vouchers replayed for free service. Only the operator's own revenue is at
//! stake, which is acceptable for load-test infrastructure; a durable channel
//! store (or an account-key state lookup to check the channel still exists)
//! would be needed to close this.

mod content;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use clap::Parser;
use commonware_codec::DecodeExt;
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::MinSig, certificate::Verifier as _, ed25519,
};
use commonware_deployer::aws::Hosts;
use commonware_runtime::Runner as _;
use commonware_storage::{
    merkle::mmr,
    qmdb::{any::value::FixedEncoding, keyless},
};
use constantinople_application::operator::service::{
    ChainReader, ConsumeOutcome, Digest, Margins, MeterSnapshot, OperatorError, OperatorService,
    Relayer, SettleOutcome, SubmitOutcome, Tx, VerifiedOpenChannel,
};
use constantinople_engine::ThresholdScheme;
use constantinople_indexer::IndexerClient;
use constantinople_mempool::webserver::{TxStatus, client::Client};
use constantinople_primitives::{
    AccountKey, Nonce, Operation, SignedTransaction, TransactionPublicKey,
    operator_api::{
        ErrorResponse, PublicKeyResponse, RegisterRequest, RegisterResponse, STREAM_CHUNK_EVENT,
        STREAM_END_EVENT, STREAM_PAYMENT_REQUIRED_EVENT, SettleRequest, SettleResponse,
        StatsResponse, StreamChunk, StreamEnd, StreamEndReason, StreamMeter, VoucherRequest,
        VoucherResponse, parse_channel,
    },
    operator_config::{
        DEFAULT_HTTP_PORT, DEFAULT_LISTEN_ADDR, DEFAULT_MIN_RUNWAY, DEFAULT_OPERATOR_SEED,
        DEFAULT_SETTLE_MARGIN, OperatorConfig,
    },
};
use exoware_qmdb::{OperationLogClient, proto::qmdb::v1::GetOperationRangeRequest};
use exoware_sdk::{StoreClient, proto::PreferZstdHttpClient};
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tracing::{info, warn};

type QmdbFamily = mmr::Family;
type TransactionEncoding = FixedEncoding<Digest>;
type TransactionOperation = keyless::Operation<QmdbFamily, TransactionEncoding>;
type TransactionProofClient =
    OperationLogClient<PreferZstdHttpClient, QmdbFamily, Sha256, TransactionOperation>;
type ConsensusScheme = ThresholdScheme<ed25519::PublicKey, MinSig>;
type Service = OperatorService<commonware_runtime::tokio::Context, RelayerAdapter, ChannelVerifier>;

/// HTTP-layer state beside the chain-facing operator service.
struct AppState {
    service: Arc<Service>,
    /// Capabilities are retained beside the service's in-memory channel state.
    capabilities: tokio::sync::RwLock<BTreeMap<AccountKey, String>>,
}

impl AppState {
    fn new(service: Arc<Service>) -> Self {
        Self {
            service,
            capabilities: tokio::sync::RwLock::new(BTreeMap::new()),
        }
    }

    /// Issues fresh OS-random bearer material for a new channel. Concurrent
    /// and later idempotent registration replays retain the original value.
    async fn issue_capability(&self, channel: AccountKey) -> String {
        let mut capabilities = self.capabilities.write().await;
        capabilities
            .entry(channel)
            .or_insert_with(generate_capability)
            .clone()
    }

    async fn authorizes(&self, channel: &AccountKey, presented: &str) -> bool {
        self.capabilities
            .read()
            .await
            .get(channel)
            .is_some_and(|expected| capability_matches(expected, presented))
    }
}

const HEIGHT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const SETTLEMENT_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Chain units one streamed token costs on `GET /stream`. Advertised on
/// `/public-key` so clients price their vouchers from configuration, not
/// convention.
const STREAM_PRICE_PER_TOKEN: u64 = 1;
/// Chain units of unpaid content a stream may run ahead of the channel's
/// latest voucher before it pauses. Bounds the operator's exposure to a
/// payer that stops paying. Advertised alongside the price.
const STREAM_DEBT_LIMIT: u64 = 32;
/// How long a paused stream waits for a fresher voucher before ending.
const STREAM_GRACE: Duration = Duration::from_secs(5);
/// How often a paused stream re-checks its channel's credit.
const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Delay between streamed tokens (the typewriter pace).
const STREAM_PACE: Duration = Duration::from_millis(50);
#[derive(Debug, Parser)]
#[command(name = "constantinople-operator")]
struct Cli {
    /// Path to the operator config YAML.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Path to the deployer-generated hosts file.
    #[arg(long)]
    hosts: Option<PathBuf>,

    /// HTTP port to listen on.
    #[arg(long, default_value_t = DEFAULT_HTTP_PORT)]
    port: u16,

    /// HTTP bind address.
    #[arg(long, default_value_t = DEFAULT_LISTEN_ADDR)]
    listen_addr: IpAddr,

    /// Relayer base URL for close transaction submission.
    #[arg(long)]
    relayer_url: Option<String>,

    /// Chain indexer Store base URL.
    #[arg(long)]
    indexer_url: Option<String>,

    /// Transaction QMDB proof service base URL.
    #[arg(long)]
    qmdb_url: Option<String>,

    /// Deterministic operator key seed (the key that settles channels).
    #[arg(long, default_value_t = DEFAULT_OPERATOR_SEED)]
    operator_seed: u64,

    /// Minimum blocks between registration and a channel's expiry.
    #[arg(long, default_value_t = DEFAULT_MIN_RUNWAY)]
    min_runway: u64,

    /// Blocks before expiry at which vouchers stop and settlement starts.
    #[arg(long, default_value_t = DEFAULT_SETTLE_MARGIN)]
    settle_margin: u64,
}

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().init();

    let config = operator_config(cli);

    let runtime_cfg = commonware_runtime::tokio::Config::default();
    let runner = commonware_runtime::tokio::Runner::new(runtime_cfg);
    runner.start(|context| async move {
        let operator = ed25519::PrivateKey::from_seed(config.operator_seed);
        let verifier = ChannelVerifier::new(config.indexer_url, config.qmdb_url);
        let relayer = RelayerAdapter {
            client: Client::new(config.relayer_url.trim_end_matches('/')),
        };
        let service = Arc::new(
            OperatorService::init(
                context,
                relayer,
                verifier,
                operator,
                Margins {
                    min_runway: config.min_runway,
                    settle_margin: config.settle_margin,
                },
            )
            .await,
        );
        tokio::spawn(track_height(service.clone()));
        tokio::spawn(settlement_sweep(service.clone()));
        let state = Arc::new(AppState::new(service));

        let addr = SocketAddr::new(config.listen_addr, config.http_port);
        let app = Router::new()
            .route("/health", get(health))
            .route("/public-key", get(public_key))
            .route("/stats", get(stats))
            .route("/channels", post(register_channel))
            .route("/vouchers", post(serve_voucher))
            .route("/settle", post(settle_channel))
            .route("/stream", get(stream_content))
            // The explorer polls /stats from the browser (a different
            // origin), so answer preflights like the indexer facades do.
            .layer(tower_http::cors::CorsLayer::very_permissive())
            .with_state(state);

        info!(%addr, "constantinople operator listening");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("operator HTTP bind failed");
        axum::serve(listener, app)
            .await
            .expect("operator HTTP failed");
    });
}

/// Resolves the runtime configuration: the YAML file (with hosts-file URL
/// resolution) when `--config` is given, bare CLI flags otherwise.
fn operator_config(cli: Cli) -> OperatorConfig {
    if let Some(config_path) = cli.config {
        let raw = std::fs::read_to_string(config_path).expect("failed to read operator config");
        let mut config: OperatorConfig =
            serde_yaml::from_str(&raw).expect("failed to parse operator config");
        let hosts = cli.hosts.as_deref().map(load_hosts);
        config.relayer_url = resolve_named_http_url(&config.relayer_url, hosts.as_ref());
        config.indexer_url = resolve_named_http_url(&config.indexer_url, hosts.as_ref());
        config.qmdb_url = resolve_named_http_url(&config.qmdb_url, hosts.as_ref());
        return config;
    }

    OperatorConfig {
        http_port: cli.port,
        listen_addr: cli.listen_addr,
        relayer_url: cli.relayer_url.expect("provide --relayer-url or --config"),
        indexer_url: cli.indexer_url.expect("provide --indexer-url or --config"),
        qmdb_url: cli.qmdb_url.expect("provide --qmdb-url or --config"),
        operator_seed: cli.operator_seed,
        min_runway: cli.min_runway,
        settle_margin: cli.settle_margin,
    }
}

/// Loads the deployer-generated hosts file into a name-to-IP map.
fn load_hosts(path: &Path) -> BTreeMap<String, IpAddr> {
    let raw = std::fs::read_to_string(path).expect("failed to read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&raw).expect("failed to parse hosts file");
    hosts
        .hosts
        .into_iter()
        .map(|host| (host.name, host.ip))
        .collect()
}

fn resolve_named_http_url(url: &str, hosts: Option<&BTreeMap<String, IpAddr>>) -> String {
    let Some(hosts) = hosts else {
        return url.to_string();
    };
    constantinople_primitives::resolve_named_http_url(url, |name| hosts.get(name).copied())
}

fn generate_capability() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    hex_lower(&secret)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Compares fixed-size bearer secrets without leaking the matching prefix.
fn capability_matches(expected: &str, presented: &str) -> bool {
    if expected.len() != presented.len() {
        return false;
    }
    expected
        .bytes()
        .zip(presented.bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

async fn health() -> &'static str {
    "ok"
}

/// Keeps the service's height cache tracking the latest finalized height.
async fn track_height(service: Arc<Service>) {
    loop {
        if let Err(error) = service.refresh_height().await {
            warn!(%error, "latest height lookup failed");
        }
        tokio::time::sleep(HEIGHT_POLL_INTERVAL).await;
    }
}

/// Runs a settlement as an owned task and returns its handle.
///
/// `settle_channel` is not cancellation-safe: it mutates multi-step state
/// (the `Settling` flag, a reserved nonce) across awaits, so dropping its
/// future mid-flight strands the channel and leaks the nonce. In particular
/// it must never be awaited directly from a request handler — hyper drops
/// that future when the client disconnects. Every settlement goes through
/// here; the task logs its own failure so callers may drop the handle.
fn spawn_settlement(
    service: Arc<Service>,
    channel: AccountKey,
) -> tokio::task::JoinHandle<Result<SettleOutcome, OperatorError>> {
    tokio::spawn(async move {
        let outcome = service.settle_channel(channel).await;
        if let Err(error) = &outcome {
            warn!(%channel, %error, "settlement failed");
        }
        outcome
    })
}

/// Force-settles voucher-bearing channels approaching their expiry.
async fn settlement_sweep(service: Arc<Service>) {
    loop {
        tokio::time::sleep(SETTLEMENT_SWEEP_INTERVAL).await;
        for channel in service.due_settlements().await {
            info!(%channel, height = service.height(), "expiry approaching, force-settling channel");
            spawn_settlement(service.clone(), channel);
        }
    }
}

async fn public_key(State(state): State<Arc<AppState>>) -> Json<PublicKeyResponse> {
    let service = &state.service;
    let margins = service.margins();
    Json(PublicKeyResponse::new(
        service.operator_public_key(),
        service.height(),
        margins.min_runway,
        margins.settle_margin,
        STREAM_PRICE_PER_TOKEN,
        STREAM_DEBT_LIMIT,
        content::tokens().len() as u64,
    ))
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<StatsResponse> {
    let service = &state.service;
    let stats = service.stats().await;
    Json(StatsResponse {
        channels: stats.channels,
        settled: stats.settled,
        abandoned: stats.abandoned,
        vouchers: stats.vouchers,
        streamed: stats.streamed,
        height: service.height(),
    })
}

async fn register_channel(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let open_tx_digest = request
        .open_tx_digest::<Digest>()
        .map_err(ApiError::bad_request)?;
    let zero_voucher = request.zero_voucher().map_err(ApiError::bad_request)?;

    let (channel, registered) = state
        .service
        .register_channel(&open_tx_digest, zero_voucher)
        .await?;
    let capability = state.issue_capability(channel).await;
    Ok(Json(RegisterResponse {
        registered,
        capability,
    }))
}

async fn serve_voucher(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VoucherRequest>,
) -> Result<Json<VoucherResponse>, ApiError> {
    let voucher = request.voucher().map_err(ApiError::bad_request)?;
    let cumulative = state.service.serve_voucher(voucher).await?;
    Ok(Json(VoucherResponse { cumulative }))
}

async fn settle_channel(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, ApiError> {
    let channel = request.channel().map_err(ApiError::bad_request)?;
    if !state.authorizes(&channel, &request.capability).await {
        return Err(ApiError::forbidden("invalid channel capability"));
    }
    let outcome = spawn_settlement(state.service.clone(), channel)
        .await
        .map_err(|error| {
            ApiError::from(OperatorError::unavailable(format!(
                "settlement task failed: {error}"
            )))
        })??;
    Ok(Json(SettleResponse {
        settled: outcome.settled,
        cumulative: outcome.cumulative,
    }))
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    channel: Option<String>,
    capability: Option<String>,
}

/// The x402 handshake: `GET /stream` without a servable, registered channel
/// answers `402 Payment Required`. Pricing is advertised on `/public-key`.
fn payment_required(message: impl ToString) -> Response {
    ApiError {
        status: StatusCode::PAYMENT_REQUIRED,
        message: message.to_string(),
    }
    .into_response()
}

/// `GET /stream?channel=<hex>`: the metered demo service. Streams the essay
/// token by token over SSE while the channel's debt stays under
/// [`STREAM_DEBT_LIMIT`], pausing (then hanging up) when payment falls
/// behind. Content position derives from the channel's served total, so a
/// reconnect resumes where the meter left off.
async fn stream_content(
    State(state): State<Arc<AppState>>,
    Query(query): Query<StreamQuery>,
) -> Response {
    let Some(channel) = query.channel else {
        return payment_required("open and register a channel, then pass ?channel=<hex>");
    };
    let channel = match parse_channel(&channel) {
        Ok(channel) => channel,
        Err(error) => return payment_required(error),
    };
    let Some(capability) = query.capability else {
        return payment_required("registration capability required");
    };
    if !state.authorizes(&channel, &capability).await {
        return payment_required("invalid channel capability");
    }
    // Zero-cost probe: surfaces an unregistered or closed channel as the
    // 402 handshake instead of an empty stream.
    let meter = match state
        .service
        .consume_bounded(&channel, 0, STREAM_DEBT_LIMIT, stream_content_limit())
        .await
    {
        Ok(
            ConsumeOutcome::Served(meter)
            | ConsumeOutcome::PaymentRequired(meter)
            | ConsumeOutcome::DepositExhausted(meter)
            | ConsumeOutcome::ContentExhausted(meter),
        ) => meter,
        Err(error) => return payment_required(error),
    };

    let session = StreamSession {
        service: state.service.clone(),
        channel,
        meter,
        grace_deadline: None,
        done: false,
    };
    let stream = futures::stream::unfold(session, |mut session| async move {
        if session.done {
            return None;
        }
        let event = session.next_event().await;
        Some((Ok::<_, std::convert::Infallible>(event), session))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

/// Maximum chain-unit meter value backed by actual stream content.
fn stream_content_limit() -> u64 {
    u64::try_from(content::tokens().len())
        .expect("stream token count fits u64")
        .saturating_mul(STREAM_PRICE_PER_TOKEN)
}

/// One client's stream position: the channel it pays with, the last meter
/// the service reported, and the pause bookkeeping.
struct StreamSession {
    service: Arc<Service>,
    channel: AccountKey,
    meter: MeterSnapshot,
    /// When a paused stream gives up, set at the start of each pause and
    /// cleared by the voucher that resumes it.
    grace_deadline: Option<tokio::time::Instant>,
    done: bool,
}

impl StreamSession {
    /// Produces the next SSE event, sleeping through pacing and payment
    /// pauses. Terminal events flag the session done so the stream closes
    /// after emitting them.
    async fn next_event(&mut self) -> Event {
        loop {
            // Pace before charging: a client that disconnects mid-pace has
            // paid for nothing undelivered (charging first would strand the
            // in-flight token — a resume skips past it). A paused stream has
            // its own poll cadence and skips the pace.
            if self.grace_deadline.is_none() {
                tokio::time::sleep(STREAM_PACE).await;
            }
            match self
                .service
                .consume_bounded(
                    &self.channel,
                    STREAM_PRICE_PER_TOKEN,
                    STREAM_DEBT_LIMIT,
                    stream_content_limit(),
                )
                .await
            {
                Ok(ConsumeOutcome::Served(meter)) => {
                    self.meter = meter;
                    self.grace_deadline = None;
                    // The token the atomic bounded charge bought, derived from
                    // the returned shared meter. Concurrent sessions may split
                    // the content, but none can advance past its final token.
                    let index = (meter.served / STREAM_PRICE_PER_TOKEN - 1) as usize;
                    let text = content::tokens()
                        .get(index)
                        .expect("bounded consume only advances over existing content");
                    return event(
                        STREAM_CHUNK_EVENT,
                        &StreamChunk {
                            text: (*text).into(),
                            served: meter.served,
                            paid: meter.paid,
                        },
                    );
                }
                Ok(ConsumeOutcome::PaymentRequired(meter)) => {
                    self.meter = meter;
                    // First refusal of this pause: tell the client and start
                    // the grace clock. After that, poll quietly — a fresher
                    // voucher resumes the loop, the deadline ends it.
                    match self.grace_deadline {
                        None => {
                            self.grace_deadline = Some(tokio::time::Instant::now() + STREAM_GRACE);
                            return event(
                                STREAM_PAYMENT_REQUIRED_EVENT,
                                &StreamMeter {
                                    served: meter.served,
                                    paid: meter.paid,
                                },
                            );
                        }
                        Some(deadline) if tokio::time::Instant::now() >= deadline => {
                            return self.end(StreamEndReason::PaymentTimeout);
                        }
                        Some(_) => tokio::time::sleep(STREAM_POLL_INTERVAL).await,
                    }
                }
                Ok(ConsumeOutcome::DepositExhausted(meter)) => {
                    self.meter = meter;
                    return self.end(StreamEndReason::DepositExhausted);
                }
                Ok(ConsumeOutcome::ContentExhausted(meter)) => {
                    self.meter = meter;
                    return self.end(StreamEndReason::Complete);
                }
                Err(_) => return self.end(StreamEndReason::ChannelClosed),
            }
        }
    }

    fn end(&mut self, reason: StreamEndReason) -> Event {
        self.done = true;
        event(
            STREAM_END_EVENT,
            &StreamEnd {
                reason,
                served: self.meter.served,
                paid: self.meter.paid,
            },
        )
    }
}

/// Builds a named SSE event from one of the wire payload types.
fn event<T: serde::Serialize>(name: &str, data: &T) -> Event {
    Event::default()
        .event(name)
        .json_data(data)
        .expect("stream wire types serialize")
}

/// Submits operator transactions through the relayer.
struct RelayerAdapter {
    client: Client,
}

impl Relayer for RelayerAdapter {
    async fn submit(&self, tx: Tx) -> Result<SubmitOutcome, String> {
        let batch = [tx];
        let status = self
            .client
            .submit(&batch)
            .await
            .map_err(|error| error.to_string())?;
        Ok(
            included_height(&status).map_or(SubmitOutcome::Excluded, |height| {
                SubmitOutcome::Included { height }
            }),
        )
    }

    async fn fetch_nonce(
        &self,
        public_key: &TransactionPublicKey,
    ) -> Result<Option<Nonce>, String> {
        self.client
            .fetch_account(public_key)
            .await
            .map(|view| view.map(|view| Nonce::new(view.nonce.base, view.nonce.bitmap)))
            .map_err(|error| error.to_string())
    }
}

/// Height at which a single-transaction batch (fully or partially) finalized,
/// or `None` if the submission concluded without including it.
const fn included_height(status: &TxStatus) -> Option<u64> {
    match status {
        TxStatus::Finalized { height } => Some(*height),
        TxStatus::PartiallyFinalized {
            height, included, ..
        } if !included.is_empty() => Some(*height),
        _ => None,
    }
}

/// Verifies finalized chain state through the indexer and QMDB proofs.
struct ChannelVerifier {
    indexer: IndexerClient,
    transactions: TransactionProofClient,
}

impl ChannelVerifier {
    fn new(indexer_url: String, qmdb_url: String) -> Self {
        let store = StoreClient::new(&indexer_url);
        // The qmdb-indexer facade nests the transaction operation log under
        // its own route (the account-state log lives under another), so the
        // configured base URL needs the route appended — exactly as the
        // explorer's client does.
        let transactions_url = format!(
            "{}{}",
            qmdb_url.trim_end_matches('/'),
            constantinople_indexer::QMDB_TRANSACTIONS_ROUTE
        );
        Self {
            indexer: IndexerClient::new(store.clone(), store),
            transactions: OperationLogClient::plaintext(&transactions_url, ()),
        }
    }
}

impl ChainReader for ChannelVerifier {
    /// Latest finalized height from the indexer.
    async fn latest_height(&self) -> Result<Option<u64>, String> {
        let certificate_cfg = (ConsensusScheme::certificate_codec_config_unbounded(), ());
        self.indexer
            .latest_height::<Sha256, ed25519::PublicKey, ConsensusScheme>(&certificate_cfg)
            .await
            .map_err(|error| format!("latest height lookup failed: {error}"))
    }

    /// `Unavailable` marks failures the indexer may resolve on its own (lag,
    /// transport, proof-service inconsistency); `Rejected` means the digest
    /// names a transaction that can never register a channel.
    async fn verify_open_channel(
        &self,
        digest: &Digest,
    ) -> Result<VerifiedOpenChannel, OperatorError> {
        // The metadata and tip lookups are independent round-trips.
        let certificate_cfg = (ConsensusScheme::certificate_codec_config_unbounded(), ());
        let (metadata, latest) = tokio::join!(
            self.indexer.transaction_metadata::<Sha256>(digest),
            self.indexer
                .latest_certified_header::<Sha256, ed25519::PublicKey, ConsensusScheme>(
                    &certificate_cfg
                ),
        );
        let metadata = metadata
            .map_err(|error| {
                OperatorError::unavailable(format!(
                    "open transaction metadata lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| OperatorError::unavailable("open transaction is not finalized"))?;
        let latest = latest
            .map_err(|error| {
                OperatorError::unavailable(format!(
                    "latest finalized header lookup failed: {error}"
                ))
            })?
            .ok_or_else(|| OperatorError::unavailable("no finalized header available"))?;
        let header = latest.header();
        let tip_height = header.height;
        let tip = header
            .transactions_range
            .end()
            .checked_sub(1)
            .ok_or_else(|| {
                OperatorError::unavailable("latest finalized transaction range is empty")
            })?;
        if metadata.qmdb_location > tip {
            return Err(OperatorError::unavailable(
                "open transaction is beyond the latest finalized transaction tip",
            ));
        }
        let proof = self
            .transactions
            .get_operation_range(
                GetOperationRangeRequest {
                    tip,
                    start_location: metadata.qmdb_location,
                    max_locations: 1,
                    ..Default::default()
                },
                &header.transactions_root,
            )
            .await
            .map_err(|error| {
                OperatorError::unavailable(format!(
                    "open transaction inclusion proof failed: {error}"
                ))
            })?;
        let Some((location, operation)) = proof.operations.into_iter().next() else {
            return Err(OperatorError::unavailable(
                "open transaction proof returned no operation",
            ));
        };
        if location.as_u64() != metadata.qmdb_location {
            return Err(OperatorError::unavailable(
                "open transaction proof returned the wrong location",
            ));
        }
        if operation.into_value().as_ref() != Some(digest) {
            return Err(OperatorError::unavailable(
                "open transaction proof does not contain the requested digest",
            ));
        }

        // `transaction_metadata` only returns bytes it has decoded and
        // digest-matched against the query, so the decode is re-extracting
        // fields, not re-establishing the body/digest binding.
        let tx = SignedTransaction::<Sha256>::decode(metadata.bytes.as_ref()).map_err(|error| {
            OperatorError::rejected(format!("open transaction decode failed: {error}"))
        })?;
        let payer = tx
            .value()
            .sender()
            .ok_or_else(|| OperatorError::rejected("open transaction sender did not decode"))?;
        let payer = constantinople_primitives::AccountKey::from_public_key(payer);
        let Operation::OpenChannel {
            receiver,
            operator,
            voucher_key,
            deposit,
            expiry,
        } = tx.value().op()
        else {
            return Err(OperatorError::rejected(
                "open transaction is not an OpenChannel",
            ));
        };
        Ok(VerifiedOpenChannel {
            payer,
            receiver: *receiver,
            voucher_key: voucher_key.clone(),
            operator: *operator,
            open_nonce: tx.value().nonce,
            deposit: *deposit,
            expiry: *expiry,
            tip_height,
        })
    }

    /// Whether the indexer has observed `digest` finalized.
    async fn is_finalized(&self, digest: &Digest) -> Result<bool, String> {
        self.indexer
            .transaction_exists::<Sha256>(digest)
            .await
            .map_err(|error| error.to_string())
    }
}

/// An operator failure: a permanent rejection answers `400 Bad Request`, a
/// transient dependency failure answers `503 Service Unavailable` so clients
/// know which errors are worth retrying.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl ToString) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    fn forbidden(message: impl ToString) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.to_string(),
        }
    }
}

impl From<OperatorError> for ApiError {
    fn from(error: OperatorError) -> Self {
        let status = match error {
            OperatorError::Rejected(_) => StatusCode::BAD_REQUEST,
            OperatorError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self {
            status,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_fresh_256_bit_bearer_material() {
        let first = generate_capability();
        let second = generate_capability();

        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
        assert!(capability_matches(&first, &first));
        assert!(!capability_matches(&first, &second));
    }

    #[test]
    fn content_limit_prices_every_existing_token_once() {
        assert_eq!(
            stream_content_limit(),
            u64::try_from(content::tokens().len()).expect("token count fits u64")
                * STREAM_PRICE_PER_TOKEN
        );
    }
}
