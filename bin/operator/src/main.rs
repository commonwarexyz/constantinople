//! Payment-channel operator process for load testing.
//!
//! The operator owns the receiver key for spammer-created channels, accepts
//! off-chain vouchers over HTTP, enforces monotonic/deposit accounting with
//! [`constantinople_application::operator::ChannelOperator`], and submits the
//! final close transaction through the relayer.
//!
//! Known restart limitation: channel registrations (and their charged/voucher
//! accounting) live only in memory. Registration verifies that the open
//! transaction finalized, not that the channel is still live, so after a
//! restart an already-settled channel can be re-registered and its old
//! vouchers replayed for free service. Only the operator's own revenue is at
//! stake, which is acceptable for load-test infrastructure; a durable channel
//! store (or an account-key state lookup to check the channel still exists)
//! would be needed to close this.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    Sha256, Signer as _, bls12381::primitives::variant::MinSig, certificate::Verifier as _, ed25519,
};
use commonware_deployer::aws::Hosts;
use commonware_formatting::{from_hex, hex};
use commonware_storage::{
    merkle::mmr,
    qmdb::{any::value::FixedEncoding, keyless},
};
use constantinople_application::operator::{ChannelOperator, ServeError};
use constantinople_engine::ThresholdScheme;
use constantinople_indexer::IndexerClient;
use constantinople_mempool::webserver::{TxStatus, client::Client};
use constantinople_primitives::{
    AccountKey, CHANNEL_NEVER_EXPIRES, NONCE_BITMAP_CAPACITY, Operation, SignedTransaction,
    TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey, Voucher, channel_address,
};
use core::num::NonZeroU64;
use exoware_qmdb::{OperationLogClient, proto::qmdb::v1::GetOperationRangeRequest};
use exoware_sdk::{StoreClient, proto::PreferZstdHttpClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

type Tx = SignedTransaction<Sha256>;
type QmdbFamily = mmr::Family;
type TransactionEncoding = FixedEncoding<<Sha256 as commonware_cryptography::Hasher>::Digest>;
type TransactionOperation = keyless::Operation<QmdbFamily, TransactionEncoding>;
type TransactionProofClient =
    OperationLogClient<PreferZstdHttpClient, QmdbFamily, Sha256, TransactionOperation>;
type ConsensusScheme = ThresholdScheme<ed25519::PublicKey, MinSig>;

const SUBMIT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
const STARTUP_FETCH_BACKOFF: Duration = Duration::from_millis(500);
const NONCE_WINDOW_BACKOFF: Duration = Duration::from_millis(100);
const HEIGHT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const SETTLEMENT_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

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
    #[arg(long, default_value_t = 8093)]
    port: u16,

    /// HTTP bind address.
    #[arg(long, default_value = "127.0.0.1")]
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

    /// Deterministic receiver key seed.
    #[arg(long, default_value_t = default_receiver_seed())]
    receiver_seed: u64,

    /// Price charged per voucher step.
    #[arg(long, default_value_t = default_price())]
    price: u64,

    /// Minimum blocks between registration and a channel's expiry.
    #[arg(long, default_value_t = default_min_runway())]
    min_runway: u64,

    /// Blocks before expiry at which vouchers stop and settlement starts.
    #[arg(long, default_value_t = default_settle_margin())]
    settle_margin: u64,
}

#[derive(Debug, Deserialize)]
struct OperatorConfig {
    http_port: u16,
    #[serde(default = "default_listen_addr")]
    listen_addr: IpAddr,
    relayer_url: String,
    indexer_url: String,
    qmdb_url: String,
    #[serde(default = "default_receiver_seed")]
    receiver_seed: u64,
    #[serde(default = "default_price")]
    price: u64,
    #[serde(default = "default_min_runway")]
    min_runway: u64,
    #[serde(default = "default_settle_margin")]
    settle_margin: u64,
}

const fn default_listen_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

const fn default_receiver_seed() -> u64 {
    2_000_000_000
}

const fn default_price() -> u64 {
    1
}

const fn default_min_runway() -> u64 {
    20
}

const fn default_settle_margin() -> u64 {
    10
}

#[derive(Clone)]
struct AppState {
    shared: Arc<AppShared>,
}

/// Read-only after startup, except for the mutable state behind the mutex and
/// the height cache.
struct AppShared {
    receiver: ed25519::PrivateKey,
    receiver_pk: TransactionPublicKey,
    receiver_account: AccountKey,
    relayer: Client,
    verifier: ChannelVerifier,
    /// Latest finalized height, refreshed by a background task. All expiry
    /// decisions read this cache.
    height: AtomicU64,
    /// Minimum blocks of runway a channel must have left at registration.
    min_runway: u64,
    /// Blocks before expiry at which vouchers stop and settlement starts.
    settle_margin: u64,
    state: Mutex<OperatorState>,
}

struct OperatorState {
    operator: ChannelOperator,
    /// Next receiver transaction nonce to reserve for a close.
    nonce: u64,
    /// Close nonces reserved but not yet finalized. Reservation is windowed
    /// against the smallest entry so a fast-finalizing close can never jump the
    /// receiver's nonce base past a still-pending lower nonce (which would
    /// permanently wedge that settlement).
    inflight: BTreeSet<u64>,
    /// Whether the chain's nonce base is known to have caught up to [`Self::nonce`].
    /// False after recovering from a dirty (mid-settlement crash) bitmap; the
    /// first close then settles alone so its jump lands before anything runs
    /// ahead of it.
    aligned: bool,
    channels: BTreeMap<AccountKey, RegisteredChannel>,
}

struct RegisteredChannel {
    payer: TransactionPublicKey,
    open_nonce: u64,
    /// Block height after which the payer may reclaim the escrow.
    expiry: u64,
    latest: Option<Voucher>,
    settlement: SettlementState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettlementState {
    Open,
    Settling,
    Settled,
    /// The close could not finalize before the payer reclaimed the channel;
    /// its vouchers are forfeited.
    Abandoned,
}

struct ChannelVerifier {
    indexer: IndexerClient,
    transactions: TransactionProofClient,
}

struct VerifiedOpenChannel {
    payer: TransactionPublicKey,
    receiver: AccountKey,
    open_nonce: u64,
    deposit: u64,
    expiry: u64,
    /// Height of the latest certified header the verification ran against;
    /// used to keep expiry checks honest even before the height poller's
    /// first result lands.
    tip_height: u64,
}

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    public_key: String,
    account: String,
    /// Latest finalized height the operator has observed (0 until the first
    /// poll lands). Lets clients pick sane channel expiries.
    height: u64,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    channel: String,
    payer: String,
    open_nonce: u64,
    open_tx_digest: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    registered: bool,
}

#[derive(Debug, Deserialize)]
struct VoucherRequest {
    channel: String,
    cumulative: u64,
    signature: String,
}

#[derive(Debug, Serialize)]
struct VoucherResponse {
    accepted: bool,
    charged: u64,
}

#[derive(Debug, Deserialize)]
struct SettleRequest {
    channel: String,
}

#[derive(Debug, Serialize)]
struct SettleResponse {
    settled: bool,
    cumulative: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt().init();

    let config = OperatorRuntimeConfig::from_cli(cli);
    assert!(config.price > 0, "--price must be > 0");

    let receiver = ed25519::PrivateKey::from_seed(config.receiver_seed);
    let receiver_pk = TransactionPublicKey::ed25519(receiver.public_key());
    let receiver_account = AccountKey::from_public_key(&receiver_pk);
    let verifier = ChannelVerifier::new(config.indexer_url, config.qmdb_url);
    let relayer = Client::new(config.relayer_url.trim_end_matches('/'));
    let (nonce, aligned) = recover_receiver_nonce(&relayer, &receiver_pk).await;
    info!(nonce, aligned, "recovered receiver nonce from chain");
    let state = AppState {
        shared: Arc::new(AppShared {
            receiver,
            receiver_pk,
            receiver_account,
            relayer,
            verifier,
            height: AtomicU64::new(0),
            min_runway: config.min_runway,
            settle_margin: config.settle_margin,
            state: Mutex::new(OperatorState {
                operator: ChannelOperator::new(config.price),
                nonce,
                inflight: BTreeSet::new(),
                aligned,
                channels: BTreeMap::new(),
            }),
        }),
    };
    tokio::spawn(track_height(state.shared.clone()));
    tokio::spawn(settlement_sweep(state.shared.clone()));

    let addr = SocketAddr::new(config.listen_addr, config.port);
    let app = Router::new()
        .route("/health", get(health))
        .route("/public-key", get(public_key))
        .route("/channels", post(register_channel))
        .route("/vouchers", post(serve_voucher))
        .route("/settle", post(settle_channel))
        .with_state(state);

    info!(%addr, "constantinople operator listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("operator HTTP bind failed");
    axum::serve(listener, app)
        .await
        .expect("operator HTTP failed");
}

struct OperatorRuntimeConfig {
    port: u16,
    listen_addr: IpAddr,
    relayer_url: String,
    indexer_url: String,
    qmdb_url: String,
    receiver_seed: u64,
    price: u64,
    min_runway: u64,
    settle_margin: u64,
}

impl OperatorRuntimeConfig {
    fn from_cli(cli: Cli) -> Self {
        if let Some(config_path) = cli.config {
            let raw = std::fs::read_to_string(config_path).expect("failed to read operator config");
            let config: OperatorConfig =
                serde_yaml::from_str(&raw).expect("failed to parse operator config");
            let hosts = cli.hosts.as_deref().map(load_hosts);
            return Self {
                port: config.http_port,
                listen_addr: config.listen_addr,
                relayer_url: resolve_named_http_url(&config.relayer_url, hosts.as_ref()),
                indexer_url: resolve_named_http_url(&config.indexer_url, hosts.as_ref()),
                qmdb_url: resolve_named_http_url(&config.qmdb_url, hosts.as_ref()),
                receiver_seed: config.receiver_seed,
                price: config.price,
                min_runway: config.min_runway,
                settle_margin: config.settle_margin,
            };
        }

        Self {
            port: cli.port,
            listen_addr: cli.listen_addr,
            relayer_url: cli.relayer_url.expect("provide --relayer-url or --config"),
            indexer_url: cli.indexer_url.expect("provide --indexer-url or --config"),
            qmdb_url: cli.qmdb_url.expect("provide --qmdb-url or --config"),
            receiver_seed: cli.receiver_seed,
            price: cli.price,
            min_runway: cli.min_runway,
            settle_margin: cli.settle_margin,
        }
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
    let Some(rest) = url.strip_prefix("http://") else {
        return url.to_string();
    };
    let (authority, suffix) = match rest.split_once('/') {
        Some((authority, suffix)) => (authority, format!("/{suffix}")),
        None => (rest, String::new()),
    };
    let Some((host, port)) = authority.rsplit_once(':') else {
        return url.to_string();
    };
    let Some(ip) = hosts.get(host) else {
        return url.to_string();
    };

    format!("http://{ip}:{port}{suffix}")
}

async fn health() -> &'static str {
    "ok"
}

/// Keeps the shared height cache tracking the latest finalized height.
async fn track_height(shared: Arc<AppShared>) {
    loop {
        match shared.verifier.latest_height().await {
            Ok(Some(height)) => {
                shared.height.fetch_max(height, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(error) => warn!(%error, "latest height lookup failed"),
        }
        tokio::time::sleep(HEIGHT_POLL_INTERVAL).await;
    }
}

/// Force-settles voucher-bearing channels approaching their expiry.
///
/// A receiver that misses a channel's expiry forfeits its vouchers (the payer
/// reclaims the whole escrow), so settlement cannot wait for the payer to ask.
async fn settlement_sweep(shared: Arc<AppShared>) {
    // Channels with a settle task already spawned by this sweep. A spawned
    // task can wait on the nonce window with the channel still `Open`, so
    // without this a channel would get one more task per tick until it flips
    // to `Settling`.
    let mut spawned: BTreeSet<AccountKey> = BTreeSet::new();
    loop {
        tokio::time::sleep(SETTLEMENT_SWEEP_INTERVAL).await;
        let height = shared.height.load(Ordering::Relaxed);
        let due: Vec<AccountKey> = {
            let state = shared.state.lock().await;
            spawned.retain(|channel| {
                state
                    .channels
                    .get(channel)
                    .is_some_and(|registered| registered.settlement == SettlementState::Open)
            });
            state
                .channels
                .iter()
                .filter(|(channel, registered)| {
                    registered.settlement == SettlementState::Open
                        && registered.latest.is_some()
                        && height.saturating_add(shared.settle_margin) >= registered.expiry
                        && !spawned.contains(channel)
                })
                .map(|(channel, _)| *channel)
                .collect()
        };
        for channel in due {
            info!(%channel, height, "expiry approaching, force-settling channel");
            spawned.insert(channel);
            let shared = shared.clone();
            tokio::spawn(async move {
                if let Err(error) = settle_registered_channel(&shared, channel).await {
                    warn!(%channel, error = %error.message, "sweep settlement failed");
                }
            });
        }
    }
}

/// Recovers the receiver's next transaction nonce from committed chain state.
///
/// The nonce cannot start at zero: after any prior settlement a fresh process
/// would reuse a consumed nonce, the close would never finalize, and every
/// settlement would wedge behind it. Retries until the relayer answers — the
/// operator cannot safely guess.
///
/// Returns the starting nonce plus whether the chain's nonce base is known to
/// equal it. A clean state (empty run-ahead bitmap) resumes at the base. A
/// dirty bitmap (crash mid-settlement) resumes one past the run-ahead window,
/// so the first close jump-clears the leftovers; that close settles alone
/// (`aligned = false`) so the jump lands before later closes run ahead of it.
async fn recover_receiver_nonce(
    relayer: &Client,
    receiver_pk: &TransactionPublicKey,
) -> (u64, bool) {
    loop {
        match relayer.fetch_account(receiver_pk).await {
            Ok(None) => return (0, true),
            Ok(Some(account)) if account.nonce.bitmap == 0 => return (account.nonce.base, true),
            Ok(Some(account)) => {
                return (
                    account.nonce.base.saturating_add(NONCE_BITMAP_CAPACITY + 1),
                    false,
                );
            }
            Err(error) => {
                warn!(%error, "receiver account lookup failed, retrying");
                tokio::time::sleep(STARTUP_FETCH_BACKOFF).await;
            }
        }
    }
}

async fn public_key(State(state): State<AppState>) -> Json<PublicKeyResponse> {
    Json(PublicKeyResponse {
        public_key: hex(&state.shared.receiver_pk.encode()),
        account: state.shared.receiver_account.to_string(),
        height: state.shared.height.load(Ordering::Relaxed),
    })
}

async fn register_channel(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let channel = decode_field::<AccountKey>("channel", &request.channel)?;
    let payer = decode_field::<TransactionPublicKey>("payer", &request.payer)?;
    let open_tx_digest = decode_field::<<Sha256 as commonware_cryptography::Hasher>::Digest>(
        "open_tx_digest",
        &request.open_tx_digest,
    )?;

    let open = state
        .shared
        .verifier
        .verify_open_channel(&open_tx_digest)
        .await
        .map_err(ApiError::bad_request)?;
    if open.payer != payer {
        return Err(ApiError::bad_request("open transaction payer mismatch"));
    }
    if open.open_nonce != request.open_nonce {
        return Err(ApiError::bad_request("open transaction nonce mismatch"));
    }
    if open.receiver != state.shared.receiver_account {
        return Err(ApiError::bad_request("open transaction receiver mismatch"));
    }
    // Past the expiry the payer can reclaim the whole escrow, voiding any
    // unsettled vouchers; refuse channels without enough runway to serve and
    // settle safely. The verification above ran against a certified header,
    // so its height also seeds the cache — the check cannot be fooled by a
    // cache still at zero right after startup.
    state
        .shared
        .height
        .fetch_max(open.tip_height, Ordering::Relaxed);
    let height = state.shared.height.load(Ordering::Relaxed);
    if open.expiry <= height.saturating_add(state.shared.min_runway) {
        return Err(ApiError::bad_request("channel expires too soon"));
    }

    let payer_account = AccountKey::from_public_key(&open.payer);
    let expected = channel_address(
        &payer_account,
        &state.shared.receiver_account,
        request.open_nonce,
    );
    if expected != channel {
        return Err(ApiError::bad_request(
            "channel address does not match registration",
        ));
    }

    let mut state = state.shared.state.lock().await;
    let state = &mut *state;
    let inserted = register_verified_channel(
        &mut state.operator,
        &mut state.channels,
        channel,
        payer,
        request.open_nonce,
        open.deposit,
        open.expiry,
    )?;
    if inserted {
        debug!(%channel, deposit = open.deposit, "registered channel");
    } else {
        debug!(%channel, "channel registration replayed");
    }
    Ok(Json(RegisterResponse { registered: true }))
}

fn register_verified_channel(
    operator: &mut ChannelOperator,
    channels: &mut BTreeMap<AccountKey, RegisteredChannel>,
    channel: AccountKey,
    payer: TransactionPublicKey,
    open_nonce: u64,
    deposit: u64,
    expiry: u64,
) -> Result<bool, ApiError> {
    if let Some(registered) = channels.get(&channel) {
        if registered.payer != payer || registered.open_nonce != open_nonce {
            return Err(ApiError::bad_request(
                "channel already registered with different metadata",
            ));
        }
        return Ok(false);
    }

    operator.register_channel(channel, payer.clone(), deposit);
    channels.insert(
        channel,
        RegisteredChannel {
            payer,
            open_nonce,
            expiry,
            latest: None,
            settlement: SettlementState::Open,
        },
    );
    Ok(true)
}

async fn serve_voucher(
    State(state): State<AppState>,
    Json(request): Json<VoucherRequest>,
) -> Result<Json<VoucherResponse>, ApiError> {
    let channel = decode_field::<AccountKey>("channel", &request.channel)?;
    let signature = decode_field::<ed25519::Signature>("signature", &request.signature)?;
    let voucher = Voucher {
        channel,
        cumulative: request.cumulative,
        signature,
    };

    let height = state.shared.height.load(Ordering::Relaxed);
    let settle_margin = state.shared.settle_margin;
    let mut state = state.shared.state.lock().await;
    let state = &mut *state;
    let Some(registered) = state.channels.get_mut(&channel) else {
        return Err(ApiError::bad_request("channel metadata missing"));
    };
    // Once a close has been built, a newer voucher can no longer be settled;
    // refuse to serve work the submitted close will not pay for.
    if registered.settlement != SettlementState::Open {
        return Err(ApiError::bad_request("channel settlement already started"));
    }
    // Near expiry a voucher may not settle before the payer can reclaim the
    // escrow; stop serving and let the sweep close the channel.
    if height.saturating_add(settle_margin) >= registered.expiry {
        return Err(ApiError::bad_request("channel is about to expire"));
    }
    let charged = state.operator.serve(&voucher).map_err(ApiError::serve)?;
    registered.latest = Some(voucher);
    Ok(Json(VoucherResponse {
        accepted: true,
        charged,
    }))
}

async fn settle_channel(
    State(state): State<AppState>,
    Json(request): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, ApiError> {
    let channel = decode_field::<AccountKey>("channel", &request.channel)?;
    settle_registered_channel(&state.shared, channel)
        .await
        .map(Json)
}

/// Settles a registered channel's latest voucher on chain.
///
/// Shared by the `/settle` handler and the expiry sweep; the settlement-state
/// machine makes concurrent calls for the same channel idempotent.
async fn settle_registered_channel(
    shared: &Arc<AppShared>,
    channel: AccountKey,
) -> Result<SettleResponse, ApiError> {
    let (payer, open_nonce, expiry, latest, nonce) = loop {
        {
            let mut state = shared.state.lock().await;
            let state = &mut *state;
            // A close may reserve a nonce at most `NONCE_BITMAP_CAPACITY`
            // ahead of the oldest unfinalized close. Beyond that, the chain
            // would consume it as a far jump that clears the run-ahead bitmap
            // and strands every pending lower nonce.
            let can_reserve = match state.inflight.first() {
                None => true,
                Some(&oldest) => state.aligned && state.nonce - oldest <= NONCE_BITMAP_CAPACITY,
            };
            let Some(registered) = state.channels.get_mut(&channel) else {
                return Err(ApiError::bad_request("unknown channel"));
            };
            match registered.settlement {
                SettlementState::Settled
                | SettlementState::Settling
                | SettlementState::Abandoned => {
                    let cumulative = registered
                        .latest
                        .as_ref()
                        .map(|voucher| voucher.cumulative)
                        .unwrap_or(0);
                    return Ok(SettleResponse {
                        settled: registered.settlement == SettlementState::Settled,
                        cumulative,
                    });
                }
                SettlementState::Open => {}
            }
            let Some(latest) = registered.latest.clone() else {
                return Err(ApiError::bad_request("channel has no accepted vouchers"));
            };
            if can_reserve {
                registered.settlement = SettlementState::Settling;
                let payer = registered.payer.clone();
                let open_nonce = registered.open_nonce;
                let expiry = registered.expiry;
                let nonce = state.nonce;
                state.nonce = state.nonce.saturating_add(1);
                state.inflight.insert(nonce);
                break (payer, open_nonce, expiry, latest, nonce);
            }
        }
        // The nonce window is full; wait for an in-flight close to finalize.
        tokio::time::sleep(NONCE_WINDOW_BACKOFF).await;
    };

    // Build and sign the close outside the lock: only the nonce reservation
    // and settlement flag above need mutual exclusion.
    let cumulative = latest.cumulative;
    let close = build_close(
        &shared.receiver,
        &shared.receiver_pk,
        &payer,
        open_nonce,
        cumulative,
        latest.signature,
        nonce,
    );
    let close_digest = *close.message_digest();
    let mut finalized = submit_close(shared, close, expiry).await;
    if !finalized {
        // Giving up does not mean the close is dead: an earlier submission
        // may still be queued at a validator and finalize later. Race a
        // same-nonce burn (a receiver self-transfer) against it — exactly one
        // of the two can consume the reserved nonce — so the in-flight
        // window's invariant (every nonce below the oldest in-flight one is
        // consumed) stays true whichever wins.
        warn!(%channel, "close did not finalize before expiry; racing a nonce burn against it");
        let burn = Transaction::new(
            shared.receiver_pk.clone(),
            shared.receiver_pk.clone(),
            NonZeroU64::new(1).expect("burn value is non-zero"),
            nonce,
        )
        .seal_and_sign(
            &shared.receiver,
            TRANSACTION_NAMESPACE,
            &mut Sha256::default(),
        );
        finalized = resolve_abandoned_close(shared, burn, &close_digest).await;
    }

    let mut state = shared.state.lock().await;
    let state = &mut *state;
    state.inflight.remove(&nonce);
    // Either the close or its burn consumed the nonce on chain, so the chain's
    // nonce base has caught up past any startup jump; later closes may run
    // ahead again.
    state.aligned = true;
    if let Some(registered) = state.channels.get_mut(&channel) {
        registered.settlement = if finalized {
            SettlementState::Settled
        } else {
            SettlementState::Abandoned
        };
    }
    Ok(SettleResponse {
        settled: finalized,
        cumulative,
    })
}

/// Submits a close until it finalizes, or gives up once the chain is past the
/// channel's expiry (the payer may reclaim the channel from that point, after
/// which the close can never land).
///
/// A close stays valid on-chain at any height while the channel exists, so
/// giving up requires more than the clock: the relayer must have processed a
/// submission to a definitive non-inclusion (the proposer filtered the close,
/// which past expiry means the channel is likely reclaimed). A transport error
/// proves nothing about the channel and always retries — abandoning on it
/// would forfeit vouchers a live channel could still settle.
///
/// Returns whether the close finalized.
async fn submit_close(shared: &Arc<AppShared>, close: Tx, expiry: u64) -> bool {
    let batch = [close];
    loop {
        let definitive = match shared.relayer.submit(&batch).await {
            Ok(TxStatus::Finalized { height }) => {
                debug!(height, "operator close finalized");
                return true;
            }
            Ok(TxStatus::PartiallyFinalized {
                height,
                included,
                filtered,
            }) if !included.is_empty() => {
                debug!(
                    height,
                    included = included.len(),
                    filtered = filtered.len(),
                    "operator close partially finalized"
                );
                return true;
            }
            Ok(status) => {
                warn!(?status, "operator close not finalized, retrying");
                true
            }
            Err(error) => {
                warn!(%error, "operator close submit failed, retrying");
                false
            }
        };
        if definitive
            && expiry != CHANNEL_NEVER_EXPIRES
            && shared.height.load(Ordering::Relaxed) > expiry
        {
            return false;
        }
        tokio::time::sleep(SUBMIT_ERROR_BACKOFF).await;
    }
}

fn build_close(
    receiver: &ed25519::PrivateKey,
    receiver_pk: &TransactionPublicKey,
    payer_pk: &TransactionPublicKey,
    open_nonce: u64,
    cumulative: u64,
    voucher: ed25519::Signature,
    nonce: u64,
) -> Tx {
    Transaction::close_channel(
        receiver_pk.clone(),
        payer_pk.clone(),
        open_nonce,
        cumulative,
        voucher,
        nonce,
    )
    .seal_and_sign(receiver, TRANSACTION_NAMESPACE, &mut Sha256::default())
}

impl ChannelVerifier {
    fn new(indexer_url: String, qmdb_url: String) -> Self {
        let store = StoreClient::new(&indexer_url);
        Self {
            indexer: IndexerClient::new(store.clone(), store),
            transactions: OperationLogClient::plaintext(&qmdb_url, ()),
        }
    }

    /// Latest finalized height from the indexer.
    async fn latest_height(&self) -> Result<Option<u64>, String> {
        let certificate_cfg = (ConsensusScheme::certificate_codec_config_unbounded(), ());
        self.indexer
            .latest_height::<Sha256, ed25519::PublicKey, ConsensusScheme>(&certificate_cfg)
            .await
            .map_err(|error| format!("latest height lookup failed: {error}"))
    }

    async fn verify_open_channel(
        &self,
        digest: &<Sha256 as commonware_cryptography::Hasher>::Digest,
    ) -> Result<VerifiedOpenChannel, String> {
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
            .map_err(|error| format!("open transaction metadata lookup failed: {error}"))?
            .ok_or_else(|| "open transaction is not finalized".to_string())?;
        let latest = latest
            .map_err(|error| format!("latest finalized header lookup failed: {error}"))?
            .ok_or_else(|| "no finalized header available".to_string())?;
        let header = latest.header();
        let tip_height = header.height;
        let tip = header
            .transactions_range
            .end()
            .checked_sub(1)
            .ok_or_else(|| "latest finalized transaction range is empty".to_string())?;
        if metadata.qmdb_location > tip {
            return Err(
                "open transaction is beyond the latest finalized transaction tip".to_string(),
            );
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
            .map_err(|error| format!("open transaction inclusion proof failed: {error}"))?;
        let Some((location, operation)) = proof.operations.into_iter().next() else {
            return Err("open transaction proof returned no operation".to_string());
        };
        if location.as_u64() != metadata.qmdb_location {
            return Err("open transaction proof returned the wrong location".to_string());
        }
        if operation.into_value().as_ref() != Some(digest) {
            return Err("open transaction proof does not contain the requested digest".to_string());
        }

        let tx = SignedTransaction::<Sha256>::decode(metadata.bytes.as_ref())
            .map_err(|error| format!("open transaction decode failed: {error}"))?;
        if tx.message_digest() != digest {
            return Err("open transaction body digest mismatch".to_string());
        }
        let payer = tx
            .value()
            .sender()
            .ok_or_else(|| "open transaction sender did not decode".to_string())?
            .clone();
        let Operation::OpenChannel {
            receiver,
            deposit,
            expiry,
        } = tx.value().op()
        else {
            return Err("open transaction is not an OpenChannel".to_string());
        };
        Ok(VerifiedOpenChannel {
            payer,
            receiver: *receiver,
            open_nonce: tx.value().nonce,
            deposit: deposit.get(),
            expiry: *expiry,
            tip_height,
        })
    }
}

/// Resolves an abandoned close by racing a same-nonce burn against it.
///
/// The close may still finalize after [`submit_close`] gives up (a submission
/// can sit in a validator mempool through a transport error), and the burn is
/// signed with the same nonce, so exactly one of the two can ever consume it.
/// Submits the burn until either transaction is observed finalized: the burn
/// landing abandons the settlement, the close landing completes it. Without
/// this check a blind burn retry would spin forever once the close won the
/// race, pinning the nonce in the in-flight set and wedging all settlements.
///
/// Returns whether the close finalized.
async fn resolve_abandoned_close(
    shared: &Arc<AppShared>,
    burn: Tx,
    close_digest: &<Sha256 as commonware_cryptography::Hasher>::Digest,
) -> bool {
    let burn_digest = *burn.message_digest();
    let batch = [burn];
    loop {
        match shared.relayer.submit(&batch).await {
            Ok(TxStatus::Finalized { height }) => {
                debug!(height, "abandoned close's nonce burned");
                return false;
            }
            Ok(TxStatus::PartiallyFinalized {
                height, included, ..
            }) if !included.is_empty() => {
                debug!(height, "abandoned close's nonce burned");
                return false;
            }
            Ok(status) => {
                warn!(?status, "nonce burn not finalized, retrying");
            }
            Err(error) => {
                warn!(%error, "nonce burn submit failed, retrying");
            }
        }
        // The burn stays filtered while the close still owns the nonce (and a
        // finalized burn's acknowledgement can itself be lost to a transport
        // error), so consult the indexer for whichever actually landed.
        match shared
            .verifier
            .indexer
            .transaction_metadata::<Sha256>(close_digest)
            .await
        {
            Ok(Some(_)) => {
                info!("abandoned close finalized after all; settlement complete");
                return true;
            }
            Ok(None) => {}
            Err(error) => warn!(%error, "close lookup failed while burning its nonce"),
        }
        match shared
            .verifier
            .indexer
            .transaction_metadata::<Sha256>(&burn_digest)
            .await
        {
            Ok(Some(_)) => {
                debug!("abandoned close's nonce burned");
                return false;
            }
            Ok(None) => {}
            Err(error) => warn!(%error, "burn lookup failed while burning the close's nonce"),
        }
        tokio::time::sleep(SUBMIT_ERROR_BACKOFF).await;
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn serve(error: ServeError) -> Self {
        Self::bad_request(format!("voucher rejected: {error:?}"))
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

/// Decodes a hex-encoded request field into any codec type with no config.
fn decode_field<T: DecodeExt<()>>(field: &str, value: &str) -> Result<T, ApiError> {
    let bytes = from_hex(value).ok_or_else(|| ApiError::bad_request(format!("bad {field} hex")))?;
    T::decode(bytes.as_slice()).map_err(|_| ApiError::bad_request(format!("bad {field}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_loopback_listen_addr() {
        let config: OperatorConfig =
            serde_yaml::from_str(
                "http_port: 8093\nrelayer_url: http://127.0.0.1:8082\nindexer_url: http://127.0.0.1:8090\nqmdb_url: http://127.0.0.1:8092\n",
            )
                .expect("operator config should parse");

        assert_eq!(config.listen_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn duplicate_registration_preserves_accepted_voucher_state() {
        let payer_key = ed25519::PrivateKey::from_seed(42);
        let payer = TransactionPublicKey::ed25519(payer_key.public_key());
        let receiver =
            TransactionPublicKey::ed25519(ed25519::PrivateKey::from_seed(43).public_key());
        let receiver_account = AccountKey::from_public_key(&receiver);
        let payer_account = AccountKey::from_public_key(&payer);
        let open_nonce = 7;
        let channel = channel_address(&payer_account, &receiver_account, open_nonce);
        let voucher = Voucher::sign(&payer_key, channel, 10);

        let mut operator = ChannelOperator::new(1);
        let mut channels = BTreeMap::new();
        assert!(
            register_verified_channel(
                &mut operator,
                &mut channels,
                channel,
                payer.clone(),
                open_nonce,
                20,
                CHANNEL_NEVER_EXPIRES,
            )
            .expect("initial registration should succeed")
        );
        operator
            .serve(&voucher)
            .expect("voucher should be accepted before replay");
        let registered = channels
            .get_mut(&channel)
            .expect("registration metadata should exist");
        registered.latest = Some(voucher.clone());
        registered.settlement = SettlementState::Settling;

        assert!(
            !register_verified_channel(
                &mut operator,
                &mut channels,
                channel,
                payer,
                open_nonce,
                20,
                CHANNEL_NEVER_EXPIRES,
            )
            .expect("duplicate registration should be idempotent")
        );

        let registered = channels
            .get(&channel)
            .expect("registration metadata should remain");
        assert_eq!(
            registered.latest.as_ref().map(|latest| latest.cumulative),
            Some(10)
        );
        assert_eq!(registered.settlement, SettlementState::Settling);
        assert!(
            operator.serve(&voucher).is_err(),
            "duplicate registration must not reset charged accounting"
        );
    }
}
