//! Payment-channel operator process for load testing.
//!
//! The operator owns the receiver key for spammer-created channels, accepts
//! off-chain vouchers over HTTP, enforces monotonic/deposit accounting with
//! [`constantinople_application::operator::ChannelOperator`], and submits the
//! final close transaction through the relayer.

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use commonware_codec::{DecodeExt as _, Encode};
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
use constantinople_mempool::webserver::client::SubmitError;
use constantinople_primitives::{
    AccountKey, Operation, SignedTransaction, TRANSACTION_NAMESPACE, Transaction,
    TransactionPublicKey, Voucher, channel_address,
};
use exoware_qmdb::{OperationLogClient, proto::qmdb::v1::GetOperationRangeRequest};
use exoware_sdk::{StoreClient, proto::PreferZstdHttpClient};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
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
    #[arg(long, default_value_t = 2_000_000_000)]
    receiver_seed: u64,

    /// Price charged per voucher step.
    #[arg(long, default_value_t = 1)]
    price: u64,
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

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<OperatorState>>,
}

struct OperatorState {
    operator: ChannelOperator,
    receiver: ed25519::PrivateKey,
    receiver_pk: TransactionPublicKey,
    receiver_account: AccountKey,
    relayer: RelayerClient,
    verifier: ChannelVerifier,
    nonce: u64,
    channels: BTreeMap<AccountKey, RegisteredChannel>,
}

struct RegisteredChannel {
    payer: TransactionPublicKey,
    open_nonce: u64,
    latest: Option<AcceptedVoucher>,
    settlement: SettlementState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettlementState {
    Open,
    Settling,
    Settled,
}

#[derive(Clone)]
struct AcceptedVoucher {
    cumulative: u64,
    signature: ed25519::Signature,
}

#[derive(Clone)]
struct RelayerClient {
    url: String,
    http: reqwest::Client,
}

#[derive(Clone)]
struct ChannelVerifier {
    indexer: IndexerClient,
    transactions: TransactionProofClient,
}

struct VerifiedOpenChannel {
    payer: TransactionPublicKey,
    receiver: AccountKey,
    open_nonce: u64,
    deposit: u64,
}

#[derive(Debug, Serialize)]
struct PublicKeyResponse {
    public_key: String,
    account: String,
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

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RelayerBatchStatus {
    Finalized {
        height: u64,
    },
    PartiallyFinalized {
        height: u64,
        included: Vec<String>,
        filtered: Vec<String>,
    },
    Dropped,
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
    let state = AppState {
        inner: Arc::new(Mutex::new(OperatorState {
            operator: ChannelOperator::new(config.price),
            receiver,
            receiver_pk,
            receiver_account,
            relayer: RelayerClient::new(config.relayer_url),
            verifier,
            nonce: 0,
            channels: BTreeMap::new(),
        })),
    };

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
}

impl OperatorRuntimeConfig {
    fn from_cli(cli: Cli) -> Self {
        if let Some(config_path) = cli.config {
            let raw = std::fs::read_to_string(config_path).expect("failed to read operator config");
            let config: OperatorConfig =
                serde_yaml::from_str(&raw).expect("failed to parse operator config");
            return Self {
                port: config.http_port,
                listen_addr: config.listen_addr,
                relayer_url: resolve_named_http_url(&config.relayer_url, cli.hosts.as_deref()),
                indexer_url: resolve_named_http_url(&config.indexer_url, cli.hosts.as_deref()),
                qmdb_url: resolve_named_http_url(&config.qmdb_url, cli.hosts.as_deref()),
                receiver_seed: config.receiver_seed,
                price: config.price,
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
        }
    }
}

fn resolve_named_http_url(url: &str, hosts_path: Option<&Path>) -> String {
    let Some(hosts_path) = hosts_path else {
        return url.to_string();
    };
    let raw = std::fs::read_to_string(hosts_path).expect("failed to read hosts file");
    let hosts: Hosts = serde_yaml::from_str(&raw).expect("failed to parse hosts file");
    let hosts_by_name = hosts
        .hosts
        .iter()
        .map(|host| (host.name.as_str(), host.ip))
        .collect::<BTreeMap<_, _>>();

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
    let Some(ip) = hosts_by_name.get(host) else {
        return url.to_string();
    };

    format!("http://{ip}:{port}{suffix}")
}

async fn health() -> &'static str {
    "ok"
}

async fn public_key(State(state): State<AppState>) -> Json<PublicKeyResponse> {
    let state = state.inner.lock().await;
    Json(PublicKeyResponse {
        public_key: hex(&state.receiver_pk.encode()),
        account: state.receiver_account.to_string(),
    })
}

async fn register_channel(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let channel = decode_account_key("channel", &request.channel)?;
    let payer = decode_public_key("payer", &request.payer)?;
    let open_tx_digest = decode_sha256_digest("open_tx_digest", &request.open_tx_digest)?;

    let (verifier, receiver_account) = {
        let state = state.inner.lock().await;
        (state.verifier.clone(), state.receiver_account)
    };

    let open = verifier
        .verify_open_channel(&open_tx_digest)
        .await
        .map_err(ApiError::bad_request)?;
    if open.payer != payer {
        return Err(ApiError::bad_request("open transaction payer mismatch"));
    }
    if open.open_nonce != request.open_nonce {
        return Err(ApiError::bad_request("open transaction nonce mismatch"));
    }
    if open.receiver != receiver_account {
        return Err(ApiError::bad_request("open transaction receiver mismatch"));
    }

    let payer_account = AccountKey::from_public_key(&open.payer);
    let expected = channel_address(&payer_account, &receiver_account, request.open_nonce);
    if expected != channel {
        return Err(ApiError::bad_request(
            "channel address does not match registration",
        ));
    }

    let mut state = state.inner.lock().await;
    state
        .operator
        .register_channel(channel, payer.clone(), open.deposit);
    state.channels.insert(
        channel,
        RegisteredChannel {
            payer,
            open_nonce: request.open_nonce,
            latest: None,
            settlement: SettlementState::Open,
        },
    );
    debug!(%channel, deposit = open.deposit, "registered channel");
    Ok(Json(RegisterResponse { registered: true }))
}

async fn serve_voucher(
    State(state): State<AppState>,
    Json(request): Json<VoucherRequest>,
) -> Result<Json<VoucherResponse>, ApiError> {
    let channel = decode_account_key("channel", &request.channel)?;
    let signature = decode_signature("signature", &request.signature)?;
    let voucher = Voucher {
        channel,
        cumulative: request.cumulative,
        signature: signature.clone(),
    };

    let mut state = state.inner.lock().await;
    let charged = state.operator.serve(&voucher).map_err(ApiError::serve)?;
    let Some(registered) = state.channels.get_mut(&channel) else {
        return Err(ApiError::bad_request("channel metadata missing"));
    };
    registered.latest = Some(AcceptedVoucher {
        cumulative: charged,
        signature,
    });
    Ok(Json(VoucherResponse {
        accepted: true,
        charged,
    }))
}

async fn settle_channel(
    State(state): State<AppState>,
    Json(request): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, ApiError> {
    let channel = decode_account_key("channel", &request.channel)?;
    let (relayer, close, cumulative) = {
        let mut state = state.inner.lock().await;
        let Some(registered) = state.channels.get(&channel) else {
            return Err(ApiError::bad_request("unknown channel"));
        };
        match registered.settlement {
            SettlementState::Settled | SettlementState::Settling => {
                let cumulative = registered
                    .latest
                    .as_ref()
                    .map(|voucher| voucher.cumulative)
                    .unwrap_or(0);
                return Ok(Json(SettleResponse {
                    settled: registered.settlement == SettlementState::Settled,
                    cumulative,
                }));
            }
            SettlementState::Open => {}
        }
        let Some(latest) = registered.latest.clone() else {
            return Err(ApiError::bad_request("channel has no accepted vouchers"));
        };
        let close = build_close(
            &state.receiver,
            &state.receiver_pk,
            &registered.payer,
            registered.open_nonce,
            latest.cumulative,
            latest.signature,
            state.nonce,
        );
        state.nonce = state.nonce.saturating_add(1);
        let registered = state
            .channels
            .get_mut(&channel)
            .expect("channel must still exist while lock is held");
        registered.settlement = SettlementState::Settling;
        (state.relayer.clone(), close, latest.cumulative)
    };

    relayer.submit_until_finalized(close).await;

    let mut state = state.inner.lock().await;
    if let Some(registered) = state.channels.get_mut(&channel) {
        registered.settlement = SettlementState::Settled;
    }
    Ok(Json(SettleResponse {
        settled: true,
        cumulative,
    }))
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

    async fn verify_open_channel(
        &self,
        digest: &<Sha256 as commonware_cryptography::Hasher>::Digest,
    ) -> Result<VerifiedOpenChannel, String> {
        let metadata = self
            .indexer
            .transaction_metadata::<Sha256>(digest)
            .await
            .map_err(|error| format!("open transaction metadata lookup failed: {error}"))?
            .ok_or_else(|| "open transaction is not finalized".to_string())?;
        let latest = self
            .indexer
            .latest_certified_header::<Sha256, ed25519::PublicKey, ConsensusScheme>(&(
                ConsensusScheme::certificate_codec_config_unbounded(),
                (),
            ))
            .await
            .map_err(|error| format!("latest finalized header lookup failed: {error}"))?
            .ok_or_else(|| "no finalized header available".to_string())?;
        let header = latest.header();
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
        let Operation::OpenChannel { receiver, deposit } = tx.value().op() else {
            return Err("open transaction is not an OpenChannel".to_string());
        };
        Ok(VerifiedOpenChannel {
            payer,
            receiver: *receiver,
            open_nonce: tx.value().nonce,
            deposit: deposit.get(),
        })
    }
}

impl RelayerClient {
    fn new(url: String) -> Self {
        Self {
            url: url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    async fn submit_until_finalized(&self, close: Tx) {
        let body = vec![close].encode();
        loop {
            match self.submit_encoded(body.clone()).await {
                Ok(RelayerBatchStatus::Finalized { height }) => {
                    debug!(height, "operator close finalized");
                    return;
                }
                Ok(RelayerBatchStatus::PartiallyFinalized {
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
                    return;
                }
                Ok(status) => {
                    warn!(?status, "operator close not finalized, retrying");
                }
                Err(error) => {
                    warn!(%error, "operator close submit failed, retrying");
                }
            }
            tokio::time::sleep(SUBMIT_ERROR_BACKOFF).await;
        }
    }

    async fn submit_encoded(&self, body: bytes::Bytes) -> Result<RelayerBatchStatus, SubmitError> {
        let response = self
            .http
            .post(format!("{}/transactions", self.url))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        match response.status().as_u16() {
            200 => {
                let bytes = response.bytes().await?;
                serde_json::from_slice(&bytes).map_err(SubmitError::InvalidResponse)
            }
            400 => Err(SubmitError::BadRequest),
            413 => Err(SubmitError::PayloadTooLarge),
            500 => Err(SubmitError::InternalServerError),
            503 => Err(SubmitError::ServiceUnavailable),
            other => Err(SubmitError::Unexpected(other)),
        }
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

fn decode_account_key(field: &str, value: &str) -> Result<AccountKey, ApiError> {
    decode_hex_field(field, value).and_then(|bytes| {
        AccountKey::decode(bytes.as_slice())
            .map_err(|_| ApiError::bad_request(format!("bad {field}")))
    })
}

fn decode_public_key(field: &str, value: &str) -> Result<TransactionPublicKey, ApiError> {
    decode_hex_field(field, value).and_then(|bytes| {
        TransactionPublicKey::decode(bytes.as_slice())
            .map_err(|_| ApiError::bad_request(format!("bad {field}")))
    })
}

fn decode_signature(field: &str, value: &str) -> Result<ed25519::Signature, ApiError> {
    decode_hex_field(field, value).and_then(|bytes| {
        ed25519::Signature::decode(bytes.as_slice())
            .map_err(|_| ApiError::bad_request(format!("bad {field}")))
    })
}

fn decode_sha256_digest(
    field: &str,
    value: &str,
) -> Result<<Sha256 as commonware_cryptography::Hasher>::Digest, ApiError> {
    decode_hex_field(field, value).and_then(|bytes| {
        <Sha256 as commonware_cryptography::Hasher>::Digest::decode(bytes.as_slice())
            .map_err(|_| ApiError::bad_request(format!("bad {field}")))
    })
}

fn decode_hex_field(field: &str, value: &str) -> Result<Vec<u8>, ApiError> {
    from_hex(value).ok_or_else(|| ApiError::bad_request(format!("bad {field} hex")))
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
}
