//! Local E2E: ephemeral RocksDB dir + simulator on an ephemeral port (no env vars).

#![allow(refining_impl_trait)]

use std::num::NonZeroU64;
use std::time::Duration;

use axum::{routing::get, Router};
use commonware_cryptography::Digest;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    journal::contiguous::variable::Config as VariableJournalConfig,
    merkle::{full::Config as MerkleConfig, Family, Graftable},
    qmdb::{
        any,
        current::{self, proof::RangeProof},
        immutable, keyless,
    },
    translator::TwoCap,
};
use commonware_utils::{NZUsize, NZU64};
use connectrpc::client::ClientConfig;
use connectrpc::{
    ConnectError, ConnectRpcService, ErrorCode, RequestContext as Context, ServiceRequest,
};
use exoware_qmdb::proto::qmdb::v1::{
    GetOperationRangeRequest, GetOperationRangeResponse, OperationLogService,
    OperationLogServiceClient, OperationLogServiceServer, SubscribeRequest, SubscribeResponse,
};
use exoware_qmdb::{CurrentBoundaryState, QmdbError};
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::StoreClient;

#[allow(dead_code)]
pub fn merkle_config(prefix: &str, page_cache: CacheRef) -> MerkleConfig<Sequential> {
    MerkleConfig {
        journal_partition: format!("{prefix}-merkle-journal"),
        metadata_partition: format!("{prefix}-merkle-metadata"),
        items_per_blob: NZU64!(8),
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
        strategy: Sequential,
        page_cache,
    }
}

#[allow(dead_code)]
pub fn variable_journal_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> VariableJournalConfig<C> {
    VariableJournalConfig {
        partition: format!("{prefix}-log"),
        items_per_section,
        compression: None,
        codec_config,
        page_cache,
        write_buffer: NZUsize!(1024),
        replay_buffer: NZUsize!(1024),
    }
}

#[allow(dead_code)]
pub fn keyless_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> keyless::variable::Config<C, Sequential> {
    keyless::Config {
        merkle: merkle_config(prefix, page_cache.clone()),
        log: variable_journal_config(prefix, page_cache, codec_config, items_per_section),
    }
}

#[allow(dead_code)]
pub fn any_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> any::VariableConfig<TwoCap, C, Sequential> {
    any::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        journal_config: variable_journal_config(
            prefix,
            page_cache,
            codec_config,
            items_per_section,
        ),
        translator: TwoCap,
        init_cache_size: None,
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

#[allow(dead_code)]
pub fn current_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> current::VariableConfig<TwoCap, C, Sequential> {
    current::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        journal_config: variable_journal_config(
            prefix,
            page_cache,
            codec_config,
            items_per_section,
        ),
        grafted_metadata_partition: format!("{prefix}-grafted-metadata"),
        translator: TwoCap,
        init_cache_size: None,
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

#[allow(dead_code)]
pub fn immutable_variable_config<C>(
    prefix: &str,
    page_cache: CacheRef,
    codec_config: C,
    items_per_section: NonZeroU64,
) -> immutable::variable::Config<TwoCap, C, Sequential> {
    immutable::Config {
        merkle_config: merkle_config(prefix, page_cache.clone()),
        log: variable_journal_config(prefix, page_cache, codec_config, items_per_section),
        translator: TwoCap,
        init_buffer: NZUsize!(1 << 21),
    }
}

/// Spawns a local simulator and returns a client for it.
pub async fn local_store_client() -> StoreClient {
    let (_task, url) = exoware_simulator::open_temp()
        .await
        .expect("spawn simulator");
    StoreClient::new(&url)
}

#[allow(dead_code)]
pub async fn retry<F, Fut, T>(f: F, label: &str) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    for attempt in 1..=15 {
        match f().await {
            Ok(v) => return v,
            Err(e) if attempt < 15 => {
                eprintln!("{label}: attempt {attempt}/{e}, retrying...");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => panic!("{label}: failed after 15 attempts: {e}"),
        }
    }
    panic!("{label}: exhausted retries");
}

mod operations;
#[allow(unused_imports)]
pub use operations::prepare_operations;

/// Extract the one operation's bitmap chunk from a native current range proof
#[allow(dead_code)]
pub async fn current_proof_chunk<F, D, Op, E, const N: usize>(
    proof: impl std::future::Future<Output = Result<(RangeProof<F, D>, Vec<Op>, Vec<[u8; N]>), E>>,
) -> Result<(RangeProof<F, D>, [u8; N]), QmdbError>
where
    F: Graftable,
    D: Digest,
    E: std::fmt::Display,
{
    let (proof, operations, chunks) = proof
        .await
        .map_err(|error| QmdbError::CorruptData(error.to_string()))?;
    assert_eq!(operations.len(), 1, "one source operation");
    assert_eq!(chunks.len(), 1, "one source bitmap chunk");
    Ok((proof, chunks[0]))
}

#[allow(dead_code)]
pub async fn commit_operations<F, Op>(
    client: &exoware_sdk::PrefixedStoreClient,
    operations: &[Op],
    cfg: &Op::Cfg,
) -> Result<(), QmdbError>
where
    F: Family,
    Op: exoware_qmdb::UploadOperation<F>,
{
    let (_, prepared) = prepare_operations::<F, Op>(operations, cfg);
    let mut batch = exoware_sdk::StoreWriteBatch::new();
    let latest = prepared.latest_location();
    exoware_qmdb::stage_authenticated_range(client, prepared, &mut batch)?;
    exoware_qmdb::stage_watermark(client, latest, &mut batch)?;
    batch.commit(client.client()).await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn commit_current_operations<F, Op, const N: usize>(
    client: &exoware_sdk::PrefixedStoreClient,
    operations: &[Op],
    cfg: &Op::Cfg,
    boundary: &CurrentBoundaryState<commonware_cryptography::sha256::Digest, N, F>,
) -> Result<(), QmdbError>
where
    F: Graftable,
    Op: exoware_qmdb::UploadOperation<F>,
{
    let (_, prepared) = prepare_operations::<F, Op>(operations, cfg);
    let prepared =
        prepared.with_current_boundary::<commonware_cryptography::Sha256, N>(boundary)?;
    let latest = prepared.latest_location();
    let mut batch = exoware_sdk::StoreWriteBatch::new();
    exoware_qmdb::stage_authenticated_range(client, prepared, &mut batch)?;
    exoware_qmdb::stage_watermark(client, latest, &mut batch)?;
    batch.commit(client.client()).await?;
    Ok(())
}

#[allow(dead_code)]
async fn health_handler() -> &'static str {
    "ok"
}

#[allow(dead_code)]
pub async fn wait_for_health(base: &str) {
    let url = format!("{base}/health");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client
            .get(&url)
            .send()
            .await
            .ok()
            .is_some_and(|res| res.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("qmdb server did not become ready at {url}");
}

/// Bind a QMDB operation-log `ConnectRpcService` stack to a random local port
/// alongside `/health`, and block until it responds.
#[allow(dead_code)]
pub async fn spawn_connect_service<D>(
    dispatcher: ConnectRpcService<D>,
) -> (tokio::task::JoinHandle<()>, String)
where
    D: ::connectrpc::Dispatcher + Send + Sync + 'static,
{
    let app = Router::new()
        .route("/health", get(health_handler))
        .fallback_service(dispatcher);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind qmdb server");
    let port = listener.local_addr().expect("local addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

#[allow(dead_code)]
pub fn operation_log_rpc_client(base: &str) -> OperationLogServiceClient<PreferZstdHttpClient> {
    OperationLogServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("qmdb uri")),
    )
}

#[allow(dead_code)]
pub fn trusted_root<D: Digest, F: commonware_storage::merkle::Family>(
    root: D,
) -> impl FnOnce(commonware_storage::merkle::Location<F>) -> Result<D, QmdbError> {
    move |_| Ok(root)
}

/// An `OperationLogService` impl that yields one caller-supplied
/// `SubscribeResponse`
/// and then closes. Used to feed tampered proofs into the validated client.
#[derive(Clone)]
pub struct StaticOperationLogService {
    pub subscribe_response: SubscribeResponse,
}

impl OperationLogService for StaticOperationLogService {
    async fn get_operation_range(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, GetOperationRangeRequest>,
    ) -> connectrpc::ServiceResult<GetOperationRangeResponse> {
        Err(ConnectError::new(
            ErrorCode::Unimplemented,
            "not implemented",
        ))
    }

    fn subscribe(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, SubscribeRequest>,
    ) -> impl std::future::Future<
        Output = connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>>,
    > + Send {
        let response = self.subscribe_response.clone();
        async move {
            Ok(connectrpc::Response::stream(futures::stream::iter([Ok(
                response,
            )])))
        }
    }
}

/// An `OperationLogService` impl that returns one caller-supplied
/// `GetOperationRangeResponse`. Used to feed tampered range proofs into the
/// validated client.
#[derive(Clone)]
pub struct StaticOperationRangeService {
    pub operation_range_response: GetOperationRangeResponse,
}

impl OperationLogService for StaticOperationRangeService {
    async fn get_operation_range(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, GetOperationRangeRequest>,
    ) -> connectrpc::ServiceResult<GetOperationRangeResponse> {
        connectrpc::Response::ok(self.operation_range_response.clone())
    }

    async fn subscribe(
        &self,
        _ctx: Context,
        _request: ServiceRequest<'_, SubscribeRequest>,
    ) -> connectrpc::ServiceResult<connectrpc::ServiceStream<SubscribeResponse>> {
        Err(ConnectError::new(
            ErrorCode::Unimplemented,
            "not implemented",
        ))
    }
}

#[allow(dead_code)]
pub async fn spawn_static_operation_log_service(
    service: StaticOperationLogService,
) -> (tokio::task::JoinHandle<()>, String) {
    spawn_connect_service(
        ConnectRpcService::new(OperationLogServiceServer::new(service))
            .with_compression(exoware_sdk::connect_compression_registry()),
    )
    .await
}

#[allow(dead_code)]
pub async fn spawn_static_operation_range_service(
    service: StaticOperationRangeService,
) -> (tokio::task::JoinHandle<()>, String) {
    spawn_connect_service(
        ConnectRpcService::new(OperationLogServiceServer::new(service))
            .with_compression(exoware_sdk::connect_compression_registry()),
    )
    .await
}

#[allow(dead_code)]
pub fn tamper_subscribe_response(mut response: SubscribeResponse) -> SubscribeResponse {
    if let Some(proof) = response.proof.as_option_mut() {
        let mut bytes = proof.proof.to_vec();
        bytes[0] ^= 0x01;
        proof.proof = bytes.into();
    }
    response
}
