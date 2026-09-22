#![allow(clippy::type_complexity)]

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{routing::get, Router};
use clap::{Parser, Subcommand};
use commonware_codec::Encode;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::tokio as cw_tokio;
use commonware_runtime::Runner as _;
use commonware_storage::qmdb::any::ordered::variable::Operation as VariableOperation;
use commonware_storage::qmdb::current::{
    ordered::variable::Db as CurrentOrderedVariableDb, VariableConfig,
};
use commonware_storage::translator::TwoCap;
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig,
    merkle::{full::Config as MerkleConfig, mmb, Location},
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use exoware_qmdb::{
    ordered_connect_stack, prepare_authenticated_range, recover_boundary_state,
    stage_authenticated_range, stage_watermark, AuthenticatedOperationRange, CurrentBoundaryState,
    OrderedClient, MAX_OPERATION_SIZE,
};
use exoware_sdk::{PrefixedStoreClient, StoreClient, StoreKeyPrefix, StoreWriteBatch};
use tower_http::cors::CorsLayer;
use tracing::info;

const N: usize = 32;
type Family = mmb::Family;
type Operation = VariableOperation<Family, Vec<u8>, Vec<u8>>;
type Db = CurrentOrderedVariableDb<
    Family,
    cw_tokio::Context,
    Vec<u8>,
    Vec<u8>,
    Sha256,
    TwoCap,
    N,
    Sequential,
>;

#[derive(Parser, Debug)]
#[command(
    name = "qmdb",
    version,
    about = "Ordered QMDB server over the store API."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Run {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value = "0.0.0.0")]
        host: IpAddr,
        #[arg(long, default_value_t = 8081)]
        port: u16,
    },
    Seed {
        #[arg(long)]
        store_url: String,
        #[arg(long, default_value_t = 2)]
        interval_secs: u64,
        /// Persistent directory for the local ordered-QMDB state. Reusing the
        /// same directory across restarts preserves the write log. Deleting it
        /// resets the demo. Defaults to `$HOME/.exoware_qmdb_mmb_seed`.
        #[arg(long)]
        directory: Option<PathBuf>,
    },
}

async fn health() -> &'static str {
    "ok"
}

async fn publish_source_range(
    store_client: &PrefixedStoreClient,
    source_db: &Db,
    start: Location<Family>,
    boundary: &CurrentBoundaryState<commonware_cryptography::sha256::Digest, N, Family>,
) {
    let end = source_db.bounds().end;
    let (proof, operations) = source_db
        .ops_historical_proof(
            end,
            start,
            NonZeroU64::new(*end - *start).expect("nonempty range"),
        )
        .await
        .expect("operation proof");
    let pinned_nodes = source_db
        .pinned_nodes_at(start)
        .await
        .expect("pinned nodes");
    let encoded_operations = operations
        .iter()
        .map(|operation| operation.encode().to_vec())
        .collect::<Vec<_>>();
    let range = AuthenticatedOperationRange {
        start_location: start,
        proof: &proof,
        pinned_nodes: &pinned_nodes,
        encoded_operations: &encoded_operations,
    };
    let prepared = prepare_authenticated_range::<Family, Sha256, Operation, Sequential>(
        &range,
        &source_db.ops_root(),
        &op_cfg(),
        &Sequential,
    )
    .expect("prepare authenticated range")
    .with_current_boundary::<Sha256, N>(boundary)
    .expect("current boundary");
    let mut batch = StoreWriteBatch::new();
    stage_authenticated_range(store_client, prepared, &mut batch).expect("stage range");
    publish_source_rows(store_client, batch, end - 1)
        .await
        .expect("commit upload");
}

async fn publish_source_rows(
    store_client: &PrefixedStoreClient,
    rows: StoreWriteBatch,
    tip: Location<Family>,
) -> Result<(), exoware_qmdb::QmdbError> {
    // Operation rows are capped at 64 KiB and this seed's boundary rows are smaller;
    // 1024 rows fit below Store's 256 MiB request limit, including keys and framing.
    let physical = store_client.client().prefixed(StoreKeyPrefix::identity());
    let mut batch = StoreWriteBatch::new();
    for (key, value) in rows.entries() {
        if batch.len() == 1024 {
            batch.commit(store_client.client()).await?;
            batch.clear();
        }
        batch.push(&physical, key, value.clone())?;
    }

    stage_watermark(store_client, tip, &mut batch)?;
    batch.commit(store_client.client()).await?;
    Ok(())
}

fn op_cfg() -> <Operation as commonware_codec::Read>::Cfg {
    (
        ((0..=MAX_OPERATION_SIZE).into(), ()),
        ((0..=MAX_OPERATION_SIZE).into(), ()),
    )
}

fn key_cfg() -> <Vec<u8> as commonware_codec::Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

async fn boundary_from_source_db(
    source_db: &Db,
    previous_operations: Option<&[Operation]>,
    operations: &[Operation],
) -> CurrentBoundaryState<commonware_cryptography::sha256::Digest, N, Family> {
    let ops_root_witness = source_db
        .ops_root_witness()
        .await
        .expect("ops root witness");
    recover_boundary_state::<Family, Sha256, _, N, _, _>(
        previous_operations,
        operations,
        source_db.root(),
        0,
        ops_root_witness,
        |location| async move {
            let (proof, mut proof_ops, mut chunks) = source_db
                .range_proof(location, NZU64!(1))
                .await
                .map_err(|error| {
                    exoware_qmdb::QmdbError::CorruptData(format!(
                        "local current range proof at {location}: {error}"
                    ))
                })?;
            proof_ops.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no operations"
                ))
            })?;
            let chunk = chunks.pop().ok_or_else(|| {
                exoware_qmdb::QmdbError::CorruptData(format!(
                    "local current range proof at {location} returned no chunks"
                ))
            })?;
            Ok((proof, chunk))
        },
    )
    .await
    .expect("recover boundary state")
}

async fn run(
    store_url: &str,
    host: IpAddr,
    port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let qmdb_client = Arc::new(OrderedClient::<Family, Sha256, Vec<u8>, Vec<u8>, N>::new(
        StoreClient::new(store_url).prefixed(StoreKeyPrefix::identity()),
        op_cfg(),
        key_cfg(),
    ));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(ordered_connect_stack(qmdb_client))
        .layer(CorsLayer::very_permissive());

    let addr = SocketAddr::from((host, port));
    info!(%addr, store_url, "ordered qmdb server listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn default_seed_directory() -> PathBuf {
    let home = std::env::var("HOME").expect("$HOME is not configured");
    PathBuf::from(format!("{home}/.exoware_qmdb_mmb_seed"))
}

async fn seed(
    store_url: &str,
    interval_secs: u64,
    directory: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let directory = directory.unwrap_or_else(default_seed_directory);
    info!(
        directory = %directory.display(),
        store_url,
        interval_secs,
        "starting seed"
    );

    let store_client = StoreClient::new(store_url).prefixed(StoreKeyPrefix::identity());

    tokio::task::spawn_blocking(move || {
        let runner_cfg = cw_tokio::Config::new().with_storage_directory(directory);
        cw_tokio::Runner::new(runner_cfg).start(|context| async move {
            use commonware_runtime::{buffer::paged::CacheRef, Supervisor as _};

            let page_cache = CacheRef::from_pooler(&context, NZU16!(64), NZUsize!(8));
            let cfg = VariableConfig {
                merkle_config: MerkleConfig {
                    journal_partition: "current-ordered-variable-mmb-seed-merkle-journal".into(),
                    metadata_partition: "current-ordered-variable-mmb-seed-merkle-metadata".into(),
                    items_per_blob: NZU64!(8),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    strategy: Sequential,
                    page_cache: page_cache.clone(),
                },
                journal_config: JournalConfig {
                    partition: "current-ordered-variable-mmb-seed-log".into(),
                    write_buffer: NZUsize!(1024),
                    replay_buffer: NZUsize!(1024),
                    compression: None,
                    codec_config: (
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                        ((0..=MAX_OPERATION_SIZE).into(), ()),
                    ),
                    items_per_section: NZU64!(8),
                    page_cache,
                },
                grafted_metadata_partition: "current-ordered-variable-mmb-seed-grafted-metadata"
                    .into(),
                translator: TwoCap,
                init_cache_size: None,
                init_buffer: NZUsize!(1 << 21),
                init_concurrency: (),
            };
            let mut source_db = Db::init(context.child("current_ordered_variable_mmb_seed"), cfg)
                .await
                .expect("init local ordered db");

            let end = source_db.bounds().end;
            let (_, mut previous_operations) = source_db
                .ops_historical_proof(
                    end,
                    Location::new(0),
                    NonZeroU64::new(*end).expect("initial commit"),
                )
                .await
                .expect("read local operation history");
            let committed_batches = previous_operations
                .iter()
                .filter(|operation| matches!(operation, Operation::CommitFloor(_, _)))
                .count()
                .saturating_sub(1) as u64;
            let mut counter = committed_batches * 3;
            // Replay the local durable prefix so a restart repairs any interrupted upload
            let boundary = boundary_from_source_db(&source_db, None, &previous_operations).await;
            publish_source_range(&store_client, &source_db, Location::new(0), &boundary).await;
            info!(
                tip = *end - 1,
                batches = committed_batches,
                "local prefix published"
            );

            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    _ = tokio::signal::ctrl_c() => {
                        info!("ctrl-c received, shutting down");
                        break;
                    }
                    _ = ticker.tick() => {}
                }

                let finalized = {
                    let mut batch = source_db.new_batch();
                    for offset in 0..3u64 {
                        let key = format!("k-{:08x}", counter + offset).into_bytes();
                        let value = format!("v-{:08x}", counter + offset).into_bytes();
                        batch = batch.write(key, Some(value));
                    }
                    if counter >= 3 {
                        let rewrite_key = format!("k-{:08x}", counter - 3).into_bytes();
                        let rewrite_value = format!("v-{:08x}-r", counter).into_bytes();
                        batch = batch.write(rewrite_key, Some(rewrite_value));
                    }
                    if counter >= 6 && counter.is_multiple_of(12) {
                        let delete_key = format!("k-{:08x}", counter - 6).into_bytes();
                        batch = batch.write(delete_key, None);
                    }
                    counter += 3;
                    batch
                        .merkleize(&source_db, None::<Vec<u8>>)
                        .await
                        .expect("merkleize")
                };
                (source_db, _) = source_db.apply_batch(finalized).await.expect("apply batch");
                source_db = source_db.sync().await.expect("sync local ordered db");

                let latest = source_db.bounds().end - 1;
                let count = NonZeroU64::new(*latest + 1).expect("non-zero op count");
                let (_proof, operations) = source_db
                    .ops_historical_proof(latest + 1, Location::<Family>::new(0), count)
                    .await
                    .expect("historical proof");
                let boundary =
                    boundary_from_source_db(&source_db, Some(&previous_operations), &operations)
                        .await;
                let start = Location::new(previous_operations.len() as u64);
                publish_source_range(&store_client, &source_db, start, &boundary).await;

                let root = boundary.root;
                println!("tip={} root=0x{}", *latest, hex::encode(root.encode()),);

                previous_operations = operations;
            }

            source_db.sync().await.expect("sync local ordered db");
        })
    })
    .await?;
    Ok(())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .try_init();
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    init_tracing();
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Run {
            store_url,
            host,
            port,
        } => run(&store_url, host, port).await,
        Command::Seed {
            store_url,
            interval_secs,
            directory,
        } => seed(&store_url, interval_secs, directory).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("qmdb failed: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[allow(refining_impl_trait)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use connectrpc::{ConnectError, ConnectRpcService, Limits, RequestContext, ServiceRequest};
    use exoware_sdk::{
        ingest::{PutRequest, PutResponse, Service, ServiceServer},
        keys::Key,
    };
    use std::{collections::BTreeMap, sync::Mutex};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Failure {
        BeforeData,
        AfterData,
        AfterPublication,
    }

    #[derive(Default)]
    struct Uploads {
        rows: BTreeMap<Key, Bytes>,
        expected: BTreeMap<Key, Bytes>,
        watermark: Key,
        sizes: Vec<usize>,
        publications: usize,
        failure: Option<Failure>,
    }

    #[derive(Clone)]
    struct Ingest(Arc<Mutex<Uploads>>);

    impl Service for Ingest {
        async fn put(
            &self,
            _: RequestContext,
            request: ServiceRequest<'_, PutRequest>,
        ) -> connectrpc::ServiceResult<PutResponse> {
            let mut state = self.0.lock().unwrap();
            state.sizes.push(request.bytes().len());
            let publishes = request.kvs.iter().any(|entry| entry.key == state.watermark);
            let fails = match state.failure {
                Some(Failure::BeforeData | Failure::AfterData) => state.sizes.len() == 2,
                Some(Failure::AfterPublication) => publishes,
                None => false,
            };
            if fails && state.failure == Some(Failure::BeforeData) {
                return Err(ConnectError::unavailable("data write not accepted"));
            }
            for entry in request.kvs.iter() {
                state.rows.insert(
                    Bytes::copy_from_slice(entry.key),
                    Bytes::copy_from_slice(entry.value),
                );
            }
            if publishes {
                state.publications += 1;
                for (key, value) in &state.expected {
                    assert_eq!(
                        state.rows.get(key),
                        Some(value),
                        "publication before complete data"
                    );
                }
            }
            if fails {
                return Err(ConnectError::unavailable(
                    "accepted write lost its response",
                ));
            }
            connectrpc::Response::ok(PutResponse {
                sequence_number: state.sizes.len() as u64,
                ..Default::default()
            })
        }
    }

    #[tokio::test]
    async fn startup_replay_is_bounded_and_publishes_only_complete_data() {
        const LIMIT: usize = 256 * 1024;
        for failure in [
            None,
            Some(Failure::BeforeData),
            Some(Failure::AfterData),
            Some(Failure::AfterPublication),
        ] {
            let state = Arc::new(Mutex::new(Uploads::default()));
            let service = ConnectRpcService::new(ServiceServer::new(Ingest(state.clone())))
                .with_limits(
                    Limits::default()
                        .with_max_request_body_size(LIMIT)
                        .with_max_message_size(LIMIT),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, Router::new().fallback_service(service))
                    .await
                    .unwrap();
            });
            let client = StoreClient::new(&url).prefixed(StoreKeyPrefix::new(vec![0xaa]).unwrap());
            let physical = client.client().prefixed(StoreKeyPrefix::identity());
            let mut data = StoreWriteBatch::new();
            for index in 0..4097u64 {
                let mut key = vec![0xf0];
                key.extend(index.to_be_bytes());
                data.push(&client, &Bytes::from(key), vec![index as u8; 128])
                    .unwrap();
            }
            assert!(
                data.entries()
                    .iter()
                    .map(|(key, value)| key.len() + value.len())
                    .sum::<usize>()
                    > LIMIT
            );
            let tip = Location::new(4096);
            let mut publication = StoreWriteBatch::new();
            stage_watermark(&client, tip, &mut publication).unwrap();
            let watermark = publication.entries()[0].0.clone();

            // Normal small writes can build a history too large for one startup request.
            let existing = if failure.is_none() { data.len() } else { 256 };
            for (index, rows) in data.entries()[..existing].chunks(256).enumerate() {
                let mut batch = StoreWriteBatch::new();
                for (key, value) in rows {
                    batch.push(&physical, key, value.clone()).unwrap();
                }
                publish_source_rows(
                    &client,
                    batch,
                    Location::new(((index * 256 + rows.len()) - 1) as u64),
                )
                .await
                .unwrap();
            }
            {
                let mut state = state.lock().unwrap();
                state.sizes.clear();
                state.expected = data.entries().iter().cloned().collect();
                state.watermark = watermark.clone();
                state.failure = failure;
            }

            let result = publish_source_rows(&client, data.clone(), tip).await;
            if let Some(failure) = failure {
                assert!(result.is_err(), "{failure:?}");
                let mut state = state.lock().unwrap();
                assert_eq!(
                    state.rows.contains_key(&watermark),
                    failure == Failure::AfterPublication
                );
                assert_eq!(
                    state.publications,
                    usize::from(failure == Failure::AfterPublication)
                );
                state.failure = None;
            } else {
                result.expect(
                    "restart replays a history accumulated through successful small writes",
                );
            }
            publish_source_rows(&client, data, tip).await.unwrap();
            let state = state.lock().unwrap();
            assert!(state.rows.contains_key(&watermark));
            assert!(state.sizes.iter().all(|size| *size <= LIMIT));
            for (key, value) in &state.expected {
                assert_eq!(state.rows.get(key), Some(value));
            }
            server.abort();
        }
    }
}
