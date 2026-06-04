use bytes::Bytes;
use commonware_codec::{Encode, EncodeSize, FixedSize};
use commonware_consensus::{
    simplex::types::Context as SimplexContext,
    types::{Round, View, coding::Commitment},
};
use commonware_cryptography::{
    Digest as _, Hasher, Signer as _, ed25519,
    sha256::{Digest as Sha256Digest, Sha256},
};
use commonware_glue::stateful::db::{DatabaseSet, Unmerkleized as _};
use commonware_parallel::Rayon;
use commonware_runtime::{
    Error as RuntimeError, Storage as _, Supervisor, ThreadPooler,
    benchmarks::{context as bench_context, tokio as bench_tokio},
    buffer::paged::CacheRef,
    tokio::{Config as RuntimeConfig, Context as RuntimeContext},
};
use commonware_storage::{
    journal::contiguous::fixed::Config as FixedJournalConfig,
    merkle::{Location, compact::Config as CompactMerkleConfig, full::Config as MmrConfig, mmr},
    metadata::{Config as MetadataConfig, Metadata},
    qmdb::{
        any::{
            FixedConfig,
            operation::Operation as AnyOperation,
            unordered::{Operation as UnorderedOperation, Update as UnorderedUpdate, fixed},
            value::FixedEncoding,
        },
        keyless,
        keyless::fixed as keyless_fixed,
    },
    queue,
    translator::EightCap,
};
use commonware_utils::{
    NZU16, NZU64, NZUsize, non_empty_range,
    sequence::{FixedBytes, U64},
    sync::AsyncRwLock,
};
use constantinople_application::consensus::TransactionHistoryDb;
use constantinople_indexer::{
    publisher::{
        SqlRow,
        qmdb::{
            Publisher, QueuedFinalizedUpload, QueuedFinalizedUploadCfg, state_qmdb_client,
            transactions_qmdb_client,
        },
    },
    sql_schema::{BLOCK_META_TABLE, TX_ACTIVITY_TABLE, TX_META_TABLE, build_meta_schema},
};
use constantinople_primitives::{
    Account, AccountKey, Block, Header, Sealable, SealedBlock, SignedTransaction,
    TRANSACTION_NAMESPACE, Transaction, TransactionPublicKey,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use exoware_qmdb::{KeylessWriter, UnorderedWriter};
use exoware_sdk::{RetryConfig, StoreClient, StoreWriteBatch};
use exoware_sql::{BatchWriter, CellValue};
use std::{
    hint::black_box,
    num::{NonZeroU16, NonZeroU64, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::{sync::Semaphore, task::JoinSet};

const TX_COUNTS: [usize; 2] = [512, 4096];
const COALESCED_BLOCKS: usize = 8;
const MOVING_FINALIZED_BLOCKS: usize = 128;
const FINALIZED_UPLOAD_BACKLOG: usize = 64;
const SIMULATED_UPLOAD_TIME: Duration = Duration::from_millis(2);
const QMDB_TX_COUNTS: [usize; 2] = [50_000, 70_000];
const FINALIZED_STATE_UPDATES_PER_TX: usize = 2;
const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(1_048_576);
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const PAGE_CACHE_PAGE_SIZE: NonZeroU16 = NZU16!(8192);
const PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(16_384);
const FINALIZED_QUEUE_ITEMS_PER_SECTION: NonZeroU64 = NZU64!(128);
const FINALIZED_QUEUE_PAGE_SIZE: NonZeroU16 = NZU16!(4_096);
const FINALIZED_QUEUE_PAGE_CACHE_CAPACITY: NonZeroUsize = NZUsize!(8_192);
const FINALIZED_QUEUE_WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);
const CURSOR_STATE_KEY: U64 = U64::new(0);
const CURSOR_TRANSACTION_KEY: U64 = U64::new(1);
static FINALIZED_STATE_CAPTURE_PREFIX: AtomicU64 = AtomicU64::new(0);

type AccountValue = FixedBytes<{ Account::SIZE }>;
type StateEncoding = FixedEncoding<AccountValue>;
type BenchStateOperation = UnorderedOperation<mmr::Family, AccountKey, StateEncoding>;
type TransactionEncoding = FixedEncoding<Sha256Digest>;
type BenchTransactionOperation = keyless::Operation<mmr::Family, TransactionEncoding>;
type BenchStateWriter =
    UnorderedWriter<mmr::Family, Sha256, AccountKey, AccountValue, StateEncoding>;
type BenchTransactionWriter = KeylessWriter<mmr::Family, Sha256, Sha256Digest, TransactionEncoding>;
type BenchApplicationStateDb =
    fixed::Db<mmr::Family, RuntimeContext, AccountKey, Account, Sha256, EightCap, Rayon>;
type BenchApplicationStateDatabase = Arc<AsyncRwLock<BenchApplicationStateDb>>;
type BenchApplicationTransactionDb = TransactionHistoryDb<RuntimeContext, Sha256, Rayon>;
type BenchApplicationTransactionDatabase = Arc<AsyncRwLock<BenchApplicationTransactionDb>>;
type BenchApplicationDatabases = (
    BenchApplicationStateDatabase,
    BenchApplicationTransactionDatabase,
);
type BenchApplicationBlock = SealedBlock<Commitment, ed25519::PublicKey, Sha256>;
type BenchQueuedUpload = QueuedFinalizedUpload<Sha256, ed25519::PublicKey>;
type BenchCursorMetadata = Metadata<RuntimeContext, U64, U64>;

fn bench_sql_metadata_upload(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let store = runtime.block_on(spawn_store());
    let mut group = c.benchmark_group("indexer/sql_metadata_upload");

    for tx_count in TX_COUNTS {
        group.throughput(Throughput::Elements(tx_count as u64));

        group.bench_with_input(
            BenchmarkId::new("flush", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                let mut next_height = 1u64;
                bencher.iter_custom(|iterations| {
                    runtime.block_on(async {
                        let mut writer = build_writer(&store.client);
                        let start = Instant::now();
                        for _ in 0..iterations {
                            let height = next_height;
                            next_height += 1;
                            let sql = sql_rows(height, tx_count);
                            upload_sql(&mut writer, &sql).await;
                        }
                        start.elapsed()
                    })
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("staged_store_batch", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                let mut next_height = 1_000_000u64;
                bencher.iter_custom(|iterations| {
                    runtime.block_on(async {
                        let mut writer = build_writer(&store.client);
                        let start = Instant::now();
                        for _ in 0..iterations {
                            let height = next_height;
                            next_height += 1;
                            let sql = sql_rows(height, tx_count);
                            upload_combined(&store.client, &mut writer, sql).await;
                        }
                        start.elapsed()
                    })
                });
            },
        );

        group.throughput(Throughput::Elements(
            tx_count
                .checked_mul(COALESCED_BLOCKS)
                .expect("benchmark throughput fits usize") as u64,
        ));
        group.bench_with_input(
            BenchmarkId::new("staged_store_batch_8_blocks", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                let mut next_height = 2_000_000u64;
                bencher.iter_custom(|iterations| {
                    runtime.block_on(async {
                        let mut writer = build_writer(&store.client);
                        let start = Instant::now();
                        for _ in 0..iterations {
                            upload_combined_blocks(
                                &store.client,
                                &mut writer,
                                next_height,
                                tx_count,
                                COALESCED_BLOCKS,
                            )
                            .await;
                            next_height += COALESCED_BLOCKS as u64;
                        }
                        start.elapsed()
                    })
                });
            },
        );
    }

    group.finish();
    drop(store);
}

fn bench_finalized_upload_admission(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("indexer/finalized_upload_admission");
    group.throughput(Throughput::Elements(MOVING_FINALIZED_BLOCKS as u64));

    group.bench_function("blocking_upload", |bencher| {
        bencher.iter_custom(|iterations| {
            runtime.block_on(async {
                let start = Instant::now();
                for _ in 0..iterations {
                    blocking_finalized_uploads(MOVING_FINALIZED_BLOCKS).await;
                }
                start.elapsed()
            })
        });
    });

    group.bench_function("background_backlog_64", |bencher| {
        bencher.iter_custom(|iterations| {
            runtime.block_on(async {
                let start = Instant::now();
                for _ in 0..iterations {
                    pipelined_finalized_uploads(MOVING_FINALIZED_BLOCKS, FINALIZED_UPLOAD_BACKLOG)
                        .await;
                }
                start.elapsed()
            })
        });
    });

    group.finish();
}

fn bench_qmdb_writer_upload(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let base = StoreClient::with_retry_config("http://127.0.0.1:0", RetryConfig::disabled());
    let state_client = state_qmdb_client(&base).expect("state QMDB client");
    let transaction_client = transactions_qmdb_client(&base).expect("transaction QMDB client");
    let mut group = c.benchmark_group("indexer/qmdb_writer_upload");

    for tx_count in QMDB_TX_COUNTS {
        let state_ops = Arc::new(state_operations(tx_count));
        let transaction_ops = Arc::new(transaction_operations(tx_count));
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("prepare_stage", tx_count),
            &tx_count,
            |bencher, &_tx_count| {
                let state_ops = state_ops.clone();
                let transaction_ops = transaction_ops.clone();
                let state_client = state_client.clone();
                let transaction_client = transaction_client.clone();
                bencher.iter_custom(|iterations| {
                    let state_ops = state_ops.clone();
                    let transaction_ops = transaction_ops.clone();
                    let state_client = state_client.clone();
                    let transaction_client = transaction_client.clone();
                    runtime.block_on(async move {
                        let start = Instant::now();
                        for _ in 0..iterations {
                            let state_writer =
                                Arc::new(BenchStateWriter::empty(state_client.clone()));
                            let transaction_writer = Arc::new(BenchTransactionWriter::empty(
                                transaction_client.clone(),
                            ));
                            let state_prepare = tokio::spawn({
                                let state_writer = state_writer.clone();
                                let state_ops = state_ops.clone();
                                async move { state_writer.prepare_upload(&state_ops).await }
                            });
                            let transaction_prepare = tokio::spawn({
                                let transaction_writer = transaction_writer.clone();
                                let transaction_ops = transaction_ops.clone();
                                async move { transaction_writer.prepare_upload(&transaction_ops).await }
                            });
                            let (state_upload, transaction_upload) =
                                tokio::join!(state_prepare, transaction_prepare);
                            let mut state_upload = state_upload
                                .expect("state prepare task exits")
                                .expect("state upload prepares");
                            let mut transaction_upload = transaction_upload
                                .expect("transaction prepare task exits")
                                .expect("transaction upload prepares");
                            let state_watermark = state_writer
                                .prepare_flush_for_uploads(std::slice::from_ref(&state_upload))
                                .await
                                .expect("state watermark prepares");
                            let transaction_watermark = transaction_writer
                                .prepare_flush_for_uploads(std::slice::from_ref(
                                    &transaction_upload,
                                ))
                                .await
                                .expect("transaction watermark prepares");

                            let mut batch = StoreWriteBatch::new();
                            state_writer
                                .stage_upload(&mut state_upload, &mut batch)
                                .expect("state upload stages");
                            transaction_writer
                                .stage_upload(&mut transaction_upload, &mut batch)
                                .expect("transaction upload stages");
                            if let Some(prepared) = &state_watermark {
                                state_writer
                                    .stage_flush(prepared, &mut batch)
                                    .expect("state watermark stages");
                            }
                            if let Some(prepared) = &transaction_watermark {
                                transaction_writer
                                    .stage_flush(prepared, &mut batch)
                                    .expect("transaction watermark stages");
                            }
                            black_box(batch.len());
                        }
                        start.elapsed()
                    })
                });
            },
        );
    }

    group.finish();
}

fn bench_synthetic_full_upload_commit(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let store = runtime.block_on(spawn_store());
    let state_client = state_qmdb_client(&store.client).expect("state QMDB client");
    let transaction_client =
        transactions_qmdb_client(&store.client).expect("transaction QMDB client");
    let mut group = c.benchmark_group("indexer/synthetic_full_upload_commit");

    for tx_count in QMDB_TX_COUNTS {
        let state_ops = Arc::new(state_operations(tx_count));
        let transaction_ops = Arc::new(transaction_operations(tx_count));
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("prepare_stage_commit", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                let mut next_height = 3_000_000u64;
                let state_ops = state_ops.clone();
                let transaction_ops = transaction_ops.clone();
                let state_client = state_client.clone();
                let transaction_client = transaction_client.clone();
                bencher.iter_custom(|iterations| {
                    let state_ops = state_ops.clone();
                    let transaction_ops = transaction_ops.clone();
                    let state_client = state_client.clone();
                    let transaction_client = transaction_client.clone();
                    let client = store.client.clone();
                    runtime.block_on(async move {
                        let mut writer = build_writer(&client);
                        let start = Instant::now();
                        for _ in 0..iterations {
                            let height = next_height;
                            next_height += 1;
                            upload_synthetic_full(
                                &client,
                                &mut writer,
                                SyntheticQmdbInputs {
                                    state_client: &state_client,
                                    transaction_client: &transaction_client,
                                    state_ops: state_ops.clone(),
                                    transaction_ops: transaction_ops.clone(),
                                },
                                height,
                                tx_count,
                            )
                            .await;
                        }
                        start.elapsed()
                    })
                });
            },
        );
    }

    group.finish();
    drop(store);
}

fn bench_finalized_state_capture(c: &mut Criterion) {
    let runner = bench_tokio::Runner::new(RuntimeConfig::default());
    let mut group = c.benchmark_group("indexer/finalized_state_capture");

    for tx_count in QMDB_TX_COUNTS {
        group.throughput(Throughput::Elements(tx_count as u64));
        group.bench_with_input(
            BenchmarkId::new("build_queued_upload", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                bencher.to_async(&runner).iter_custom(move |iterations| async move {
                    let runtime = bench_context::get::<RuntimeContext>();
                    let prefix = finalized_state_capture_prefix(tx_count);
                    cleanup_application_partitions(&runtime, &prefix).await;
                    let fixture =
                        FinalizedStateCaptureFixture::new(&runtime, tx_count, &prefix).await;
                    let start = Instant::now();
                    for _ in 0..iterations {
                        let upload = Publisher::<Sha256, ed25519::PublicKey>::build_queued_finalized_upload_with_context(
                            runtime.child("finalized_state_capture"),
                            fixture.state_start,
                            fixture.transaction_start,
                            &fixture.block,
                            &fixture.databases,
                        )
                        .await
                        .expect("finalized upload captures");
                        black_box(upload.encode_size());
                    }
                    let elapsed = start.elapsed();
                    drop(fixture);
                    cleanup_application_partitions(&runtime, &prefix).await;
                    elapsed
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("build_enqueue_cursor", tx_count),
            &tx_count,
            |bencher, &tx_count| {
                bencher.to_async(&runner).iter_custom(move |iterations| async move {
                    let runtime = bench_context::get::<RuntimeContext>();
                    let prefix = finalized_state_capture_prefix(tx_count);
                    cleanup_application_partitions(&runtime, &prefix).await;
                    let fixture =
                        FinalizedStateCaptureFixture::new(&runtime, tx_count, &prefix).await;
                    let (queue_writer, _queue_reader) =
                        init_finalized_queue(&runtime, &prefix).await;
                    let mut metadata = init_finalized_cursor_metadata(&runtime, &prefix).await;
                    let start = Instant::now();
                    for _ in 0..iterations {
                        let upload = Publisher::<Sha256, ed25519::PublicKey>::build_queued_finalized_upload_with_context(
                            runtime.child("finalized_state_capture"),
                            fixture.state_start,
                            fixture.transaction_start,
                            &fixture.block,
                            &fixture.databases,
                        )
                        .await
                        .expect("finalized upload captures");
                        let state_next = upload.state_end();
                        let transaction_next = upload.transaction_end();
                        let position = queue_writer
                            .enqueue(upload)
                            .await
                            .expect("finalized queue enqueue succeeds");
                        metadata.put(CURSOR_STATE_KEY, U64::new(state_next));
                        metadata.put(CURSOR_TRANSACTION_KEY, U64::new(transaction_next));
                        metadata.sync().await.expect("cursor metadata sync succeeds");
                        black_box(position);
                    }
                    let elapsed = start.elapsed();
                    drop(metadata);
                    drop(queue_writer);
                    drop(fixture);
                    cleanup_application_partitions(&runtime, &prefix).await;
                    elapsed
                });
            },
        );
    }

    group.finish();
}

async fn blocking_finalized_uploads(blocks: usize) {
    for _ in 0..blocks {
        simulated_upload().await;
    }
}

async fn pipelined_finalized_uploads(blocks: usize, backlog: usize) {
    let backlog = Arc::new(Semaphore::new(backlog));
    let mut uploads = JoinSet::new();

    for _ in 0..blocks {
        let permit = backlog
            .clone()
            .acquire_owned()
            .await
            .expect("benchmark semaphore is open");
        uploads.spawn(async move {
            let _permit = permit;
            simulated_upload().await;
        });
    }

    while let Some(result) = uploads.join_next().await {
        result.expect("simulated upload task should finish");
    }
}

async fn simulated_upload() {
    tokio::time::sleep(SIMULATED_UPLOAD_TIME).await;
}

struct BenchStore {
    client: StoreClient,
    _handle: tokio::task::JoinHandle<()>,
    _dir: TempDir,
}

async fn spawn_store() -> BenchStore {
    let dir = TempDir::new().expect("tempdir");
    let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
        .await
        .expect("spawn simulator");
    let client = StoreClient::with_retry_config(&url, RetryConfig::disabled());
    BenchStore {
        client,
        _handle: handle,
        _dir: dir,
    }
}

struct FinalizedStateCaptureFixture {
    databases: BenchApplicationDatabases,
    block: BenchApplicationBlock,
    state_start: u64,
    transaction_start: u64,
}

impl FinalizedStateCaptureFixture {
    async fn new(runtime: &RuntimeContext, tx_count: usize, prefix: &str) -> Self {
        let strategy = application_strategy(runtime);
        let databases = BenchApplicationDatabases::init(
            runtime.child("application_databases"),
            (
                application_state_db_config(runtime, prefix, strategy.clone()),
                application_transaction_db_config(prefix, strategy),
            ),
        )
        .await;

        let state_update_count = tx_count
            .checked_mul(FINALIZED_STATE_UPDATES_PER_TX)
            .expect("state update count fits usize");
        let (state_batch, transaction_batch) = databases.new_batches().await;
        let state_batch = (0..state_update_count).fold(state_batch, |batch, index| {
            batch.write(
                account_key(index as u64),
                Some(Account {
                    balance: (index as u64).saturating_add(1),
                    nonce: index as u64,
                }),
            )
        });
        let (state_merkleized, transaction_merkleized) =
            futures::join!(state_batch.merkleize(), transaction_batch.merkleize());
        databases
            .finalize((
                state_merkleized.expect("state merkleization should succeed"),
                transaction_merkleized.expect("transaction merkleization should succeed"),
            ))
            .await;

        let (state_target, _) = databases.committed_targets().await;
        let state_start = *state_target.range.start();
        let state_end = *state_target.range.end();
        let transaction_start = 0;
        let block = finalized_state_capture_block(
            tx_count,
            state_target.root,
            state_start,
            state_end,
            transaction_start,
        );

        Self {
            databases,
            block,
            state_start,
            transaction_start,
        }
    }
}

fn finalized_state_capture_block(
    tx_count: usize,
    state_root: Sha256Digest,
    state_start: u64,
    state_end: u64,
    transaction_start: u64,
) -> BenchApplicationBlock {
    let leader = ed25519::PrivateKey::from_seed(u64::MAX).public_key();
    let tx = signed_transaction();
    let transactions = vec![tx; tx_count];
    let transaction_end = transaction_start
        .checked_add(tx_count as u64)
        .and_then(|end| end.checked_add(2))
        .expect("transaction range fits u64");
    let header = Header {
        context: SimplexContext {
            round: Round::zero(),
            leader,
            parent: (View::zero(), Commitment::EMPTY),
        },
        parent: Sha256Digest::EMPTY,
        height: 1,
        timestamp: 0,
        state_root,
        state_range: non_empty_range!(state_start, state_end),
        transactions_root: Sha256Digest::EMPTY,
        transactions_range: non_empty_range!(transaction_start, transaction_end),
    };

    Block::new(header, transactions).seal(&mut Sha256::default())
}

fn signed_transaction() -> SignedTransaction<Sha256> {
    let sender = ed25519::PrivateKey::from_seed(1);
    let recipient = ed25519::PrivateKey::from_seed(2).public_key();
    Transaction::new(
        TransactionPublicKey::ed25519(sender.public_key()),
        TransactionPublicKey::ed25519(recipient),
        NonZeroU64::new(1).expect("transaction value is non-zero"),
        0,
    )
    .seal_and_sign(&sender, TRANSACTION_NAMESPACE, &mut Sha256::default())
}

fn application_strategy(runtime: &RuntimeContext) -> Rayon {
    Rayon::with_pool(runtime.create_thread_pool(NZUsize!(8)).unwrap())
}

fn application_state_db_config(
    runtime: &RuntimeContext,
    prefix: &str,
    strategy: Rayon,
) -> FixedConfig<EightCap, Rayon> {
    let page_cache = CacheRef::from_pooler(
        &runtime.child("state_page_cache"),
        PAGE_CACHE_PAGE_SIZE,
        PAGE_CACHE_CAPACITY,
    );

    FixedConfig {
        merkle_config: MmrConfig {
            journal_partition: format!("{prefix}-state-journal"),
            metadata_partition: format!("{prefix}-state-metadata"),
            items_per_blob: ITEMS_PER_BLOB,
            write_buffer: WRITE_BUFFER,
            strategy,
            page_cache: page_cache.clone(),
        },
        journal_config: FixedJournalConfig {
            partition: format!("{prefix}-state-log"),
            items_per_blob: ITEMS_PER_BLOB,
            page_cache,
            write_buffer: WRITE_BUFFER,
        },
        translator: EightCap,
    }
}

fn application_transaction_db_config(
    prefix: &str,
    strategy: Rayon,
) -> keyless_fixed::CompactConfig<Rayon> {
    keyless_fixed::CompactConfig {
        merkle: CompactMerkleConfig {
            partition: format!("{prefix}-transactions-merkle"),
            strategy,
        },
        commit_codec_config: (),
    }
}

fn finalized_state_capture_prefix(tx_count: usize) -> String {
    let id = FINALIZED_STATE_CAPTURE_PREFIX.fetch_add(1, Ordering::Relaxed);
    format!("indexer-finalized-state-capture-{tx_count}-{id}")
}

async fn cleanup_application_partitions(runtime: &RuntimeContext, prefix: &str) {
    for partition in [
        format!("{prefix}-state-journal"),
        format!("{prefix}-state-metadata"),
        format!("{prefix}-state-log"),
        format!("{prefix}-transactions-merkle"),
        format!("{prefix}-finalized-index-queue"),
        format!("{prefix}-finalized-index-cursor"),
    ] {
        match runtime.remove(&partition, None).await {
            Ok(()) | Err(RuntimeError::PartitionMissing(_)) => {}
            Err(error) => panic!("benchmark partition cleanup should succeed: {error}"),
        }
    }
}

async fn init_finalized_queue(
    runtime: &RuntimeContext,
    prefix: &str,
) -> (
    queue::Writer<RuntimeContext, BenchQueuedUpload>,
    queue::Reader<RuntimeContext, BenchQueuedUpload>,
) {
    let page_cache = CacheRef::from_pooler(
        runtime,
        FINALIZED_QUEUE_PAGE_SIZE,
        FINALIZED_QUEUE_PAGE_CACHE_CAPACITY,
    );
    queue::shared::init(
        runtime.child("finalized_queue"),
        queue::Config {
            partition: format!("{prefix}-finalized-index-queue"),
            items_per_section: FINALIZED_QUEUE_ITEMS_PER_SECTION,
            compression: None,
            codec_config: QueuedFinalizedUploadCfg::default(),
            page_cache,
            write_buffer: FINALIZED_QUEUE_WRITE_BUFFER,
        },
    )
    .await
    .expect("finalized queue initializes")
}

async fn init_finalized_cursor_metadata(
    runtime: &RuntimeContext,
    prefix: &str,
) -> BenchCursorMetadata {
    Metadata::init(
        runtime.child("finalized_cursor"),
        MetadataConfig {
            partition: format!("{prefix}-finalized-index-cursor"),
            codec_config: (),
        },
    )
    .await
    .expect("finalized cursor metadata initializes")
}

fn build_writer(client: &StoreClient) -> BatchWriter {
    build_meta_schema(client.clone())
        .expect("meta schema")
        .batch_writer()
}

async fn upload_sql(writer: &mut BatchWriter, rows: &[SqlRow]) {
    insert_sql_rows(writer, rows);
    writer.flush().await.expect("sql flush");
}

async fn upload_combined(client: &StoreClient, writer: &mut BatchWriter, sql: Vec<SqlRow>) {
    insert_sql_rows(writer, &sql);
    let prepared = writer
        .prepare_flush()
        .expect("sql prepare")
        .expect("sql rows are present");
    let mut batch = StoreWriteBatch::new();
    batch.reserve(prepared.entry_count());
    writer
        .stage_flush(&prepared, &mut batch)
        .expect("sql rows stage");
    let seq = batch.commit(client).await.expect("combined commit");
    writer.mark_flush_persisted(prepared, seq);
}

async fn upload_combined_blocks(
    client: &StoreClient,
    writer: &mut BatchWriter,
    start_height: u64,
    tx_count: usize,
    block_count: usize,
) {
    let mut sql = Vec::with_capacity(block_count * (1 + 3 * tx_count));
    for offset in 0..block_count {
        let height = start_height + offset as u64;
        sql.extend(sql_rows(height, tx_count));
    }
    upload_combined(client, writer, sql).await;
}

async fn upload_synthetic_full(
    client: &StoreClient,
    writer: &mut BatchWriter,
    qmdb: SyntheticQmdbInputs<'_>,
    height: u64,
    tx_count: usize,
) {
    let state_writer = Arc::new(BenchStateWriter::empty(qmdb.state_client.clone()));
    let transaction_writer = Arc::new(BenchTransactionWriter::empty(
        qmdb.transaction_client.clone(),
    ));
    let sql = sql_rows(height, tx_count);
    insert_sql_rows(writer, &sql);
    let prepared_sql = writer
        .prepare_flush()
        .expect("sql prepare")
        .expect("sql rows are present");
    let state_prepare = tokio::spawn({
        let state_writer = state_writer.clone();
        let state_ops = qmdb.state_ops.clone();
        async move { state_writer.prepare_upload(&state_ops).await }
    });
    let transaction_prepare = tokio::spawn({
        let transaction_writer = transaction_writer.clone();
        let transaction_ops = qmdb.transaction_ops.clone();
        async move { transaction_writer.prepare_upload(&transaction_ops).await }
    });
    let (state_upload, transaction_upload) = tokio::join!(state_prepare, transaction_prepare);
    let mut state_upload = state_upload
        .expect("state prepare task exits")
        .expect("state upload prepares");
    let mut transaction_upload = transaction_upload
        .expect("transaction prepare task exits")
        .expect("transaction upload prepares");
    let state_watermark = state_writer
        .prepare_flush_for_uploads(std::slice::from_ref(&state_upload))
        .await
        .expect("state watermark prepares");
    let transaction_watermark = transaction_writer
        .prepare_flush_for_uploads(std::slice::from_ref(&transaction_upload))
        .await
        .expect("transaction watermark prepares");
    let mut batch = StoreWriteBatch::new();
    batch.reserve(prepared_sql.entry_count());
    writer
        .stage_flush(&prepared_sql, &mut batch)
        .expect("sql rows stage");
    state_writer
        .stage_upload(&mut state_upload, &mut batch)
        .expect("state upload stages");
    transaction_writer
        .stage_upload(&mut transaction_upload, &mut batch)
        .expect("transaction upload stages");
    if let Some(prepared) = &state_watermark {
        state_writer
            .stage_flush(prepared, &mut batch)
            .expect("state watermark stages");
    }
    if let Some(prepared) = &transaction_watermark {
        transaction_writer
            .stage_flush(prepared, &mut batch)
            .expect("transaction watermark stages");
    }

    let seq = batch.commit(client).await.expect("full upload commit");
    writer.mark_flush_persisted(prepared_sql, seq);
    state_writer.mark_upload_persisted(state_upload, seq).await;
    transaction_writer
        .mark_upload_persisted(transaction_upload, seq)
        .await;
    if let Some(prepared) = state_watermark {
        state_writer.mark_flush_persisted(prepared, seq).await;
    }
    if let Some(prepared) = transaction_watermark {
        transaction_writer.mark_flush_persisted(prepared, seq).await;
    }
    black_box(seq);
}

struct SyntheticQmdbInputs<'a> {
    state_client: &'a StoreClient,
    transaction_client: &'a StoreClient,
    state_ops: Arc<Vec<BenchStateOperation>>,
    transaction_ops: Arc<Vec<BenchTransactionOperation>>,
}

fn insert_sql_rows(writer: &mut BatchWriter, rows: &[SqlRow]) {
    for row in rows {
        writer
            .insert(row.table, row.values.clone())
            .expect("sql row encodes");
    }
}

fn sql_rows(height: u64, tx_count: usize) -> Vec<SqlRow> {
    let mut rows = Vec::with_capacity(1 + 3 * tx_count);
    rows.push(SqlRow {
        table: BLOCK_META_TABLE,
        values: vec![
            CellValue::UInt64(height),
            CellValue::FixedBinary(digest(height).to_vec()),
            CellValue::UInt64(tx_count as u64),
            CellValue::FixedBinary(digest(height ^ 0xA5A5).to_vec()),
            CellValue::UInt64(height.saturating_mul(tx_count as u64 + 1)),
            CellValue::UInt64(0),
            CellValue::Timestamp(height as i64),
        ],
    });
    for idx in 0..tx_count {
        let tx_digest = digest(height ^ (idx as u64).rotate_left(17));
        let sender = digest((idx as u64).rotate_left(7));
        let receiver = digest((idx as u64).rotate_left(11) ^ 0xA5);
        let qmdb_location = height
            .saturating_mul(tx_count as u64 + 1)
            .saturating_add(idx as u64);
        rows.push(SqlRow {
            table: TX_META_TABLE,
            values: vec![
                CellValue::UInt64(height),
                CellValue::UInt64(idx as u64),
                CellValue::FixedBinary(tx_digest.to_vec()),
                CellValue::FixedBinary(sender.to_vec()),
                CellValue::FixedBinary(receiver.to_vec()),
                CellValue::UInt64(idx as u64 + 1),
                CellValue::UInt64(idx as u64),
                CellValue::UInt64(qmdb_location),
                CellValue::Utf8(hex_lower(&tx_digest)),
            ],
        });
        rows.push(activity_row(
            sender,
            0,
            height,
            idx,
            tx_digest,
            receiver,
            qmdb_location,
        ));
        rows.push(activity_row(
            receiver,
            1,
            height,
            idx,
            tx_digest,
            sender,
            qmdb_location,
        ));
    }
    rows
}

fn activity_row(
    account: [u8; 32],
    role: u64,
    height: u64,
    idx: usize,
    tx_digest: [u8; 32],
    counterparty: [u8; 32],
    qmdb_location: u64,
) -> SqlRow {
    SqlRow {
        table: TX_ACTIVITY_TABLE,
        values: vec![
            CellValue::FixedBinary(account.to_vec()),
            CellValue::UInt64(u64::MAX - height),
            CellValue::UInt64(u64::MAX - idx as u64),
            CellValue::UInt64(role),
            CellValue::UInt64(height),
            CellValue::UInt64(idx as u64),
            CellValue::FixedBinary(tx_digest.to_vec()),
            CellValue::FixedBinary(counterparty.to_vec()),
            CellValue::UInt64(idx as u64 + 1),
            CellValue::UInt64(idx as u64),
            CellValue::UInt64(qmdb_location),
        ],
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn digest(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, chunk) in out.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_add(idx as u64).to_be_bytes());
    }
    out
}

fn state_operations(count: usize) -> Vec<BenchStateOperation> {
    let mut ops = Vec::with_capacity(count + 1);
    for index in 0..count {
        ops.push(AnyOperation::Update(UnorderedUpdate(
            account_key(index as u64),
            encode_account(Account {
                balance: (index as u64).saturating_add(1),
                nonce: index as u64,
            }),
        )));
    }
    ops.push(AnyOperation::CommitFloor(None, Location::new(0)));
    ops
}

fn transaction_operations(count: usize) -> Vec<BenchTransactionOperation> {
    let mut ops = Vec::with_capacity(count + 2);
    ops.push(BenchTransactionOperation::Commit(None, Location::new(0)));
    for index in 0..count {
        ops.push(BenchTransactionOperation::Append(Sha256::hash(
            &index.to_be_bytes(),
        )));
    }
    ops.push(BenchTransactionOperation::Commit(None, Location::new(0)));
    ops
}

fn account_key(seed: u64) -> AccountKey {
    let mut bytes = [0u8; AccountKey::SIZE];
    for (idx, chunk) in bytes.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_add(idx as u64).to_be_bytes());
    }
    AccountKey::from_bytes(Bytes::copy_from_slice(&bytes)).expect("synthetic account key")
}

fn encode_account(account: Account) -> AccountValue {
    let bytes = account.encode();
    let mut out = [0u8; Account::SIZE];
    out.copy_from_slice(&bytes);
    FixedBytes::new(out)
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3));
    targets = bench_sql_metadata_upload, bench_finalized_upload_admission, bench_qmdb_writer_upload, bench_synthetic_full_upload_commit, bench_finalized_state_capture
}
criterion_main!(benches);
