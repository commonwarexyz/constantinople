use bytes::Bytes;
use constantinople_indexer::{
    keys,
    publisher::SqlRow,
    sql_schema::{BLOCK_META_TABLE, TX_META_TABLE, build_meta_schema},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use exoware_sdk::{RetryConfig, StoreClient, StoreWriteBatch, keys::Key};
use exoware_sql::{BatchWriter, CellValue};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const TX_COUNTS: [usize; 2] = [512, 4096];
const COALESCED_BLOCKS: usize = 8;

fn bench_raw_sql_upload(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let store = runtime.block_on(spawn_store());
    let mut group = c.benchmark_group("indexer/raw_sql_upload");

    for tx_count in TX_COUNTS {
        group.throughput(Throughput::Elements(tx_count as u64));

        group.bench_with_input(
            BenchmarkId::new("separate_commits", tx_count),
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
                            let raw = raw_rows(height, tx_count);
                            let sql = sql_rows(height, tx_count);
                            upload_raw(&store.client, &raw).await;
                            upload_sql(&mut writer, &sql).await;
                        }
                        start.elapsed()
                    })
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("combined_store_batch", tx_count),
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
                            let raw = raw_rows(height, tx_count);
                            let sql = sql_rows(height, tx_count);
                            upload_combined(&store.client, &mut writer, &raw, &sql).await;
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
            BenchmarkId::new("combined_store_batch_8_blocks", tx_count),
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

fn build_writer(client: &StoreClient) -> BatchWriter {
    build_meta_schema(client.clone())
        .expect("meta schema")
        .batch_writer()
}

async fn upload_raw(client: &StoreClient, rows: &[(Key, Bytes)]) {
    let kvs: Vec<(&Key, &[u8])> = rows
        .iter()
        .map(|(key, value)| (key, value.as_ref()))
        .collect();
    client.ingest().put(&kvs).await.expect("raw upload");
}

async fn upload_sql(writer: &mut BatchWriter, rows: &[SqlRow]) {
    insert_sql_rows(writer, rows);
    writer.flush().await.expect("sql flush");
}

async fn upload_combined(
    client: &StoreClient,
    writer: &mut BatchWriter,
    raw: &[(Key, Bytes)],
    sql: &[SqlRow],
) {
    insert_sql_rows(writer, sql);
    let prepared = writer
        .prepare_flush()
        .expect("sql prepare")
        .expect("sql rows are present");
    let mut batch = StoreWriteBatch::new();
    for (key, value) in raw {
        batch.push(client, key, value).expect("raw row stages");
    }
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
    let mut raw = Vec::with_capacity(block_count * (2 + 2 * tx_count));
    let mut sql = Vec::with_capacity(block_count * (1 + tx_count));
    for offset in 0..block_count {
        let height = start_height + offset as u64;
        raw.extend(raw_rows(height, tx_count));
        sql.extend(sql_rows(height, tx_count));
    }
    upload_combined(client, writer, &raw, &sql).await;
}

fn insert_sql_rows(writer: &mut BatchWriter, rows: &[SqlRow]) {
    for row in rows {
        writer
            .insert(row.table, row.values.clone())
            .expect("sql row encodes");
    }
}

fn raw_rows(height: u64, tx_count: usize) -> Vec<(Key, Bytes)> {
    let block_digest = digest(height);
    let mut rows = Vec::with_capacity(2 + 2 * tx_count);
    rows.push((
        keys::block(&block_digest).expect("block key"),
        Bytes::from(block_digest.to_vec()),
    ));
    rows.push((
        keys::block_by_height(height).expect("block height key"),
        Bytes::copy_from_slice(&block_digest),
    ));
    for idx in 0..tx_count {
        let tx_digest = digest(height ^ (idx as u64).rotate_left(17));
        rows.push((
            keys::tx(&tx_digest).expect("tx key"),
            Bytes::copy_from_slice(&tx_digest),
        ));
        rows.push((
            keys::tx_by_height(height, idx as u32).expect("tx height key"),
            Bytes::copy_from_slice(&tx_digest),
        ));
    }
    rows
}

fn sql_rows(height: u64, tx_count: usize) -> Vec<SqlRow> {
    let mut rows = Vec::with_capacity(1 + tx_count);
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
        rows.push(SqlRow {
            table: TX_META_TABLE,
            values: vec![
                CellValue::UInt64(height),
                CellValue::UInt64(idx as u64),
                CellValue::FixedBinary(digest(height ^ idx as u64).to_vec()),
                CellValue::UInt64(height.saturating_mul(tx_count as u64 + 1) + idx as u64),
            ],
        });
    }
    rows
}

fn digest(seed: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, chunk) in out.chunks_exact_mut(8).enumerate() {
        chunk.copy_from_slice(&seed.wrapping_add(idx as u64).to_be_bytes());
    }
    out
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(3));
    targets = bench_raw_sql_upload
}
criterion_main!(benches);
