//! Ingest throughput benchmark for the RocksDB-backed simulator store.
//!
//! Measures `put_batch` on the workload the simulator is expected to sustain:
//! large batches (hundreds of thousands of keys each), both from a single
//! serial writer and from several concurrent writers that keep the write
//! pipeline full.
//!
//! Run with:
//!
//! ```bash
//! cargo bench -p exoware-simulator --bench ingest
//! ```
//!
//! Environment overrides: `BENCH_BATCHES`, `BENCH_KEYS_PER_BATCH`,
//! `BENCH_VALUE_LEN`, `BENCH_WRITERS`.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use exoware_server::Ingest;
use exoware_simulator::RocksStore;

// Match the simulator binary's allocator so bench numbers reflect the deployed configuration.
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

/// Builds one batch of unique keys with pseudo-random, incompressible-ish values.
fn build_batch(batch_index: usize, keys_per_batch: usize, value_len: usize) -> Vec<(Bytes, Bytes)> {
    let mut kvs = Vec::with_capacity(keys_per_batch);
    for i in 0..keys_per_batch {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(b"bench/");
        key.extend_from_slice(&(batch_index as u64).to_be_bytes());
        key.extend_from_slice(&(i as u64).to_be_bytes());

        // Mix the tail so keys are not fully sequential in memcmp order.
        let mixed = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        key.extend_from_slice(&mixed.to_be_bytes());

        let mut value = vec![0u8; value_len];
        let mut state = mixed ^ (batch_index as u64);
        for chunk in value.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        kvs.push((Bytes::from(key), Bytes::from(value)));
    }
    kvs
}

fn batch_payload_bytes(batches: &[Vec<(Bytes, Bytes)>]) -> usize {
    batches
        .iter()
        .flatten()
        .map(|(k, v)| k.len() + v.len())
        .sum()
}

fn report(label: &str, keys: usize, payload_bytes: usize, elapsed_secs: f64) {
    println!(
        "{label}: {keys} keys in {elapsed_secs:.3}s -> {:.0} keys/s, {:.1} MiB/s",
        keys as f64 / elapsed_secs,
        payload_bytes as f64 / (1024.0 * 1024.0) / elapsed_secs,
    );
}

/// Writes every batch through `writers` concurrent tasks; one writer is the serial mode.
async fn run(store: Arc<RocksStore>, batches: Vec<Vec<(Bytes, Bytes)>>, writers: usize) -> f64 {
    let mut queues: Vec<Vec<Vec<(Bytes, Bytes)>>> = (0..writers).map(|_| Vec::new()).collect();
    for (index, batch) in batches.into_iter().enumerate() {
        queues[index % writers].push(batch);
    }

    let start = Instant::now();
    let mut tasks = Vec::with_capacity(writers);
    for queue in queues {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            for batch in queue {
                store.put_batch(batch).await.expect("put batch");
            }
        }));
    }
    for task in tasks {
        task.await.expect("writer task");
    }
    start.elapsed().as_secs_f64()
}

fn main() {
    let batches = env_usize("BENCH_BATCHES", 16).max(1);
    let keys_per_batch = env_usize("BENCH_KEYS_PER_BATCH", 250_000).max(1);
    let value_len = env_usize("BENCH_VALUE_LEN", 128);
    let writers = env_usize("BENCH_WRITERS", 4).max(1);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    println!(
        "workload: {batches} batches x {keys_per_batch} keys, {value_len}B values, {writers} concurrent writers"
    );

    for (label, concurrent) in [("serial", false), ("concurrent", true)] {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(RocksStore::open(dir.path(), None).expect("open store"));
        let data: Vec<_> = (0..batches)
            .map(|batch| build_batch(batch, keys_per_batch, value_len))
            .collect();
        let payload = batch_payload_bytes(&data);
        let keys = batches * keys_per_batch;

        let elapsed = runtime.block_on(run(
            store.clone(),
            data,
            if concurrent { writers } else { 1 },
        ));
        report(label, keys, payload, elapsed);
        drop(store);
    }
}
