//! Contract tests for store capabilities (RocksDB simulator).

use std::future::Future;

use bytes::Bytes;
use exoware_server::{Ingest, Query, RangeScan, Sequence};
use exoware_simulator::RocksStore;
use tempfile::tempdir;

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn put_batch(store: &RocksStore, kvs: Vec<(Bytes, Bytes)>) -> u64 {
    block_on(store.put_batch(kvs)).expect("put_batch")
}

fn seed_abc(store: &RocksStore) {
    put_batch(
        store,
        vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
        ],
    );
}

fn keys(rows: &[(Bytes, Bytes)]) -> Vec<&[u8]> {
    rows.iter().map(|(k, _)| k.as_ref()).collect()
}

fn scan(
    store: &RocksStore,
    start: &[u8],
    end: &[u8],
    limit: usize,
    forward: bool,
) -> Vec<(Bytes, Bytes)> {
    let mut cursor = block_on(store.range_scan(
        Bytes::copy_from_slice(start),
        Bytes::copy_from_slice(end),
        limit,
        forward,
    ))
    .expect("open scan");
    let mut rows = Vec::new();
    loop {
        let batch = block_on(cursor.next_batch(usize::MAX)).expect("scan");
        if batch.rows.is_empty() {
            break;
        }
        rows.extend(batch.rows);
    }
    rows
}

fn get_value(store: &RocksStore, key: &[u8]) -> Option<Bytes> {
    block_on(store.get(Bytes::copy_from_slice(key)))
        .expect("get")
        .0
}

fn get_many_values(store: &RocksStore, keys: &[&[u8]]) -> Vec<(Bytes, Option<Bytes>)> {
    let keys = keys.iter().map(|key| Bytes::copy_from_slice(key)).collect();
    block_on(store.get_many(keys)).expect("get_many").0
}

// -- get --

#[test]
fn get_returns_none_for_missing_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    assert!(get_value(&store, b"missing").is_none());
}

#[test]
fn get_returns_value_after_put() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))],
    );
    assert_eq!(get_value(&store, b"k").as_deref(), Some(b"v".as_slice()));
}

// -- put_batch / sequence --

#[test]
fn put_batch_returns_monotonic_sequence_numbers() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let s1 = put_batch(
        &store,
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
    );
    let s2 = put_batch(
        &store,
        vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))],
    );
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(store.current_sequence(), 2);
}

#[test]
fn sequence_persists_across_reopen() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
    );
    put_batch(
        &store,
        vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))],
    );
    drop(store);

    let reopened = RocksStore::open(dir.path(), None).expect("reopen db");
    assert_eq!(reopened.current_sequence(), 2);
    let s3 = put_batch(
        &reopened,
        vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
    );
    assert_eq!(s3, 3);
}

// -- forward range_scan --

#[test]
fn range_scan_inclusive_end_includes_end_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b", b"c"]);
}

#[test]
fn range_scan_empty_end_is_unbounded_above() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![
            (Bytes::from_static(b"m"), Bytes::from_static(b"x")),
            (Bytes::from_static(b"z"), Bytes::from_static(b"y")),
        ],
    );

    let rows = scan(&store, b"m", b"", usize::MAX, true);
    assert_eq!(rows.len(), 2);
}

#[test]
fn range_scan_forward_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b"]);
}

#[test]
fn range_scan_returns_empty_when_no_keys_match() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"d", b"f", usize::MAX, true);
    assert!(rows.is_empty());
}

#[test]
fn range_scan_limit_zero_returns_empty() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 0, true);
    assert!(rows.is_empty());
}

// -- reverse range_scan --

#[test]
fn range_scan_reverse_returns_descending_order() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_reverse_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b"]);
}

#[test]
fn range_scan_reverse_unbounded_end() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_single_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"b", b"b", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"b".as_slice()]);
}

// -- get_many --

#[test]
fn get_many_returns_found_and_missing() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let results = get_many_values(&store, &[b"a", b"missing", b"c"]);
    assert_eq!(results.len(), 3);
    assert_eq!(
        results[0],
        (Bytes::from_static(b"a"), Some(Bytes::from_static(b"1")))
    );
    assert_eq!(results[1], (Bytes::from_static(b"missing"), None));
    assert_eq!(
        results[2],
        (Bytes::from_static(b"c"), Some(Bytes::from_static(b"3")))
    );
}
