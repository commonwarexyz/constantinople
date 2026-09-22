//! Contract tests for RocksDB simulator pruning (user-key scopes via `Prune`) and sequence-log
//! retention (continuously enforced via `Retention`/`SetRetention`).

use std::future::Future;

use bytes::Bytes;
use exoware_sdk::keys::Prefix;
use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
    PRUNE_POLICY_DOCUMENT_VERSION,
};
use exoware_sdk::retention::RetentionPolicy;
use exoware_sdk::selector::Selector;
use exoware_server::{Ingest, Log, Prune, Query, Retention, Sequence};
use exoware_simulator::RocksStore;
use tempfile::tempdir;

const TEST_PREFIX: u8 = 1;

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn prefix() -> Prefix {
    Prefix::from_byte(TEST_PREFIX)
}

fn versioned_key(logical: &[u8], version: u64) -> Bytes {
    let mut payload = Vec::new();
    payload.extend_from_slice(logical);
    payload.extend_from_slice(b"\0\0");
    payload.extend_from_slice(&version.to_be_bytes());
    prefix().encode(&payload).expect("encode key")
}

fn put_batch(store: &RocksStore, kvs: Vec<(Bytes, Bytes)>) -> u64 {
    block_on(store.put_batch(kvs)).expect("put_batch")
}

fn put_one(store: &RocksStore, key: &'static [u8], value: &'static [u8]) -> u64 {
    put_batch(
        store,
        vec![(Bytes::from_static(key), Bytes::from_static(value))],
    )
}

fn get_value(store: &RocksStore, key: &Bytes) -> Option<Bytes> {
    block_on(store.get(key.clone())).expect("get").0
}

/// True when the log still serves a batch at `sequence`.
fn has_batch(store: &RocksStore, sequence: u64) -> bool {
    block_on(store.get_batch(sequence))
        .expect("get batch")
        .is_some()
}

fn oldest_retained(store: &RocksStore) -> Option<u64> {
    block_on(store.oldest_retained_batch()).expect("oldest retained")
}

/// Drives the `Retention` RPC surface (async trait method) the way the server does.
fn set_retention(store: &RocksStore, policy: Option<RetentionPolicy>) -> Option<u64> {
    block_on(store.set_retention(policy)).expect("set_retention")
}

fn prune_document(policies: &[PrunePolicy]) -> PrunePolicyDocument {
    PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies: policies.to_vec(),
    }
}

fn try_apply_prune(store: &RocksStore, policies: &[PrunePolicy]) -> Result<(), String> {
    block_on(store.apply_prune_policies(prune_document(policies)))
}

fn apply_prune(store: &RocksStore, policies: &[PrunePolicy]) {
    try_apply_prune(store, policies).expect("apply prune policies");
}

fn version_policy_with_encoding(retain: RetainPolicy, encoding: OrderEncoding) -> PrunePolicy {
    PrunePolicy {
        scope: KeysScope {
            selector: Selector {
                prefix: Bytes::from(vec![TEST_PREFIX]),
                payload_regex: Utf8::from(
                    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                ),
            },
            group_by: GroupBy {
                capture_groups: vec![Utf8::from("logical")],
            },
            order_by: Some(OrderBy {
                capture_group: Utf8::from("version"),
                encoding,
            }),
        },
        retain,
    }
}

fn version_policy(retain: RetainPolicy) -> PrunePolicy {
    version_policy_with_encoding(retain, OrderEncoding::U64Be)
}

#[test]
fn keys_drop_all_deletes_matching_family_keys() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let a1 = versioned_key(b"a", 1);
    let b1 = versioned_key(b"b", 1);
    put_batch(
        &store,
        vec![
            (a1.clone(), Bytes::from_static(b"a1")),
            (b1.clone(), Bytes::from_static(b"b1")),
            (Bytes::from_static(b"raw"), Bytes::from_static(b"raw")),
        ],
    );

    apply_prune(&store, &[version_policy(RetainPolicy::DropAll)]);

    assert!(get_value(&store, &a1).is_none());
    assert!(get_value(&store, &b1).is_none());
    assert_eq!(
        get_value(&store, &Bytes::from_static(b"raw")).as_deref(),
        Some(b"raw".as_slice())
    );
}

#[test]
fn keys_keep_latest_deletes_old_versions_without_advancing_sequence() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = put_batch(
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    );

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
    );

    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
    assert_eq!(store.current_sequence(), initial_sequence);
    assert!(block_on(store.get_batch(initial_sequence + 1))
        .expect("get batch")
        .is_none());
}

#[test]
fn key_prune_is_idempotent_when_reapplied() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = put_batch(
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    );
    let policy = version_policy(RetainPolicy::KeepLatest { count: 1 });

    apply_prune(&store, std::slice::from_ref(&policy));
    let sequence_after_first_prune = store.current_sequence();
    apply_prune(&store, &[policy]);

    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
    assert_eq!(sequence_after_first_prune, initial_sequence);
    assert_eq!(store.current_sequence(), sequence_after_first_prune);
    assert!(block_on(store.get_batch(sequence_after_first_prune + 1))
        .expect("get batch")
        .is_none());
}

#[test]
fn keys_threshold_retains_greater_than_or_equal_versions() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let v3 = versioned_key(b"row", 3);
    let v4 = versioned_key(b"row", 4);
    let v5 = versioned_key(b"row", 5);
    put_batch(
        &store,
        vec![
            (v3.clone(), Bytes::from_static(b"v3")),
            (v4.clone(), Bytes::from_static(b"v4")),
            (v5.clone(), Bytes::from_static(b"v5")),
        ],
    );

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::GreaterThanOrEqual {
            threshold: 4,
        })],
    );

    assert!(get_value(&store, &v3).is_none());
    assert_eq!(get_value(&store, &v4).as_deref(), Some(b"v4".as_slice()));
    assert_eq!(get_value(&store, &v5).as_deref(), Some(b"v5".as_slice()));
}

#[test]
fn keys_threshold_retention_rejects_i64_ordering() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let v1 = versioned_key(b"row", 1);
    put_batch(&store, vec![(v1.clone(), Bytes::from_static(b"v1"))]);

    let err = try_apply_prune(
        &store,
        &[version_policy_with_encoding(
            RetainPolicy::GreaterThanOrEqual { threshold: 1 << 63 },
            OrderEncoding::I64Be,
        )],
    )
    .expect_err("i64 threshold retention should be rejected");

    assert!(err.contains("threshold retention requires order_by.encoding = u64_be"));
    assert_eq!(get_value(&store, &v1).as_deref(), Some(b"v1".as_slice()));
}

/// An installed rule keeps trimming as later batches arrive, with no further RPC:
/// `keep_latest{2}`'s window follows the frontier across two enforcement rounds driven purely
/// by ingest.
#[test]
fn retention_keep_latest_tracks_frontier_continuously() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_one(&store, b"a", b"1");
    put_one(&store, b"b", b"2");
    put_one(&store, b"c", b"3");

    // One synchronous enforcement against frontier 3 keeps the newest two batches.
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 2 })),
        Some(2)
    );
    assert!(!has_batch(&store, 1));
    assert!(has_batch(&store, 2));
    assert!(has_batch(&store, 3));
    assert_eq!(store.current_sequence(), 3);

    // Two more batches, no new RPC: the ingest path re-enforces each time, so the retained
    // window slides forward to [4, 5].
    put_one(&store, b"d", b"4");
    put_one(&store, b"e", b"5");

    assert!(!has_batch(&store, 2));
    assert!(!has_batch(&store, 3));
    assert!(has_batch(&store, 4));
    assert!(has_batch(&store, 5));
    assert_eq!(oldest_retained(&store), Some(4));

    // Retention never advances the ingest frontier; it only evicts log rows.
    assert_eq!(store.current_sequence(), 5);
}

#[test]
fn retention_greater_than_and_greater_than_or_equal_thresholds() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_one(&store, b"a", b"1");
    put_one(&store, b"b", b"2");
    put_one(&store, b"c", b"3");
    put_one(&store, b"d", b"4");
    put_one(&store, b"e", b"5");

    // `greater_than{2}` retains sequence numbers strictly above 2, so the floor is 3.
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::GreaterThan { threshold: 2 })),
        Some(3)
    );
    assert!(!has_batch(&store, 1));
    assert!(!has_batch(&store, 2));
    assert!(has_batch(&store, 3));

    // Tightening to `greater_than_or_equal{4}` moves the floor to 4 (4 itself is retained).
    assert_eq!(
        set_retention(
            &store,
            Some(RetentionPolicy::GreaterThanOrEqual { threshold: 4 })
        ),
        Some(4)
    );
    assert!(!has_batch(&store, 3));
    assert!(has_batch(&store, 4));
    assert!(has_batch(&store, 5));
    assert_eq!(store.current_sequence(), 5);
}

#[test]
fn retention_drop_all_keeps_log_empty_as_batches_arrive() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_one(&store, b"a", b"1");
    put_one(&store, b"b", b"2");

    // drop_all evicts everything up to the live frontier; the log has no retained row.
    assert_eq!(set_retention(&store, Some(RetentionPolicy::DropAll)), None);
    assert_eq!(oldest_retained(&store), None);
    assert!(!has_batch(&store, 1));
    assert!(!has_batch(&store, 2));

    // Later batches are evicted continuously, so the log stays empty without another RPC. The
    // ingest frontier still advances (put_batch returns the committed sequence).
    let third = put_one(&store, b"c", b"3");
    assert_eq!(third, 3);
    assert_eq!(store.current_sequence(), 3);
    assert_eq!(oldest_retained(&store), None);
    assert!(!has_batch(&store, 3));
}

#[test]
fn retention_clear_stops_enforcement() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_one(&store, b"a", b"1");
    put_one(&store, b"b", b"2");
    put_one(&store, b"c", b"3");

    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 2 })),
        Some(2)
    );
    assert!(!has_batch(&store, 1));

    // Clearing stops enforcement; already-evicted batches stay evicted.
    set_retention(&store, None);
    assert!(!has_batch(&store, 1));

    // With the rule cleared the ingest path stops trimming: batches 4 and 5 join 2 and 3
    // untouched.
    put_one(&store, b"d", b"4");
    put_one(&store, b"e", b"5");
    assert_eq!(oldest_retained(&store), Some(2));
    for sequence in 2..=5 {
        assert!(has_batch(&store, sequence), "batch {sequence} must survive");
    }
}

/// Key pruning (`Prune`) and sequence-log retention (`SetRetention`) target different data and
/// compose: current key rows are deleted by the prune, log rows are trimmed by retention, and
/// neither advances the ingest frontier.
#[test]
fn keys_prune_and_retention_compose() {
    let dir = tempdir().expect("tempdir");
    let (v1, v2, v3, last) = {
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let v1 = versioned_key(b"row", 1);
        let v2 = versioned_key(b"row", 2);
        let v3 = versioned_key(b"row", 3);
        put_batch(&store, vec![(v1.clone(), Bytes::from_static(b"v1"))]);
        put_batch(&store, vec![(v2.clone(), Bytes::from_static(b"v2"))]);
        let last = put_batch(&store, vec![(v3.clone(), Bytes::from_static(b"v3"))]);

        // Prune keeps only the newest key version; retention keeps only the newest log batch.
        apply_prune(
            &store,
            &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
        );
        assert_eq!(
            set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 1 })),
            Some(last)
        );

        assert!(get_value(&store, &v1).is_none());
        assert!(get_value(&store, &v2).is_none());
        assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
        assert!(!has_batch(&store, last - 2));
        assert!(!has_batch(&store, last - 1));
        assert!(has_batch(&store, last));
        assert_eq!(store.current_sequence(), last);
        (v1, v2, v3, last)
    };

    // Reopening replays retained log rows above the state floor; it must resurrect neither the
    // key-pruned rows nor the retention-evicted log rows, and must not regress the frontier.
    let store = RocksStore::open(dir.path(), None).expect("reopen db");
    assert_eq!(store.current_sequence(), last);
    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
    assert!(!has_batch(&store, last - 1));
    assert!(has_batch(&store, last));
}

#[test]
fn retention_drop_all_survives_reopen() {
    let dir = tempdir().expect("tempdir");
    let last = {
        let store = RocksStore::open(dir.path(), None).expect("open db");
        put_batch(
            &store,
            vec![(versioned_key(b"row", 1), Bytes::from_static(b"v1"))],
        );
        let last = put_batch(
            &store,
            vec![(versioned_key(b"row", 2), Bytes::from_static(b"v2"))],
        );
        set_retention(&store, Some(RetentionPolicy::DropAll));
        assert!(block_on(store.oldest_retained_batch())
            .expect("oldest")
            .is_none());
        last
    };

    // Every log row is gone, so the floor written atomically with the tombstone is the only
    // record of the frontier; without it a reopen would re-issue acked sequence numbers.
    let store = RocksStore::open(dir.path(), None).expect("reopen db");
    assert_eq!(store.current_sequence(), last);
    let next = put_batch(
        &store,
        vec![(versioned_key(b"row", 3), Bytes::from_static(b"v3"))],
    );
    assert_eq!(next, last + 1);
    // The restored rule keeps evicting, so the new batch never lingers in the log.
    assert_eq!(oldest_retained(&store), None);
}

#[test]
fn key_pruned_state_survives_reopen_when_versions_share_a_batch() {
    let dir = tempdir().expect("tempdir");
    let (v1, v2, v3) = {
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let v1 = versioned_key(b"row", 1);
        let v2 = versioned_key(b"row", 2);
        let v3 = versioned_key(b"row", 3);

        // All versions land in one batch, so one retained log row holds the pruned keys.
        put_batch(
            &store,
            vec![
                (v1.clone(), Bytes::from_static(b"v1")),
                (v2.clone(), Bytes::from_static(b"v2")),
                (v3.clone(), Bytes::from_static(b"v3")),
            ],
        );

        apply_prune(
            &store,
            &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
        );
        assert!(get_value(&store, &v1).is_none());
        assert!(get_value(&store, &v2).is_none());
        (v1, v2, v3)
    };

    // Reopening replays retained log rows; that replay must not resurrect key-pruned rows
    // whose log entries are still retained.
    let store = RocksStore::open(dir.path(), None).expect("reopen db");
    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
}
