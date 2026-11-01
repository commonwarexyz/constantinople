use super::*;
use crate::{
    publisher::sql::{TxActivityRole, TxActivityRow, encode_tx_activity_row},
    store::writer_store_client,
};
use exoware_server::{
    AppState, Query, QueryResult, QueryState, RangeScan, RangeScanBatch, RangeScanResult, Sequence,
    connect_stack, query_service,
};
use exoware_simulator::RocksStore;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
struct Reads {
    range_rows: AtomicUsize,
    point_rows: AtomicUsize,
    active_scans: AtomicUsize,
    idle: Notify,
}

impl Reads {
    async fn finish(&self) -> (usize, usize) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let idle = self.idle.notified();
                if self.active_scans.load(Ordering::SeqCst) == 0 {
                    break;
                }
                idle.await;
            }
        })
        .await
        .expect("Store range cursors must close after the SQL query finishes");
        (
            self.range_rows.swap(0, Ordering::SeqCst),
            self.point_rows.swap(0, Ordering::SeqCst),
        )
    }
}

struct CountingStore {
    store: Arc<RocksStore>,
    reads: Arc<Reads>,
}

struct CountingScan {
    scan: <RocksStore as Query>::RangeScan,
    reads: Arc<Reads>,
}

impl Drop for CountingScan {
    fn drop(&mut self) {
        if self.reads.active_scans.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.reads.idle.notify_one();
        }
    }
}

impl RangeScan for CountingScan {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let batch = self.scan.next_batch(max_items).await?;
        self.reads
            .range_rows
            .fetch_add(batch.rows.len(), Ordering::SeqCst);
        Ok(batch)
    }
}

impl Sequence for CountingStore {
    fn current_sequence(&self) -> u64 {
        self.store.current_sequence()
    }
}

impl Query for CountingStore {
    type RangeScan = CountingScan;

    async fn get(&self, key: Bytes) -> Result<QueryResult<Option<Bytes>>, String> {
        let result = self.store.get(key).await?;
        self.reads
            .point_rows
            .fetch_add(usize::from(result.value.is_some()), Ordering::SeqCst);
        Ok(result)
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<QueryResult<Vec<(Bytes, Option<Bytes>)>>, String> {
        let result = self.store.get_many(keys).await?;
        self.reads.point_rows.fetch_add(
            result
                .value
                .iter()
                .filter(|(_, value)| value.is_some())
                .count(),
            Ordering::SeqCst,
        );
        Ok(result)
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<RangeScanResult<CountingScan>, String> {
        let result = self.store.range_scan(start, end, limit, forward).await?;
        self.reads.active_scans.fetch_add(1, Ordering::SeqCst);
        Ok(RangeScanResult {
            scan: CountingScan {
                scan: result.scan,
                reads: self.reads.clone(),
            },
            sequence_number: result.sequence_number,
        })
    }
}

fn cursors(batches: &[RecordBatch]) -> Vec<Cursor> {
    batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows()).map(|row| Cursor {
                height: uint(batch, 0, row).unwrap(),
                index: uint(batch, 1, row).unwrap(),
                role: uint(batch, 2, row).unwrap(),
            })
        })
        .collect()
}

async fn compare_page(
    sql: &SqlContext,
    reads: &Reads,
    account: [u8; 32],
    cursor: Cursor,
    expected: &[(u64, u64, u64)],
    deep: bool,
) {
    let request = AccountRequest {
        key: AccountKey::from(account),
        mode: None,
        cursor: Some(cursor),
        snapshot: None,
        activity: true,
    };
    let old_query = format!(
        "SELECT height, index, role, tx_digest, qmdb_location FROM tx_activity WHERE account = X'{}' AND height <= 4096 AND (height < {} OR (height = {} AND index < {}) OR (height = {} AND index = {} AND role < {})) ORDER BY height DESC, index DESC, role DESC LIMIT 11",
        hex(&account),
        cursor.height,
        cursor.height,
        cursor.index,
        cursor.height,
        cursor.index,
        cursor.role
    );
    let old = query_rows(sql, &old_query, 11).await.unwrap();
    let old_reads = reads.finish().await;
    let new = activity_rows(sql, &request, 4096).await.unwrap();
    let new_reads = reads.finish().await;
    let tuples = |batches: &[RecordBatch]| {
        cursors(batches)
            .into_iter()
            .map(|cursor| (cursor.height, cursor.index, cursor.role))
            .collect::<Vec<_>>()
    };
    assert_eq!(tuples(&old), expected);
    assert_eq!(tuples(&new), expected);
    assert!(
        new_reads.0 + new_reads.1 <= 11,
        "cursor seeks must read at most the remaining page budget: {new_reads:?}"
    );
    if deep {
        assert!(
            old_reads.0 >= 2048,
            "the residual cursor must exercise the discarded prefix: {old_reads:?}"
        );
    }
    eprintln!(
        "activity cursor ({},{},{}) old range/point={old_reads:?}, seek range/point={new_reads:?}",
        cursor.height, cursor.index, cursor.role
    );
}

#[tokio::test]
async fn activity_cursor_seeks_read_only_the_remaining_page() {
    let store = Arc::new(RocksStore::open_owned(tempfile::tempdir().unwrap(), None).unwrap());
    let reads = Arc::new(Reads::default());
    let query = Arc::new(CountingStore {
        store: store.clone(),
        reads: reads.clone(),
    });
    let app = Router::new()
        .route_service(
            "/store.query.v1.Service/{method}",
            query_service(QueryState::new(query)),
        )
        .fallback_service(connect_stack(AppState::new(store)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = writer_store_client(&url, None).unwrap();
    let client = sql_meta_client(&client).unwrap();
    let schema = build_meta_schema(client.clone()).unwrap();
    let sql = SqlContext::new(client);
    let mut writer = schema.batch_writer();
    schema.register_all(&sql).unwrap();
    let mut insert = |account, height, index| {
        let row = encode_tx_activity_row(TxActivityRow {
            account,
            role: TxActivityRole::Sender,
            height,
            index,
            digest: [0; 32],
            counterparty: [9; 32],
            value: 1,
            nonce: u64::from(index),
            qmdb_location: height + u64::from(index),
        });
        writer.insert(row.table, row.values).unwrap();
    };
    for index in 0..4096 {
        insert([1; 32], 1000, index);
        insert([2; 32], u64::from(index) + 1, 0);
    }
    for index in 0..21 {
        insert([3; 32], 1, index);
    }
    for index in 0..3 {
        insert([3; 32], 2, index);
    }
    writer.flush().await.unwrap();
    assert_eq!(reads.finish().await, (0, 0));

    compare_page(
        &sql,
        &reads,
        [1; 32],
        Cursor {
            height: 1000,
            index: 32,
            role: 1,
        },
        &(22..=32)
            .rev()
            .map(|index| (1000, index, 0))
            .collect::<Vec<_>>(),
        true,
    )
    .await;
    compare_page(
        &sql,
        &reads,
        [2; 32],
        Cursor {
            height: 32,
            index: 0,
            role: 1,
        },
        &(22..=32)
            .rev()
            .map(|height| (height, 0, 0))
            .collect::<Vec<_>>(),
        true,
    )
    .await;
    let composed = [(2, 2, 0), (2, 1, 0), (2, 0, 0)]
        .into_iter()
        .chain((13..=20).rev().map(|index| (1, index, 0)))
        .collect::<Vec<_>>();
    compare_page(
        &sql,
        &reads,
        [3; 32],
        Cursor {
            height: 2,
            index: 2,
            role: 1,
        },
        &composed,
        false,
    )
    .await;
    let request = AccountRequest {
        key: AccountKey::from([3; 32]),
        mode: None,
        cursor: Some(Cursor {
            height: 1,
            index: 0,
            role: 0,
        }),
        snapshot: None,
        activity: true,
    };
    assert!(
        activity_rows(&sql, &request, 4096)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(reads.finish().await, (0, 0));
    server.abort();
    let _ = server.await;
}
