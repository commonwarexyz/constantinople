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

/// Store rows returned to SQL queries, with the number of open range scans.
#[derive(Default)]
struct Reads {
    range_rows: AtomicUsize,
    point_rows: AtomicUsize,
    active_scans: AtomicUsize,
    /// Signaled when the last open range scan closes.
    idle: Notify,
}

impl Reads {
    /// Waits for every range scan to close, then returns and resets the range
    /// and point row counts.
    async fn finish(&self) -> (usize, usize) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                // Register for the notification before checking, so a scan that
                // closes in between still wakes the waiter.
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

/// RocksDB query backend that counts the rows it returns.
struct CountingStore {
    store: Arc<RocksStore>,
    reads: Arc<Reads>,
}

/// Range scan that counts returned rows and reports when it closes.
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

/// Asserts that the authenticated interval reads only its own rows.
async fn assert_page(
    sql: &SqlContext,
    reads: &Reads,
    account: [u8; 32],
    end: u64,
    expected: &[(u64, u64, u64)],
) {
    let request = AccountRequest {
        key: AccountKey::from(account),
        cursor: Some(Cursor(end)),
        snapshot: None,
        account_location: None,
        activity: true,
    };
    let batches = activity_rows(sql, &request, end.saturating_sub(10), end, 4096)
        .await
        .unwrap();
    let actual = batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows()).map(|row| {
                (
                    uint(batch, 0, row).unwrap(),
                    uint(batch, 1, row).unwrap(),
                    uint(batch, 2, row).unwrap(),
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    let (range, point) = reads.finish().await;
    assert!(
        range + point <= expected.len(),
        "account intervals must read only their page: range={range}, point={point}"
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

    // Account indices form one ordered key range across block boundaries.
    let mut insert = |account, account_index, height, index| {
        let row = encode_tx_activity_row(TxActivityRow {
            account,
            account_index,
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
        insert([1; 32], u64::from(index), 1000, index);
        insert([2; 32], u64::from(index), u64::from(index) + 1, 0);
    }
    for index in 0..24 {
        let (height, block_index) = if index < 21 {
            (1, index)
        } else {
            (2, index - 21)
        };
        insert([3; 32], u64::from(index), height, block_index);
    }
    writer.flush().await.unwrap();
    assert_eq!(reads.finish().await, (0, 0));

    assert_page(
        &sql,
        &reads,
        [1; 32],
        33,
        &(23..33)
            .rev()
            .map(|index| (index, 1000, index))
            .collect::<Vec<_>>(),
    )
    .await;
    assert_page(
        &sql,
        &reads,
        [2; 32],
        32,
        &(22..32)
            .rev()
            .map(|index| (index, index + 1, 0))
            .collect::<Vec<_>>(),
    )
    .await;
    assert_page(
        &sql,
        &reads,
        [3; 32],
        24,
        &(14..24)
            .rev()
            .map(|index| {
                if index < 21 {
                    (index, 1, index)
                } else {
                    (index, 2, index - 21)
                }
            })
            .collect::<Vec<_>>(),
    )
    .await;
    assert_page(&sql, &reads, [3; 32], 3, &[(2, 1, 2), (1, 1, 1), (0, 1, 0)]).await;
    assert_page(&sql, &reads, [3; 32], 0, &[]).await;

    server.abort();
    let _ = server.await;
}
