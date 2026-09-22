//! Naive reference storage for local development: user keys and values are written as-is to
//! RocksDB. A `meta` column family holds the state-floor row, and a `log` column family keeps
//! one row per commit group: the exact `log.stream.v1.GetResponse` bytes the stream service
//! serves for that sequence, loaded on demand. Everything is addressed by key: recovery and
//! pruning never assume which SST files rows live in, so RocksDB is free to place and compact
//! them however it likes.
//!
//! Writes bypass the WAL and the memtables: `prepare` coalesces queued requests into commit
//! groups that each share one sequence number and queues them for a pool of stage workers,
//! which build each group's log row and sorted state rows as two SST files (concurrently
//! across groups), while `commit` reorders staged groups back into sequence order and ingests
//! each: the log file first (the durable row alone defines the group; `open` derives the
//! frontier from the highest retained row and the state-floor meta row), then the state file,
//! then publish and ack. Several groups can be queued, staging, or buffered awaiting their
//! predecessors at once (the queue and worker count bound staged memory), but ingestion stays
//! atomic and strictly ordered, so a crash never leaves a partial batch and at most the
//! newest ingested group can be missing its state ingestion; `open` repairs that by
//! re-applying the newest retained log row (idempotent: its rows are the newest writes for
//! their keys). The floor meta row is written by key pruning and by sequence-log retention
//! enforcement, and is durable by the time either acks: it marks state the replay must never
//! touch (re-applying key-pruned rows would resurrect them) and keeps a fully-evicted log from
//! regressing the frontier. A separate meta row persists the active retention rule (see the
//! [`Retention`] impl), which the ingest path re-enforces continuously as the log grows.
//!
//! Any write failure in the pipeline is fatal: once a group's log row is durable it cannot be
//! rolled back (its sequence number must never be re-issued), so the writer panics and the next
//! open rolls the store forward instead of any in-process recovery.

use std::cmp::Ordering as CmpOrdering;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use buffa::{Message, MessageView};
use bytes::Bytes;
use commonware_codec::{Copying, DecodeExt, Encode};
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::keys::Prefix;
use exoware_sdk::log::stream::v1::{
    GetResponse as StreamGetResponse, GetResponseView as StreamGetResponseView,
};
use exoware_sdk::prune_policy::{KeysScope, OrderEncoding, PrunePolicyDocument, RetainPolicy};
use exoware_sdk::retention::{validate_retention_policy, RetentionPolicy};
use exoware_sdk::selector::compile_payload_regex;
use exoware_server::{
    Ingest, IngestError, Log, LogBatch, Prune, Query, QueryExtra, RangeScan, RangeScanBatch,
    Retention, Sequence,
};
use parking_lot::Mutex;
use regex::bytes::Regex;
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DBCompactionStyle, DBCompressionType, DBIterator,
    Direction, IngestExternalFileOptions, IteratorMode, Options, SstFileWriter, WriteOptions, DB,
};
use tokio::sync::oneshot;
use tracing::debug;

const STATE_CF: &str = rocksdb::DEFAULT_COLUMN_FAMILY_NAME;
const META_CF: &str = "meta";
const SEQ_META_KEY: &[u8] = b"sequence";
/// Meta row holding the active sequence-log retention rule (the codec-encoded
/// [`RetentionPolicy`]). Absence of the row means no rule is installed.
const RETENTION_META_KEY: &[u8] = b"retention";
const PRUNE_SCAN_BATCH_SIZE: usize = 4096;
const PRUNE_DELETE_CHUNK_KEYS: usize = 4096;
const DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
const LOG_INGEST_DIR: &str = "ingest";
const LOG_CF: &str = "log";
const LOG_BATCH_KEY_LEN: usize = 8;
pub const WRITER_THREAD_PREFIX: &str = "simulator-rocks-";
const DEFAULT_STAGE_WORKERS: usize = 4;
type RocksIterItem = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>;

/// A resource dropped strictly after the database has closed (see [`Database`]).
type Closer = Box<dyn std::any::Any + Send + Sync>;

/// The open RocksDB handle plus everything that must outlive it.
///
/// Every holder of the database (store clones, the writer threads, open range-scan cursors,
/// in-flight blocking reads) shares one `Arc<Database>`, so the database closes exactly when
/// the last holder drops, wherever that happens. A closer attached at open drops strictly
/// after the database (fields drop in declaration order).
struct Database {
    db: DB,
    /// Dropped only after `db`: any resource that must outlive the open database. For a
    /// store opened with [`RocksStore::open_owned`], this is the owner whose drop deletes
    /// the data directory (for example a `tempfile::TempDir`).
    _closer: Option<Closer>,
}

impl std::ops::Deref for Database {
    type Target = DB;

    fn deref(&self) -> &DB {
        &self.db
    }
}

/// Owns the DB handle for a RocksDB iterator that is moved through blocking tasks.
struct OwnedRocksIterator {
    iter: DBIterator<'static>,
    _db: Arc<Database>,
}

impl OwnedRocksIterator {
    /// Creates a RocksDB iterator whose borrowed DB handle is kept alive by the wrapper.
    fn new(db: Arc<Database>, mode: IteratorMode<'_>) -> Self {
        // SAFETY: `iter` is dropped before `db` because fields are dropped in
        // declaration order. The RocksDB iterator therefore cannot outlive the
        // Arc-owned DB it borrows.
        let db_ref: &'static DB = unsafe { &(*Arc::as_ptr(&db)).db };
        let iter = db_ref.iterator(mode);
        Self { iter, _db: db }
    }

    /// Advances the wrapped RocksDB iterator without exposing its borrowed lifetime.
    fn next(&mut self) -> Option<RocksIterItem> {
        self.iter.next()
    }
}

struct RocksRangeScanState {
    iterator: OwnedRocksIterator,
    start: Bytes,
    end: Bytes,
    limit: usize,
    forward: bool,
    emitted: usize,
    done: bool,
}

impl RocksRangeScanState {
    /// Creates an iterator positioned at the first row that may belong to the requested range.
    fn new(db: Arc<Database>, start: Bytes, end: Bytes, limit: usize, forward: bool) -> Self {
        let mode = if forward {
            IteratorMode::From(start.as_ref(), Direction::Forward)
        } else if end.is_empty() {
            IteratorMode::End
        } else {
            IteratorMode::From(end.as_ref(), Direction::Reverse)
        };
        Self {
            iterator: OwnedRocksIterator::new(db, mode),
            start,
            end,
            limit,
            forward,
            emitted: 0,
            done: limit == 0,
        }
    }

    /// Reads one page from the existing RocksDB iterator and stops at the range or item limit.
    fn next_batch(&mut self, max_items: usize) -> Result<Vec<(Bytes, Bytes)>, String> {
        if max_items == 0 || self.done {
            return Ok(Vec::new());
        }

        let mut batch = Vec::new();
        while batch.len() < max_items && !self.done {
            let Some(item) = self.iterator.next() else {
                self.done = true;
                break;
            };
            let (key, value) = match item {
                Ok(row) => row,
                Err(e) => {
                    self.done = true;
                    return Err(e.to_string());
                }
            };
            let key_ref = key.as_ref();
            if self.forward {
                if !self.end.is_empty() && key_ref > self.end.as_ref() {
                    self.done = true;
                    break;
                }
            } else if key_ref < self.start.as_ref() {
                self.done = true;
                break;
            }

            self.emitted += 1;
            if self.emitted >= self.limit {
                self.done = true;
            }
            batch.push((
                Bytes::copy_from_slice(key_ref),
                Bytes::copy_from_slice(value.as_ref()),
            ));
        }
        Ok(batch)
    }
}

pub struct RocksRangeScanCursor {
    state: Option<RocksRangeScanState>,
}

impl RocksRangeScanCursor {
    /// Stores scan state in an `Option` so it can be moved into `spawn_blocking` per page.
    fn new(db: Arc<Database>, start: Bytes, end: Bytes, limit: usize, forward: bool) -> Self {
        Self {
            state: Some(RocksRangeScanState::new(db, start, end, limit, forward)),
        }
    }
}

impl RangeScan for RocksRangeScanCursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let Some(mut state) = self.state.take() else {
            return Ok(RangeScanBatch::default());
        };
        let (state, result) = tokio::task::spawn_blocking(move || {
            let result = state.next_batch(max_items);
            (state, result)
        })
        .await
        .map_err(|e| format!("range scan task failed: {e}"))?;
        self.state = Some(state);
        result.map(|rows| RangeScanBatch {
            rows,
            extra: QueryExtra::default(),
        })
    }
}

struct KeyEntry {
    key: Bytes,
    order_value: Vec<u8>,
}

/// Extracts the per-key ordering value used to decide which matching keys a prune policy retains.
fn extract_order_value(payload: &[u8], regex: &Regex, scope: &KeysScope) -> Option<Vec<u8>> {
    let order_by = scope.order_by.as_ref()?;
    let captures = regex.captures(payload)?;
    let matched = captures.name(&order_by.capture_group)?;
    let raw = matched.as_bytes();
    match order_by.encoding {
        OrderEncoding::BytesAsc => Some(raw.to_vec()),
        OrderEncoding::U64Be | OrderEncoding::I64Be => {
            if raw.len() == 8 {
                Some(raw.to_vec())
            } else {
                None
            }
        }
    }
}

/// Builds the grouping key that scopes retention independently within a key prune policy.
fn extract_group_key(payload: &[u8], regex: &Regex, scope: &KeysScope) -> Option<Vec<u8>> {
    if scope.group_by.capture_groups.is_empty() {
        return Some(Vec::new());
    }
    let captures = regex.captures(payload)?;
    let mut group_key = Vec::new();
    for group_name in &scope.group_by.capture_groups {
        let matched = captures.name(group_name)?;
        let bytes = matched.as_bytes();
        group_key.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        group_key.extend_from_slice(bytes);
    }
    Some(group_key)
}

/// Compares captured policy order values according to the encoding declared by the key scope.
fn compare_order_values(a: &[u8], b: &[u8], scope: &KeysScope) -> CmpOrdering {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => {
            let a_val = a.try_into().map(u64::from_be_bytes).unwrap_or(0);
            let b_val = b.try_into().map(u64::from_be_bytes).unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::I64Be) => {
            let a_val = a.try_into().map(i64::from_be_bytes).unwrap_or(0);
            let b_val = b.try_into().map(i64::from_be_bytes).unwrap_or(0);
            a_val.cmp(&b_val)
        }
        Some(OrderEncoding::BytesAsc) | None => a.cmp(b),
    }
}

/// Encodes a retention threshold into the same representation used by captured order values.
fn threshold_order_value(scope: &KeysScope, threshold: u64) -> Result<[u8; 8], String> {
    match scope.order_by.as_ref().map(|o| &o.encoding) {
        Some(OrderEncoding::U64Be) => Ok(threshold.to_be_bytes()),
        Some(OrderEncoding::I64Be | OrderEncoding::BytesAsc) => Err(
            "threshold retention requires order_by.encoding = u64_be for key scopes".to_string(),
        ),
        None => Err("threshold retention requires order_by for key scopes".to_string()),
    }
}

/// Selects the keys to delete from one already-partitioned retention group.
fn keys_to_delete(
    mut entries: Vec<KeyEntry>,
    scope: &KeysScope,
    retain: &RetainPolicy,
) -> Result<Vec<Bytes>, String> {
    entries.sort_by(|a, b| compare_order_values(&a.order_value, &b.order_value, scope));

    match retain {
        RetainPolicy::KeepLatest { count } => {
            if entries.len() <= *count {
                return Ok(Vec::new());
            }
            Ok(entries[..entries.len() - count]
                .iter()
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::GreaterThan { threshold } => {
            let threshold = threshold_order_value(scope, *threshold)?;
            Ok(entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) != CmpOrdering::Greater
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::GreaterThanOrEqual { threshold } => {
            let threshold = threshold_order_value(scope, *threshold)?;
            Ok(entries
                .iter()
                .filter(|e| {
                    compare_order_values(&e.order_value, &threshold, scope) == CmpOrdering::Less
                })
                .map(|e| e.key.clone())
                .collect())
        }
        RetainPolicy::DropAll => Ok(entries.iter().map(|e| e.key.clone()).collect()),
    }
}

/// Sequence frontier shared by the store and its writer stages.
struct Frontiers {
    /// Highest sequence whose log row and state rows are both committed; gates every
    /// sequence-addressed read (`current_sequence`, `get_batch`, `oldest_retained_batch`).
    /// Point reads of current state are deliberately ungated: state may lead this frontier by
    /// the one group being published, but never lags it. The durable frontier (highest sequence
    /// whose log row is durable) is not tracked in-process: it only runs ahead of `published`
    /// while a group's state ingestion is in flight, and is re-derived at open from the
    /// retained log rows and the state-floor meta row.
    published: AtomicU64,
    /// Serializes floor persists (so the persisted state floor never moves backward even
    /// though whole prunes run concurrently) and orders state visibility against floor reads:
    /// `commit` ingests and publishes each group's state under this lock, so a prune that
    /// loads `published` under it sees a frontier covering every row its scan could have
    /// observed.
    persist: Mutex<()>,
    /// Highest `cutoff_exclusive` already applied by `prune_log` in this process. Lets the
    /// per-append retention hook skip the write entirely when the floor has not advanced
    /// (static thresholds, coalesced ingest waves), so redundant range tombstones never pile
    /// up ahead of compaction. Starts at zero; open's one-shot enforcement re-seeds it
    /// when a rule is installed.
    trimmed: AtomicU64,
}

impl Frontiers {
    fn new(published: u64) -> Self {
        Self {
            published: AtomicU64::new(published),
            persist: Mutex::new(()),
            trimmed: AtomicU64::new(0),
        }
    }
}

struct WriteRequest {
    kvs: Vec<(Bytes, Bytes)>,
    response: oneshot::Sender<Result<u64, IngestError>>,
}

/// One coalesced wave awaiting SST staging: every request shares a single sequence number,
/// whose log row carries all their rows in arrival order.
struct QueuedWave {
    sequence: u64,
    requests: Vec<WriteRequest>,
    rows: Vec<(Bytes, Bytes)>,
}

/// One staged commit group: every coalesced request shares a single sequence number, whose log
/// row carries all their rows in arrival order.
struct PreparedWrite {
    sequence: u64,
    requests: Vec<WriteRequest>,
    /// Staged single-row log SST (the group's encoded batch), ready for ingestion.
    log: PathBuf,
    /// Staged current-state SST (sorted by key, last write per key), ready for ingestion.
    state: PathBuf,
    /// Combined payload bytes staged, for debug logging.
    staged_bytes: usize,
}

struct Writer {
    /// `None` only during `Drop`, which closes the channel before joining the workers.
    sender: Option<mpsc::Sender<WriteRequest>>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Writer {
    /// Starts the write pipeline. `prepare` drains queued requests up to the configured byte
    /// cap into commit groups that each share one sequence number (continuing from the
    /// published frontier, which is exactly the frontier derived at open since nothing has
    /// committed yet) and queues them for the stage workers, any of which takes the next
    /// group and builds its log and state SSTs concurrently with the other workers;
    /// `commit` reorders staged groups back into sequence order, ingests each log file, then
    /// its state file, publishes the frontier, and resolves the requests. `commit` still
    /// ingests strictly in order, so a crash leaves at most the newest ingested group without
    /// its state. Any write failure in any stage is fatal (the worker panics): the durable
    /// log row alone defines the group, so the next open re-derives the frontier and replays
    /// the rows above the floor. Sequence numbers never need to be reclaimed in-process.
    fn start(
        db: Arc<Database>,
        ingest_dir: PathBuf,
        frontiers: Arc<Frontiers>,
        write_pipeline: RocksWritePipelineConfig,
    ) -> Self {
        let next = frontiers.published.load(Ordering::Acquire);
        let (request_sender, request_receiver) = mpsc::channel();
        let max_commit_batch_bytes = write_pipeline.max_commit_batch_bytes.get();
        let stage_workers = write_pipeline.stage_workers.get();
        let max_queued_waves = write_pipeline.max_queued_waves.get();

        // Staged groups queue shallowly toward `commit`, which reorders them by sequence.
        let (staged_sender, staged_receiver) = mpsc::sync_channel(stage_workers);

        let commit = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}commit"))
            .spawn(move || run_commit(db, frontiers, staged_receiver, next))
            .expect("failed to spawn RocksDB commit worker");

        // One shared bounded queue, so `prepare` cannot run away from staging and any idle
        // worker takes the next wave (a slow wave never blocks the others); the queue plus
        // in-progress waves bound staged memory.
        let (wave_sender, wave_receiver) = mpsc::sync_channel::<QueuedWave>(max_queued_waves);
        let wave_receiver = Arc::new(Mutex::new(wave_receiver));
        let mut handles = Vec::with_capacity(stage_workers + 2);
        for worker in 0..stage_workers {
            let ingest_dir = ingest_dir.clone();
            let staged_sender = staged_sender.clone();
            let wave_receiver = wave_receiver.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("{WRITER_THREAD_PREFIX}stage-{worker}"))
                    .spawn(move || run_stage(ingest_dir, wave_receiver, staged_sender))
                    .expect("failed to spawn RocksDB stage worker"),
            );
        }
        drop(staged_sender);
        drop(wave_receiver);

        let prepare = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}prepare"))
            .spawn(move || run_prepare(next, request_receiver, wave_sender, max_commit_batch_bytes))
            .expect("failed to spawn RocksDB prepare worker");

        handles.insert(0, prepare);
        handles.push(commit);
        Self {
            sender: Some(request_sender),
            handles,
        }
    }

    /// Enqueues one ingest request and resolves once `commit` has durably published it.
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        // An empty batch would still cut a log row, but rejecting it keeps every sequence
        // backed by at least one entry. The RPC layer already requires at least one entry per
        // put.
        if kvs.is_empty() {
            return Err(IngestError::Internal {
                message: "cannot ingest an empty batch".to_string(),
            });
        }
        let (response, result) = oneshot::channel();

        // The sender is `None` only inside `Writer::drop`, which cannot overlap a live call:
        // dropping the writer requires exclusive access, and every in-flight `put_batch`
        // holds a borrow through the store's `Arc<Writer>`. A writer whose workers are gone
        // is the closed-channel case, surfaced as an error by `send` below.
        self.sender
            .as_ref()
            .expect("sender is None only during drop, which cannot overlap a call")
            .send(WriteRequest { kvs, response })
            .map_err(|_| IngestError::Internal {
                message: "rocks writer stopped".to_string(),
            })?;
        result.await.map_err(|_| IngestError::Internal {
            message: "rocks writer stopped before completing write".to_string(),
        })?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        // Closing the request channel lets the writer drain and exit; joining keeps the
        // background thread from outliving the store.
        self.sender.take();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

/// Drains each byte-bounded wave of queued requests into a group with the next sequence number
/// and queues it for the stage workers. Exits when the request channel closes (store drop);
/// panics if every stage worker died, since that only happens on a fatal write error.
fn run_prepare(
    mut next: u64,
    receiver: mpsc::Receiver<WriteRequest>,
    waves: mpsc::SyncSender<QueuedWave>,
    max_commit_batch_bytes: usize,
) {
    while let Ok(first) = receiver.recv() {
        let (wave, disconnected) =
            coalesce_queued_write(&receiver, first, next, max_commit_batch_bytes);
        next = wave.sequence;
        if waves.send(wave).is_err() {
            panic!("rocks stage workers died");
        }

        if disconnected {
            break;
        }
    }
}

/// Stages waves pulled from the queue shared with the other workers and hands each group to
/// `commit`. The lock is held only while waiting on the channel, never while staging. Exits
/// when the wave channel closes (store drop); panics if `commit` died, since that only
/// happens on a fatal write error.
fn run_stage(
    ingest_dir: PathBuf,
    receiver: Arc<Mutex<mpsc::Receiver<QueuedWave>>>,
    sender: mpsc::SyncSender<PreparedWrite>,
) {
    loop {
        let Ok(wave) = receiver.lock().recv() else {
            break;
        };
        let group = stage_wave(&ingest_dir, wave);
        if sender.send(group).is_err() {
            panic!("rocks commit worker died");
        }
    }
}

/// Commits staged groups strictly in sequence order (log ingestion, state ingestion, publish,
/// ack), buffering groups whose predecessors are still staging, until the group channel closes
/// (store drop). Any write failure panics inside `commit_group`.
fn run_commit(
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    receiver: mpsc::Receiver<PreparedWrite>,
    mut committed: u64,
) {
    let mut pending: BTreeMap<u64, PreparedWrite> = BTreeMap::new();
    let commit_ready = |committed: &mut u64, pending: &mut BTreeMap<u64, PreparedWrite>| {
        while let Some(group) = pending.remove(&(*committed + 1)) {
            *committed = group.sequence;
            commit_group(&db, &frontiers, group);
        }
    };
    while let Ok(group) = receiver.recv() {
        pending.insert(group.sequence, group);
        commit_ready(&mut committed, &mut pending);
    }

    // The channel closes only once every stage worker has exited, after handing over every
    // staged group, so a clean shutdown leaves nothing buffered.
    assert!(pending.is_empty(), "staged groups lost at shutdown");
}

/// Coalesces one wave from requests already queued behind `first` without waiting for new
/// arrivals, stopping once the accumulated payload reaches the soft byte cap. The request that
/// crosses the cap stays in the wave so a single large request can still make progress. The
/// whole wave shares one sequence number: its rows, in arrival order, form one log batch.
fn coalesce_queued_write(
    receiver: &mpsc::Receiver<WriteRequest>,
    first: WriteRequest,
    from: u64,
    max_batch_bytes: usize,
) -> (QueuedWave, bool) {
    let sequence = from
        .checked_add(1)
        .expect("rocks sequence number overflowed");
    let mut requests = Vec::with_capacity(64);
    let mut rows: Vec<(Bytes, Bytes)> = Vec::with_capacity(first.kvs.len());
    let mut staged_bytes = 0usize;
    let mut request = first;
    let mut disconnected = false;

    loop {
        // Payload counted twice: once as state rows and once inside the encoded log batch.
        staged_bytes += 2 * request
            .kvs
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>();
        rows.extend(request.kvs.iter().cloned());
        requests.push(request);
        if staged_bytes >= max_batch_bytes {
            break;
        }

        match receiver.try_recv() {
            Ok(next_request) => request = next_request,
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }

    (
        QueuedWave {
            sequence,
            requests,
            rows,
        },
        disconnected,
    )
}

/// Stages one wave's two SST files in parallel: the single-row log SST on this thread, the
/// sorted state SST on a scoped thread. Ingestion later links them into their column
/// families, so each payload byte reaches the disk exactly once, in its final resting place.
/// A staging failure is fatal; leftover staged files are removed by the next open.
fn stage_wave(ingest_dir: &Path, wave: QueuedWave) -> PreparedWrite {
    let QueuedWave {
        sequence,
        requests,
        rows,
    } = wave;
    let log = ingest_dir.join(format!("log-{sequence:020}.sst"));
    let state = ingest_dir.join(format!("state-{sequence:020}.sst"));
    let (log_result, state_result) = thread::scope(|scope| {
        let state_task = thread::Builder::new()
            .name(format!("{WRITER_THREAD_PREFIX}stage"))
            .spawn_scoped(scope, || stage_state_file(&state, &rows))
            .expect("failed to spawn SST staging thread");
        let log_result = stage_log_file(&log, sequence, &rows);
        (
            log_result,
            state_task.join().expect("state staging thread panicked"),
        )
    });
    let log_bytes = log_result.unwrap_or_else(|error| panic!("failed to stage log SST: {error}"));
    let state_bytes =
        state_result.unwrap_or_else(|error| panic!("failed to stage state SST: {error}"));
    PreparedWrite {
        sequence,
        requests,
        log,
        state,
        staged_bytes: log_bytes + state_bytes,
    }
}

/// Stages the single-row log SST: the group's sequence mapped to the exact encoded batch the
/// stream service serves. Uncompressed, like the state SST.
fn stage_log_file(path: &Path, sequence: u64, rows: &[(Bytes, Bytes)]) -> Result<usize, String> {
    let payload = encode_log_value(sequence, rows);
    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::None);
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    writer
        .put(sequence_log_key(sequence), &payload)
        .map_err(|e| e.to_string())?;

    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;
    Ok(LOG_BATCH_KEY_LEN + payload.len())
}

/// Stages the current-state SST: the group's rows sorted by key, with the last write per key
/// winning (in arrival order across coalesced requests). Uncompressed: compressing on the
/// ingest path would trade ack latency for bytes, and the state CF keeps compression off at
/// every level per [`state_cf_options`].
fn stage_state_file(path: &Path, rows: &[(Bytes, Bytes)]) -> Result<usize, String> {
    let mut rows: Vec<(&Bytes, &Bytes)> = rows.iter().map(|(key, value)| (key, value)).collect();

    // Stable sort: equal keys keep arrival order, so the last occurrence is the newest.
    rows.sort_by(|a, b| a.0.cmp(b.0));

    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::None);
    let mut writer = SstFileWriter::create(&options);
    writer.open(path).map_err(|e| e.to_string())?;
    let mut bytes = 0;
    for (index, (key, value)) in rows.iter().enumerate() {
        if rows.get(index + 1).is_some_and(|next| next.0 == *key) {
            continue;
        }
        bytes += key.len() + value.len();
        writer
            .put(key.as_ref(), value.as_ref())
            .map_err(|e| e.to_string())?;
    }

    // `finish` syncs the file before it is linked into the DB.
    writer.finish().map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// Commits one group: ingests its log row (durability), then its state file (visibility), then
/// publishes the frontier and resolves the requests. Any write failure is fatal (panic): once
/// the log row is durable the group cannot be rolled back (its sequence must not be
/// re-issued), and the next open rolls it forward by replaying the row, so nothing is ever
/// reclaimed or retried in-process. The panic drops the group's response channels, so waiting
/// callers observe an error even though the group may resurface after the restart repair, an
/// accepted at-least-once ambiguity of this severe error path.
fn commit_group(db: &DB, frontiers: &Frontiers, group: PreparedWrite) {
    assert!(!group.requests.is_empty(), "groups are never empty");
    let PreparedWrite {
        sequence,
        requests,
        log,
        state,
        staged_bytes,
    } = group;

    // Log first: the durable row alone defines the group (an ingested state file without its
    // log row could leave keys in the store that were never part of a sequenced batch). Safe
    // against a concurrent prune without a lock: a prune only deletes rows below a published
    // frontier it loaded earlier, and this sequence sits above every published frontier until
    // publish.
    ingest_staged_file(db, LOG_CF, &log);

    // Ingest and publish under the floor lock: a prune loads the published frontier as its
    // state floor under the same lock, so no scan-visible state row can outrun the frontier
    // covering it (a key prune must never delete a row the floor does not cover).
    let publish_guard = frontiers.persist.lock();
    ingest_staged_file(db, STATE_CF, &state);

    // Release so `current_sequence` readers only observe frontiers whose rows are readable.
    frontiers.published.store(sequence, Ordering::Release);
    drop(publish_guard);
    debug!(
        requests = requests.len(),
        staged_bytes, sequence, "committed write batch"
    );
    for request in requests {
        let _ = request.response.send(Ok(sequence));
    }
}

/// Ingests one staged SST file into `cf`. Ingestion links the file into the column family and
/// syncs the manifest, so the rows are durable and readable once this returns. Failure is fatal:
/// see `commit_group`.
fn ingest_staged_file(db: &DB, cf: &str, path: &Path) {
    let handle = db.cf_handle(cf).expect("CFs exist (created on open)");
    let mut ingest_options = IngestExternalFileOptions::default();
    ingest_options.set_move_files(true);
    db.ingest_external_file_cf_opts(handle, &ingest_options, vec![path])
        .unwrap_or_else(|error| {
            panic!(
                "failed to ingest staged SST {} into {cf}: {error}",
                path.display()
            )
        });
}

/// Writes a batch with sync enabled, used for the meta row that defines the durable floor.
fn write_synced_batch(db: &DB, batch: rocksdb::WriteBatch) -> Result<(), String> {
    let mut write_options = WriteOptions::default();
    write_options.set_sync(true);
    db.write_opt(batch, &write_options)
        .map_err(|e| e.to_string())
}

/// Creates the SST staging directory and deletes files a crashed writer left behind. A
/// leftover can exist even for an ingested group: move-ingestion hard-links the staged file
/// into the database and unlinks the original afterward, so a crash in between leaves the
/// original behind while its rows are already visible. Deleting leftovers is safe either way
/// because the database owns its own link to every ingested file. Nothing here decides
/// whether a group committed: the retained log rows alone do.
fn prepare_ingest_dir(store_path: &Path) -> Result<PathBuf, String> {
    let ingest_dir = store_path.join(LOG_INGEST_DIR);
    std::fs::create_dir_all(&ingest_dir)
        .map_err(|e| format!("failed to create staging directory: {e}"))?;
    for entry in std::fs::read_dir(&ingest_dir)
        .map_err(|e| format!("failed to read staging directory: {e}"))?
    {
        let entry = entry.map_err(|e| format!("failed to read staging directory: {e}"))?;
        std::fs::remove_file(entry.path())
            .map_err(|e| format!("failed to remove staged file: {e}"))?;
    }
    Ok(ingest_dir)
}

/// Encodes a sequence number as a log-CF key that preserves numeric order in RocksDB.
fn sequence_log_key(sequence: u64) -> [u8; LOG_BATCH_KEY_LEN] {
    sequence.to_be_bytes()
}

/// Decodes a log-CF key back into the sequence number it indexes.
fn sequence_from_log_key(key: &[u8]) -> Result<u64, String> {
    if key.len() != LOG_BATCH_KEY_LEN {
        return Err(format!("log CF key has unexpected length {}", key.len()));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&key[..8]);
    Ok(u64::from_be_bytes(raw))
}

/// Reads the state-floor meta row, defaulting to zero when no prune has written it yet. A
/// malformed row is corruption and fails the open: silently treating it as zero would let the
/// replay resurrect key-pruned rows.
fn read_state_floor(db: &DB) -> Result<u64, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, SEQ_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| "corrupt state-floor meta row".to_string())?;
            Ok(u64::from_le_bytes(bytes))
        }
        None => Ok(0),
    }
}

/// Reads the persisted retention rule. Absence of the row means no rule is installed (a cleared
/// rule deletes the row), so enforcement stops. A row that fails to decode or validate is
/// corruption and fails the open: a rule the RPC layer would reject (`keep_latest` count zero
/// enforces like `drop_all`) must not be enforced just because it round-trips the codec.
fn read_retention_policy(db: &DB) -> Result<Option<RetentionPolicy>, String> {
    let meta_cf = db
        .cf_handle(META_CF)
        .expect("meta CF must exist (created on open)");
    match db
        .get_cf(meta_cf, RETENTION_META_KEY)
        .map_err(|e| e.to_string())?
    {
        Some(bytes) => {
            let policy = RetentionPolicy::decode(Copying(bytes.as_slice()))
                .map_err(|e| format!("corrupt retention rule meta row: {e}"))?;
            validate_retention_policy(&policy)
                .map_err(|e| format!("corrupt retention rule meta row: {e}"))?;
            Ok(Some(policy))
        }
        None => Ok(None),
    }
}

/// Lowest sequence a retention rule keeps against `frontier`: the exclusive cutoff for log
/// trimming, so every row below it is evicted and the row at it (if any) is the oldest retained.
/// Mirrors the floor math the stream service owns end to end.
fn retention_floor(policy: &RetentionPolicy, frontier: u64) -> u64 {
    match policy {
        RetentionPolicy::KeepLatest { count } => frontier.saturating_sub(*count).saturating_add(1),
        RetentionPolicy::GreaterThan { threshold } => threshold.saturating_add(1),
        RetentionPolicy::GreaterThanOrEqual { threshold } => *threshold,
        RetentionPolicy::DropAll => frontier.saturating_add(1),
    }
}

/// Re-applies the newest retained log row to the state column family and returns its sequence
/// (zero when the log is empty). Rows are only ever ingested by sequential, atomic commits, so
/// the returned sequence is a lower bound on the durable frontier. `commit` ingests strictly
/// in order (a group's log row lands before its state, and the next group's row only after
/// that state), so every older group's state is already durably ingested and at most the
/// newest group can be missing it; re-applying is idempotent because the row's entries are the
/// newest writes for their keys. A row at or below `floor` is never replayed: its state is
/// authoritative, and key pruning may have deleted rows a replay would resurrect. Ingestion is
/// atomic, so no partial row can exist; a row that fails to decode is real corruption and
/// fails the open.
fn replay_newest_log_row(db: &DB, floor: u64) -> Result<u64, String> {
    let log_cf = db
        .cf_handle(LOG_CF)
        .expect("log CF must exist (created on open)");
    let Some(item) = db.iterator_cf(log_cf, IteratorMode::End).next() else {
        return Ok(0);
    };
    let (key, value) = item.map_err(|e| e.to_string())?;
    let sequence = sequence_from_log_key(key.as_ref())?;
    if sequence <= floor {
        return Ok(sequence);
    }
    let response = StreamGetResponseView::decode_view(value.as_ref())
        .map_err(|e| format!("corrupt log row for sequence {sequence}: {e}"))?;
    let mut batch = rocksdb::WriteBatch::default();
    for entry in response.entries.iter() {
        batch.put(entry.key, entry.value);
    }

    // Synced: once a later commit moves the newest row past this group, a repair lost to power
    // loss would never be re-run.
    write_synced_batch(db, batch)?;
    Ok(sequence)
}

/// Application-level write pipeline options used by [`RocksStore::open`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RocksWritePipelineConfig {
    /// Soft maximum combined size (state rows plus encoded log rows) before cutting a prepared
    /// commit group.
    pub max_commit_batch_bytes: NonZeroUsize,
    /// Stage workers building wave SSTs concurrently. Each worker stages one wave at a time
    /// across two threads (log and state SSTs in parallel).
    pub stage_workers: NonZeroUsize,
    /// Coalesced waves that may queue ahead of the stage workers before `prepare` blocks.
    /// Together with `stage_workers` this bounds staged memory: every queued or staging wave
    /// holds up to `max_commit_batch_bytes` of payload. Defaults to one queued wave per
    /// default worker.
    pub max_queued_waves: NonZeroUsize,
}

impl Default for RocksWritePipelineConfig {
    fn default() -> Self {
        Self {
            max_commit_batch_bytes: NonZeroUsize::new(DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES)
                .expect("default commit batch byte limit must be nonzero"),
            stage_workers: NonZeroUsize::new(DEFAULT_STAGE_WORKERS)
                .expect("default stage worker count must be nonzero"),
            max_queued_waves: NonZeroUsize::new(DEFAULT_STAGE_WORKERS)
                .expect("default queued wave limit must be nonzero"),
        }
    }
}

/// RocksDB engine and application-level write pipeline options used by [`RocksStore::open`].
#[derive(Default)]
pub struct RocksConfig {
    /// Database-wide options, applied as-is (stock defaults). Two knobs matter under sustained
    /// ingest: `max_background_jobs` (stock RocksDB fixes it at 2, and compactions must keep
    /// merging the overlapping ingested state SSTs) and `max_open_files` (stock RocksDB keeps
    /// every touched table file open forever, and ingest creates one log and one state SST per
    /// commit group).
    pub db_options: Options,
    /// Options for the application-level ingest write pipeline.
    pub write_pipeline: RocksWritePipelineConfig,
}

/// Options for the state column family, tuned to the store's write path.
///
/// Ingested state SSTs overlap (store keys are uniformly distributed), so this family bears
/// all compaction: universal compaction merges whole sorted runs instead of rewriting every
/// overlapping level, compression stays off (staged SSTs arrive uncompressed; recompressing
/// them buys nothing on ingest-bound stores), and the level-zero slowdown/stop triggers are
/// raised because `IngestExternalFile` waits on stop-writes conditions (stock triggers stall
/// ingest whenever compaction lags).
fn state_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts.set_compaction_style(DBCompactionStyle::Universal);
    opts.set_level_zero_file_num_compaction_trigger(16);
    opts.set_level_zero_slowdown_writes_trigger(1024);
    opts.set_level_zero_stop_writes_trigger(2048);
    opts
}

/// Options for the log column family.
///
/// Log rows are keyed by a monotonic sequence, so ingested log SSTs never overlap and settle
/// without rewrites; compression stays off to match the uncompressed staged files.
fn log_cf_options() -> Options {
    let mut opts = Options::default();
    opts.set_compression_type(DBCompressionType::None);
    opts.set_bottommost_compression_type(DBCompressionType::None);
    opts
}

/// Minimal RocksDB-backed store for the simulator: batch writes plus a global sequence u64
/// plus a per-sequence log.
#[derive(Clone)]
pub struct RocksStore {
    /// Declared before `db` so the last store drop joins the writer threads before releasing
    /// its database handle: the prepare thread stages files inside the data directory without
    /// holding [`Database`], so it must never outlive the handles that keep the directory
    /// alive.
    writer: Arc<Writer>,
    db: Arc<Database>,
    frontiers: Arc<Frontiers>,
    /// In-memory mirror of the persisted retention rule (the meta row is the source of truth
    /// across reopens). The ingest path reads it on every commit to trim continuously, so a
    /// cheap cache keeps a rule-less store off the disk on that hot path.
    retention: Arc<Mutex<Option<RetentionPolicy>>>,
}

impl RocksStore {
    /// Open the store with default options, unless `config` overrides the database or
    /// write-pipeline options. Column families run options tuned to the store's write path
    /// (see `state_cf_options` and `log_cf_options`).
    /// Re-derives the durable frontier from the retained log rows and the state-floor meta row,
    /// then re-applies the newest log row to the state column family so the current state is
    /// complete below the durable sequence even after a crash mid-commit.
    ///
    /// The caller keeps the directory at `path` alive until every handle to the store (clones,
    /// open cursors, in-flight operations) has dropped. [`RocksStore::open_owned`] hands that
    /// ordering to the store instead.
    pub fn open(path: &Path, config: Option<RocksConfig>) -> Result<Self, String> {
        Self::open_database(path, config, None)
    }

    /// Open a store that owns its data directory: `directory` is dropped strictly after the
    /// database has fully closed. Every store clone, open cursor, and in-flight operation
    /// keeps the database open, and the last of them releases the directory wherever it
    /// drops, so a directory whose drop has effects (for example `tempfile::TempDir`,
    /// which deletes it) can never be torn down under a live database.
    pub fn open_owned<D>(directory: D, config: Option<RocksConfig>) -> Result<Self, String>
    where
        D: AsRef<Path> + Send + Sync + 'static,
    {
        let path = directory.as_ref().to_path_buf();
        Self::open_database(&path, config, Some(Box::new(directory)))
    }

    /// Shared open path: see [`RocksStore::open`] for the recovery contract and
    /// [`RocksStore::open_owned`] for the directory-ownership contract.
    fn open_database(
        path: &Path,
        config: Option<RocksConfig>,
        closer: Option<Closer>,
    ) -> Result<Self, String> {
        let RocksConfig {
            mut db_options,
            write_pipeline,
        } = config.unwrap_or_default();

        db_options.create_if_missing(true);
        db_options.create_missing_column_families(true);

        let cf_state = ColumnFamilyDescriptor::new(STATE_CF, state_cf_options());
        let cf_meta = ColumnFamilyDescriptor::new(META_CF, Options::default());
        let cf_log = ColumnFamilyDescriptor::new(LOG_CF, log_cf_options());
        let db = DB::open_cf_descriptors(&db_options, path, vec![cf_state, cf_meta, cf_log])
            .map_err(|e| e.to_string())?;
        let db = Arc::new(Database {
            db,
            _closer: closer,
        });

        let ingest_dir = prepare_ingest_dir(path)?;

        // Commits do not write the state-floor meta row; the log rows are the durable record.
        let floor = read_state_floor(&db)?;
        let seq = floor.max(replay_newest_log_row(&db, floor)?);

        // Restore the retention rule so the ingest path keeps enforcing it after a reopen.
        let retention = Arc::new(Mutex::new(read_retention_policy(&db)?));

        let frontiers = Arc::new(Frontiers::new(seq));
        let writer = Arc::new(Writer::start(
            db.clone(),
            ingest_dir,
            frontiers.clone(),
            write_pipeline,
        ));
        let store = Self {
            db,
            frontiers,
            writer,
            retention,
        };
        // Re-apply the rule against the reopened log before serving reads: a crash can
        // lose the last (unsynced) trim, and a batch observed as evicted must never
        // become readable again.
        if store.retention.lock().is_some() {
            store.enforce_retention()?;
        }
        Ok(store)
    }

    /// Returns the log column-family handle created during open.
    fn log_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(LOG_CF)
            .expect("log CF must exist (created on open)")
    }

    /// Returns the meta column-family handle created during open.
    fn meta_cf(&self) -> &ColumnFamily {
        self.db
            .cf_handle(META_CF)
            .expect("meta CF must exist (created on open)")
    }

    /// Reads the current value for one default-column-family key.
    fn get_raw(&self, key: &[u8]) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        self.db.get(key)
    }

    /// Raises the durable state floor to the published frontier, marking every published row
    /// as state the open-time replay must never re-apply. Loaded and written under the
    /// publish lock, so the floor covers every row a prune's scan could have observed (a
    /// group's state becomes scan-visible only under the same lock hold that publishes it)
    /// and concurrent raises never regress it. Unsynced: the floor only has to be durable by
    /// the time the prune acks, and the caller's final synced write flushes it.
    fn raise_state_floor(&self) -> Result<(), String> {
        let _guard = self.frontiers.persist.lock();
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(
            self.meta_cf(),
            SEQ_META_KEY,
            self.frontiers
                .published
                .load(Ordering::Acquire)
                .to_le_bytes(),
        );
        self.db.write(batch).map_err(|e| e.to_string())
    }

    /// Deletes current rows in bounded chunks, entirely off the publish lock: keys are
    /// write-once, so a concurrent commit only ever adds new keys, never a row this delete
    /// targets. Chunking keeps any single batch from monopolizing the RocksDB write path
    /// that `commit`'s ingestions briefly pause and wait behind. The final chunk is synced,
    /// which flushes the whole run; a crash between chunks loses whole batches atomically,
    /// leaving rows the next prune pass re-deletes.
    fn delete_keys(&self, keys: &[Bytes]) -> Result<(), String> {
        let mut chunks = keys.chunks(PRUNE_DELETE_CHUNK_KEYS).peekable();
        while let Some(chunk) = chunks.next() {
            let mut batch = rocksdb::WriteBatch::default();
            for k in chunk {
                batch.delete(k.as_ref());
            }
            if chunks.peek().is_none() {
                write_synced_batch(&self.db, batch)?;
            } else {
                self.db.write(batch).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Deletes replay-log rows with sequence numbers below `cutoff_exclusive`. A no-op when
    /// the cutoff does not advance past what this process already trimmed.
    fn prune_log(&self, cutoff_exclusive: u64) -> Result<(), String> {
        if cutoff_exclusive == 0
            || self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive
        {
            return Ok(());
        }
        let _guard = self.frontiers.persist.lock();
        // Recheck under the lock: a concurrent trim from the same ingest wave may have
        // covered this cutoff while we waited.
        if self.frontiers.trimmed.load(Ordering::Acquire) >= cutoff_exclusive {
            return Ok(());
        }

        // One atomic batch: the range tombstone that deletes the rows, and the state floor
        // that keeps `open` from re-deriving a regressed frontier once they are gone.
        // The published frontier covers every pruned row (the cutoff is capped at
        // published + 1), and everything at or below it is durable and applied to the state.
        // That also makes this safe against the writer's concurrent, lock-free log ingestion:
        // an in-flight group's row sits above every published frontier this prune could have
        // loaded. Space is reclaimed by ordinary compaction; nothing assumes which SST files
        // hold the rows.
        //
        // Unsynced: batch atomicity means a crash loses the tombstone and the floor raise
        // together, leaving the rows intact and open's re-derivation consistent; the next
        // enforcement reapplies the trim. This keeps the per-append retention hook from
        // adding a second fsync to every ingest.
        let published = self.frontiers.published.load(Ordering::Acquire);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(self.meta_cf(), SEQ_META_KEY, published.to_le_bytes());
        batch.delete_range_cf(
            self.log_cf(),
            sequence_log_key(0),
            sequence_log_key(cutoff_exclusive),
        );
        self.db.write(batch).map_err(|e| e.to_string())?;
        self.frontiers
            .trimmed
            .store(cutoff_exclusive, Ordering::Release);
        Ok(())
    }

    /// Applies each prune policy in document order to current rows. A prune document is
    /// Keys-only; sequence-log retention is handled by `log.retention.v1.SetRetention`
    /// (see the [`Retention`] impl).
    fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        for policy in &document.policies {
            self.apply_key_prune_policy(&policy.scope, &policy.retain)?;
        }
        Ok(())
    }

    /// Scans matching current keys in bounded chunks, groups them, and deletes non-retained rows.
    fn apply_key_prune_policy(
        &self,
        scope: &KeysScope,
        retain: &RetainPolicy,
    ) -> Result<(), String> {
        let prefix =
            Prefix::new(scope.selector.prefix.clone()).map_err(|e| format!("policy: {e}"))?;
        let regex = compile_payload_regex(&scope.selector.payload_regex)
            .map_err(|e| format!("policy: {e}"))?;

        let (start, end) = prefix.bounds();
        let mut rows = RocksRangeScanState::new(self.db.clone(), start, end, usize::MAX, true);
        let mut groups: BTreeMap<Vec<u8>, Vec<KeyEntry>> = BTreeMap::new();

        loop {
            let batch = rows.next_batch(PRUNE_SCAN_BATCH_SIZE)?;
            if batch.is_empty() {
                break;
            }

            for (key, _value) in batch {
                let payload = match prefix.strip(&key) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                if !regex.is_match(&payload) {
                    continue;
                }

                let group_key = match extract_group_key(&payload, &regex, scope) {
                    Some(group_key) => group_key,
                    None => continue,
                };
                let order_value = extract_order_value(&payload, &regex, scope).unwrap_or_default();

                groups
                    .entry(group_key)
                    .or_default()
                    .push(KeyEntry { key, order_value });
            }
        }

        let mut all_deletes = Vec::new();
        for (_group_key, entries) in groups {
            all_deletes.extend(keys_to_delete(entries, scope, retain)?);
        }
        if all_deletes.is_empty() {
            return Ok(());
        }

        // The floor is raised before the deletes so the final synced chunk makes it durable
        // by ack: an acked prune must never be undone by the newest-log-row replay at reopen.
        self.raise_state_floor()?;
        self.delete_keys(&all_deletes)
    }

    /// Lowest retained log sequence at or below the published frontier, or `None` when the log
    /// holds no such row. Shared by `oldest_retained_batch` and retention enforcement.
    fn oldest_retained_sequence(&self) -> Result<Option<u64>, String> {
        let mut it = self.db.iterator_cf(self.log_cf(), IteratorMode::Start);
        match it.next() {
            None => Ok(None),
            Some(item) => {
                let (key, _) = item.map_err(|e| e.to_string())?;
                let sequence = sequence_from_log_key(key.as_ref())?;

                // Gate on the published frontier: never advertise an oldest batch that
                // `get_batch` would then hide (a log row can outrun the published frontier while
                // its group's state ingestion is in flight or has failed).
                if sequence > self.frontiers.published.load(Ordering::Acquire) {
                    return Ok(None);
                }
                Ok(Some(sequence))
            }
        }
    }

    /// Persists the retention rule durably, or deletes the row when clearing. A single-admin
    /// control write, so it is synced and last-write-wins; enforcement reads go through the
    /// in-memory cache seeded from this row at open.
    fn store_retention_policy(&self, policy: Option<&RetentionPolicy>) -> Result<(), String> {
        let mut batch = rocksdb::WriteBatch::default();
        match policy {
            Some(policy) => batch.put_cf(self.meta_cf(), RETENTION_META_KEY, policy.encode()),
            None => batch.delete_cf(self.meta_cf(), RETENTION_META_KEY),
        }
        write_synced_batch(&self.db, batch)
    }

    /// Runs one round of retention enforcement against the current frontier and returns the
    /// resulting oldest retained sequence (`None` when the log is empty / no floor exists). With
    /// no rule installed this only reports the current oldest batch, leaving the log untouched.
    fn enforce_retention(&self) -> Result<Option<u64>, String> {
        // Clone the rule out in its own statement so the cache lock drops before trimming:
        // an `if let self.retention.lock().clone()` scrutinee would (edition 2021) hold the
        // guard for the whole block. `prune_log` takes the persist lock and issues a range
        // delete; holding the retention mutex across that disk write would block every
        // `put_batch` rule check on a Tokio worker.
        let policy = self.retention.lock().clone();
        if let Some(policy) = policy {
            let frontier = self.frontiers.published.load(Ordering::Acquire);

            // Never delete log rows above the published frontier: a group whose log ingestion
            // committed but whose state ingestion did not still needs its rows for the repair
            // replay at the next open.
            let cutoff_exclusive =
                retention_floor(&policy, frontier).min(frontier.saturating_add(1));
            self.prune_log(cutoff_exclusive)?;
        }
        self.oldest_retained_sequence()
    }

    /// Installs (`Some`) or clears (`None`) the retention rule, then enforces it once. The rule
    /// is persisted durably and mirrored into the cache the ingest path reads, so it keeps
    /// tracking the frontier continuously; clearing stops enforcement but leaves already-evicted
    /// rows evicted. Returns the oldest retained sequence after this enforcement.
    fn set_retention(&self, policy: Option<RetentionPolicy>) -> Result<Option<u64>, String> {
        self.store_retention_policy(policy.as_ref())?;
        *self.retention.lock() = policy;
        self.enforce_retention()
    }
}

impl Sequence for RocksStore {
    fn current_sequence(&self) -> u64 {
        self.frontiers.published.load(Ordering::Acquire)
    }
}

// Ingest uses dedicated writer threads so blocking storage writes do not occupy Tokio workers.
// The writer folds already-queued requests into one commit group that shares a single sequence
// number and replay-log batch.
impl Ingest for RocksStore {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        let sequence = self.writer.put_batch(kvs).await?;

        // Continuous retention: trim the just-grown log to the active rule's floor so the rule
        // tracks the frontier without another RPC. The rule-less case is a cheap cache check;
        // an installed rule takes the blocking trim (an unsynced range tombstone, skipped
        // outright when the floor has not advanced) off the Tokio worker.
        //
        // Best-effort: the batch is already durably committed and acked above, so a trim failure
        // must NOT fail the ingest. Failing here would make the caller re-ingest durable data
        // under a fresh sequence, duplicating the batch for subscribers. The trim is idempotent,
        // so the next append (or a `SetRetention`) reapplies it.
        if self.retention.lock().is_some() {
            let store = self.clone();
            match tokio::task::spawn_blocking(move || store.enforce_retention()).await {
                Ok(Ok(_)) => {}
                Ok(Err(message)) => tracing::warn!(
                    sequence,
                    error = %message,
                    "continuous retention trim failed after commit; batch is durable, retrying on the next append",
                ),
                Err(join_error) => tracing::warn!(
                    sequence,
                    error = %join_error,
                    "retention enforcement task failed after commit; batch is durable, retrying on the next append",
                ),
            }
        }
        Ok(sequence)
    }
}

impl Query for RocksStore {
    type RangeScan = RocksRangeScanCursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        let store = self.clone();
        store
            .get_raw(&key)
            .map(|value| (value.map(Bytes::from), QueryExtra::default()))
            .map_err(|e| e.to_string())
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Self::RangeScan, String> {
        Ok(RocksRangeScanCursor::new(
            self.db.clone(),
            start,
            end,
            limit,
            forward,
        ))
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        let store = self.clone();
        let results = store.db.multi_get(keys.iter().map(|key| key.as_ref()));
        let entries = keys
            .into_iter()
            .zip(results)
            .map(|(k, r)| {
                let value = r.map_err(|e| e.to_string())?;
                Ok((k, value.map(Bytes::from)))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok((entries, QueryExtra::default()))
    }
}

// Pruning scans the full selector range and issues synced writes, so it runs on the blocking
// pool instead of occupying a Tokio worker.
impl Prune for RocksStore {
    async fn apply_prune_policies(&self, document: PrunePolicyDocument) -> Result<(), String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.apply_prune_policies(document))
            .await
            .map_err(|e| format!("prune task failed: {e}"))?
    }
}

// Log batches are loaded from the log column family on demand: no cache, one read per request.
impl Log for RocksStore {
    async fn get_batch(&self, sequence_number: u64) -> Result<Option<LogBatch>, String> {
        // Serve only published batches: rows above the visible frontier are still being
        // committed and must not be observable early.
        if sequence_number > self.frontiers.published.load(Ordering::Acquire) {
            return Ok(None);
        }

        // The read runs on the blocking pool so this future yields. An inline read
        // holds a Tokio worker for the whole RocksDB lookup, which serializes the
        // subscribe lookahead and stalls unrelated tasks on cold reads.
        let store = self.clone();
        let value = tokio::task::spawn_blocking(move || {
            store
                .db
                .get_cf(store.log_cf(), sequence_log_key(sequence_number))
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("log read task failed: {e}"))??;

        let Some(value) = value else {
            return Ok(None);
        };
        Ok(Some(LogBatch::from_response_bytes(sequence_number, value)))
    }

    async fn oldest_retained_batch(&self) -> Result<Option<u64>, String> {
        self.oldest_retained_sequence()
    }
}

// Retention persists a rule (a synced write) and trims the sequence log, so it runs on the
// blocking pool instead of occupying a Tokio worker. The ingest path enforces the same rule
// continuously as the log grows (see `Ingest::put_batch`).
impl Retention for RocksStore {
    async fn set_retention(&self, policy: Option<RetentionPolicy>) -> Result<Option<u64>, String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.set_retention(policy))
            .await
            .map_err(|e| format!("retention task failed: {e}"))?
    }
}

/// Encodes the batch payload served for one sequence's key/value rows.
fn encode_log_value(sequence: u64, kvs: &[(Bytes, Bytes)]) -> Vec<u8> {
    StreamGetResponse {
        sequence_number: sequence,
        entries: kvs
            .iter()
            .map(|(key, value)| Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use exoware_server::{Ingest, Log, Sequence};
    use tempfile::tempdir;

    fn write_request(key: &'static [u8]) -> WriteRequest {
        let (response, _result) = oneshot::channel();
        WriteRequest {
            kvs: vec![(Bytes::from_static(key), Bytes::from_static(b"value"))],
            response,
        }
    }

    fn response_entries(response: StreamGetResponse) -> Vec<(Bytes, Bytes)> {
        response
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect()
    }

    fn batch_entries(batch: LogBatch) -> Vec<(Bytes, Bytes)> {
        response_entries(batch.decode_response().expect("decode batch response"))
    }

    fn encoded_log_entry(sequence: u64, key: &'static [u8], value: &'static [u8]) -> Vec<u8> {
        StreamGetResponse {
            sequence_number: sequence,
            entries: vec![Entry {
                key: key.to_vec(),
                value: Bytes::from_static(value),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec()
    }

    /// Commits one group through the commit stage, returning the published frontier afterwards.
    fn commit_and_apply(store: &RocksStore, group: PreparedWrite) -> u64 {
        commit_group(&store.db, &store.frontiers, group);
        store.frontiers.published.load(Ordering::Acquire)
    }

    /// Writes one log row directly, bypassing the write pipeline and the floor advance.
    fn seed_log_row(store: &RocksStore, sequence: u64, payload: &[u8]) {
        store
            .db
            .put_cf(store.log_cf(), sequence_log_key(sequence), payload)
            .expect("seed log row");
    }

    /// Stages one commit group carrying `kvs` under the sequence after `from`.
    fn prepared_write(store: &RocksStore, from: u64, kvs: Vec<(Bytes, Bytes)>) -> PreparedWrite {
        let (_sender, receiver) = mpsc::channel::<WriteRequest>();
        let (response, _result) = oneshot::channel();
        let ingest_dir = store.db.path().join(LOG_INGEST_DIR);
        let (wave, _) = coalesce_queued_write(
            &receiver,
            WriteRequest { kvs, response },
            from,
            DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES,
        );
        stage_wave(&ingest_dir, wave)
    }

    #[test]
    fn owned_directory_outlives_every_database_holder() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().to_path_buf();
        let store = RocksStore::open_owned(dir, None).expect("open owned store");

        // A cursor keeps the database, and therefore the owned directory, alive after every
        // store handle is gone.
        let cursor = RocksRangeScanCursor::new(
            store.db.clone(),
            Bytes::new(),
            Bytes::new(),
            usize::MAX,
            true,
        );
        drop(store);
        assert!(
            path.exists(),
            "directory must survive while a cursor still holds the database"
        );

        drop(cursor);
        assert!(
            !path.exists(),
            "directory must be deleted once the last database holder drops"
        );
    }

    /// A drop-order canary: reopening the path only succeeds once the previous database
    /// instance has released its `LOCK` file.
    struct ReopenOnDrop {
        path: PathBuf,
    }

    impl Drop for ReopenOnDrop {
        fn drop(&mut self) {
            DB::open(&Options::default(), &self.path)
                .expect("closer must drop only after the database has closed");
        }
    }

    #[test]
    fn closer_drops_only_after_database_closes() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("db");
        let mut options = Options::default();
        options.create_if_missing(true);
        let db = DB::open(&options, &path).expect("open db");

        // Struct fields drop in declaration order, so `db` drops (and releases its `LOCK`
        // file) before the canary closer runs. If the order ever flipped, the reopen inside
        // the closer would fail against the still-held lock.
        drop(Database {
            db,
            _closer: Some(Box::new(ReopenOnDrop { path: path.clone() })),
        });
    }

    #[test]
    fn rocks_config_default_pins_commit_batch_cap() {
        assert_eq!(
            RocksConfig::default()
                .write_pipeline
                .max_commit_batch_bytes
                .get(),
            16 * 1024 * 1024
        );
    }

    #[test]
    fn coalesce_queued_write_collects_all_pending_below_byte_cap() {
        let dir = tempdir().expect("tempdir");
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (wave, disconnected) =
            coalesce_queued_write(&receiver, first, 0, DEFAULT_COMMIT_COALESCE_MAX_BATCH_BYTES);
        assert_eq!(wave.sequence, 1);
        assert_eq!(wave.requests.len(), 3);
        assert!(disconnected);
        let group = stage_wave(dir.path(), wave);
        assert_eq!(group.sequence, 1);
        assert_eq!(group.requests.len(), 3);
        assert!(group.log.exists());
        assert!(group.state.exists());
        assert!(group.staged_bytes > 0);
    }

    #[test]
    fn coalesce_queued_write_stops_after_soft_byte_cap() {
        let (sender, receiver) = mpsc::channel();
        sender.send(write_request(b"a")).expect("send");
        sender.send(write_request(b"b")).expect("send");
        sender.send(write_request(b"c")).expect("send");
        drop(sender);

        let first = receiver.recv().expect("first request");
        let (wave, disconnected) = coalesce_queued_write(&receiver, first, 0, 1);

        assert_eq!(wave.requests.len(), 1);
        assert_eq!(wave.requests[0].kvs[0].0.as_ref(), b"a");
        assert!(!disconnected);
        assert_eq!(
            receiver
                .try_recv()
                .expect("next wave should keep queued request")
                .kvs[0]
                .0
                .as_ref(),
            b"b"
        );
    }

    /// A missing staged file makes ingestion fail, which is fatal: the group cannot be rolled
    /// back once any of it is durable, and the next open repairs whatever the dead writer left.
    #[test]
    #[should_panic(expected = "failed to ingest staged SST")]
    fn write_errors_are_fatal() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let group = prepared_write(
            &store,
            0,
            vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
        );
        std::fs::remove_file(&group.state).expect("sabotage staged state file");
        commit_and_apply(&store, group);
    }

    /// One multi-megabyte batch, sized to exercise multi-block ingested log rows.
    fn large_batch(tag: u8) -> Vec<(Bytes, Bytes)> {
        (0..1040)
            .map(|i| {
                let mut key = vec![tag];
                key.extend_from_slice(&(i as u64).to_be_bytes());
                (Bytes::from(key), Bytes::from(vec![tag; 4096]))
            })
            .collect()
    }

    #[tokio::test]
    async fn batches_commit_through_ingestion_and_survive_reopen() {
        let dir = tempdir().expect("tempdir");
        let (first, second) = {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let first = store.put_batch(large_batch(1)).await.expect("put");
            let second = store.put_batch(large_batch(2)).await.expect("put");
            assert_eq!(store.current_sequence(), second);

            let batch = store
                .get_batch(first)
                .await
                .expect("get batch")
                .expect("batch retained");
            assert_eq!(batch_entries(batch), large_batch(1));
            (first, second)
        };

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), second);
        for (sequence, tag) in [(first, 1u8), (second, 2u8)] {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            assert_eq!(batch_entries(batch), large_batch(tag));
        }
        assert_eq!(
            store.get_raw(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0]).expect("get"),
            Some(vec![1u8; 4096])
        );

        // Retention evicts log rows by key; space reclamation is compaction's job.
        store
            .set_retention(Some(RetentionPolicy::KeepLatest { count: 1 }))
            .expect("set retention");
        assert!(store.get_batch(first).await.expect("get").is_none());
        assert!(store.get_batch(second).await.expect("get").is_some());
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(second)
        );
    }

    #[tokio::test]
    async fn reopen_enforces_restored_retention_rule() {
        let dir = tempdir().expect("tempdir");
        let (first, second, third) = {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            let first = store.put_batch(large_batch(1)).await.expect("put");
            let second = store.put_batch(large_batch(2)).await.expect("put");
            let third = store.put_batch(large_batch(3)).await.expect("put");
            // Persist the rule without running its enforcement, leaving rows below the
            // rule's floor in the log — the state a crash that lost the last (unsynced)
            // trim leaves behind.
            store
                .store_retention_policy(Some(&RetentionPolicy::KeepLatest { count: 1 }))
                .expect("store policy");
            (first, second, third)
        };

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        for evicted in [first, second] {
            assert!(store.get_batch(evicted).await.expect("get").is_none());
        }
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(third)
        );
    }

    #[tokio::test]
    async fn reopen_rejects_invalid_persisted_retention_rule() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            // Bypass `set_retention` (whose callers validate) to persist a rule the RPC
            // layer would reject: `keep_latest` count zero enforces like `drop_all`.
            store
                .store_retention_policy(Some(&RetentionPolicy::KeepLatest { count: 0 }))
                .expect("store policy");
        }

        let Err(error) = RocksStore::open(dir.path(), None) else {
            panic!("invalid rule must fail open");
        };
        assert!(error.contains("keep_latest count must be > 0"), "{error}");
    }

    /// Number of retained rows in the log column family.
    fn live_log_rows(store: &RocksStore) -> usize {
        store
            .db
            .iterator_cf(store.log_cf(), IteratorMode::Start)
            .count()
    }

    #[tokio::test]
    async fn reopen_replays_newest_log_batch_missing_from_state() {
        let dir = tempdir().expect("tempdir");
        {
            let store = RocksStore::open(dir.path(), None).expect("open db");
            store
                .put_batch(vec![(Bytes::from_static(b"k1"), Bytes::from_static(b"v1"))])
                .await
                .expect("put");

            // Simulate a crash that lost the WAL-less state rows for sequence 2 (the group
            // whose commit was interrupted) but kept its durable log row: write it directly,
            // bypassing the state apply stage and the floor advance. The reopened store must
            // re-derive the durable frontier from the retained rows alone, exactly as after a
            // crash that also lost the unsynced floor advance.
            let payload = StreamGetResponse {
                sequence_number: 2,
                entries: vec![
                    Entry {
                        key: b"k2".to_vec(),
                        value: Bytes::from_static(b"v2-stale"),
                        ..Default::default()
                    },
                    Entry {
                        key: b"k2".to_vec(),
                        value: Bytes::from_static(b"v2"),
                        ..Default::default()
                    },
                    Entry {
                        key: b"k3".to_vec(),
                        value: Bytes::from_static(b"v3"),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }
            .encode_to_vec();
            seed_log_row(&store, 2, &payload);
        }

        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), 2);

        // Replay applied the missing rows in arrival order: last writer wins for k2.
        for (key, value) in [
            (b"k1" as &[u8], b"v1" as &[u8]),
            (b"k2", b"v2"),
            (b"k3", b"v3"),
        ] {
            assert_eq!(
                store.get_raw(key).expect("get").as_deref(),
                Some(value),
                "key {key:?}"
            );
        }

        // A second reopen replays again (the floor only advances on prune); idempotent.
        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db again");
        assert_eq!(store.current_sequence(), 2);
        assert_eq!(
            store.get_raw(b"k2").expect("get").as_deref(),
            Some(b"v2" as &[u8])
        );
    }

    #[tokio::test]
    async fn empty_batches_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let error = store.put_batch(Vec::new()).await.expect_err("must reject");
        assert_eq!(
            error,
            IngestError::Internal {
                message: "cannot ingest an empty batch".to_string(),
            }
        );
        assert_eq!(store.current_sequence(), 0);
    }

    /// Concurrent puts staged by parallel workers must still commit in
    /// contiguous sequence order and survive reopen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_commit_in_sequence_order() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let puts: Vec<_> = (0..64u32)
            .map(|i| {
                let store = store.clone();
                tokio::spawn(async move {
                    let key = Bytes::from(format!("key-{i:03}"));
                    let value = Bytes::from(vec![i as u8; 4096]);
                    store.put_batch(vec![(key, value)]).await.expect("put")
                })
            })
            .collect();
        let mut sequences = Vec::with_capacity(puts.len());
        for put in puts {
            sequences.push(put.await.expect("put task"));
        }
        // Concurrent puts coalesce into shared-sequence waves; the waves must
        // still commit contiguously from 1 with none skipped or reordered.
        let top = store.current_sequence();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences, (1..=top).collect::<Vec<u64>>());

        drop(store);
        let store = RocksStore::open(dir.path(), None).expect("reopen db");
        assert_eq!(store.current_sequence(), top);
    }

    /// The tuned column-family options must reach RocksDB: assert against the
    /// OPTIONS file the database persists on open.
    #[tokio::test]
    async fn column_family_options_apply() {
        let dir = tempdir().expect("tempdir");
        let _store = RocksStore::open(dir.path(), None).expect("open db");

        let options_file = std::fs::read_dir(dir.path())
            .expect("read db dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("OPTIONS-"))
            })
            .max()
            .expect("OPTIONS file exists");
        let options = std::fs::read_to_string(options_file).expect("read OPTIONS file");

        let state = options
            .split("[CFOptions \"default\"]")
            .nth(1)
            .expect("state CF section")
            .split("[TableOptions")
            .next()
            .expect("state CF body");
        assert!(state.contains("compaction_style=kCompactionStyleUniversal"));
        assert!(state.contains("compression=kNoCompression"));
        assert!(state.contains("level0_slowdown_writes_trigger=1024"));

        let log = options
            .split("[CFOptions \"log\"]")
            .nth(1)
            .expect("log CF section")
            .split("[TableOptions")
            .next()
            .expect("log CF body");
        assert!(log.contains("compression=kNoCompression"));
    }

    #[tokio::test]
    async fn rocks_store_accepts_custom_config() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(
            dir.path(),
            Some(RocksConfig {
                write_pipeline: RocksWritePipelineConfig {
                    max_commit_batch_bytes: NonZeroUsize::new(1).expect("nonzero"),
                    stage_workers: NonZeroUsize::new(2).expect("nonzero"),
                    max_queued_waves: NonZeroUsize::new(1).expect("nonzero"),
                },
                ..Default::default()
            }),
        )
        .expect("open db");

        let sequence = store
            .put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
            .await
            .expect("put");
        assert_eq!(sequence, 1);
        assert_eq!(store.current_sequence(), 1);
    }

    #[tokio::test]
    async fn coalesced_group_shares_one_sequence() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let prepared = prepared_write(
            &store,
            0,
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            ],
        );
        assert_eq!(prepared.sequence, 1);
        assert_eq!(commit_and_apply(&store, prepared), 1);

        let second = prepared_write(
            &store,
            1,
            vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
        );
        assert_eq!(second.sequence, 2);
        assert_eq!(commit_and_apply(&store, second), 2);

        // Each group serves one batch carrying all its rows.
        let batch = store
            .get_batch(1)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch_entries(batch),
            vec![
                (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
                (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            ]
        );
        let batch = store
            .get_batch(2)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(
            batch_entries(batch),
            vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_puts_keep_all_rows_in_sequence_logs() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let mut puts = Vec::new();

        for i in 0u8..32 {
            let store = store.clone();
            puts.push(tokio::spawn(async move {
                store
                    .put_batch(vec![(Bytes::from(vec![i]), Bytes::from(vec![i + 1]))])
                    .await
                    .expect("put")
            }));
        }

        let mut sequences = Vec::new();
        for put in puts {
            sequences.push(put.await.expect("put task"));
        }
        let current = store.current_sequence();
        assert!((1..=32).contains(&current));
        assert!(sequences
            .iter()
            .all(|sequence| (1..=current).contains(sequence)));

        let mut logged_keys = BTreeSet::new();
        for sequence in 1..=current {
            let batch = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .expect("batch retained");
            let batch = batch_entries(batch);
            assert!(!batch.is_empty());
            for (key, value) in batch {
                assert_eq!(value.as_ref(), &[key[0] + 1]);
                logged_keys.insert(key[0]);
            }
        }
        assert_eq!(logged_keys, (0u8..32).collect::<BTreeSet<_>>());
    }

    #[tokio::test]
    async fn retention_spares_log_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        // A durable log row whose group never published (its state ingestion was in flight at
        // a crash): retention must spare it. It is the repair replay's input at the next open.
        seed_log_row(&store, 1, &encoded_log_entry(1, b"k", b"v"));

        store
            .set_retention(Some(RetentionPolicy::DropAll))
            .expect("set retention");

        assert_eq!(
            live_log_rows(&store),
            1,
            "unpublished log row must survive retention enforcement"
        );
    }

    #[tokio::test]
    async fn oldest_retained_batch_hides_rows_above_published_frontier() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        seed_log_row(&store, 1, &encoded_log_entry(1, b"k", b"v"));

        // The row's group never published (e.g. its state ingestion is still in flight), so it
        // must stay invisible to both the point read and the oldest-retained probe.
        assert!(store.get_batch(1).await.expect("get").is_none());
        assert_eq!(store.oldest_retained_batch().await.expect("oldest"), None);
    }

    #[tokio::test]
    async fn get_batch_reads_values_from_sequence_log() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        let key = Bytes::from_static(b"key");
        let value = Bytes::from_static(b"value");
        let sequence = store
            .put_batch(vec![(key.clone(), value.clone())])
            .await
            .expect("put");

        store
            .delete_keys(std::slice::from_ref(&key))
            .expect("delete primary row");

        let batch = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .expect("batch retained");
        assert_eq!(batch_entries(batch), vec![(key, value)]);
    }

    // The subscribe lookahead can only overlap log reads if `get_batch` yields.
    // An inline read completes within a single poll, so the in-flight gauge
    // would never exceed one and this test would fail.
    #[tokio::test]
    async fn get_batch_reads_overlap_under_buffered_lookahead() {
        use futures::StreamExt;

        let dir = tempdir().expect("tempdir");
        let store = Arc::new(RocksStore::open(dir.path(), None).expect("open db"));
        let batches = 8u64;
        for i in 0..batches {
            store
                .put_batch(vec![(
                    Bytes::from(format!("key-{i}")),
                    Bytes::from_static(b"value"),
                )])
                .await
                .expect("put");
        }

        let in_flight = Arc::new(AtomicU64::new(0));
        let max_in_flight = Arc::new(AtomicU64::new(0));
        let mut reads = futures::stream::iter(1..=batches)
            .map(|sequence| {
                let store = store.clone();
                let in_flight = in_flight.clone();
                let max_in_flight = max_in_flight.clone();
                async move {
                    let level = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_in_flight.fetch_max(level, Ordering::SeqCst);
                    let result = store.get_batch(sequence).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    result
                }
            })
            .buffered(batches as usize);
        while let Some(batch) = reads.next().await {
            batch.expect("get batch").expect("batch retained");
        }

        assert!(
            max_in_flight.load(Ordering::SeqCst) >= 2,
            "buffered get_batch reads never overlapped",
        );
    }

    #[tokio::test]
    async fn writer_accepts_concurrent_arrivals() {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");

        let (seq_a, seq_b) = tokio::join!(
            store.put_batch(vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))]),
            store.put_batch(vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
        );
        let seq_a = seq_a.expect("first write");
        let seq_b = seq_b.expect("second write");

        let current = store.current_sequence();
        assert!((1..=2).contains(&current));
        assert!((1..=current).contains(&seq_a));
        assert!((1..=current).contains(&seq_b));
        assert_eq!(
            store.db.get(b"a").expect("get a").as_deref(),
            Some(&b"1"[..])
        );
        assert_eq!(
            store.db.get(b"b").expect("get b").as_deref(),
            Some(&b"2"[..])
        );
    }
}
