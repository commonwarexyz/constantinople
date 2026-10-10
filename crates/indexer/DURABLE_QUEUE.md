# Indexer durable queue

The finalized queue records everything required to regenerate SQL, state QMDB,
transaction QMDB, and Simplex artifacts after a restart. The queue and its
capture receipt define local progress. Remote writer recovery is unnecessary.

This implementation starts a fresh index from genesis. Existing durable queue
storage must be wiped and remote namespaces must be empty. No migration is provided.

## Capture and persistence

Commonware requests capture with the winning merkleized batches and readers
before applying them. When a finalized hook is installed, Constantinople retains
the exact operation vectors and pinned prefix nodes for both QMDBs. After
successful application, the engine passes those artifacts and the shared block
to the queue producer through the hook. Genesis, startup reconciliation, and
state sync do not produce these individual artifacts.

The producer retrieves the height finalization from the marshal archive when
one was stored and verifies that it certifies the block commitment. Marshal
stores a per-height certificate only when it observed one. Heights finalized
through a descendant certificate, and heights backfilled after downtime, carry
none. The producer requires consecutive heights and operation ranges. The first
captured block is height one and both ranges start at location one, after their
authenticated genesis sentinels.

Each payload contains:

- A magic number and a format version.
- The full block, the optional finalization certificate, and the finalized timestamp.
- Both operation ranges, including their exact encoded operations and pins.

Payloads live in one blob per height. A small fixed-size queue record holds the
block's capture receipt and its payload descriptor. The receipt is the height,
block digest, and both range ends. The descriptor is the payload length and
checksum. The producer syncs the payload before committing its record. Consumer
admission opens only after that record is durable.

The queue tail is the capture receipt while records remain. The producer keeps
that receipt in memory for duplicate detection. Before pruning a completed
record section, the consumer syncs the last removed record's receipt to a
separate metadata partition. This preserves the capture boundary even when the
queue becomes empty and avoids a third sync for every captured block.

## Admission and ownership

Recovery scans fixed-size records and validates payload presence without
reading or decoding payloads. Payload lengths are verified on read. Payload
reads and structured decoding start only after byte admission. A concurrency
limit bounds the number of active uploads in addition to the estimated byte
budget. An oversized item reserves the whole budget and runs alone.

An `UploadReservation` owns the semaphore permit. Rust drops that permit on
success, failure, or cancellation. Its lifetime includes payload read, decode,
preparation, and data and Simplex persistence. It ends before ordered publication
and acknowledgement, so completed uploads behind a slow head do not retain
large allocations.

Captured operation vectors use `Arc`. Sharing an `Arc` retains the existing
allocation rather than copying the operations. The engine block also owns shared
block data, and preparation borrows the queued operations and pins.

Payload reads can overlap, but a predecessor admission gate ensures the
publisher receives uploads in queue order. Completed tasks are reaped while the
next record waits for capacity. Queue read errors retry even if the producer
never enqueues another block.

## Authenticated preparation and publication

Preparation validates each range against its certified header root and emits
deterministic absolute Store rows. The exact range start comes from the captured
batch. A header's inactivity boundary does not identify that start.

The inactive peak count is derived from the range end and the inactivity floor
in the block header. The pinned prefix and captured operations reconstruct the
header root without a separate range proof.

The operation encodings, range ends, pins, terminal commit, format
version, and adjacent range boundaries must agree. Unsupported formats or
invalid artifacts fail the supervised indexer and remain unacknowledged.

Each publisher starts by emitting supplied pins, including after a restart in
the middle of the operation log. Once an upload's data requests are all durable,
admission records that later uploads can omit supplied pins. Those nodes come
from earlier admitted ranges in the same history. Some predecessors may still
be uploading, so publication must continue to wait for the fully durable
contiguous prefix. Node rows are retained without a pruning policy.

Each block stages its SQL rows and both QMDB ranges together. Data requests
are split by an encoded-byte budget and a row cap. These are publisher tuning
budgets, not Store protocol limits. The README lists their values.

Small batches remain one request. Larger batches commit with several chunk
requests in flight per block. The limit covers request encoding, compression,
and retries. Each active block has its own chunk slots. Upload admission still
bounds active blocks and their memory budget. Every chunk must finish durably
before the block can enter the contiguous publication prefix.

Preparation retains the verified final locations for publication. The Exoware
API stages presence rows with the immutable data. Visibility remains gated by
the corresponding published watermark.

Different blocks may persist out of order. One coordinator publishes only the
complete contiguous prefix. Its atomic barrier contains both QMDB watermarks
and one height-to-digest publication target for every newly covered height.
Only one barrier is in flight. A later block cannot publish across an earlier
incomplete block, even if its data has already committed.

Transient and ambiguous failures repeat the same deterministic writes. Each
Store commit retries for at most 8 attempts and 60 seconds. After that the
indexer task fails and the validator exits. The restarted process replays from
the durable queue. Store request encoding and compression run off the async
executor. QMDB preparation uses a separate publisher CPU pool. The ignored
`large_block_data_uploads_with_bounded_requests` test uploads a 32 MiB proposal's
SQL and QMDB rows through the real simulator transport.

Simplex stores the full encoded block as one value. The Store's value limit
must also cover that block. The pinned Store server and simulator default to a
32 MiB value limit. The deploy CLI defaults to 8 MiB proposals and `deploy.sh`
selects 16 MiB, so both fit under that limit.

## Completion, replay, and cleanup

An upload completes only after its SQL and both QMDB data sets are durable, its
publication barrier has succeeded, and its full block is persisted. When the
payload carries a finalization certificate, it is persisted in the same Store
commit as the block. Publication targets and barriers do not
depend on the certificate. Unrelated consensus observer events do not authorize
queue completion.

Acknowledgements advance across the fully completed contiguous queue prefix.
Acknowledgement alone does not permit payload deletion because it is not a
durable restart boundary. Once a whole record section completes, the consumer
syncs its receipt and queue, prunes the section, and then deletes its payloads
inline on a best-effort basis. Startup removes orphan payloads left by
interrupted writes or failed deletions.

On restart:

1. Open the record, payload, and receipt partitions.
2. Check record height continuity and payload presence.
3. Recover the capture boundary from the queue tail and receipt in memory.
   Reject a contradictory or impossibly advanced receipt.
4. Replay every retained record through its recorded encoders.
5. Repeat immutable data, block, certificate, and barrier writes as necessary.
6. Acknowledge and prune only the complete contiguous prefix.

A receipt can legitimately remain after all records have pruned. Remote
watermarks never determine which local records to skip. The queue is a
publication journal, so remote data loss after pruning requires a separate
reindex operation.

## Reader contract

The publication target binds a height to its block digest. Its observed Store
sequence is a minimum visibility floor for subsequent reads. It is not a
snapshot ceiling, and a service may observe later rows.

Readers verify the target's certificate and block digest, use the certified
QMDB roots and boundaries, and pass the floor through Store, SQL, Simplex, and
QMDB requests. A metadata row appearing early does not establish publication.
A lagging service or unpublished QMDB tip remains retryable.

`tx_meta` contains the digest, QMDB location, containing height, and signed
transaction bytes. Rust lookups read the immutable transaction row, require the
publication target at its height, and check the target's block digest at that
target's Store floor. There is no separate transaction-proof metadata table.

`account_meta` is append-only with key `(account, qmdb_location)`. Historical
account reads select the latest location below the certified state boundary.
The minimum Store sequence alone cannot select historical account state.

Explorer subscribes to publication targets and yields every covered height in a
Store frame. A separate SQL stream caches block metadata ahead of publication.
Display still requires matching publication sequence and digest checks, with
point queries covering cache misses. Proof inputs can load concurrently, and
account-page rows share a certificate instead of refreshing it per row. A proof
for a height without a certificate cannot complete. The Explorer cannot yet
tell a missing certificate apart from one whose Simplex upload has not landed,
so it keeps retrying that proof.

## Deployment and observability

Fresh deployments require empty queue partitions and fresh state QMDB,
transaction QMDB, and publication-target namespaces. A single owning publisher
controls the namespace pair. When nothing was ever captured, startup checks the
namespaces before the engine starts, so the check precedes the first capture.
Restarted queues can safely reuse their existing remote namespaces.

An indexer must apply every finalized block from genesis. Configuration rejects
an indexer combined with peer `StateSync`. Normal validator state sync remains
available for nodes that do not index.

The deploy CLI exposes indexer runtime threads, publisher CPU threads, and
optional indexer instance sizing. The generated YAML sets upload concurrency
and the upload byte budget. The configured amplification estimate needs
validation under representative load.

The publisher records preparation timings for queue wait, expansion, staging,
and chunking, plus a paired CPU histogram for the preparation thread. It also
records persistence, publication wait, and finalization-to-publication
latency. The chunks-per-block histogram includes data chunks from successfully
persisted blocks and excludes barriers.

Store commit duration, batch rows, and encoded bytes share a `kind` label with
`chunk`, `barrier`, and `simplex` values. Each records one sample per completed
logical commit, including failures. Duration includes retry attempts and backoff.
Encoded bytes measure the uncompressed protobuf request, including physical keys.

Finalization-to-publication latency starts at the finalization timestamp stored
in the queue and ends when the contiguous QMDB and SQL publication barrier
completes. It includes queue waiting across restarts. It uses wall time and clamps
negative values to zero if the clock moves backwards. It does not include waiting
for Simplex artifacts or Explorer observation.

The validator records queue read, queue sync, record enqueue, and admission wait
latencies.

## Validation

Use `just test`, `just lint`, and `just build` for the Rust workspace. Run
`just explorer-test` and `just explorer-build` for the Explorer. Run the large
Store upload separately because constructing its signed transactions is costly.

```sh
just test --run-ignored only -E 'test(large_block_data_uploads_with_bounded_requests)'
```

Regression coverage must establish:

- Exact artifact capture and deterministic queue encoding.
- Rejection of invalid replay inputs, discontinuities, and contradictory receipts.
- Recovery around payload persistence, record commit, acknowledgement, and pruning.
- Publication barriers that never cross an incomplete prefix.
- Completion waiting for both data publication and Simplex artifacts.
- Payloads and Simplex uploads for heights without a finalization certificate.
- Retry and cancellation behavior when a worker or service fails.
- Published-height reads that preserve sequence, digest, and root bindings.
- Multi-height subscriptions, metadata catch-up, and bounded proof retries.

Deployment acceptance additionally requires backlog catch-up, restart, and
request-size measurements at the intended proposal size. Confirm that memory
plateaus, the acknowledgement floor advances, and publication remains ordered
while uploads finish out of order. Local unit coverage does not establish those
load-dependent limits by itself.
