# Indexer durable queue

The finalized queue records everything required to regenerate SQL, state QMDB,
transaction QMDB, and Simplex artifacts after a restart. The queue and its
capture receipt define local progress. Remote writer recovery is unnecessary.

This implementation starts a fresh index from genesis. Existing queue formats
and remote namespaces require a separate migration or reindex design.

## Dependencies

Rust uses the Commonware and Exoware 2026.9.0 releases from crates.io.
Exoware includes authenticated range preparation and Store, SQL, QMDB, and
Simplex read consistency.

Explorer pins the published SDK, SQL, QMDB, and Simplex npm packages to
2026.9.0. Installation does not require sibling checkouts.

## Capture and persistence

Commonware calls `Application::capture` with the winning merkleized batches and
readers before applying them. Constantinople retains the exact operation
vectors, range proofs, and pinned prefix nodes for both QMDBs. After successful
application, `Application::finalized` passes those artifacts to the queue
producer. Genesis, startup reconciliation, and state sync do not produce these
individual artifacts.

The producer retrieves the exact height finalization from the marshal archive
and verifies that it certifies the block commitment. It requires consecutive
heights and operation ranges. The first captured block is height one and both
ranges start at location one, after their authenticated genesis sentinels.

Each payload contains:

- Queue format, hasher, Merkle family, row layout, and operation codec identities.
- The metadata encoder version required for deterministic replay.
- The full block, exact finalization certificate, and finalized timestamp.
- Both operation ranges, including their exact encoded operations, proofs, and pins.

Payloads live in one blob per height. A small fixed-size queue record holds the
height, digest, range boundaries, payload length, and checksum. The producer
syncs the payload before committing its record. Consumer admission opens only
after that record is durable.

The queue tail is the capture receipt while records remain. The producer keeps
that receipt in memory for duplicate detection. Before pruning a completed
record section, the consumer syncs the last removed record's receipt to a
separate metadata partition. This preserves the capture boundary even when the
queue becomes empty and avoids a third sync for every captured block.

## Admission and ownership

Recovery scans fixed-size records and validates payload presence and lengths
without decoding all payloads. Payload reads and structured decoding start only
after byte admission. A concurrency limit bounds the number of active uploads
in addition to the estimated byte budget. An oversized item reserves the whole
budget and runs alone.

An `UploadReservation` owns the semaphore permit. Rust drops that permit on
success, failure, or cancellation. Its lifetime includes payload read, decode,
preparation, and data and Simplex persistence. It ends before ordered publication
and acknowledgement, so completed uploads behind a slow head do not retain
large allocations.

Captured operation vectors use `Arc`. Sharing an `Arc` retains the existing
allocation rather than copying the operations. The engine block also owns shared
block data, and queued artifacts borrow their proof inputs during preparation.

Payload reads can overlap, but a predecessor admission gate ensures the
publisher receives uploads in queue order. Completed tasks are reaped while the
next record waits for capacity. Queue read errors retry even if the producer
never enqueues another block.

## Authenticated preparation and publication

Preparation validates each range against its certified header root and emits
deterministic absolute Store rows. The exact range start comes from the captured
batch. A header's inactivity boundary does not identify that start.

The operation encodings, proof leaf count, pins, terminal commit, frozen codec
identities, and adjacent range boundaries must agree. Unsupported formats or
invalid artifacts fail the supervised indexer and remain unacknowledged.

Each publisher starts by emitting supplied pins, including after a restart in
the middle of the operation log. Once an upload's data requests are all durable,
admission records that later uploads can omit supplied pins. Those nodes come
from earlier admitted ranges in the same history. Some predecessors may still
be uploading, so publication must continue to wait for the fully durable
contiguous prefix. Node rows are retained without a pruning policy.

Each block stages its SQL rows and both QMDB ranges together. Data requests
use a 24 MiB encoded-byte budget and a 250,000-row cap. The SDK accounts for
physical keys and exact protobuf framing. The byte budget splits SQL-heavy
chunks to reduce encoding, compression, and transfer time. The row cap limits
the Store's serial per-row work independently of bytes. These are publisher
tuning budgets, not Store protocol limits.

Small batches remain one request. Larger batches commit with up to ten chunk
requests in flight per block so typical large blocks can upload their chunks
in one wave. The limit covers request encoding, compression, and retries.
Each active block has its own chunk slots. Upload admission still bounds active
blocks and their memory budget. Every chunk must finish durably before the
block can enter the contiguous publication prefix.

Preparation retains the verified final locations for publication. The Exoware
API stages presence rows with the immutable data. Visibility remains gated by
the corresponding published watermark.

Different blocks may persist out of order. One coordinator publishes only the
complete contiguous prefix. Its atomic barrier contains both QMDB watermarks
and one height-to-digest publication target for every newly covered height.
Only one barrier is in flight. A later block cannot publish across an earlier
incomplete block, even if its data has already committed.

Transient and ambiguous failures repeat the same deterministic writes. Store
request encoding and compression run off the async executor. QMDB preparation
uses a separate publisher CPU pool. The ignored
`large_block_data_uploads_with_bounded_requests` test uploads a 32 MiB proposal's
SQL and QMDB rows through the real simulator transport.

Simplex stores the full encoded block as one value. The Store's value limit
must also cover that block. The simulator's default 10 MiB value limit covers
the default 8 MiB proposals. Running 32 MiB proposals requires a Store configured
for larger values in addition to splitting the SQL and QMDB data requests.

## Completion, replay, and cleanup

An upload completes only after its SQL and both QMDB data sets are durable, its
publication barrier has succeeded, and its full block and exact finalization
certificate are persisted. The certificate upload waits for block persistence.
Unrelated consensus observer events do not authorize queue completion.

Acknowledgements advance across the fully completed contiguous queue prefix.
Acknowledgement alone does not permit payload deletion because it is not a
durable restart boundary. Once a whole record section completes, the consumer
syncs its receipt and queue, prunes the section, and submits its payloads to a
bounded cleanup worker. Cleanup retries storage failures. Startup removes orphan
payloads left by interrupted writes or cleanup.

On restart:

1. Open the record, payload, and receipt partitions.
2. Check record continuity, digests, ranges, and payload lengths.
3. Recover the capture boundary from the queue tail and receipt. Repair a receipt
   behind the tail and reject a contradictory or impossibly advanced receipt.
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

`tx_meta` contains the digest, QMDB location, and signed transaction bytes.
The containing height is derived from the preceding `block_meta` transaction
boundary. A secondary index on `transactions_tip` bounds that lookup to one
index entry, including for old transactions. Rust lookups first discover a
location and height as hints, then require the exact publication target and
repeat the metadata reads at its Store floor. There is no separate
transaction-proof metadata table.

`account_meta` is append-only with key `(account, qmdb_location)`. Historical
account reads select the latest location below the certified state boundary.
The minimum Store sequence alone cannot select historical account state.

Explorer subscribes to publication targets and yields every covered height in a
Store frame. A separate SQL stream caches block metadata ahead of publication.
Display still requires matching publication sequence and digest checks, with
point queries covering cache misses. Proof inputs can load concurrently, and
account-page rows share a certificate instead of refreshing it per row.

## Deployment and observability

Deploy the increased chunk concurrency only after the SQL and QMDB facades
use the SDK's raised response decode budgets and the Store enforces a
2,000,000-entry sequence cap with whole-PUT carryover. Concurrent PUTs can
coalesce into one Subscribe frame. The decoder updates and sequence cap must
be live before the publisher starts using the additional chunk slots.

Fresh deployments require empty queue partitions and fresh state QMDB,
transaction QMDB, and publication-target namespaces. A single owning publisher
controls the namespace pair. Initial namespace checks happen before the first
capture is accepted. Restarted queues can safely reuse their existing remote
namespaces.

An indexer must apply every finalized block from genesis. Configuration rejects
an indexer combined with peer `StateSync`. Normal validator state sync remains
available for nodes that do not index.

Deployment configuration exposes indexer runtime threads, publisher CPU threads,
upload concurrency, byte budget, and optional indexer instance sizing. The
configured amplification estimate needs validation under representative load.

The dashboard includes capture and acknowledgement lag, queue progress, capture
stage latency, queue record and payload read latency, preparation and persistence
latency, publication wait, Store commit retries and concurrency, chunks per block,
and upload memory amplification. Payload cleanup metrics expose delayed deletion
and disk reclamation costs.

Preparation has separate queue wait, expansion, staging, and chunking timings.
The wait starts when an upload enters the publisher and ends when preparation
starts executing. Expansion covers metadata rows and authenticated QMDB ranges.
Staging covers SQL preparation and Store rows. Preparation wall time includes
request splitting and excludes scheduling. Its paired CPU histogram measures
only the preparation thread, excluding Rayon workers. A failed CPU-clock read
logs a warning and omits that CPU sample without interrupting publication.

Preparation, commit, and finalization-to-publication histograms have roughly
25-percent bucket spacing from 50 ms through 2.5 seconds. Longer buckets retain
outage and recovery visibility. The chunks-per-block histogram and chunk counter
include data chunks from successfully persisted blocks and exclude barriers.

Store commit duration, batch rows, and encoded bytes share a `kind` label with
`chunk`, `barrier`, and `simplex` values. Each records one sample per completed
logical commit, including failures. Duration includes retry attempts and backoff.
Encoded bytes measure the uncompressed protobuf request, including physical keys.
Exact rows and bytes also appear on the commit span. They are observations rather
than labels so distinct batch sizes do not create additional time series.

Consumer admission metrics distinguish waiting for active-upload capacity from
the per-record wait for the byte budget. Decode scheduling and execution have
separate timers, followed by a predecessor-turn wait before publisher admission.
Payload open timers distinguish the write path from the read path. The write
timer starts before opening the blob, while the read timer includes its open and
length lookup. Recovery-only length probes do not enter these open histograms.

Finalization-to-publication latency starts at the finalization timestamp stored
in the queue and ends when the contiguous QMDB and SQL publication barrier
completes. It includes queue waiting across restarts. It uses wall time and clamps
negative values to zero if the clock moves backwards. It does not include waiting
for Simplex artifacts or Explorer observation.

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
- Completion waiting for both data publication and exact Simplex artifacts.
- Retry and cancellation behavior when a worker or service fails.
- Published-height reads that preserve sequence, digest, and root bindings.
- Multi-height subscriptions, metadata catch-up, and bounded proof retries.

Deployment acceptance additionally requires backlog catch-up, restart, and
request-size measurements at the intended proposal size. Confirm that memory
plateaus, the acknowledgement floor advances, and publication remains ordered
while uploads finish out of order. Local unit coverage does not establish those
load-dependent limits by itself.
