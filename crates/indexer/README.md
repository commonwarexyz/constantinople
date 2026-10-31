# constantinople-indexer

Publishes consensus artifacts from secondary (non-voting) Constantinople
validators into an [exoware](https://exoware.xyz) store via
[`exoware-sdk::StoreClient`](https://docs.rs/exoware-sdk).

The validator-side indexer is **publish-only**. Querying is served by the
`chain-indexer` Store, by the
[`exoware-sql`](https://docs.rs/exoware-sql) SQL server for metadata tables,
and by `qmdb-indexer` for QMDB operation-log proofs and combined explorer reads.

## Storage paths

Constantinople stores every finalized block across complementary surfaces so
low-latency UI consumers and detailed-evidence consumers can each pick the API
that fits.

| Path | Surface | Used by |
| ---- | ------- | ------- |
| **Simplex block storage** | certified headers, `{ header, body }` blocks by digest, finalization indexes | Tools that need verifiable block headers, optional full block bodies, and certified height/latest reads through [`IndexerClient`](src/client.rs). |
| **Metadata and lookup storage** (SQL) | `block_meta`, `tx_meta`, `tx_activity`, `account_meta` | The explorer ([`explorer/`](../../explorer)), [`IndexerClient`](src/client.rs), and any other consumer that wants finalized block streams, transaction bodies/proof locations, account activity, or account proof locations without paying full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x00`. Transaction-hash operations under Store prefix `0x01`. | `qmdb-indexer` read APIs. `/state` serves account-state operation ranges. `/transactions` serves transaction-hash operation ranges and proofs. |
| **Simplex proof artifacts** | `exoware-simplex` finalization rows in the shared Store | The explorer and proof clients that need browser-verifiable finalization certificates. Common homepage/header reads do not fetch block bodies. |
| **Provable targets** | Height-ordered block digests under Store prefix `0x04` | Proof clients that need the newest finalized block covered by both QMDB publication boundaries. |

All paths use the same exoware Store service. The owning secondary prepares the
SQL rows and authenticated QMDB ranges for each finalized block, then commits
the resulting data in byte-bounded Store requests. Once a contiguous prefix of blocks has completed,
one publication barrier advances both QMDB watermarks and publishes the
height-to-digest targets for that prefix. Simplex block and certificate
artifacts use separate Store commits, but the durable queue entry remains
unacknowledged until both publication paths complete. QMDB uses Store prefixes
`0x00` and `0x01`.
SQL table and index prefixes are owned by
[`exoware-sql`'s `KvSchema`][kvschema].
The current SQL table-prefix allocation is:

| SQL table | Table prefix | Secondary indexes |
| --------- | ------------ | ----------------- |
| `block_meta` | `0x0` | none |
| `tx_meta` | `0x1` | none |
| `tx_activity` | `0x2` | none |
| `account_meta` | `0x3` | none |

`exoware-sql` expands those table prefixes into its Store key layout. Every
table is append-only. Store keys are immutable, so
no table may rewrite an existing key with a different value. `account_meta` is
keyed by `(account, qmdb_location)` with one row per account-state QMDB
operation, and proof readers take the highest location below the certified
state boundary for an account. Each finalized transaction adds one `tx_meta`
row and one `tx_activity` row per distinct side to the bulk commit. The bulk
commit bounds indexer throughput, so a per-transaction row is only added when
readers cannot derive the same information elsewhere.

The digest-keyed `tx_meta` row contract is:

| Column | Type | Nullability | Purpose |
| ------ | ---- | ----------- | ------- |
| `tx_digest` | fixed-size binary with 32 bytes | non-null | Transaction digest and primary key. |
| `qmdb_location` | unsigned 64-bit integer | non-null | Transaction-hash QMDB append location. |
| `body` | binary | non-null | Encoded signed transaction bytes. |
| `height` | unsigned 64-bit integer | non-null | Finalized block height containing the transaction. |

A transaction proof needs the finalized height that contains the transaction
and its QMDB location. `tx_meta` carries both, so a digest lookup is one point
read. Each `tx_activity` row also carries its transaction's `qmdb_location`.
Combined account reads use those locations for one multi-proof and fetch the
signed transaction bodies with a batch of digest-keyed `tx_meta` lookups.

Proofs become queryable once a grouped publication barrier covers the upload
that carried the transaction. The publisher writes append-only publication
targets in the same Store batch that establishes coverage in both QMDB
families. Their big-endian height keys make one reverse range read return the
newest covered block digest.

The explorer homepage uses that range read to initialize or recover its direct
Store subscription. Each target update includes the atomic Store batch
sequence. Combined explorer reads select a certified target covered by the
publication boundary, then use its sequence as the minimum visibility floor
for related SQL, Simplex, and QMDB reads. The certificate's digest, roots, and
tips identify the snapshot independently of that floor.

Simplex is the canonical block/header store. Blocks are available by digest
without requiring a height certificate. Height/latest reads start from a
finalization certificate, verify the commitment/header relationship, and fetch
the full body only when requested. A height finalized through a descendant
certificate, or backfilled after downtime, may have no certificate available at
capture. Combined explorer reads assemble a descendant certificate and the
parent-header chain using batched SQL digest lookups. The browser verifies
every link and proves the requested transactions against the certified QMDB
root. Missing proof inputs remain retryable while their uploads catch up.

[kvschema]: https://docs.rs/exoware-sql/latest/exoware_sql/struct.KvSchema.html

## Crate contents

- [`sql_schema::build_meta_schema`](src/sql_schema.rs) — the canonical
  source of truth for the live `block_meta`, `tx_meta`, `tx_activity`, and
  `account_meta` table layouts. The explorer's column-name strings live here
  too, so a schema change is a one-place edit.
- A [`CertificateReporter`](src/publisher/certificate.rs) that uploads each
  finalized block by digest as `exoware-simplex` proof artifacts in the shared
  Store, together with its finalization certificate when one was observed.
- A [`Publisher`](src/publisher/qmdb.rs) that runs from the finalized hook
  on the single owning secondary. It commits SQL and authenticated QMDB data,
  then publishes only the contiguous completed prefix through one barrier.
- [`IndexerClient`](src/client.rs) is a typed read wrapper over Simplex block
  storage and SQL transaction lookup rows. Digest lookups combine `tx_meta`
  with `block_meta` and a publication target to coordinate read visibility.
  `TransactionMetadata` returns the index's claimed height and QMDB location
  as untrusted lookup hints, together with signed transaction bytes whose body
  hashes to the requested digest. It does not verify the signature or finalized
  inclusion. Callers establish inclusion with a QMDB proof against a root from
  a verified finalized header. Establishing the exact inclusion height also
  requires authenticating that the location belongs to that block's new appends.
  Latest-finalized-height is derived from the Simplex finalization height index.
- `[[bin]] chain-indexer` requires `--features chain-indexer`. It wraps
  `exoware_simulator::server::run` for local development and deployer-managed remote bundles.
- `[[bin]] metadata-indexer` — thin wrapper that registers
  [`build_meta_schema`](src/sql_schema.rs) onto an
  [`exoware_sql::SqlServer`](https://docs.rs/exoware-sql/latest/exoware_sql/struct.SqlServer.html)
  so the explorer can reach the `sql.v1.Service` `Subscribe` RPC.
- `[[bin]] qmdb-indexer` — QMDB Connect facade over the same Store. It mounts
  account-state operation logs at `/state` and transaction-hash operation logs
  at `/transactions`, alongside the combined reads below.

## Combined explorer reads

These GET routes return certificates and raw QMDB proofs for independent client
verification. They share the QMDB service's CORS configuration.

| Route | Parameters | Result |
| ----- | ---------- | ------ |
| `/explorer/accounts/{account}` | 32-byte hex account; optional `mode=all\|sent\|received`, 24-byte hex `cursor`, paired `at` height and `digest`, or `activity=false` | Account update proof when indexed, plus up to ten transactions under one certified snapshot. |
| `/explorer/blocks/{height}` | Positive height; optional decimal `offset` | Up to 50 consecutive transactions, with a certificate and ancestry proving the block's own transaction interval. |
| `/explorer/transactions/{digest}` | 32-byte hex transaction digest | One transaction with its exact inclusion height and proof. |

Block reads discover transaction digests from consecutive QMDB operations,
then fetch bodies through the digest primary key. A later certificate can cover
a block that has no certificate of its own. Account pagination supplies both the
snapshot height and digest to retain the same view while publication advances.

All-activity pages seek directly from the cursor and read at most 11 activity-index
rows. Sent and received filters use the existing primary index and may scan
additional history before filling a page, especially when matches are sparse.

Responses encode bytes as hex and 64-bit integers as decimal strings. The
limits are 4096 ancestry headers, 1 MiB per proof, and 8 MiB per response.
Malformed requests return 400, temporarily unavailable publication or evidence
returns 503, invalid stored evidence returns 500, and work exceeding the
supported bounds returns 422.
Account proofs establish historical membership, and a missing update is not a
nonexistence proof. Account transaction lists carry membership proofs for their
returned rows without a claim of completeness.

## Back-pressure model

The durable queue and authenticated publication contract is specified in
[`DURABLE_QUEUE.md`](DURABLE_QUEUE.md).

The application captures owned authenticated range artifacts before applying a
winning batch. The finalized hook combines those artifacts with the finalized
block and its finalization certificate when one was observed, syncs the encoded
entry as one payload blob per block, then commits a small queue record before
returning. The payload starts with a magic number and a format version, and
unsupported versions are rejected before replay. This schema requires a fresh
index from genesis.

The background uploader derives SQL rows and authenticated QMDB writes from the
queue entry. Uploads may complete concurrently, but publication barriers and
queue acknowledgements advance only through the contiguous completed prefix.
This keeps SQL-row encoding off the finalized application path while making
recovery independent from local database pruning.

QMDB and SQL data requests are limited to 3.75 MiB (3,932,160 encoded bytes) and
65,536 rows. Up to 64 chunks per block can upload concurrently. This permits one
wave for blocks with at most 64 chunks, subject to shared runtime and Store
capacity. The byte ceiling across those requests is 240 MiB per block. This
excludes request overhead and other copies. Simplex full-block uploads use a
separate request path.

Each Store Put sends one unary protobuf request. All rows in that request form
one atomic write and receive one Store sequence number. Request splitting above
creates separate writes.

Preparation materializes the block's SQL and QMDB rows before uploads start.
The SDK accepts a complete `StoreWriteBatch` and encodes and compresses the full
request on each attempt. Preparation and transmission do not overlap, and the
request path does not bound total preparation memory.

Remote Store commits retry the fully staged `StoreWriteBatch` with capped
exponential backoff. Retries resend the complete logical request. Retryable
failures have no attempt cap or overall deadline. Each writer request retains
its 30-second timeout. Permanent errors fail the indexer task. Publication
barriers advance only after all data requests have succeeded.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html

## Tracing finalized uploads

The owning secondary exports these spans through the validator's existing
OpenTelemetry pipeline. Set the deployer's `--traces` sampling rate above zero
and keep the `info` log level enabled. `deploy.sh` configures `--traces 1`. In Grafana
Explore, select Tempo and search by block height with
[TraceQL](https://grafana.com/docs/tempo/latest/traceql/construct-traceql-queries/):

```traceql
{ span.height = 12345 }
```

Add `&& resource.service.name = "<secondary public key>"` inside the braces to
restrict the search to one secondary. Heights are numeric span attributes.

Each `indexer.block` trace starts at the finalized hook and remains open through
durable queue pruning and payload deletion. Its fields include `height`,
`block_digest`, queue `position`, `payload_bytes`, and `outcome`.
Child spans expose these stages:

| Stage | Spans and timing |
| ----- | ---------------- |
| Capture and enqueue | Receipt lock, artifact validation, payload encoding, checksum, file writes and sync, and durable queue enqueue. `indexer.queue.enqueue_to_read` includes enqueue persistence and time until the consumer reads the record. |
| Admission | Memory admission, payload read and decode, and waiting for the ordered admission turn. |
| QMDB and SQL preparation | `indexer.qmdb.prepare.*` separates authenticated state and transaction preparation, metadata construction, transaction and account rows, SQL encoding and staging, QMDB staging, and request chunking. Scheduling waits are separate spans. |
| Simplex preparation | `indexer.simplex.*` separates queue waits, full body encoding, row preparation and staging, and persistence. |
| Store uploads | Each `indexer.qmdb.chunk` records its index, chunk count, rows, and encoded bytes. Concurrent chunks appear as sibling spans. `store_commit` contains individual `store_put_attempt` spans and retry backoffs. Attempts include SDK request encoding, compression, and network time. |
| Publication and deletion | Per-block spans cover the publication wait, the wait for the record section to prune, and payload deletion. |

Grouped publication barriers and queue pruning cover multiple blocks. They carry
height ranges and span links to the contributing block traces. Each block also
has its own wait spans. Queue storage prunes complete sections of 16 records,
so a block can wait for later blocks after its uploads finish.

Durations measure wall time. They can include scheduling or parallel CPU work
and are not CPU profiles. Completed child spans can appear before the root
exports at deletion. Search by height to find these partial traces.

Trace context is kept in memory without changing durable queue records. After a
restart, replay starts a new trace with `origin = "replay"`. The enqueue context
registry retains at most 4096 blocks. Older contexts close with
`outcome = "context_evicted"`, and their eventual uploads start a new trace with
`origin = "continuation"`. Search by height to correlate these traces.
