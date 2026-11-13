# constantinople-indexer

Publishes consensus artifacts from secondary (non-voting) Constantinople
validators into an [exoware](https://exoware.xyz) store via
[`exoware-sdk::StoreClient`](https://docs.rs/exoware-sdk).

The validator-side indexer is **publish-only**. `chain-indexer` serves the
Store. `explorer-indexer` reads that Store with the SQL and QMDB libraries and
serves the explorer's ConnectRPC API, including transaction submission through a
configured relayer. The browser needs only this application endpoint and its
committee verification material.

## Storage paths

Constantinople stores every finalized block across complementary surfaces so
low-latency UI consumers and detailed-evidence consumers can each pick the API
that fits.

| Path | Surface | Used by |
| ---- | ------- | ------- |
| **Simplex block storage** | certified headers, `{ header, body }` blocks by digest, finalization indexes | Tools that need verifiable block headers, optional full block bodies, and certified height/latest reads through [`IndexerClient`](src/client.rs). |
| **Metadata and lookup storage** (SQL) | `block_meta`, `tx_meta`, `tx_activity`, `account_meta` | The explorer ([`explorer/`](../../explorer)), [`IndexerClient`](src/client.rs), and any other consumer that wants finalized block streams, transaction bodies/proof locations, account activity, or account proof locations without paying full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x00`. Transaction-hash operations under Store prefix `0x01`. | `explorer-indexer` reads these logs to assemble account, block, and transaction proofs. |
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
row and one `tx_activity` row per distinct participating account to the bulk commit.
Activity rows are keyed by `(account, account_index)`, where the index is
authenticated by the transaction-history append. A self-transfer consumes one
account index and produces one sender activity row. The bulk
commit bounds indexer throughput, so a per-transaction row is only added when
readers cannot derive the same information elsewhere.

The digest-keyed `tx_meta` row contract is:

| Column | Type | Nullability | Purpose |
| ------ | ---- | ----------- | ------- |
| `tx_digest` | fixed-size binary with 32 bytes | non-null | Transaction digest and primary key. |
| `qmdb_location` | unsigned 64-bit integer | non-null | Transaction-history QMDB append location. |
| `body` | binary | non-null | Encoded signed transaction bytes. |
| `height` | unsigned 64-bit integer | non-null | Finalized block height containing the transaction. |
| `sender_index` | unsigned 64-bit integer | non-null | Sender history index from the captured append. |
| `recipient_index` | unsigned 64-bit integer | non-null | Recipient history index from the captured append. |

A transaction proof needs the finalized height that contains the transaction
and its QMDB location. `tx_meta` carries both, so a digest lookup is one point
read. Each `tx_activity` row also carries its transaction's `qmdb_location`.
Combined account reads use those locations for one multi-proof and fetch the
signed transaction bodies with a batch of digest-keyed `tx_meta` lookups.

Transaction-history appends contain the message digest followed by two
big-endian `u64` indices. With SHA-256 this is a 48-byte value. Account values
contain balance, nonce base, nonce bitmap, and transaction count, each encoded
as a big-endian `u64`, for 32 bytes. The publisher indexes the captured values;
it does not reconstruct authenticated indices from SQL.

Account pages bind a retained account update to its inclusion block through
parent headers and the block's state append interval. The account proof's
`write_height` describes that inclusion; floor copies can include an unchanged
value in a later block. It does not establish the latest value at the certificate.
The authenticated account count fixes a complete history interval. The first
page ends at that count; every page returns exactly the indices
`[max(0, end - 10), end)` in descending order. A next cursor is the eight-byte
big-endian lower endpoint and exists only when that endpoint is nonzero.
Subsequent requests pin `at`, `digest`, and `account_location` from the first
response.
Missing account evidence means unknown, rather than a proven empty history.

The transaction proof uses the same certified root as the account response,
and every transaction must precede the account's inclusion block commit.
Historical transaction locations below the transaction inactivity floor remain
valid. Account state operations must remain inside the certified state range.
Account inclusion ancestry has the same 4096-header bound as block ancestry.
These encoding and SQL schema changes require a fresh spike Store; they do not
migrate an existing deployment.

Proofs become queryable once a grouped publication barrier covers the upload
that carried the transaction. The publisher writes append-only publication
targets in the same Store batch that establishes coverage in both QMDB
families. Their big-endian height keys make one reverse range read return the
newest covered block digest.

The explorer server uses bounded height ranges to serve its block stream.
Each target read supplies a Store sequence floor for the corresponding SQL
summary. Combined explorer reads select a certified target covered by the
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

- [`sql_schema::build_meta_schema`](src/sql_schema.rs) is the canonical
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
- `[[bin]] explorer-indexer` serves certified block ancestry, indexed search,
  transaction submission, and the combined proof reads below. SQL, QMDB,
  and Store protocols remain internal to the service.

## Explorer service

Run `explorer-indexer --store-url http://127.0.0.1:8090
--relayer-url http://127.0.0.1:8080`. It listens on `0.0.0.0:8092` by default.
`--host`, `--port`, and `--metrics-port` configure its listeners. `/health`
and `/ready` report successful startup; `/metrics` shares the application
listener unless a separate metrics port is configured.

Deployer mode accepts `--hosts hosts.yaml --config config.yaml` with:

```yaml
port: 8092
metrics_port: 9090
store_url: http://chain-indexer:8090
api_key: store-read-key
relayer_url: http://relayer:8080
```

Named HTTP hosts in both service URLs resolve through the hosts file. A CLI
`--store-url` override drops the YAML Store credential. `relayer_url` is
optional; submission returns `unavailable` without it. The Store key is used
only for Store requests.

The service is `constantinople.explorer.v1.ExplorerService`. Its authoritative
schema is [`explorer.proto`](proto/constantinople/explorer/v1/explorer.proto).
Rust bindings are generated during the build with `connectrpc-build`; `protoc`
must be installed. Browser clients use generated TypeScript bindings.

| Method | Request | Result |
| ------ | ------- | ------ |
| `GetAccount` | 32-byte account; optional 8-byte exclusive-end cursor; paired snapshot height/digest and account location for continuation; activity flag | Historical account update proof, inclusion ancestry, and an exact complete page of up to fifty transactions. |
| `GetBlock` | Positive height and optional offset | Up to 50 consecutive transactions, with a certificate and ancestry proving the block's own transaction interval. |
| `GetTransaction` | 32-byte transaction digest | One transaction with its exact inclusion height and proof. |
| `Search` | One 32-byte identity | One indexed account or transaction navigation hint. |
| `WatchBlocks` | Optional verified height to resume after | A server stream of published certificates and encoded ancestor headers. |
| `SubmitTransaction` | Encoded transaction batch | A complete relayer reply or explicit ambiguous outcome. |

A new `WatchBlocks` call without `after` returns the newest published certificate
and its block's parent header, when present. An explicit `after` returns a newer
certificate and every ancestor through that previously verified height. Clients
verify the certificate and parent links, require the final overlap digest to
match their retained digest, then publish all new rows together. `after = 0`
includes ancestry through block 1; no genesis header is required. The sequence
number records Store visibility and is not an authenticated chain fact.

The server prefers the newest certificate within the next 64 heights. If none
exists there, it selects the nearest later certificate, allowing sparse
certification to cover multiple blocks. A gap exceeding 4096 heights returns
`resource_exhausted`; it never resets the cursor. Encoded headers are limited to
512 bytes each, certificates to 16 KiB, and each response to 3 MiB. SQL supplies
only header lookup hints under the publication sequence floor. Clients derive
block counts and proposal timestamps from authenticated headers. Caught-up
streams poll every 250 ms; each read attempt times out after 10 seconds. An
upstream failure ends the stream, and dropping the response cancels pending
reads.

`Search` returns `invalid_argument` for a malformed identity, `not_found` for no
indexed match, and `unavailable` for transient Store failures. Search results
are navigation hints; destination views verify their certificates and proofs.

`SubmitTransaction` forwards exactly one opaque batch to the configured relayer's
`/transactions` endpoint, without redirects or retries. A complete upstream reply
retains its HTTP status, body, and content type, and recognized outcomes have typed
fields. A finalization report for a single transaction may include transaction evidence
hex-encoded. It is forwarded unverified as a typed `ProofBundle` when it decodes, is at
most 16 KiB, and fits the 64 KiB reply bound together with the upstream body. Evidence that
fails these checks is omitted from an otherwise unchanged report.
An incomplete reply or transport failure carries an ambiguous outcome,
because the transaction may have reached the relayer. Batch size is limited to 4 MiB plus
the five-byte batch prefix, and upstream replies to 64 KiB. The transport bounds
encoded request bodies and messages to 8 MiB and decoder element memory to 256 KiB.
Its 11-second deadline includes request receipt and handler execution. A transport
deadline or client cancellation may end the RPC before an ambiguous reply can be
sent; callers must treat that error as uncertain delivery too.

## Combined explorer reads

Proof responses use protobuf bytes for certificates, headers, transaction bodies,
and QMDB proofs; heights, locations, and sequence numbers use `uint64`. The schema
represents account cursors and block offsets separately. All application requests
use ConnectRPC; health, readiness, and metrics remain ordinary HTTP endpoints.

Block reads discover transaction digests from consecutive QMDB operations,
then fetch bodies through the digest primary key. A later certificate can cover
a block that has no certificate of its own. Account pagination supplies the
snapshot height, digest, and account operation location to retain the same
proven account version while publication advances.

Account pages seek directly over their authenticated index interval and read
at most fifty activity rows. Missing, reordered, or mismatched indices fail the
response. Every page is complete: a sent-only or received-only page could not prove
that it omitted nothing.

Limits are 4096 ancestry headers, 1 MiB per proof, and 8 MiB per protobuf
response. Malformed requests return `invalid_argument`, temporarily unavailable
publication or evidence returns `unavailable`, contradictory stored evidence
returns `internal`, and work exceeding supported bounds returns
`resource_exhausted`.

Account proofs establish historical membership, and a missing update is not a
nonexistence proof.

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
