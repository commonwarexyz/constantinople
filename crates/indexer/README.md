# constantinople-indexer

Publishes consensus artifacts from secondary (non-voting) Constantinople
validators into an [exoware](https://exoware.xyz) store via
[`exoware-sdk::StoreClient`](https://docs.rs/exoware-sdk).

The validator-side indexer is **publish-only**. Querying is served by the
`chain-indexer` Store, by the
[`exoware-sql`](https://docs.rs/exoware-sql) SQL server for metadata tables,
and by `qmdb-indexer` for QMDB operation-log proofs.

## Storage paths

Constantinople stores every finalized block across complementary surfaces so
low-latency UI consumers and detailed-evidence consumers can each pick the API
that fits.

| Path | Surface | Used by |
| ---- | ------- | ------- |
| **Simplex block storage** | certified headers, `{ header, body }` blocks by digest, finalization indexes | Tools that need verifiable block headers, optional full block bodies, and certified height/latest reads through [`IndexerClient`](src/client.rs). |
| **Metadata and lookup storage** (SQL) | `block_meta`, `tx_meta`, `tx_activity`, `account_meta` | The explorer ([`explorer/`](../../explorer)), [`IndexerClient`](src/client.rs), and any other consumer that wants finalized block streams, transaction bodies/proof locations, account activity, or account proof locations without paying full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x8`; transaction-hash operations under Store prefix `0x9` | `qmdb-indexer` read APIs. `/state` serves account-state operation ranges; `/transactions` serves transaction-hash operation ranges and proofs. |
| **Simplex proof artifacts** | `exoware-simplex` notarization/finalization rows in the shared Store | The explorer and proof clients that need browser-verifiable finalization certificates. Common homepage/header reads do not fetch block bodies. |

All paths use the same exoware Store service. The owning secondary commits each
`block_meta` row through an ordered metadata lane. It commits transaction
lookup rows and both QMDB families through a bulk lane after that block's
metadata row is durable. Consumers may therefore observe a block summary
before its transaction and proof details. Simplex block and certificate
artifacts use separate Store commits. QMDB uses Store prefixes `0x8` and `0x9`.
SQL table and index prefixes are owned by
[`exoware-sql`'s `KvSchema`][kvschema].
The current SQL table-prefix allocation is:

| SQL table | Table prefix | Secondary indexes |
| --------- | ------------ | ----------------- |
| `block_meta` | `0x0` | none |
| `tx_meta` | `0x1` | none |
| `tx_activity` | `0x2` | none |
| `account_meta` | `0x3` | none |

`exoware-sql` expands those table prefixes into its Store key layout. There are
currently no secondary SQL index rows, so finalized-block SQL writes only add
primary table rows. Every table is append-only. Store keys are immutable, so
no table may rewrite an existing key with a different value. `account_meta` is
keyed by `(account, qmdb_location)` with one row per account-state QMDB
operation, and readers take the highest location for an account. Each
finalized transaction adds exactly three rows to the bulk commit: one `tx_meta`
row and one `tx_activity` row per side. The bulk commit is what bounds indexer
throughput, so a per-transaction row is only added when readers cannot derive
the same information elsewhere.

The digest-keyed `tx_meta` row contract is:

| Column | Type | Nullability | Purpose |
| ------ | ---- | ----------- | ------- |
| `tx_digest` | fixed-size binary with 32 bytes | non-null | Transaction digest and primary key. |
| `qmdb_location` | unsigned 64-bit integer | non-null | Transaction-hash QMDB append location. |
| `body` | binary | non-null | Encoded signed transaction bytes. |

A transaction proof needs the finalized height that contains the transaction.
Readers derive it from `block_meta`: the containing block is the first row
whose `transactions_tip` exceeds `tx_meta.qmdb_location`. `block_meta` holds
one row per block, so the lookup is a small range query rather than a
per-transaction table.

Proofs become queryable once an inline or later grouped watermark covers the
upload that carried the transaction.

Simplex is the canonical block/header store. Blocks are available by digest
without requiring a height certificate; height/latest reads start from a
finalization certificate, verify the commitment/header relationship, and fetch
the full body only when requested.

[`StoreClient`]: https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClient.html
[kvschema]: https://docs.rs/exoware-sql/latest/exoware_sql/struct.KvSchema.html

## Crate contents

- [`sql_schema::build_meta_schema`](src/sql_schema.rs) — the canonical
  source of truth for the live `block_meta`, `tx_meta`, `tx_activity`, and
  `account_meta` table layouts. The explorer's column-name strings live here
  too, so a schema change is a one-place edit.
- A [`CertificateReporter`](src/publisher/certificate.rs) that taps
  simplex `Activity` events, uploads full blocks by digest, pairs certificates
  with finalized headers, and uploads `exoware-simplex` proof artifacts to the
  shared Store.
- A [`Publisher`](src/publisher/qmdb.rs) that runs from the finalized hook
  on the single owning secondary. It commits `block_meta` first, then commits
  transaction lookup rows and both QMDB families through the gated bulk lane.
- [`IndexerClient`](src/client.rs) — typed read wrapper over Simplex block
  storage and SQL transaction lookup rows. Digest lookups combine `tx_meta`
  with `block_meta` and expose the finalized height, QMDB location, and
  signed body through `TransactionMetadata`.
  Latest-finalized-height is derived from the Simplex finalization height index.
- `[[bin]] chain-indexer` — thin wrapper around `exoware_simulator::server::run`
  for local development and deployer-managed remote bundles.
- `[[bin]] metadata-indexer` — thin wrapper that registers
  [`build_meta_schema`](src/sql_schema.rs) onto an
  [`exoware_sql::SqlServer`](https://docs.rs/exoware-sql/latest/exoware_sql/struct.SqlServer.html)
  so the explorer can reach the `sql.v1.Service` `Subscribe` RPC.
- `[[bin]] qmdb-indexer` — QMDB Connect facade over the same Store. It mounts
  account-state operation logs at `/state` and transaction-hash operation logs
  at `/transactions`.

## Back-pressure model

The finalized hook runs after finalized database application and before prune.
It writes a durable finalized upload queue entry before returning to consensus.
That entry is deliberately the pre-prune boundary: it contains the finalized
block, finalized timestamp, QMDB writer start cursors, and the account-state delta
that must be read while the local QMDB can still prove the finalized range.
The writer end cursors are derived from the block header and start cursors.

The background uploader derives both persistence lanes from that durable
entry. The metadata lane commits `block_meta` in queue order. The bulk lane
derives transaction lookup rows, QMDB operations, account metadata rows, and
watermarks. A bulk Store commit waits for its block's metadata signal. This
keeps SQL-row encoding off the durable queue write path while still making
recovery independent from local database pruning.

Remote Store commits retry indefinitely with a capped exponential backoff using
the fully staged `StoreWriteBatch`, so a transient store outage stalls queued
upload progress rather than dropping data.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html
