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
| **Metadata and lookup storage** (SQL) | `block_meta`, `tx_meta`, `tx_activity`, `account_meta` | The explorer ([`explorer/`](../../explorer)), [`IndexerClient`](src/client.rs), and any other consumer that wants finalized block streams, transaction bodies/proof locations, account activity, or latest account proof locations without paying full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x8`; transaction-hash operations under Store prefix `0x9` | `qmdb-indexer` read APIs. `/state` serves account-state operation ranges; `/transactions` serves transaction-hash operation ranges and proofs. |
| **Simplex proof artifacts** | `exoware-simplex` notarization/finalization rows in the shared Store | The explorer and proof clients that need browser-verifiable finalization certificates. Common homepage/header reads do not fetch block bodies. |

All paths share the same exoware [`StoreClient`] under the hood. The owning
secondary stages SQL rows and both QMDB row families into one Store batch from
the finalized hook; simplex block and certificate artifacts are published from
the same finalized path after data upload. QMDB uses Store prefixes `0x8` and
`0x9`; SQL table/index prefixes are owned by [`exoware-sql`'s `KvSchema`][kvschema].
The current SQL table-prefix allocation is:

| SQL table | Table prefix | Secondary indexes |
| --------- | ------------ | ----------------- |
| `block_meta` | `0x0` | none |
| `tx_meta` | `0x1` | `tx_meta_by_digest` |
| `tx_activity` | `0x2` | `tx_activity_by_role` |
| `account_meta` | `0x3` | none |

`exoware-sql` expands those table prefixes into its Store key layout: primary
rows reserve 5 high-order key bits (`table_prefix << 1`), while secondary index
rows reserve 9 high-order key bits (`table_prefix`, index-kind bit, and index
slot).

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
  on the single owning secondary and commits SQL, account-state QMDB, and
  transaction-hash QMDB rows in one Store batch.
- [`IndexerClient`](src/client.rs) — typed read wrapper over Simplex block
  storage and SQL transaction lookup rows. Latest-finalized-height is derived
  from the Simplex finalization height index.
- `[[bin]] chain-indexer` — thin wrapper around `exoware_simulator::server::run`
  for local development and deployer-managed remote bundles.
- `[[bin]] metadata-indexer` — thin wrapper that registers
  [`build_meta_schema`](src/sql_schema.rs) onto an
  [`exoware_sql::SqlServer`](https://docs.rs/exoware-sql/latest/exoware_sql/struct.SqlServer.html)
  so the explorer can reach the `store.sql.v1.Service` `Subscribe` RPC.
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

The background uploader derives the rest from that durable entry: SQL rows,
transaction-hash QMDB operations, account metadata rows, watermarks, and the
final Store batch. This keeps SQL-row encoding off the durable queue write path
while still making recovery independent from local database pruning.

Remote Store commits retry indefinitely with a capped exponential backoff using
the fully staged `StoreWriteBatch`, so a transient store outage stalls queued
upload progress rather than dropping data.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html
