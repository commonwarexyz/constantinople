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
| **Full storage** (KV) | `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H` | Tools that need full `SignedTransaction` bodies through [`IndexerClient`](src/client.rs). |
| **Metadata stream** (SQL) | `block_meta(height, digest, tx_count, transactions_root, transactions_tip, view, finalized_ts)` | The explorer ([`explorer/`](../../explorer)), and any other consumer that wants a column-oriented finalized-block feed without paying the full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x8`; transaction-hash operations under Store prefix `0x9` | `qmdb-indexer` read APIs. `/state` serves account-state operation ranges; `/transactions` serves transaction-hash operation ranges and proofs. |
| **Simplex artifacts** | `exoware-simplex` header and finalization indexes in the shared Store | The explorer and proof clients that need a browser-verifiable finalization certificate for a block. Full block and transaction reads still come from the KV path through [`IndexerClient`](src/client.rs). |

All paths share the same exoware [`StoreClient`] under the hood. The owning
secondary stages raw KV rows, SQL rows, and both QMDB row families into one
Store batch from the finalized hook; simplex artifacts are published from the
same finalized path after data upload. The active KV families are namespaced under
`reserved_bits=4, prefix=0x1,0x2,0x5,0x6` (see [`src/keys.rs`](src/keys.rs));
the SQL tables use a disjoint prefix range
(`0x00..=0x0F`, declared in [`exoware-sql`'s `KvSchema`][kvschema]) so a
single store can host every index without collision.

Simplex artifacts carry certified block payloads for proof verification, but
they are not the canonical block or transaction store and are not read by
[`IndexerClient`](src/client.rs).

[`StoreClient`]: https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClient.html
[kvschema]: https://docs.rs/exoware-sql/latest/exoware_sql/struct.KvSchema.html

## Crate contents

- `KeyCodec` wrappers for the raw KV artifact families (blocks,
  transactions, and height/digest indexes).
- [`sql_schema::build_meta_schema`](src/sql_schema.rs) — the canonical
  source of truth for the live `block_meta` table layout and the legacy
  queryable `tx_meta` table. The explorer's column-name strings live here too,
  so a schema change is a one-place edit.
- A [`CertificateReporter`](src/publisher/certificate.rs) that taps
  simplex `Activity` events, pairs certificates with finalized blocks, and
  uploads `exoware-simplex` proof artifacts to the shared Store.
- A [`Publisher`](src/publisher/qmdb.rs) that runs from the finalized hook
  on the single owning secondary and commits raw KV, SQL, account-state
  QMDB, and transaction-hash QMDB rows in one Store batch.
- [`IndexerClient`](src/client.rs) — typed read wrapper over the two KV
  `StoreClient`s. The latest-finalized-height cursor is now derived from
  a backward range scan of `BLOCK_BY_H` (formerly stored in a redundant
  KV `META` family).
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

The background uploader derives the rest from that durable entry: raw KV rows,
SQL `block_meta` rows, transaction-hash QMDB operations, account lookup rows,
watermarks, and the final Store batch. This keeps SQL and raw-row encoding off
the durable queue write path while still making recovery independent from local
database pruning.

Remote Store commits retry indefinitely with a capped exponential backoff using
the fully staged `StoreWriteBatch`, so a transient store outage stalls queued
upload progress rather than dropping data.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html
