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
| **Full storage** (KV) | `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H`, `FINALIZED`, `NOTARIZED` | Tools that need full `SignedTransaction` bodies or certificate artifacts through [`IndexerClient`](src/client.rs). |
| **Metadata stream** (SQL) | `block_meta(height, digest, tx_count, view, finalized_ts, transactions_root, transactions_tip)` and `tx_meta(height, index, tx_digest, qmdb_location)` | The explorer ([`explorer/`](../../explorer)), and any other consumer that wants a column-oriented finalized-block feed without paying the full-block decode cost. |
| **QMDB operation logs** | Account-state operations under Store prefix `0x8`; transaction-hash operations under Store prefix `0x9` | `qmdb-indexer` read APIs. `/state` serves account-state operation ranges; `/transactions` serves transaction-hash operation ranges and proofs. |

All paths share the same exoware [`StoreClient`] under the hood. In non-QMDB
mode, raw KV and SQL uploads run as separate background uploaders. In QMDB
mode, the owning secondary stages raw KV rows, SQL rows, and both QMDB row
families into one Store batch before acknowledging the finalized block.
The KV families are namespaced under
`reserved_bits=4, prefix=0x1..=0x6` (see [`src/keys.rs`](src/keys.rs));
the SQL tables use a disjoint prefix range
(`0x00..=0x0F`, declared in [`exoware-sql`'s `KvSchema`][kvschema]) so a
single store can host every index without collision.

[`StoreClient`]: https://docs.rs/exoware-sdk/latest/exoware_sdk/struct.StoreClient.html
[kvschema]: https://docs.rs/exoware-sql/latest/exoware_sql/struct.KvSchema.html

## Crate contents

- `KeyCodec` wrappers for the six KV artifact families (blocks,
  transactions, certificates, height/digest indexes).
- [`sql_schema::build_meta_schema`](src/sql_schema.rs) — the canonical
  source of truth for the `block_meta` and `tx_meta` table layouts. The
  explorer's column-name strings live here too, so a schema change is a
  one-place edit.
- A [`BlockReporter`](src/publisher/block.rs) that taps marshal
  `Update::Block` events and fans each finalized block out across raw KV and
  SQL uploaders when QMDB upload is disabled.
- A [`CertificateReporter`](src/publisher/certificate.rs) that taps
  simplex `Activity` events and uploads notarization / finalization
  certificates to the blocks KV store.
- A [`QmdbPublisher`](src/publisher/qmdb.rs) that runs from the finalized hook
  on the single QMDB-owning secondary and commits raw KV, SQL, account-state
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

Non-QMDB publishers offload network I/O to background tokio tasks. Marshal
back-pressures the engine on the still-held [`Exact`] acknowledgement: each
reporter clones the ack once per uploader, every uploader fulfills its clone
after its own put / flush succeeds, and the marshal waiter only resolves once
all clones have acknowledged.

The QMDB publisher runs after finalized database application and before prune.
It prepares QMDB rows concurrently, stages raw KV rows and SQL rows beside
them, commits one Store batch, then marks SQL and QMDB uploads persisted. Flush
errors retry indefinitely with a capped exponential backoff so a transient
store outage slows the engine down rather than dropping data.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html
