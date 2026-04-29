# constantinople-indexer

Publishes consensus artifacts from secondary (non-voting) Constantinople
validators into an [exoware](https://exoware.xyz) store via
[`exoware-sdk::StoreClient`](https://docs.rs/exoware-sdk).

The indexer is **publish-only**. Querying is served directly by the exoware
server (KV families) and by the
[`exoware-sql`](https://docs.rs/exoware-sql) SQL server (metadata tables).

## Two paths through exoware

Constantinople fans every finalized block out across two parallel
storage paths so that low-latency UI consumers and detailed-evidence
consumers can each pick the surface that fits.

| Path                | Surface                                          | Used by                                                  |
| ------------------- | ------------------------------------------------ | -------------------------------------------------------- |
| **Full storage** (KV)   | `BLOCK`, `BLOCK_BY_H`, `TX`, `TX_BY_H`, `FINALIZED`, `NOTARIZED` | Tools that need the full `SignedTransaction` body or a QMDB proof — fetched by digest through [`IndexerClient`](src/client.rs). |
| **Metadata stream** (SQL) | `block_meta(height, digest, tx_count, view, finalized_ts)` and `tx_meta(height, index, tx_digest)` | The explorer ([`explorer/`](../../explorer)), and any other consumer that wants a column-oriented "every finalized block" feed without paying the full-block decode cost. |

Both paths share the same exoware [`StoreClient`] under the hood — the SQL
publisher just speaks `BatchWriter::insert + flush().await` instead of raw
KV puts. The KV families are namespaced under
`reserved_bits=4, prefix=0x1..=0x6` (see [`src/keys.rs`](src/keys.rs));
the SQL tables use a disjoint prefix range
(`0x00..=0x0F`, declared in [`exoware-sql`'s `KvSchema`][kvschema]) so a
single store can host both without collision.

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
  `Update::Block` events and fans each finalized block out across all
  three uploader channels (blocks KV, transactions KV, SQL metadata).
- A [`CertificateReporter`](src/publisher/certificate.rs) that taps
  simplex `Activity` events and uploads notarization / finalization
  certificates to the blocks KV store.
- [`IndexerClient`](src/client.rs) — typed read wrapper over the two KV
  `StoreClient`s. The latest-finalized-height cursor is now derived from
  a backward range scan of `BLOCK_BY_H` (formerly stored in a redundant
  KV `META` family).
- `[[bin]] indexer` — thin wrapper around `exoware_simulator::server::run`
  for local development.
- `[[bin]] sql` — thin wrapper that registers
  [`build_meta_schema`](src/sql_schema.rs) onto an
  [`exoware_sql::SqlServer`](https://docs.rs/exoware-sql/latest/exoware_sql/struct.SqlServer.html)
  so the explorer can reach the `store.sql.v1.Service` `Subscribe` RPC.

## Back-pressure model

Both publishers offload network I/O to background tokio tasks via
[`dispatch_batch`](src/publisher/mod.rs). Marshal back-pressures the
engine on the still-held [`Exact`] acknowledgement: each reporter clones
the ack once per uploader, every uploader fulfills its clone after its
own put / flush succeeds, and the marshal waiter only resolves once all
clones have acknowledged. Flush errors retry indefinitely with a capped
exponential backoff so a transient store outage slows the engine down
rather than dropping data.

[`Exact`]: https://docs.rs/commonware-utils/latest/commonware_utils/acknowledgement/struct.Exact.html
