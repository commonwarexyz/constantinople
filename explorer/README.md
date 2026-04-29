# constantinople / explorer

A small React + Vite app that streams newly finalized blocks from the
constantinople indexer's SQL metadata path and renders them as they
arrive.

## What it does

The explorer opens a single `Subscribe` stream against
[`store.sql.v1.Service`][rpc] for the `block_meta` table. Every
delivered `SubscribeResponse` frame carries the rows from one atomic
ingest batch, and the indexer flushes once per finalized block, so most
frames decode to exactly one new block summary —
`(height, txCount, arrival time, sequence)`.

The schema column names (`height`, `tx_count`, …) come from
[`crates/indexer/src/sql_schema.rs`](../crates/indexer/src/sql_schema.rs),
which is the canonical source of truth for both the publisher and this
client.

[rpc]: https://github.com/exowarexyz/monorepo/blob/main/proto/store/v1/sql.proto

The UI renders a one-line block summary plus a multi-line ASCII
histogram showing tx-count-per-block over the last ~80 blocks so the
operator can see throughput scale at a glance. The histogram's y-axis
is auto-scaled to the peak in the visible window.

### Why SQL, not the raw KV stream?

The indexer publishes every finalized block to two parallel surfaces
(see [`crates/indexer/README.md`](../crates/indexer/README.md)):

- **Full storage (KV)** — `BLOCK`, `TX`, `BLOCK_BY_H`, `TX_BY_H`,
  `FINALIZED`, `NOTARIZED`. Use this path when you need the full
  `SignedTransaction` body or a QMDB proof; fetch by digest through
  the existing `StoreClient`. The default port for that store in
  local-deploy mode is `8090` (`VITE_INDEXER_URL`).
- **Metadata stream (SQL)** — `block_meta` / `tx_meta` tables on top
  of the same store. Cheap to subscribe to from the browser and
  already deduplicated to one row per block; this is what the live UI
  consumes.

A future drill-down feature ("click a row, see its transactions") would
combine both: subscribe via SQL for the live tail, then fetch a specific
tx body or QMDB proof from the KV store on demand.

## Configuration

| Env var             | Default                  | Notes                                          |
| ------------------- | ------------------------ | ---------------------------------------------- |
| `VITE_SQL_URL`      | `http://127.0.0.1:8091`  | The `exoware-sql` server. Matches the local-deploy `--sql-port` default. |
| `VITE_INDEXER_URL`  | _(unset by default)_     | The KV store. Forwarded by the local-deploy mprocs script for future drill-down; the current UI does not read it. |

The exoware Store and the SQL server both enable a permissive CORS
layer, so the dev server can talk to them cross-origin without a Vite
proxy.

## Local development

```sh
npm install
npm run dev
```

The dev server defaults to <http://localhost:5173>. To get live data,
point a secondary validator at the simulator and start the spammer:

```sh
cargo run -p constantinople-deploy -- generate \
    --validators 4 --secondaries 1 --output-dir local --spammer \
    local --indexer
mprocs ...   # the deploy job prints the full mprocs invocation
```

`local --indexer` automatically appends the simulator (`indexer` bin),
the SQL server (`sql` bin from `constantinople-indexer`), and this dev
server to the printed mprocs command list (see
[`bin/deploy/src/local.rs`](../bin/deploy/src/local.rs)).

## Build

```sh
npm run build
```

Outputs a static bundle to `dist/`. The explorer lives outside the cargo
workspace and is **not** exercised by `just test`; ship-time verification
is just `npm run build`.

## Styling: why we don't depend on www-sacred directly

[SRCL / www-sacred](https://github.com/internet-development/www-sacred) is
distributed as a Next.js + SCSS application, not as a consumable npm
component library. Pulling it in would drag Next.js (and SCSS tooling) into
this otherwise plain Vite/React app for no real gain.

Instead, [`src/styles.css`](src/styles.css) mirrors SRCL's terminal
aesthetic with a small set of tokens — monospace stack, OKLCH-derived dark
palette, `tabular-nums lining-nums`, 1ch-based padding — so the look is
recognizably "sacred" without the framework cost. If we ever need richer
SRCL components we can vendor them piecemeal under `src/components/`.
