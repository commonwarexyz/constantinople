# constantinople / explorer

A small React + Vite app that streams newly finalized blocks from the
constantinople indexer's SQL metadata path, verifies submitted-transaction
proofs through QMDB, and renders both as they arrive.

## What it does

The explorer bootstraps the newest publication target with one Store range
read, then keeps it current through a direct Store subscription. A separate
SQL subscription caches up to 128 `block_meta` rows. Each row is displayed
only after a matching publication target covers its commit sequence. This
keeps block delivery independent of SQL query visibility delays. Bootstrap
and cache misses use point queries under the target's Store sequence floor.

The schema column names (`height`, `tx_count`, …) come from
[`crates/indexer/src/sql_schema.rs`](../crates/indexer/src/sql_schema.rs),
which is the canonical source of truth for both the publisher and this
client.

[rpc]: https://github.com/exowarexyz/monorepo/blob/main/proto/sql/v1/service.proto

The UI renders a one-line block summary plus a multi-line ASCII
histogram showing tx-count-per-block over the last ~80 blocks so the
operator can see throughput scale at a glance. The histogram's y-axis
is auto-scaled to the peak in the visible window.

When the signed-in account submits a transaction, the explorer distinguishes
validator-reported finalization from verified certificates and proofs. Once
the reported height is published, its certificate and `tx_meta` row are read
concurrently. The reported height is a lookup hint. The explorer still checks
the certificate, transaction body digest, and location within the certified
block range before fetching and verifying the QMDB operation-log proof under
`/transactions`. When no height was reported, it discovers the containing
height through `block_meta`.

Account pages show the certificate as soon as it is verified and load state
and transaction proofs concurrently. Row proofs retain a certificate that
covers the newest transaction on the selected page. A newer page shares one
certificate refresh across its rows. Account-state retries do not restart
transaction proofs already in progress.

The publication target's Store sequence becomes the minimum sequence for
related SQL, Simplex, and QMDB reads. A lagging query node must catch up instead
of returning a stale miss.

### Why SQL?

The indexer publishes every finalized block to complementary surfaces
(see [`crates/indexer/README.md`](../crates/indexer/README.md)):

- **Simplex block/certificate storage.** Certified headers, full blocks by
  digest, and finalization indexes. The explorer uses this for browser-side
  certificate/header verification and only fetches full block bodies when a
  workflow needs them.
- **Metadata and lookup storage (SQL).** `block_meta`, `tx_meta`,
  `tx_activity`, and `account_meta` tables share the same store. They are cheap to
  subscribe to from the browser and directly queryable for transaction proof
  metadata, transaction bodies, account activity, and account proof
  locations.
- **QMDB operation logs.** Transaction inclusion and account-state proofs
  checked against roots in verified finalization certificates.

## Configuration

| Env var | Default | Notes |
| ------- | ------- | ----- |
| `VITE_SQL_URL` | `http://127.0.0.1:8091` | The `metadata-indexer` service. Matches the local-deploy `--metadata-indexer-port` default. |
| `VITE_QMDB_URL` | `http://127.0.0.1:8092` | The `qmdb-indexer` service. Matches the local-deploy `--qmdb-indexer-port` default. |
| `VITE_STORE_URL` | `http://127.0.0.1:8090` | The shared `chain-indexer` Store used for Simplex artifacts and provable-target updates. |
| `VITE_MEMPOOL_URL` | `http://127.0.0.1:8080` | The transaction admission endpoint. Local deploy points this at the relayer when `--relayer` is enabled. |
| `VITE_SIMPLEX_VERIFICATION_MATERIAL` | empty | Hex-encoded Simplex committee verification material. Required for certificate and transaction proof verification. |
| `VITE_VERIFY_CERTIFICATES` | `true` | Set to `false` to disable block-list certificate verification while profiling live block streaming. |

The metadata and QMDB services enable permissive CORS layers, so the dev
server can talk to them cross-origin without a Vite proxy.

## Local development

```sh
npm install
npm run dev
```

The dev server defaults to <http://localhost:5173>. To get live data,
point a secondary validator at the simulator and start the spammer:

```sh
cargo run -p constantinople-deploy -- generate \
    --validators 4 --indexer --relayer --output-dir local --spammer \
    local
mprocs ...   # the deploy job prints the full mprocs invocation
```

`--indexer` automatically appends the shared store (`chain-indexer` bin), the
metadata service (`metadata-indexer` bin from `constantinople-indexer`), the
QMDB facade (`qmdb-indexer` bin), and this dev server to the printed mprocs command list (see
[`bin/deploy/src/local.rs`](../bin/deploy/src/local.rs)).

## Build

```sh
just explorer-build
```

Outputs a static bundle to `dist/`. The explorer lives outside the Cargo
workspace and is **not** exercised by `just test`. Run `just explorer-test`
for client tests and `just explorer-build` to type-check and bundle the app.

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
