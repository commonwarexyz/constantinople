# constantinople / explorer

A React + Vite app for finalized blocks, accounts, and wallet transactions.
The browser verifies finalization certificates and QMDB proofs before displaying
authenticated balances or transaction results.

## What it does

The explorer bootstraps the newest publication target with one Store range
read, then keeps it current through a direct Store subscription. A separate
[SQL subscription][rpc] caches recent `block_meta` rows. Each row is displayed
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

When the signed-in account submits a transaction, the explorer accepts either
a terminal status or an empty HTTP 202 from the relayer. A pending response or
an ambiguous delivery failure keeps the nonce reserved while the explorer
reconciles the transaction by digest. Submission history survives reloads so
those reservations and proof retries can continue.
The explorer does not yet identify transactions replaced by another digest.
Account nonce advancement and missing SQL metadata do not prove rejection, so
unresolved submissions keep their reservations. Reload retries proof errors after
backend or verifier repairs.

Wallet balances, account pages, and transaction reconciliation each use one
combined response from `qmdb-indexer`. It contains the certificate, account
proof when present, signed transaction bodies, and one transaction multi-proof
for the page. WebAssembly initialization overlaps the request. The browser
verifies the certificate and proofs locally, recomputes transaction digests,
and derives sender, recipient, value, and nonce from their authenticated bodies.
Account-list heights and indices remain SQL hints; block and single-transaction
views authenticate the transaction's exact inclusion height and index.
The UI records validator-reported finalization and successful proof verification
separately.

An account page selects a published, certified snapshot and retains its height
and digest while paging through ten transactions at a time. Changing the
activity filter retains that snapshot; refreshing selects a new one. Wallet
balance requests omit activity. A returned account update proves membership
under the snapshot's state root. This historical proof does not establish that
the update is the latest for the account, and an absent account result does not
prove nonexistence. Activity proofs authenticate returned transactions but do
not prove that the index supplied the complete account history.

Clicking a homepage block opens its transactions in pages of 50. A block can be
covered by a later finalization certificate. The response carries the intervening
headers, and the browser verifies their hashes and heights back to the requested
block and its parent. Their transaction boundaries identify the block's own
appends. Each returned location must fill the requested interval and verify
against the covering certificate's transaction root. This also authenticates
empty blocks. Transaction reconciliation uses the same ancestry and membership
checks to establish the exact inclusion height.

The server selects a target covered by both publication and a certificate.
Related Store reads use its sequence as a minimum visibility floor; the
certificate's digest, roots, and tips identify the snapshot. Temporary gaps in
publication remain retryable. Combined responses are bounded to 8 MiB and
4096 ancestry headers; requests exceeding the supported ancestry length return
a terminal error.

### SQL analysis

The **search** button opens the SQL popup with its previous draft and results.
Choose an example, edit it, and use **run query** or Command/Ctrl+Enter.
The schema and query guide lists the available columns and address syntax.

Results include a table and, when suitable columns are present, a chart.
Aliases `x` and `y` select chart axes; the chart controls can also change them.
Single-row numeric results appear as totals. Balance history is plotted by
state operation location because account-state rows have no timestamp.
`finalized_ts` in block queries is the publisher's observed time.
SQL results are index data and do not carry the certificate and proof checks
used by the account and block viewers.

The popup shows elapsed request-and-decode time, returned rows, columns,
Arrow batches, and the observed Store sequence. The SQL service returns one
complete response and exposes no scan progress or server execution timing,
so the progress bar is indeterminate. Cancel or closing the popup stops the
browser request; it does not guarantee that server computation has stopped.

The editor accepts one `SELECT` or `WITH` query, caps the result at 1,000 rows,
and uses a 30-second request deadline without automatic retries. The row cap
does not bound scanned input; use indexed predicates and bounded examples.
The editor guard is a convenience, not authorization on the SQL service.

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
| `VITE_QMDB_URL` | `http://127.0.0.1:8092` | The `qmdb-indexer` service, including combined account, block, and transaction reads. Matches the local-deploy `--qmdb-indexer-port` default. |
| `VITE_STORE_URL` | `http://127.0.0.1:8090` | The shared `chain-indexer` Store used for Simplex artifacts and provable-target updates. |
| `VITE_MEMPOOL_URL` | `http://127.0.0.1:8080` | The transaction admission endpoint. Local deploy points this at the relayer when `--relayer` is enabled. |
| `VITE_SIMPLEX_VERIFICATION_MATERIAL` | empty | Hex-encoded Simplex committee verification material. Required for certificate and transaction proof verification. |

The metadata and QMDB services enable permissive CORS layers, so the dev
server can talk to them cross-origin without a Vite proxy.

## Local development

```sh
just explorer-install
cd explorer
npm run dev
```

The four `@exowarexyz` browser packages must support the indexer's proof APIs.
Their `2026.9.0` npm release lacks the standalone verifier required by the
explorer. Until matching packages are published and pinned, use the Exoware
revision pinned in the root [`Cargo.toml`](../Cargo.toml). Build `sdk/ts`,
`qmdb/ts`, `simplex/ts`, and `sql/ts` in that checkout, then install them together
from this repository's root:

```sh
just explorer-install --no-save --package-lock=false \
  /path/to/exoware/sdk/ts /path/to/exoware/qmdb/ts \
  /path/to/exoware/simplex/ts /path/to/exoware/sql/ts
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

## Verification

Run from the repository root:

```sh
just explorer-test
just explorer-build
```

The build outputs a static bundle to `explorer/dist/`. The Explorer tests run
separately from the Rust workspace's `just test` recipe.

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
