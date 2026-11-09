# constantinople / explorer

A React + Vite app for finalized blocks, accounts, and wallet transactions.
The browser authenticates displayed blocks, transaction results, and historical
account updates using finalization certificates and QMDB proofs.

## What it does

The browser uses one `explorer-indexer` origin through the generated ConnectRPC
`ExplorerService` client for block updates, proof bundles, search, and transaction
submission. `WatchBlocks` streams a finalization certificate and the ancestor
headers it covers. The browser verifies the certificate and every parent link
before publishing a batch of block rows. It retains the last verified height and
digest across reconnects, preserving blocks that share one publication sequence.
A row identifies either its own certificate or the finalized descendant that
authenticates it.

The block list and scrolling histogram use transaction counts and proposal
timestamps derived from authenticated headers. The histogram fits the available
width and scales to the peak count in the visible window. Throughput is a local
observation of verified transactions received over time.

When the signed-in account submits a transaction, the explorer treats the
relayer's reply as a delivery report and verifies inclusion before showing
finality. An unresolved reply or an ambiguous delivery failure keeps the nonce
reserved while the explorer reconciles the transaction by digest. Submission history survives reloads so
those reservations and proof retries can continue. Histories from the earlier
service configuration migrate by committee and wallet identity before submission
is enabled.
The explorer does not yet identify transactions replaced by another digest.
Account nonce advancement and missing indexed metadata do not prove rejection, so
unresolved submissions keep their reservations. Reload retries proof errors after
backend or verifier repairs.

Historical wallet updates, account pages, and transaction reconciliation each use one
combined response from `explorer-indexer`. It contains the certificate, account
proof when present, signed transaction bodies, and one transaction multi-proof
for the page. WebAssembly initialization overlaps the request. The browser
verifies the certificate and proofs locally, recomputes transaction digests,
and derives sender, recipient, value, and nonce from their authenticated bodies.
Account-list heights and indices are unauthenticated index hints and are not
displayed. Block and single-transaction views authenticate the transaction's exact
inclusion height and index. Submission history shows finality only after the
transaction body, membership proof, and owning block all agree; verification
timings are local observations.

Bindings are generated from `crates/indexer/proto/constantinople/explorer/v1/explorer.proto`
with `just explorer-generate`. Unary responses and each
stream message are bounded before decoding. Submissions have a twelve-second
deadline, are sent once without redirects or retries, and preserve uncertain
delivery when the transport fails.

An account page selects a published, certified snapshot and retains its height
and digest while paging through ten transactions at a time. Changing the
activity filter retains that snapshot, and refreshing selects a new one. Wallet
balance requests omit activity. A returned account update proves membership
under the snapshot's state root. This historical proof does not establish that
the update is the latest for the account, and an absent account result does not
prove nonexistence. Activity proofs authenticate returned transactions but do
not prove that the index supplied the complete account history. The wallet's
current balance remains unknown, and its transaction nonce is labeled as a local
draft. Persisted proof status is reverified after a reload.

Clicking a homepage block opens its transactions in pages of 50. A block can be
covered by a later finalization certificate. The response carries the intervening
headers, and the browser verifies their hashes and heights back to the requested
block and its parent. Their transaction boundaries identify the block's own
appends. Each returned location must fill the requested interval and verify
against the covering certificate's transaction root. This also authenticates
empty blocks. Transaction reconciliation uses the same ancestry and membership
checks to establish the exact inclusion height.

The server selects a target covered by both publication and a certificate.
Related Store reads use its sequence as a minimum visibility floor, and the
certificate's digest, roots, and tips identify the snapshot. Temporary gaps in
publication remain retryable. Combined responses are bounded to 8 MiB and 4096
ancestry headers. Requests exceeding the supported ancestry length return a
terminal error.

The header search field accepts an account address or transaction hash. A match
opens its page directly. Search is a navigation hint: the destination verifies
its certificate and proofs before showing authenticated details. Transaction
pages display the sender, recipient, value, nonce, and exact block position from
the verified transaction body and inclusion proof.

## Configuration

| Env var | Default | Notes |
| ------- | ------- | ----- |
| `VITE_INDEXER_URL` | `http://127.0.0.1:8092` | The `explorer-indexer` origin for all application requests. |
| `VITE_SIMPLEX_VERIFICATION_MATERIAL` | empty | Hex-encoded Simplex committee verification material. Required for the block feed and all proof verification. |

The indexer enables cross-origin requests for the local Vite development server.
Store credentials stay on the server. The browser runs QMDB and Simplex proof
verification locally in WebAssembly.

## Local development

```sh
just explorer-install
cd explorer
npm run dev
```

The `@exowarexyz` browser verifier packages must support the indexer's proof APIs.
Their `2026.9.0` npm release lacks the standalone verifier required by the
explorer. Until matching packages are published and pinned, use the Exoware
revision pinned in the root [`Cargo.toml`](../Cargo.toml). Build `sdk/ts`,
`qmdb/ts`, and `simplex/ts` in that checkout, then install them together
from this repository's root:

```sh
just explorer-install --no-save --package-lock=false \
  /path/to/exoware/sdk/ts /path/to/exoware/qmdb/ts \
  /path/to/exoware/simplex/ts
```

The dev server defaults to <http://localhost:5173>. To get live data,
point a secondary validator at the simulator and start the spammer:

```sh
cargo run -p constantinople-deploy -- generate \
    --validators 4 --indexer --relayer --output-dir local --spammer \
    local
mprocs ...   # the deploy job prints the full mprocs invocation
```

`--indexer` appends the shared Store (`chain-indexer`), the application server
(`explorer-indexer`), and this development server to the printed mprocs command
list (see [`bin/deploy/src/local.rs`](../bin/deploy/src/local.rs)). The application
server forwards submissions to the relayer, or to a validator when no relayer
is configured by the local deployer.

## Verification

Run from the repository root:

```sh
just explorer-test
just explorer-build
```

The build outputs a static bundle to `explorer/dist/`. The Explorer tests run
separately from the Rust workspace's `just test` recipe.

## Styling

The explorer's terminal appearance draws from
[SRCL / www-sacred](https://github.com/internet-development/www-sacred).
[`STYLE_GUIDE.md`](STYLE_GUIDE.md) defines the typography, spacing, controls,
and component rules. [`src/styles.css`](src/styles.css) implements those rules
with shared tokens.
