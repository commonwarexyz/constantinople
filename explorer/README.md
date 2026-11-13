# constantinople / explorer

A React + Vite app for finalized blocks, accounts, and wallet transactions.
The browser authenticates displayed blocks, transaction results, and account state using finalization certificates and QMDB proofs.

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

Account and wallet certificate cells compare the certified block timestamp
with the browser clock once per second. The age reads `<n>s ago`, `<n>m ago`
or `10s ahead`; only its color changes, turning red after 60 seconds without a
recent timestamp, or amber for a clock mismatch when the timestamp is more than
5 seconds ahead. These are local display thresholds, not consensus rules or
proof that the browser has the globally latest block. Receiving old blocks does
not reset their age. Valid proof indicators stay green even when their
timestamps are old. The homepage block log shows each block's timestamp instead.

When the signed-in account submits a transaction, the explorer treats the
relayer's reply as a delivery report and verifies inclusion before showing
finality. A report may carry transaction evidence in the shape `GetTransaction`
serves. The explorer verifies it with the same certificate and proof checks, so
the row can show finality before the indexer has published the block. Evidence
that is absent or fails verification leaves the row waiting for the indexer.
An unresolved reply or an ambiguous delivery failure keeps the nonce
reserved while the explorer reconciles the transaction by digest. Submission history survives reloads so
those reservations and proof retries can continue. Histories from the earlier
service configuration migrate by committee and wallet identity before submission
is enabled.
The explorer does not yet identify transactions replaced by another digest.
Account nonce advancement and missing indexed metadata do not prove rejection, so
unresolved submissions keep their reservations. Reload retries proof errors after
backend or verifier repairs.

Wallet state, account pages, and transaction reconciliation each use one
combined response from `explorer-indexer`. It contains the certificate, account
inclusion proof, signed transaction bodies, and one transaction multi-proof
for the page. WebAssembly initialization overlaps the request. The browser
verifies the certificate and proofs locally, recomputes transaction digests,
and derives sender, recipient, value, and nonce from their authenticated bodies.
Each transaction proof authenticates its body digest and both participants'
history indices. Account rows show the requested account's authenticated index;
indexer-reported block positions are not displayed. Block and single-transaction
views authenticate the transaction's exact inclusion height and index.
Submission history shows finality only after the transaction body, membership
proof, and owning block all agree; verification timings are local observations.

Bindings are generated from `crates/indexer/proto/constantinople/explorer/v1/explorer.proto`
with `just explorer-generate`. Unary responses and each
stream message are bounded before decoding. Submissions have a twelve-second
deadline, are sent once without redirects or retries, and preserve uncertain
delivery when the transport fails.

An account page selects a published, certified snapshot and retains its height,
digest, account operation location, and transaction count while paging through
fifty transactions at a time. Refreshing selects a new one. Wallet
balance requests omit activity. A returned account update proves active membership
under the snapshot's current unordered state root. Authenticated ancestor headers identify the
block that appended that account operation. The account's count fixes each
page's exact descending index interval and continuation cursor; omitted,
repeated, reordered, or foreign transactions fail verification. Pages always show
the complete interval; a sent-only or received-only page could not prove it omitted
nothing. Self-transfers occupy one history entry.

The browser verifies account inclusion with the native fixed account verifier.
Each proof binds the requested key and the exact state root and operation tip
from the certificate. The state database has no absence proofs. The indexer
reports an account without an update as not found, which is not authenticated.
The account page then shows the address and a plain `account not found` line.
The wallet shows the chain's default balance marked `new account`, since such an
account can spend it at once, and shows no certificate or proof cells until the
account has an update. The certificate cell's age counts up from the certified
timestamp: red after 60 seconds, amber for a browser clock mismatch. A recent timestamp
provides an as-of observation, not a guarantee of the globally newest head.
The transaction nonce remains a local draft. Persisted proof status is reverified
after a reload.

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

The explorer uses the Node.js major version in [`.nvmrc`](.nvmrc).

The `@exowarexyz/qmdb` and `@exowarexyz/simplex` browser verifiers must match the
Exoware crates the indexer runs, so they come from the Exoware revision pinned in
the root [`Cargo.toml`](../Cargo.toml) rather than from npm. `just explorer-install`
runs [`scripts/build-exoware.sh`](scripts/build-exoware.sh), which checks out that
revision into `.exoware/` at the repository root and builds its `sdk/ts`,
`qmdb/ts`, and `simplex/ts` packages, then installs the locked dependencies with
`npm ci`. `package.json` links the two verifier packages from `.exoware/`. The
build runs again only when the pinned revision changes.

Building the verifiers needs `git`, `wasm-pack`, the Rust
`wasm32-unknown-unknown` target, and a C compiler that targets wasm32. On macOS,
put Homebrew LLVM first on `PATH` (`export PATH=/opt/homebrew/opt/llvm/bin:$PATH`)
because Apple's clang has no wasm32 target. The script installs the matching
`wasm-bindgen` CLI into `.exoware/bin` when `PATH` lacks it.

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

Native fixture exports can be tested without copying them into this checkout:

```sh
just explorer-fixtures /tmp/explorer-fixtures
EXPLORER_FIXTURE_DIR=/tmp/explorer-fixtures just explorer-test
```

`just explorer-fixtures` exports `proofBundle.json`, `blockFeed.json`, and
`transactionActivityProof.json` from the indexer tests of this checkout. CI runs
the same commands on every pull request and push to `main`. The count
variant uses 32-byte account values and 48-byte transaction-history values.
The tests identify incompatible older fixtures and report the affected crypto
checks as skipped; an explicitly supplied directory must use the matching format.

The build outputs a static bundle to `explorer/dist/`. The Explorer tests run
separately from the Rust workspace's `just test` recipe.

## Styling

The explorer's terminal appearance draws from
[SRCL / www-sacred](https://github.com/internet-development/www-sacred).
[`STYLE_GUIDE.md`](STYLE_GUIDE.md) defines the typography, spacing, controls,
and component rules. [`src/styles.css`](src/styles.css) implements those rules
with shared tokens.
