# constantinople / explorer

A small React + Vite app that subscribes to the constantinople indexer
(exoware simulator) and renders newly finalized transactions as they arrive,
batched per finalized block.

## What it does

The explorer opens a single `subscribe()` stream against the indexer's
[`store.stream.v1.Service`][rpc] for the `TX_BY_H` key family
(`reservedBits = 4`, `prefix = 0x6` — see
[`crates/indexer/src/keys.rs`](../crates/indexer/src/keys.rs)). Every key in
that family is `(u64 BE height, u32 BE index) → 32-byte tx digest`, and each
atomic store batch corresponds to the transactions of a single finalized
block.

[rpc]: https://github.com/exowarexyz/monorepo/blob/main/proto/store/v1/stream.proto

Rather than streaming every transaction (a single block can contain tens of
thousands during spammer runs), the UI aggregates each batch into a one-line
block summary — `(height, txCount, arrival time)` — and renders a multi-line
ASCII histogram at the top showing tx-count-per-block over the last
~80 blocks so the operator can see throughput scale at a glance. The
histogram's y-axis is auto-scaled to the peak in the visible window.

The full transaction body lives in the `TX` family (`prefix = 0x5`). Decoding
it requires deserializing `SignedTransaction`, which is non-trivial from
TypeScript; the explorer deliberately leaves that out — height + tx count is
enough to read the live cadence of the chain.

## Configuration

| Env var             | Default                  | Notes                                          |
| ------------------- | ------------------------ | ---------------------------------------------- |
| `VITE_INDEXER_URL`  | `http://127.0.0.1:8090`  | Matches the local-deploy `--indexer-port` default |

The exoware simulator already enables a permissive CORS layer
(`tower_http::cors::CorsLayer::very_permissive()`), so the dev server can
talk to it cross-origin without a Vite proxy.

## Local development

```sh
npm install
npm run dev
```

The dev server defaults to <http://localhost:5173>. To get live data, point
the validator's indexer wiring at the simulator and start the spammer:

```sh
cargo run -p constantinople-deploy -- generate \
    --validators 4 --secondaries 1 --output-dir local --spammer \
    local --indexer
mprocs ...   # the deploy job prints the full mprocs invocation
```

`local --indexer` automatically appends both the simulator and this dev
server to the printed mprocs command list (see
[`bin/deploy/src/local.rs`](../bin/deploy/src/local.rs)).

## Build

```sh
npm run build
```

Outputs a static bundle to `dist/`. The explorer lives outside the cargo
workspace and is **not** exercised by `just test`; ship-time verification is
just `npm run build`.

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
