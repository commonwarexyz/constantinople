# Constantinople

A high-throughput blockchain demo built on [`commonware`](https://github.com/commonwarexyz/monorepo) primitives.
Constantinople wires together simplex consensus, erasure-coded broadcast, and QMDB storage into a
simple blockchain that supports only account-to-account transfers.

## Architecture

```
bin/
  validator/        CLI that assembles and runs a validator node
  tx-cli/           Transaction builder and submission tool

crates/
  primitives/       Core types: blocks, transactions, and accounts
  application/      Consensus integration and transaction processor
  mempool/          HTTP mempool server and transaction source
  engine/           Engine assembly: wires consensus, marshal, QMDB, and p2p together
```

### Commonware Primitives

| Primitive | Role |
|---|---|
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (simplex) | Single-epoch BFT consensus with threshold BLS finality |
| [`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-consensus) (marshal) | Erasure-coded broadcast and backfill of finalized blocks |
| [`commonware-storage`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-storage) (QMDB) | Merkleized key-value database for state and transaction roots |
| [`commonware-glue`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-glue) (stateful) | State management, startup sync (marshal-sync and state-sync) |
| [`commonware-p2p`](https://github.com/commonwarexyz/monorepo/tree/main/commonware-p2p) | Authenticated peer-to-peer networking with discovery |

### Transaction Processor

The processor in `crates/application/src/processor` implements a transfer-only
account model:

- **Transactions**: every transaction contains only `sender`, `to`, `value`, and `nonce`.
- **Execution**: the processor validates nonce and balance constraints, then applies direct
  balance transfers and sender nonce increments.
- **Deterministic scheduling**: the scheduler groups transactions into dependency rounds using
  inferred sender/recipient write conflicts and executes them in a deterministic order.

## Quick Start

### Setup

Generate validator configs for a local cluster (e.g. 4 validators):

```sh
cargo run --bin constantinople -- setup \
  --validators 4 \
  --output-dir ./configs \
  --base-port 3000 \
  --base-http-port 8080
```

### Run

Start each validator with its config:

```sh
cargo run --bin constantinople -- run --config ./configs/validator-0.toml
```

Or use the `mprocs` command printed by `setup` to launch all validators at once.

### Submit a Transaction

```sh
cargo run --bin constantinople-tx -- transfer \
  --key <hex-private-key> \
  --to <hex-address> \
  --value 100 \
  --nonce 0 \
  --endpoint http://localhost:8080
```

## Development

```sh
just build    # build the workspace
just test     # run all tests (includes doc tests)
just lint     # format check + doc check + clippy (denies warnings)
just fmt-fix  # auto-fix formatting
```

## License

[MIT](LICENSE.md)
