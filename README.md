# Constantinople

A high-throughput blockchain demo built on [`commonware`](https://github.com/commonwarexyz/monorepo) primitives.
Constantinople wires together simplex consensus, erasure-coded broadcast, and QMDB storage into a
simple blockchain that supports only account-to-account transfers.

## Architecture

```
bin/
  validator/        CLI that assembles and runs a validator node
  spammer/          `constantinople-spammer` transaction spammer

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
- **Execution model**: blocks execute as a simple sequential in-memory account update pass.

## Quick Start

`constantinople-deploy` is the entrypoint for generating deployment artifacts.

### Local Deployment

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./configs \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This writes:

- `validator-0.toml`, `validator-1.toml`, ...
- `peers.toml`
- optionally `spammer.toml` if `--spammer-count` and `--spammer-tps` are supplied

It also prints an `mprocs` command that starts the whole local cluster.

To run a single local validator directly:

```sh
cargo run --bin constantinople -- \
  --config ./configs/validator-0.toml \
  --peers ./configs/peers.toml
```

To run the whole local cluster, use the printed `mprocs` command, or run each validator in a separate terminal:

```sh
cargo run --bin constantinople -- --config ./configs/validator-0.toml --peers ./configs/peers.toml
cargo run --bin constantinople -- --config ./configs/validator-1.toml --peers ./configs/peers.toml
cargo run --bin constantinople -- --config ./configs/validator-2.toml --peers ./configs/peers.toml
cargo run --bin constantinople -- --config ./configs/validator-3.toml --peers ./configs/peers.toml
```

To generate a local cluster plus a spammer config:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./configs \
  --spammer-count 4096 \
  --spammer-tps 100000 \
  local
```

Then run the spammer against the local peer topology:

```sh
cargo run --bin constantinople-spammer -- \
  --config ./configs/spammer.toml \
  --peers ./configs/peers.toml
```

### Remote Deployment

Remote deployments use the same service TOML configs, but networking is resolved from the deployer
hosts file at runtime.

Generate a remote deployment bundle:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./deploy \
  --spammer-count 4096 \
  --spammer-tps 100000 \
  remote \
  --tag constantinople-testnet \
  --validator-binary ./docker/validator \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.large \
  --storage-size 25 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./monitoring/dashboard.json \
  --spammer-binary ./docker/spammer
```

This writes:

- one validator TOML config per validator
- optionally `spammer.toml`
- `config.yaml` for `commonware-deployer`
- a copied dashboard file for monitoring

The deploy command then prints the `commonware-deployer` command to run.

### Runtime Interfaces

Validator:

```sh
constantinople --config ./validator.toml --peers ./peers.toml
constantinople --config ./validator.toml --hosts ./hosts.yaml
```

Spammer:

```sh
constantinople-spammer --config ./spammer.toml --peers ./peers.toml
constantinople-spammer --config ./spammer.toml --hosts ./hosts.yaml
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
