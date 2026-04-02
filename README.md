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
  --output-dir ./local \
  --worker-threads 2 \
  --rayon-threads 2 \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This writes:

- `validator-0.yaml`, `validator-1.yaml`, ...
- `peers.yaml`
- optionally `spammer.yaml` if `--spammer-count` and `--spammer-tps` are supplied

It also prints an `mprocs` command that starts the whole local cluster.

To run a single local validator directly:

```sh
cargo run --bin constantinople -- \
  --config ./local/validator-0.yaml \
  --peers ./local/peers.yaml
```

To run the whole local cluster, use the printed `mprocs` command, or run each validator in a separate terminal:

```sh
cargo run --bin constantinople -- --config ./local/validator-0.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-1.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-2.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-3.yaml --peers ./local/peers.yaml
```

To generate a local cluster plus a spammer config:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./local \
  --worker-threads 2 \
  --rayon-threads 2 \
  --spammer-count 128 \
  --spammer-tps 1024 \
  local
```

Then use the printed `mprocs` command, or run the spammer against the local peer topology:

```sh
cargo run --bin constantinople-spammer -- \
  --config ./local/spammer.yaml \
  --peers ./local/peers.yaml
```

### Remote Deployment

Remote deployments use the same service YAML configs, but networking is resolved from the deployer
hosts file at runtime. `generate remote` does not build binaries. It only writes the deployment
bundle, and you build `validator` and optional `spammer` into that same directory afterwards.

Generate the remote deployment bundle first:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  --spammer-count 4096 \
  --spammer-tps 32768 \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

The generate step writes:

- one validator YAML config per validator
- optionally `spammer.yaml`
- `config.yaml` for `commonware-deployer`
- a copied dashboard file for monitoring

Then build the deployable ARM64 binaries into that directory:

```sh
docker buildx bake -f docker/docker-bake.hcl constantinople-validator
docker run --rm -v ${PWD}:/constantinople constantinople-validator-builder:local

docker buildx bake -f docker/docker-bake.hcl constantinople-spammer
docker run --rm -v ${PWD}:/constantinople constantinople-spammer-builder:local
```

The Docker build step then writes:

- `deploy/validator`
- `deploy/validator-debug`
- `deploy/spammer`
- `deploy/spammer-debug`

The deploy command then prints the exact commands to run:

```sh
cd ./deploy
deployer aws create --config config.yaml
```

`--http-cidr` controls who can reach validator mempool HTTP ports in remote deployments. If you
deploy a spammer alongside the validators, you must explicitly decide what CIDR(s) should be able
to submit transactions.

### Runtime Interfaces

Validator:

```sh
constantinople --config ./validator.yaml --peers ./peers.yaml
constantinople --config ./validator.yaml --hosts ./hosts.yaml
```

Spammer:

```sh
constantinople-spammer --config ./spammer.yaml --peers ./peers.yaml
constantinople-spammer --config ./spammer.yaml --hosts ./hosts.yaml
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
