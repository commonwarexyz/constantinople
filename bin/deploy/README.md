# Deployment

`constantinople-deploy` generates deployment artifacts for local and remote Constantinople clusters.

## Local Deployment

Generate a local bundle:

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

It also prints an `mprocs` command that starts the whole local cluster.

Run a single validator directly:

```sh
cargo run --bin constantinople -- \
  --config ./local/validator-0.yaml \
  --peers ./local/peers.yaml
```

Run the whole local cluster with the printed `mprocs` command, or start each validator in a
separate terminal:

```sh
cargo run --bin constantinople -- --config ./local/validator-0.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-1.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-2.yaml --peers ./local/peers.yaml
cargo run --bin constantinople -- --config ./local/validator-3.yaml --peers ./local/peers.yaml
```

### Local Deployment with Spammer

Add `--spammer` to include a spam bot in the `mprocs` command:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./local \
  --spammer \
  --spammer-accounts 10 \
  --spammer-value 1 \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

The spammer waits 10 seconds for validators to start, then continuously submits ring transfers.
Each validator receives transactions from its own independent set of accounts.

You can also run the spammer manually against an existing local cluster:

```sh
cargo run --release --bin constantinople-spammer -- \
  --peers ./local/peers.yaml \
  --accounts 10 \
  --value 1
```

### Local Deployment with Indexer + Explorer

Add `--indexer` (a flag on the `local` subcommand) to spin up the exoware
simulator backing the indexer **and** the React explorer dev server alongside
the validators:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --secondaries 1 \
  --output-dir ./local \
  --spammer \
  local \
  --indexer
```

This requires `--secondaries >= 1` because only secondaries upload to the
indexer; primaries leave their `indexer:` block unset.

The printed `mprocs` command list grows by two entries:

- `cargo run -p constantinople-indexer --bin indexer -- --port 8090 --data-dir ./local/indexer-data`
  — the simulator-backed indexer store. `--indexer-port` overrides the port.
- `VITE_INDEXER_URL=http://127.0.0.1:8090 npm --prefix explorer run dev`
  — the [React explorer](../../explorer/README.md), which subscribes to the
  indexer's `TX_BY_H` family and streams new transactions live.

End-to-end "spin everything up" with the spammer for live transaction flow:

```sh
# 1. install explorer deps once
npm --prefix explorer install

# 2. generate the bundle and run the printed mprocs command
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --secondaries 1 \
  --output-dir ./local \
  --spammer \
  local --indexer
mprocs ...   # paste the line printed by `generate`
```

Then open <http://localhost:5173> in your browser to watch transactions
arrive in real time.

## Remote Deployment

`generate remote` writes the deployment bundle, but it does not build the validator binary. Use
`--output-dir ./deploy` if you want to use the bundled `just` targets unchanged.

Generate the remote bundle:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This writes:

- one validator YAML config per validator
- `config.yaml` for `commonware-deployer`
- `dashboard.json`

Build the deployable validator binary into `./deploy`:

```sh
just validator-graviton-binary
```

For Intel instances such as `c8i.*`, use:

```sh
just validator-intel-binary
```

Both targets write `deploy/validator` and `deploy/validator-debug`. See
[`docker/README.md`](../../docker/README.md) for the Docker build details.

Create the remote deployment:

```sh
cd ./deploy
deployer aws create --config config.yaml
```

`--http-cidr` controls who can reach validator mempool HTTP ports in remote deployments.

### Remote Deployment with Spammer

Add `--spammer` to include a spammer instance in the remote deployment:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  --spammer \
  --spammer-accounts 10 \
  --spammer-value 1 \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This additionally writes `spammer.yaml` and adds a spammer instance to the deployer config.

Build both binaries before creating the deployment. For Graviton instances:

```sh
just graviton-binaries
```

For Intel instances:

```sh
just intel-binaries
```

These targets write `deploy/validator`, `deploy/validator-debug`, `deploy/spammer`, and
`deploy/spammer-debug`.

Then create the deployment as usual:

```sh
cd ./deploy
deployer aws create --config config.yaml
```

The spammer is resilient to transient network errors and will retry with backoff until validators
are reachable. It can safely be deployed before or alongside validators. Spammer logs are emitted
as JSON in deployer mode so they are scraped by Promtail/Loki alongside validator logs.

Use `--spammer-instance-type` to override the instance type for the spammer (defaults to the
validator instance type):

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --spammer \
  remote \
  --instance-type c8g.2xlarge \
  --spammer-instance-type c8g.large \
  ...
```

## Secondary Validators

Secondary validators join the P2P network and observe consensus, but do **not** participate in
consensus. They receive an ed25519 identity during setup but **no DKG share**, so they cannot sign
consensus messages. They are registered through the `p2p::discovery` secondary peer set, which
every node (primary and secondary) tracks identically.

Secondaries do **not** run the mempool HTTP webserver — since they cannot propose blocks, they
have no need to ingest transactions. Submit transactions to a primary validator instead.

Use cases:

- Passive observers / monitoring nodes
- Block propagation redundancy

Add `--secondaries N` to include `N` secondary nodes in either local or remote bundles:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --secondaries 2 \
  --output-dir ./local \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This additionally writes `secondary-0.yaml`, `secondary-1.yaml`, ... alongside the primary
`validator-*.yaml` files. `peers.yaml` gains a `secondaries:` block that every node consumes to
populate the secondary peer set; the spammer ignores it and only sends transactions to primary
validators.

Run a secondary manually (same binary, same flags as a primary):

```sh
cargo run --bin constantinople -- \
  --config ./local/secondary-0.yaml \
  --peers ./local/peers.yaml
```

Local secondaries listen on loopback P2P ports starting at `base_port + validators`, and metrics
ports starting at `base_metrics_port + validators`. HTTP ports are allocated but unused (no
mempool webserver is bound). Remote secondaries reuse `--instance-type` and `--storage-size` —
there are no secondary-specific sizing flags.

Notes:

- Every node in the deployment (primary and secondary) must agree on the full primary+secondary
  set. The deploy tool emits identical lists into every YAML to guarantee this. Editing one
  config in isolation will break `discovery`.
- The DKG polynomial is sized to the primary count only — adding secondaries does not change
  consensus quorum thresholds.

## Runtime Interfaces

Use `--peers` for local bundles:

```sh
constantinople --config ./validator.yaml --peers ./peers.yaml
```

Use `--hosts` for deployer-managed remote bundles:

```sh
constantinople --config ./validator.yaml --hosts ./hosts.yaml
```

The spammer follows the same pattern:

```sh
constantinople-spammer --peers ./peers.yaml --accounts 10 --value 1
constantinople-spammer --config ./spammer.yaml --hosts ./hosts.yaml
```
