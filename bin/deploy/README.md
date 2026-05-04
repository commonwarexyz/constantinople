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

Add `--spammer-accounts-jitter J` (default `0`, no jitter) to randomize each submitter's
batch size as `accounts + rand(0..=floor(accounts * J))`, where `J` must be in `0..=1`.
With `J>0` blocks no longer pin to a flat `accounts`-per-block size, which gives the indexer histogram (see
[Local Deployment with Indexer + Explorer](#local-deployment-with-indexer--explorer)) a
visibly varying throughput stream:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --secondaries 1 --output-dir ./local \
  --spammer --spammer-accounts-jitter 0.25 \
  local --indexer
```

You can also run the spammer manually against an existing local cluster:

```sh
cargo run --release --bin constantinople-spammer -- \
  --peers ./local/peers.yaml \
  --accounts 10 \
  --value 1 \
  --accounts-jitter 0.25
```

### Local Deployment with Indexer + Explorer

Add `--indexer` (a flag on the `local` subcommand) to spin up the shared
`chain-indexer` store, the `metadata-indexer` query/stream service, and the
React explorer dev server alongside the validators:

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

- `cargo run -p constantinople-indexer --bin chain-indexer -- --port 8090 --data-dir ./local/chain-indexer`
  — the simulator-backed shared store. `--chain-indexer-port` overrides the port.
- `cargo run -p constantinople-indexer --bin metadata-indexer -- --store-url http://127.0.0.1:8090 --port 8091`
  — the metadata query/stream service. `--metadata-indexer-port` overrides the port.
- `VITE_SQL_URL=http://127.0.0.1:8091 npm --prefix explorer run dev`
  — the [React explorer](../../explorer/README.md), which subscribes to the
  metadata service and streams new finalized blocks live.

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

`generate remote` writes the deployment bundle, but it does not build the deployable binaries. Use
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

### Remote Deployment with Indexer Stack

Add `--indexer` to launch the shared remote indexer stack:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --secondaries 2 \
  --output-dir ./deploy \
  remote \
  --indexer \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This requires `--secondaries >= 1` because only secondaries upload to the
shared `chain-indexer` store. Primaries still omit their `indexer:` block.

The generated bundle now also includes:

- `chain-indexer.yaml` — deployer config for the shared store instance.
- `metadata-indexer.yaml` — deployer config for the metadata query/stream service.
- two extra deployer instances in `config.yaml`: `chain-indexer` and `metadata-indexer`.

Topology and defaults:

- `chain-indexer` is a single shared simulator-backed store instance.
- `metadata-indexer` is a single shared SQL query/stream service layered on that store.
- both shared services land in the first remote region.
- `chain-indexer` listens on port `8090` by default.
- `metadata-indexer` listens on port `8091` by default.
- even in metadata-only mode, the shared `chain-indexer` store is still required because the
  metadata service reads from that backing store.

The deployer opens both shared-service ports globally because `commonware-deployer`'s port list is
deployment-wide rather than per-instance.

Build every deployable binary before creating the deployment. For Graviton instances:

```sh
just graviton-binaries
```

For Intel instances:

```sh
just intel-binaries
```

Those aggregate targets now write:

- `deploy/validator`
- `deploy/spammer` when `--spammer` is enabled
- `deploy/chain-indexer`
- `deploy/metadata-indexer`

### Remote Metadata-Only Mode

Add `--indexer-metadata-only` instead of `--indexer` when secondaries should publish only the SQL
metadata tables (`block_meta`, `tx_meta`) and skip the full KV block / transaction / certificate
path:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --secondaries 2 \
  --output-dir ./deploy \
  remote \
  --indexer-metadata-only \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This is a real runtime split, not just a deploy-time flag: secondary validators only spawn the SQL
metadata uploader in this mode. The shared `chain-indexer` and `metadata-indexer` services are
still deployed because the metadata service reads from the shared store.

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
