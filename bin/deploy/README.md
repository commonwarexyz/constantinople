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
- `simplex-verification-material.hex`

When secondary roles are enabled, this also writes `secondary-0.yaml`,
`secondary-1.yaml`, ...

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
  --relayer \
  --spammer \
  --spammer-accounts 10 \
  --spammer-value 1 \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

The spammer continuously submits ring transfers through the generated relayer.
Each relayer submitter receives transactions from its own independent set of
accounts.

Add `--spammer-accounts-jitter J` (default `0`, no jitter) to randomize each submitter's
batch size as `accounts + rand(0..=floor(accounts * J))`, where `J` must be in `0..=1`.
With `J>0` blocks no longer pin to a flat `accounts`-per-block size, which gives the indexer histogram (see
[Local Deployment with Indexer + Explorer](#local-deployment-with-indexer--explorer)) a
visibly varying throughput stream:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --indexer --relayer --output-dir ./local \
  --spammer --spammer-accounts-jitter 0.25 \
  local
```

Add `--spammer-presigned-batches N` (default `16`) to keep more fully signed batches ready
locally per submitter. The spammer still submits only one batch at a time to each target leader.

You can also run the spammer manually against an existing local cluster:

```sh
PRIMARY_TARGETS=$(yq -r '.validators[].name' ./local/peers.yaml | paste -sd, -)
cargo run --bin constantinople-spammer -- \
  --relayer-url http://127.0.0.1:8084 \
  --relayer-submitters 4 \
  --relayer-targets "$PRIMARY_TARGETS" \
  --accounts 10 \
  --value 1 \
  --accounts-jitter 0.25 \
  --presigned-batches 16
```

### Local Transaction Relayer

Add `--relayer` to include a transaction relayer secondary:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --relayer \
  --output-dir ./local \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This adds one extra secondary validator with a `relayer` section and starts it with the normal
`constantinople` binary. The relayer listens on the next local HTTP port after validators and
the optional indexer secondary, follows consensus directly, and forwards normal user batches to
the leaders of the next two views.

When `--spammer` is set, the generated spammer command uses `--relayer-url`,
`--relayer-submitters <validators>`, and `--relayer-targets <primary-keys>`.
Each relayed submitter pins an exact primary validator target and requests
single-leader routing, so concurrent streams feed different primaries without
creating stale duplicate nonce copies.

### Local Deployment with Indexer + Explorer

Add `--indexer` to spin up the shared `chain-indexer` store, the
`metadata-indexer` query/stream service, the `qmdb-indexer` query facade, and
the React explorer dev server alongside the validators:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --indexer \
  --relayer \
  --output-dir ./local \
  --spammer \
  local
```

Primaries leave their `indexer:` block unset. The indexer secondary owns the
full upload path for raw KV, SQL metadata, simplex, and QMDB writes. When both
`--indexer` and `--relayer` are set, the indexer is `secondary-0` and the
relayer is `secondary-1`.

The printed `mprocs` command list grows by four entries:

- `cargo run --release -p constantinople-indexer --bin chain-indexer -- --port 8090 --data-dir ./local/chain-indexer`
  — the simulator-backed shared store. `--chain-indexer-port` overrides the port.
- `cargo run --release -p constantinople-indexer --bin metadata-indexer -- --store-url http://127.0.0.1:8090 --port 8091`
  — the metadata query/stream service. `--metadata-indexer-port` overrides the port.
- `cargo run --release -p constantinople-indexer --bin qmdb-indexer -- --store-url http://127.0.0.1:8090 --port 8092`
  — the QMDB query facade over the same shared store. `--qmdb-indexer-port`
  overrides the port.
- `VITE_SQL_URL=http://127.0.0.1:8091 VITE_QMDB_URL=http://127.0.0.1:8092 VITE_STORE_URL=http://127.0.0.1:8090 VITE_SIMPLEX_VERIFICATION_MATERIAL=<simplex-committee-identity> npm --prefix explorer run dev`
  — the [React explorer](../../explorer/README.md), which subscribes to the
  metadata service, streams new finalized blocks live, and verifies
  submitted-transaction proofs against `qmdb-indexer` and Simplex finalization
  certificates in the shared store.
  Add `VITE_VERIFY_CERTIFICATES=false` to disable block-list certificate
  verification during streaming-performance experiments.

Validators do not upload QMDB data to `qmdb-indexer` directly. The indexer
secondary writes QMDB rows into the shared `chain-indexer` store using reserved
Store prefixes. `qmdb-indexer` reads those rows from the same store and exposes
account-state operation-log APIs under `/state` and transaction-hash
operation-log APIs under `/transactions`.

Validators also write Simplex finalization artifacts into the shared
`chain-indexer` store through `exoware-simplex`. The explorer reads those
artifacts through `VITE_STORE_URL`, verifies them with
`VITE_SIMPLEX_VERIFICATION_MATERIAL`, checks that the certified marshal
commitment names the decoded block, and only then uses the block's transaction
root as the trusted root for the QMDB transaction proof.

When `--relayer` is also set, the explorer command receives
`VITE_MEMPOOL_URL` pointing at the local relayer.

End-to-end "spin everything up" with the spammer for live transaction flow:

```sh
# 1. install explorer deps once
npm --prefix explorer install

# 2. generate the bundle and run the printed mprocs command
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --indexer --relayer \
  --output-dir ./local \
  --spammer \
  local
mprocs ...   # paste the line printed by `generate`
```

Then open <http://localhost:5173> in your browser to watch transactions
arrive in real time.

To recover explorer verification material from an existing generated node
config:

```sh
cargo run --bin constantinople-deploy -- simplex-verification-material \
  --config ./local/validator-0.yaml
```

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
  --dashboard ./dashboard.json
```

This writes:

- one validator YAML config per validator
- `config.yaml` for `commonware-deployer`
- `dashboard.json`
- `simplex-verification-material.hex`

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

Add `--spammer` with `--relayer` to include a spammer instance in the remote deployment:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  --relayer \
  --spammer \
  --spammer-accounts 10 \
  --spammer-presigned-batches 16 \
  --spammer-value 1 \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./dashboard.json
```

This additionally writes `spammer.yaml` and adds a spammer instance to the
deployer config. The spammer submits through the generated relayer.

### Remote Transaction Relayer

Add `--relayer` to include a relayer secondary:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --relayer \
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
  --dashboard ./dashboard.json
```

This adds one extra secondary validator with a `relayer` section. The relayer listens on the
configured HTTP port, follows consensus directly, and forwards normal user batches to the leaders
of the next two views.

When `--spammer` is used, `spammer.yaml` includes `relayer_url` pointing at
the relayer secondary and `relayer_submitters: <validators>`. Each relayed
submitter pins an exact primary validator target and requests single-leader
routing, so concurrent streams feed different primaries without creating stale
duplicate nonce copies.

Build the deployable binaries before creating the deployment. The aggregate
targets are the usual deploy path and include the validator, spammer, and
indexer binaries. For Graviton instances:

```sh
just graviton-binaries
```

For Intel instances:

```sh
just intel-binaries
```

For a spammer-only remote bundle, the minimum required targets are
`validator-*-binary` and `spammer-*-binary`.

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
  --relayer \
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
  --indexer \
  --output-dir ./deploy \
  remote \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./dashboard.json
```

Primaries omit their `indexer:` block. The indexer secondary owns the full
upload path, and the shared read services are colocated in the first remote
region.

The generated bundle now also includes:

- `chain-indexer.yaml` — deployer config for the shared store instance.
- `metadata-indexer.yaml` — deployer config for the metadata query/stream service.
- `qmdb-indexer.yaml` — deployer config for the QMDB query facade.
- `simplex-verification-material.hex` — explorer verification material derived from DKG output.
- three extra deployer instances in `config.yaml`: `chain-indexer`, `metadata-indexer`, and
  `qmdb-indexer`.

Topology and defaults:

- `chain-indexer` is a single shared simulator-backed store instance.
- `chain-indexer` runs a Constantinople-specific write-heavy RocksDB profile.
- `metadata-indexer` is a single shared SQL query/stream service layered on that store.
- `qmdb-indexer` is a single shared QMDB Connect facade layered on that store.
- Simplex finalization artifacts are stored in `chain-indexer` and read
  directly by proof-verifying clients through the Store API.
- all shared indexer services land in the first remote region.
- `chain-indexer` uses a `c8gb.4xlarge` instance and a 500 GiB `io2` volume with
  16,000 IOPS by default; override these with `--chain-indexer-instance-type`,
  `--chain-indexer-storage-size`, and `--chain-indexer-storage-iops`.
- `chain-indexer` listens on port `8090` by default.
- `metadata-indexer` listens on port `8091` by default.
- `qmdb-indexer` listens on port `8092` by default.
- Full indexer uploads are enabled on only the indexer secondary.

QMDB rows are committed by validators through the shared `chain-indexer` Store URL, not by sending
writes to `qmdb-indexer`. The QMDB facade only serves reads: account-state operation-log APIs are
mounted under `/state`, and transaction-hash operation-log APIs are mounted under `/transactions`.
Simplex certificates follow the same boundary: validators commit them through
the shared Store URL, and clients read them from the Store rather than from
`qmdb-indexer`.

The deployer opens shared-service ports globally because `commonware-deployer`'s port list is
deployment-wide rather than per-instance.

Build every deployable binary before creating the deployment. For Graviton instances:

```sh
just graviton-binaries
```

For Intel instances:

```sh
just intel-binaries
```

Those aggregate targets write:

- `deploy/validator`
- `deploy/spammer`
- `deploy/chain-indexer`
- `deploy/metadata-indexer`
- `deploy/qmdb-indexer`

### Local Explorer Against Remote

After the remote deployment has completed, run the explorer locally against the
remote shared services:

```sh
TAG=$(yq -r '.tag' deploy/config.yaml)
HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml

CHAIN_IP=$(yq -r '.hosts[] | select(.name=="chain-indexer") | .ip' "$HOSTS")
SQL_IP=$(yq -r '.hosts[] | select(.name=="metadata-indexer") | .ip' "$HOSTS")
QMDB_IP=$(yq -r '.hosts[] | select(.name=="qmdb-indexer") | .ip' "$HOSTS")

SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

VITE_SQL_URL=http://$SQL_IP:8091 \
VITE_QMDB_URL=http://$QMDB_IP:8092 \
VITE_STORE_URL=http://$CHAIN_IP:8090 \
VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
npm --prefix explorer run dev
```

The generated local `mprocs` command sets `VITE_MEMPOOL_URL` automatically when
`--relayer` is enabled. For a local explorer pointed at a remote deployment,
set it manually if you want local submissions to go through the remote relayer:

```sh
RELAYER_NAME=$(for f in deploy/*.yaml; do yq -e '.relayer' "$f" >/dev/null 2>&1 && basename "$f" .yaml; done)
RELAYER_IP=$(yq -r ".hosts[] | select(.name==\"$RELAYER_NAME\") | .ip" "$HOSTS")

VITE_MEMPOOL_URL=http://$RELAYER_IP:8080 \
VITE_SQL_URL=http://$SQL_IP:8091 \
VITE_QMDB_URL=http://$QMDB_IP:8092 \
VITE_STORE_URL=http://$CHAIN_IP:8090 \
VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
npm --prefix explorer run dev
```

## Secondary Validators

Secondary validators join the P2P network and observe consensus, but do **not** participate in
consensus. They receive an ed25519 identity during setup but **no DKG share**, so they cannot sign
consensus messages. They are registered through the `p2p::discovery` secondary peer set, which
every node (primary and secondary) tracks identically.

Secondaries do **not** run the mempool HTTP webserver — since they cannot propose blocks, they
have no need to ingest transactions. Submit transactions to a primary validator instead.

Use `--indexer` and `--relayer` to include the supported secondary roles in
either local or remote bundles:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --indexer \
  --relayer \
  --output-dir ./local \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This writes `secondary-0.yaml` and/or `secondary-1.yaml` alongside the primary
`validator-*.yaml` files. `peers.yaml` gains a `secondaries:` block that every
node consumes to populate the secondary peer set.

Run a secondary manually (same binary, same flags as a primary):

```sh
cargo run --bin constantinople -- \
  --config ./local/secondary-0.yaml \
  --peers ./local/peers.yaml
```

Local secondaries listen on loopback P2P ports starting at `base_port + validators`, and metrics
ports starting at `base_metrics_port + validators`. The relayer binds its HTTP server on its
allocated secondary HTTP port; the indexer secondary does not bind a mempool HTTP server. Remote
secondaries reuse `--instance-type` and `--storage-size`; there are no secondary-specific sizing
flags.

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
constantinople-spammer --relayer-url http://127.0.0.1:8084 --accounts 10 --value 1
constantinople-spammer --config ./spammer.yaml --hosts ./hosts.yaml
```
