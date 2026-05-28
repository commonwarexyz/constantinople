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

By default, `--spammer` submits directly to primary validator mempool endpoints. Add `--relayer`
as well if the spammer should submit through the transaction relayer instead.

Add `--spammer-accounts-jitter J` (default `0`, no jitter) to randomize each submitter's
batch size as `accounts + rand(0..=floor(accounts * J))`, where `J` must be in `0..=1`.
With `J>0` blocks no longer pin to a flat `accounts`-per-block size, which gives the indexer histogram (see
[Local Deployment with Indexer + Explorer](#local-deployment-with-indexer--explorer)) a
visibly varying throughput stream:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --secondaries 1 --output-dir ./local \
  --spammer --spammer-accounts-jitter 0.25 \
  local
```

You can also run the spammer manually against an existing local cluster:

```sh
cargo run --release --bin constantinople-spammer -- \
  --peers ./local/peers.yaml \
  --accounts 10 \
  --value 1 \
  --accounts-jitter 0.25
```

### Local Deployment with Relayer

Add `--relayer` to include the transaction relayer in the generated local bundle:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --output-dir ./local \
  --relayer \
  local \
  --base-port 3000 \
  --base-http-port 8080
```

This adds one extra secondary validator with a `relayer` section and starts it with the normal
`constantinople` binary. The relayer listens on the next local HTTP port after validators and
configured secondaries (`base_http_port + validators + secondaries`), follows consensus directly,
and forwards normal user batches to the leaders of the next two views.

When both `--spammer` and `--relayer` are set, the generated spammer command uses
`--relayer-url` and `--relayer-submitters <validators>`, preserving the same number of independent
nonce-ordered streams as direct mode. Each relayed submitter pins an exact primary validator target
and requests single-leader routing, so concurrent streams feed different primaries without creating
stale duplicate nonce copies. Without `--relayer`, the spammer uses `--peers` and submits directly
to primary validators.

### Local Deployment with Indexer + Explorer

Set `--secondaries` to a non-zero value to spin up the shared `chain-indexer`
store, the `metadata-indexer` query/stream service, the `qmdb-indexer` query
facade, and the React explorer dev server alongside the validators:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 \
  --secondaries 1 \
  --output-dir ./local \
  --spammer \
  local
```

There are only two local deployment shapes: validators only when
`--secondaries 0`, or validators plus secondaries, explorer, and the full
indexer stack when `--secondaries > 0`. Primaries leave their `indexer:` block
unset. The first secondary owns the QMDB upload path; other secondaries still
upload KV and SQL indexer data but leave QMDB disabled so the QMDB writer
contract has a single writer.

The printed `mprocs` command list grows by four entries:

- `cargo run -p constantinople-indexer --bin chain-indexer -- --port 8090 --data-dir ./local/chain-indexer`
  — the simulator-backed shared store. `--chain-indexer-port` overrides the port.
- `cargo run -p constantinople-indexer --bin metadata-indexer -- --store-url http://127.0.0.1:8090 --port 8091`
  — the metadata query/stream service. `--metadata-indexer-port` overrides the port.
- `cargo run -p constantinople-indexer --bin qmdb-indexer -- --store-url http://127.0.0.1:8090 --port 8092`
  — the QMDB query facade over the same shared store. `--qmdb-indexer-port`
  overrides the port.
- `VITE_SQL_URL=http://127.0.0.1:8091 VITE_QMDB_URL=http://127.0.0.1:8092 VITE_STORE_URL=http://127.0.0.1:8090 VITE_SIMPLEX_VERIFICATION_MATERIAL=<simplex-committee-identity> npm --prefix explorer run dev`
  — the [React explorer](../../explorer/README.md), which subscribes to the
  metadata service, streams new finalized blocks live, and verifies
  submitted-transaction proofs against `qmdb-indexer` and Simplex finalization
  certificates in the shared store.
  Add `VITE_VERIFY_CERTIFICATES=false` to disable block-list certificate
  verification during streaming-performance experiments.

Validators do not upload QMDB data to `qmdb-indexer` directly. The first
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

If `--relayer` is also enabled, the explorer command receives `VITE_MEMPOOL_URL` pointing at the
local relayer. Otherwise it uses its default direct mempool URL.

End-to-end "spin everything up" with the spammer for live transaction flow:

```sh
# 1. install explorer deps once
npm --prefix explorer install

# 2. generate the bundle and run the printed mprocs command
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --secondaries 1 \
  --output-dir ./local \
  --spammer \
  local
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
By default, the spammer targets primary validator HTTP endpoints discovered from `hosts.yaml`.
Add `--relayer` to route the spammer through the relayer.

### Remote Deployment with Relayer

Add `--relayer` to include a relayer secondary in the remote deployment:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --output-dir ./deploy \
  --worker-threads 4 \
  --rayon-threads 4 \
  --relayer \
  remote \
  --http-cidr 0.0.0.0/0 \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

This adds one extra secondary validator with a `relayer` section. The relayer listens on the
configured HTTP port, follows consensus directly, and forwards normal user batches to the leaders
of the next two views. It is optional; `--spammer` does not create a relayer unless `--relayer` is
also set.

When `--spammer --relayer` are used together, `spammer.yaml` includes
`relayer_url` pointing at the relayer secondary and `relayer_submitters: <validators>`. With
`--spammer --relayer`, each relayed submitter pins an exact primary validator target and requests
single-leader routing, so concurrent streams feed different primaries without creating stale
duplicate nonce copies. With `--spammer` alone, `relayer_url` is omitted and the spammer submits
directly to primary validators.

Build both binaries before creating the deployment. For Graviton instances:

```sh
just graviton-binaries
```

For Intel instances:

```sh
just intel-binaries
```

These targets write `deploy/validator`, `deploy/validator-debug`, `deploy/spammer`,
`deploy/spammer-debug`, `deploy/relayer`, and `deploy/relayer-debug`.

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

Set `--secondaries` to a non-zero value to launch the shared remote indexer stack:

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 \
  --secondaries 2 \
  --output-dir ./deploy \
  remote \
  --regions us-east-1,us-west-2 \
  --instance-type c8g.2xlarge \
  --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge \
  --monitoring-storage-size 100 \
  --dashboard ./docker/dashboard.json
```

There are only two remote deployment shapes: validators only when
`--secondaries 0`, or validators plus secondaries and the full shared indexer
stack when `--secondaries > 0`. Primaries still omit their `indexer:` block.

The generated bundle now also includes:

- `chain-indexer.yaml` — deployer config for the shared store instance.
- `metadata-indexer.yaml` — deployer config for the metadata query/stream service.
- `qmdb-indexer.yaml` — deployer config for the QMDB query facade.
- three extra deployer instances in `config.yaml`: `chain-indexer`, `metadata-indexer`, and
  `qmdb-indexer`.

Topology and defaults:

- `chain-indexer` is a single shared simulator-backed store instance.
- `metadata-indexer` is a single shared SQL query/stream service layered on that store.
- `qmdb-indexer` is a single shared QMDB Connect facade layered on that store.
- Simplex finalization artifacts are stored in `chain-indexer` and read
  directly by proof-verifying clients through the Store API.
- all shared indexer services land in the first remote region.
- `chain-indexer` listens on port `8090` by default.
- `metadata-indexer` listens on port `8091` by default.
- `qmdb-indexer` listens on port `8092` by default.
- QMDB uploads are enabled on only the first secondary. All other secondaries leave
  QMDB disabled to preserve the QMDB single-writer contract.

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

Those aggregate targets now write:

- `deploy/validator`
- `deploy/spammer` when `--spammer` is enabled
- `deploy/relayer` when `--relayer` is enabled
- `deploy/chain-indexer`
- `deploy/metadata-indexer`
- `deploy/qmdb-indexer`

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
