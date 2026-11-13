# Deployment

`constantinople-deploy` generates deployment artifacts for local and remote Constantinople clusters.

At least four validators are required for erasure coding. The consensus maximum
is 16 MiB for a complete encoded block, independent of validator count.
`--max-propose-bytes` sets the local encoded block budget, including framing.
It defaults to 8 MiB. Deployment generation and validator startup reject budgets
above 16 MiB or too small for an empty block with the largest supported header.
The deployment script sets this budget to 16 MiB. Transaction selection and
submission admission reserve space for block encoding overhead.

Shard decoding derives its raw shard limit from the shared 16 MiB block cap and
the agreed validator count. A smaller local proposal budget does not restrict
receiving valid peer blocks. Network messages remain capped at 32 MiB.

`deploy.sh` accepts `--validators`, `--regions`, `--storage-size`,
`--spammer-accounts`, `--spammer-submitters`, and `--max-pool-bytes`.
Run `./deploy.sh --help` for defaults.

Each node runs two page caches. The state cache defaults to 6 GiB and holds the
account-state journals. The history cache defaults to 2 GiB and is shared by the
finalized block, finalization, and marshal archives, the transaction history
witness journal, and the simplex vote journal. This applies to validators and to
the indexer and relayer secondaries, which run the validator binary. Both caches
are allocated and zeroed at startup, so each node commits the full 8 GiB before
serving traffic. Size local clusters with that in mind. The larger state cache
gives operation-log pages more room to remain cached until floor advancement
reuses them with the standard Clock2Q+ policy. Keeping history apart from state
keeps backfill and replay scans from evicting the state working set.
Use the generator's `--state-page-cache-bytes` and `--history-page-cache-bytes`
options to override these budgets, including for local clusters. Existing YAML
configs with explicit cache budgets retain those values.

`--worker-threads` and `--rayon-threads` set each node's async workers and engine
Rayon pool. Use `--indexer-worker-threads` and `--indexer-rayon-threads` to override
those counts for the indexer secondary in either deployment mode.
`--indexer-publisher-rayon-threads` sizes its separate publication pool and defaults
to `2`. The generated indexer YAML stores this as `indexer.publisher_rayon_threads`.

`deploy.sh` sets these counts for its own topology. QMDB preparation and Simplex
block encoding and staging use the runtime's shared blocking pool. Store
requests run on async workers, including transport encoding and compression.
Leave CPU headroom for both pools. Thread counts do not pin threads to
particular cores.

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

`--spammer-submitters N` sets the number of concurrent submitters in both local
and remote deployments. It defaults to the validator count and must be positive.
Set it explicitly to keep offered load constant when changing the validator count.

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
`--spammer-accounts` configures accounts per submitter, so the generated total is
`spammer_accounts * relayer_submitters`.
Add `--spammer-rayon-threads N` (default `2`) to set the spammer's parallel
signing thread count in generated local commands and remote `spammer.yaml`.

By default, the spammer selects and logs a fresh account seed whenever the
process starts. This avoids restarting at nonce zero for accounts used by a
previous run. Pass `--spammer-seed-offset N` to the deployment generator or
`--seed-offset N` to the spammer binary when a reproducible account set is
required. In YAML, set `seed_offset` explicitly. Reusing a seed
after transactions have been accepted recreates the old accounts and is not
restart-safe.

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
the optional indexer secondary and follows consensus directly. It forwards single-transaction
user submissions to up to four upcoming leaders and larger batches to up to two.
It waits up to ten seconds for a terminal result before returning an empty HTTP 202.
Forwarding continues after that response, with a thirty-second timeout per leader.
Each copy shares its validator's ingress verification capacity with background
traffic. Copies can remain queued or tracked after another leader finalizes the
transaction. Resolution can wait for a later proposal and its expiry window.
This spends additional verification and
tracking work to reach upcoming leaders promptly. The public relayer is intended
for interactive traffic and has no global limit on outstanding forwarding tasks.

When `--spammer` is set, the generated spammer command uses `--relayer-url`,
`--relayer-submitters <validators>`, and `--relayer-targets <primary-keys>`.
Each relayed submitter pins an exact primary validator target and uses its
background queue. Each stream waits for a terminal result before submitting its
next batch. Transient failures retry the same encoded batch with backoff, so a
lost response does not advance the stream's nonces prematurely.
Pinned requests have a connection timeout but no finalization deadline. A stream
waits while its leader is stalled or foreground traffic keeps its batch queued.
Size the spammer below the background queue's drain rate. Capacity drops advance
to the next batch immediately and still incur ingress verification work.

### Local Deployment with Indexer + Explorer

Add `--indexer` to start a shared `chain-indexer` Store, one
`explorer-indexer` HTTP service, and the React explorer alongside the validators.
The indexer secondary publishes SQL rows, Simplex artifacts, and QMDB data to
Store. The explorer server reads that Store directly and serves block streams,
search, combined proof responses, and transaction submission through one
ConnectRPC service.

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 4 --indexer --relayer --spammer --output-dir ./local local
```

Primaries leave their `indexer:` block unset. When both `--indexer` and
`--relayer` are set, the publisher is `secondary-0` and the relayer is
`secondary-1`.

The printed `mprocs` command adds three services:

- `chain-indexer` listens on `8090`. `--chain-indexer-port` overrides its Store
  port. Its separate metrics port follows the validator, secondary, and spammer
  metrics range starting at `--base-metrics-port`.
- `explorer-indexer` listens on `8092`. `--explorer-indexer-port` overrides its
  HTTP port. The command passes `--store-url` and `--relayer-url`; the latter
  selects the relayer when enabled, otherwise the first validator's HTTP port.
  It waits for Store's `/ready` endpoint before starting, using `curl` probes
  with a one-second timeout and a one-second interval.
- Vite listens on `5173`, with `VITE_INDEXER_URL` pointing at `explorer-indexer`
  and `VITE_SIMPLEX_VERIFICATION_MATERIAL` holding the committee verification
  material. No Store credentials or internal service URLs are sent to the browser.

The API is `constantinople.explorer.v1.ExplorerService`. Its unary methods are
`GetAccount`, `GetBlock`, `GetTransaction`, `Search`, and `SubmitTransaction`;
`WatchBlocks` streams published blocks. Connect requests use paths such as
`/constantinople.explorer.v1.ExplorerService/GetAccount` on the configured
origin. The protobuf schema lives in
[`explorer.proto`](../../crates/indexer/proto/constantinople/explorer/v1/explorer.proto).
Run `just explorer-generate` to regenerate the browser's typed bindings after
changing that schema.

The browser verifies certificates and QMDB proofs locally. It accesses neither
raw Store nor SQL/QMDB RPC endpoints. Wallet submissions use the same explorer
origin and are forwarded by the server to its configured admission endpoint.

End-to-end "spin everything up" with the spammer for live transaction flow:

```sh
# 1. install explorer deps once
just explorer-install

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

Enabled service ports must be distinct and cannot use ports 22, 9080, 9090, or 9100,
which are reserved for SSH, Promtail, application metrics, and Node Exporter.
All application hosts share ingress rules, so reusing ports across services can
expose restricted HTTP or metrics endpoints on other hosts.

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
  --spammer-rayon-threads 4 \
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

The generated bundle also includes `chain-indexer.yaml`,
`explorer-indexer.yaml`, and `simplex-verification-material.hex`. Store and the
explorer server run as separate managed instances in the first remote region.
The indexer secondary runs the validator executable and publishes to Store.

`chain-indexer` listens on `8090` by default and uses a `c8gb.4xlarge` instance
with a 500 GiB `io2` volume and 16,000 IOPS. Override its resources with
`--chain-indexer-instance-type`, `--chain-indexer-storage-size`, and
`--chain-indexer-storage-iops`. The explorer API listens on `8092`, configurable
with `--explorer-indexer-port`. Its generated `relayer_url` names the relayer
secondary when present, otherwise the first validator's HTTP endpoint.

The deployer opens managed service ports globally because
`commonware-deployer` has a deployment-wide port list.

### Peer HTTP access after creation

With the default empty `--http-cidr` list, or a list limited to operator
addresses, allow workload-to-workload HTTP access before submitting
transactions. The deployer's operator-IP rule allows the operator to reach a
validator; it does not allow the explorer server's public IP to do so. The
managed explorer sends submissions to the relayer when enabled, otherwise to
the first validator. The relayer in turn needs HTTP access to every primary
validator, and a spammer needs HTTP access to the relayer.

Hostnames resolve to public IPs from the completed deployment's `hosts.yaml`.
Arrange narrow source-IP and HTTP-port access through your network policy, or
choose the existing deployer's broader authorization command described below.
The generator leaves your `--http-cidr` policy unchanged and prints a reminder
for managed explorer deployments without public HTTP access. `deploy.sh`
explicitly supplies `--http-cidr 0.0.0.0/0`, so its HTTP policy already permits
these hops.

**Optional broad peer authorization:** `deployer aws authorize --ip` trusts
that source IP on **all ports in every deployment security group**, including
SSH and monitoring. It is not a rule limited to the admission HTTP port. Use
it only if that workload trust is appropriate; narrow HTTP rules remain an
alternative.

After `deployer aws create` completes, this example deliberately authorizes
the managed explorer's source IP through the existing deployer:

```sh
TAG=$(yq -r '.tag' deploy/config.yaml)
HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml
INDEXER_IP=$(yq -r '.hosts[] | select(.name=="explorer-indexer") | .ip' "$HOSTS")
deployer aws authorize --config deploy/config.yaml --ip "$INDEXER_IP"
```

When enabled, the relayer and spammer also need their source IPs authorized or
covered by equivalent narrow HTTP rules. The spammer is named `spammer` in
`hosts.yaml`; the relayer's host name is the identity of the secondary whose
generated configuration contains `relayer`. Repeat the optional command with
each source IP only if you intend to grant the same broad trust. External
explorer operators must arrange their own admission access.

### External Store and Explorer Service

Pass `--store-url <url>` with `--indexer` to use an external Exoware Store.
The publisher and managed explorer server receive that URL; no `chain-indexer`
instance, binary, config, or port rule is generated. Add `--indexer-url <url>`
to use an existing explorer server backed by that same Store. This suppresses
its managed instance, binary, config, and port rule. The external server owns
its transaction admission configuration and must implement all six methods of
`constantinople.explorer.v1.ExplorerService`. `--indexer-url` supplies the
service origin; it does not include an RPC method path.

| Remote flags | Managed services |
| ------------ | ---------------- |
| none | `chain-indexer`, `explorer-indexer` |
| `--store-url` | `explorer-indexer` |
| `--store-url` and `--indexer-url` | none |

`--indexer-url` requires `--store-url`. The generator validates URL syntax;
operators must ensure the external service reads the correct Store.

```sh
cargo run --bin constantinople-deploy -- generate \
  --validators 20 --indexer --output-dir ./deploy remote \
  --instance-type c8g.2xlarge --storage-size 75 \
  --monitoring-instance-type c8g.2xlarge --monitoring-storage-size 100 \
  --store-url https://store.example.com \
  --indexer-url https://explorer.example.com \
  --regions us-east-1,us-west-2 --dashboard ./dashboard.json
```

The writer credential (`--store-api-key` or `CONSTANTINOPLE_STORE_API_KEY`)
is serialized only into the publisher secondary. The reader credential
(`--adapter-store-api-key` or `CONSTANTINOPLE_ADAPTER_STORE_API_KEY`) is
serialized only into the managed explorer server. Both require an external
Store URL. External explorer services receive neither credential. An omitted
key preserves the SDK's `EXOWARE_API_KEY` fallback. The writer needs both read
and write scopes if Store reads require authentication.

Writers use four HTTP/2 connections per origin and compress requests with Zstd.
External HTTPS proxies must negotiate h2 through ALPN. Plain HTTP must support
prior-knowledge h2c. Explorer Store reads may use HTTP/1.1.

Balanced writer RPCs use the SDK's 30-second deadline as the timeout and retry
threshold. Failed commits retry the same batch. A Store that consistently takes
longer will stall publication until requests complete within that deadline.

The explorer server accepts `--store-url`, `--relayer-url`, `--port`,
`--host`, `--metrics-port`, and deployer `--hosts`/`--config`. Named hosts in
both service URLs resolve through the deployer host map. An explicit CLI Store
URL overrides the YAML URL and drops its associated credential.

The server probes Store readiness before binding. `/health` and `/ready`
indicate completed startup, not ongoing Store availability. Managed deployment
sets `metrics_port: 9090` on a separate listener. The browser only needs access
to the explorer API; Store, SQL, and QMDB access stays on the server.

### Deployment Script with External Services

The deployment script accepts the same service URLs and builds only managed
binaries. Store credentials remain in the generated service configuration.

```sh
./deploy.sh \
  --store-url https://store.example.com \
  --indexer-url https://explorer.example.com
```

The script exports `VITE_INDEXER_URL` and
`VITE_SIMPLEX_VERIFICATION_MATERIAL` to the local Vite process. With a managed
server it resolves the `explorer-indexer` host IP and port `8092`; with
`--indexer-url` it uses that URL verbatim. The managed Store's Intel binary is
built last because the architecture recipes share its output path.

### Local Explorer Against Remote

After deployment, start the explorer locally against the managed API:

```sh
TAG=$(yq -r '.tag' deploy/config.yaml)
HOSTS=$HOME/.commonware_deployer/$TAG/hosts.yaml
INDEXER_IP=$(yq -r '.hosts[] | select(.name=="explorer-indexer") | .ip' "$HOSTS")
SIMPLEX_VERIFICATION_MATERIAL=$(tr -d '[:space:]' < deploy/simplex-verification-material.hex)

VITE_INDEXER_URL=http://$INDEXER_IP:8092 \
VITE_SIMPLEX_VERIFICATION_MATERIAL=$SIMPLEX_VERIFICATION_MATERIAL \
npm --prefix explorer run dev
```

For an external explorer service, use its URL as `VITE_INDEXER_URL`. Search,
verified account and transaction pages, block streaming, and wallet submission
all use this origin.

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
