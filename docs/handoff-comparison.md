# Handoff comparison

This workflow compares three running Constantinople chains using the primary
validators' Prometheus endpoints. It measures finalization throughput and
leader-only consensus latency from view entry. It does **not** measure
transaction latency or intervals derived from block timestamps.

The expected Commonware source for these metrics is
[commit `8d5a87e`](https://github.com/commonwarexyz/monorepo/commit/8d5a87ecf49130dab67fb1a062d4413fd8663995).
The tool records this expected version for reproducibility; Prometheus does not
prove the running binary's source revision, so verify that separately.

Measured global AWS results are summarized in [handoff-results.md](handoff-results.md).

## Generate comparable chains

Build once with Rust 1.95 or newer so every chain uses the same release binaries:

```sh
just build --release
```

Generate each mode with identical validator and runtime settings. Separate
directories and non-overlapping P2P, HTTP, and metrics ports prevent state or
listener reuse:

```sh
target/release/constantinople-deploy generate \
  --validators 4 --worker-threads 2 --rayon-threads 2 \
  --output-dir ./local-handoff-baseline \
  --handoff-mode baseline \
  local --base-port 3000 --base-http-port 8080 --base-metrics-port 9090

target/release/constantinople-deploy generate \
  --validators 4 --worker-threads 2 --rayon-threads 2 \
  --output-dir ./local-handoff-build-only \
  --handoff-mode build-only \
  local --base-port 4000 --base-http-port 8180 --base-metrics-port 9190

target/release/constantinople-deploy generate \
  --validators 4 --worker-threads 2 --rayon-threads 2 \
  --output-dir ./local-handoff-build-and-broadcast \
  --handoff-mode build-and-broadcast \
  local --base-port 5000 --base-http-port 8280 --base-metrics-port 9290
```

`baseline` is the default when `--handoff-mode` is omitted. Production uses the
default rotating `RoundRobin` elector, whose term length is one; keep that
default for this comparison. The modes mean:

- `baseline`: build after parent certification.
- `build-only`: prepare early and publish after parent certification.
- `build-and-broadcast`: prepare and publish early when eligible.

Early publication trusts the outgoing leader not to equivocate, as described
in [PR #4739](https://github.com/commonwarexyz/monorepo/pull/4739). This is an
experimental comparison build pinned to that PR; the required Exoware
compatibility patches are documented in [vendor/README.md](../vendor/README.md).

Start every validator with the `mprocs` invocation printed by each generator
command. Do not include secondary-validator metrics URLs: histogram aggregation
is over all primary validators only.

The commands above create no transaction workload; they compare consensus
while producing empty blocks. For an otherwise identical loaded comparison,
add these options to **each** `generate` invocation before `--output-dir`:

```sh
--relayer --spammer --spammer-accounts 4096 --spammer-seed-offset 0
```

Keep every workload option identical across modes. The fixed seed makes runs
reproducible, but do not reuse its generated data directory after that account
state has advanced.

## Measure

### Synthetic build time

For a controlled scheduling experiment, add `--proposal-build-delay-ms 50`
to `generate` before the `local` or `remote` subcommand. The generated
`proposal_build_delay_ms` setting defaults to zero. Each proposal awaits the
same asynchronous delay after its parent becomes available, before building;
verification and voting do not receive this artificial delay.

Use one run per mode. Keep the delay identical across modes and label results
as synthetic: this models elapsed construction time, not CPU contention,
transaction verification, or larger block payloads. The collector saves
`engine_application_proposal_build_duration` (construction excluding the
delay) and `engine_application_proposal_build_delay_duration` separately in
`build_timings`, plus raw handoff metrics. Cancelled proposals can cause their
sample counts to differ; do not treat the sum of independent averages as a
paired per-proposal measurement.

For AWS runs, add `--expected-build-delay-ms 50` to `just run-aws-handoffs`.
This requires the delay in every canonical configuration and checks both
histograms on every validator before accepting a window. Export each validator's
`/var/log/binary.log` (and any rotated files) before destroying the deployment
to retain the timestamped
`application.propose.start` and `application.propose.complete` events. Handoff
counters distinguish publication before/after certification and held
proposals; they do not provide exact per-proposal certification timestamps.
The deployer redirects application output to this file; systemd journals alone
contain service lifecycle records and are insufficient for proposal timings.

The metrics endpoints for the example above are:

- baseline: `http://127.0.0.1:9090/metrics` through `:9093/metrics`
- build-only: `http://127.0.0.1:9190/metrics` through `:9193/metrics`
- build-and-broadcast: `http://127.0.0.1:9290/metrics` through `:9293/metrics`

Run the comparison after all chains are healthy:

```sh
just compare-handoffs \
  --chain baseline=http://127.0.0.1:9090/metrics,http://127.0.0.1:9091/metrics,http://127.0.0.1:9092/metrics,http://127.0.0.1:9093/metrics \
  --chain build-only=http://127.0.0.1:9190/metrics,http://127.0.0.1:9191/metrics,http://127.0.0.1:9192/metrics,http://127.0.0.1:9193/metrics \
  --chain build-and-broadcast=http://127.0.0.1:9290/metrics,http://127.0.0.1:9291/metrics,http://127.0.0.1:9292/metrics,http://127.0.0.1:9293/metrics \
  --warmup 30 --duration 300 \
  --output ./handoff-comparison.json
```

Every chain in one invocation must list the same number of primary endpoints,
and endpoint URLs must be disjoint across chain names. These checks prevent a
smaller committee or a reused process from silently skewing aggregate
histogram totals. A single `--chain` is also valid: for sequential experiments,
run the command once per mode (using distinct output files) after starting only
that mode's chain.

Scrapes are concurrent. For each chain, the first URL is the designated node
for `engine_marshal_finalized_height`; finalized blocks per second is that
node's height progress divided by the actual time between its completed
baseline and final scrapes. The reported mean finalized interval is the
reciprocal of that observed rate. It is a rate-derived average, not a mean of
block timestamp gaps.

The tool aggregates deltas from the leader-only
`engine_simplex_voter_{notarization,finalization}_latency_from_view_entry`
histograms across all listed primaries. Means use aggregate `_sum / _count`.
The p50 and p95 are the upper bounds of the containing Prometheus buckets, so
they are explicit bucket approximations rather than exact quantiles. Handoff
event and abandonment deltas are retained by label in JSON.

The JSON includes the relevant baseline and final samples for every node,
scrape timing, derived values, and the expected metric source commit. The
command fails instead of reporting partial data when an endpoint is
unavailable, a required histogram is absent or malformed, or a
gauge/counter/histogram decreases between the two snapshots. Two snapshots
cannot detect a restart or reset that catches up beyond its baseline value;
correlate results with process supervision when that is possible.

## Avoid resource-contention bias

For the cleanest comparison, run the modes sequentially on the same otherwise
idle host: stop one chain, clear only its own generated data directory if
regenerating it, start the next chain, and apply the same warmup and duration.
Sequential runs avoid three chains competing for CPU, memory bandwidth, disk,
and loopback networking, but they are exposed to changes in background host
load over time.

Simultaneous runs reduce time-of-day drift but directly contend for host
resources. Use them only when the machine has ample reserved capacity, keep
all three configurations identical apart from mode/directories/ports, and
repeat while rotating startup order. Record whether the chains ran
sequentially or simultaneously alongside the JSON artifact.

Run the focused unit tests with:

```sh
just test-handoff-comparison
```

## Global AWS comparison

The global experiment uses seven `c8g.xlarge` validators: two each in
`us-east-1`, `us-west-2`, and `eu-west-1`, and one in `ap-southeast-1`.
An `m8g.large` monitoring instance runs in `us-east-1`. Each validator has
four vCPUs, with two runtime workers and two Rayon workers. The initial
experiment produces empty blocks, without a spammer, relayer, or indexer.

Build the ARM64 release with `just validator-graviton-binary`. Build the
Commonware deployer from the same pinned commit with its `aws` feature;
an older globally installed deployer may have different configuration or
deployment behavior. Generate one remote bundle and preserve its validator
identities, committee, deployment tag, and binary across all runs.

Run modes sequentially on the same fleet. Each transition stops every
validator before installing the next configuration and restarting the fleet.
Assign a unique `partition_prefix` for each run to start from fresh state.
The deployer's rolling `aws update` operation does not provide this barrier.

By default, run each mode once (three runs total): baseline, build-only, then
build-and-broadcast. With 120 seconds of warmup and 600 seconds of measurement
per mode, this takes 36 minutes plus provisioning, transitions, and cleanup.
Build time is additional. Use `--rounds 3` only when repeated measurements
are explicitly desired; that rotates the order as follows:

1. baseline, build-only, build-and-broadcast
2. build-only, build-and-broadcast, baseline
3. build-and-broadcast, baseline, build-only

For every run, wait for all validators to become healthy, warm up for 120
seconds, then measure for 600 seconds. Collect the raw metrics from the
monitoring machine, which is permitted to reach the validators' metrics
ports. Keep those ports restricted to monitoring. Check service process IDs,
start times, and restart counters around each window; discard a window if
any process restarted.

The existing-fleet runner accepts a JSON manifest with exactly these fields:
`tag`, `key` (absolute SSH key path), `monitor_ip`,
`expected_binary_sha256`, `nodes`, and `output_dir` (absolute path).
Each of the seven `nodes` has `name`, `ip`, `region`, and `config` (absolute
path to its canonical validator YAML). Derive the IP mapping from
`~/.commonware_deployer/<tag>/hosts.yaml`, keeping node order fixed so the
designated height source remains the same validator.

```sh
just test-aws-handoffs
just run-aws-handoffs --manifest /absolute/path/to/manifest.json --rounds 1
```

The runner verifies every remote binary hash, stages configurations with
hash checks, applies the fleet barriers, and saves one `comparison.json`
and `status.json` per run. Only use results whose status is `completed`.
It stops validator services when it exits, including on a failed run; it
does not provision or destroy AWS resources. Keep generated validator
configs and SSH keys private and out of version control.

Control operations use bounded transport retries. The timed collector is
never automatically rerun. After an interrupted campaign, `--start-run N`
starts a new campaign at the Nth position in the rotated schedule, with new
storage namespaces. Preserve previously completed windows separately and
check their binary/configuration hashes before combining them with the
resumed results. A failed window must be rerun in full.

Report the finalized block cadence and leader view-entry latency for each
mode, with variation across repetitions. Empty-block results primarily
exercise consensus and network timing; a loaded execution comparison is a
separate experiment. Terminate the tagged deployment after collecting the
artifacts; stopping services alone leaves the instances billable.
