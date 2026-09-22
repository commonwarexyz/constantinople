# Global handoff timing results

These experiments compare the three handoff modes enabled by
[Commonware PR #4739](https://github.com/commonwarexyz/monorepo/pull/4739),
pinned at `8d5a87ecf49130dab67fb1a062d4413fd8663995`.
The [comparison workflow](handoff-comparison.md) describes how to rerun them.

## Setup

Seven AWS `c8g.xlarge` validators ran across Virginia, Oregon, Ireland, and
Singapore (2/2/2/1 validators), with two runtime workers and two Rayon workers
per validator. Blocks were empty: no spammer, relayer, or indexer.
Each mode ran sequentially on the same fleet and binary, with fresh chain
storage, 120 seconds of warmup, and 600 seconds of measurement.

The first deployment used three windows per mode with rotating order. A second
deployment used one window per mode and added a 50 ms asynchronous delay after
the parent became available in proposal construction. This models elapsed build
time; it does not model CPU contention, transaction execution, or larger payloads.
The default for future comparisons is one window per mode (three runs total).

## Results

Mean finalized-block intervals, derived from finalized-height progress over
measured elapsed time:

| Mode | Empty blocks | Empty blocks + 50 ms build delay |
| --- | ---: | ---: |
| `baseline`: build after parent certification | 122 ms | 169 ms |
| `build-only`: prepare early, publish after certification | 120 ms | 140 ms |
| `build-and-broadcast`: prepare and publish early when eligible | 94 ms | 134 ms |

With empty blocks, preparation alone was close to baseline (about 1.5% more
blocks per second, within the variation across windows). Early publication
increased finalized-block throughput by about 30%. The individual window
intervals ranged from 119–124 ms for baseline, 118–125 ms for build-only, and
92–96 ms for build-and-broadcast.

With the synthetic build delay, preparation alone increased throughput by about
20%, while early publication increased it by about 26% relative to that
deployment's baseline, or about 5% beyond preparation alone. These observations
are consistent with overlapping construction with parent certification and,
when eligible, overlapping proposal distribution as well.

Leader-only mean finalization latency, measured from consensus view entry:

| Mode | Empty blocks | Empty blocks + 50 ms build delay |
| --- | ---: | ---: |
| `baseline` | 172 ms | 214 ms |
| `build-only` | 168 ms | 186 ms |
| `build-and-broadcast` | 144 ms | 179 ms |

Finalized-block cadence and leader view-entry latency measure different things;
neither is transaction latency. Cadence pools finalized-height progress and
elapsed time across windows; latency pools histogram sums and counts across
validators and windows.

## Checks and limitations

All 12 accepted windows had stable validator processes, verified binary and
configuration hashes, and zero recorded handoff abandonments. In the delayed
experiment, the measured delay averaged about 51 ms and actual empty-block
construction averaged about 0.066 ms. Early publication occurred for 1,806 of
4,501 returned candidates in that experiment; candidates ready after parent
certification published normally.

The campaigns ran on separate deployments on September 21–22, 2026 (UTC).
Compare modes within each campaign: the single delayed window per mode does
not establish a confidence interval, and sequential runs remain exposed to
network variation. These are indicative scheduling results, not a loaded
transaction benchmark or evidence about adversarial behavior. Early publication
has the outgoing-leader trust assumption described in PR #4739.

Sanitized numerical summaries include per-window measurements, binary hashes,
and handoff counters: [empty blocks](benchmarks/empty-blocks.json) and
[50 ms build delay](benchmarks/build-delay-50ms.json). Deployment credentials,
configurations, and raw fleet logs are excluded. Both deployments were destroyed
after collection.
