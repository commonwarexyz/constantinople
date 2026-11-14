# Performance

This document describes how a Constantinople fleet performs under the configurations `deploy.sh`
produces and explains why, so you can pick a configuration and know what to expect from it. Every
figure comes from runs in November 2026, all but one on 50-validator fleets on AWS, and is quoted
with the conditions it ran under. Figures marked *derived* are arithmetic on measured values.
Explanations marked *inferred* fit the measurements but were not tested on their own.

| Configuration | TPS | Blocks/s | Finalization | Measured on |
|---|---:|---:|---:|---|
| `--leader rotating` (the default, 16 MiB blocks) | 342k to 345k | 3.3 | 272 ms | c8a.4xlarge in us-east-1 and us-west-2, PR #87, Nov 12 |
| `--leader stable` (8 MiB blocks) | 706k to 738k | 13.8 | 183 ms | c8a.4xlarge in us-east-1 and us-west-2, PR #87, Nov 12 |
| `--leader stable --max-propose-bytes 16777216` | 720k to 740k | 6.9 | 290 ms | c8a.4xlarge in us-east-1 and us-west-2, PR #87, Nov 12 |
| `--leader stable`, 8 MiB blocks, 40 streams of 250 accounts | 49.9k | 54 | 110 ms | c8a.4xlarge in us-west-2, us-east-1 and us-east-2, branch store-file-count, Nov 14 |
| `--leader stable`, 168,000-byte blocks, 64 streams of 226 accounts | 49.3k | 52 | 110 ms | the same fleet as the row above |

The first three rows ran without the indexing services, and the stable ones ran for about 3 and 17
minutes. The last two ran with the whole indexing path and with `leader_optimistic_views` at 4,
which `deploy.sh` does not expose (its stable preset uses 16). The sections below give the rest of
each row's conditions.

## Reading the numbers

### The load

The spammer drives every run. It signs batches of transfers and submits them through the relayer in
independent streams, as many as `--spammer-submitters` sets. A batch holds `--spammer-accounts`
transfers plus a random jitter of up to a tenth more, which `deploy.sh` fixes at 0.1. Each stream is
a closed loop. It keeps one batch outstanding and sends the next only after the relayer reports the
last one's outcome, with two signed batches in reserve (`--spammer-presigned-batches 2`). Offered
load is therefore not a fixed rate. It is the number of transfers in flight divided by the time a
batch takes to travel from the spammer through the relayer to the leader and come back finalized, so
anything that lengthens that round trip lowers throughput even when the validators have room to
spare.

Under a rotating leader each stream names one validator, and the relayer forwards its batches there
to wait for that validator's turn. Under a stable leader the relayer sends every batch to the leader
of the current term. If the term ends before a batch resolves, the relayer answers 503 and the
spammer retries the same batch with the next leader. The spammer runs at most 512 streams, because
each holds one Tokio blocking thread, and the `deploy.sh` defaults stay below that.

### The metrics

| Metric | Meaning |
|---|---|
| TPS | Transfers included in blocks per second across the fleet. A range is the spread of samples over the run. |
| Blocks/s | Blocks finalized per second. |
| Finalization | Latency from a block's proposal to its finalization, as the validators report it. |
| Store commit latency | Time for the chain indexer's Store to commit a write, sampled every 15 s as a 30 s mean seen by the indexer. Percentiles are over those samples. |
| Publication lag | Time from a block's finalization until the indexer has published it, which is when the explorer can serve it. |

### The fleet

Unless a section says otherwise, a fleet is what `deploy.sh` generates. There are 50 validators on
c8a.4xlarge, each with a 300 GiB gp3 volume at 500 MB/s, spread evenly over `--regions` (default
us-east-1 and us-west-2), each running 3 Tokio worker threads and 13 Rayon threads. The relayer,
spammer, indexer secondary (c8a.8xlarge), chain indexer and explorer indexer all run in the first
region in the list, and the deployer places the monitoring instance in us-east-1. The validators,
relayer and spammer launch with `vpc-1` bandwidth weighting. Runs are short, from 3 to 26 minutes,
and most cases ran once.

## Rotating or stable

`--leader` chooses between a new leader every view and one leader for a term of 1,000,000 views. The
two presets differ in more than the term, because a stable leader receives every stream and a
rotating one receives only the streams that name it.

| Setting | `rotating` (default) | `stable` |
|---|---|---|
| `leader_term_length` | 1 | 1,000,000 |
| `leader_optimistic_views` | unused | 16 |
| `mempool_propose_priority`, `propose_skip_final_refill` | off | on |
| `--max-propose-bytes` | 16 MiB | 8 MiB |
| `--max-pool-bytes` | 64 MiB | 512 MiB |
| `--spammer-submitters` | 500 | 200 |
| `--spammer-accounts` | 12,700 | 6,300 |

The presets were measured on two fleets of 50 × c8a.4xlarge in us-east-1 and us-west-2 with `vpc-1`,
built from PR #87 on Nov 12 and generated through `deploy.sh`'s option handling without the indexing
services. Each case ran once.

| Leader | Block cap | Pool | TPS | Blocks/s | Finalization | Length |
|---|---|---|---:|---:|---:|---|
| rotating | 16 MiB | 64 MiB | 342k to 345k | 3.3 | 272 ms | one run |
| stable | 16 MiB | 512 MiB | 720k to 740k | 6.9 | 290 ms | 17 minutes |
| stable | 8 MiB | 512 MiB | 706k to 738k | 13.8 | 183 ms | about 3 minutes, last sample 685k |
| stable | 8 MiB | 64 MiB | 640k to 650k | 12.3 | 183 ms | about 3 minutes |

A stable leader runs about twice as fast as rotating leaders on the same fleet. Under rotation every
view is a handoff, and the incoming leader has to receive its parent block and process it before it
can build its own. Traces of rotating views on earlier builds show that wait as the largest part of
a view. A stable leader built the parent itself and skips that wait. The stable preset also serves
proposal requests ahead of other mempool work and ends a build after a selection round that drops
nothing. Those waits matter only where one mempool takes every submission, and an A/B on Nov 10
found no effect on rotating leaders, so the rotating preset leaves them off.

A stable leader's pool must hold a batch from every stream. The background lane admits a batch only
while its bytes fit within `--max-pool-bytes` minus `--max-propose-bytes` and answers 503 otherwise,
before it verifies any signatures. The spammer retries the same batch, so nothing is lost, but the
retries cost throughput (640k to 650k with a 64 MiB pool against 706k to 738k with 512 MiB). The
stable preset's 200 streams of up to 6,930 transfers at 149 bytes come to about 206 MB in flight
(derived), which is why its pool is 512 MiB. Keep a pool of that order whenever many streams send to
one leader.

A fresh stable chain usually abandons its first one or two terms before a quorum connects, so the
first leader is not known in advance. The trials saw streams get 503, retry and drop nothing. With
the stable leader stopped under load at 16 MiB, the streams got 503 for six seconds, consensus moved
to the next term, and throughput was back at 719k 37 seconds after the stop.

## Where the validators sit

`--regions` spreads the validators evenly over the listed regions. C8a is offered in us-east-1,
us-east-2 and us-west-2 but not in us-west-1, so a US-only c8a fleet uses those three. The table
compares a US-only fleet with one in two US and two European regions, run at the same time on 50 ×
c8a.8xlarge with `vpc-1`, Nov 11 to 12. The build was an experiment build of the PR #86 tree with
the stable-leader keys that PR #87 later added. Blocks were full, with 7,000 accounts at 8 MiB and
14,000 at 16 MiB and no jitter, so eight batches fill a block, and with 500 streams for rotating
leaders and 120 to 200 for stable ones. Each case ran once over a 45-second window. A second US and
Europe fleet reproduced three of the cases within 2% and 4 ms.

| Leader | Block cap | TPS, US | TPS, US and Europe | Finalization, US | Finalization, US and Europe |
|---|---|---:|---:|---:|---:|
| stable | 8 MiB | 760k | 734k | 151 ms | 205 ms |
| stable | 16 MiB | 743k | 709k | 224 ms | 268 ms |
| rotating | 8 MiB | 368k | 327k | not recorded | not recorded |
| rotating | 16 MiB | 470k | 396k | not recorded | 261 ms |

Adding Europe cost a stable leader 3 to 5% of throughput and 44 to 54 ms of finalization. Rotating
leaders lost 11 to 16%, which fits each handoff waiting for a parent block that may have to cross
the Atlantic (inferred). At 50k TPS the gap persists. With an 8 MiB cap and
`leader_optimistic_views` 4, a stable leader finalized in 139 ms on two US and two European regions
(Nov 13, PR #89, 49 blocks/s) and in 110 ms on three US regions (Nov 14, branch store-file-count, 54
blocks/s).

The leader's position relative to the spammer matters as much as the layout. The relayer, spammer
and indexing services sit in the first region of `--regions`, while the leader is wherever the
settled term puts it, and every batch's cycle crosses that distance. On the Nov 13 four-region
fleet, 40 streams of 205 accounts gave 50k TPS with the leader in us-east-1, the spammer's region,
and 33k with the leader in eu-west-1. On the Nov 14 US-only fleet, with the spammer in us-west-2 and
the leader in us-east-2, the same streams gave 41k, and raising the batch to 250 accounts restored
50k. Size the in-flight load for the farthest leader the chain might settle on, not for the nearest.

## Block size

`--max-propose-bytes` caps a block's encoded size, framing included, at no more than 16 MiB. A
transfer takes 147 bytes plus 2 bytes of framing, so 8 MiB holds about 56,280 transfers.

### Large caps

Larger blocks help rotating leaders and not a stable one. In the geography table, rotating leaders
went from 368k to 470k on US-only regions when the cap doubled from 8 to 16 MiB, while the stable
leader stayed level and finalized 73 ms later. On the PR #87 fleet the stable leader ran as fast at
8 MiB as at 16 MiB and finalized about 100 ms sooner, which is why the stable preset uses 8 MiB. A
rotating leader pays the handoff once per view, and a larger block spreads that cost over more
transfers (inferred).

A block reaches its cap only if the spammer supplies enough whole batches. The mempool takes whole
batches, oldest first, until the next one does not fit, so a block holds a whole number of batches.
`deploy.sh` derives the default batch from the cap so that eight batches at their largest jittered
size fit in one block, which gives 12,700 accounts at 16 MiB and 6,300 at 8 MiB. A rotating leader
also needs enough batches waiting when its turn comes. With at most 512 streams spread over 50
validators, each leader has about 10 batches per turn however many streams are configured. Check
transfers per block against capacity before reading a run as full-block throughput.

### Even blocks at a steady rate

Far below capacity, a large cap makes blocks bursty. With a stable leader at 50k TPS on the Nov 14
US-only fleet, an 8 MiB cap and 40 streams of 250 accounts, 42% of blocks were empty and the largest
held 9,633 transfers. The closed-loop streams synchronise. A leader with room for every waiting
batch takes them into one block, the streams wait on the same finalization, and they resubmit
together (inferred).

Two changes give even blocks. First, cap the block near the average block, in whole batches. At 50k
TPS and about 52 blocks a second the average block holds about 960 transfers (derived), and a
168,000-byte cap holds four whole batches of up to 275 transfers. Second, run more streams than the
cap can drain, so a backlog always waits. Both changes ran on the same fleet (50 × c8a.4xlarge in
us-west-2, us-east-1 and us-east-2, stable leader, `leader_optimistic_views` 4, branch
store-file-count, Nov 14).

| Cap | Streams × accounts | TPS | Blocks/s | Empty blocks | Transfers per block, p10 / p50 / p90 / max |
|---|---|---:|---:|---:|---|
| 8 MiB | 40 × 250 | 49.9k | 54 | 42% | 0 / 267 / 2,881 / 9,633 |
| 168,000 bytes | 40 × 250 | 48.3k | 53 | 3% | 519 / 1,043 / 1,067 / 1,095 |
| 168,000 bytes | 64 × 226 | 49.3k | 52 | 0% | 930 / 948 / 966 / 985 |

A changed cap is a validator setting and needs a fresh chain from genesis, while a stream or batch
change needs only a spammer restart. `deploy.sh` would derive batches of 100 accounts from a
168,000-byte cap (derived), so pass the batch and stream count explicitly.

```sh
./deploy.sh --leader stable --regions us-west-2,us-east-1,us-east-2 \
  --max-propose-bytes 168000 --spammer-submitters 64 --spammer-accounts 226
```

Even blocks also put more steady work on the indexing path, covered below.

## Bandwidth

The deployer gives hosts only public addresses, and validators dial each other on them, so all
peer-to-peer traffic, even between validators in one region, passes through the AWS internet
gateway. AWS caps multi-flow traffic through the gateway at half of the instance's network baseline.
On c8a.8xlarge that is 7.5 Gbps, and on an earlier build with larger blocks its shard bursts of 93
MB ran at about 7.4 Gbps, at the cap.

`--bandwidth-weighting` moves an instance's bandwidth between the network and EBS. `deploy.sh` sets
`vpc-1` on the validators, relayer and spammer, and other instances keep the standard split.

| Instance | Weighting | Network baseline | Through the gateway | EBS |
|---|---|---:|---:|---:|
| c8a.4xlarge | `default` | 7.5 Gbps | 3.75 Gbps (derived) | 5 Gbps |
| c8a.4xlarge | `vpc-1` | 9.375 Gbps | about 4.7 Gbps (derived) | 3.125 Gbps |
| c8a.8xlarge | `default` | 15 Gbps | 7.5 Gbps | 10 Gbps |
| c8a.8xlarge | `vpc-1` | 18.75 Gbps | about 9.4 Gbps | 6.25 Gbps |

A block leaves its proposer as erasure-coded shards, one per validator, each about a seventeenth of
the block on these 50-validator fleets, so the proposer sends about 2.9 times the block. At the
stable preset's 730k TPS that averages about 2.6 Gbps from the leader, with bursts above the average
(derived). No run has compared `vpc-1` with `default` on the current code, so the gain from the
weighting there is not measured. Use `ebs-1` only for an instance whose limit is its disk, such as a
Store on EBS.

## The indexing path

`deploy.sh` always deploys the indexing services. The indexer secondary is a non-voting node running
the validator binary in indexer mode. It captures each finalized block and uploads it to the chain
indexer, an Exoware Store backed by RocksDB, and the explorer indexer serves the explorer from that
Store. Every fleet measurement in this section was taken with a stable leader at about 50k TPS and
49 to 54 blocks a second. None was taken at the presets' full rate.

### Indexer secondary

The secondary's capture is a durable queue on disk, so its write latency bounds how many blocks a
second it can follow. On gp3 it spent 22 to 25 ms per block in finalization (capture 21 ms, opening
the payload for write 11.7 ms), which capped it near 44 blocks a second while the chain produced 58,
and the explorer fell minutes behind (Nov 13, c8a.8xlarge, four regions, PR #87). On a 300 GiB io2
volume at 16,000 IOPS its capture took 4.4 ms and its finalization 5 ms a block, and it kept pace at
49 blocks a second (Nov 13, PR #89). `deploy.sh` does not expose the secondary's volume. Set
`storage_class` to `io2` and `storage_iops` to 16,000 on its entry in the generated deployer
`config.yaml` before creating the fleet. Keep it on persistent storage. The node may not state sync,
so losing its partition means rebuilding the index.

### Store file count

Every Store commit ingests files into RocksDB, and RocksDB rebuilds the target column family's file
list, walking every live file, twice per ingestion. Before exowarexyz/monorepo#256 the Store's log
family never merged its files, so each commit added one and commit latency grew with the number of
commits. On a fleet at 49 blocks a second and 50k TPS, with the Store on io2, it climbed about 35 ms
a minute and passed 1.1 s at 20 minutes with 54,100 SST files, and the indexer fell behind (Nov 13,
four regions).

#256 merges small log files in the background every 1,024 commit groups, writes a small state group
whose keys lie beyond the stored keys as one synced batch instead of a file, and cuts state
compaction output at 256 MiB. Its median commit latency has no trend over a fleet run. On a laptop,
one Put at a time, the p50 stayed at about 0.5 ms through 300,000 commits, against 38.2 ms at 94,000
commits without the change. The branch store-file-count pins the chain indexer to #256's head and
caps RocksDB's open table files at 16,384. #256 is not merged yet.

### Compaction and disk bandwidth

What remains is the state family's compaction. Each large state file spans the whole key space, so
universal compaction rewrites the state about 5.5 times as it merges sorted runs, and the largest
compactions grow with the store (18 to 62 GiB within 20 to 26 minutes). A large compaction takes the
disk's whole bandwidth for about a minute, and commits wait behind it. The Store's steady disk
traffic at 50k TPS and 49 blocks a second was about 680 MB/s, reads included. Turning off
size-amplification compaction did not help (p90 560 ms).

| Run | Store host and disk bandwidth | Compaction limit | Load and window | Commit p50 / p90 / max | Samples at or above 150 ms | Publication lag p50 / p90 |
|---|---|---|---|---|---:|---|
| A | c8a.4xlarge, io2, EBS 625 MB/s baseline and 1.25 GB/s burst | none | 49 blocks/s, minutes 2 to 20 | 60 / 576 / 681 ms | 34% | 193 / 1,446 ms |
| B | c8a.16xlarge, io2, EBS 2.5 GB/s | none | 49 blocks/s, minutes 2 to 20 | 59 / 95 / 187 ms | 4% | 207 / 290 ms |
| C | as A | 600 MB/s | 49 blocks/s, minutes 2 to 20 | 66 / 108 / 185 ms | 1% | 211 / 310 ms |
| D | c8a.4xlarge, io2 | 600 MB/s | 54 blocks/s, uneven, minutes 2 to 16 | 83 / 125 / 179 ms | 4% | 262 / 340 ms |
| E | c8a.8xlarge with `ebs-1`, io2, EBS about 1,560 MB/s | none | 52 blocks/s, even, minutes 2 to 13 | 126 / 340 / 410 ms | 29% | 355 / 757 ms |
| F | c8id.8xlarge, local NVMe | none | 52 blocks/s, even, minutes 2 to 21 | 10 / 14 / 182 ms | 1% | 71 / 81 ms |

Runs A to C ran on Nov 13 with 50 validators on c8a.4xlarge in two US and two European regions, a
stable leader, an 8 MiB cap and 50k TPS, with validators built from PR #89 and io2 at 16,000 IOPS
for the Store. Run A used #256's head, and runs B and C its first commit. Run B's host also had 64
vCPUs against 16, with the same 12 RocksDB background jobs. Runs D to F ran on Nov 14 on the US-only
fleet from branch store-file-count (#256's head), D with an 8 MiB cap and E and F with the
168,000-byte cap and 64 streams of 226 accounts. Each run started from genesis.

### The rate limit

`--chain-indexer-compaction-rate-limit <mb/s>` caps what RocksDB may write in compactions and
flushes, and is off by default. A limit spreads a large compaction over time without reducing the
total, so it helps only while the disk's sustained bandwidth covers the steady compaction demand.

Run C shows it working. Over 20 minutes at 49 blocks a second a 600 MB/s limit took p90 commit
latency from above 500 ms to 108 ms on the same disk. Its state level zero peaked at 240 files
against 90 without the limit, which is deferred work.

Run D shows it failing. At 54 blocks a second the limit was saturated, with 617 MB/s written against
a 600 MB/s limit and the instance's 625 MB/s EBS baseline, when the Store's disk traffic had already
been about 680 MB/s at the lower block rate. When a 21 GiB state compaction started at minute 13,
state level zero went from 12 to 1,197 files in 80 seconds, RocksDB stalled writes and commit
latency doubled. The run's percentiles look healthy only because its window ended about three
minutes later. Run C's 20 minutes most likely ended before its deferred work came due (inferred).
Size the disk for the compaction demand rather than limiting it, and keep the limit for smoothing
spikes on a disk whose sustained bandwidth already exceeds that demand. A limit close to the average
compaction rate has not been run for hours. While a long compaction runs, RocksDB keeps obsolete
files on disk, so a count of `*.sst` files overstates the live files. Read live counts from
`compacted to: files[...]` in the RocksDB LOG.

### EBS or NVMe

Bandwidth is not the only limit. Each block becomes about three ingestions on the Store's single
commit thread, and each ingestion makes three fdatasync calls and one fsync. On the c8a.8xlarge EBS
Store at the 168,000-byte cap and 52 to 53 blocks a second, that came to about 167 ingestions a
second, and the thread spent about 70% of its time in those flushes while the CPU sat 90% idle and
the disk wrote 785 MB/s of its roughly 1,560. Flush latency, not bandwidth or CPU, set commit
latency there. Local NVMe flushes much faster. At the same load run F's commit p50 fell from 126 to
10 ms and its publication lag from 355 to 71 ms, with no write stalls, and its worst commit, 182 ms,
came during a 53 GiB state compaction.

NVMe has costs. The instance store is lost when the instance stops, so the Store's data does not
survive a stop and start. On c8id the chain indexer needs its Intel build, because the AMD build
traps. `deploy.sh`'s managed chain indexer is a c8id.4xlarge, built with
`just chain-indexer-intel-binary`, with a 50 GiB io2 root volume. The deployer mounts the instance
store at `/home/ubuntu` when it creates the instance, so the Store's data directory is on NVMe
without further setup. An instance changed to an NVMe type after creation has to be formatted and
mounted by hand, which is how run F was set up. The NVMe measurement used c8id.8xlarge, and
c8id.4xlarge, with half the disk, has not been measured.

### Explorer and wallet

The explorer can show a block once the indexer has published it. After capture a block's data is one
Store write, and then it waits for the publication barrier, of which one is in flight at a time, so
the delay is about 2.5 Store write latencies plus polling. Uploads hold one of 64 slots until
published, so at 48 blocks a second publication falls behind without bound once a Store write takes
longer than about 0.53 s (derived on a 51k TPS fleet, Nov 13, where Store write latency rose from
0.05 to 0.5 s over 15 minutes before the #256 fix). When the explorer lags, look at Store commit
latency first.

With PR #89 the wallet does not wait for publication to confirm a transfer. The relayer attaches
inclusion evidence to its finalization report, and the browser verifies it. On a stable-leader fleet
at 50k TPS and 49 blocks a second (50 validators in four regions, Nov 13, PR #89), the report
arrived a mean 357 ms after submission (p90 434 ms) and the certificate verified 4 to 6 ms after the
report, against 1.3 and 2.0 s through the indexer for two submissions without the change. The
balance still waits for publication, and on a young Store it read `updating` for about 1.0 s after
each certificate.

### Disk sizing

| Host | Load | Growth | Measured on |
|---|---|---|---|
| Validator | stable, 16 MiB, 720k to 740k TPS | about 13 GB a minute until pruning begins near block 5,500, then a median peak near 150 GB and 193 GB on the fullest | c8a.4xlarge, us-east-1 and us-west-2, PR #87, Nov 12, 17 minutes |
| Chain indexer Store | 50k TPS, 8 MiB cap, 49 blocks/s | about 9 GB a minute | four regions, PR #89, Nov 13 |
| Chain indexer Store | 50k TPS, 168,000-byte cap, 52 blocks/s | about 11 GB a minute, so 1.9 TB of NVMe lasts about 2.7 hours and the preset's 950 GB about 1.4 hours (derived) | US-only, branch store-file-count, Nov 14 |

Validators prune, keeping up to about 10,500 blocks (about 6,150 in the finalized archive and 4,350
in marshal's view cache), which is about 164 GiB of full 16 MiB blocks beside the state. That is why
`--storage-size` defaults to 300 GiB. No run lasted long enough to show whether the Store's growth
levels off, so size its disk as growth per minute times the planned run length, with headroom.

## Choosing a configuration

For peak throughput, run `./deploy.sh --leader stable`. On the default two-region fleet expect 706k
to 738k TPS at about 14 blocks a second and about 183 ms to finalization. Keep the 512 MiB pool. The
indexing services are deployed but unmeasured at this rate, so do not expect the explorer to keep
up.

For rotating leaders, run `./deploy.sh` with no leader option and expect 342k to 345k TPS at 3.3
blocks a second and 272 ms to finalization. Keep 16 MiB blocks, because rotating leaders lose
throughput at smaller caps.

For a fleet whose explorer stays current, run a stable leader at about 50k TPS with even blocks,
using the command under Block size, keep the Store on the preset's local NVMe and put the indexer
secondary on io2 at 16,000 IOPS. Expect about 49k TPS at 52 blocks a second, Store commits near 10
ms and publication lag near 71 ms. The measured runs differed from what `deploy.sh` produces in two
ways that have not been tested separately. They used `leader_optimistic_views` 4 instead of 16, and
the Store ran on c8id.8xlarge instead of c8id.4xlarge.

For any of these, adding European regions to a US-only fleet in us-east-1, us-east-2 and us-west-2
cost 3 to 16% of throughput and 44 to 54 ms of finalization in the runs above.

## What is not measured

- The indexing path at the presets' full rate. Every Store and secondary result is at about 50k
  TPS.
- `vpc-1` against `default` bandwidth weighting on the current code.
- 1, 2 and 4 MiB caps and the 168,000-byte cap on US and European regions on the current code.

- The effect of `leader_optimistic_views` 4 against the preset's 16.
- The chain indexer on c8id.4xlarge, the size `deploy.sh` picks, and the compaction rate limit
  with #256's head beyond 16 minutes.
- Runs longer than 26 minutes. Store growth, validator pruning past one cycle, and long
  compactions over hours have not been observed.
- The rewrite load from RocksDB's bottommost-file compactions, which begin once the explorer reads
  the Store and release snapshots. One run counted 1,017 single-file rewrites (0.7 GiB) within
  minutes of the explorer starting, and their effect on commit latency is unknown.
