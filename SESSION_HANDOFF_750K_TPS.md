# Constantinople 750k TPS Investigation Handoff

Status captured: 2026-08-16. The current compact QMDB lookup experiment is promising but **not yet deploy-ready**. Do not deploy it until the validation checklist below is complete.

This document intentionally contains no AWS credentials, SSH private-key material, or other secrets. Obtain fresh temporary credentials if a deployment is authorized.

## Objective and production workload

The goal is sustained throughput above 750k TPS with a stable leader, without rapid leader rotation, followers falling materially behind, or unbounded validator RSS.

The production-shaped workload and deployment constraints are:

- 50 validators distributed across regions, with the stable leader path enabled.
- Proposals can be about 24 MiB and are paced no faster than one per 100 ms.
- Marshal must still serve a complete 24 MiB proposal when requested. The 2 MiB setting is a shard limit, not a whole-message limit.
- Prefer `c8a.8xlarge`/32 vCPUs or smaller. Do not assume a larger instance is the throughput fix.
- `io2` Block Express is supported, but live evidence says disk is not the current critical-path limiter.
- Keep the shared Simplex issue/admission window at 16, Marshal pending ACKs at 8, the 64-shard per-peer ring, and 2,048 decoded-message slots.
- Healthy followers should normally be less than roughly one second behind. Large pending/rebuild depth is a symptom of slow service, not a reason to widen consensus windows.
- Never retransmit signed proposal votes.

## Repository snapshot

Primary application worktree:

- Path: `/Users/patrickogrady/code/constantinople-stable-testing`
- Branch: `stable-testing`
- HEAD: `95a7b1aad50e5c44b19f21afccfdc30b7e77e29d` (`progress`)
- State at handoff: clean before this handoff file was added.

Pinned Commonware worktree:

- Path: `/Users/patrickogrady/code/monorepo-optimize-glue-sync-glue-tweaks-plus`
- Branch: `glue-tweaks-plus`
- HEAD: `a84c2bdb0e79cf7c94bd2b23ebcc2e1ce7465031` (`progress`)
- Uncommitted files:
  - `storage/src/qmdb/any/batch.rs`
  - `storage/src/qmdb/benches/constantinople.rs`
- Current diff size: 259 additions and 25 deletions, consisting only of the compact lazy diff index and the production MMR benchmark variant.

Temporary A/B worktrees created by this investigation:

- `/private/tmp/commonware-qmdb-baseline.BZdO5R`: detached at `a84c2bdb0`; dirty only with the MMR benchmark variant.
- `/Users/patrickogrady/code/monorepo-qmdb-baseline-cadence-tmp`: detached clean at `a84c2bdb0`.
- `/Users/patrickogrady/code/constantinople-cadence-baseline-tmp`: detached at `95a7b1a`; only `Cargo.toml` is changed to point dependencies at the baseline Commonware worktree.

These are investigation-owned artifacts. Preserve them for immediate paired benchmarks, then remove them with `git worktree remove` only after confirming their stated diffs are no longer needed. Do not use recursive deletion.

The committed architecture reference is [`PERFORMANCE_STORAGE_ARCHITECTURE.md`](./PERFORMANCE_STORAGE_ARCHITECTURE.md). Treat this handoff's current-experiment section as newer than that document.

Relevant semantic sessions:

- `@@019ff18e-0766-7b41-9db0-15332da86ec0`: original stable-leader and durability investigation.
- `@@019ff9ab-167c-7d12-b682-e55a13d9c67c`: extended throughput investigation, failed deployments, rollback, profiling, and the current lookup work.

## Last known good deployed baseline

The committed reduced architecture was last observed at approximately 683–687k sustained finalized TPS with one stable leader. The latest known dashboard host was `44.202.240.167` (normally Grafana on `:3000`, Tempo on `:3200`); verify that the cluster still exists before relying on it.

The healthy run showed:

- one stable proposer after warmup;
- timestamp-corrected follower skew around 1.5–2.2 views;
- pending depth at most 5 and rebuild depth at most 3;
- negligible iowait and no evidence that EBS/NVMe throughput was limiting TPS;
- leader CPU equivalent to roughly 9.6 logical cores at about 3.74 GHz, leaving machine-wide headroom.

Do not use an in-place restart over old stores as a clean TPS baseline. Catch-up/replay can retain tens of GiB and obscure steady-state memory and throughput. Use a fresh cluster for final acceptance.

## Live trace and profile evidence

Representative live timings from the healthy ~685k run:

- proposal-side staged QMDB reads: about 66–99 ms;
- Stateful mailbox/admission wait: about 47–73 ms;
- full state-application work: roughly 210 ms in the sampled traces;
- proposal wall spans: roughly 150 ms;
- verifier wall spans: roughly 129–136 ms;
- finalization: roughly 60 ms;
- QMDB apply within finalization: roughly 40 ms.

The strongest CPU attribution was QMDB ancestor lookup:

- `lookup_sorted<AccountKey, DiffEntry>`: 20.75% of total process CPU samples;
- 63.09% of those samples were floor ancestor resolution (about 13.1% of process CPU);
- 36.91% were pending-diff reads (about 7.7% of process CPU).

Assembly inspection showed that `AccountKey` comparison already checks four big-endian 64-bit limbs and random digests almost always differ in the first limb. The problem is the binary-search memory walk through large 170k-entry diffs, not a scalar byte comparator waiting for AVX/NEON.

A 15-second live `perf stat` sample showed approximately 1.37 IPC and 1.02% branch misses. This also points to cache/backend pressure rather than branch prediction or disk.

RSS still needs a fresh-cluster soak. One healthy-run sample was about 11.7 GiB median with an estimated +0.397 MiB/s slope over 30 minutes. That was not proven to be a leak, but it is unresolved. Earlier 50–63 GiB catch-up RSS was reachable rewind/generation/network state, not an allocator-only problem.

## Accepted ownership and durability invariants

Do not change these without a new failing regression and an explicit recovery proof:

1. Stateful's processing actor is the sole finalized-state owner.
2. A finalized block is applied, non-durably flushed, passed to the finalized hook, published as the processed anchor, and exactly ACKed to Marshal in that order.
3. Per-block flush keeps buffered memory bounded and disk busy; it is not a durability claim and must not perform block execution again.
4. Durability is mandatory only immediately before pruning Marshal/QMDB history needed to replay the dirty suffix.
5. Recovery may replay any number of finalized blocks above the durable QMDB point, provided those blocks have not been pruned.
6. Proposal and verification are distinct request-owned computations. Exact-digest cached state may be reused, but independent verification verdicts must not be coalesced.
7. Normal flush/apply processes each finalized database batch once. Recovery replay is the explicit exception.
8. No background multi-block finalizer, second logical-generation protocol, candidate-verdict single-flight, or vote retransmission.

PR #4432's apply optimization is already in committed Commonware HEAD `a84c2bdb0`: one QMDB `apply_batch` overlaps its journal append with its independent in-memory index/bitmap update, then joins both before publishing metadata. This is bounded disjoint work inside one actor-owned apply; it does not overlap arbitrary execute/apply generations.

## Rejected approaches and why they failed

### Premium disks or larger instances as the primary fix

The original disk hypothesis was reasonable because finalization showed multi-millisecond storage spans. Live telemetry instead showed roughly 1 ms write waits, low device busy, sub-1% iowait, no causal ENA/EBS allowance event, and substantial idle CPU. Better storage remains useful for capacity and variance, not as the current throughput fix.

### One-child asynchronous finalization overlap

The insight was that hiding a roughly 90 ms QMDB apply behind the next proposal could make cadence approach `max(proposal, apply)`. After correcting an accidental leading verification barrier, deployments still reached only roughly 513–536k TPS. Each subsequent proposal simply encountered the prior block's apply, so the wait moved one block instead of leaving steady state.

### `spawn_blocking`/detached QMDB apply

A local variant was rejected because QMDB itself submits nested blocking/strategy work. An outer constrained blocking task can occupy the pool needed by its children and deadlock. The design also cloned a proposal-sized block. Do not revive it without tracing executor ownership and eliminating the copy.

### Multi-block pending state, background writers, and generation handoff

Several iterations tried to let proposal/verification advance over asynchronous physical apply. They introduced difficult owner/cancellation/rebase contracts, large retained state, stuck followers, rapid leader rotations, and deployments around 150k TPS. Six consecutive deployments were reported broken during this period. The committed baseline deliberately returned to actor-owned finalization.

### FIFO-1 and candidate-level verification coalescing

FIFO-1 appeared to simplify ownership and memory, but it came from a misread of Marshal rather than a safety invariant and discarded useful ACK8 overlap. Candidate-level full-verdict single-flight caused finalization/replay stalls and violated independent verification ownership. Both were removed; keep ACK8.

### Widening the 16-view window or Marshal buffers

Receiver admission at `2W+1`, raising the shared window to 32, and larger Marshal buffers were considered when followers reached depth 16–17. Correct pacing showed healthy followers should be much closer; the depth was a symptom of slow verification. Marshal already has sufficient 36-view/64-slot shard headroom. Do not mask sustained under-capacity by increasing these limits.

### Signed-vote retransmission

An exact signed-vote retransmission mechanism was implemented and locally green, but explicitly rejected before deployment. Never retransmit signed votes.

### Extra durable-prefix/pruning protocol

A storage fast path attempted to prune an already-durable prefix while a newer replayable suffix continued syncing. A real 32-block run showed existing sync coalescing and conservative pruning already kept the hot path moving. The extra recovery protocol added complexity without a measured gain and was removed.

### Cursor/keyed-merge ancestor lookup

The live lookup profile motivated sorting query slots and sweeping ancestor diffs with cursors. A prior version deployed at about 594k TPS; corrected local dispatch improved the full pipeline only about 3.8%. In this continuation, a clean 30-run A/B again rejected the cursor implementation: compared with baseline it regressed depth-0 by about 2.0 ms, depth-2 by about 2.7 ms, and depth-3 by about 1.2 ms. Sorting arbitrary query order costs as much as the searches it removes.

### Eager full-key stride directory

A stride-8 directory cloned every eighth 32-byte key. It reduced pending-read latency, but retained about 680,000 bytes per 170k-entry diff and cost around 2 ms to build. Production-shaped results were mixed: depth-2 improved, depth-3 whole-block time was effectively flat, and no-ancestor drained cadence regressed. It was fully removed.

### Eager compact directory

Replacing cloned keys with 32-bit hints reduced storage to about 85,000 bytes per diff and made depth-2/3 benchmarks substantially faster, but eagerly building even this small sidecar produced a measurable no-ancestor cadence penalty. The current experiment makes it lazy instead.

### SIMD execution as the immediate next step

SIMD remains a possible later optimization for execution/planning, but the current profile does not identify key comparison or arithmetic as the main limiter. Do not start an AVX/NEON rewrite before resolving the measured QMDB lookup path and reprofiling the resulting cluster.

## Current uncommitted experiment: lazy compact diff hints

The current code is in Commonware [`storage/src/qmdb/any/batch.rs`](../monorepo-optimize-glue-sync-glue-tweaks-plus/storage/src/qmdb/any/batch.rs).

Design:

- Every immutable `MerkleizedBatch` contains a clone-shared `DiffIndex` with a `OnceLock<Arc<[u32]>>`.
- The index is not built when the batch is merkleized or applied. It is built only when that exact batch is queried as a current/ancestor diff.
- It samples one four-byte big-endian hint for every eight sorted diff entries.
- At 170k entries, the initialized sidecar is 21,250 × 4 bytes = 85,000 bytes (about 83 KiB). Three initialized ancestors retain about 249 KiB, versus about 1.95 MiB for the rejected full-key copy.
- Sample hints must be nondecreasing. If not, the index disables itself and uses the original full binary search.
- A lookup uses the hint only to suggest an eight-entry block, then proves that the query lies between that block's real `K::cmp` boundaries. If that proof fails, it performs the original full binary search.
- This makes the hint a correctness-neutral accelerator even for key types whose `AsRef<[u8]>` order differs from `Ord`.
- `Deleted` remains a resolving diff hit, nearest ancestors still win, caller slot order is unchanged, and DB fallback occurs only after all live diffs miss.
- Bulk pending reads initialize each referenced ancestor's hints once before parallel resolution. Point/floor lookups initialize synchronously on first use.
- The raw diff remains authoritative for apply/commit/rewind; no invalidation protocol or strong parent retention was added.

The same file routes both measured hot paths through the sidecar:

- floor ancestor resolution via `resolve_in_ancestors`;
- staged/pending and merkleized `get_many` resolution via `resolve_pending_from_diffs`/`DiffSource`.

The current benchmark addition is [`storage/src/qmdb/benches/constantinople.rs`](../monorepo-optimize-glue-sync-glue-tweaks-plus/storage/src/qmdb/benches/constantinople.rs), which adds the production `any::unordered::fixed::mmr` variant.

## Current local evidence

### Production-shaped QMDB MMR mechanism benchmark

Configuration: 1M keys, 170k staged reads, 170k updates, 20 Rayon workers, 512 MiB page cache, 30 timed iterations. Every candidate root matched the baseline root for the same iteration.

| Pending ancestor depth | Baseline median | Current lazy compact median | Change |
| --- | ---: | ---: | ---: |
| 0 | 31.85 ms | 30.45 ms | effectively neutral; run-order noise exceeds the structural difference |
| 2 | 45.35 ms | 39.12 ms | 13.7% faster |
| 3 | 52.39 ms | 44.21 ms | 15.6% faster |

The depth-2/3 staged-read component fell from roughly 10–13 ms to about 7–8 ms. Absolute numbers varied across repeated runs, so rely on paired direction and whole-block medians, not a single sample.

The current standalone harness still uses replacement-sampled random keys, so 170k configured updates produce fewer unique keys than Constantinople's approximately 170,001 ring-touched accounts. It also does not apply every timed leaf. Harden that benchmark before treating it as final production acceptance.

### Cross-layer no-ancestor cadence

The application cadence includes the full state QMDB, compact transaction-history QMDB, apply/non-durable flush, and final drain. Signatures are disabled to isolate storage/application work.

Configuration: 1M accounts, 170k transfers/block, 3 Tokio workers, 20 engine workers, 10 warmup blocks, 100 measured blocks, one pending apply.

- Baseline: 67.165 ms/block, 2,531,066 drained TPS.
- Current lazy compact: 67.087 ms/block, 2,534,004 drained TPS.

This is effectively neutral (+0.1%), which is the required no-ancestor result. The cadence worker stayed faster than the builder, so `MAX_PENDING_APPLIES=3` still produced only a backlog of 1 and did not exercise a deterministic ancestor chain.

### Tests already passed on the current lazy design

- `diff_index_matches_lookup_sorted`
- `diff_index_falls_back_for_non_byte_ordered_keys`
- `get_many_resolves_mutation_parent_and_db`
- `unordered_bulk_update_paths_match_explicit_writes`
- `test_any_batch_floor_raise_chained`
- `floor_scan_falls_through_to_uncommitted_tail`
- `unordered_staged_updates_survive_ancestor_commit`
- `test_unordered_fixed_read_merkleize_parity`

The only emitted warning was macOS's pre-existing large `__eh_frame` compact-unwind warning while linking the storage test binary.

## Required work before another deploy

1. Review the full current diff for accidental remnants of the rejected eager/full-key implementations.
2. Add/confirm deterministic coverage for:
   - large initialized ancestor diffs with nearest-parent shadowing;
   - ancestor tombstones suppressing older ancestor/DB values;
   - concurrent first initialization and clone sharing;
   - initialized ancestor commit/drop followed by correct DB fallback;
   - branch lifetime and RSS bounds.
3. Harden the MMR benchmark to use the exact unique ring-touched account shape, apply/drain timed leaves, and assert floor/root/readback parity.
4. Run full upstream validation:

   ```sh
   cd /Users/patrickogrady/code/monorepo-optimize-glue-sync-glue-tweaks-plus
   just fix-fmt
   just test -p commonware-storage
   just clippy -p commonware-storage
   git diff --check
   ```

5. Run application validation:

   ```sh
   cd /Users/patrickogrady/code/constantinople-stable-testing
   just test
   just lint
   ```

6. Repeat the paired MMR runs from candidate and baseline worktrees in interleaved order:

   ```sh
   cargo bench -p commonware-storage --bench constantinople -- any::unordered::fixed::mmr 0 30 1000000 170000 1 170000 20 131072
   cargo bench -p commonware-storage --bench constantinople -- any::unordered::fixed::mmr 2 30 1000000 170000 1 170000 20 131072
   cargo bench -p commonware-storage --bench constantinople -- any::unordered::fixed::mmr 3 30 1000000 170000 1 170000 20 131072
   ```

7. Re-run the 100-block no-ancestor cadence and add a deterministic cross-layer depth-2/3 state-path benchmark. Do not infer depth from `MAX_PENDING_APPLIES`; the current writer often catches up.
8. Perform a deletion/symmetry pass. Keep each new helper/branch only if it owns a correctness invariant or measured reuse.
9. Only then perform a fresh-cluster rollout. Use `deployer aws update` from the `deploy/` directory for fleet-wide binaries/configuration. SSH is appropriate for read-only diagnostics and one-off profiling, not the rollout mechanism.
10. If the spammer restarts on an existing state, choose a fresh seed offset to avoid invalid nonce failures.
11. Wait for peer reconnection, one stable proposer, and tight view spread before measuring. A rolling update must remain quorum-safe (no more than five validators at once).
12. Acceptance requires a sustained live improvement, not a lower microbenchmark number:
    - above 750k finalized TPS under the same 24 MiB workload;
    - one stable leader and no repeated timeouts/rotations;
    - followers normally under about one second behind;
    - lower staged-QMDB and proposal cadence spans;
    - bounded RSS over a meaningful soak;
    - no disk/network allowance saturation.

## Deployment and operational notes

- Run deployer commands from `/Users/patrickogrady/code/constantinople-stable-testing/deploy` with `--config config.yaml`; invoking from the repository root with `--config deploy/config.yaml` breaks relative payload paths.
- Fleet-wide transfer/restart: `deployer aws update`.
- Direct SSH: read-only diagnostics and one-off temporary profiling are allowed.
- Insufficient EC2 capacity retries should be unbounded but must emit warning logs.
- Preserve geographic distribution; do not collapse all validators into one region merely to avoid an AZ capacity error.
- The user handles cluster cleanup unless explicitly delegated.
- Never copy old temporary AWS credentials from a transcript or handoff. Request fresh credentials.

## Recommended kickoff prompt

```text
Continue the Constantinople stable-leader >750k TPS work from:

/Users/patrickogrady/code/constantinople-stable-testing/SESSION_HANDOFF_750K_TPS.md

Read that handoff and both repositories' AGENTS.md files completely before acting. The app worktree is /Users/patrickogrady/code/constantinople-stable-testing at 95a7b1a. The upstream worktree is /Users/patrickogrady/code/monorepo-optimize-glue-sync-glue-tweaks-plus at a84c2bdb0 with an uncommitted lazy compact QMDB diff-index experiment and MMR benchmark variant.

First independently audit the current diff and its lifecycle/correctness invariants. Do not reintroduce background multi-block finalization, pending logical generations, FIFO-1, candidate-verdict coalescing, widened consensus windows, or signed-vote retransmission. Do not accept a microbenchmark-only win: finish deterministic large-ancestor/tombstone/commit-drop tests, harden the production-shaped MMR benchmark, run full storage and app validation, and prove no-ancestor cadence remains neutral.

The current evidence is promising: identical roots, D2 45.35->39.12 ms, D3 52.39->44.21 ms, and 100-block no-ancestor cadence 67.165->67.087 ms. Treat these as provisional until independently reproduced. Preserve user changes, use apply_patch, leave work uncommitted, and do not deploy until you can give a principled readiness argument. When a cluster test is justified, ask for fresh AWS credentials and use deployer aws update from deploy/; use SSH only for one-off diagnostics.
```
