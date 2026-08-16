# Constantinople Performance and Storage Architecture

## Outcome

The storage path has one owner: Stateful's processing actor. A finalized block is applied,
non-durably flushed, reported to the application, and acknowledged to Marshal in that order on the
actor task. There is no detached finalization worker, background multi-block writer, read-generation
handoff, or second pending-state index.

QMDB is accelerated inside that ownership boundary. Its journal append and independent in-memory
index/bitmap update run concurrently, then join before the database publishes the new root and
metadata. Full and compact databases also apply concurrently as separate members of the database
set. These are bounded sub-operations of one finalized block, not a second lifecycle.

This deliberately returns to the lifecycle shape of the approximately 670--700k TPS candidate while
keeping the newer executor, signature, coding, ingress, deployment, and QMDB hot-path improvements.
The local final-tree cadence has substantial storage/application headroom, but only a fresh cluster
can establish WAN throughput and leader stability.

## Steady-state lifecycle

```text
Marshal finalizes block N
          |
          v
Stateful processing actor (sole finalization owner)
          |
          +--> quiesce/reclassify verification work crossing N
          |
          +--> obtain N's exact merkleized batch
          |      |
          |      +--> reuse proposal/verification/replay result when present
          |      `--> reconstruct once with Application::apply only when absent
          |
          +--> DatabaseSet::apply(batch N)
          |      |
          |      +--> full QMDB apply_and_flush -------------------+
          |      |      +--> journal append -----------+           |
          |      |      `--> index + bitmap update ----+ join      | join
          |      |                                                |
          |      `--> compact QMDB apply_and_flush ---------------+
          |             `--> compact apply includes witness append
          |
          +--> Application::finalized(N) with read-only DB handles
          +--> publish N as the processed logical anchor
          +--> Exact acknowledgement to Marshal
          |
          `--> admit the next actor message / finalized block

Only when retained recovery history is about to be pruned:

          quiesce replay/verification work
          -> DatabaseSet::finalize()
          -> await every durability handle
          -> advance durable replay metadata
          -> prune QMDB and Marshal history
```

The per-block flush writes memory-resident authenticated-Merkle state through the storage layer but
does not call `sync` and is not a crash-durability claim. It bounds buffered memory and keeps writes
moving continuously. The separate prune barrier is the point at which persistence is mandatory.

New actor messages do not enter proposal or verification while finalized database apply/flush owns
the write boundary. A verification that was already executing may continue only when its parent is
proven to be on the finalized branch. Its branch-local batch remains valid as applied state advances
along that same branch, and the database-set lock prevents it from observing a half-published apply.
All other live verification work is retried before application execution or rejected as an
incompatible branch. This preserves the branch-compatible verifier scheduling already present in the
approximately 670--700k TPS candidate without admitting new work across the physical write boundary.

## Avoiding duplicate block execution

Proposal and verification are distinct, request-owned consensus operations. Each accepted request
uses the same staged application execution path, and its merkleized result is cached by exact block
digest. Multiple independent verification requests are not allowed to share a verdict, but a later
request can accept state already cached for the same digest without executing the application again.

Actor-driven finalization preserves an already-running compatible verification instead of cancelling
and restarting its application work. A request still acquiring ancestry may be retried before it
enters the application. Caller cancellation can abandon an in-progress attempt, so the lifecycle does
not claim a global exactly-once guarantee for arbitrary cancelled requests.

Finalization is not another normal execution pass. It consumes the cached winner and applies that
sealed batch to storage. When restart, cancellation, or out-of-order delivery leaves required state
missing, replay has one owner per exact digest and all other consumers wait for that flight. Supplying
valid state from proposal, verification, or another completed replay wakes the waiters and prevents a
stale replay from publishing.

```text
proposal request N  -- Application::propose --+
                                                  +--> exact batch cache[N]
verification N      -- Application::verify ------+
replay N    -- one shared Application::apply fallback, only if state is missing

finalize N  -- consume cache[N] -> physical apply + non-durable flush
```

A verifier that falls behind shares missing-ancestor reconstruction by exact digest, then verifies
its requested block against the rebuilt pending batch. Concurrent descendants wait on the same replay
flight, and subsequent blocks fork from its cached result. Flush never invokes proposal,
verification, or replay. Finalization invokes `Application::apply` only for the explicit
missing-winner recovery case.

Verification verdicts remain request-owned; one caller never borrows another caller's verdict. No
signed vote is retransmitted. Marshal retains the existing acknowledgement window rather than hiding
slow followers by widening consensus admission.

## Recovery and durability

Let `D` be the last durable database replay base, `P` Marshal's processed height, and `A` Stateful's
applied/acknowledged anchor. During normal operation:

```text
D <= P <= A
A - P <= 1 only during the brief publish-before-acknowledge step; otherwise P == A
A - D may span multiple finalized blocks while retained Marshal history is replayable
active physical finalization writers = 1
```

An Exact acknowledgement proves that both databases completed apply and non-durable flush, the
application's finalized hook completed, and Stateful published the new anchor. It does not claim that
QMDB has fsynced that block.

Finalized Marshal history is the recovery authority above `D`. On restart, Stateful rewinds to the
durable base and replays the retained finalized suffix. Before pruning could remove any part of that
suffix, the actor starts database durability, awaits all handles, advances the durable replay base,
and only then prunes. This permits many non-durable applied blocks without making any of them
unrecoverable. Startup replay also runs each replayed block's application finalized hook. Marshal
redelivery acknowledges that reconstructed suffix without running those hooks a second time; a
state-sync anchor that was not replayed still receives its hook on redelivery.

A mutable database operation consumes its database handle. Failure or cancellation after ownership
is taken is therefore supervised as a process/recovery boundary, not retried against possibly partial
state. The paged-writer flush path used by this boundary separately guarantees that cancellation
during its physical write does not advance or mutate its logical buffer before the write completes.

## Why the QMDB optimization is bounded

Within one `apply_batch`, QMDB owns three disjoint resources:

```text
journal log             <- append batch operations asynchronously
snapshot + bitmap       <- apply exact index changes on the strategy pool
root/floor/key metadata <- publish only after both operations join successfully
```

The spawned index job cannot outlive the call. There is no queue of future blocks and no alternative
database view. A journal failure is fatal and consumes the database, so publishing or rolling back a
partially updated object is impossible. The compact database keeps its existing asynchronous apply
contract because applying its batch also appends the compact witness; it is still awaited by the same
database-set boundary.

The application-side staged reads reduce redundant QMDB probes for both proposal and verification.
They retain ordinary QMDB batch ancestry and actor-fenced database handles; they do not snapshot or
clone the full million-account index.

## High-level validation

The local tests exercise lifecycle blocking and recovery, not just leaf microbenchmarks:

- Finalized apply is proved to run on the processing actor with no detached flusher task.
- Newly admitted proposals and verifications are held outside the application until finalized apply
  and flush finish; an already-running compatible verification is proved to remain branch-valid.
- Consecutive finalized batches apply, flush, run hooks, and acknowledge in FIFO order.
- A later finalization cannot pass the prior finalized hook.
- Exact-digest replay has one owner and waiters; a valid supplied result cancels stale publication.
- Finalization reuses the winner without re-executing the application; missing winners reconstruct
  once and must match the block's committed roots.
- Durability starts only for a prune boundary, and pruning cannot begin before its barrier resolves.
- Cancellation, crash/restart, full outage, lossy network, late state sync, and recovery replay are
  covered by the full integration suites.
- Startup replay followed by Marshal redelivery is proved to run the application finalized hook
  exactly once per block.
- The deployed 24 MiB proposal passes block codec, whole-message resolver, and coding round trips.
  The 2 MiB bound is tested as a coded-shard ceiling, independent of the 32 MiB whole-message limit.

On the final tree, the complete Constantinople suite passed 301 tests. The targeted Commonware
runtime, storage, consensus, glue, and deployer suites passed 5,043 tests, along with formatting,
documentation, Clippy, and package builds.

## Final local capacity result

The production-shaped cadence run used one million accounts, 170,000 transfers per block, three
Tokio workers, 20 execution workers, both full and compact QMDBs, and a one-block physical apply
queue. Signatures were disabled so the result isolates application and storage cadence rather than
double-counting the separately validated signature backend.

```text
build/merkleize mean       37.845 ms
QMDB apply/flush mean      21.825 ms
drained block cadence      59.689 ms
drained throughput          2,848,077 TPS
maximum apply backlog       1
prune-boundary durability  22.973 ms
```

At 170,000 transfers per block, 750k TPS permits about 226.7 ms per block. The measured local
application/storage path consumes about 59.7 ms, leaving roughly 167 ms for signatures, coding,
consensus, and WAN delay. This is evidence that QMDB is no longer the throughput limiter on the local
path; it is not a claim that an EC2 cluster must achieve 2.85M TPS.

The exact AMD/c8a validator release artifact also builds successfully in the deployment container
with the Commonware checkout mounted at the path used by Cargo.

## Deployment bounds and acceptance

The deployment remains on `c8a.8xlarge` (32 vCPUs) with 3 Tokio workers, 20 core Rayon workers, and
9 isolated ingress/signature workers. It uses io2 storage without requiring per-block fsync. The
configured proposal budget is 25,165,824 bytes; the coded-shard ceiling is 2 MiB; and the P2P
whole-message ceiling is 32 MiB.

A fresh-cluster run is still required before calling the 750k target achieved. Acceptance should be
based on the following together:

- a stable leader rather than rapid view rotation;
- sustained TPS above 750k after warmup;
- followers remaining close to the leader and catching up without duplicate application work;
- one ordered finalization at a time, with apply/flush and finalized-hook traces draining well inside
  the block cadence;
- bounded RSS and no monotonic pending-state growth;
- no processed-height stalls, invalid-nonce storm, storage errors, or durability/prune inversion; and
- the expected optimized Ed25519 backend on c8a.

If the cluster misses the target while these lifecycle conditions remain healthy, the next tuning
step should follow the dominant live trace span (signature verification, execution, coding, or WAN
consensus) rather than introducing another storage ownership pipeline.
