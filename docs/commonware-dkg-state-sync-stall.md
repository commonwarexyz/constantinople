# Commonware DKG Late-Join State-Sync Stall

Status: baseline late join resolved; failed-ceremony combination unresolved  
Observed against Commonware `cl/dkg-peer-manager` at `ce9746e8d4b7cf4ab10f9d09c31002a8761ff5b0`  
Recorded: 2026-07-23

## Summary

Constantinople's continuously running validator scenarios are green: stable
resharing, committee additions and removals, failed-ceremony carry-over, and
restart immediately before or after an epoch boundary. A focused cold late-join
scenario is also green: an unknown validator is registered by transaction,
starts in `StateSync` only after it is announced as a next player, restores the
committee database, receives a reshared threshold share, and finalizes after
activation.

The remaining unresolved case combines that late join with a prior failed DKG
ceremony. It has not been reduced to a confirmed production bug. There is still
evidence that an already-running validator can wait indefinitely at the
DKG/orchestrator fence, so a core reshare or state-sync liveness issue has not
been ruled out.

Generated indexer and relayer service nodes start as persistent bootstrap
secondaries. Separately, `generate-validator` creates a genuinely post-genesis
identity for the now-covered cold state-sync path.

## Intended scenario

The attempted test combined the following:

1. Start a genesis committee and additional eligible future validators.
2. Force one DKG ceremony to fail by filtering that ceremony's DKG messages.
3. Carry the previous threshold output across the failed ceremony.
4. Start a future validator late, causing `EngineDefinition::init` to select
   `StartupMode::StateSync`.
5. State-sync the validator before it is selected for activation.
6. Complete a later successful reshare and observe the late validator operating
   as a signer in its selected epoch.

The branch's own reshare harness has a closely related failure/recovery test in
`commonware/glue/src/dkg/tests/reshare/mod.rs`, but Constantinople additionally
uses the addressable lookup peer manager and a stateful application with three
QMDBs.

## What was observed

- In one deterministic trace, all four original validators finalized the first
  boundary, but only three entered the next epoch. The lagging original
  validator was already stuck before the delayed validator started, so the
  filtered later ceremony alone did not explain the lag.
- The lagging validator waited in the orchestrator's epoch transition for the
  DKG fence. The fence advances only after reshare commits the finalized epoch
  artifact and registers the corresponding scheme.
- While `enter_epoch` waited on the fence, the orchestrator's outer receive loop
  was not servicing backup traffic. Backup/mux queue warnings followed, but
  increasing mux capacity would only delay those warnings; it would not advance
  the fence.
- The simulated manager logged duplicate peer-set registrations because every
  validator registers the same epoch ID against one shared manager.
- A delayed validator attempted to register bootstrap peer-set ID 0 after the
  shared manager had advanced to ID 1. The global monotonic-ID check rejected
  that registration. A real lookup network gives each validator its own local
  manager, so this behavior is not representative of production.
- The combined scenario eventually reached the deterministic timeout rather
  than its target activation epoch.

No standalone trace artifact was retained. These observations came from the
deterministic test logs and targeted instrumentation used while implementing
the integration.

## Harness problems already fixed

Several genuine Constantinople test-harness problems were found and corrected
before the remaining scenario was set aside:

- The local deterministic plan now configures eight retained peer sets and
  seeds distinct genesis primary and secondary sets. See
  [`crates/engine/src/tests/plan.rs`](../crates/engine/src/tests/plan.rs).
- Validator initialization returns its state before waiting for the committee
  database attachment, so starting a delayed validator no longer blocks the
  simulator's control loop.
- Tests use shorter Commonware-style Simplex timeouts rather than production
  timing.
- Exit conditions require progress from the intended committee instead of all
  active observer processes.
- Crash holds use processed-height thresholds and the restart-before/restart-
  after cases run independently.
- Eligible validators are kept as persistent lookup secondaries in production.

These fixes made the baseline delayed resharing scenario deterministic and
green. The failed-ceremony-plus-late-join combination remains set aside pending
the upstream simulator and fence work below.

## Current green coverage

[`crates/engine/src/tests/dkg_integration.rs`](../crates/engine/src/tests/dkg_integration.rs)
currently covers:

- seven validators crossing three epoch boundaries without committee changes;
- two E+2 committee rotations across four boundary artifacts;
- addition and removal of validators with exact lookup primary/secondary
  tracking checks;
- a failed DKG ceremony carrying the prior threshold state and committee
  lookahead;
- restart immediately before and immediately after an epoch boundary, including
  recovery of the persisted DKG share.

[`crates/engine/src/tests/late_peer.rs`](../crates/engine/src/tests/late_peer.rs)
covers a validator absent from the genesis DKG and bootstrap directory. It
starts after the registration is finalized and the epoch-1 artifact announces
it, state-syncs all application databases, becomes an active dealer in epoch 3,
and persists its new share.

These tests use the real Constantinople engine actor graph, stateful QMDBs,
marshal, reshare, orchestrator, and deterministic P2P transport. They do not
yet cover a no-history process joining after a failed ceremony.

## Leading hypotheses

### 1. Shared simulated peer-set state

Confidence: high that this invalidates the current reproduction.

`glue::simulate::PlanBuilder` creates one simulated network and currently fixes
`tracked_peer_sets` to one. Its oracle exposes a shared, monotonic peer-set
registry. Identical registrations from multiple validators are treated as
duplicates, and a delayed validator cannot independently bootstrap ID 0 after
another validator has registered ID 1.

The simulator should either model one peer-set manager per validator or make
identical same-ID registrations idempotent while preserving validator-local
bootstrap semantics. `PlanBuilder` should also expose tracked-set retention and
initial primary/secondary topology.

### 2. Fence cannot advance after missing local ceremony state

Confidence: plausible, not isolated.

The already-running validator that remained in the previous epoch suggests a
second problem may exist. If a node sees the finalized failure/carry-over
artifact but lacks some local ceremony outcome, reshare may fail to commit the
artifact, register the carried scheme, or advance the fence. The relevant flow
is:

1. marshal reports the finalized boundary block;
2. reshare validates and commits its `EpochInfo`;
3. the registrar installs a signer or verifier for the artifact epoch;
4. reshare advances the fence;
5. orchestrator completes `enter_epoch`.

Instrumentation is needed at every transition to determine which step is
missing. Queue saturation after the wait is a symptom, not a root cause.

### 3. The delayed participant was started too early

Confidence: confirmed issue in the original combined fixture.

One attempted fixture delayed a validator intended to join epoch 3 at the
epoch-1 midpoint, before the current artifact named it in either `players` or
`next_players`. A corrected test should start that validator only after it is
announced as a next player, or should delay the validator selected for the
earlier transition.

## Suggested upstream reproduction

Add a focused Commonware test before restoring the Constantinople scenario:

1. Extend `glue::simulate::PlanBuilder` with:
   - configurable `tracked_peer_sets` (at least four for this test);
   - separate initial primary and secondary participants;
   - validator-local peer-set tracking, or equivalent delayed-bootstrap
     semantics.
2. Split the behavior into three tests:
   - delayed future player with every ceremony successful;
   - failed ceremony with every validator already running;
   - failed ceremony followed by a delayed future player's state sync.
3. Start the delayed validator only after an artifact announces it in
   `next_players`, but before its activation ceremony needs it online.
4. Record, per validator and epoch:
   - accepted `manager.track` calls and feedback;
   - selected state-sync floor and `EpochInfo`;
   - reshare artifact validation and durable commit;
   - registrar calls and whether signer or verifier material was installed;
   - fence advancement;
   - orchestrator entry and completion;
   - recovered share presence in the secret store.
5. Assert that the delayed validator obtains the selected floor, reconstructs
   the carried threshold state after failure, participates in the later
   ceremony, and finalizes blocks after activation.

If the scenario passes with validator-local simulated managers, the stall was a
test-infrastructure artifact. If an already-running validator still waits on the
fence, reduce the failure to the reshare/orchestrator harness and inspect the
artifact commit and registrar paths before changing Constantinople.

## Acceptance condition for closing this note

Restore a deterministic Constantinople E2E in which a process with no local
chain or DKG history:

- starts after at least one epoch boundary;
- state-syncs all three application QMDBs and the DKG artifact;
- survives a prior failed ceremony with the previous threshold state carried
  forward;
- is announced before its activation ceremony;
- receives a valid signer share; and
- finalizes blocks after joining the active committee.

The test must verify accepted peer-set registrations, not only attempted calls,
and must pass without increasing queue capacities to hide a blocked fence.
