# DKG Committee Lookahead Stall

Status: resolved production liveness incident  
Recorded: 2026-07-24

## Summary

A local production-style cluster stopped making progress at the second epoch
boundary. One validator had processed only through height 125, another stopped
after 253, and the remaining nodes reached 254. The chain did not finalize
height 255 or begin height 256.

The cause was a self-deadlock in the DKG reshare actor. While building or
verifying a final-epoch block, reshare handled an `EpochInfo` request inline and
asked the application for the committee at `E+2`. The committee provider waited
for marshal to report the source epoch through `final - 1`. However, advancing
marshal through that height required an acknowledgement from the same reshare
actor, whose mailbox loop was still blocked in the `EpochInfo` request.

This incident is resolved by freezing committee mutations for the final two
blocks of every epoch and reading the committee after the last mutable block,
`final - 2`. The final architecture gates that read on an application-finalized
watermark published after the stateful databases commit, rather than on
marshal's aggregate reporter acknowledgement.

## Failure mechanism

Constantinople uses 128-block epochs. At the end of epoch `E`, the final block
contains the public artifact for `E+1`, including the committee lookahead for
`E+2`. Reshare obtains that lookahead through `ParticipantsProvider`.

Before the fix, the provider waited until marshal's durable processed height
reached `final - 1`. The sequence was:

1. Consensus asked reshare for `EpochInfo` while proposing or verifying the
   epoch's final block.
2. Reshare handled the request inline in its actor loop and called
   `participants(E+2)`.
3. The provider polled marshal until `processed_height >= final - 1`.
4. Marshal could not advance to `final - 1` until all clones of that block's
   acknowledgement completed.
5. One clone belonged to reshare, but reshare could not process the queued
   finalized-block notification while blocked in the `EpochInfo` handler.

The durable state matched this dependency exactly. The validator that never
entered epoch 1 stopped at 125 while the lookahead waited for 126. At the next
boundary, another validator stopped at 253 while the lookahead waited for 254.
Those are cutoff-minus-one stalls, not random consensus timeouts. With the
first validator already absent and the second blocked, the remaining committee
could not finalize height 255 and start height 256.

## Fix and invariant

Committee mutations are now accepted only through `final - 2`. The penultimate
and final blocks reject committee transactions, so the committee is immutable
before reshare requests its lookahead. For 128-block epochs, the last mutable
heights are therefore:

- 125 for the epoch ending at 127;
- 253 for the epoch ending at 255;
- 381 for the epoch ending at 383;
- and the corresponding `128n + 125` height thereafter.

This is an externally visible transaction rule: a committee transaction that
would otherwise be valid is rejected in an epoch's penultimate or final block.
Clients should submit committee changes before that two-block freeze window.
The reducer and execution checks enforce the rule; see
[`crates/application/src/consensus/execution.rs`](../crates/application/src/consensus/execution.rs)
and its consensus tests.

The provider cutoff is now `final - 2`; see
[`crates/engine/src/dkg.rs`](../crates/engine/src/dkg.rs). More importantly, it
does not infer application readiness from marshal's aggregate acknowledgement.
Stateful publishes an application-finalized watermark after the finalized
batch has committed to every managed database. The watermark is published
before any optional external finalized hook runs, so indexer or other hook
latency cannot delay DKG committee reads. Reshare gates its database read on
that watermark. This preserves the required invariant:

> An `E+2` committee read may begin only after the last height capable of
> mutating that committee has committed to the application database.

It also removes the circular dependency on the aggregate marshal
acknowledgement, which covers reshare, orchestrator, stateful, and external
reporters together and is not an application-commit signal.

## Validation

Deterministic integration tests now require progress through `boundary + 1`,
not merely finalization of the boundary block. That assertion verifies that the
next epoch's actor, scheme, and application path are actually live.

The first real-cluster run after moving the committee cutoff passed the original
failure points: all four validators crossed 127/128, 255/256, and 383/384, and
the chain reached height 424.

A second four-validator run exercised the final application-watermark
architecture. Every validator entered epochs 1, 2, and 3, agreed at all three
boundary transitions, and reached height 421. The run produced no error-level
events, panics, or fatal failures. Together these runs validate both the
freeze-window correction and the final removal of marshal acknowledgement state
from the committee-read dependency.

## Commonware follow-up

The investigation also identified a separate orchestrator lifecycle hazard.
When crossing an epoch boundary, the orchestrator should abort the old epoch
actor before awaiting the readiness gate or spawning its replacement. Keeping
the old actor alive while awaiting replacement can retain resources and
complicate blocked-transition behavior.

Current upstream examples and end-to-end configurations use
`max_pending_acks = 1`. They therefore do not exercise the multi-ack scheduling
that exposed this failure, and there is no Tokio test that delays the epoch gate
while multiple marshal acknowledgements are in flight. Upstream coverage
should add that delayed-gate, multi-ack case in addition to fixing the actor
replacement ordering.

## Scope

This resolved incident concerns continuously running validators and committee
lookahead at ordinary epoch boundaries. It is distinct from the unresolved
[Commonware DKG late-join state-sync stall](commonware-dkg-state-sync-stall.md),
which concerns a cold future validator starting without local history. Evidence
or fixes for this lookahead deadlock do not close that late-join issue.
