# Constantinople Engine

Assembly for the full Constantinople validator stack.

This crate wires together:

- `constantinople-application`
- `commonware-glue::stateful`
- erasure-coded marshal
- simplex consensus

The validator set is fixed at startup from a supplied list of public keys, and
tolerates `f` faults among `n >= 5f + 1` validators. There is no epoch
orchestrator.

A transaction is authenticated by a signature or by tags: its sender shares a
key with every validator and sends one short tag for each to the validator that
is to propose it. The proposer sends each validator its tags for a block on a
separate channel, and a validator's vote for the block reports which tags
match. The next block carries those votes, and its transactions of the block
before it are applied according to them.

The engine is runtime and network-agnostic. Tests can run it under the
deterministic runtime and simulated networking, while production can supply a
real runtime and transport.
