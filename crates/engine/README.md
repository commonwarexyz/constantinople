# Constantinople Engine

Assembly for the full Constantinople validator stack.

This crate wires together:

- `constantinople-application`
- `commonware-glue::stateful`
- erasure-coded marshal
- simplex consensus

The validator set and threshold scheme are fixed at startup from a supplied
threshold output and optional local share. There is no DKG actor and no epoch
orchestrator.

The engine is runtime and network-agnostic. Tests can run it under the
deterministic runtime and simulated networking, while production can supply a
real runtime and transport.
