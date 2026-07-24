# Constantinople Engine

Assembly for the full Constantinople validator stack.

This crate wires together:

- `constantinople-application`
- `commonware-glue::stateful` for speculative execution and QMDB state sync
- `commonware-glue::dkg` for epoch orchestration and continuous resharing
- erasure-coded marshal
- simplex consensus
- address-bearing lookup peer sets

Production runs in 64-block epochs. A dedicated committee QMDB implements the
DKG participant and address providers, carrying the previous committee forward
when an epoch has no explicit row. Finalized transactions can add or remove
validators from the next mutable future committee; the final two blocks freeze
that state before DKG reads it. Nodes without a genesis share follow as
secondaries, state-sync the application and DKG artifacts, and receive a share
when a later reshare promotes them.

The included disk-backed DKG secret store is intentionally naive plaintext
bootstrap infrastructure. It uses restrictive permissions and atomic writes,
but it is not production-grade secret management.

The engine is runtime and network-agnostic. Tests can run it under the
deterministic runtime and simulated networking, while production can supply a
real runtime and transport.
