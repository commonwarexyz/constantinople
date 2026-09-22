# `constantinople-validator`

Validator binary for the constantinople blockchain.

Generated validator YAML accepts `handoff_mode: baseline` (the default),
`handoff_mode: build_only`, or `handoff_mode: build_and_broadcast`. Use the same
mode across the cluster for a controlled comparison. `build_and_broadcast`
trusts outgoing leaders not to equivocate.
