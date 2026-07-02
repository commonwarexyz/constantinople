# `constantinople-application`

Consensus-facing application: the transfer executor and the payment-channel lane.

The crate is intentionally small:

- `executor` owns deterministic account transitions (transfers).
- `consensus` adapts the executor to `commonware_glue::stateful`, and runs the
  payment-channel lane (`consensus::channel`) alongside it.
- `operator` is the off-chain channel operator used by the demo: it verifies
  vouchers with the same predicate the chain applies at settlement.

Keep this crate direct and performance-oriented. Avoid abstraction layers unless
they remove real hot-path complexity.
