# `constantinople-application`

Consensus-facing application and transfer executor.

The crate is intentionally small:

- `executor` defines how a transaction settles, as a `commonware_glue::transfers`
  transfer over Constantinople accounts.
- `consensus` adapts the executor to `commonware_glue::stateful`.

Keep this crate direct and performance-oriented. Avoid abstraction layers unless
they remove real hot-path complexity.

Each accepted transaction consumes one history position for its sender and
recipient, or one shared position for a self-transfer. Count increments use the
same Glue account effects as nonce consumption. Exhausting either count rejects
the entire transfer; proposal selection rolls back all of its effects before
trying the next candidate.

After settlement, a reverse pass over the accepted body derives both history
indices from the final account counts. Every accepted participant has a `Put`
slot because its count increased. The pass uses these slots without additional
database reads or writes and ignores accounts touched only by dropped candidates.
The compact keyless history database appends the resulting entries in block order
while the state database merkleizes. Finalized capture retains the exact appended
operations and their authenticated root.
