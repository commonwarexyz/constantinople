# Transfer-Only Simplification Plan

## Goal

Reduce `crates/application` and `crates/primitives` to a transfer-only chain.

The new model should support only simple value transfers:

- transactions move non-zero value from `sender` to `to`
- execution mutates account balances and sender nonces
- there are no access lists
- there is no account storage
- there are no precompiles
- there are no callframes

Breaking changes are acceptable. This should be treated as a rebuild of the
execution model, not a compatibility refactor.

## Status

This plan is complete.

The implementation followed the original transfer-only simplification plan and
also incorporated the later design change that removed transaction receipts.
That means the final model is slightly simpler than the earlier sections below:

- blocks finalize only `state_root` and `transactions_root`
- transactions do not emit receipts
- proposers filter invalid transactions before block construction
- verifiers reject blocks containing any statically invalid transaction

## Target Model

### Transactions

Transactions become:

- `sender`
- `to`
- `value: NonZeroU64`
- `nonce`

Transactions no longer contain:

- `input`
- declared access lists

### Blocks

Blocks become:

- `header`
- `body`

Blocks and headers no longer contain:

- block access lists
- block access list hashes

### State

Chain state becomes account-only:

- `Account { balance, nonce }`

State no longer contains:

- storage slots
- storage values
- storage writes

## What To Delete

### `crates/primitives`

Delete these concepts entirely:

- `AccessMode`
- `Access`
- `AccessList`
- `BlockAccessList`
- `AccountWrite`
- `StorageWrite`
- `Slot`

Collapse these types:

- `Transaction` loses `input` and uses `NonZeroU64` for `value`
- `Header` loses `block_access_list_hash`
- `Block` loses `access_list`
- `BlockCfg` loses BAL decoding config

Strong recommendation:

- remove `StateValue`
- store `Account` directly in the state database

`StateValue` exists today to support the account-or-storage split. Once
storage is gone, the enum becomes unnecessary indirection.

### `crates/application`

Delete these modules or concepts:

- `processor::Precompiles`
- `processor::frame`
- `processor::access`
- BAL proposal and BAL verification paths
- final-write verification against declared BAL state

Rewrite these parts around transfer-only execution:

- `processor::executor`
- `processor::schedule`
- `processor::state`
- consensus state loading and block application

## New Execution Model

Execution should become a direct account transfer engine.

For each transaction:

1. load sender account
2. load recipient account
3. verify sender nonce
4. verify sender balance can cover `value`
5. increment sender nonce
6. debit sender balance
7. credit recipient balance

There is no nested execution, no calls, and no revertible subframes.

### Validation

Recommendation:

- keep `validate()`
- make it track both pending nonces and pending balances per sender

In a transfer-only world, allowing obviously overspending transactions through
static validation only to revert later adds noise without buying flexibility.

## New Scheduler

The scheduler can be reduced to inferred write conflicts.

Each transaction writes exactly two logical accounts:

- `sender`
- `to`

Scheduling rule:

- two transactions may run in parallel only if they do not share either
  logical account

That means:

- no read/write mode tracking
- no storage conflict tracking
- no observed-vs-declared access comparison
- no access-list discovery pass

The scheduling implementation can stay greedy and round-based, but the inputs
become much smaller and easier to reason about.

## Consensus Changes

Consensus should stop carrying execution hints in blocks.

### Proposal

Proposal should:

1. validate candidate transactions
2. execute them with the transfer-only processor
3. write resulting account changes to the speculative state batch
4. finalize state root and transaction root
5. build a block from `header + body`

### Verification

Verification should:

1. verify signatures
2. verify timestamp rules
3. preload accounts referenced by transaction senders and recipients
4. re-execute the block with the transfer-only processor
5. compare derived roots and ranges against the header

### Certified Apply

`apply()` should no longer trust declared final writes from the block.

Instead:

1. verify the block signatures
2. reconstruct verified transactions
3. re-execute the block
4. write the resulting account changes
5. merkleize

This is simpler and removes BAL-specific trusted data from the block format.

## State Loading

Replace BAL-driven preload with transaction-driven preload.

Old model:

- preload every account and storage key declared in the block access list

New model:

- collect unique `sender` and `to` addresses from the block body
- load only those accounts

If `StateValue` is removed, the state loader becomes simpler as well because it
no longer needs to distinguish account keys from storage keys.

## Downstream Breakage

This change propagates beyond `application` and `primitives`.

### `crates/engine`

Remove the `Precompiles` generic and all wiring that carries it through the
engine and tests.

### `crates/mempool`

Update transaction decoding and any size assumptions for the new transaction
format.

### Tests and Benches

Replace the current processor harness and benches, which are heavily built
around:

- access lists
- storage reads and writes
- precompile calls
- nested execution

The new harness should be account-only and focused on transfer semantics and
parallel conflict behavior.

## Recommended Revision Split

This work should be split into small but meaningful revisions.

### Revision 1: simplify primitives

- remove access-list and storage-related primitive types
- update transaction, block, and codec configs
- update primitive tests

### Revision 2: replace processor with transfer-only executor

- delete frame/precompile/access modules
- simplify state to accounts only
- implement inferred-conflict scheduling
- replace processor tests

### Revision 3: simplify consensus execution flow

- remove BAL hashing and verification
- replace BAL-driven preload with transaction-driven preload
- make `apply()` re-execute
- update consensus tests

### Revision 4: repair downstream crates

- remove `Precompiles` from engine plumbing
- update mempool decoding and tests
- rewrite processor benches
- update docs and READMEs

## Test Plan

Add or rewrite tests around the new model.

### Primitive tests

- transaction codec roundtrip without `input`
- zero-value transaction is invalid
- block codec roundtrip without access-list payloads

### Processor tests

- valid transfer succeeds
- invalid nonce is rejected
- insufficient balance is rejected
- self-transfer behaves correctly
- repeated same-sender transactions respect nonce and balance sequencing
- shared sender conflicts
- shared recipient conflicts
- disjoint transfers can execute in parallel
- overflow and underflow are rejected safely

### Consensus tests

- proposal, verification, and apply derive the same roots
- malformed blocks are rejected under the new transaction/block format
- state preload loads only sender/recipient accounts

## Implementation Notes

- Prefer early returns and obvious control flow.
- Keep the new processor surface small.
- Do not preserve compatibility layers for removed concepts unless a concrete
  downstream caller requires one temporarily.
- If `commonware_codec` support for `NonZeroU64` is awkward, introduce a small
  newtype wrapper rather than weakening the model back to plain `u64`.

## Summary

The simplification should remove most of the current execution complexity:

- no access-list declarations
- no access-list discovery
- no storage
- no precompiles
- no callframes
- no BAL verification
- no BAL final-write application

What remains is a small transfer engine with deterministic account loading,
simple inferred scheduling, and straightforward consensus re-execution.
