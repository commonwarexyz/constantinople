# Native explorer fixtures

The explorer tests read three native exports: `proofBundle.json`,
`transactionActivityProof.json`, and `blockFeed.json`. Set
`EXPLORER_FIXTURE_DIR` to an absolute directory containing those exact names to
verify a freshly generated set:

```sh
EXPLORER_FIXTURE_DIR=/absolute/path/to/fixtures just explorer-test
```

An override is strict: missing or malformed files fail, as do proof fixtures
without `writeHeight`, current account update operations, participant indices, the
oldest/exhausted account bundles, the default account balance, or the complete 48-byte history
values. The override never falls back to
the checked-in files.

The checked-in proof fixtures predate account counts: their account values are
24 bytes and their transaction-history values are 32-byte digests. Those bytes
cannot verify the account32/history48 format. Without an override, affected
account, transaction, block and standalone history-proof tests explicitly report
skips with the incompatible field in the reason. Pure account-page, wire/transport,
header and certified block-feed tests continue running. A passing run with those
skips does not establish native account/history proof compatibility.

`just explorer-fixtures <dir>` exports all three from this checkout's indexer tests,
the same way CI does before it runs the explorer tests:

```sh
just explorer-fixtures /absolute/path/to/fixtures
```

It runs `publisher_bundles_cover_descendants_empty_blocks_and_fixed_account_pages`,
`historical_transactions_below_inactivity_floor_remain_available`, and
`bootstrap_and_resume_ignore_sql_counts_and_preserve_advancing_floors` with
`EXPLORER_FIXTURE_PATH`, `EXPLORER_ACTIVITY_FIXTURE_PATH`, and
`EXPLORER_FEED_FIXTURE_PATH` pointing into the directory.

`proofBundle.json` preserves real publisher/indexer certificates, headers, proofs,
and signed transaction bodies. It also carries the chain's `defaultAccountBalance` as a decimal
string, which the wallet shows for an account with no stored state. A test asserts the explorer's
constant against it. Each account update has `location`, `proof`, and
`writeHeight`, plus the `encodedOperation` its proof authenticates: the account's
active fixed unordered update at the certified root. Transaction rows carry decimal-string `senderIndex` and
`recipientIndex` values; the proof commits to the transaction digest followed by
those two big-endian u64 indices. Account values encode balance, nonce, nonce
bitmap and transaction count as four big-endian u64 values.

The native account fixture has count 58. Its first page contains the self-transfer
once, with equal participant indices and the sent role. Participant-based filters
include that same row once in both sent and received views. `accountNext` continues
at exclusive index 8, `accountOldest` starts at 3, and `accountExhausted` starts
at 0. Cursors are eight-byte big-endian exclusive indices.
Continuation requests retain the first page's certified height/digest, account
location and authenticated transaction count.

`transactionActivityProof.json` contains a SHA-256 MMR multiproof generated from
native transaction-history operations. Every `operations[].value` is the full
48-byte encoded history entry, including both indices. The browser verifies
those values directly and never reconstructs the proof from digest-only legacy
fixtures. `blockFeed.json` carries certified header chains; feed tests derive
expected block digests by independently hashing the raw headers rather than
pinning roots that change with the history format.

The native account tests run the application-specific fixed account WASM verifier;
they reject changed request keys, another account's operation, root replay,
malformed proofs and missing or truncated operations.
