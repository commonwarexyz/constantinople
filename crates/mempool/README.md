# `constantinople-mempool`

Transaction sourcing for Constantinople validators.

The webserver mempool keeps separate foreground and background queues. Background
traffic can fill the pool up to its configured limit minus one maximum proposal.
That reservation lets interactive submissions enter under sustained background
load. Queued foreground transactions consume the reservation. The pool limit
must exceed the proposal limit so background submissions have capacity.
Proposals take foreground transactions first, then fill remaining space
from the background queue. Each queue preserves arrival order.

| Endpoint | Queue | Response |
| --- | --- | --- |
| `POST /transactions` | Foreground | Waits for a terminal transaction status. |
| `POST /transactions/background` | Background | Waits for a terminal transaction status. |
| `POST /transactions/ingest` | Foreground | Returns after admission. |
| `POST /submissions` | Foreground | Waits for a terminal transaction status. |
| `POST /submissions/background` | Background | Waits for a terminal transaction status. |

The relayer sends normal user submissions to the foreground endpoint and pinned
spammer batches to the background endpoint.

The `/transactions` endpoints take signed transactions and verify the
signatures. The `/submissions` endpoints take transactions of X25519 accounts,
which carry no signature. Each comes with one tag per validator and a MAC, all
computed for this validator as proposer. The validator pools a submission if
the MAC and its own tag are right. Tags for one validator are of no use to
another, so the relayer forwards a submission to the validator it names and to
no other.

A block's transactions execute with the next block, so a status is terminal
once the block after the one that lists the transaction is finalized:

| Status | Meaning |
| --- | --- |
| `finalized` | Every transaction of the batch was listed and applied. |
| `partially_finalized` | Some were applied. The rest were not applied or never listed. |
| `rejected` | A finalized block lists the batch and none of it was applied. |
| `dropped` | No transaction of the batch reached a finalized block. |

A proposed transaction that reaches no finalized block is dropped if it is
signed. A tagged one returns to the pool, up to three times.
