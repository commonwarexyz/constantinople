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

The relayer sends normal user submissions to the foreground endpoint and pinned
spammer batches to the background endpoint.
