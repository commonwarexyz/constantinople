# `constantinople-mempool`

High-throughput transaction sourcing for `constantinople`.

This crate keeps the consensus integration intentionally narrow: validators hand
it to the application as a `TransactionSource`, and the mempool returns verified
transactions for proposals while learning about included or rejected hashes from
finalized blocks.

## Design

The mempool is built around a small FIFO core:

- hash lookup for idempotent duplicate detection before capacity checks
- a ready queue for FIFO proposal order
- in-flight lease batches so retries reuse the exact same proposed transactions
- lazy tombstones instead of middle-of-queue removals
- recent terminal status caching for included and rejected transactions
- waiter registration for long-poll style clients

Lease expiry retries the same in-flight batch directly instead of dropping those
transactions back into the ready queue as new work. This keeps retries stable
while making finalize and reject paths O(k) in the number of resolved hashes.

## HTTP API

The router exposes both compatibility routes and hot-path batch routes:

- `POST /tx` submits one hex-encoded transaction and waits for a terminal result
- `POST /tx/accept` submits one hex-encoded transaction and returns immediately
- `POST /tx/status` returns point-in-time statuses for a list of hashes
- `POST /tx/accept_batch` accepts concatenated binary transaction bytes
- `POST /tx/wait_batch` long-polls a hash batch until it becomes terminal or times out

The batch accept route expects `application/octet-stream` input containing the
usual transaction encodings concatenated back-to-back. The batch wait route is
JSON-based and returns statuses in the same order as the requested hashes.
