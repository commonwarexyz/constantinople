// Streaming client for the constantinople indexer (SQL metadata path).
//
// Subscribes to the `block_meta` table over the `store.sql.v1.Service`
// `Subscribe` RPC. Each delivered SubscribeResponse frame carries the
// rows from one atomic ingest batch, and at the indexer's "one flush per
// finalized block" cadence that is exactly one row per finalized block.
//
// The full-storage KV path (BLOCK / BLOCK_BY_H / TX / TX_BY_H /
// FINALIZED / NOTARIZED) is unchanged — fetching a specific transaction
// body or QMDB proof by digest still goes through the indexer's KV
// `StoreClient` at `VITE_INDEXER_URL`. This module only owns the
// metadata stream surfaced via the SQL server at `VITE_SQL_URL`.
//
// Column names mirror `crates/indexer/src/sql_schema.rs` and must stay in
// sync with `BLOCK_META_*` constants there.

import { createTransport, type SqlSubscribeResponse, SqlService } from '@exowarexyz/sdk';
import { Code, ConnectError, createClient } from '@connectrpc/connect';

/** `block_meta` column names (mirror `crates/indexer/src/sql_schema.rs`). */
const COL_HEIGHT = 'height';
const COL_TX_COUNT = 'tx_count';

/** The SQL table the explorer subscribes to. */
const BLOCK_META_TABLE = 'block_meta';

/** Aggregate summary of one finalized block as observed on the live stream. */
export interface ObservedBlock {
    /** Finalized block height the row corresponds to. */
    readonly height: bigint;
    /** Number of transactions contained in the block. */
    readonly txCount: number;
    /** Wall-clock arrival time on this client, in epoch milliseconds. */
    readonly arrivedAt: number;
    /** Underlying store batch sequence number; useful as a stable React key. */
    readonly sequence: bigint;
}

/**
 * Open a streaming subscription to every block newly finalized by the
 * indexer at `sqlUrl`. The returned async generator yields one
 * `ObservedBlock` per `block_meta` row.
 *
 * Transient `OUT_OF_RANGE` errors from the underlying KV stream (see
 * [`isTransientBatchRaceError`]) are caught and the subscription is
 * automatically reopened — they're a documented race against concurrent
 * uploads and reconnecting fresh always recovers.
 */
export async function* subscribeBlocks(
    sqlUrl: string,
    signal?: AbortSignal,
): AsyncGenerator<ObservedBlock, void, void> {
    // The SDK's `createTransport` is the right wire format for the SQL
    // server (Connect-over-HTTP). We pass it to `createClient` because
    // `@exowarexyz/sdk`'s `Client` only exposes compact/ingest/query/stream
    // — there is no high-level wrapper for `SqlService`.
    const transport = createTransport(sqlUrl);
    const sql = createClient(SqlService, transport);

    // Cap consecutive transient retries so a genuinely broken server can't
    // trap us in a tight reconnect loop. A single delivered frame resets
    // the counter.
    const MAX_TRANSIENT_RETRIES = 10;
    let transientRetries = 0;

    while (!signal?.aborted) {
        try {
            const stream = sql.subscribe(
                {
                    table: BLOCK_META_TABLE,
                    // Empty predicate => emit every block_meta row. The
                    // server still applies its own bounded compile budget.
                    whereSql: '',
                },
                { signal },
            );

            for await (const frame of stream) {
                transientRetries = 0;
                yield* decodeFrame(frame);
            }
            // Server-streaming RPC ended cleanly (no more frames). Loop
            // and re-subscribe so the UI keeps following the live tail.
        } catch (error) {
            if (signal?.aborted) {
                return;
            }
            if (
                !isTransientBatchRaceError(error) ||
                transientRetries >= MAX_TRANSIENT_RETRIES
            ) {
                throw error;
            }
            transientRetries++;
            // Brief backoff before reconnecting; the race window is short
            // (commit ordering across the indexer's concurrent uploaders)
            // so a single reconnect almost always succeeds.
            await sleep(250);
        }
    }
}

/**
 * Decode a single SubscribeResponse frame into one `ObservedBlock` per row.
 *
 * The server emits one frame per atomic ingest batch (== one finalized
 * block at the publisher's "flush per block" cadence), so most frames
 * carry exactly one row. We still iterate `frame.rows` defensively in case
 * the server batches rows differently in the future.
 */
function* decodeFrame(frame: SqlSubscribeResponse): Generator<ObservedBlock> {
    const heightIdx = frame.column.indexOf(COL_HEIGHT);
    const txCountIdx = frame.column.indexOf(COL_TX_COUNT);
    if (heightIdx < 0 || txCountIdx < 0) {
        // Server schema diverged from the explorer's compile-time
        // expectations — surface as zero rows so the UI keeps streaming
        // (rather than crashing) until the schema is rolled forward.
        return;
    }
    const arrivedAt = Date.now();
    for (const row of frame.rows) {
        const heightCell = row.cells[heightIdx];
        const txCountCell = row.cells[txCountIdx];
        if (
            heightCell?.kind.case !== 'uint64Value' ||
            txCountCell?.kind.case !== 'uint64Value'
        ) {
            continue;
        }
        // `block_meta.tx_count` is u64; Number() is safe for any realistic
        // block (Number.MAX_SAFE_INTEGER is 2^53 - 1, far above per-block tx counts).
        yield {
            height: heightCell.kind.value,
            txCount: Number(txCountCell.kind.value),
            arrivedAt,
            sequence: frame.sequenceNumber,
        };
    }
}

/**
 * The exoware Store's stream service publishes an in-memory "next published
 * sequence" before each commit lands in its batch_log column family. With
 * the indexer's concurrent uploaders racing the same store, a subscriber
 * that wakes mid-commit can briefly observe `current_sequence` ahead of the
 * batch_log row, and the server returns
 * `OUT_OF_RANGE { reason: BATCH_EVICTED }` instead of waiting. The race
 * window is on the order of milliseconds; reopening the subscription
 * resyncs past it. The SQL service inherits this behaviour from the
 * underlying KV stream.
 */
function isTransientBatchRaceError(error: unknown): boolean {
    return (
        error instanceof ConnectError &&
        error.code === Code.OutOfRange &&
        /evicted|out_of_range/i.test(error.message)
    );
}

function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
