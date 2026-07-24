// Streaming client for the constantinople indexer (SQL metadata path).
//
// Subscribes to the `block_meta` table over the `store.sql.v1.Service`
// `Subscribe` RPC. Each delivered SubscribeResponse frame carries the
// rows from one atomic ingest batch, and at the indexer's "one flush per
// finalized block" cadence that is exactly one row per finalized block.
//
// This client only talks to the block metadata stream. Transaction/account
// lookup queries use SQL too; submitted-transaction proofs use the QMDB and
// Simplex clients in `qmdb.ts`.
//
// Column names mirror `crates/indexer/src/sql_schema.rs` and must stay in
// sync with `BLOCK_META_*` constants there.

import { Code, ConnectError } from '@connectrpc/connect';
import { SqlClient } from '@exowarexyz/sql';
import { decodeBlockFrame, type ObservedBlock } from './blockMetadata';
import { collectLiveBlocks, createBlockSequenceCursor } from './blockSequence';

export type { ObservedBlock } from './blockMetadata';

/** The SQL table the explorer subscribes to. */
const BLOCK_META_TABLE = 'block_meta';
const NETWORK_RECONNECT_DELAY_MS = 5_000;

export interface SubscribeBlocksOptions {
    readonly signal?: AbortSignal;
    readonly onNetworkError?: (message: string) => void;
    readonly onReconnect?: () => void;
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
    options: SubscribeBlocksOptions = {},
): AsyncGenerator<ObservedBlock, void, void> {
    const sql = new SqlClient(sqlUrl);
    const signal = options.signal;

    // Cap consecutive transient retries so a genuinely broken server can't
    // trap us in a tight reconnect loop. A single delivered frame resets
    // the counter.
    const MAX_TRANSIENT_RETRIES = 10;
    let transientRetries = 0;
    let nextSequence: bigint | undefined;
    const cursor = createBlockSequenceCursor();

    while (!signal?.aborted) {
        try {
            options.onReconnect?.();
            const stream = sql.subscribe(
                {
                    table: BLOCK_META_TABLE,
                    // Empty predicate => emit every block_meta row. The
                    // server still applies its own bounded compile budget.
                    whereSql: '',
                    sinceSequenceNumber: nextSequence,
                },
                { signal },
            );

            for await (const frame of stream) {
                transientRetries = 0;
                const frameNextSequence = frame.sequenceNumber + 1n;
                yield* collectLiveBlocks(cursor, decodeBlockFrame(frame));
                nextSequence = frameNextSequence;
            }
            // Server-streaming RPC ended cleanly (no more frames). Loop
            // and re-subscribe from `nextSequence` so the UI keeps following
            // the live tail without dropping batches committed between RPCs.
        } catch (error) {
            if (signal?.aborted) {
                return;
            }
            if (isNetworkError(error)) {
                options.onNetworkError?.(errorMessage(error));
                await sleep(NETWORK_RECONNECT_DELAY_MS, signal);
                continue;
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

function isNetworkError(error: unknown): boolean {
    if (error instanceof ConnectError) {
        return (
            error.code === Code.Unavailable ||
            error.code === Code.Aborted ||
            error.code === Code.DeadlineExceeded ||
            (error.code === Code.Unknown && /fetch|network|transport|failed/i.test(error.message))
        );
    }
    return error instanceof TypeError && /fetch|network|load|failed/i.test(error.message);
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
            return;
        }
        const timeout = window.setTimeout(resolve, ms);
        signal?.addEventListener(
            'abort',
            () => {
                window.clearTimeout(timeout);
                reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
            },
            { once: true },
        );
    });
}
