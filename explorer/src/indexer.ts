// Streaming client for the constantinople indexer (SQL metadata path).
//
// Subscribes to the `block_meta` table over the `store.sql.v1.Service`
// `Subscribe` RPC. Each delivered SubscribeResponse frame carries the
// rows from one atomic ingest batch, and at the indexer's "one flush per
// finalized block" cadence that is exactly one row per finalized block.
//
// This client only talks to the metadata stream. Full transaction bodies are
// also published through raw KV; submitted-transaction proofs use the QMDB and
// Simplex clients in `qmdb.ts`.
//
// Column names mirror `crates/indexer/src/sql_schema.rs` and must stay in
// sync with `BLOCK_META_*` constants there.

import { Code, ConnectError } from '@connectrpc/connect';
import { type DecodedSubscribeFrame, SqlClient } from '@exowarexyz/sql';
import { collectLiveBlocks, createBlockSequenceCursor } from './blockSequence';

/** `block_meta` column names (mirror `crates/indexer/src/sql_schema.rs`). */
const COL_HEIGHT = 'height';
const COL_DIGEST = 'digest';
const COL_TX_COUNT = 'tx_count';

/** The SQL table the explorer subscribes to. */
const BLOCK_META_TABLE = 'block_meta';
const NETWORK_RECONNECT_DELAY_MS = 5_000;

/** Aggregate summary of one finalized block as observed on the live stream. */
export interface ObservedBlock {
    /** Finalized block height the row corresponds to. */
    readonly height: bigint;
    /** Finalized block digest certified by Simplex. */
    readonly digest: Uint8Array;
    /** Number of transactions contained in the block. */
    readonly txCount: number;
    /** Wall-clock arrival time on this client, in epoch milliseconds. */
    readonly arrivedAt: number;
    /** Underlying store batch sequence number. Multiple rows may share it. */
    readonly sequence: bigint;
}

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
                yield* collectLiveBlocks(cursor, decodeFrame(frame));
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
 * Decode a single SubscribeResponse frame into one `ObservedBlock` per row.
 *
 * The server emits one frame per atomic ingest batch (== one finalized
 * block at the publisher's "flush per block" cadence), so most frames
 * carry exactly one row. We still iterate `frame.rows` defensively in case
 * the server batches rows differently in the future.
 */
function* decodeFrame(frame: DecodedSubscribeFrame): Generator<ObservedBlock> {
    const heightIdx = frame.columns.indexOf(COL_HEIGHT);
    const digestIdx = frame.columns.indexOf(COL_DIGEST);
    const txCountIdx = frame.columns.indexOf(COL_TX_COUNT);
    if (heightIdx < 0 || digestIdx < 0 || txCountIdx < 0) {
        // Server schema diverged from the explorer's compile-time
        // expectations — surface as zero rows so the UI keeps streaming
        // (rather than crashing) until the schema is rolled forward.
        return;
    }
    const arrivedAt = Date.now();
    const blocks: ObservedBlock[] = [];
    for (const row of frame.rows) {
        const heightCell = row.cells[heightIdx];
        const digestCell = row.cells[digestIdx];
        const txCountCell = row.cells[txCountIdx];
        if (
            typeof heightCell !== 'bigint' ||
            !(digestCell instanceof Uint8Array) ||
            typeof txCountCell !== 'bigint'
        ) {
            continue;
        }
        // `block_meta.tx_count` is u64; Number() is safe for any realistic
        // block (Number.MAX_SAFE_INTEGER is 2^53 - 1, far above per-block tx counts).
        blocks.push({
            height: heightCell,
            digest: digestCell,
            txCount: Number(txCountCell),
            arrivedAt,
            sequence: frame.sequenceNumber,
        });
    }
    blocks.sort((a, b) => compareBigint(a.height, b.height));
    yield* blocks;
}

function compareBigint(a: bigint, b: bigint): number {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
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
