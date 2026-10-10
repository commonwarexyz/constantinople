import type { DecodedQueryResult, DecodedSubscribeFrame, SqlClient } from '@exowarexyz/sql';
import { bytesEqual } from './codec.ts';
import {
    errorMessage,
    isConsistencyNotReadyError,
    NETWORK_RECONNECT_DELAY_MS,
    waitForRetry,
} from './proofRetry.ts';
import type { PublishedProofTarget } from './proofTarget.ts';
import { columnValue, firstTableRow, tableRows, type SqlRow } from './sqlTable.ts';
import {
    BLOCK_META_DIGEST,
    BLOCK_META_HEIGHT,
    BLOCK_META_TABLE,
    BLOCK_META_TX_COUNT,
} from './transactionHeight.ts';

const CATCH_UP_RETRY_DELAY_MS = 250;
const MAX_CACHED_BLOCK_ROWS = 128;

export interface ObservedBlock {
    readonly height: bigint;
    readonly digest: Uint8Array;
    readonly txCount: number;
    readonly arrivedAt: number;
}

export interface SubscribeBlocksOptions {
    readonly signal?: AbortSignal;
    readonly reconnectDelayMs?: number;
    readonly onError?: (message: string) => void;
    readonly onReconnect?: () => void;
}

export type BlockMetadataSqlClient = Pick<SqlClient, 'query' | 'subscribe'>;

export async function* subscribeBlocksFromTargets(
    sql: BlockMetadataSqlClient,
    targets: AsyncIterable<PublishedProofTarget>,
    options: SubscribeBlocksOptions = {},
): AsyncGenerator<ObservedBlock, void, void> {
    const signal = options.signal;
    const reconnectDelayMs = options.reconnectDelayMs ?? NETWORK_RECONNECT_DELAY_MS;
    const catchUpDelayMs = Math.min(reconnectDelayMs, CATCH_UP_RETRY_DELAY_MS);
    if (signal?.aborted) return;
    options.onReconnect?.();

    const metadata = new Map<bigint, { row: SqlRow; sequence: bigint }>();
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    let deliveredHeight = -1n;
    let reader: Promise<void> | undefined;

    try {
        for await (const target of targets) {
            if (!reader) {
                reader = readBlockMetadata(
                    sql,
                    target.sequenceNumber,
                    controller.signal,
                    reconnectDelayMs,
                    (frame) => {
                        for (const row of tableRows(frame.table)) {
                            const height = rowHeight(row);
                            if (height <= deliveredHeight || metadata.has(height)) continue;
                            metadata.set(height, { row, sequence: frame.sequenceNumber });
                            if (metadata.size > MAX_CACHED_BLOCK_ROWS) {
                                metadata.delete(metadata.keys().next().value!);
                            }
                        }
                    },
                    options.onError,
                );
            }

            while (!signal?.aborted) {
                let block: ObservedBlock | null;
                const cached = metadata.get(target.height);

                // A streamed row is usable only once its commit is covered by
                // the matching publication barrier. Point reads cover misses.
                if (cached && cached.sequence <= target.sequenceNumber) {
                    block = decodeBlockMetadataRow(cached.row, target);
                } else {
                    let result: DecodedQueryResult;
                    try {
                        result = await sql.query(
                            blockMetadataQuery(target.height),
                            target.sequenceNumber,
                            { signal },
                        );
                    } catch (error) {
                        if (signal?.aborted) return;

                        // A target can reach the browser before the SQL service
                        // ingests its rows. That lag is catch-up, not an outage.
                        if (isConsistencyNotReadyError(error)) {
                            if (!(await waitForRetry(catchUpDelayMs, signal))) return;
                            continue;
                        }
                        options.onError?.(errorMessage(error));
                        if (!(await waitForRetry(reconnectDelayMs, signal))) return;
                        options.onReconnect?.();
                        continue;
                    }
                    block = decodeBlockMetadata(result, target);
                }

                if (block) {
                    deliveredHeight = target.height;
                    for (const height of metadata.keys()) {
                        if (height <= deliveredHeight) metadata.delete(height);
                    }
                    yield block;
                    break;
                }
                if (!(await waitForRetry(catchUpDelayMs, signal))) return;
            }
        }
    } finally {
        signal?.removeEventListener('abort', abort);
        controller.abort();
        await reader;
    }
}

async function readBlockMetadata(
    sql: BlockMetadataSqlClient,
    sinceSequenceNumber: bigint,
    signal: AbortSignal,
    reconnectDelayMs: number,
    receive: (frame: DecodedSubscribeFrame) => void,
    onError?: (message: string) => void,
): Promise<void> {
    let nextSequence: bigint | undefined = sinceSequenceNumber;
    while (!signal.aborted) {
        try {
            for await (const frame of sql.subscribe(
                { table: BLOCK_META_TABLE, sinceSequenceNumber: nextSequence },
                { signal },
            )) {
                if (signal.aborted) return;
                receive(frame);
                nextSequence = frame.sequenceNumber + 1n;
            }
        } catch (error) {
            if (signal.aborted) return;
            onError?.(errorMessage(error));

            // The cache is optional. Resume live after a lost cursor and let
            // sequence-gated point reads fill any missed rows.
            nextSequence = undefined;
        }
        if (!(await waitForRetry(reconnectDelayMs, signal))) return;
    }
}

function blockMetadataQuery(height: bigint): string {
    return `SELECT ${BLOCK_META_HEIGHT}, ${BLOCK_META_DIGEST}, ${BLOCK_META_TX_COUNT} FROM ${BLOCK_META_TABLE} WHERE ${BLOCK_META_HEIGHT} = ${height} LIMIT 1`;
}

function decodeBlockMetadata(
    result: DecodedQueryResult,
    target: PublishedProofTarget,
): ObservedBlock | null {
    if (result.sequenceNumber < target.sequenceNumber) {
        throw new Error('block metadata query evaluated below the proof target sequence');
    }

    const row = firstTableRow(result.table);
    if (!row) return null;
    return decodeBlockMetadataRow(row, target);
}

function decodeBlockMetadataRow(row: SqlRow, target: PublishedProofTarget): ObservedBlock {
    const height = rowHeight(row);
    const digest = columnValue(row, BLOCK_META_DIGEST);
    const txCount = columnValue(row, BLOCK_META_TX_COUNT);
    if (height !== target.height) {
        throw new Error(`block metadata height ${height} does not match proof target ${target.height}`);
    }
    if (!(digest instanceof Uint8Array)) {
        throw new Error('block metadata digest must be bytes');
    }
    if (!bytesEqual(digest, target.blockDigest)) {
        throw new Error(`block metadata digest does not match proof target at height ${target.height}`);
    }
    if (typeof txCount !== 'bigint' || txCount < 0n || txCount > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error('block metadata transaction count must be a safe non-negative integer');
    }

    return {
        height,
        digest: digest.slice(),
        txCount: Number(txCount),
        arrivedAt: Date.now(),
    };
}

function rowHeight(row: SqlRow): bigint {
    const height = columnValue(row, BLOCK_META_HEIGHT);
    if (typeof height !== 'bigint') {
        throw new Error('block metadata height must be a bigint');
    }
    return height;
}
