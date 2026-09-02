import { type DecodedQueryResult, SqlClient } from '@exowarexyz/sql';
import {
    subscribePublishedProofTargets,
    waitForRetry,
    type PublishedProofTarget,
} from './proofTarget.ts';

const BLOCK_META_TABLE = 'block_meta';
const COL_HEIGHT = 'height';
const COL_DIGEST = 'digest';
const COL_TX_COUNT = 'tx_count';
const NETWORK_RECONNECT_DELAY_MS = 5_000;
const CATCH_UP_RETRY_DELAY_MS = 250;

export interface ObservedBlock {
    readonly height: bigint;
    readonly digest: Uint8Array;
    readonly txCount: number;
    readonly arrivedAt: number;
    readonly sequence: bigint;
}

export interface SubscribeBlocksOptions {
    readonly signal?: AbortSignal;
    readonly reconnectDelayMs?: number;
    readonly onError?: (message: string) => void;
    readonly onReconnect?: () => void;
}

export type BlockMetadataSqlClient = Pick<SqlClient, 'query'>;

export async function* subscribeBlocks(
    sqlUrl: string,
    storeUrl: string,
    options: SubscribeBlocksOptions = {},
): AsyncGenerator<ObservedBlock, void, void> {
    const targets = subscribePublishedProofTargets(storeUrl, {
        signal: options.signal,
        reconnectDelayMs: options.reconnectDelayMs,
        onError: (message) => {
            options.onError?.(message);
            options.onReconnect?.();
        },
    });
    yield* subscribeBlocksFromTargets(new SqlClient(sqlUrl), targets, options);
}

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

    for await (const target of targets) {
        while (!signal?.aborted) {
            let result: DecodedQueryResult;
            try {
                result = await sql.query(blockMetadataQuery(target.height), {
                    signal,
                    minSequenceNumber: target.sequenceNumber,
                });
            } catch (error) {
                if (signal?.aborted) return;
                options.onError?.(errorMessage(error));
                if (!(await waitForRetry(reconnectDelayMs, signal))) return;
                options.onReconnect?.();
                continue;
            }

            const block = decodeBlockMetadata(result, target);
            if (block) {
                yield block;
                break;
            }
            if (!(await waitForRetry(catchUpDelayMs, signal))) return;
        }
    }
}

function blockMetadataQuery(height: bigint): string {
    return `SELECT ${COL_HEIGHT}, ${COL_DIGEST}, ${COL_TX_COUNT} FROM ${BLOCK_META_TABLE} WHERE ${COL_HEIGHT} = ${height} LIMIT 1`;
}

function decodeBlockMetadata(
    result: DecodedQueryResult,
    target: PublishedProofTarget,
): ObservedBlock | null {
    if (result.sequenceNumber < target.sequenceNumber) {
        throw new Error('block metadata query evaluated below the proof target sequence');
    }

    const row = result.rows[0];
    if (!row) return null;

    const height = row.values[COL_HEIGHT];
    const digest = row.values[COL_DIGEST];
    const txCount = row.values[COL_TX_COUNT];
    if (typeof height !== 'bigint') {
        throw new Error('block metadata height must be a bigint');
    }
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
        sequence: target.sequenceNumber,
    };
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}
