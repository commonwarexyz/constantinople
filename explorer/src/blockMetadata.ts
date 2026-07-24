import { type DecodedSubscribeFrame } from '@exowarexyz/sql';

/** `block_meta` column names (mirror `crates/indexer/src/sql_schema.rs`). */
const COL_HEIGHT = 'height';
const COL_DIGEST = 'digest';
const COL_TX_COUNT = 'tx_count';
const COL_EPOCH = 'epoch';

/** Aggregate summary of one finalized block as observed on the live stream. */
export interface ObservedBlock {
    /** Finalized block height the row corresponds to. */
    readonly height: bigint;
    /** Finalized block digest certified by Simplex. */
    readonly digest: Uint8Array;
    /** Number of transactions contained in the block. */
    readonly txCount: number;
    /** Simplex consensus epoch that finalized the block. */
    readonly epoch: bigint;
    /** Wall-clock arrival time on this client, in epoch milliseconds. */
    readonly arrivedAt: number;
    /** Underlying store batch sequence number. Multiple rows may share it. */
    readonly sequence: bigint;
}

/** Decode one SQL subscription frame into finalized block metadata. */
export function* decodeBlockFrame(
    frame: DecodedSubscribeFrame,
): Generator<ObservedBlock> {
    const heightIdx = frame.columns.indexOf(COL_HEIGHT);
    const digestIdx = frame.columns.indexOf(COL_DIGEST);
    const txCountIdx = frame.columns.indexOf(COL_TX_COUNT);
    const epochIdx = frame.columns.indexOf(COL_EPOCH);
    if (heightIdx < 0 || digestIdx < 0 || txCountIdx < 0 || epochIdx < 0) {
        return;
    }

    const arrivedAt = Date.now();
    const blocks: ObservedBlock[] = [];
    for (const row of frame.rows) {
        const height = row.cells[heightIdx];
        const digest = row.cells[digestIdx];
        const txCount = row.cells[txCountIdx];
        const epoch = row.cells[epochIdx];
        if (
            typeof height !== 'bigint' ||
            !(digest instanceof Uint8Array) ||
            typeof txCount !== 'bigint' ||
            typeof epoch !== 'bigint'
        ) {
            continue;
        }

        // `block_meta.tx_count` is u64; Number() is safe for realistic blocks.
        blocks.push({
            height,
            digest,
            txCount: Number(txCount),
            epoch,
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
