export interface HeightedBlock {
    readonly height: bigint;
}

export interface BlockSequenceCursor {
    latestHeight: bigint | null;
    readonly seenHeights: Set<string>;
    readonly seenHeightOrder: string[];
    readonly maxSeenHeights: number;
}

const DEFAULT_MAX_SEEN_HEIGHTS = 4_096;

export function createBlockSequenceCursor(
    maxSeenHeights = DEFAULT_MAX_SEEN_HEIGHTS,
): BlockSequenceCursor {
    return {
        latestHeight: null,
        seenHeights: new Set(),
        seenHeightOrder: [],
        maxSeenHeights: Math.max(1, Math.floor(maxSeenHeights)),
    };
}

export function collectLiveBlocks<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: Iterable<T>,
): T[] {
    const next: T[] = [];
    for (const block of blocks) {
        if (hasSeen(cursor, block.height)) {
            continue;
        }

        if (cursor.latestHeight === null || block.height > cursor.latestHeight) {
            cursor.latestHeight = block.height;
        }
        rememberHeight(cursor, block.height);
        next.push(block);
    }
    return next;
}

function hasSeen(cursor: BlockSequenceCursor, height: bigint): boolean {
    return cursor.seenHeights.has(heightKey(height));
}

function rememberHeight(cursor: BlockSequenceCursor, height: bigint): void {
    const key = heightKey(height);
    cursor.seenHeights.add(key);
    cursor.seenHeightOrder.push(key);

    while (cursor.seenHeightOrder.length > cursor.maxSeenHeights) {
        const stale = cursor.seenHeightOrder.shift();
        if (stale !== undefined) {
            cursor.seenHeights.delete(stale);
        }
    }
}

function heightKey(height: bigint): string {
    return height.toString();
}
