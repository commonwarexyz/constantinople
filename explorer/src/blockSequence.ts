export interface HeightedBlock {
    readonly height: bigint;
}

export interface BlockSequenceCursor {
    latestHeight: bigint | null;
    readonly seenHeights: Set<string>;
}

export function createBlockSequenceCursor(): BlockSequenceCursor {
    return {
        latestHeight: null,
        seenHeights: new Set(),
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
        addIfNew(cursor, next, block);
    }
    return next;
}

export async function collectNewBlocks<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: Iterable<T>,
    fetchMissing: (fromHeight: bigint, toHeight: bigint) => Promise<readonly T[]>,
): Promise<T[]> {
    const next: T[] = [];
    for (const block of blocks) {
        if (hasSeen(cursor, block.height)) {
            continue;
        }

        if (cursor.latestHeight !== null && block.height > cursor.latestHeight + 1n) {
            for (const missing of await fetchMissing(cursor.latestHeight + 1n, block.height - 1n)) {
                addIfNew(cursor, next, missing);
            }
        }

        if (cursor.latestHeight === null || block.height > cursor.latestHeight) {
            cursor.latestHeight = block.height;
        }
        addIfNew(cursor, next, block);
    }
    return next;
}

function addIfNew<T extends HeightedBlock>(
    cursor: BlockSequenceCursor,
    blocks: T[],
    block: T,
): void {
    if (hasSeen(cursor, block.height)) {
        return;
    }
    cursor.seenHeights.add(heightKey(block.height));
    blocks.push(block);
}

function hasSeen(cursor: BlockSequenceCursor, height: bigint): boolean {
    return cursor.seenHeights.has(heightKey(height));
}

function heightKey(height: bigint): string {
    return height.toString();
}
