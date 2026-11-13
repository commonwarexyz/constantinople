import type { VerifiedBlock } from './indexer.ts';

type HistogramBlock = Pick<VerifiedBlock, 'height' | 'txCount'>;

/** One fixed-width column: a block's share of the visible peak, or an empty block. */
export interface HistogramColumn {
    readonly height: bigint;
    readonly txCount: number;
    /** Bar height as a share of the visible peak, in [0, 1]; zero for an empty block. */
    readonly fraction: number;
}

/**
 * The newest `width` blocks as columns, oldest first, scaled to their exact peak. Columns before
 * the first observed block are null so unobserved history stays blank rather than fabricated.
 */
export function buildHistogram(
    blocks: readonly HistogramBlock[],
    width: number,
): { columns: (HistogramColumn | null)[]; domain: number } {
    const recent = blocks.slice(0, width).reverse();
    const peak = recent.reduce((value, block) => Math.max(value, block.txCount), 0);
    const domain = peak || 1;
    const padding: null[] = Array.from({ length: width - recent.length }, () => null);
    const columns = recent.map((block) => ({
        height: block.height, txCount: block.txCount, fraction: block.txCount / domain,
    }));
    return { columns: [...padding, ...columns], domain };
}

export function formatAverageTxPerBlock(totalTransactions: number, totalBlocks: number): string {
    if (totalBlocks === 0) return '—';
    const average = totalTransactions / totalBlocks;
    if (average > 0 && average < 0.01) return '<0.01';
    return average.toLocaleString(undefined, { maximumFractionDigits: 2 });
}
