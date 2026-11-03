import type { VerifiedBlock } from './indexer.ts';

type HistogramBlock = Pick<VerifiedBlock, 'height' | 'txCount'>;
const BLOCK_GLYPHS = ' ▁▂▃▄▅▆▇█';

export function buildHistogram(
    blocks: readonly HistogramBlock[],
    width: number,
    rows: number,
): { lines: string[]; zeroLine: string; domain: number } {
    const recent = blocks.slice(0, width).reverse();
    const peak = recent.reduce((value, block) => Math.max(value, block.txCount), 0);
    const domain = peak || 1;
    const padding = ' '.repeat(width - recent.length);
    const ramp = BLOCK_GLYPHS.length - 1;
    const stepsPerColumn = rows * ramp;
    const columnSteps = recent.map((block) => block.txCount === 0 ? 0
        : Math.min(stepsPerColumn, Math.max(1, Math.round(block.txCount / domain * stepsPerColumn))));
    const lines: string[] = [];
    for (let row = 0; row < rows; row++) {
        const rowsBelow = rows - 1 - row;
        lines.push(padding + columnSteps.map((steps) =>
            BLOCK_GLYPHS[Math.max(0, Math.min(ramp, steps - rowsBelow * ramp))],
        ).join(''));
    }
    const zeroLine = padding + recent.map((block) => block.txCount === 0 ? '·' : ' ').join('');
    return { lines, zeroLine, domain };
}

export function formatAverageTxPerBlock(totalTransactions: number, totalBlocks: number): string {
    if (totalBlocks === 0) return '—';
    const average = totalTransactions / totalBlocks;
    if (average > 0 && average < 0.01) return '<0.01';
    return average.toLocaleString(undefined, { maximumFractionDigits: 2 });
}
