import type { AnalysisCell, AnalysisResult } from './analysis.ts';

/** Column indices of the chart axes in an analysis result. */
export interface ChartAxes { x: number; y: number }

/** Exact chart coordinate. Integers stay bigint so large values keep full precision. */
export type ChartValue = number | bigint;

/** Value range of one axis and a mapping from a value to its position in `[0, 1]`. */
export interface ChartScale {
    min: ChartValue;
    max: ChartValue;
    position: (value: ChartValue) => number;
}

/** Returns the exact integer when available, falling back to the finite numeric view. */
export function chartValue(cell: AnalysisCell): ChartValue | null {
    if (typeof cell.value === 'bigint') return cell.value;
    return cell.numeric;
}

/** Integer coordinates are scaled before conversion, preserving small changes in large balances. */
export function chartScale(values: ChartValue[], includeZero = false): ChartScale | null {
    // A scale needs at least one value, all of one type, and no infinities or NaN.
    if (!values.length || values.some(value => typeof value !== typeof values[0] || (typeof value === 'number' && !Number.isFinite(value)))) return null;
    let min = values.reduce((a, b) => a < b ? a : b);
    let max = values.reduce((a, b) => a > b ? a : b);
    if (includeZero) {
        const zero = typeof min === 'bigint' ? 0n : 0;
        if (min > zero) min = zero;
        if (max < zero) max = zero;
    }
    return {
        min, max,
        position(value) {
            if (min === max) return 0.5;

            // Integer offsets are scaled to billionths before conversion. Floats whose extent
            // overflows are halved first so the division stays finite.
            if (typeof value === 'bigint' && typeof min === 'bigint' && typeof max === 'bigint') {
                return Number((value - min) * 1_000_000_000n / (max - min)) / 1_000_000_000;
            }
            const extent = Number(max) - Number(min);
            return Number.isFinite(extent)
                ? (Number(value) - Number(min)) / extent
                : (Number(value) / 2 - Number(min) / 2) / (Number(max) / 2 - Number(min) / 2);
        },
    };
}

/**
 * Chooses default axes for results with at least two rows, or returns null when no numeric column
 * other than x has a value to plot.
 */
export function inferChart(result: AnalysisResult): ChartAxes | null {
    if (result.rows.length < 2) return null;

    // Prefer an explicit `x` alias, then time, then a chain position, then a text category, and
    // finally the first numeric column.
    const columns = result.columns;
    const numeric = columns.map((column, index) => column.kind === 'number' ? index : -1).filter(index => index >= 0);
    let x = columns.findIndex(column => column.name.toLowerCase() === 'x');
    if (x < 0) x = columns.findIndex(column => column.kind === 'time');
    if (x < 0) x = columns.findIndex(column => /^(height|qmdb_location)$/i.test(column.name));
    if (x < 0) x = columns.findIndex(column => column.kind === 'text');
    if (x < 0) x = numeric[0] ?? -1;

    // Prefer an explicit `y` alias or a known measure, then any numeric column that is not a
    // position, index, role, or nonce.
    let y = numeric.find(index => index !== x && /^(y|balance|tx_count|transactions|count|value)$/i.test(columns[index].name));
    y ??= numeric.find(index => index !== x && !/^(height|qmdb_location|index|role|nonce|nonce_base|nonce_bitmap)$/i.test(columns[index].name));
    if (x < 0 || y === undefined) return null;
    if (!result.rows.some(row => chartValue(row[y]) !== null)) return null;
    return { x, y };
}
