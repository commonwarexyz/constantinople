import type { AnalysisCell, AnalysisResult } from './analysis.ts';

export interface ChartAxes { x: number; y: number }
export type ChartValue = number | bigint;
export interface ChartScale {
    min: ChartValue;
    max: ChartValue;
    position: (value: ChartValue) => number;
}

export function chartValue(cell: AnalysisCell): ChartValue | null {
    if (typeof cell.value === 'bigint') return cell.value;
    return cell.numeric;
}

/** Integer coordinates are scaled before conversion, preserving small changes in large balances. */
export function chartScale(values: ChartValue[], includeZero = false): ChartScale | null {
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

export function inferChart(result: AnalysisResult): ChartAxes | null {
    if (result.rows.length < 2) return null;
    const columns = result.columns;
    const numeric = columns.map((column, index) => column.kind === 'number' ? index : -1).filter(index => index >= 0);
    let x = columns.findIndex(column => column.name.toLowerCase() === 'x');
    if (x < 0) x = columns.findIndex(column => column.kind === 'time');
    if (x < 0) x = columns.findIndex(column => /^(height|qmdb_location)$/i.test(column.name));
    if (x < 0) x = columns.findIndex(column => column.kind === 'text');
    if (x < 0) x = numeric[0] ?? -1;
    let y = numeric.find(index => index !== x && /^(y|balance|tx_count|transactions|count|value)$/i.test(columns[index].name));
    y ??= numeric.find(index => index !== x && !/^(height|qmdb_location|index|role|nonce|nonce_base|nonce_bitmap)$/i.test(columns[index].name));
    if (x < 0 || y === undefined) return null;
    if (!result.rows.some(row => chartValue(row[y]) !== null)) return null;
    return { x, y };
}
