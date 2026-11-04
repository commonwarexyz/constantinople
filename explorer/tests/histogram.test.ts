import assert from 'node:assert/strict';
import test from 'node:test';
import { buildHistogram, formatAverageTxPerBlock } from '../src/histogram.ts';

const block = (height: number, txCount = 0) => ({ height: BigInt(height), txCount });
const fractions = (chart: ReturnType<typeof buildHistogram>) => chart.columns.map((column) => column && column.fraction);

test('bootstrap uses one fixed column per observed block, oldest first', () => {
    const chart = buildHistogram([block(3, 2), block(2), block(1, 2)], 8);
    assert.deepEqual(fractions(chart), [null, null, null, null, null, 1, 0, 1]);
    assert.deepEqual(chart.columns.slice(5).map((column) => column!.height), [1n, 2n, 3n]);
    assert.equal(chart.domain, 2);
});

test('each arrival appends one column without stretching previous bars', () => {
    assert.deepEqual(fractions(buildHistogram([block(1, 2)], 5)), [null, null, null, null, 1]);
    assert.deepEqual(fractions(buildHistogram([block(2), block(1, 2)], 5)), [null, null, null, 1, 0]);
    assert.deepEqual(fractions(buildHistogram([block(4, 4), block(3, 2), block(2), block(1, 2)], 5)), [null, 0.5, 0, 0.5, 1]);
});

test('unobserved history has no fabricated bars, and empty blocks are zero-height columns', () => {
    assert.deepEqual(buildHistogram([], 8), { columns: Array(8).fill(null), domain: 1 });
    const zeros = buildHistogram([block(2), block(1)], 7);
    assert.deepEqual(fractions(zeros), [null, null, null, null, null, 0, 0]);
    assert.equal(zeros.domain, 1);
});

test('quiet traffic scales to its exact peak and keeps block order', () => {
    const chart = buildHistogram([block(100, 4), block(50, 2), block(20)], 3);
    assert.equal(chart.domain, 4);
    assert.deepEqual(fractions(chart), [0, 0.5, 1]);
});

test('only the newest visible blocks are rendered and set the scale', () => {
    const chart = buildHistogram([block(4, 2), block(3), block(2, 100), block(1)], 2);
    assert.equal(chart.domain, 2);
    assert.deepEqual(fractions(chart), [0, 1]);
});

test('the scale is the exact visible peak with a nonzero empty denominator', () => {
    for (const [count, domain] of [[0, 1], [2, 2], [10, 10], [11, 11], [20, 20], [21, 21], [51, 51], [101, 101]]) {
        assert.equal(buildHistogram([block(1, count)], 4).domain, domain);
    }
});

test('scale changes proportionally when the peak rises from twenty to twenty-one', () => {
    const before = buildHistogram([block(1, 20)], 2);
    const after = buildHistogram([block(2, 21), block(1, 20)], 2);
    assert.deepEqual(fractions(before), [null, 1]);
    assert.deepEqual(fractions(after), [20 / 21, 1]);
});

test('the average preserves quiet traffic instead of rounding it to zero or one', () => {
    assert.equal(formatAverageTxPerBlock(256, 513), '0.5');
    assert.equal(formatAverageTxPerBlock(258, 513), '0.5');
    assert.equal(formatAverageTxPerBlock(1, 101), '<0.01');
    assert.equal(formatAverageTxPerBlock(0, 10), '0');
    assert.equal(formatAverageTxPerBlock(0, 0), '—');
});
