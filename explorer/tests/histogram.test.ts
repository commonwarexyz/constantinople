import assert from 'node:assert/strict';
import test from 'node:test';
import { buildHistogram, formatAverageTxPerBlock } from '../src/histogram.ts';

const block = (height: number, txCount = 0) => ({ height: BigInt(height), txCount });

test('bootstrap uses one fixed glyph column per observed block', () => {
    assert.deepEqual(buildHistogram([block(3, 2), block(2), block(1, 2)], 8, 2), {
        lines: ['     █ █', '     █ █'],
        zeroLine: '      · ',
        domain: 2,
    });
});

test('each arrival appends one column without stretching previous bars', () => {
    const first = buildHistogram([block(1, 2)], 5, 2);
    const next = buildHistogram([block(2), block(1, 2)], 5, 2);
    const batch = buildHistogram([block(4, 4), block(3, 2), block(2), block(1, 2)], 5, 2);
    assert.equal(first.lines[1], '    █');
    assert.equal(next.lines[1], '   █ ');
    assert.equal(next.zeroLine, '    ·');
    assert.equal(batch.lines[1], ' █ ██');
    assert.equal(batch.zeroLine, '  ·  ');
});

test('unobserved history has no fabricated bars or zero markers', () => {
    assert.deepEqual(buildHistogram([], 8, 2), {
        lines: ['        ', '        '], zeroLine: '        ', domain: 1,
    });
    const zeros = buildHistogram([block(2), block(1)], 7, 2);
    assert.deepEqual(zeros.lines, ['       ', '       ']);
    assert.equal(zeros.zeroLine, '     ··');
});

test('quiet traffic scales to its exact peak and keeps block order', () => {
    const chart = buildHistogram([block(100, 4), block(50, 2), block(20)], 3, 2);
    assert.equal(chart.domain, 4);
    assert.deepEqual(chart.lines, ['  █', ' ██']);
    assert.equal(chart.zeroLine, '·  ');
});

test('only the newest visible blocks are rendered and set the scale', () => {
    const chart = buildHistogram([block(4, 2), block(3), block(2, 100), block(1)], 2, 2);
    assert.equal(chart.domain, 2);
    assert.deepEqual(chart.lines, [' █', ' █']);
    assert.equal(chart.zeroLine, '· ');
});

test('the scale is the exact visible peak with a nonzero empty denominator', () => {
    for (const [count, domain] of [[0, 1], [2, 2], [10, 10], [11, 11], [20, 20], [21, 21], [51, 51], [101, 101]]) {
        assert.equal(buildHistogram([block(1, count)], 4, 10).domain, domain);
    }
});

test('scale changes proportionally when the peak rises from twenty to twenty-one', () => {
    const before = buildHistogram([block(1, 20)], 2, 21);
    const after = buildHistogram([block(2, 21), block(1, 20)], 2, 21);
    assert.equal(before.domain, 20);
    assert.equal(after.domain, 21);
    assert.equal(before.lines.every((line) => line === ' █'), true);
    assert.equal(after.lines[0], ' █');
    assert.equal(after.lines.slice(1).every((line) => line === '██'), true);
});

test('actual zero marks remain one glyph wide at every viewport capacity', () => {
    for (let width = 3; width < 12; width++) {
        const chart = buildHistogram([block(100), block(10), block(1)], width, 4);
        assert.equal(chart.zeroLine, ' '.repeat(width - 3) + '···');
        assert.equal(chart.lines.every((line) => line.length === width), true);
    }
});

test('the average preserves quiet traffic instead of rounding it to zero or one', () => {
    assert.equal(formatAverageTxPerBlock(256, 513), '0.5');
    assert.equal(formatAverageTxPerBlock(258, 513), '0.5');
    assert.equal(formatAverageTxPerBlock(1, 101), '<0.01');
    assert.equal(formatAverageTxPerBlock(0, 10), '0');
    assert.equal(formatAverageTxPerBlock(0, 0), '—');
});
