import assert from 'node:assert/strict';
import test from 'node:test';
import { chartScale, inferChart } from '../src/analysisChart.ts';
import type { AnalysisResult } from '../src/analysis.ts';

test('chart scales preserve small changes in u64 values without rounding the source', () => {
    const base = (1n << 64n) - 101n;
    const scale = chartScale([base + 100n, base, base + 50n]);
    assert.ok(scale);
    assert.equal(scale.min, base);
    assert.equal(scale.max, base + 100n);
    assert.equal(scale.position(base), 0);
    assert.equal(scale.position(base + 50n), 0.5);
    assert.equal(scale.position(base + 100n), 1);
});

test('bar scales include zero and handle signed, constant, and empty domains', () => {
    const scale = chartScale([-30n, -10n], true);
    assert.ok(scale);
    assert.equal(scale.max, 0n);
    assert.equal(scale.position(-15n), 0.5);
    assert.equal(chartScale([7, 7])?.position(7), 0.5);
    assert.equal(chartScale([], true), null);
    assert.equal(chartScale([1, 2n]), null);
    assert.equal(chartScale([Infinity, 1]), null);
    assert.equal(chartScale([-Number.MAX_VALUE, Number.MAX_VALUE])?.position(0), 0.5);
});

function result(names: string[], kinds: AnalysisResult['columns'][number]['kind'][]): AnalysisResult {
    return {
        columns: names.map((name, index) => ({ name, kind: kinds[index], type: '', nullable: false })),
        rows: [1, 2].map(value => names.map(() => ({ value, numeric: value, text: String(value) }))),
        truncated: false,
        stats: { rowCount: 2, columnCount: names.length, batchCount: 1, elapsedMs: 1, sequenceNumber: undefined },
    };
}

test('chart inference respects SQL axes, timestamps and balance history without graphing identifiers', () => {
    assert.deepEqual(inferChart(result(['height', 'tx_count', 'finalized_ts'], ['number', 'number', 'time'])), { x: 2, y: 1 });
    assert.deepEqual(inferChart(result(['qmdb_location', 'balance', 'nonce_base'], ['number', 'number', 'number'])), { x: 0, y: 1 });
    assert.deepEqual(inferChart(result(['y', 'height', 'x'], ['number', 'number', 'number'])), { x: 2, y: 0 });
    assert.equal(inferChart(result(['tx_digest', 'height', 'qmdb_location'], ['binary', 'number', 'number'])), null);
    const emptyValues = result(['x', 'y'], ['number', 'number']);
    for (const row of emptyValues.rows) row[1] = { value: null, numeric: null, text: 'NULL' };
    assert.equal(inferChart(emptyValues), null);
});
