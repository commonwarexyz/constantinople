import assert from 'node:assert/strict';
import test from 'node:test';
import {
    Decimal, Field, Float64, Int64, RecordBatch, Schema, Struct, Table, TimestampMicrosecond,
    Uint64, Utf8, Binary, makeData, tableToIPC, vectorFromArray,
} from 'apache-arrow';
import {
    ANALYSIS_ROW_LIMIT, ANALYSIS_SQL_LIMIT, analysisPresets, normalizeAnalysisResult,
    prepareAnalysisQuery, runAnalysis,
} from '../src/analysis.ts';

test('read-query guard handles ANSI quotes, comments, CTEs and nested queries', () => {
    // Keywords and semicolons inside quotes or comments must not trip the guard, and every accepted
    // query is wrapped with the display limit plus one sentinel row.
    for (const sql of [
        'SELECT 1;',
        `-- select example\nWITH x AS (SELECT 'it''s; DROP TABLE x' AS s) SELECT * FROM x`,
        '/* outer /* nested */ comment */ SELECT "DELETE", ");;" FROM (SELECT 1) AS x;',
        'SELECT 1 -- final comment without newline',
        'SELECT 1 UNION ALL SELECT 2',
    ]) {
        const result = prepareAnalysisQuery(sql);
        assert.match(result, /^SELECT \* FROM \(\n/);
        assert.match(result, /\n\) AS analysis_result LIMIT 1001$/);
    }

    // A line comment at the end of input must not swallow the query.
    assert.ok(prepareAnalysisQuery('SELECT 1 -- trailing').includes('SELECT 1'));
});

test('read-query guard blocks escaping, multiple statements and nested write commands', () => {
    // Each input is either not a single read query or uses syntax the scanner does not model.
    for (const sql of [
        '', '-- nothing', 'SHOW TABLES', 'SET x = 1', 'INSERT INTO x VALUES (1)',
        'WITH x AS (DELETE FROM tx_meta RETURNING *) SELECT * FROM x',
        'WITH x AS (SELECT 1) INSERT INTO y SELECT * FROM x',
        'SELECT * INTO y FROM tx_meta', 'SELECT 1; SELECT 2',
        'SELECT 1); DROP TABLE tx_meta; --', 'SELECT (1', 'SELECT 1)',
        "SELECT 'unclosed", 'SELECT /* unclosed', 'SELECT $$dollar$$',
        'SELECT `backticks`', String.raw`SELECT 'back\'slash'`,
        'SELECT 1; /* harmless */ UPDATE tx_meta SET height=1',
    ]) assert.throws(() => prepareAnalysisQuery(sql), Error, sql);

    // The length limit applies both to the input and to the query after wrapping.
    assert.throws(() => prepareAnalysisQuery('SELECT ' + ' '.repeat(ANALYSIS_SQL_LIMIT)), /65,535/);
    assert.throws(() => prepareAnalysisQuery('SELECT ' + ' '.repeat(ANALYSIS_SQL_LIMIT - 8) + '1'), /limit/);
});

test('normalization preserves duplicate columns, nulls, exact integers, bytes and timestamp units', () => {
    // Build one batch with two same-named columns and a null in most columns.
    const vectors = [
        vectorFromArray([18446744073709551615n, null], new Uint64()),
        vectorFromArray([-7n, 12n], new Int64()),
        vectorFromArray([new Uint8Array([0, 255]), null], new Binary()),
        vectorFromArray([1234, null], new TimestampMicrosecond()),
        vectorFromArray([NaN, 1.5], new Float64()),
        vectorFromArray(['text', null], new Utf8()),
    ];
    const schema = new Schema(vectors.map((vector, index) => new Field(index < 2 ? 'same' : `c${index}`, vector.type, true)));
    const batch = new RecordBatch(schema, makeData({ type: new Struct(schema.fields), length: 2, children: vectors.map(vector => vector.data[0]) }));
    Object.assign(batch, { schema });
    const result = normalizeAnalysisResult(new Table(schema, [batch]), 9007199254740993n, 12);

    // Unsafe u64 values stay exact, bytes become hex, and timestamps display as milliseconds.
    assert.deepEqual(result.columns.slice(0, 2).map(column => column.name), ['same', 'same']);
    assert.deepEqual(result.rows[0][0], { value: 18446744073709551615n, text: '18446744073709551615', numeric: null });
    assert.deepEqual(result.rows[0][1], { value: -7n, text: '-7', numeric: -7 });
    assert.equal(result.rows[0][2].value, '0x00ff');
    assert.equal(result.rows[0][3].value, 1234);
    assert.equal(result.rows[0][3].text, '1970-01-01T00:00:01.234Z');
    assert.equal(result.rows[0][3].numeric, 1234);
    assert.equal(result.rows[0][4].numeric, null);
    assert.equal(result.rows[1][0].value, null);
    assert.equal(result.rows[1][0].text, 'NULL');

    // Stats report the response sequence and the result's shape.
    assert.equal(result.stats.sequenceNumber, 9007199254740993n);
    assert.equal(result.stats.rowCount, 2);
    assert.equal(result.stats.columnCount, 6);
    assert.equal(result.stats.batchCount, 1);
});

test('normalization uses the sentinel row without displaying it and preserves empty schemas', () => {
    // One row past the limit marks the result as truncated without being shown.
    const rows = vectorFromArray(Array.from({ length: 1001 }, (_, i) => i), new Float64());
    const result = normalizeAnalysisResult(new Table({ value: rows }), undefined, 0);
    assert.equal(result.rows.length, ANALYSIS_ROW_LIMIT);
    assert.equal(result.truncated, true);
    assert.equal(result.stats.rowCount, 1000);

    // An empty result still reports its column types.
    const empty = normalizeAnalysisResult(new Table({ value: vectorFromArray([], new Int64()) }), undefined, 0);
    assert.equal(empty.rows.length, 0);
    assert.equal(empty.columns[0].kind, 'number');
    assert.equal(empty.truncated, false);
});

test('decimal normalization preserves the scale without approximate numeric conversion', () => {
    const table = new Table({ value: vectorFromArray([new Uint32Array([12345, 0, 0, 0])], new Decimal(2, 38, 128)) });
    const result = normalizeAnalysisResult(table, undefined, 0);
    assert.deepEqual(result.rows[0][0], { value: '123.45', text: '123.45', numeric: null });
});

test('presets bound indexed reads and describe balance by operation rather than time', () => {
    // Every example passes the guard and covers the 100 blocks ending at the latest height.
    const examples = analysisPresets(150n, '0x' + 'AB'.repeat(32));
    assert.equal(examples.length, 5);
    for (const example of examples) prepareAnalysisQuery(example.sql);
    assert.match(examples[0].sql, /height >= 51 AND height <= 150/);
    assert.match(examples[1].sql, new RegExp(`X'${'ab'.repeat(32)}'`));
    assert.match(examples[1].description, /no wall-clock/);

    // Without an account, account examples match nothing and are disabled. Invalid inputs throw.
    assert.equal(analysisPresets(1n)[1].requiresAccount, true);
    assert.match(analysisPresets(1n)[1].sql, /WHERE FALSE/);
    assert.equal(examples[1].requiresAccount, false);
    assert.throws(() => analysisPresets(0n));
    assert.throws(() => analysisPresets(1n, 'nope'));
});

/** Encodes a protobuf varint for the hand-built Connect response. */
function varint(input: number): number[] {
    const bytes: number[] = [];
    do { const value = input & 127; input >>>= 7; bytes.push(value | (input ? 128 : 0)); } while (input);
    return bytes;
}

test('runAnalysis sends a capped unary query, preserves result sequence and uses one attempt', async (t) => {
    // The response encodes an Arrow IPC stream in field 1 and Store sequence 17 in field 3.
    const ipc = tableToIPC(new Table({ value: vectorFromArray([9n], new Uint64()) }), 'stream');
    const response = new Uint8Array([10, ...varint(ipc.length), ...ipc, 24, 17]);

    // Capture the submitted SQL from the request body and check the Connect deadline header.
    let submitted = '';
    const fetch = t.mock.method(globalThis, 'fetch', async (_url: RequestInfo | URL, init?: RequestInit) => {
        const body = new Uint8Array(await new Response(init?.body).arrayBuffer());
        let length = 0, shift = 0, index = 1;
        do { const byte = body[index++]; length |= (byte & 127) << shift; shift += 7; if (!(byte & 128)) break; } while (index < body.length);
        submitted = new TextDecoder().decode(body.subarray(index, index + length));
        const deadline = Number(new Headers(init?.headers).get('connect-timeout-ms'));
        assert.ok(deadline > 0 && deadline <= 30000);
        return new Response(response, { headers: { 'content-type': 'application/proto' } });
    });

    // The prepared query is sent once and the decoded result keeps the response sequence.
    const result = await runAnalysis('https://sql.example', 'SELECT 9', new AbortController().signal);
    assert.equal(submitted, prepareAnalysisQuery('SELECT 9'));
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal(result.rows[0][0].value, 9n);
    assert.equal(result.stats.sequenceNumber, 17n);
    assert.ok(result.stats.elapsedMs >= 0);
});

test('invalid or pre-canceled queries never fetch; transient failure is not silently retried', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ code: 'unavailable', message: 'offline' }), {
        status: 503, headers: { 'content-type': 'application/json' },
    }));

    // A rejected query or an already aborted signal fails before any request.
    await assert.rejects(runAnalysis('https://sql.example', 'DELETE FROM tx_meta', new AbortController().signal));
    const controller = new AbortController(); controller.abort();
    await assert.rejects(runAnalysis('https://sql.example', 'SELECT 1', controller.signal));
    assert.equal(fetch.mock.callCount(), 0);

    // A retryable service error surfaces after exactly one request.
    await assert.rejects(runAnalysis('https://sql.example', 'SELECT 1', new AbortController().signal), /offline/);
    assert.equal(fetch.mock.callCount(), 1);
});

test('cancellation reaches an in-flight request and cannot return a completed result', async (t) => {
    // Aborting during the request must reach the fetch signal and reject the query.
    const controller = new AbortController();
    const fetch = t.mock.method(globalThis, 'fetch', async (_url: RequestInfo | URL, init?: RequestInit) => {
        assert.ok(init?.signal);
        controller.abort();
        assert.equal(init.signal.aborted, true);
        throw new DOMException('Aborted', 'AbortError');
    });
    await assert.rejects(runAnalysis('https://sql.example', 'SELECT 1', controller.signal));
    assert.equal(fetch.mock.callCount(), 1);
});
