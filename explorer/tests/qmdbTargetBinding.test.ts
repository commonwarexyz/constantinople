import assert from 'node:assert/strict';
import test from 'node:test';

import {
    QmdbOperationLogClient,
    type BytesLike,
    type OperationRangeRequest,
    type VerifiedFixedKeylessAppendProof,
    type VerifiedFixedUnorderedUpdateProof,
} from '@exowarexyz/qmdb';
import {
    SqlClient,
    type CellValue,
    type DecodedQueryResult,
    type SqlQueryOptions,
} from '@exowarexyz/sql';
import { toArrayBuffer, toHex } from '../src/codec.ts';
import {
    fetchAccountTransactionsPage,
    fetchAndVerifyAccountProof,
    fetchAndVerifyTransactionRowProof,
    type LatestProofTarget,
} from '../src/qmdb.ts';

const HEIGHT = 7n;
const FLOOR = 41n;
const LOCATION = 4n;

test('account proof retains the publication floor for SQL and QMDB', async (t) => {
    const target = { ...latestTarget(), stateStart: 2n };
    const sqlFloors: Array<bigint | undefined> = [];
    const sqlQueries: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, options: SqlQueryOptions = {}) => {
        sqlQueries.push(sql);
        sqlFloors.push(options.minSequenceNumber);
        return queryResult({
            balance: 9n,
            nonce_base: 2n,
            nonce_bitmap: 3n,
            qmdb_location: LOCATION,
        });
    });

    const qmdbFloors: Array<bigint | undefined> = [];
    t.mock.method(
        QmdbOperationLogClient.prototype,
        'getFixedUnorderedUpdate',
        async (
            request: OperationRangeRequest,
            expectedRoot: BytesLike,
            expectedLocation: bigint,
            expectedKey: BytesLike,
        ) => {
            qmdbFloors.push(request.minSequenceNumber);
            return unorderedProof(
                request,
                expectedRoot as Uint8Array,
                expectedLocation,
                expectedKey as Uint8Array,
            );
        },
    );

    await fetchAndVerifyAccountProof({
        qmdbUrl: 'http://qmdb',
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        target,
    });

    assert.deepEqual(sqlFloors, [FLOOR]);
    assert.match(sqlQueries[0] ?? '', /qmdb_location < 10 ORDER BY qmdb_location DESC/);
    assert.deepEqual(qmdbFloors, [FLOOR]);
});

test('account page retains the publication floor, height, and abort signal', async (t) => {
    const controller = new AbortController();
    const sqlOptions: SqlQueryOptions[] = [];
    const sqlQueries: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, options = {}) => {
        sqlQueries.push(sql);
        sqlOptions.push(options);
        return emptyQueryResult();
    });

    await fetchAccountTransactionsPage({
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        signal: controller.signal,
        minSequenceNumber: FLOOR,
        maxHeight: HEIGHT,
    });

    assert.equal(sqlOptions.length, 1);
    assert.equal(sqlOptions[0]?.signal, controller.signal);
    assert.equal(sqlOptions[0]?.minSequenceNumber, FLOOR);
    assert.match(sqlQueries[0] ?? '', /height <= 7/);
});

test('account page SQL request stops when its forwarded signal is aborted', async (t) => {
    const controller = new AbortController();
    t.mock.method(
        SqlClient.prototype,
        'query',
        async (_sql: string, options: SqlQueryOptions = {}) =>
            new Promise<DecodedQueryResult>((_resolve, reject) => {
                const signal = options.signal;
                assert.ok(signal);
                signal.addEventListener('abort', () => reject(signal.reason), { once: true });
            }),
    );

    const page = fetchAccountTransactionsPage({
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        signal: controller.signal,
        minSequenceNumber: FLOOR,
        maxHeight: HEIGHT,
    });
    controller.abort(new Error('account page cancelled'));

    await assert.rejects(page, /account page cancelled/);
});

test('transaction row proof retains the publication floor for SQL and QMDB', async (t) => {
    const target = latestTarget();
    const body = new Uint8Array(82).fill(0x33);
    const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', toArrayBuffer(body)),
    );
    const sqlFloors: Array<bigint | undefined> = [];
    t.mock.method(SqlClient.prototype, 'query', async (_sql: string, options: SqlQueryOptions = {}) => {
        sqlFloors.push(options.minSequenceNumber);
        return queryResult({ qmdb_location: LOCATION, body });
    });

    const qmdbFloors: Array<bigint | undefined> = [];
    t.mock.method(
        QmdbOperationLogClient.prototype,
        'getFixedKeylessAppend',
        async (
            request: OperationRangeRequest,
            expectedRoot: BytesLike,
            expectedLocation: bigint,
            expectedValue: BytesLike,
        ) => {
            qmdbFloors.push(request.minSequenceNumber);
            return keylessProof(
                request,
                expectedRoot as Uint8Array,
                expectedLocation,
                expectedValue as Uint8Array,
            );
        },
    );

    await fetchAndVerifyTransactionRowProof({
        qmdbUrl: 'http://qmdb',
        sqlUrl: 'http://sql',
        row: {
            digest: toHex(digest),
            direction: 'sent',
            counterparty: '44'.repeat(32),
            value: 1n,
            nonce: 2n,
            height: HEIGHT,
            blockIndex: 0,
        },
        target,
    });

    assert.deepEqual(sqlFloors, [FLOOR]);
    assert.deepEqual(qmdbFloors, [FLOOR]);
});

function queryResult(values: Record<string, CellValue>): DecodedQueryResult {
    return {
        sequenceNumber: FLOOR,
        columns: Object.keys(values),
        rows: [{ values, cells: Object.values(values) }],
    };
}

function emptyQueryResult(): DecodedQueryResult {
    return { sequenceNumber: FLOOR, columns: [], rows: [] };
}

function keylessProof(
    request: OperationRangeRequest,
    root: Uint8Array,
    location: bigint,
    value: Uint8Array,
): VerifiedFixedKeylessAppendProof {
    return {
        sequenceNumber: request.minSequenceNumber ?? 0n,
        location,
        value,
        root,
        proofSizeBytes: 12,
        operationCount: 1,
    };
}

function unorderedProof(
    request: OperationRangeRequest,
    root: Uint8Array,
    location: bigint,
    key: Uint8Array,
): VerifiedFixedUnorderedUpdateProof {
    return {
        sequenceNumber: request.minSequenceNumber ?? 0n,
        location,
        key,
        value: accountValue(9n, 2n, 3n),
        root,
        proofSizeBytes: 14,
        operationCount: 1,
    };
}

function latestTarget(): LatestProofTarget {
    return {
        height: HEIGHT,
        view: 9n,
        sequenceNumber: FLOOR,
        blockDigest: new Uint8Array(32),
        stateRoot: new Uint8Array(32).fill(0x51),
        stateStart: 1n,
        stateTip: 10n,
        transactionsRoot: new Uint8Array(32).fill(0x52),
        transactionsStart: 2n,
        transactionsTip: 8n,
    };
}

function accountValue(balance: bigint, nonce: bigint, nonceBitmap: bigint): Uint8Array {
    return concat(u64(balance), u64(nonce), u64(nonceBitmap));
}

function u64(value: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value);
    return bytes;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
    const result = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return result;
}
