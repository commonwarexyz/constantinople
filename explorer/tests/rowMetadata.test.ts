import assert from 'node:assert/strict';
import test from 'node:test';

import type { TransactionRowMetadataResult } from '../src/qmdb.ts';
import { TransactionRowMetadataCache, type TransactionRowMetadataBatch } from '../src/rowMetadata.ts';

const FIRST = 'aa'.repeat(32);
const SECOND = 'bb'.repeat(32);

test('a later certificate floor reissues one shared batch and never lowers it', async () => {
    const floors: bigint[] = [];
    const cache = new TransactionRowMetadataCache({
        fetchBatch: async (floor) => {
            floors.push(floor);
            return batch(floor);
        },
        isRetryable: () => true,
        floor: 10n,
        prefetched: Promise.resolve(batch(10n)),
    });

    assert.deepEqual(await cache.lookup(FIRST, 10n), { location: 1n, sequenceNumber: 10n });
    assert.deepEqual(floors, []);

    const raised = await Promise.all([cache.lookup(FIRST, 12n), cache.lookup(SECOND, 12n)]);
    assert.deepEqual(raised.map((metadata) => metadata?.sequenceNumber), [12n, 12n]);
    assert.deepEqual(floors, [12n]);

    assert.deepEqual(await cache.lookup(SECOND, 11n), { location: 2n, sequenceNumber: 12n });
    assert.deepEqual(floors, [12n]);
});

test('only transient batch failures are cleared for a replacement query', async () => {
    for (const [retryable, calls] of [[true, 2], [false, 1]] as const) {
        let attempts = 0;
        const cache = new TransactionRowMetadataCache({
            fetchBatch: async () => {
                attempts += 1;
                throw new Error('batch failed');
            },
            isRetryable: () => retryable,
            floor: 10n,
        });
        await assert.rejects(cache.lookup(FIRST, 10n), /batch failed/);
        await assert.rejects(cache.lookup(SECOND, 10n), /batch failed/);
        assert.equal(attempts, calls);
    }
});

test('a missing digest switches to its own query after one batch miss', async () => {
    let attempts = 0;
    const missing = new Error('missing');
    const cache = new TransactionRowMetadataCache({
        fetchBatch: async () => {
            attempts += 1;
            return new Map<string, TransactionRowMetadataResult>([[FIRST, { status: 'missing', error: missing }]]);
        },
        isRetryable: () => true,
        floor: 10n,
    });
    await assert.rejects(cache.lookup(FIRST, 10n), (error) => error === missing);
    assert.equal(await cache.lookup(FIRST, 10n), undefined);
    assert.equal(await cache.lookup(FIRST, 12n), undefined);
    assert.equal(attempts, 1);
});

test('an invalid digest stays terminal across attempts', async () => {
    const invalid = new Error('invalid');
    const cache = new TransactionRowMetadataCache({
        fetchBatch: async () => new Map<string, TransactionRowMetadataResult>([
            [FIRST, { status: 'invalid', error: invalid }],
        ]),
        isRetryable: () => true,
        floor: 10n,
    });
    await assert.rejects(cache.lookup(FIRST, 10n), (error) => error === invalid);
    await assert.rejects(cache.lookup(FIRST, 10n), (error) => error === invalid);
});

test('a digest omitted from the batch is rejected', async () => {
    const cache = new TransactionRowMetadataCache({
        fetchBatch: async () => new Map(),
        isRetryable: () => true,
        floor: 10n,
    });
    await assert.rejects(cache.lookup(FIRST, 10n), /omitted tx digest/);
});

function batch(sequenceNumber: bigint): TransactionRowMetadataBatch {
    return new Map<string, TransactionRowMetadataResult>([
        [FIRST, { status: 'indexed', metadata: { location: 1n, sequenceNumber } }],
        [SECOND, { status: 'indexed', metadata: { location: 2n, sequenceNumber } }],
    ]);
}
