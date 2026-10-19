import assert from 'node:assert/strict';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';
import { Client, HttpError, StoreKeyPrefix } from '@exowarexyz/sdk';
import { SqlClient } from '@exowarexyz/sql';

import {
    accountRetryReason,
    errorMessage,
    isConsistencyNotReadyError,
    isMissingAccountProofError,
    isRetryableAccountProofError,
    isRetryableProofError,
    retryAccountWork,
} from '../src/proofRetry.ts';
import { transactionProofTip } from '../src/proofMath.ts';

const CONSISTENCY_NOT_READY = '[aborted] minimum consistency token is not yet visible';
const NETWORK_FAILURES = [
    'Failed to fetch',
    'fetch failed',
    'Load failed',
    'network error',
    'terminated',
    'Error in body stream',
    'Error in input stream',
    'NetworkError when attempting to fetch resource.',
];

test('SQL tx metadata misses are retried while the indexer catches up', () => {
    assert.equal(
        isRetryableProofError('tx digest 1adb68d9800...a2a15bb3 is not finalized yet'),
        true,
    );
});

test('sequence freshness gates are retried while a query node catches up', () => {
    for (const detail of [CONSISTENCY_NOT_READY, `HTTP error: 409 ${CONSISTENCY_NOT_READY}`]) {
        assert.equal(isRetryableProofError(detail), true);
        assert.equal(isRetryableAccountProofError(detail), true);
        assert.equal(isConsistencyNotReadyError(detail), true);
    }
    assert.equal(isConsistencyNotReadyError('[unavailable] disconnected'), false);
});

test('structured consistency lag is retried without accepting unrelated aborted errors', () => {
    const cause = new ConnectError('consistency lag', Code.Aborted);
    cause.details.push({
        type: 'google.rpc.ErrorInfo',
        value: new Uint8Array([
            0x0a, 0x15,
            ...new TextEncoder().encode('CONSISTENCY_NOT_READY'),
        ]),
    });
    const retryable = new HttpError(409, cause.message, cause.code, cause);

    assert.equal(isRetryableProofError(retryable), true);
    assert.equal(
        isRetryableProofError(new ConnectError('transaction digest mismatch', Code.Aborted)),
        false,
    );
});

test('Wasm load failures are terminal because the SDK caches failed initialization', () => {
    for (const status of ['403 Forbidden', '404 Not Found']) {
        const error = new Error(`failed to fetch Wasm: ${status} fetching 'http://localhost:5173/verifier.wasm'`);

        assert.equal(isRetryableProofError(error), false);
        assert.equal(isRetryableAccountProofError(error), false);
    }

    for (const detail of NETWORK_FAILURES) {
        for (const error of [new TypeError(detail), `TypeError: ${detail}`]) {
            assert.equal(isRetryableProofError(error), false, detail);
            assert.equal(isRetryableAccountProofError(error), false, detail);
        }
    }
});

test('SDK transport failures remain retryable after client error wrapping', async (t) => {
    for (const detail of NETWORK_FAILURES) {
        // The SDK captures fetch when a client is built, so clients follow the mock.
        t.mock.method(globalThis, 'fetch', async () => {
            throw new TypeError(detail);
        });
        const sql = new SqlClient('https://example.invalid');
        const store = new Client('https://example.invalid').store(new StoreKeyPrefix(new Uint8Array([2])));

        for (const read of [
            () => sql.query('SELECT 1', 1n),
            () => store.get(new Uint8Array([1]), 1n),
        ]) {
            await assert.rejects(read(), (error: unknown) => {
                const rethrown = new Error(`${errorMessage(error)} · height 1`, { cause: error });
                for (const candidate of [error, rethrown]) {
                    assert.equal(isRetryableProofError(candidate), true, detail);
                    assert.equal(accountRetryReason(candidate), 'retrying after service error', detail);
                }
                return true;
            });
        }
        t.mock.restoreAll();
    }
});

test('Unknown errors without a network fetch cause remain terminal', async (t) => {
    t.mock.method(globalThis, 'fetch', async () => new Response('upstream failure', { status: 500 }));
    const sql = new SqlClient('https://example.invalid');
    const store = new Client('https://example.invalid').store(new StoreKeyPrefix(new Uint8Array([2])));

    for (const read of [
        () => sql.query('SELECT 1', 1n),
        () => store.get(new Uint8Array([1]), 1n),
    ]) {
        await assert.rejects(read(), (error: unknown) => {
            assert.equal(isRetryableProofError(error), false);
            assert.equal(accountRetryReason(error), undefined);
            return true;
        });
    }

    for (const error of [
        new ConnectError('Failed to fetch', Code.Unknown),
        new ConnectError('Error in body stream', Code.Unknown),
        new ConnectError('Error in input stream', Code.Unknown),
        new ConnectError('missing EndStreamResponse', Code.Unknown),
        new Error('missing EndStreamResponse'),
        new ConnectError('Invalid URL', Code.Unknown, undefined, undefined, new TypeError('Invalid URL')),
        new ConnectError('Invalid header value', Code.Unknown, undefined, undefined, new TypeError('Invalid header value')),
        new ConnectError('Failed to fetch', Code.Internal, undefined, undefined, new TypeError('Failed to fetch')),
        new Error('[unknown] Failed to fetch · height 1'),
    ]) {
        assert.equal(isRetryableProofError(error), false, error.message);
        assert.equal(accountRetryReason(error), undefined, error.message);
    }
});

test('account work remains pending beyond the old retry bound', async () => {
    const controller = new AbortController();
    const delays: number[] = [];
    let attempts = 0;

    const result = await retryAccountWork(
        async () => {
            attempts += 1;
            if (attempts <= 13) {
                throw new Error(CONSISTENCY_NOT_READY);
            }
            return 'ready';
        },
        controller.signal,
        isConsistencyNotReadyError,
        {
            wait: async (delayMs) => {
                delays.push(delayMs);
                return true;
            },
        },
    );

    assert.equal(result, 'ready');
    assert.equal(attempts, 14);
    assert.equal(delays.length, 13);
    assert.equal(Math.max(...delays), 2_000);
});

test('account work stops when retry backoff is aborted', async () => {
    const controller = new AbortController();
    let attempts = 0;

    await assert.rejects(
        retryAccountWork(
            async () => {
                attempts += 1;
                throw new Error(CONSISTENCY_NOT_READY);
            },
            controller.signal,
            isConsistencyNotReadyError,
            {
                wait: async () => {
                    controller.abort();
                    return false;
                },
            },
        ),
        /account lookup cancelled/,
    );
    assert.equal(attempts, 1);
});

test('account proof retries adopt a newer published target', async () => {
    const controller = new AbortController();
    let publishedTarget = { height: 41n, sequenceNumber: 700n };
    const attempts: Array<{ height: bigint; sequenceNumber: bigint }> = [];

    const result = await retryAccountWork(
        async () => {
            const target = publishedTarget;
            attempts.push(target);
            if (target.height === 41n) {
                throw new Error('account location 303 is outside finalized state range');
            }
            return target;
        },
        controller.signal,
        isRetryableAccountProofError,
        {
            wait: async () => {
                publishedTarget = { height: 42n, sequenceNumber: 705n };
                return true;
            },
        },
    );

    assert.deepEqual(attempts, [
        { height: 41n, sequenceNumber: 700n },
        { height: 42n, sequenceNumber: 705n },
    ]);
    assert.deepEqual(result, { height: 42n, sequenceNumber: 705n });
});

test('immutable Simplex configuration errors are terminal', () => {
    assert.equal(isRetryableProofError('failed to decode Simplex verification material'), false);
    assert.equal(isRetryableProofError('Simplex verification material contains trailing bytes'), false);
});

test('QMDB transaction root mismatches are terminal', () => {
    assert.equal(
        isRetryableProofError(
            'historical ops root did not match expected root · height 337 · location 4865826 · tip 4865827 · proof start 4865826 · ops 1 · block index 17845 · block txs 17846',
        ),
        false,
    );
});

test('non-indexer proof errors are not retried forever', () => {
    assert.equal(isRetryableProofError('transaction location 3 is not a transaction append of block 7 · appends 4..7'), false);
});

test('QMDB transaction proof tip uses inclusive operation location', () => {
    assert.equal(transactionProofTip(128n), 127n);
});

test('account proof index catch-up errors are retried', () => {
    assert.equal(
        isRetryableAccountProofError('account location 303 is outside finalized state range'),
        true,
    );
    assert.equal(
        isRetryableAccountProofError('[out_of_range] requested proof tip is not published yet'),
        true,
    );
    assert.equal(
        isRetryableAccountProofError(
            '[out_of_range] requested location 304 is above published writer watermark 303',
        ),
        true,
    );
    assert.equal(isRetryableAccountProofError('finalization missing at height 42'), true);
    assert.equal(isRetryableAccountProofError('[unavailable] transport disconnected'), true);
    assert.equal(isRetryableAccountProofError(ConnectError.from(new TypeError('Failed to fetch'))), true);
});

test('missing account proof rows are not retried as index catch-up', () => {
    const detail = 'account a0bf226776...6068e27a is not indexed';
    assert.equal(isMissingAccountProofError(detail), true);
    assert.equal(isRetryableAccountProofError(detail), false);
});

test('account retries distinguish indexer lag from service errors', () => {
    for (const detail of [
        CONSISTENCY_NOT_READY,
        'finalization missing at height 42',
        'transaction location 9 is not yet covered by a provable finalization',
        '[out_of_range] requested proof tip is not published yet',
    ]) {
        assert.equal(accountRetryReason(new Error(detail)), 'waiting for indexer', detail);
    }
    for (const error of [
        new Error('[unavailable] transport disconnected'),
        ConnectError.from(new TypeError('Failed to fetch')),
    ]) {
        assert.equal(accountRetryReason(error), 'retrying after service error', error.message);
    }
    for (const detail of ['SQL transaction body does not match transaction digest']) {
        assert.equal(accountRetryReason(new Error(detail)), undefined, detail);
        assert.equal(isRetryableAccountProofError(new Error(detail)), false, detail);
    }
});

test('account retries report each retryable failure before waiting', async () => {
    const controller = new AbortController();
    const events: string[] = [];
    const failures = ['[unavailable] transport disconnected', 'finalization missing at height 42'];

    const result = await retryAccountWork(
        async () => {
            const failure = failures.shift();
            if (failure) throw new Error(failure);
            return 'ready';
        },
        controller.signal,
        isRetryableAccountProofError,
        {
            wait: async () => {
                events.push('wait');
                return true;
            },
            onRetry: (error) => events.push(String(accountRetryReason(error))),
        },
    );

    assert.equal(result, 'ready');
    assert.deepEqual(events, ['retrying after service error', 'wait', 'waiting for indexer', 'wait']);
});

test('QMDB account root mismatches are terminal', () => {
    assert.equal(isRetryableAccountProofError('historical ops root did not match expected root'), false);
});

test('deterministic account proof failures are terminal', async () => {
    const details = [
        'finalized artifact is missing certified header bytes',
        'finalized artifact commitment does not match certificate payload',
        'historical ops root did not match expected root',
        'account proof value does not match account index row',
        'QMDB account proof evaluated before the requested Store sequence',
        'QMDB transaction proof evaluated before the requested Store sequence',
        'SQL query evaluated before the requested Store sequence',
    ];

    for (const detail of details) {
        const controller = new AbortController();
        let attempts = 0;

        await assert.rejects(
            retryAccountWork(
                async () => {
                    attempts += 1;
                    throw new Error(detail);
                },
                controller.signal,
                isRetryableAccountProofError,
                { wait: async () => true },
            ),
            new RegExp(detail),
        );
        assert.equal(attempts, 1);
    }
});

test('rows newer than the provable finalization are retried until coverage catches up', () => {
    const detail = 'transaction location 7849756400 is not yet covered by a provable finalization';

    assert.equal(isRetryableAccountProofError(detail), true);
    assert.equal(isRetryableProofError(detail), true);
});
