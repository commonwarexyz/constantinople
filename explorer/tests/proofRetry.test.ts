import assert from 'node:assert/strict';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';
import { HttpError } from '@exowarexyz/sdk';

import {
    isMissingAccountProofError,
    isRetryableAccountProofError,
    isRetryableProofError,
    isRetryableSequenceConsistencyError,
    retryAccountWork,
} from '../src/proofRetry.ts';
import { assertTransactionLocationBeforeTip, transactionProofTip } from '../src/proofMath.ts';

test('SQL tx metadata misses are retried while the indexer catches up', () => {
    assert.equal(
        isRetryableProofError('tx digest 1adb68d9800...a2a15bb3 is not finalized yet'),
        true,
    );
});

test('sequence freshness gates are retried while a query node catches up', () => {
    assert.equal(
        isRetryableProofError('[aborted] consistency_not_ready'),
        true,
    );
    assert.equal(
        isRetryableAccountProofError('[aborted] consistency_not_ready'),
        true,
    );
    assert.equal(
        isRetryableSequenceConsistencyError('[aborted] consistency_not_ready'),
        true,
    );
    assert.equal(isRetryableSequenceConsistencyError('[unavailable] disconnected'), false);
});

test('structured consistency lag is retried without accepting unrelated aborted errors', () => {
    const cause = new ConnectError('minimum consistency token is not yet visible', Code.Aborted);
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

test('account work remains pending beyond the old retry bound', async () => {
    const controller = new AbortController();
    const delays: number[] = [];
    let attempts = 0;

    const result = await retryAccountWork(
        async () => {
            attempts += 1;
            if (attempts <= 13) {
                throw new Error('[aborted] consistency_not_ready');
            }
            return 'ready';
        },
        controller.signal,
        isRetryableSequenceConsistencyError,
        async (delayMs) => {
            delays.push(delayMs);
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
                throw new Error('[aborted] consistency_not_ready');
            },
            controller.signal,
            isRetryableSequenceConsistencyError,
            async () => {
                controller.abort();
                throw new Error('account lookup cancelled');
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
        async () => {
            publishedTarget = { height: 42n, sequenceNumber: 705n };
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
    assert.equal(isRetryableProofError('transaction location 3 is outside finalized block range'), false);
});

test('QMDB transaction proof tip uses inclusive operation location', () => {
    assert.equal(transactionProofTip(128n), 127n);
});

test('latest-root transaction proofs allow locations before the sync floor', () => {
    assert.doesNotThrow(() => assertTransactionLocationBeforeTip(567443n, 900000n));
});

test('latest-root transaction proofs reject only future locations', () => {
    assert.throws(
        () => assertTransactionLocationBeforeTip(900000n, 900000n),
        /outside finalized transaction range/,
    );
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
    assert.equal(
        isRetryableAccountProofError('tx digest abc123 missing from raw transaction index'),
        true,
    );
    assert.equal(isRetryableAccountProofError('finalization missing at height 42'), true);
    assert.equal(isRetryableAccountProofError('[unavailable] transport disconnected'), true);
    assert.equal(isRetryableAccountProofError('TypeError: Failed to fetch'), true);
});

test('missing account proof rows are not retried as index catch-up', () => {
    const detail = 'account a0bf226776...6068e27a is not indexed';
    assert.equal(isMissingAccountProofError(detail), true);
    assert.equal(isRetryableAccountProofError(detail), false);
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
                async () => {},
            ),
            new RegExp(detail),
        );
        assert.equal(attempts, 1);
    }
});

test('rows newer than the provable finalization are retried until coverage catches up', () => {
    assert.equal(
        isRetryableAccountProofError(
            'transaction location 7849756400 is not yet covered by a provable finalization',
        ),
        true,
    );
});
