import assert from 'node:assert/strict';
import test from 'node:test';

import {
    TransactionSubmissionError,
    classifySubmissionResponse,
    isDeterministicSubmissionRejection,
    parseTxStatus,
    singleTransactionOutcome,
} from '../src/submissionResponse.ts';
import {
    SUBMISSION_TIMEOUT_MS,
    boundedSubmissionSignal,
} from '../src/submissionRequest.ts';

test('HTTP 200 carries status while HTTP 202 falls back to proof reconciliation', () => {
    assert.equal(classifySubmissionResponse(200), 'status');
    assert.equal(classifySubmissionResponse(202), 'pending');
    assert.equal(classifySubmissionResponse(204), 'ambiguous');
});

test('bad requests and oversized batches are deterministic rejections', () => {
    assert.equal(classifySubmissionResponse(400), 'rejected');
    assert.equal(classifySubmissionResponse(413), 'rejected');
});

test('admission exhaustion and server failures remain ambiguous', () => {
    assert.equal(classifySubmissionResponse(503), 'ambiguous');
    assert.equal(classifySubmissionResponse(500), 'ambiguous');
});

test('only classified rejection errors are terminal', () => {
    assert.equal(
        isDeterministicSubmissionRejection(
            new TransactionSubmissionError('rejected', 'transaction rejected'),
        ),
        true,
    );
    assert.equal(
        isDeterministicSubmissionRejection(
            new TransactionSubmissionError('ambiguous', 'delivery unknown'),
        ),
        false,
    );
    assert.equal(isDeterministicSubmissionRejection(new TypeError('fetch failed')), false);
});

test('transaction status responses parse every relayer outcome', () => {
    assert.deepEqual(parseTxStatus({ status: 'finalized', height: 7 }), {
        status: 'finalized',
        height: 7,
    });
    assert.deepEqual(
        parseTxStatus({
            status: 'partially_finalized',
            height: 8,
            included: 2,
            filtered: 1,
        }),
        {
            status: 'partially_finalized',
            height: 8,
            included: 2,
            filtered: 1,
        },
    );
    assert.deepEqual(parseTxStatus({ status: 'dropped' }), { status: 'dropped' });
});

test('invalid transaction status responses remain ambiguous', () => {
    assert.throws(() => parseTxStatus({ status: 'finalized', height: '7' }));
    assert.throws(() =>
        parseTxStatus({
            status: 'partially_finalized',
            height: 8,
            included: -1,
            filtered: 1,
        }),
    );
    assert.throws(() => parseTxStatus({ status: 'accepted' }));
});

test('partial singleton outcomes use counts only when they identify the transaction', () => {
    assert.deepEqual(
        singleTransactionOutcome({
            status: 'partially_finalized',
            height: 8,
            included: 1,
            filtered: 0,
        }),
        { kind: 'finalized', height: 8 },
    );
    assert.deepEqual(
        singleTransactionOutcome({
            status: 'partially_finalized',
            height: 8,
            included: 0,
            filtered: 1,
        }),
        { kind: 'dropped' },
    );
    assert.equal(
        singleTransactionOutcome({
            status: 'partially_finalized',
            height: 8,
            included: 1,
            filtered: 1,
        }).kind,
        'ambiguous',
    );
});

test('submission requests use a twelve second browser deadline', () => {
    assert.equal(SUBMISSION_TIMEOUT_MS, 12_000);
});

test('bounded submission requests preserve caller cancellation', () => {
    const caller = new AbortController();
    const request = boundedSubmissionSignal(caller.signal, 60_000);
    const reason = new Error('caller cancelled');

    caller.abort(reason);

    assert.equal(request.signal.aborted, true);
    assert.equal(request.signal.reason, reason);
    request.dispose();
});

test('bounded submission requests abort after their deadline', async () => {
    const request = boundedSubmissionSignal(undefined, 0);
    await new Promise<void>((resolve) => {
        request.signal.addEventListener('abort', () => resolve(), { once: true });
    });

    assert.equal(request.signal.aborted, true);
    assert.match(String(request.signal.reason), /timed out/);
    request.dispose();
});
