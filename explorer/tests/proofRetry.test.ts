import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';

import {
    accountRetryReason,
    errorMessage,
    isRetryableAccountProofError,
    isRetryableProofError,
    retryAccountWork,
    waitForRetry,
} from '../src/proofRetry.ts';

const NETWORK_FAILURES = [
    'Failed to fetch',
    'fetch failed',
    'Load failed',
    'The Internet connection appears to be offline.',
    'The network connection was lost.',
    'network error',
    'terminated',
    'Error in body stream',
    'Error in input stream',
    'NetworkError when attempting to fetch resource.',
];

test('typed unavailability and deadlines retry independently of their message', () => {
    for (const code of [Code.Unavailable, Code.DeadlineExceeded]) {
        const error = new ConnectError('request could not complete', code);
        for (const candidate of [error, new Error('proof request failed', { cause: error })]) {
            assert.equal(isRetryableProofError(candidate), true);
            assert.equal(isRetryableAccountProofError(candidate), true);
            assert.equal(accountRetryReason(candidate), 'retrying after service error');
        }
    }
});

test('other service codes remain terminal even when the message resembles an outage', () => {
    for (const code of [
        Code.Canceled, Code.Unknown, Code.InvalidArgument, Code.NotFound, Code.AlreadyExists,
        Code.PermissionDenied, Code.ResourceExhausted, Code.FailedPrecondition, Code.Aborted,
        Code.OutOfRange, Code.Unimplemented, Code.Internal, Code.DataLoss, Code.Unauthenticated,
    ]) {
        const error = new ConnectError('[unavailable] Failed to fetch', code);
        assert.equal(isRetryableProofError(error), false, Code[code]);
        assert.equal(isRetryableAccountProofError(error), false, Code[code]);
        assert.equal(accountRetryReason(error), undefined, Code[code]);
    }
});

test('wrapped fetch failures retry only with a recognized local cause', () => {
    for (const detail of NETWORK_FAILURES) {
        const error = ConnectError.from(new TypeError(detail));
        const wrapped = new Error(`${errorMessage(error)} at height 1`, { cause: error });
        for (const candidate of [error, wrapped]) {
            assert.equal(isRetryableProofError(candidate), true, detail);
            assert.equal(isRetryableAccountProofError(candidate), true, detail);
        }
        for (const candidate of [new TypeError(detail), new ConnectError(detail, Code.Unknown)]) {
            assert.equal(isRetryableProofError(candidate), false, detail);
        }
    }
});

test('truncated Connect streams retry without broadening application errors', () => {
    assert.equal(isRetryableProofError(ConnectError.from('missing EndStreamResponse')), true);
    assert.equal(isRetryableProofError(new ConnectError('protocol error: incomplete envelope', Code.InvalidArgument)), true);
    for (const error of [
        new ConnectError('missing EndStreamResponse', Code.Unknown),
        new ConnectError('protocol error: incomplete envelope', Code.Unknown),
        new ConnectError('protocol error: invalid envelope', Code.InvalidArgument),
        ConnectError.from('missing request message'),
        ConnectError.from(new TypeError('Invalid URL')),
        ConnectError.from(new TypeError('Invalid header value')),
    ]) {
        assert.equal(isRetryableProofError(error), false, error.message);
    }
});

test('serialized errors and local verification failures are terminal', () => {
    for (const message of [
        '[aborted] minimum consistency token is not yet visible',
        'HTTP error: 409 [aborted] minimum consistency token is not yet visible',
        '[unavailable] request failed',
        '[deadline_exceeded] request timed out',
        'failed to fetch Wasm: 403 Forbidden',
        'failed to decode Simplex verification material',
        'Simplex verification material contains trailing bytes',
        'transaction body does not match requested digest',
        'historical ops root did not match expected root',
        'aggregate response exceeds size limit',
    ]) {
        assert.equal(isRetryableProofError(message), false, message);
        assert.equal(isRetryableProofError(new Error(message)), false, message);
    }
});

test('cause traversal is bounded and handles cycles', () => {
    let error: Error = new ConnectError('unavailable', Code.Unavailable);
    for (let depth = 0; depth < 7; depth++) error = new Error('context', { cause: error });
    assert.equal(isRetryableProofError(error), true);
    assert.equal(isRetryableProofError(new Error('too deep', { cause: error })), false);
    const cycle = new Error('cycle');
    cycle.cause = cycle;
    assert.equal(isRetryableProofError(cycle), false);
});

test('account work waits after every transient failure with bounded backoff', async () => {
    const controller = new AbortController();
    const delays: number[] = [];
    let attempts = 0;
    const result = await retryAccountWork(
        async () => {
            if (++attempts <= 13) throw new ConnectError('publication pending', Code.Unavailable);
            return 'ready';
        },
        controller.signal,
        isRetryableProofError,
        { wait: async (delay) => { delays.push(delay); return true; } },
    );

    assert.equal(result, 'ready');
    assert.equal(attempts, 14);
    assert.deepEqual(delays, [350, 500, 650, 800, 950, 1_100, 1_250, 1_400, 1_550, 1_700, 1_850, 2_000, 2_000]);
});

test('account retries report each typed failure before waiting', async () => {
    const events: string[] = [];
    const failures = [
        new ConnectError('publication pending', Code.Unavailable),
        new ConnectError('request deadline', Code.DeadlineExceeded),
    ];
    const result = await retryAccountWork(
        async () => {
            const failure = failures.shift();
            if (failure) throw failure;
            return 'ready';
        },
        new AbortController().signal,
        isRetryableAccountProofError,
        {
            onRetry: (error) => events.push(errorMessage(error)),
            wait: async () => { events.push('wait'); return true; },
        },
    );

    assert.equal(result, 'ready');
    assert.deepEqual(events, ['[unavailable] publication pending', 'wait', '[deadline_exceeded] request deadline', 'wait']);
});

test('terminal failures preserve the original error and never wait', async () => {
    for (const error of [
        new ConnectError('invalid proof request', Code.InvalidArgument),
        new ConnectError('proof unavailable for snapshot', Code.FailedPrecondition),
        new Error('transaction body does not match requested digest'),
    ]) {
        let attempts = 0;
        await assert.rejects(retryAccountWork(
            async () => { attempts++; throw error; },
            new AbortController().signal,
            isRetryableProofError,
            {
                onRetry: () => assert.fail('terminal error reported as a retry'),
                wait: async () => { assert.fail('terminal error waited'); },
            },
        ), (caught) => caught === error);
        assert.equal(attempts, 1);
    }
});

test('abort releases a pending backoff and prevents another attempt', { timeout: 1_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    let backoff!: () => void;
    const waiting = new Promise<void>((resolve) => { backoff = resolve; });
    let attempts = 0;
    const pending = retryAccountWork(
        async () => { attempts++; throw new ConnectError('pending', Code.Unavailable); },
        controller.signal,
        isRetryableProofError,
        { wait: (_delay, signal) => {
            const result = waitForRetry(60_000, signal);
            backoff();
            return result;
        } },
    );
    const rejected = assert.rejects(pending, /account lookup cancelled/);
    await waiting;
    assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
    controller.abort();
    await rejected;
    assert.equal(attempts, 1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('abort during work discards a late successful result', async () => {
    const controller = new AbortController();
    let finish!: (value: string) => void;
    let attempts = 0;
    const pending = retryAccountWork(
        () => { attempts++; return new Promise<string>((resolve) => { finish = resolve; }); },
        controller.signal,
        isRetryableProofError,
        { onRetry: () => assert.fail('cancellation reported as a retry') },
    );
    const rejected = assert.rejects(pending, /account lookup cancelled/);
    controller.abort();
    finish('stale');
    await rejected;
    assert.equal(attempts, 1);
});

test('an already cancelled lookup starts no work or backoff', async () => {
    await assert.rejects(retryAccountWork(
        async () => { assert.fail('cancelled work started'); },
        AbortSignal.abort(),
        isRetryableProofError,
        { wait: async () => { assert.fail('cancelled work waited'); } },
    ), /account lookup cancelled/);
});

test('completed and already cancelled waits release their listeners', async () => {
    const controller = new AbortController();
    assert.equal(await waitForRetry(0, controller.signal), true);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    controller.abort();
    assert.equal(await waitForRetry(60_000, controller.signal), false);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});
