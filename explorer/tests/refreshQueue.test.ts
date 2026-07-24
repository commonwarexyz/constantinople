import assert from 'node:assert/strict';
import test from 'node:test';

import { createRefreshQueue } from '../src/refreshQueue.ts';

test('rapid refreshes coalesce without starving intermediate results', async () => {
    const { queue, loads, results, errors, loading } = refreshHarness();

    const first = queue.request();
    const second = queue.request();
    const third = queue.request();
    assert.equal(loads.length, 1);

    loads[0].resolve(124);
    await flushMicrotasks();
    assert.equal(loads.length, 2);
    assert.deepEqual(results, [124]);

    loads[1].resolve(128);
    await Promise.all([first, second, third]);

    assert.deepEqual(results, [124, 128]);
    assert.deepEqual(errors, []);
    assert.deepEqual(loading, [true, false]);
});

test('a superseded error is hidden while loading stays active', async () => {
    const { queue, loads, results, errors, loading } = refreshHarness();

    const first = queue.request();
    const latest = queue.request();
    loads[0].reject(new Error('stale failure'));
    await flushMicrotasks();

    assert.deepEqual(errors, []);
    assert.deepEqual(loading, [true]);
    loads[1].resolve(7);
    await Promise.all([first, latest]);

    assert.deepEqual(results, [7]);
    assert.deepEqual(errors, []);
    assert.deepEqual(loading, [true, false]);
});

test('a latest error is reported without discarding the last result', async () => {
    const { queue, loads, results, errors, loading } = refreshHarness();

    const initial = queue.request();
    loads[0].resolve(5);
    await initial;

    const refresh = queue.request();
    loads[1].reject(new Error('latest failure'));
    await refresh;

    assert.deepEqual(results, [5]);
    assert.deepEqual(
        errors.map((error) => (error instanceof Error ? error.message : String(error))),
        ['latest failure'],
    );
    assert.deepEqual(loading, [true, false, true, false]);
});

test('dispose aborts the active load and ignores late completion', async () => {
    const { queue, loads, results, errors, loading } = refreshHarness();

    const requested = queue.request();
    queue.dispose();
    await requested;
    assert.equal(loads[0].signal.aborted, true);

    loads[0].resolve(9);
    await flushMicrotasks();
    await queue.request();
    assert.deepEqual(results, []);
    assert.deepEqual(errors, []);
    assert.deepEqual(loading, [true, false]);
});

interface PendingLoad<T> {
    readonly promise: Promise<T>;
    readonly resolve: (value: T) => void;
    readonly reject: (error: unknown) => void;
    readonly signal: AbortSignal;
}

function refreshHarness() {
    const loads: PendingLoad<number>[] = [];
    const results: number[] = [];
    const errors: unknown[] = [];
    const loading: boolean[] = [];
    const queue = createRefreshQueue({
        load: (signal) => {
            const next = deferred<number>(signal);
            loads.push(next);
            return next.promise;
        },
        onResult: (result) => results.push(result),
        onError: (error) => errors.push(error),
        onLoading: (value) => loading.push(value),
    });
    return { queue, loads, results, errors, loading };
}

function deferred<T>(signal: AbortSignal): PendingLoad<T> {
    let resolve!: (value: T) => void;
    let reject!: (error: unknown) => void;
    const promise = new Promise<T>((resolvePromise, rejectPromise) => {
        resolve = resolvePromise;
        reject = rejectPromise;
    });
    return { promise, resolve, reject, signal };
}

async function flushMicrotasks(): Promise<void> {
    await Promise.resolve();
    await Promise.resolve();
}
