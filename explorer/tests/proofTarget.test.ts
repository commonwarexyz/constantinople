import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError } from '@connectrpc/connect';
import { Client, HttpError, TraversalMode } from '@exowarexyz/sdk';
import { getEventListeners } from 'node:events';

import {
    createSharedProofTargets,
    createSharedProofTargetsFromStore,
    decodePublishedProofTarget,
    subscribePublishedProofTargetsFromStore,
    type PublishedProofTargetStore,
} from '../src/proofTarget.ts';

function heightKey(height: bigint): Uint8Array {
    const key = new Uint8Array(8);
    new DataView(key.buffer).setBigUint64(0, height);
    return key;
}

test('provable target decodes its big-endian height and block digest', () => {
    const digest = new Uint8Array(32).fill(0xa5);
    const target = decodePublishedProofTarget(
        heightKey(0x0102_0304_0506_0708n),
        digest,
        19n,
    );

    assert.equal(target.height, 0x0102_0304_0506_0708n);
    assert.deepEqual(target.blockDigest, digest);
    assert.equal(target.sequenceNumber, 19n);
});

test('provable target rejects malformed keys and digests', () => {
    assert.throws(
        () => decodePublishedProofTarget(new Uint8Array(7), new Uint8Array(32)),
        /key must be 8 bytes/,
    );
    assert.throws(
        () => decodePublishedProofTarget(new Uint8Array(8), new Uint8Array(31)),
        /digest must be 32 bytes/,
    );
});

test('provable target subscription bootstraps then resumes without a gap', async () => {
    const subscriptions: bigint[] = [];
    const controller = new AbortController();
    const store = {
        async query() {
            return queryResult(4n, 11n);
        },
        subscribe(filters: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            subscriptions.push(filters.sinceSequenceNumber ?? 0n);
            return batches([
                {
                    sequenceNumber: 14n,
                    entries: [{ key: heightKey(5n), value: digest(5) }],
                },
            ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
    });

    const bootstrap = await stream.next();
    assert.equal(bootstrap.value?.height, 4n);
    assert.equal(bootstrap.value?.sequenceNumber, 11n);

    const live = await stream.next();
    assert.equal(live.value?.height, 5n);
    assert.equal(live.value?.sequenceNumber, 14n);
    assert.deepEqual(subscriptions, [12n]);

    controller.abort();
    await stream.return();
});

test('provable target subscription yields every target in a batch in height order', async () => {
    const controller = new AbortController();
    const store = {
        async query() {
            return queryResult(4n, 11n);
        },
        subscribe() {
            return batches([
                {
                    sequenceNumber: 14n,
                    entries: [
                        { key: heightKey(7n), value: digest(7) },
                        { key: heightKey(4n), value: digest(4) },
                        { key: heightKey(5n), value: digest(5) },
                        { key: heightKey(6n), value: digest(6) },
                    ],
                },
            ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
    });

    assert.equal((await stream.next()).value?.height, 4n);
    const heights: bigint[] = [];
    for (let i = 0; i < 3; i++) {
        const next = await stream.next();
        heights.push(next.value?.height ?? -1n);
        assert.equal(next.value?.sequenceNumber, 14n);
    }
    assert.deepEqual(heights, [5n, 6n, 7n]);

    controller.abort();
    await stream.return();
});

test('provable target subscription waits for the first target after an empty bootstrap', async () => {
    const subscriptions: bigint[] = [];
    const controller = new AbortController();
    const store = {
        async query() {
            return { results: [], sequenceNumber: 3n };
        },
        subscribe(filters: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            subscriptions.push(filters.sinceSequenceNumber ?? 0n);
            return batches([
                {
                    sequenceNumber: 6n,
                    entries: [{ key: heightKey(1n), value: digest(1) }],
                },
            ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
    });

    const first = await stream.next();
    assert.equal(first.value?.height, 1n);
    assert.equal(first.value?.sequenceNumber, 6n);
    assert.deepEqual(subscriptions, [4n]);

    controller.abort();
    await stream.return();
});

test('provable target subscription releases a pending bootstrap on abort', async () => {
    const controller = new AbortController();
    let seenSignal: AbortSignal | undefined;
    let started!: () => void;
    const queryStarted = new Promise<void>((resolve) => {
        started = resolve;
    });
    const store = {
        query(...args: Parameters<PublishedProofTargetStore['query']>) {
            seenSignal = args[6]?.signal;
            started();
            return new Promise<never>(() => {});
        },
        subscribe() {
            return batches([]);
        },
    } as PublishedProofTargetStore;
    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
    });

    const result = stream.next();
    await queryStarted;
    controller.abort();

    assert.deepEqual(await result, { done: true, value: undefined });
    assert.equal(seenSignal, controller.signal);
});

test('provable target subscription preserves its cursor after a generic error', async () => {
    const subscriptions: bigint[] = [];
    const controller = new AbortController();
    const store = {
        async query() {
            return queryResult(4n, 11n);
        },
        subscribe(filters: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            subscriptions.push(filters.sinceSequenceNumber ?? 0n);
            return subscriptions.length === 1
                ? failedBatchStream('network unavailable')
                : batches([
                    {
                        sequenceNumber: 15n,
                        entries: [{ key: heightKey(5n), value: digest(5) }],
                    },
                ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
    });

    assert.equal((await stream.next()).value?.height, 4n);
    assert.equal((await stream.next()).value?.height, 5n);
    assert.deepEqual(subscriptions, [12n, 12n]);

    controller.abort();
    await stream.return();
});

test('provable target subscription fails closed on a malformed batch entry', async () => {
    const errors: string[] = [];
    const subscriptions: bigint[] = [];
    const controller = new AbortController();
    const store = {
        async query() {
            return queryResult(4n, 11n);
        },
        subscribe(filters: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            subscriptions.push(filters.sinceSequenceNumber ?? 0n);
            return batches([
                {
                    sequenceNumber: 14n,
                    entries: [{ key: heightKey(5n), value: new Uint8Array(31) }],
                },
            ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
        onError: (message) => errors.push(message),
    });

    assert.equal((await stream.next()).value?.height, 4n);
    await assert.rejects(stream.next(), /provable target digest must be 32 bytes/);
    assert.deepEqual(subscriptions, [12n]);
    assert.deepEqual(errors, ['provable target digest must be 32 bytes']);

    controller.abort();
    await stream.return();
});

test('provable target subscription reboots after retention eviction', async () => {
    let queryCalls = 0;
    const subscriptions: bigint[] = [];
    const controller = new AbortController();
    const store = {
        async query() {
            queryCalls++;
            return queryCalls === 1 ? queryResult(7n, 20n) : queryResult(8n, 31n);
        },
        subscribe(filters: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            subscriptions.push(filters.sinceSequenceNumber ?? 0n);
            return subscriptions.length === 1
                ? failedBatchStream(storeStreamError(Code.OutOfRange, 'BATCH_EVICTED'))
                : batches([
                    {
                        sequenceNumber: 34n,
                        entries: [{ key: heightKey(9n), value: digest(9) }],
                    },
                ]);
        },
    } as PublishedProofTargetStore;

    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
    });

    assert.equal((await stream.next()).value?.height, 7n);
    const recovered = await stream.next();
    assert.equal(recovered.value?.height, 8n);
    assert.equal(recovered.value?.sequenceNumber, 31n);
    assert.equal(queryCalls, 2);
    assert.equal((await stream.next()).value?.height, 9n);
    assert.deepEqual(subscriptions, [21n, 32n]);

    controller.abort();
    await stream.return();
});

function queryResult(height: bigint, sequenceNumber: bigint) {
    return {
        results: [{ key: heightKey(height), value: digest(Number(height)) }],
        sequenceNumber,
    };
}

function digest(seed: number): Uint8Array {
    return new Uint8Array(32).fill(seed);
}

async function* batches(
    values: Array<{
        sequenceNumber: bigint;
        entries: Array<{ key: Uint8Array; value: Uint8Array }>;
    }>,
) {
    yield* values;
}

async function* failedBatchStream(error: unknown) {
    throw error;
}

function storeStreamError(code: Code, reason: string): HttpError {
    const cause = new ConnectError('Store stream failed', code);
    cause.details.push({
        type: 'google.rpc.ErrorInfo',
        value: new BinaryWriter()
            .tag(1, WireType.LengthDelimited)
            .string(reason)
            .tag(2, WireType.LengthDelimited)
            .string('log.stream')
            .finish(),
    });
    return new HttpError(400, 'Store stream failed', code, cause);
}


test('bootstrap uses an inclusive big-endian lower bound with eight heights of slack', async () => {
    for (const hint of [0n, 3n, 8n, 0x0102_0304_0506_0708n, 0xffff_ffff_ffff_ffffn]) {
        const controller = new AbortController();
        const store = {
            async query(...args: Parameters<PublishedProofTargetStore['query']>) {
                assert.deepEqual(args[0], heightKey(hint > 8n ? hint - 8n : 0n));
                assert.equal(args[1], undefined);
                assert.equal(args[2], 1);
                assert.equal(args[3], 1);
                assert.equal(args[4], TraversalMode.REVERSE);
                return queryResult(hint, 10n);
            },
            subscribe() { return batches([]); },
        } as PublishedProofTargetStore;
        const stream = subscribePublishedProofTargetsFromStore(store, {
            lastKnownHeight: hint,
            signal: controller.signal,
        });
        assert.equal((await stream.next()).value?.height, hint);
        controller.abort();
        await stream.return();
    }
});

test('a stale high hint falls back once and resumes from the fallback sequence', async () => {
    const controller = new AbortController();
    let queries = 0;
    const cursors: Array<bigint | undefined> = [];
    const store = {
        async query(...args: Parameters<PublishedProofTargetStore['query']>) {
            queries++;
            assert.equal(args[2], 1);
            assert.equal(args[3], 1);
            if (queries === 1) {
                assert.deepEqual(args[0], heightKey(992n));
                return { results: [], sequenceNumber: 20n };
            }
            assert.deepEqual(args[0], heightKey(0n));
            assert.equal(args[5], 20n);
            return queryResult(3n, 23n);
        },
        subscribe(request: Parameters<PublishedProofTargetStore['subscribe']>[0]) {
            cursors.push(request.sinceSequenceNumber);
            return batches([{ sequenceNumber: 25n, entries: [{ key: heightKey(4n), value: digest(4) }] }]);
        },
    } as PublishedProofTargetStore;
    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        lastKnownHeight: 1000n,
    });
    assert.equal((await stream.next()).value?.height, 3n);
    assert.equal((await stream.next()).value?.height, 4n);
    assert.equal(queries, 2);
    assert.deepEqual(cursors, [24n]);
    controller.abort();
    await stream.return();
});

test('retention eviction bounds bootstrap by the newest streamed height', async () => {
    const controller = new AbortController();
    const starts: Array<Uint8Array | undefined> = [];
    let subscriptions = 0;
    const store = {
        async query(...args: Parameters<PublishedProofTargetStore['query']>) {
            starts.push(args[0]);
            return starts.length === 1 ? queryResult(70n, 100n) : queryResult(85n, 130n);
        },
        async *subscribe() {
            subscriptions++;
            if (subscriptions === 1) {
                yield { sequenceNumber: 110n, entries: [{ key: heightKey(80n), value: digest(80) }] };
                throw storeStreamError(Code.OutOfRange, 'BATCH_EVICTED');
            }
        },
    } as PublishedProofTargetStore;
    const stream = subscribePublishedProofTargetsFromStore(store, {
        signal: controller.signal,
        reconnectDelayMs: 0,
        lastKnownHeight: 60n,
    });
    assert.equal((await stream.next()).value?.height, 70n);
    assert.equal((await stream.next()).value?.height, 80n);
    assert.equal((await stream.next()).value?.height, 85n);
    assert.deepEqual(starts, [heightKey(52n), heightKey(72n)]);
    controller.abort();
    await stream.return();
});

test('shared targets use one query and stream while retaining every slow-consumer target', async () => {
    const controller = new AbortController();
    let queries = 0;
    let subscriptions = 0;
    let streamSignal: AbortSignal | undefined;
    const store = {
        async query() { queries++; return queryResult(4n, 11n); },
        async *subscribe(_request: unknown, options: { signal?: AbortSignal } = {}) {
            subscriptions++;
            streamSignal = options.signal;
            yield {
                sequenceNumber: 15n,
                entries: [5n, 6n, 7n].map((height) => ({ key: heightKey(height), value: digest(Number(height)) })),
            };
            await new Promise<void>((resolve) => {
                if (streamSignal?.aborted) resolve();
                else streamSignal?.addEventListener('abort', () => resolve(), { once: true });
            });
        },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store, { signal: controller.signal });
    const proof = shared.subscribe();
    const blocks = shared.subscribe();
    for (const height of [4n, 5n, 6n, 7n]) assert.equal((await proof.next()).value?.height, height);
    assert.equal(queries, 1);
    assert.equal(subscriptions, 1);
    for (const height of [4n, 5n, 6n, 7n]) assert.equal((await blocks.next()).value?.height, height);
    const late = shared.subscribe();
    assert.equal((await late.next()).value?.height, 7n);
    const pending = [proof.next(), blocks.next(), late.next()];
    controller.abort();
    assert.deepEqual(await Promise.all(pending), Array(3).fill({ done: true, value: undefined }));
    assert.equal(streamSignal?.aborted, true);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('a consumer abort releases only that consumer while owner close cancels bootstrap', async () => {
    const owner = new AbortController();
    const consumer = new AbortController();
    let querySignal: AbortSignal | undefined;
    const store = {
        query(...args: Parameters<PublishedProofTargetStore['query']>) {
            querySignal = args[6]?.signal;
            return new Promise<never>(() => {});
        },
        subscribe() { return batches([]); },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store, { signal: owner.signal });
    const first = shared.subscribe({ signal: consumer.signal });
    const second = shared.subscribe();
    const firstPending = first.next();
    consumer.abort();
    assert.deepEqual(await firstPending, { done: true, value: undefined });
    assert.equal(querySignal?.aborted, false);
    assert.equal(getEventListeners(consumer.signal, 'abort').length, 0);
    const secondPending = second.next();
    shared.close();
    assert.deepEqual(await secondPending, { done: true, value: undefined });
    assert.equal(querySignal?.aborted, true);
    assert.equal(getEventListeners(owner.signal, 'abort').length, 0);
});


test('shared terminal errors reject all consumers and late subscribers', async () => {
    const store = {
        async query() { return queryResult(4n, 11n); },
        subscribe() {
            return batches([{ sequenceNumber: 15n, entries: [{ key: heightKey(5n), value: new Uint8Array(1) }] }]);
        },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store);
    const first = shared.subscribe();
    const second = shared.subscribe();
    await Promise.all([first.next(), second.next()]);
    await Promise.all([
        assert.rejects(first.next(), /digest must be 32 bytes/),
        assert.rejects(second.next(), /digest must be 32 bytes/),
    ]);
    await assert.rejects(shared.subscribe().next(), /digest must be 32 bytes/);
    shared.close();
});

test('return releases a waiting shared iterator without aborting its peers', async () => {
    let querySignal: AbortSignal | undefined;
    const store = {
        query(...args: Parameters<PublishedProofTargetStore['query']>) {
            querySignal = args[6]?.signal;
            return new Promise<never>(() => {});
        },
        subscribe() { return batches([]); },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store);
    const first = shared.subscribe();
    const second = shared.subscribe();
    const pending = first.next();
    await first.return!();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.equal(querySignal?.aborted, false);
    shared.close();
    assert.deepEqual(await second.next(), { done: true, value: undefined });
});

test('an aborted shared owner starts no bootstrap and delivers no cached target', async () => {
    const controller = new AbortController();
    controller.abort();
    const store = {
        async query() { assert.fail('aborted owner queried Store'); },
        subscribe() { assert.fail('aborted owner opened a stream'); },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store, { signal: controller.signal });
    assert.deepEqual(await shared.subscribe().next(), { done: true, value: undefined });
    shared.close();
});


test('factory persists heights across reloads and isolates normalized Store URLs', async (context) => {
    const values = new Map<string, string>();
    mockHeightStorage(context, {
        getItem: (key) => values.get(key) ?? null,
        setItem: (key, value) => { values.set(key, value); },
    });
    let publishedHeight = 100n;
    let expectedStart = 0n;
    const store = {
        async query(...args: Parameters<PublishedProofTargetStore['query']>) {
            assert.deepEqual(args[0], heightKey(expectedStart));
            return queryResult(publishedHeight, 120n);
        },
        subscribe() { return batches([]); },
    } as PublishedProofTargetStore;
    context.mock.method(Client.prototype, 'store', () => store as ReturnType<Client['store']>);

    const first = createSharedProofTargets('http://store/deployment-a/');
    assert.equal((await first.subscribe().next()).value?.height, 100n);
    first.close();
    expectedStart = 92n;
    publishedHeight = 110n;
    const reloaded = createSharedProofTargets('http://store/deployment-a');
    assert.equal((await reloaded.subscribe().next()).value?.height, 110n);
    reloaded.close();
    expectedStart = 0n;
    const other = createSharedProofTargets('http://store/deployment-b');
    await other.subscribe().next();
    other.close();
    assert.equal(values.size, 2);
});

test('invalid persisted hints and storage failures cannot prevent bootstrap', async (context) => {
    let value: string | null = null;
    let failRead = false;
    mockHeightStorage(context, {
        getItem() {
            if (failRead) throw new Error('storage denied');
            return value;
        },
        setItem() { throw new Error('storage full'); },
    });
    const store = {
        async query(...args: Parameters<PublishedProofTargetStore['query']>) {
            assert.deepEqual(args[0], heightKey(0n));
            return queryResult(3n, 10n);
        },
        subscribe() { return batches([]); },
    } as PublishedProofTargetStore;
    context.mock.method(Client.prototype, 'store', () => store as ReturnType<Client['store']>);
    for (value of [null, 'garbage', '-1', '18446744073709551616', '9'.repeat(1000)]) {
        const shared = createSharedProofTargets('http://store');
        assert.equal((await shared.subscribe().next()).value?.height, 3n);
        shared.close();
    }
    failRead = true;
    const shared = createSharedProofTargets('http://store');
    assert.equal((await shared.subscribe().next()).value?.height, 3n);
    shared.close();
});

test('a slow consumer fails explicitly at the queue bound while proofs keep advancing', async () => {
    const store = {
        async query() { return queryResult(0n, 0n); },
        async *subscribe(_request: unknown, options: { signal?: AbortSignal } = {}) {
            for (let height = 1n; height <= 4100n; height++) {
                yield { sequenceNumber: height, entries: [{ key: heightKey(height), value: digest(1) }] };
            }
            await new Promise<void>((resolve) => {
                if (options.signal?.aborted) resolve();
                else options.signal?.addEventListener('abort', () => resolve(), { once: true });
            });
        },
    } as PublishedProofTargetStore;
    const shared = createSharedProofTargetsFromStore(store);
    const slow = shared.subscribe();
    const fast = shared.subscribe();
    for (let height = 0n; height <= 4100n; height++) {
        assert.equal((await fast.next()).value?.height, height);
    }
    await assert.rejects(slow.next(), /exceeded 4096 queued targets/);
    shared.close();
});

function mockHeightStorage(context: TestContext, storage: Pick<Storage, 'getItem' | 'setItem'>) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
    Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
    context.after(() => {
        if (descriptor) Object.defineProperty(globalThis, 'localStorage', descriptor);
        else Reflect.deleteProperty(globalThis, 'localStorage');
    });
}
