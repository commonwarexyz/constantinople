import assert from 'node:assert/strict';
import test from 'node:test';
import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError } from '@connectrpc/connect';
import { HttpError } from '@exowarexyz/sdk';

import {
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
