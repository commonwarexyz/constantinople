import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import test from 'node:test';
import type { DecodedQueryResult, Table } from '@exowarexyz/sql';

import {
    subscribeBlocksFromTargets,
    type BlockMetadataSqlClient,
} from '../src/indexer.ts';
import type { PublishedProofTarget } from '../src/proofTarget.ts';

test('block subscription queries SQL after the target and keeps its sequence floor', async () => {
    const events: string[] = [];
    const target = proofTarget(7n, 23n, 0xa5);
    const sql = sqlClient(async (query, minSequenceNumber) => {
        events.push('sql');
        assert.match(query, /FROM block_meta WHERE height = 7 LIMIT 1/);
        assert.equal(minSequenceNumber, 23n);
        return queryResult(41n, 7n, target.blockDigest, 9n);
    });
    const stream = subscribeBlocksFromTargets(sql, targets(target, events));

    const next = await stream.next();

    assert.equal(next.done, false);
    assert.deepEqual(events, ['target', 'sql']);
    assert.equal(next.value.height, 7n);
    assert.deepEqual(next.value.digest, target.blockDigest);
    assert.equal(next.value.txCount, 9);
    assert.equal(next.value.sequence, 23n);
    await stream.return();
});

test('missing block metadata retries without dropping the target', async () => {
    const target = proofTarget(8n, 29n, 0x3c);
    let targetPulls = 0;
    let queries = 0;
    const source = {
        async *[Symbol.asyncIterator]() {
            targetPulls++;
            yield target;
            targetPulls++;
        },
    };
    const sql = sqlClient(async (_query, minSequenceNumber) => {
        queries++;
        assert.equal(minSequenceNumber, 29n);
        if (queries === 1) return queryResult(29n);
        return queryResult(31n, 8n, target.blockDigest, 4n);
    });
    const stream = subscribeBlocksFromTargets(sql, source, { reconnectDelayMs: 0 });

    const next = await stream.next();

    assert.equal(next.done, false);
    assert.equal(next.value.height, 8n);
    assert.equal(queries, 2);
    assert.equal(targetPulls, 1);
    await stream.return();
});

test('missing block metadata catch-up stops when cancelled', async () => {
    const target = proofTarget(8n, 29n, 0x3c);
    const controller = new AbortController();
    let queried!: () => void;
    const queryStarted = new Promise<void>((resolve) => {
        queried = resolve;
    });
    const sql = sqlClient(async () => {
        queried();
        return queryResult(29n);
    });
    const stream = subscribeBlocksFromTargets(sql, targets(target), {
        signal: controller.signal,
        reconnectDelayMs: 10_000,
    });

    const next = stream.next();
    await queryStarted;
    await new Promise((resolve) => setTimeout(resolve, 0));
    controller.abort();

    assert.deepEqual(await next, { done: true, value: undefined });
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('block metadata must match the proof target height and digest', async (context) => {
    const target = proofTarget(9n, 34n, 0x11);

    await context.test('height mismatch', async () => {
        const sql = sqlClient(async () => queryResult(34n, 10n, target.blockDigest, 1n));
        const stream = subscribeBlocksFromTargets(sql, targets(target));

        await assert.rejects(stream.next(), /height 10 does not match proof target 9/);
    });

    await context.test('digest mismatch', async () => {
        const sql = sqlClient(async () => queryResult(34n, 9n, digest(0x12), 1n));
        const stream = subscribeBlocksFromTargets(sql, targets(target));

        await assert.rejects(stream.next(), /digest does not match proof target at height 9/);
    });
});

test('block metadata retries backend errors until cancelled', async () => {
    const target = proofTarget(12n, 44n, 0x72);
    const controller = new AbortController();
    const errors: string[] = [];
    let reconnects = 0;
    const sql = sqlClient(async () => {
        throw new Error('backend unavailable');
    });
    const stream = subscribeBlocksFromTargets(sql, targets(target), {
        signal: controller.signal,
        reconnectDelayMs: 0,
        onError: (message) => {
            errors.push(message);
            if (errors.length === 2) {
                assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
                controller.abort();
            }
        },
        onReconnect: () => {
            reconnects++;
        },
    });

    assert.deepEqual(await stream.next(), { done: true, value: undefined });
    assert.deepEqual(errors, ['backend unavailable', 'backend unavailable']);
    assert.equal(reconnects, 2);
});

test('streamed metadata waits for its publication target and avoids a point read', async () => {
    const first = proofTarget(7n, 23n, 0xa5);
    const second = proofTarget(8n, 29n, 0x3c);
    const queries: string[] = [];
    const source = streamingSql([queryResult(25n, 8n, second.blockDigest, 9n)], async (query) => {
        queries.push(query);
        await source.ready;
        return queryResult(23n, 7n, first.blockDigest, 1n);
    });
    let publish!: () => void;
    const published = new Promise<void>((resolve) => { publish = resolve; });
    const stream = subscribeBlocksFromTargets(source.client, (async function* () {
        yield first;
        await published;
        yield second;
    })());

    assert.equal((await stream.next()).value?.height, 7n);
    let delivered = false;
    const pending = stream.next().then((value) => { delivered = true; return value; });
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(delivered, false);
    publish();

    const block = (await pending).value;
    assert.equal(block?.height, 8n);
    assert.equal(block?.sequence, 29n);
    assert.equal(block?.txCount, 9);
    assert.equal(queries.length, 1);
    await stream.return();
    assert.equal(source.stopped(), true);
});

test('a streamed row beyond the publication sequence requires a point read', async () => {
    const first = proofTarget(7n, 23n, 0xa5);
    const second = proofTarget(8n, 29n, 0x3c);
    const floors: Array<bigint | undefined> = [];
    const source = streamingSql([queryResult(30n, 8n, second.blockDigest, 99n)], async (_query, minSequenceNumber) => {
        floors.push(minSequenceNumber);
        await source.ready;
        return floors.length === 1
            ? queryResult(23n, 7n, first.blockDigest, 1n)
            : queryResult(31n, 8n, second.blockDigest, 9n);
    });
    const stream = subscribeBlocksFromTargets(source.client, (async function* () {
        yield first;
        yield second;
    })());

    await stream.next();
    assert.equal((await stream.next()).value?.txCount, 9);
    assert.deepEqual(floors, [23n, 29n]);
    await stream.return();
});

test('streamed metadata must match the published digest', async () => {
    const first = proofTarget(7n, 23n, 0xa5);
    const second = proofTarget(8n, 29n, 0x3c);
    const source = streamingSql([queryResult(25n, 8n, digest(0xff), 9n)], async () => {
        await source.ready;
        return queryResult(23n, 7n, first.blockDigest, 1n);
    });
    const stream = subscribeBlocksFromTargets(source.client, (async function* () {
        yield first;
        yield second;
    })());

    await stream.next();
    await assert.rejects(stream.next(), /digest does not match proof target at height 8/);
    assert.equal(source.stopped(), true);
});

test('evicted metadata is fetched without losing a published block', async () => {
    const first = proofTarget(7n, 23n, 0xa5);
    let queries = 0;
    const frames = Array.from({ length: 140 }, (_, i) =>
        queryResult(25n, BigInt(i + 8), digest(0xa5), 1n));
    const source = streamingSql(frames, async () => {
        queries++;
        await source.ready;
        return queryResult(29n, queries === 1 ? 7n : 8n, first.blockDigest, 1n);
    });
    const stream = subscribeBlocksFromTargets(source.client, (async function* () {
        yield first;
        yield proofTarget(8n, 29n, 0xa5);
        yield proofTarget(147n, 30n, 0xa5);
    })());

    assert.equal((await stream.next()).value?.height, 7n);
    assert.equal((await stream.next()).value?.height, 8n);
    assert.equal((await stream.next()).value?.height, 147n);
    assert.equal(queries, 2);
    await stream.return();
});

test('metadata subscription resumes live after a lost cursor while point reads cover gaps', async () => {
    const first = proofTarget(7n, 23n, 0xa5);
    const second = proofTarget(8n, 29n, 0x3c);
    const source = streamingSql([queryResult(25n, 8n, second.blockDigest, 9n)], async () => {
        await source.ready;
        return queryResult(23n, 7n, first.blockDigest, 1n);
    });
    const subscribe = source.client.subscribe!;
    const cursors: Array<bigint | undefined> = [];
    source.client.subscribe = async function* (request, options) {
        cursors.push(request.sinceSequenceNumber);
        if (cursors.length === 1) throw new Error('cursor evicted');
        yield* subscribe(request, options);
    };
    const errors: string[] = [];
    const stream = subscribeBlocksFromTargets(source.client, (async function* () {
        yield first;
        yield second;
    })(), { reconnectDelayMs: 0, onError: (message) => errors.push(message) });

    assert.equal((await stream.next()).value?.height, 7n);
    assert.equal((await stream.next()).value?.height, 8n);
    assert.deepEqual(cursors, [23n, undefined]);
    assert.deepEqual(errors, ['cursor evicted']);
    await stream.return();
    assert.equal(source.stopped(), true);
});

function streamingSql(frames: DecodedQueryResult[], query: BlockMetadataSqlClient['query']) {
    let ready!: () => void;
    const received = new Promise<void>((resolve) => { ready = resolve; });
    let stopped = false;
    const client: BlockMetadataSqlClient = {
        query,
        async *subscribe(_request, options) {
            const signal = options?.signal;
            assert.ok(signal);
            try {
                for (const frame of frames) yield frame;
                ready();
                if (!signal.aborted) {
                    await new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }));
                }
            } finally {
                stopped = true;
            }
        },
    };
    return { client, ready: received, stopped: () => stopped };
}

function sqlClient(
    query: BlockMetadataSqlClient['query'],
): BlockMetadataSqlClient {
    return { query };
}

function queryResult(
    sequenceNumber: bigint,
    height?: bigint,
    blockDigest?: Uint8Array,
    txCount?: bigint,
): DecodedQueryResult {
    if (height === undefined || blockDigest === undefined || txCount === undefined) {
        return { sequenceNumber, table: testTable([]) };
    }
    return {
        sequenceNumber,
        table: testTable([{ height, digest: blockDigest, tx_count: txCount }]),
    };
}

function testTable(rows: readonly Record<string, unknown>[]): Table {
    return {
        numRows: rows.length,
        getChild(column: string) {
            if (!rows.some((row) => Object.hasOwn(row, column))) return null;
            return { get: (index: number) => rows[index]?.[column] };
        },
    } as unknown as Table;
}

function proofTarget(
    height: bigint,
    sequenceNumber: bigint,
    seed: number,
): PublishedProofTarget {
    return {
        height,
        blockDigest: digest(seed),
        sequenceNumber,
    };
}

async function* targets(target: PublishedProofTarget, events?: string[]) {
    events?.push('target');
    yield target;
}

function digest(seed: number): Uint8Array {
    return new Uint8Array(32).fill(seed);
}
