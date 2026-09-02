import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import test from 'node:test';
import type { DecodedQueryResult } from '@exowarexyz/sql';

import {
    subscribeBlocksFromTargets,
    type BlockMetadataSqlClient,
} from '../src/indexer.ts';
import type { PublishedProofTarget } from '../src/proofTarget.ts';

test('block subscription queries SQL after the target and keeps its sequence floor', async () => {
    const events: string[] = [];
    const target = proofTarget(7n, 23n, 0xa5);
    const sql = sqlClient(async (query, options) => {
        events.push('sql');
        assert.match(query, /FROM block_meta WHERE height = 7 LIMIT 1/);
        assert.equal(options?.minSequenceNumber, 23n);
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
    const sql = sqlClient(async (_query, options) => {
        queries++;
        assert.equal(options?.minSequenceNumber, 29n);
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
    const columns = ['height', 'digest', 'tx_count'];
    if (height === undefined || blockDigest === undefined || txCount === undefined) {
        return { sequenceNumber, columns, rows: [] };
    }
    const cells = [height, blockDigest, txCount];
    return {
        sequenceNumber,
        columns,
        rows: [
            {
                cells,
                values: { height, digest: blockDigest, tx_count: txCount },
            },
        ],
    };
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
