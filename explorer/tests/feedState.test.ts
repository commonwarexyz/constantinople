import assert from 'node:assert/strict';
import test from 'node:test';
import { appendVerifiedBatch, EMPTY_FEED } from '../src/feedState.ts';
import type { VerifiedBlockBatch } from '../src/indexer.ts';

function batch(heights: number[], receivedAt: number, txCount = 0): VerifiedBlockBatch {
    const height = BigInt(heights.at(-1)!);
    return {
        blocks: heights.map((value) => ({
            height: BigInt(value), digest: new Uint8Array(32).fill(value), txCount,
            timestampMs: BigInt(value * 1000),
            finality: { certifiedHeight: height, certificateView: 9n },
        })),
        target: {
            height, view: 9n, contextView: 8n, timestampMs: height * 1000n,
            blockDigest: new Uint8Array(32).fill(Number(height)),
            stateRoot: new Uint8Array(32), stateStart: 0n, stateTip: 1n,
            transactionsRoot: new Uint8Array(32), transactionsStart: 0n, transactionsTip: 1n,
        },
        sequenceNumberHint: 500n, receivedAt,
    };
}

test('one verified batch publishes its rows, counts and proof target together', () => {
    const initial = appendVerifiedBatch(EMPTY_FEED, batch([1], 50_000, 3));
    const incoming = batch([2, 3], 52_000, 2);
    const next = appendVerifiedBatch(initial, incoming);
    assert.deepEqual(next.blocks.map((block) => block.height), [3n, 2n, 1n]);
    assert.equal(next.totalBlocksObserved, 3);
    assert.equal(next.totalTxObserved, 7);
    assert.equal(next.publishedProofTarget, incoming.target);
    assert.deepEqual(next.observedRateWindow, { firstBlockAt: 50_000, latestBlockAt: 52_000 });
    assert.equal(next.blocks[0]!.timestampMs, 3_000n);
    assert.equal(next.blocks[1]!.finality.certifiedHeight, 3n);
    assert.equal('sequenceNumber' in next.publishedProofTarget!, false);
    assert.deepEqual(initial.blocks.map((block) => block.height), [1n]);
    assert.deepEqual(incoming.blocks.map((block) => block.height), [2n, 3n]);
});

test('equal sequence hints retain every authenticated height and zero transaction count', () => {
    const initial = appendVerifiedBatch(EMPTY_FEED, batch([100], 1));
    const next = appendVerifiedBatch(initial, batch([105, 106], 2));
    assert.deepEqual(next.blocks.map((block) => block.height), [106n, 105n, 100n]);
    assert.equal(next.totalBlocksObserved, 3);
    assert.equal(next.totalTxObserved, 0);
});

test('bounded chart history does not discard observations from a large authenticated batch', () => {
    const incoming = batch(Array.from({ length: 500 }, (_, index) => index + 1), 200, 1);
    const next = appendVerifiedBatch(EMPTY_FEED, incoming);
    assert.equal(next.blocks.length, 360);
    assert.equal(next.blocks[0]!.height, 500n);
    assert.equal(next.blocks.at(-1)!.height, 141n);
    assert.equal(next.totalBlocksObserved, 500);
    assert.equal(next.totalTxObserved, 500);
    assert.equal(next.publishedProofTarget, incoming.target);
});

test('an empty replay leaves both authenticated state and local observation window unchanged', () => {
    const initial = appendVerifiedBatch(EMPTY_FEED, batch([1], 1));
    const replay = { ...batch([2], 100), blocks: [] };
    assert.equal(appendVerifiedBatch(initial, replay), initial);
});
