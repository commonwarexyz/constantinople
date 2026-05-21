import assert from 'node:assert/strict';
import test from 'node:test';

import {
    collectLiveBlocks,
    collectNewBlocks,
    createBlockSequenceCursor,
    type HeightedBlock,
} from '../src/blockSequence.ts';

interface TestBlock extends HeightedBlock {
    readonly label: string;
}

test('late lower blocks still fill a previously observed gap', async () => {
    const cursor = createBlockSequenceCursor();
    const missingResponses = new Map<string, readonly TestBlock[]>([
        ['43:43', []],
    ]);

    const first = await collectNewBlocks(
        cursor,
        [block(42n), block(44n)],
        async (fromHeight, toHeight) =>
            missingResponses.get(`${fromHeight}:${toHeight}`) ?? [],
    );
    assert.deepEqual(
        first.map((entry) => entry.height),
        [42n, 44n],
    );

    const late = await collectNewBlocks(cursor, [block(43n)], async () => {
        throw new Error('late lower block should not trigger another gap query');
    });
    assert.deepEqual(
        late.map((entry) => entry.height),
        [43n],
    );
});

test('replayed duplicate heights are ignored', async () => {
    const cursor = createBlockSequenceCursor();

    const first = await collectNewBlocks(cursor, [block(7n)], async () => []);
    const replay = await collectNewBlocks(cursor, [block(7n)], async () => []);

    assert.deepEqual(first.map((entry) => entry.height), [7n]);
    assert.deepEqual(replay, []);
});

test('live collection does not wait for missing heights', () => {
    const cursor = createBlockSequenceCursor();

    const observed = collectLiveBlocks(cursor, [block(7n), block(9n)]);

    assert.deepEqual(
        observed.map((entry) => entry.height),
        [7n, 9n],
    );
    assert.equal(cursor.latestHeight, 9n);
});

function block(height: bigint): TestBlock {
    return {
        height,
        label: height.toString(),
    };
}
