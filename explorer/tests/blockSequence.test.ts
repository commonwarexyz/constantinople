import assert from 'node:assert/strict';
import test from 'node:test';

import {
    collectLiveBlocks,
    createBlockSequenceCursor,
    type HeightedBlock,
} from '../src/blockSequence.ts';

interface TestBlock extends HeightedBlock {
    readonly label: string;
}

test('live collection does not wait for missing heights', () => {
    const cursor = createBlockSequenceCursor();

    const observed = collectLiveBlocks(cursor, [block(7n), block(9n)]);

    assert.deepEqual(
        observed.map((entry) => entry.height),
        [7n, 9n],
    );
    assert.equal(cursor.latestHeight, 9n);
});

test('replayed duplicate heights are ignored', () => {
    const cursor = createBlockSequenceCursor();

    const first = collectLiveBlocks(cursor, [block(7n)]);
    const replay = collectLiveBlocks(cursor, [block(7n)]);

    assert.deepEqual(first.map((entry) => entry.height), [7n]);
    assert.deepEqual(replay, []);
});

test('late lower blocks are still collected once', () => {
    const cursor = createBlockSequenceCursor();

    collectLiveBlocks(cursor, [block(42n), block(44n)]);
    const late = collectLiveBlocks(cursor, [block(43n), block(44n)]);

    assert.deepEqual(
        late.map((entry) => entry.height),
        [43n],
    );
    assert.equal(cursor.latestHeight, 44n);
});

test('live cursor keeps duplicate tracking bounded', () => {
    const cursor = createBlockSequenceCursor(3);

    collectLiveBlocks(cursor, [block(1n), block(2n), block(3n), block(4n)]);

    assert.equal(cursor.seenHeights.size, 3);
    assert.deepEqual(Array.from(cursor.seenHeights), ['2', '3', '4']);
});

function block(height: bigint): TestBlock {
    return {
        height,
        label: height.toString(),
    };
}
