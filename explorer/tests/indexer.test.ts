import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeBlockFrame } from '../src/blockMetadata.ts';

test('block metadata decoding carries the indexed consensus epoch', () => {
    const digest = new Uint8Array(32).fill(7);
    const blocks = Array.from(
        decodeBlockFrame({
            sequenceNumber: 42n,
            columns: ['view', 'epoch', 'tx_count', 'digest', 'height'],
            rows: [
                {
                    values: {},
                    cells: [11n, 3n, 17n, digest, 511n],
                },
            ],
        }),
    );

    assert.equal(blocks.length, 1);
    assert.equal(blocks[0]?.height, 511n);
    assert.equal(blocks[0]?.epoch, 3n);
    assert.equal(blocks[0]?.txCount, 17);
    assert.deepEqual(blocks[0]?.digest, digest);
    assert.equal(blocks[0]?.sequence, 42n);
});

test('block metadata decoding requires the epoch column', () => {
    const blocks = Array.from(
        decodeBlockFrame({
            sequenceNumber: 1n,
            columns: ['height', 'digest', 'tx_count'],
            rows: [
                {
                    values: {},
                    cells: [1n, new Uint8Array(32), 0n],
                },
            ],
        }),
    );

    assert.deepEqual(blocks, []);
});
