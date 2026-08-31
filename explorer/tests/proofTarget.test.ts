import assert from 'node:assert/strict';
import test from 'node:test';

import { decodePublishedProofTarget } from '../src/proofTarget.ts';

function heightKey(height: bigint): Uint8Array {
    const key = new Uint8Array(8);
    new DataView(key.buffer).setBigUint64(0, height);
    return key;
}

test('provable target decodes its big-endian height and block digest', () => {
    const digest = new Uint8Array(32).fill(0xa5);
    const target = decodePublishedProofTarget(heightKey(0x0102_0304_0506_0708n), digest);

    assert.equal(target.height, 0x0102_0304_0506_0708n);
    assert.deepEqual(target.blockDigest, digest);
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
