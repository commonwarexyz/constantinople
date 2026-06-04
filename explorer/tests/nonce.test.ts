import assert from 'node:assert/strict';
import test from 'node:test';

import {
    consumeNonce,
    mergeNonceStates,
    nextAvailableNonce,
    type NonceState,
} from '../src/nonce.ts';

test('local reservation skips fetched bitmap nonces after consuming the base', () => {
    const fetched = nonceState(0n, 0b1n);

    const reserved = consumeNonce(fetched, nextAvailableNonce(fetched));

    assert.deepEqual(reserved, nonceState(2n, 0n));
});

test('merging fetched nonce state keeps consumed bitmap bits', () => {
    const local = nonceState(0n, 0n);
    const fetched = nonceState(0n, 0b1n);

    const merged = mergeNonceStates(local, fetched);
    const reserved = consumeNonce(merged, nextAvailableNonce(merged));

    assert.deepEqual(reserved, nonceState(2n, 0n));
});

function nonceState(base: bigint, bitmap: bigint): NonceState {
    return { base, bitmap };
}
