import assert from 'node:assert/strict';
import test from 'node:test';

import {
    consumeNonce,
    mergeNonceStates,
    nextAvailableNonce,
    reserveNonces,
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

test('restored reservations preserve gaps above the committed base', () => {
    const committed = nonceState(5n, 0n);

    const reserved = reserveNonces(committed, [6n]);

    assert.deepEqual(reserved, nonceState(5n, 0b1n));
    assert.equal(nextAvailableNonce(reserved), 5n);
});

test('older account refreshes cannot undo committed nonce observations', () => {
    const committed = mergeNonceStates(nonceState(6n, 0n), nonceState(5n, 0n));
    assert.equal(nextAvailableNonce(reserveNonces(committed, [])), 6n);

    const withBitmap = mergeNonceStates(nonceState(5n, 1n), nonceState(5n, 0n));
    assert.equal(nextAvailableNonce(reserveNonces(withBitmap, [5n])), 7n);
});

test('restored reservations consume contiguous submitted nonces in order', () => {
    const committed = nonceState(5n, 0n);

    const reserved = reserveNonces(committed, [7n, 5n, 6n, 6n]);

    assert.deepEqual(reserved, nonceState(8n, 0n));
});

function nonceState(base: bigint, bitmap: bigint): NonceState {
    return { base, bitmap };
}
