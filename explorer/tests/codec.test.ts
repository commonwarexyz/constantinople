import assert from 'node:assert/strict';
import test from 'node:test';

import {
    accountKeyFromPublicKey,
    encodeSignedTransaction,
    fromHex,
    signedTransactionBodyLength,
    toHex,
} from '../src/codec.ts';

test('ed25519 transaction public keys map to legacy account bytes', async () => {
    const publicKey = fromHex(`00${'11'.repeat(32)}00`);

    assert.equal(toHex(await accountKeyFromPublicKey(publicKey)), '11'.repeat(32));
});

test('secp256r1 transaction public keys map to hashed account bytes', async () => {
    const publicKey = fromHex(`01${'22'.repeat(33)}`);
    const digestInput = new Uint8Array(new ArrayBuffer(publicKey.byteLength));
    digestInput.set(publicKey);
    const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput));

    assert.equal(toHex(await accountKeyFromPublicKey(publicKey)), toHex(expected));
});

test('transfers encode in the tagged wire layout', async () => {
    const senderPublicKey = fromHex(`01${'22'.repeat(33)}`);
    const toAccountKey = fromHex('33'.repeat(32));
    const encoded = await encodeSignedTransaction(
        {
            senderPublicKey,
            toAccountKey,
            value: 7n,
            nonce: 9n,
        },
        async () => new Uint8Array(64),
    );

    // Layout: sender(34) | nonce(8) | tag(1) | to(32) | value(8) | signature(64).
    assert.equal(toHex(encoded.bytes.slice(0, 34)), toHex(senderPublicKey));
    assert.equal(toHex(encoded.bytes.slice(34, 42)), '0000000000000009');
    assert.equal(encoded.bytes[42], 0, 'transfer operation tag');
    assert.equal(toHex(encoded.bytes.slice(43, 75)), toHex(toAccountKey));
    assert.equal(toHex(encoded.bytes.slice(75, 83)), '0000000000000007');
    assert.equal(encoded.bytes.length, 83 + 64);
});

test('signed transaction body length handles transfer and channel open layouts', () => {
    const transfer = signedTransactionWithTag(0, 83);
    const open = signedTransactionWithTag(1, 83);

    assert.equal(signedTransactionBodyLength(transfer), 83);
    assert.equal(signedTransactionBodyLength(open), 83);
});

test('signed transaction body length handles channel close layout', () => {
    const close = signedTransactionWithTag(2, 157);

    assert.equal(signedTransactionBodyLength(close), 157);
});

test('signed transaction body length rejects malformed bodies', () => {
    assert.throws(
        () => signedTransactionBodyLength(new Uint8Array(42)),
        /truncated/,
    );

    assert.throws(
        () => signedTransactionBodyLength(signedTransactionWithTag(99, 83)),
        /unknown operation tag/,
    );
});

function signedTransactionWithTag(tag: number, bodyLength: number): Uint8Array {
    const bytes = new Uint8Array(bodyLength + 64);
    bytes[42] = tag;
    return bytes;
}
