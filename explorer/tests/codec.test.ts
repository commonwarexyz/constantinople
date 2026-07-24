import assert from 'node:assert/strict';
import test from 'node:test';

import {
    accountKeyFromPublicKey,
    encodeSignedTransaction,
    encodeTransferTransactionBody,
    fromHex,
    toHex,
    transactionBodyFromSignedTransaction,
} from '../src/codec.ts';

const SENDER =
    '00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00';
const TRANSFER_GOLDEN =
    `${SENDER}010203040506070800${'22'.repeat(32)}1112131415161718`;
const TRANSFER_DIGEST_GOLDEN =
    'a5ff840481cb4f15e7742583ebaf4456813f4088d4b683f645add31d14578b59';

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

test('transfer body matches the finalized Rust golden vector', () => {
    const body = encodeTransferTransactionBody({
        senderPublicKey: fromHex(SENDER),
        nonce: 0x0102030405060708n,
        toAccountKey: fromHex('22'.repeat(32)),
        value: 0x1112131415161718n,
    });

    assert.equal(toHex(body), TRANSFER_GOLDEN);
    assert.equal(body.length, 83);
    assert.equal(body[42], 0);
});

test('signed transfers hash the tagged body and append the encoded signature', async () => {
    const signature = fromHex(`01${'44'.repeat(64)}`);
    const encoded = await encodeSignedTransaction(
        {
            senderPublicKey: fromHex(SENDER),
            nonce: 0x0102030405060708n,
            toAccountKey: fromHex('22'.repeat(32)),
            value: 0x1112131415161718n,
        },
        async () => signature,
    );

    assert.equal(toHex(encoded.bytes), `${TRANSFER_GOLDEN}${toHex(signature)}`);
    assert.equal(encoded.digestHex, TRANSFER_DIGEST_GOLDEN);
    assert.equal(
        toHex(transactionBodyFromSignedTransaction(encoded.bytes)),
        TRANSFER_GOLDEN,
    );
});

test('transfer value retains the NonZeroU64 invariant', () => {
    assert.throws(
        () =>
            encodeTransferTransactionBody({
                senderPublicKey: fromHex(SENDER),
                nonce: 0n,
                toAccountKey: fromHex('22'.repeat(32)),
                value: 0n,
            }),
        /value must be greater than zero/,
    );
});
