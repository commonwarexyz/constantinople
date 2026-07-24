import assert from 'node:assert/strict';
import test from 'node:test';

import {
    encodeCommitteeTransactionBody,
    encodeSignedCommitteeTransaction,
    fromHex,
    toHex,
    transactionBodyFromSignedTransaction,
} from '../src/codec.ts';

const SENDER =
    '00d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00';
const PEER = '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c';
const COMMITTEE_GOLDEN =
    `${SENDER}010203040506070801${PEER}0104c00002092328`;
const COMMITTEE_DIGEST_GOLDEN =
    'fc058f6b5b1aaba75b2b7e84b490571b3b932e9db015b89397d2d788b892eb1f';

test('committee body matches the finalized Rust golden vector', () => {
    const body = encodeCommitteeTransactionBody({
        senderPublicKey: fromHex(SENDER),
        nonce: 0x0102030405060708n,
        peer: `ed25519:${PEER}`,
        address: '192.0.2.9:9000',
    });

    assert.equal(toHex(body), COMMITTEE_GOLDEN);
    assert.equal(body.length, 83);
    assert.equal(body[42], 1);
    assert.equal(toHex(body.slice(43, 75)), PEER);
});

test('signed committee updates hash the complete body', async () => {
    const encoded = await encodeSignedCommitteeTransaction(
        {
            senderPublicKey: fromHex(SENDER),
            nonce: 0x0102030405060708n,
            peer: `ed25519:${PEER}`,
            address: '192.0.2.9:9000',
        },
        async () => fromHex(`00${'44'.repeat(64)}`),
    );

    assert.equal(encoded.digestHex, COMMITTEE_DIGEST_GOLDEN);
    assert.equal(
        toHex(encoded.bytes.slice(0, COMMITTEE_GOLDEN.length / 2)),
        COMMITTEE_GOLDEN,
    );
});

test('committee bytes do not depend on the indexed target epoch', () => {
    const encodeForIndexedTargetEpoch = (targetEpoch: bigint) => {
        const snapshot = {
            targetEpoch,
        };
        const bytes = encodeCommitteeTransactionBody({
            senderPublicKey: fromHex(SENDER),
            nonce: 7n,
            peer: `ed25519:${PEER}`,
            address: null,
        });
        return { snapshot, bytes };
    };

    const first = encodeForIndexedTargetEpoch(300n);
    const second = encodeForIndexedTargetEpoch(301n);
    assert.notEqual(first.snapshot.targetEpoch, second.snapshot.targetEpoch);
    assert.deepEqual(first.bytes, second.bytes);
});

test('QMDB body parsing follows removal, IPv4, and IPv6 address framing', () => {
    for (const [address, suffix] of [
        [null, '00'],
        ['192.0.2.9:9000', '0104c00002092328'],
        ['[2001:db8::9]:9000', '010620010db80000000000000000000000092328'],
    ] as const) {
        const body = encodeCommitteeTransactionBody({
            senderPublicKey: fromHex(SENDER),
            nonce: 7n,
            peer: PEER,
            address,
        });
        const signed = fromHex(`${toHex(body)}${'55'.repeat(65)}`);

        assert.ok(toHex(body).endsWith(`${PEER}${suffix}`));
        assert.equal(toHex(transactionBodyFromSignedTransaction(signed)), toHex(body));
    }
});

test('QMDB body parsing rejects truncated committee fields', () => {
    const body = encodeCommitteeTransactionBody({
        senderPublicKey: fromHex(SENDER),
        nonce: 7n,
        peer: PEER,
        address: '[2001:db8::9]:9000',
    });

    for (let length = 43; length < body.length; length++) {
        assert.throws(
            () => transactionBodyFromSignedTransaction(body.slice(0, length)),
            /body is truncated/,
        );
    }
});
