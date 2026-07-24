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
    `${SENDER}010203040506070801ac02${PEER}0104c00002092328`;
const COMMITTEE_DIGEST_GOLDEN =
    '77976ccace7e707bcff0b3459ee0bf04aaa70b61e12e631a9f8ef23ff2a4d2bc';

test('committee body matches the finalized Rust golden vector', () => {
    const body = encodeCommitteeTransactionBody({
        senderPublicKey: fromHex(SENDER),
        nonce: 0x0102030405060708n,
        targetEpoch: 300n,
        peer: `ed25519:${PEER}`,
        address: '192.0.2.9:9000',
    });

    assert.equal(toHex(body), COMMITTEE_GOLDEN);
    assert.equal(body.length, 85);
    assert.equal(body[42], 1);
    assert.equal(toHex(body.slice(43, 45)), 'ac02');
});

test('signed committee updates hash the complete variable body', async () => {
    const encoded = await encodeSignedCommitteeTransaction(
        {
            senderPublicKey: fromHex(SENDER),
            nonce: 0x0102030405060708n,
            targetEpoch: 300n,
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

test('QMDB body parsing follows the committee epoch varint length', () => {
    for (const [epoch, encoded] of [
        [0n, '00'],
        [127n, '7f'],
        [128n, '8001'],
        [300n, 'ac02'],
        [(1n << 64n) - 1n, 'ffffffffffffffffff01'],
    ] as const) {
        const body = encodeCommitteeTransactionBody({
            senderPublicKey: fromHex(SENDER),
            nonce: 7n,
            targetEpoch: epoch,
            peer: `ed25519:${PEER}`,
            address: null,
        });
        const signed = fromHex(`${toHex(body)}${'55'.repeat(65)}`);

        assert.equal(toHex(body.slice(43, 43 + encoded.length / 2)), encoded);
        assert.equal(toHex(transactionBodyFromSignedTransaction(signed)), toHex(body));
    }
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
            targetEpoch: 300n,
            peer: PEER,
            address,
        });
        const signed = fromHex(`${toHex(body)}${'55'.repeat(65)}`);

        assert.ok(toHex(body).endsWith(`${PEER}${suffix}`));
        assert.equal(toHex(transactionBodyFromSignedTransaction(signed)), toHex(body));
    }
});

test('QMDB body parsing rejects non-canonical committee epochs', () => {
    const nonCanonical = fromHex(
        `${SENDER}0000000000000000018000${PEER}00${'55'.repeat(65)}`,
    );

    assert.throws(
        () => transactionBodyFromSignedTransaction(nonCanonical),
        /epoch is not canonical/,
    );
});
