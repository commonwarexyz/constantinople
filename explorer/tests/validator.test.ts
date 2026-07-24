import assert from 'node:assert/strict';
import test from 'node:test';

import {
    normalizeEd25519PublicKey,
    normalizeValidatorEndpoint,
    parseValidatorEndpoint,
} from '../src/validator.ts';

test('Ed25519 public keys normalize to lowercase unprefixed hex', () => {
    assert.equal(normalizeEd25519PublicKey(` ED25519:${'AB'.repeat(32)} `), 'ab'.repeat(32));
    assert.equal(normalizeEd25519PublicKey(`0x${'CD'.repeat(32)}`), 'cd'.repeat(32));
});

test('invalid Ed25519 public keys are rejected', () => {
    for (const value of ['', 'ab'.repeat(31), 'gg'.repeat(32), `01${'ab'.repeat(32)}`]) {
        assert.throws(() => normalizeEd25519PublicKey(value), /32-byte Ed25519 key/);
    }
});

test('IPv4 and IPv6 endpoints normalize and expose wire bytes', () => {
    assert.equal(normalizeValidatorEndpoint(' 192.000.2.9:09000 '), '192.0.2.9:9000');
    assert.equal(
        normalizeValidatorEndpoint('[2001:0DB8:0:0:0:0:0:9]:9000'),
        '[2001:db8::9]:9000',
    );
    assert.equal(
        normalizeValidatorEndpoint('[::ffff:192.0.2.128]:9000'),
        '[::ffff:c000:280]:9000',
    );
    assert.deepEqual([...parseValidatorEndpoint('192.0.2.9:9000').addressBytes], [192, 0, 2, 9]);
    assert.equal(parseValidatorEndpoint('[::1]:443').addressBytes.length, 16);
});

test('invalid endpoints are rejected', () => {
    for (const value of [
        'validator.example:9000',
        '192.0.2.999:9000',
        '192.0.2.1:0',
        '192.0.2.1:65536',
        '2001:db8::1:9000',
        '[2001:db8::1]',
        '[2001::db8::1]:9000',
        '[::ffff:192.0.2.999]:9000',
        '[fe80::1%en0]:9000',
    ]) {
        assert.throws(() => normalizeValidatorEndpoint(value));
    }
});
