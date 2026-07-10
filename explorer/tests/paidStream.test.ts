import assert from 'node:assert/strict';
import test from 'node:test';

import {
    CHANNEL_EXPIRY_SLACK,
    channelExpiry,
    nonceConsumed,
    parseAdvertisement,
    parseStreamChunk,
    parseStreamEnd,
    parseStreamMeter,
    voucherTopUp,
} from '../src/paidStream.ts';

const advertisementBody = {
    public_key: '00'.repeat(34),
    account: '11'.repeat(32),
    height: 100,
    min_runway: 20,
    settle_margin: 10,
    price_per_token: 1,
    debt_limit: 32,
};

test('advertisement parses and prices the channel expiry', () => {
    const advertisement = parseAdvertisement(advertisementBody);
    assert.equal(advertisement.debtLimit, 32n);
    assert.equal(advertisement.pricePerToken, 1n);
    assert.equal(channelExpiry(advertisement), 130n + CHANNEL_EXPIRY_SLACK);
});

test('advertisement missing a knob is rejected, not zero-defaulted', () => {
    const { debt_limit: _dropped, ...partial } = advertisementBody;
    assert.throws(() => parseAdvertisement(partial), /debt_limit/);
    assert.throws(() => parseAdvertisement(null), /JSON object/);
});

/// voucherTopUp with the steady-state extras zeroed out.
function topUp(served: bigint, paid: bigint, debtLimit: bigint, deposit: bigint): bigint | null {
    return voucherTopUp({ served, paid, lastSigned: 0n, deadTarget: null, debtLimit, deposit });
}

test('voucher top-up stays half a window ahead of the stream', () => {
    const limit = 32n;
    const deposit = 1_000n;

    // Fresh channel: no debt, no voucher.
    assert.equal(topUp(0n, 0n, limit, deposit), null);
    // Below half the window, streaming continues unpaid.
    assert.equal(topUp(15n, 0n, limit, deposit), null);
    // At half the window, pay half a window past what was served.
    assert.equal(topUp(16n, 0n, limit, deposit), 32n);
    // Prepaid: no new voucher until the debt builds again.
    assert.equal(topUp(20n, 32n, limit, deposit), null);
    assert.equal(topUp(48n, 32n, limit, deposit), 64n);
});

test('voucher top-up never exceeds the deposit', () => {
    const limit = 32n;
    // Near the deposit the target clamps to it...
    assert.equal(topUp(90n, 74n, limit, 100n), 100n);
    // ...and once the deposit is fully paid, no voucher can help.
    assert.equal(topUp(100n, 100n, limit, 100n), null);
});

test('voucher top-up never signs below an in-flight cumulative', () => {
    // The operator still reports paid=0, but a voucher for 32 is already
    // signed (its post may not be acknowledged yet): the debt is measured
    // against 32, and any new target must exceed it.
    const inputs = { paid: 0n, lastSigned: 32n, deadTarget: null, debtLimit: 32n, deposit: 1_000n };
    assert.equal(voucherTopUp({ served: 20n, ...inputs }), null);
    assert.equal(voucherTopUp({ served: 48n, ...inputs }), 64n);
    // Deposit clamp below the in-flight cumulative: nothing left to sign.
    assert.equal(voucherTopUp({ served: 40n, ...inputs, deposit: 32n }), null);
});

test('voucher top-up never re-signs a rejected cumulative', () => {
    const inputs = { paid: 0n, lastSigned: 0n, debtLimit: 32n, deposit: 1_000n };
    assert.equal(voucherTopUp({ served: 16n, deadTarget: 32n, ...inputs }), null);
    // A different target is still signable.
    assert.equal(voucherTopUp({ served: 17n, deadTarget: 32n, ...inputs }), 33n);
});

test('nonce consumption covers the base and the run-ahead bitmap', () => {
    // Mirrors Nonce::is_consumed in account.rs: bit 0 records base + 1.
    const state = { base: 10n, bitmap: 0b101n };
    assert.equal(nonceConsumed(state, 9n), true, 'below base is stale');
    assert.equal(nonceConsumed(state, 10n), false, 'base itself is the next free nonce');
    assert.equal(nonceConsumed(state, 11n), true, 'bit 0 set');
    assert.equal(nonceConsumed(state, 12n), false, 'bit 1 clear');
    assert.equal(nonceConsumed(state, 13n), true, 'bit 2 set');
    assert.equal(nonceConsumed(state, 75n), false, 'beyond the run-ahead window is unrecorded');
    assert.equal(nonceConsumed({ base: 10n, bitmap: 1n << 63n }, 74n), true, 'bit 63 set');
});

test('stream payloads parse and reject malformed data', () => {
    const chunk = parseStreamChunk('{"text":"hello ","served":7,"paid":32}');
    assert.deepEqual(chunk, { text: 'hello ', served: 7n, paid: 32n });

    const meter = parseStreamMeter('{"served":32,"paid":0}');
    assert.deepEqual(meter, { served: 32n, paid: 0n });

    const end = parseStreamEnd('{"reason":"payment_timeout","served":32,"paid":0}');
    assert.equal(end.reason, 'payment_timeout');

    assert.throws(() => parseStreamChunk('{"served":1,"paid":0}'), /text/);
    assert.throws(() => parseStreamEnd('{"reason":"whatever","served":1,"paid":0}'), /reason/);
    assert.throws(() => parseStreamMeter('{"served":-1,"paid":0}'), /served/);
});
