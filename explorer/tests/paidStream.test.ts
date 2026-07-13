import assert from 'node:assert/strict';
import test from 'node:test';

import {
    CHANNEL_EXPIRY_SLACK,
    channelDeposit,
    channelExpiry,
    isSettlementBoundaryMessage,
    parseAdvertisement,
    parseRegisterCapability,
    parseStats,
    parseStreamChunk,
    parseStreamEnd,
    parseStreamMeter,
    settleRequestBody,
    streamRequestQuery,
    voucherFinalTopUp,
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
    stream_tokens: 500,
};

test('advertisement parses and prices the channel expiry', () => {
    const advertisement = parseAdvertisement(advertisementBody);
    assert.equal(advertisement.debtLimit, 32n);
    assert.equal(advertisement.pricePerToken, 1n);
    assert.equal(advertisement.streamTokens, 500n);
    assert.equal(channelExpiry(advertisement), 130n + CHANNEL_EXPIRY_SLACK);
});

test('deposit covers the whole stream plus a debt window of headroom', () => {
    const advertisement = parseAdvertisement(advertisementBody);
    assert.equal(channelDeposit(advertisement), 532n);
    // A zero advertised price still yields a fundable deposit.
    assert.equal(channelDeposit({ ...advertisement, pricePerToken: 0n }), 532n);
    assert.equal(channelDeposit({ ...advertisement, pricePerToken: 3n }), 1_596n);
});

test('operator stats parse the voucher counter', () => {
    assert.equal(parseStats({ vouchers: 7, streamed: 100 }).vouchers, 7n);
    assert.throws(() => parseStats({ streamed: 100 }), /vouchers/);
});

test('authorized operator requests carry the registration capability', () => {
    assert.equal(parseRegisterCapability({ registered: true, capability: 'secret-token' }), 'secret-token');
    assert.throws(() => parseRegisterCapability({ registered: true }), /capability/);
    assert.deepEqual(JSON.parse(settleRequestBody('aa', 'secret token')), {
        channel: 'aa',
        capability: 'secret token',
    });
    assert.equal(streamRequestQuery('aa', 'secret token'), 'channel=aa&capability=secret+token');
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

test('voucher top-up triggers at half a window without paying ahead', () => {
    const limit = 32n;
    const deposit = 1_000n;

    // Fresh channel: no debt, no voucher.
    assert.equal(topUp(0n, 0n, limit, deposit), null);
    // Below half the window, streaming continues unpaid.
    assert.equal(topUp(15n, 0n, limit, deposit), null);
    // At half the window, pay only for content already delivered.
    assert.equal(topUp(16n, 0n, limit, deposit), 16n);
    // No new voucher until another half-window has been delivered.
    assert.equal(topUp(20n, 16n, limit, deposit), null);
    assert.equal(topUp(32n, 16n, limit, deposit), 32n);
});

test('voucher top-up never exceeds the deposit', () => {
    const limit = 32n;
    // Near the deposit the voucher covers only the delivered cumulative.
    assert.equal(topUp(90n, 74n, limit, 100n), 90n);
    // A defensive clamp still protects against an impossible over-deposit
    // served value.
    assert.equal(topUp(110n, 94n, limit, 100n), 100n);
    // ...and once the deposit is fully paid, no voucher can help.
    assert.equal(topUp(100n, 100n, limit, 100n), null);
});

test('voucher top-up never signs below an in-flight cumulative', () => {
    // The operator still reports paid=0, but a voucher for 32 is already
    // signed (its post may not be acknowledged yet): the debt is measured
    // against 32, and any new target must exceed it without paying ahead.
    const inputs = { paid: 0n, lastSigned: 32n, deadTarget: null, debtLimit: 32n, deposit: 1_000n };
    assert.equal(voucherTopUp({ served: 20n, ...inputs }), null);
    assert.equal(voucherTopUp({ served: 48n, ...inputs }), 48n);
    // Deposit clamp below the in-flight cumulative: nothing left to sign.
    assert.equal(voucherTopUp({ served: 40n, ...inputs, deposit: 32n }), null);
});

test('voucher top-up never re-signs a rejected cumulative', () => {
    const inputs = { paid: 0n, lastSigned: 0n, debtLimit: 32n, deposit: 1_000n };
    assert.equal(voucherTopUp({ served: 16n, deadTarget: 16n, ...inputs }), null);
    // A different target is still signable.
    assert.equal(voucherTopUp({ served: 17n, deadTarget: 16n, ...inputs }), 17n);
});

test('settlement flushes delivered content below the batching threshold', () => {
    assert.equal(
        voucherFinalTopUp({ served: 7n, paid: 0n, lastSigned: 0n, deposit: 100n }),
        7n,
    );
    assert.equal(
        voucherFinalTopUp({ served: 7n, paid: 7n, lastSigned: 0n, deposit: 100n }),
        null,
    );
    assert.equal(
        voucherFinalTopUp({ served: 9n, paid: 0n, lastSigned: 7n, deposit: 100n }),
        9n,
    );
    assert.throws(
        () => voucherFinalTopUp({ served: 101n, paid: 100n, lastSigned: 100n, deposit: 100n }),
        /exceeds the channel deposit/,
    );
});

test('only settlement-boundary voucher errors permit the close to continue', () => {
    assert.equal(isSettlementBoundaryMessage('channel settlement already started'), true);
    assert.equal(isSettlementBoundaryMessage('channel is about to expire'), true);
    assert.equal(isSettlementBoundaryMessage('voucher rejected: BadSignature'), false);
    assert.equal(isSettlementBoundaryMessage('channel metadata missing'), false);
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
