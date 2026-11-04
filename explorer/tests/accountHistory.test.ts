import assert from 'node:assert/strict';
import test from 'node:test';
import { AccountHistorySession } from '../src/accountHistory.ts';

const version = (txCount: bigint, writeHeight = txCount, location = writeHeight) => ({
    txCount, writeHeight, location,
});

const scope = {
    indexerUrl: 'https://indexer.example',
    simplexVerificationMaterial: 'abcd',
    account: 'ab'.repeat(32),
};

test('canceled responses cannot raise the count or reject the next valid response', () => {
    const session = new AccountHistorySession();
    const canceled = new AbortController();
    const first = session.begin(scope, canceled.signal);
    canceled.abort();
    assert.equal(session.observe(first, version(100n, 10n)), false);
    const next = session.begin(scope, new AbortController().signal);
    assert.equal(session.observe(next, version(2n, 11n)), true);
});

test('replaced requests cannot poison the active account even before abort cleanup', () => {
    const session = new AccountHistorySession();
    const old = session.begin(scope, new AbortController().signal);
    const current = session.begin(scope, new AbortController().signal);
    assert.equal(session.observe(old, version(100n, 10n)), false);
    assert.equal(session.observe(current, version(5n, 11n)), true);
    session.invalidate();
    assert.equal(session.observe(current, version(200n, 12n)), false);
    const next = session.begin(scope, new AbortController().signal);
    assert.equal(session.observe(next, version(5n, 13n)), true);
    assert.throws(() => session.observe(next, version(4n, 14n)), /count regressed/);
});

test('rollback guard follows normalized chain, indexer and account within one view', () => {
    const session = new AccountHistorySession();
    const observe = (context: typeof scope, count: bigint) => session.observe(
        session.begin(context, new AbortController().signal), version(count, 20n, count + 20n),
    );
    assert.equal(observe(scope, 10n), true);
    assert.throws(() => observe({
        indexerUrl: `${scope.indexerUrl}/`,
        simplexVerificationMaterial: ' ABCD ',
        account: `0x${scope.account.toUpperCase()}`,
    }, 9n), /count regressed/);
    for (const context of [
        { ...scope, simplexVerificationMaterial: 'ffff' },
        { ...scope, indexerUrl: 'https://other.example' },
        { ...scope, account: '22'.repeat(32) },
    ]) {
        assert.equal(observe(context, 1n), true);
    }
    assert.throws(() => observe(scope, 9n), /count regressed/);
});

test('separate views can retain older snapshots while a wallet sees newer state', () => {
    const browse = new AccountHistorySession();
    const wallet = new AccountHistorySession();
    const page = browse.begin(scope, new AbortController().signal);
    assert.equal(browse.observe(page, version(10n)), true);
    assert.equal(wallet.observe(wallet.begin(scope, new AbortController().signal), version(20n)), true);
    const nextPage = browse.begin(scope, new AbortController().signal);
    assert.equal(browse.observe(nextPage, version(10n)), true);
});

test('older account versions remain valid without lowering the newer writer guard', () => {
    const session = new AccountHistorySession();
    const request = session.begin(scope, new AbortController().signal);
    assert.equal(session.observe(request, version(20n)), true);
    assert.equal(session.observe(request, version(10n)), true);
    assert.throws(() => session.observe(request, version(15n, 21n)), /count regressed/);
    assert.throws(() => session.observe(request, version(19n, 20n, 21n)), /count regressed/);
    assert.equal(session.observe(request, version(21n)), true);
});

test('one account location cannot describe conflicting versions', () => {
    const session = new AccountHistorySession();
    const request = session.begin(scope, new AbortController().signal);
    assert.equal(session.observe(request, version(10n, 20n, 30n)), true);
    assert.throws(() => session.observe(request, version(11n, 20n, 30n)), /conflicting version/);
    assert.throws(() => session.observe(request, version(10n, 21n, 30n)), /conflicting version/);
});
