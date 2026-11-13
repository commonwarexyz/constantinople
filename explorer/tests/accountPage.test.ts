import assert from 'node:assert/strict';
import test from 'node:test';
import { accountCursor, accountHistoryPage, type AccountHistoryTransaction } from '../src/accountPage.ts';
import { fromHex } from '../src/codec.ts';
import { decodeAccountValue, TRANSACTION_PAGE } from '../src/qmdb.ts';

const account = '11'.repeat(32);
const other = '22'.repeat(32);

test('account values authenticate four exact big-endian u64 fields', () => {
    const encoded = fromHex('010203040506070800000000000000090000000000000010ffffffffffffffff');
    assert.deepEqual(decodeAccountValue(encoded), {
        balance: 0x0102030405060708n, nonce: 9n, nonceBitmap: 16n, txCount: (1n << 64n) - 1n,
    });
    for (const length of [0, 24, 31, 33]) {
        assert.throws(() => decodeAccountValue(new Uint8Array(length)), /malformed account proof value/);
    }
});

function transactions(end: bigint, count = Number(end > TRANSACTION_PAGE ? TRANSACTION_PAGE : end)): AccountHistoryTransaction[] {
    return Array.from({ length: count }, (_, offset) => {
        const index = end - 1n - BigInt(offset);
        const sent = offset % 2 === 0;
        return {
            digest: index.toString(16).padStart(64, '0'), sender: sent ? account : other,
            recipient: sent ? other : account, value: 1n, nonce: index, location: 100n + index * 2n,
            senderIndex: sent ? index : 200n + index, recipientIndex: sent ? 300n + index : index,
            role: sent ? 0 : 1,
        };
    });
}

test('account cursors encode the exclusive account index as an eight-byte big-endian u64', () => {
    assert.deepEqual([...accountCursor(0x0102030405060708n)], [1, 2, 3, 4, 5, 6, 7, 8]);
    assert.deepEqual([...accountCursor((1n << 64n) - 1n)], Array(8).fill(255));
    assert.throws(() => accountCursor(-1n), /invalid account cursor/);
    assert.throws(() => accountCursor(1n << 64n), /invalid account cursor/);
});

test('a complete page derives its descending indices and next boundary from the account count', () => {
    const input = transactions(108n);
    const page = accountHistoryPage(account, 108n, null, accountCursor(58n), input);
    assert.deepEqual(page.rows.map((row) => row.accountIndex), Array.from({ length: 50 }, (_, i) => 107n - BigInt(i)));
    assert.deepEqual(page.nextCursor, accountCursor(58n));
    assert.deepEqual(page.rows.map((row) => [row.senderIndex, row.recipientIndex]), input.map((row) => [row.senderIndex, row.recipientIndex]));
    assert.ok(page.rows.every((row) => !('height' in row) && !('blockIndex' in row)));
    const next = accountHistoryPage(account, 108n, page.nextCursor, accountCursor(8n), transactions(58n));
    assert.equal(next.rows[0]!.accountIndex, 57n);
    assert.ok(next.rows.every((row) => !page.rows.some((prior) => prior.digest === row.digest)));
});

test('short and exhausted pages cover the exact remaining interval', () => {
    const oldest = accountHistoryPage(account, 58n, accountCursor(3n), null, transactions(3n));
    assert.deepEqual(oldest.rows.map((row) => row.accountIndex), [2n, 1n, 0n]);
    assert.equal(oldest.nextCursor, null);
    assert.deepEqual(accountHistoryPage(account, 58n, accountCursor(0n), null, []), { rows: [], nextCursor: null });
    assert.deepEqual(accountHistoryPage(account, 0n, null, null, []), { rows: [], nextCursor: null });
});

test('a page of one role is complete verification evidence like any other page', () => {
    const input = transactions(58n).map((row) => ({ ...row, sender: account, recipient: other, senderIndex: row.role === 0 ? row.senderIndex : row.recipientIndex, role: 0 }));
    const page = accountHistoryPage(account, 58n, null, accountCursor(8n), input);
    assert.equal(page.rows.length, 50);
    assert.ok(page.rows.every((row) => row.direction === 'sent' && row.counterparty === other));
    assert.deepEqual(page.nextCursor, accountCursor(8n));
    const forged = structuredClone(input);
    forged[7]!.senderIndex++;
    assert.throws(() => accountHistoryPage(account, 58n, null, accountCursor(8n), forged), /exact descending interval/);
    assert.throws(() => accountHistoryPage(account, 58n, null, accountCursor(8n), input.slice(0, 49)), /cover/);
});

test('a self-transfer is one sent row with equal participant indices', () => {
    const self = { ...transactions(1n)[0]!, recipient: account, recipientIndex: 0n };
    const page = accountHistoryPage(account, 1n, null, null, [self]);
    assert.equal(page.rows.length, 1);
    assert.equal(page.rows[0]!.direction, 'sent');
    assert.equal(page.rows[0]!.counterparty, account);
    assert.throws(() => accountHistoryPage(account, 1n, null, null, [{ ...self, recipientIndex: 1n }]), /unequal/);
    assert.throws(() => accountHistoryPage(account, 1n, null, null, [{ ...self, role: 1 }]), /role/);
});

for (const [name, mutate, expected] of [
    ['omission', (rows: AccountHistoryTransaction[]) => { rows.splice(4, 1); }, /cover/],
    ['extra row', (rows: AccountHistoryTransaction[]) => { rows.push(rows.at(-1)!); }, /cover/],
    ['repeated digest at a distinct location', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, digest: rows[0]!.digest }; }, /repeats/],
    ['equal locations', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, location: rows[0]!.location }; }, /repeats|reorders/],
    ['increasing locations', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, location: rows[0]!.location + 1n }; }, /reorders/],
    ['reordered entries', (rows: AccountHistoryTransaction[]) => { [rows[0], rows[1]] = [rows[1]!, rows[0]!]; }, /descending/],
    ['foreign participant', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, recipient: other }; }, /involve/],
    ['wrong sender index', (rows: AccountHistoryTransaction[]) => { rows[0] = { ...rows[0]!, senderIndex: 56n }; }, /descending/],
    ['wrong recipient index', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, recipientIndex: 55n }; }, /descending/],
    ['wrong role', (rows: AccountHistoryTransaction[]) => { rows[1] = { ...rows[1]!, role: 0 }; }, /role/],
] as const) {
    test(`account history rejects ${name}`, () => {
        const rows = transactions(58n);
        mutate(rows);
        assert.throws(() => accountHistoryPage(account, 58n, null, accountCursor(8n), rows), expected);
    });
}

test('claimed early end, wrong continuation and out-of-range cursor fail', () => {
    const rows = transactions(58n);
    for (const claimed of [null, accountCursor(9n), new Uint8Array(24)]) {
        assert.throws(() => accountHistoryPage(account, 58n, null, claimed, rows), /next cursor/);
    }
    assert.throws(() => accountHistoryPage(account, 58n, accountCursor(59n), null, rows), /exceeds/);
    assert.throws(() => accountHistoryPage(account, 58n, new Uint8Array(24), null, rows), /invalid account cursor/);
    assert.throws(() => accountHistoryPage(account, 3n, null, accountCursor(0n), transactions(3n)), /next cursor/);
});
