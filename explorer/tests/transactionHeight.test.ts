import assert from 'node:assert/strict';
import test from 'node:test';
import {
    containingTransactionHeight,
    transactionHeightPredecessorQuery,
} from '../src/transactionHeight.ts';

test('transaction height lookup scans backward from the newest block', () => {
    assert.equal(
        transactionHeightPredecessorQuery(42n).replace(/\s+/g, ' ').trim(),
        'SELECT height FROM block_meta WHERE transactions_tip <= 42 ORDER BY height DESC LIMIT 1',
    );
});

test('transaction height follows its predecessor and defaults to genesis', () => {
    assert.equal(containingTransactionHeight(null), 0n);
    assert.equal(containingTransactionHeight(0n), 1n);
    assert.equal(containingTransactionHeight(6n), 7n);
});
