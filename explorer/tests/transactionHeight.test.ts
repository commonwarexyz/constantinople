import assert from 'node:assert/strict';
import test from 'node:test';
import {
    containingTransactionHeight,
    transactionHeightPredecessorQuery,
} from '../src/transactionHeight.ts';

test('transaction height lookup seeks the preceding boundary', () => {
    assert.equal(
        transactionHeightPredecessorQuery(42n).replace(/\s+/g, ' ').trim(),
        'SELECT height FROM block_meta WHERE transactions_tip <= 42 ORDER BY transactions_tip DESC LIMIT 1',
    );
});

test('transaction height follows its predecessor and defaults to the first finalized block', () => {
    assert.equal(containingTransactionHeight(null), 1n);
    assert.equal(containingTransactionHeight(0n), 1n);
    assert.equal(containingTransactionHeight(6n), 7n);
});
