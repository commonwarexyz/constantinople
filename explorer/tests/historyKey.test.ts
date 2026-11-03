import assert from 'node:assert/strict';
import test from 'node:test';

import { submittedTransactionHistoryKey, type HistoryScope } from '../src/historyKey.ts';

const scope: HistoryScope = {
    indexerUrl: 'http://127.0.0.1:8092',
    simplexVerificationMaterial: 'abc123',
};

test('submitted transaction history is not keyed before wallet sign-in', () => {
    assert.equal(submittedTransactionHistoryKey(scope, null), null);
});

test('submitted transaction history is scoped by wallet', () => {
    assert.notEqual(
        submittedTransactionHistoryKey(scope, 'wallet-a'),
        submittedTransactionHistoryKey(scope, 'wallet-b'),
    );
});

test('submitted transaction history is scoped by deployment', () => {
    assert.notEqual(
        submittedTransactionHistoryKey(scope, 'wallet-a'),
        submittedTransactionHistoryKey(
            { ...scope, simplexVerificationMaterial: 'different-deployment' },
            'wallet-a',
        ),
    );
});

test('submitted transaction history normalizes trailing slashes', () => {
    assert.equal(
        submittedTransactionHistoryKey(scope, 'wallet-a'),
        submittedTransactionHistoryKey(
            {
                ...scope,
                indexerUrl: `${scope.indexerUrl}/`,
            },
            'wallet-a',
        ),
    );
});
