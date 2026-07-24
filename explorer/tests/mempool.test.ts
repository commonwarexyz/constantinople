import assert from 'node:assert/strict';
import test from 'node:test';

import { singleTransactionFinalized } from '../src/mempool.ts';

test('single transaction finalization recognizes partial batch progress', () => {
    assert.equal(singleTransactionFinalized({ status: 'finalized', height: 9 }), true);
    assert.equal(singleTransactionFinalized({
        status: 'partially_finalized',
        height: 9,
        included: 1,
        filtered: 0,
    }), true);
    assert.equal(singleTransactionFinalized({
        status: 'partially_finalized',
        height: 9,
        included: 0,
        filtered: 1,
    }), false);
    assert.equal(singleTransactionFinalized({ status: 'dropped' }), false);
});
