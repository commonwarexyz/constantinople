import assert from 'node:assert/strict';
import test from 'node:test';

import { isRetryableProofError } from '../src/proofRetry.ts';

test('raw tx-by-height misses are retried while the indexer catches up', () => {
    assert.equal(
        isRetryableProofError('tx digest 1adb68d9800...a2a15bb3 missing at height 127'),
        true,
    );
});

test('non-indexer proof errors are not retried forever', () => {
    assert.equal(isRetryableProofError('transaction location 3 is outside finalized block range'), false);
});
