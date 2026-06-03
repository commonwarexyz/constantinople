import assert from 'node:assert/strict';
import test from 'node:test';

import { isRetryableAccountProofError, isRetryableProofError } from '../src/proofRetry.ts';
import { assertTransactionLocationBeforeTip, transactionProofTip } from '../src/proofMath.ts';

test('SQL tx metadata misses are retried while the indexer catches up', () => {
    assert.equal(
        isRetryableProofError('tx digest 1adb68d9800...a2a15bb3 missing at height 127'),
        true,
    );
});

test('QMDB transaction root mismatches are terminal', () => {
    assert.equal(
        isRetryableProofError(
            'historical ops root did not match expected root · height 337 · location 4865826 · tip 4865827 · proof start 4865826 · ops 1 · block index 17845 · block txs 17846',
        ),
        false,
    );
});

test('non-indexer proof errors are not retried forever', () => {
    assert.equal(isRetryableProofError('transaction location 3 is outside finalized block range'), false);
});

test('QMDB transaction proof tip uses inclusive operation location', () => {
    assert.equal(transactionProofTip(128n), 127n);
});

test('latest-root transaction proofs allow locations before the sync floor', () => {
    assert.doesNotThrow(() => assertTransactionLocationBeforeTip(567443n, 900000n));
});

test('latest-root transaction proofs reject only future locations', () => {
    assert.throws(
        () => assertTransactionLocationBeforeTip(900000n, 900000n),
        /outside finalized transaction range/,
    );
});

test('account proof index catch-up errors are retried', () => {
    assert.equal(
        isRetryableAccountProofError('account location 303 is outside finalized state range'),
        true,
    );
    assert.equal(
        isRetryableAccountProofError('[out_of_range] requested proof tip is not published yet'),
        true,
    );
});

test('QMDB account root mismatches are terminal', () => {
    assert.equal(isRetryableAccountProofError('historical ops root did not match expected root'), false);
});
