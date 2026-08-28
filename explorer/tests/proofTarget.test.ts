import assert from 'node:assert/strict';
import test from 'node:test';

import { parsePublishedWatermark, targetWithinWatermarks } from '../src/proofTarget.ts';

test('published watermark is read from the QMDB out_of_range rejection', () => {
    assert.equal(
        parsePublishedWatermark(
            'requested location 14646658295 is above published writer watermark 14645935855',
        ),
        14645935855n,
    );
    assert.equal(parsePublishedWatermark('historical ops root did not match expected root'), null);
});

test('a target is provable only when both families are published through its tips', () => {
    const watermarks = { state: 1_000n, transactions: 500n };
    // Range ends are exclusive, so a tip of 1_001 means the last location 1_000.
    assert.equal(targetWithinWatermarks({ stateTip: 1_001n, transactionsTip: 501n }, watermarks), true);
    assert.equal(targetWithinWatermarks({ stateTip: 900n, transactionsTip: 400n }, watermarks), true);
    assert.equal(targetWithinWatermarks({ stateTip: 1_002n, transactionsTip: 501n }, watermarks), false);
    assert.equal(targetWithinWatermarks({ stateTip: 1_001n, transactionsTip: 502n }, watermarks), false);
});
