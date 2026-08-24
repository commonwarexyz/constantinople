import assert from 'node:assert/strict';
import test from 'node:test';

import {
    TransactionSubmissionError,
    classifySubmissionResponse,
    isDeterministicSubmissionRejection,
} from '../src/submissionResponse.ts';

test('HTTP 202 is the only accepted admission response', () => {
    assert.equal(classifySubmissionResponse(202), 'accepted');
    assert.equal(classifySubmissionResponse(200), 'ambiguous');
    assert.equal(classifySubmissionResponse(204), 'ambiguous');
});

test('bad requests and oversized batches are deterministic rejections', () => {
    assert.equal(classifySubmissionResponse(400), 'rejected');
    assert.equal(classifySubmissionResponse(413), 'rejected');
});

test('admission exhaustion and server failures remain ambiguous', () => {
    assert.equal(classifySubmissionResponse(503), 'ambiguous');
    assert.equal(classifySubmissionResponse(500), 'ambiguous');
});

test('only classified rejection errors are terminal', () => {
    assert.equal(
        isDeterministicSubmissionRejection(
            new TransactionSubmissionError('rejected', 'transaction rejected'),
        ),
        true,
    );
    assert.equal(
        isDeterministicSubmissionRejection(
            new TransactionSubmissionError('ambiguous', 'delivery unknown'),
        ),
        false,
    );
    assert.equal(isDeterministicSubmissionRejection(new TypeError('fetch failed')), false);
});
