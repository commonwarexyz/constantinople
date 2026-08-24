import assert from 'node:assert/strict';
import test from 'node:test';

import {
    assignReconciliationOrder,
    markReconciliationCertificate,
    markSubmissionReconciling,
    markSubmissionRejected,
    markTransactionFinalized,
    normalizeSubmittedTransaction,
    prependTransaction,
    reconciliationRetryDelay,
    shouldReconcileTransaction,
    type SubmittedTransaction,
} from '../src/submissionHistory.ts';

const sender = '11'.repeat(32);
const recipient = '22'.repeat(32);
const digest = '33'.repeat(32);

function reconcilingTransaction(): SubmittedTransaction {
    return {
        reconciliationVersion: 1,
        sender,
        digest,
        to: recipient,
        value: '7',
        nonce: '2',
        submittedAt: 1_000,
        finalizedInMs: null,
        status: 'reconciling',
        detail: 'admitted by a leader',
        finalizedHeight: null,
        certificate: { status: 'waiting', detail: 'queued for finalized metadata' },
        proof: { status: 'waiting', detail: 'queued for finalized metadata' },
    };
}

test('legacy dropped rows return to digest reconciliation', () => {
    const transaction = normalizeSubmittedTransaction({
        ...reconcilingTransaction(),
        reconciliationVersion: undefined,
        status: 'dropped',
        detail: 'dropped',
        proof: { status: 'waiting', detail: 'not finalized' },
    });

    assert.equal(transaction?.status, 'reconciling');
    assert.equal(transaction?.finalizedInMs, null);
    assert.equal(transaction?.finalizedHeight, null);
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(transaction!, sender), true);
});

test('legacy filtered rows return to digest reconciliation', () => {
    const transaction = normalizeSubmittedTransaction({
        ...reconcilingTransaction(),
        reconciliationVersion: undefined,
        status: 'partially_finalized',
        proof: { status: 'waiting', detail: 'not included' },
    });

    assert.equal(transaction?.status, 'reconciling');
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(transaction!, sender), true);
});

test('deterministic rejection stops reconciliation without latency', () => {
    const [transaction] = markSubmissionRejected(
        digest,
        'transaction submission failed with HTTP 400',
        [reconcilingTransaction()],
    );

    assert.equal(transaction.status, 'rejected');
    assert.equal(transaction.finalizedInMs, null);
    assert.equal(transaction.certificate.status, 'unavailable');
    assert.equal(transaction.proof.status, 'unavailable');
    assert.equal(shouldReconcileTransaction(transaction, sender), false);

    const [afterCertificate] = markReconciliationCertificate(
        digest,
        19,
        {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        [transaction],
    );
    assert.deepEqual(afterCertificate, transaction);
});

test('latency is recorded only with a verified finalized proof', () => {
    const certificate = {
        status: 'verified',
        detail: 'verified at height 19',
        height: '19',
        view: '4',
    } as const;
    const waiting = markTransactionFinalized(
        digest,
        19,
        certificate,
        { status: 'waiting', detail: 'waiting for QMDB proof' },
        1_500,
        [reconcilingTransaction()],
    )[0];
    assert.equal(waiting.finalizedInMs, null);

    const finalized = markTransactionFinalized(
        digest,
        19,
        certificate,
        {
            status: 'verified',
            detail: 'verified at height 19',
            location: '120',
            tip: '130',
            proofSizeBytes: 240,
        },
        1_500,
        [reconcilingTransaction()],
    )[0];
    assert.equal(finalized.status, 'finalized');
    assert.equal(finalized.finalizedHeight, 19);
    assert.equal(finalized.finalizedInMs, 500);

    const [afterAdmission] = markSubmissionReconciling(
        digest,
        'admitted by a leader',
        [finalized],
    );
    assert.deepEqual(afterAdmission, finalized);

    const [afterRejection] = markSubmissionRejected(
        digest,
        'late deterministic response',
        [finalized],
    );
    assert.deepEqual(afterRejection, finalized);
});

test('only waiting rows owned by the current sender are reconciled', () => {
    const transaction = reconcilingTransaction();
    assert.equal(shouldReconcileTransaction(transaction, sender), true);
    assert.equal(shouldReconcileTransaction(transaction, recipient), false);
    assert.equal(
        shouldReconcileTransaction(
            { ...transaction, proof: { status: 'error', detail: 'invalid certificate' } },
            sender,
        ),
        false,
    );
});

test('retrying rows remain ahead of later submissions', () => {
    const retrying = reconcilingTransaction();
    const later = {
        ...reconcilingTransaction(),
        digest: '44'.repeat(32),
        submittedAt: 2_000,
    };
    const order = new Map<string, number>([[retrying.digest, 1]]);
    const sequence = assignReconciliationOrder([later, retrying], order, 1);
    const [selected] = [later, retrying].sort(
        (left, right) => order.get(left.digest)! - order.get(right.digest)!,
    );

    assert.equal(sequence, 2);
    assert.equal(selected.digest, retrying.digest);
});

test('reconciliation retries use capped exponential backoff with jitter', () => {
    assert.equal(reconciliationRetryDelay(1, () => 0.5), 1_000);
    assert.equal(reconciliationRetryDelay(2, () => 0.5), 2_000);
    assert.equal(reconciliationRetryDelay(99, () => 0.5), 30_000);
    assert.ok(reconciliationRetryDelay(2, () => 0) < reconciliationRetryDelay(2, () => 1));
});

test('history bounds terminal rows without expiring reconciliation', () => {
    const oldReconciling = reconcilingTransaction();
    const terminal = Array.from({ length: 101 }, (_, index) => ({
        ...reconcilingTransaction(),
        digest: index.toString(16).padStart(64, '0'),
        status: 'rejected' as const,
    }));
    const newReconciling = {
        ...reconcilingTransaction(),
        digest: '44'.repeat(32),
    };

    const next = prependTransaction(newReconciling, [...terminal, oldReconciling]);
    assert.deepEqual(
        next.filter((tx) => tx.status === 'reconciling').map((tx) => tx.digest),
        [newReconciling.digest, oldReconciling.digest],
    );
    assert.equal(next.filter((tx) => tx.status !== 'reconciling').length, 100);

    const resolved = markSubmissionRejected(oldReconciling.digest, 'rejected', next);
    assert.equal(resolved.filter((tx) => tx.status === 'reconciling').length, 1);
    assert.equal(resolved.filter((tx) => tx.status !== 'reconciling').length, 100);
});
