import assert from 'node:assert/strict';
import test from 'node:test';

import {
    assignReconciliationOrder,
    markReconciliationCertificate,
    markSubmissionAdmitted,
    markSubmissionReconciling,
    markSubmissionRejected,
    markTransactionFinalized,
    markValidatorFinalizationObserved,
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
        reconciliationVersion: 2,
        sender,
        digest,
        to: recipient,
        value: '7',
        nonce: '2',
        submittedAt: 1_000,
        admittedInMs: null,
        finalizationObservedInMs: null,
        proofObservedInMs: null,
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
    assert.equal(transaction?.admittedInMs, null);
    assert.equal(transaction?.finalizationObservedInMs, null);
    assert.equal(transaction?.proofObservedInMs, null);
    assert.equal(transaction?.finalizedHeight, null);
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(transaction!, sender), true);
});

test('version one finalized rows migrate latency to proof observation only', () => {
    const transaction = normalizeSubmittedTransaction({
        ...reconcilingTransaction(),
        reconciliationVersion: 1,
        status: 'finalized',
        finalizedInMs: 500,
        finalizedHeight: 19,
        certificate: {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        proof: {
            status: 'verified',
            detail: 'verified at height 19',
            location: '120',
            tip: '130',
            proofSizeBytes: 240,
        },
    });

    assert.equal(transaction?.reconciliationVersion, 2);
    assert.equal(transaction?.status, 'finalized');
    assert.equal(transaction?.admittedInMs, null);
    assert.equal(transaction?.finalizationObservedInMs, null);
    assert.equal(transaction?.proofObservedInMs, 500);
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

test('dropped response stops reconciliation without latency', () => {
    const admitted = markSubmissionAdmitted(
        digest,
        'admitted by a leader',
        1_200,
        [reconcilingTransaction()],
    )[0];
    const withCertificate = markReconciliationCertificate(
        digest,
        19,
        {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        1_400,
        [admitted],
    )[0];
    const [transaction] = markSubmissionRejected(
        digest,
        'validator reported transaction dropped before finalization',
        [withCertificate],
    );

    assert.equal(transaction.status, 'rejected');
    assert.equal(transaction.admittedInMs, null);
    assert.equal(transaction.finalizationObservedInMs, null);
    assert.equal(transaction.proofObservedInMs, null);
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
        1_500,
        [transaction],
    );
    assert.deepEqual(afterCertificate, transaction);

    const [afterProof] = markTransactionFinalized(
        digest,
        19,
        {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        {
            status: 'verified',
            detail: 'verified at height 19',
            location: '120',
            tip: '130',
            proofSizeBytes: 240,
        },
        1_600,
        [transaction],
    );
    assert.deepEqual(afterProof, transaction);
});

test('each submission phase records its own first observation', () => {
    const certificate = {
        status: 'verified',
        detail: 'verified at height 19',
        height: '19',
        view: '4',
    } as const;
    const admitted = markSubmissionAdmitted(
        digest,
        'admitted by a leader',
        1_200,
        [reconcilingTransaction()],
    )[0];
    assert.equal(admitted.admittedInMs, 200);
    assert.equal(admitted.finalizationObservedInMs, null);
    assert.equal(admitted.proofObservedInMs, null);

    const withCertificate = markReconciliationCertificate(
        digest,
        19,
        certificate,
        1_400,
        [admitted],
    )[0];
    assert.equal(withCertificate.admittedInMs, 200);
    assert.equal(withCertificate.finalizationObservedInMs, 400);
    assert.equal(withCertificate.proofObservedInMs, null);

    const repeatedCertificate = markReconciliationCertificate(
        digest,
        19,
        certificate,
        1_450,
        [withCertificate],
    )[0];
    assert.equal(repeatedCertificate.finalizationObservedInMs, 400);

    const waiting = markTransactionFinalized(
        digest,
        19,
        certificate,
        { status: 'waiting', detail: 'waiting for QMDB proof' },
        1_500,
        [repeatedCertificate],
    )[0];
    assert.equal(waiting.status, 'reconciling');
    assert.equal(waiting.proofObservedInMs, null);

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
        1_600,
        [waiting],
    )[0];
    assert.equal(finalized.status, 'finalized');
    assert.equal(finalized.finalizedHeight, 19);
    assert.equal(finalized.admittedInMs, 200);
    assert.equal(finalized.finalizationObservedInMs, 400);
    assert.equal(finalized.proofObservedInMs, 600);

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

test('validator finality records height and observations without ending reconciliation', () => {
    const [observed] = markValidatorFinalizationObserved(
        digest,
        19,
        1_250,
        [reconcilingTransaction()],
    );

    assert.equal(observed.status, 'reconciling');
    assert.equal(observed.finalizedHeight, 19);
    assert.equal(observed.admittedInMs, 250);
    assert.equal(observed.finalizationObservedInMs, 250);
    assert.equal(observed.proofObservedInMs, null);
    assert.equal(observed.certificate.status, 'waiting');
    assert.equal(observed.proof.status, 'waiting');

    const restored = normalizeSubmittedTransaction(observed);
    assert.equal(restored?.status, 'reconciling');
    assert.equal(restored?.finalizedHeight, 19);
    assert.equal(restored?.admittedInMs, 250);
    assert.equal(restored?.finalizationObservedInMs, 250);
    assert.equal(restored?.proofObservedInMs, null);

    const [withCertificate] = markReconciliationCertificate(
        digest,
        19,
        {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        1_400,
        [observed],
    );
    assert.equal(withCertificate.status, 'reconciling');
    assert.equal(withCertificate.finalizationObservedInMs, 250);
    assert.equal(withCertificate.certificate.status, 'verified');
    assert.equal(withCertificate.proof.status, 'fetching');
});

test('admission response timing survives proof completion racing ahead', () => {
    const finalized = markTransactionFinalized(
        digest,
        19,
        {
            status: 'verified',
            detail: 'verified at height 19',
            height: '19',
            view: '4',
        },
        {
            status: 'verified',
            detail: 'verified at height 19',
            location: '120',
            tip: '130',
            proofSizeBytes: 240,
        },
        1_300,
        [reconcilingTransaction()],
    )[0];
    const admitted = markSubmissionAdmitted(
        digest,
        'admitted by a leader',
        1_400,
        [finalized],
    )[0];

    assert.equal(admitted.status, 'finalized');
    assert.equal(admitted.detail, 'finalized at 19');
    assert.equal(admitted.admittedInMs, 400);
    assert.equal(admitted.proofObservedInMs, 300);
});

test('only waiting rows owned by the current sender are reconciled', () => {
    const transaction = reconcilingTransaction();
    assert.equal(shouldReconcileTransaction(transaction, sender), true);
    assert.equal(
        shouldReconcileTransaction(transaction, sender, new Set([transaction.digest])),
        false,
    );
    assert.equal(shouldReconcileTransaction(transaction, sender, new Set()), true);
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

test('reconciliation retries every 300 milliseconds below ten seconds', () => {
    assert.equal(reconciliationRetryDelay(1, 0, () => 0), 300);
    assert.equal(reconciliationRetryDelay(99, 9_999, () => 1), 300);
});

test('reconciliation retries resume bounded jitter at ten seconds', () => {
    assert.equal(reconciliationRetryDelay(1, 10_000, () => 0.5), 1_000);
    assert.equal(reconciliationRetryDelay(4, 10_000, () => 0.5), 5_000);
    assert.equal(reconciliationRetryDelay(99, 59_999, () => 0.5), 5_000);
    assert.equal(reconciliationRetryDelay(99, 59_999, () => 1), 5_000);
    assert.ok(
        reconciliationRetryDelay(4, 10_000, () => 0) <
            reconciliationRetryDelay(4, 10_000, () => 1),
    );
});

test('reconciliation retries use capped exponential backoff after one minute', () => {
    assert.equal(reconciliationRetryDelay(4, 60_000, () => 0.5), 8_000);
    assert.equal(reconciliationRetryDelay(5, 60_000, () => 0.5), 16_000);
    assert.equal(reconciliationRetryDelay(99, 60_000, () => 0.5), 30_000);
    assert.equal(reconciliationRetryDelay(99, 60_000, () => 1), 30_000);
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
