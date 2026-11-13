import assert from 'node:assert/strict';
import test from 'node:test';
import type { VerifiedTransactionBundle } from '../src/proofBundle.ts';

import {
    assignReconciliationOrder,
    assertSubmittedTransactionMatches,
    markReconciliationError,
    markReconciliationFetching,
    markReconciliationWaiting,
    markSubmissionReconciling,
    markSubmissionRejected,
    markTransactionFinalized,
    markValidatorFinalizationObserved,
    submissionTimeline,
    restoreSubmittedTransaction,
    prependTransaction,
    reconciliationRetryDelay,
    selectReconciliations,
    shouldReconcileTransaction,
    type SubmittedTransaction,
} from '../src/submissionHistory.ts';

const sender = '11'.repeat(32);
const recipient = '22'.repeat(32);
const digest = '33'.repeat(32);

function verifiedBundle(): VerifiedTransactionBundle {
    const root = new Uint8Array(32);
    return {
        height: 19n, view: 4n, location: 120n, tip: 140n, proofSizeBytes: 240,
        blockDigest: root,
        transaction: { digest, sender, recipient, value: 7n, nonce: 2n, location: 120n, index: 0 },
        target: {
            height: 23n, view: 9n, contextView: 8n, timestampMs: 10n, blockDigest: root,
            stateRoot: root, stateStart: 1n, stateTip: 140n,
            transactionsRoot: root, transactionsStart: 1n, transactionsTip: 140n, sequenceNumber: 1n,
        },
    };
}

test('stored display fields must match the proved body before finalization is published', () => {
    const local = reconcilingTransaction();
    const verified = verifiedBundle();
    assert.doesNotThrow(() => assertSubmittedTransactionMatches(local, verified.transaction));
    const changes: Partial<SubmittedTransaction>[] = [
        { sender: '44'.repeat(32) }, { to: '44'.repeat(32) },
        { digest: '44'.repeat(32) }, { value: '999' }, { nonce: '999' },
    ];
    for (const change of changes) {
        const restored = restoreSubmittedTransaction({ ...local, ...change, status: 'finalized' })!;
        assert.throws(() => assertSubmittedTransactionMatches(restored, verified.transaction), /do not match/);
        const [result] = markTransactionFinalized(verified, 1_600, [restored]);
        assert.equal(result.status, 'reconciling');
        assert.notEqual(result.certificate.status, 'verified');
        assert.notEqual(result.proof.status, 'verified');
        assert.equal(result.finalizedHeight, null);
        assert.equal(result.finalizationObservedInMs, null);
        assert.equal(result.proofObservedInMs, null);
        assert.equal(result.nonce, restored.nonce);
        if (restored.digest === verified.transaction.digest) {
            assert.equal(result.certificate.status, 'error');
            assert.equal(result.proof.status, 'error');
            assert.match(result.detail, /do not match/);
        }
    }
});

function reconcilingTransaction(): SubmittedTransaction {
    return {
        reconciliationVersion: 2,
        sender,
        digest,
        to: recipient,
        value: '7',
        nonce: '2',
        submittedAt: 1_000,
        reportedInMs: null,
        reportedHeight: null,
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
    const transaction = restoreSubmittedTransaction({
        ...reconcilingTransaction(),
        reconciliationVersion: undefined,
        status: 'dropped',
        detail: 'dropped',
        proof: { status: 'waiting', detail: 'not finalized' },
    });

    assert.equal(transaction?.status, 'reconciling');
    assert.equal(transaction?.finalizationObservedInMs, null);
    assert.equal(transaction?.proofObservedInMs, null);
    assert.equal(transaction?.finalizedHeight, null);
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(transaction!, sender), true);
});

test('version one finalized rows require fresh verification after restore', () => {
    const transaction = restoreSubmittedTransaction({
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
    assert.equal(transaction?.status, 'reconciling');
    assert.equal(transaction?.finalizedHeight, null);
    assert.equal(transaction?.certificate.status, 'waiting');
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(transaction?.finalizationObservedInMs, null);
    assert.equal(transaction?.proofObservedInMs, null);
});

test('legacy filtered rows return to digest reconciliation', () => {
    const transaction = restoreSubmittedTransaction({
        ...reconcilingTransaction(),
        reconciliationVersion: undefined,
        status: 'partially_finalized',
        proof: { status: 'waiting', detail: 'not included' },
    });

    assert.equal(transaction?.status, 'reconciling');
    assert.equal(transaction?.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(transaction!, sender), true);
});

test('local rejection stops reconciliation without latency', () => {
    const [transaction] = markSubmissionRejected(
        digest,
        'transaction failed local validation before dispatch',
        [reconcilingTransaction()],
    );

    assert.equal(transaction.status, 'rejected');
    assert.equal(transaction.finalizationObservedInMs, null);
    assert.equal(transaction.proofObservedInMs, null);
    assert.equal(transaction.certificate.status, 'unavailable');
    assert.equal(transaction.proof.status, 'unavailable');
    assert.equal(shouldReconcileTransaction(transaction, sender), false);

    const [afterProof] = markTransactionFinalized(verifiedBundle(), 1_600, [transaction]);
    assert.deepEqual(afterProof, transaction);
});

test('full membership publishes finality, certificate, proof, and observation times together', () => {
    const finalized = markTransactionFinalized(verifiedBundle(), 1_600, [reconcilingTransaction()])[0];
    assert.equal(finalized.status, 'finalized');
    assert.equal(finalized.finalizedHeight, 19);
    assert.equal(finalized.finalizationObservedInMs, 600);
    assert.equal(finalized.proofObservedInMs, 600);
    assert.deepEqual(finalized.certificate, {
        status: 'verified', detail: 'verified at height 23', height: '23', view: '9',
    });
    assert.deepEqual(finalized.proof, {
        status: 'verified', detail: 'verified at height 19', location: '120', tip: '140', proofSizeBytes: 240,
    });
    assert.deepEqual(markTransactionFinalized(verifiedBundle(), 1_700, [finalized])[0], finalized);
    assert.deepEqual(markSubmissionReconciling(digest, 'admitted by a leader', [finalized])[0], finalized);
    assert.deepEqual(markSubmissionRejected(digest, 'late deterministic response', [finalized])[0], finalized);
});

test('an owning height outside the stored numeric range cannot publish partial chain state', () => {
    const local = reconcilingTransaction();
    const [result] = markTransactionFinalized({ ...verifiedBundle(), height: 1n << 53n }, 1_600, [local]);
    assert.equal(result.status, 'reconciling');
    assert.equal(result.certificate.status, 'error');
    assert.equal(result.proof.status, 'error');
    assert.equal(result.finalizedHeight, null);
    assert.equal(result.finalizationObservedInMs, null);
    assert.equal(result.proofObservedInMs, null);
    assert.match(result.detail, /height exceeds Number.MAX_SAFE_INTEGER/);
});

test('wallet observation timing records only previously unobserved milestones', () => {
    for (const timing of [
        { finalizationObservedInMs: 0, proofObservedInMs: null },
        { finalizationObservedInMs: null, proofObservedInMs: 250 },
    ]) {
        const [finalized] = markTransactionFinalized(verifiedBundle(), 1_600, [{
            ...reconcilingTransaction(), ...timing,
        }]);
        assert.equal(finalized.finalizationObservedInMs, timing.finalizationObservedInMs ?? 600);
        assert.equal(finalized.proofObservedInMs, timing.proofObservedInMs ?? 600);
        assert.equal(finalized.status, 'finalized');
    }
});

test('wallet observation timing restores only nonnegative safe integer durations', () => {
    const cases: [unknown, number | null][] = [
        [0, 0], [600, 600], [Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
        [undefined, null], [null, null], [-1, null], [0.5, null],
        [Number.MAX_SAFE_INTEGER + 1, null], [NaN, null], [Infinity, null],
        ['600', null], [true, null], [{}, null], [[], null],
    ];
    for (const [duration, expected] of cases) {
        const restored = restoreSubmittedTransaction({
            ...reconcilingTransaction(), finalizationObservedInMs: duration, proofObservedInMs: duration,
        })!;
        assert.equal(restored.finalizationObservedInMs, expected);
        assert.equal(restored.proofObservedInMs, expected);
        assert.equal(restored.nonce, '2');
        assert.equal(shouldReconcileTransaction(restored, sender), true);
    }
});

test('a relayer finality report records local timing but no authenticated height or observation', () => {
    const [observed] = markValidatorFinalizationObserved(
        digest,
        19,
        1_250,
        [reconcilingTransaction()],
    );

    assert.equal(observed.status, 'reconciling');
    assert.equal(observed.finalizedHeight, null);
    assert.equal(observed.reportedInMs, 250);
    assert.equal(observed.reportedHeight, 19);
    assert.equal(observed.finalizationObservedInMs, null);
    assert.equal(observed.proofObservedInMs, null);
    assert.equal(observed.certificate.status, 'waiting');
    assert.equal(observed.proof.status, 'waiting');

    const restored = restoreSubmittedTransaction(observed);
    assert.equal(restored?.status, 'reconciling');
    assert.equal(restored?.finalizedHeight, null);
    assert.equal(restored?.reportedInMs, 250);
    assert.equal(restored?.reportedHeight, 19);
    assert.equal(restored?.finalizationObservedInMs, null);
    assert.equal(restored?.proofObservedInMs, null);

    const [finalized] = markTransactionFinalized(verifiedBundle(), 1_400, [observed]);
    assert.equal(finalized.status, 'finalized');
    assert.equal(finalized.finalizedHeight, 19);
    assert.equal(finalized.finalizationObservedInMs, 400);
    assert.equal(finalized.certificate.status, 'verified');
    assert.equal(finalized.proof.status, 'verified');

    const [afterReport] = markValidatorFinalizationObserved(digest, 99, 1_500, [finalized]);
    assert.deepEqual(afterReport, finalized);
});

test('the submission timeline ends at the first pending or failed step and keeps stored timing', () => {
    const submitted = reconcilingTransaction();
    assert.deepEqual(submissionTimeline(submitted).map((step) => [step.kind, step.state, step.elapsedMs]), [['reported', 'pending', null]]);

    const [reported] = markValidatorFinalizationObserved(digest, 19, 1_640, [submitted]);
    assert.deepEqual(submissionTimeline(reported).map((step) => [step.label, step.state, step.elapsedMs]),
        [['reported h19', 'done', 640], ['awaiting proof', 'pending', null]]);

    const [verified] = markTransactionFinalized(verifiedBundle(), 2_200, [reported]);
    const steps = submissionTimeline(verified);
    assert.deepEqual(steps.map((step) => [step.state, step.elapsedMs]), [['done', 640], ['done', 1_200]]);
    assert.match(steps[1]!.label, /^cert h\d+ \/ loc \d+$/);

    // A reload keeps both durations while the chain evidence is re-verified.
    const restored = restoreSubmittedTransaction(verified)!;
    assert.deepEqual(submissionTimeline(restored).map((step) => [step.state, step.elapsedMs]), [['done', 640], ['pending', null]]);
    const [again] = markTransactionFinalized(verifiedBundle(), 9_999, [restored]);
    assert.deepEqual(submissionTimeline(again).map((step) => step.elapsedMs), [640, 1_200]);

    const [failed] = markReconciliationError(digest, 'certificate failed verification', [reported]);
    assert.deepEqual(submissionTimeline(failed).map((step) => [step.state, step.detail]),
        [['done', ''], ['failed', 'certificate failed verification']]);
    const [rejected] = markSubmissionRejected(digest, 'nonce already used', [submitted]);
    assert.deepEqual(submissionTimeline(rejected).map((step) => [step.label, step.state, step.detail]), [['rejected', 'failed', 'nonce already used']]);
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

test('sleeping retries leave capacity for queued proofs without retrying early', () => {
    const transactions = Array.from({ length: 5 }, (_, index) => ({
        ...reconcilingTransaction(),
        digest: index.toString(16).padStart(64, '0'),
    }));
    const order = new Map(transactions.map((tx, index) => [tx.digest, index]));
    const handles = new Map<string, { timer: number | null }>(
        transactions.slice(0, 3).map((tx) => [tx.digest, { timer: 1 }]),
    );

    assert.deepEqual(selectReconciliations(transactions, handles, order, 3), transactions.slice(3));

    handles.get(transactions[0].digest)!.timer = null;
    handles.get(transactions[1].digest)!.timer = null;
    assert.deepEqual(selectReconciliations(transactions, handles, order, 3), [transactions[3]]);

    handles.get(transactions[2].digest)!.timer = null;
    assert.deepEqual(selectReconciliations(transactions, handles, order, 3), []);

    handles.delete(transactions[2].digest);
    order.set(transactions[2].digest, 5);
    assert.deepEqual(selectReconciliations(transactions, handles, order, 3), [transactions[3]]);
});

test('reloaded proof errors retry corrected backend data', () => {
    for (const reconciliationVersion of [1, 2]) {
        const transaction = restoreSubmittedTransaction({
            ...reconcilingTransaction(),
            reconciliationVersion,
            certificate: { status: 'error', detail: 'SQL transaction body does not match transaction digest' },
            proof: { status: 'error', detail: 'SQL transaction body does not match transaction digest' },
        });

        assert.equal(transaction?.status, 'reconciling');
        assert.equal(transaction?.certificate.status, 'waiting');
        assert.equal(transaction?.proof.status, 'waiting');
        assert.equal(shouldReconcileTransaction(transaction!, sender), true);
    }
});

test('finalized in-memory evidence survives retry updates but restore requires new proof', () => {
    const initial = markTransactionFinalized(verifiedBundle(), 1_600, [reconcilingTransaction()])[0];
    const fetching = markReconciliationFetching(digest, [initial])[0];
    const waiting = markReconciliationWaiting(digest, 'retry scheduled', [fetching])[0];
    const failed = markReconciliationError(digest, 'invalid proof', [waiting])[0];

    for (const tx of [fetching, waiting, failed]) assert.deepEqual(tx, initial);
    const restored = restoreSubmittedTransaction(failed)!;
    assert.equal(restored.certificate.status, 'waiting');
    assert.equal(restored.finalizedHeight, null);
    assert.equal(restored.proof.status, 'waiting');
    assert.equal(shouldReconcileTransaction(restored, sender), true);
});

test('stored status and proof claims cannot stop reconciliation or authorize badges', () => {
    for (const reconciliationVersion of [undefined, 1, 2]) {
        for (const status of ['finalized', 'rejected', 'dropped', 'partially_finalized', 'reconciling']) {
            const transaction = restoreSubmittedTransaction({
                ...reconcilingTransaction(),
                reconciliationVersion,
                status,
                detail: 'finalized at 19',
                finalizedHeight: 19,
                finalizationObservedInMs: 250,
                proofObservedInMs: 300,
                certificate: { status: 'verified', detail: 'verified', height: '19', view: '4' },
                proof: { status: 'verified', detail: 'verified', location: '120', tip: '130', proofSizeBytes: 240 },
            });

            assert.ok(transaction);
            assert.equal(transaction.status, 'reconciling');
            assert.equal(transaction.nonce, '2');
            assert.equal(transaction.finalizedHeight, null);
            assert.equal(transaction.finalizationObservedInMs, 250);
            assert.equal(transaction.proofObservedInMs, 300);
            assert.equal(transaction.certificate.status, 'waiting');
            assert.equal(transaction.proof.status, 'waiting');
            assert.notEqual(transaction.detail, 'finalized at 19');
            assert.equal(shouldReconcileTransaction(transaction, sender), true);
        }
    }
});

test('restore ignores missing or malformed chain claims while retaining valid local fields', () => {
    const local = {
        sender, digest, to: recipient, value: '7', nonce: '2', submittedAt: 1_000,
    };
    const expected = restoreSubmittedTransaction(local);
    assert.ok(expected);
    assert.deepEqual(restoreSubmittedTransaction({
        ...local,
        status: 'finalized',
        certificate: 'invalid',
        proof: null,
        finalizedHeight: Number.MAX_SAFE_INTEGER,
    }), expected);

    for (const invalid of [
        { nonce: '-1' }, { nonce: '18446744073709551616' }, { nonce: '0'.repeat(1000) },
        { value: '18446744073709551616' }, { submittedAt: NaN }, { submittedAt: Infinity },
        { sender: 'invalid' }, { digest: '' },
    ]) {
        assert.equal(restoreSubmittedTransaction({ ...local, ...invalid }), null);
    }
    assert.equal(restoreSubmittedTransaction({ ...local, nonce: '18446744073709551615' })?.nonce,
        '18446744073709551615');
});
