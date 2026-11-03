import assert from 'node:assert/strict';
import test from 'node:test';
import type { VerifiedTransactionBundle } from '../src/proofBundle.ts';
import { readStoredHistory } from '../src/historyStorage.ts';
import { submittedTransactionHistoryKey } from '../src/historyKey.ts';
import { emptyNonceState, nextAvailableNonce, reserveNonces } from '../src/nonce.ts';
import {
    WAITING_FINALIZATION_CERTIFICATE,
    WAITING_FINALIZATION_PROOF,
    markTransactionFinalized,
    prependTransaction,
    shouldReconcileTransaction,
    type SubmittedTransaction,
} from '../src/submissionHistory.ts';

const account = 'aa'.repeat(32);
const material = 'bb'.repeat(32);
const key = submittedTransactionHistoryKey({ indexerUrl: 'http://indexer', simplexVerificationMaterial: material }, account)!;
const legacy = (committee = material, wallet = account) => `constantinople.submitted-transactions.v3:http%3A%2F%2Fsql:http%3A%2F%2Fqmdb:http%3A%2F%2Fstore:http%3A%2F%2Frelayer:${committee}:${wallet}`;
const pending: SubmittedTransaction = {
    reconciliationVersion: 2, sender: account, digest: 'cc'.repeat(32), to: 'dd'.repeat(32),
    value: '1', nonce: '0', submittedAt: 1, finalizationObservedInMs: null,
    proofObservedInMs: null, status: 'reconciling', detail: 'delivery uncertain',
    finalizedHeight: null, certificate: WAITING_FINALIZATION_CERTIFICATE, proof: WAITING_FINALIZATION_PROOF,
};

const verified: VerifiedTransactionBundle = {
    height: 19n, view: 4n, location: 120n, tip: 140n, proofSizeBytes: 240,
    blockDigest: new Uint8Array(32),
    transaction: {
        digest: pending.digest, sender: pending.sender, recipient: pending.to,
        value: 1n, nonce: 0n, location: 120n, index: 0,
    },
    target: {
        height: 23n, view: 9n, contextView: 8n, timestampMs: 10n, blockDigest: new Uint8Array(32),
        stateRoot: new Uint8Array(32), stateStart: 1n, stateTip: 140n,
        transactionsRoot: new Uint8Array(32), transactionsStart: 1n, transactionsTip: 140n, sequenceNumber: 1n,
    },
};

function memoryStorage(entries: [string, string][]): Storage {
    const values = new Map(entries);
    return {
        get length() { return values.size; },
        clear: () => values.clear(),
        getItem: (key) => values.get(key) ?? null,
        key: (index) => [...values.keys()][index] ?? null,
        removeItem: (key) => { values.delete(key); },
        setItem: (key, value) => { values.set(key, value); },
    };
}

test('single-indexer upgrade keeps ambiguous nonce reservations from the same chain', () => {
    const storage = memoryStorage([[legacy(), JSON.stringify([pending])]]);
    const history = readStoredHistory(key, storage);
    const reserved = reserveNonces(emptyNonceState(), history.filter((tx) => tx.status !== 'rejected').map((tx) => BigInt(tx.nonce)));
    assert.equal(nextAvailableNonce(reserved), 1n);
    assert.equal(storage.getItem(key), JSON.stringify(history));
    assert.equal(readStoredHistory(key, storage).length, 1);
});

test('migration excludes other committees and wallets', () => {
    const storage = memoryStorage([
        [legacy('ee'.repeat(32)), JSON.stringify([pending])],
        [legacy(material, 'ff'.repeat(32)), JSON.stringify([pending])],
    ]);
    assert.deepEqual(readStoredHistory(key, storage), []);
});

test('an existing current history is authoritative after migration and clearing', () => {
    const storage = memoryStorage([[legacy(), JSON.stringify([pending])], [key, '[]']]);
    assert.deepEqual(readStoredHistory(key, storage), []);
});


test('migration failure cannot report history as safely loaded', () => {
    const storage = memoryStorage([[legacy(), JSON.stringify([pending])]]);
    storage.setItem = () => { throw new Error('storage blocked'); };
    assert.throws(() => readStoredHistory(key, storage), /storage blocked/);
});

test('duplicate legacy histories retain a nonce reservation regardless of cached status', () => {
    const second = legacy().replace('http%3A%2F%2Fsql', 'http%3A%2F%2Fother-sql');
    const storage = memoryStorage([
        [legacy(), JSON.stringify([pending])],
        [second, JSON.stringify([{ ...pending, status: 'rejected' }])],
    ]);
    const history = readStoredHistory(key, storage);
    assert.equal(history.length, 1);
    assert.equal(history[0]!.status, 'reconciling');
});

test('current stored finalized and rejected rows reserve nonces and require fresh proof', () => {
    const stored = ['finalized', 'rejected', 'dropped'].map((status, index) => ({
        ...pending,
        status,
        digest: String(index + 1).repeat(64),
        nonce: String(index),
        finalizedHeight: 19,
        finalizationObservedInMs: 10,
        proofObservedInMs: 20,
        certificate: { status: 'verified', detail: 'verified', height: '19', view: '4' },
        proof: { status: 'verified', detail: 'verified', location: '120', tip: '130', proofSizeBytes: 240 },
    }));
    const storage = memoryStorage([[key, JSON.stringify(stored)]]);
    const history = readStoredHistory(key, storage);

    assert.equal(history.length, 3);
    for (const transaction of history) {
        assert.equal(transaction.certificate.status, 'waiting');
        assert.equal(transaction.proof.status, 'waiting');
        assert.equal(transaction.finalizedHeight, null);
        assert.equal(transaction.finalizationObservedInMs, 10);
        assert.equal(transaction.proofObservedInMs, 20);
        assert.equal(shouldReconcileTransaction(transaction, account), true);
    }
    const reserved = reserveNonces(emptyNonceState(), history.map((transaction) => BigInt(transaction.nonce)));
    assert.equal(nextAvailableNonce(reserved), 3n);
});

test('legacy verified rows are downgraded before the migrated history is persisted', () => {
    const storage = memoryStorage([[legacy(), JSON.stringify([{
        ...pending,
        status: 'finalized',
        finalizedHeight: 19,
        certificate: { status: 'verified', detail: 'verified', height: '19', view: '4' },
        proof: { status: 'verified', detail: 'verified', location: '120', tip: '130', proofSizeBytes: 240 },
    }])]]);
    const history = readStoredHistory(key, storage);

    assert.equal(history[0]!.status, 'reconciling');
    assert.equal(history[0]!.certificate.status, 'waiting');
    assert.equal(history[0]!.proof.status, 'waiting');
    assert.equal(storage.getItem(key), JSON.stringify(history));
    assert.deepEqual(readStoredHistory(key, storage), history);
});

test('storage reads do not downgrade fresh in-memory verification during another submission', () => {
    const live = markTransactionFinalized(verified, 20, [pending]);
    const storage = memoryStorage([[key, JSON.stringify(live)]]);
    const next = { ...pending, digest: 'ee'.repeat(32), nonce: '1' };

    storage.setItem(key, JSON.stringify(prependTransaction(next, readStoredHistory(key, storage))));
    const updatedLive = prependTransaction(next, live);

    assert.equal(live[0]!.status, 'finalized');
    assert.deepEqual(updatedLive[1], live[0]);
    assert.equal(updatedLive[1]!.finalizationObservedInMs, 19);
    assert.equal(updatedLive[1]!.proofObservedInMs, 19);
    assert.ok(readStoredHistory(key, storage).every((transaction) =>
        transaction.status === 'reconciling' && transaction.certificate.status === 'waiting' &&
        transaction.proof.status === 'waiting'));
    assert.equal(readStoredHistory(key, storage)[1]!.proofObservedInMs, 19);
});

test('wallet observation timing survives repeated storage reloads and proof verification', () => {
    const storage = memoryStorage([[key, JSON.stringify(markTransactionFinalized(verified, 501, [pending]))]]);

    for (const observedAt of [10_000, 800_000]) {
        const restored = readStoredHistory(key, storage);
        assert.equal(restored[0]!.status, 'reconciling');
        assert.equal(restored[0]!.certificate.status, 'waiting');
        assert.equal(restored[0]!.proof.status, 'waiting');
        assert.equal(restored[0]!.finalizedHeight, null);
        assert.equal(shouldReconcileTransaction(restored[0]!, account), true);
        assert.equal(restored[0]!.finalizationObservedInMs, 500);
        assert.equal(restored[0]!.proofObservedInMs, 500);

        const verifiedAgain = markTransactionFinalized(verified, observedAt, restored);
        assert.equal(verifiedAgain[0]!.status, 'finalized');
        assert.equal(verifiedAgain[0]!.proof.status, 'verified');
        assert.equal(verifiedAgain[0]!.finalizationObservedInMs, 500);
        assert.equal(verifiedAgain[0]!.proofObservedInMs, 500);
        storage.setItem(key, JSON.stringify(verifiedAgain));
    }
});

test('a verified digest cannot finalize forged siblings restored from current history', () => {
    const forged = { ...pending, value: '999', nonce: '1', status: 'finalized' };
    const storage = memoryStorage([[key, JSON.stringify([forged, pending])]]);
    const restored = readStoredHistory(key, storage);
    assert.equal(restored.length, 2);

    const [rejectedEvidence, finalized] = markTransactionFinalized(verified, 20, restored);
    assert.equal(finalized.status, 'finalized');
    assert.equal(finalized.certificate.status, 'verified');
    assert.equal(finalized.proof.status, 'verified');
    assert.equal(rejectedEvidence.status, 'reconciling');
    assert.equal(rejectedEvidence.certificate.status, 'error');
    assert.equal(rejectedEvidence.proof.status, 'error');
    assert.equal(rejectedEvidence.finalizedHeight, null);
    assert.equal(rejectedEvidence.finalizationObservedInMs, null);
    assert.equal(rejectedEvidence.proofObservedInMs, null);
    assert.equal(rejectedEvidence.nonce, '1');
    const reserved = reserveNonces(emptyNonceState(), [rejectedEvidence, finalized].map((tx) => BigInt(tx.nonce)));
    assert.equal(nextAvailableNonce(reserved), 2n);
});
