import assert from 'node:assert/strict';
import test from 'node:test';

import {
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
    connectivityAdvisory,
    parseCommitteeResponse,
    planCommitteeTransactions,
    validateCommitteeSelection,
} from '../src/committee.ts';

const PEER_A = `ed25519:${'11'.repeat(32)}`;
const PEER_B = `ed25519:${'22'.repeat(32)}`;
const PEER_C = `ed25519:${'33'.repeat(32)}`;

test('committee response requires exact decimal strings and retains all eligible peers', () => {
    const snapshot = parseCommitteeResponse(response());

    assert.equal(snapshot.height, 17_890n);
    assert.equal(snapshot.epoch, 17n);
    assert.equal(snapshot.targetEpoch, 19n);
    assert.deepEqual(snapshot.available.map(({ peer }) => peer), [PEER_A, PEER_B, PEER_C]);
    assert.equal(snapshot.available[1]?.connected, false);

    assert.throws(
        () => parseCommitteeResponse({ ...response(), height: 17890 }),
        /height must be a canonical decimal string/,
    );
    assert.throws(
        () => parseCommitteeResponse({ ...response(), targetEpoch: '20' }),
        /targetEpoch must equal epoch \+ 2/,
    );
});

test('selection diff includes disconnected eligible peers because connectivity is advisory', () => {
    const snapshot = parseCommitteeResponse(response());
    const selected = new Set([PEER_A, PEER_B]);

    assert.deepEqual(committeeChanges(snapshot, selected), [
        { peer: PEER_B, registered: true },
        { peer: PEER_C, registered: false },
    ]);
    assert.equal(connectivityAdvisory(false), 'not connected · advisory');
    assert.equal(validateCommitteeSelection(new Set()), 'committee must contain at least one peer');
});

test('lock model names the exact rejecting final block and last accepted block', () => {
    const snapshot = parseCommitteeResponse(response());

    assert.equal(blocksUntilCommitteeLock(snapshot), 541n);
    assert.equal(
        committeeLockDetail(snapshot),
        'final block 18431 rejects updates; accepted through block 18430',
    );
});

test('per-peer E+2 actions reserve sequential nonces before signing', () => {
    const changes = [
        { peer: PEER_B, registered: true },
        { peer: PEER_C, registered: false },
        { peer: PEER_A, registered: false },
    ];

    const plan = planCommitteeTransactions(changes, 19n, { base: 7n, bitmap: 0n });

    assert.deepEqual(plan.transactions.map(({ nonce }) => nonce), [7n, 8n, 9n]);
    assert.ok(plan.transactions.every(({ targetEpoch }) => targetEpoch === 19n));
    assert.deepEqual(plan.nextNonceState, { base: 10n, bitmap: 0n });
});

function response(): Record<string, unknown> {
    return {
        height: '17890',
        epoch: '17',
        targetEpoch: '19',
        updatesOpen: true,
        lockHeight: '18431',
        current: [PEER_A, PEER_C],
        scheduled: [PEER_A, PEER_C],
        available: [
            { peer: PEER_A, address: 'validator-a:9000', connected: true },
            { peer: PEER_B, address: 'validator-b:9000', connected: false },
            { peer: PEER_C, address: 'validator-c:9000', connected: true },
        ],
    };
}
