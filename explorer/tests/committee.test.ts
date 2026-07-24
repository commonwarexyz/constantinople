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
    assert.equal(
        validateCommitteeSelection(new Set(Array.from({ length: 65 }, (_, index) => peer(index)))),
        'committee must contain at most 64 peers',
    );
});

test('lock model names the exact rejecting final block and last accepted block', () => {
    const snapshot = parseCommitteeResponse(response());

    assert.equal(blocksUntilCommitteeLock(snapshot), 540n);
    assert.equal(
        committeeLockDetail(snapshot),
        'final block 18431 rejects updates; accepted through block 18430',
    );
});

test('lock distance reaches zero when the penultimate block is finalized', () => {
    const snapshot = parseCommitteeResponse({
        ...response(),
        height: '18430',
        updatesOpen: false,
    });

    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('per-peer E+2 actions reserve sequential nonces before signing', () => {
    const changes = [
        { peer: PEER_B, registered: true },
        { peer: PEER_C, registered: false },
        { peer: PEER_A, registered: false },
    ];

    const plan = planCommitteeTransactions(changes, 19n, { base: 7n, bitmap: 0n }, 2);

    assert.deepEqual(plan.transactions.map(({ nonce }) => nonce), [7n, 8n, 9n]);
    assert.ok(plan.transactions.every(({ targetEpoch }) => targetEpoch === 19n));
    assert.deepEqual(plan.nextNonceState, { base: 10n, bitmap: 0n });
});

test('sole-member replacement adds before removing the last member', () => {
    const snapshot = committeeSnapshot([PEER_A], [PEER_A, PEER_B]);
    const expected = [
        { peer: PEER_B, registered: true },
        { peer: PEER_A, registered: false },
    ];

    assert.deepEqual(committeeChanges(snapshot, new Set([PEER_B])), expected);

    const plan = planCommitteeTransactions(
        [...expected].reverse(),
        snapshot.targetEpoch,
        { base: 10n, bitmap: 0n },
        1,
    );
    assert.deepEqual(plan.transactions.map(changeWithoutPlanFields), expected);
    assert.deepEqual(intermediateCommitteeSizes(plan.transactions, 1), [2, 1]);
});

test('full 64-member replacement removes before adding the new member', () => {
    const peers = Array.from({ length: 65 }, (_, index) => peer(index));
    const scheduled = peers.slice(0, 64);
    const selected = new Set([...scheduled.slice(1), peers[64]]);
    const snapshot = committeeSnapshot(scheduled, peers);
    const expected = [
        { peer: peers[0], registered: false },
        { peer: peers[64], registered: true },
    ];

    assert.deepEqual(committeeChanges(snapshot, selected), expected);

    const plan = planCommitteeTransactions(
        [...expected].reverse(),
        snapshot.targetEpoch,
        { base: 20n, bitmap: 0n },
        64,
    );
    assert.deepEqual(plan.transactions.map(changeWithoutPlanFields), expected);
    assert.deepEqual(intermediateCommitteeSizes(plan.transactions, 64), [63, 64]);
});

test('multi-swap ordering adapts at capacity and remains deterministic', () => {
    const peers = Array.from({ length: 65 }, (_, index) => peer(index));
    const scheduled = peers.slice(0, 63);
    const selected = new Set([...scheduled.slice(2), peers[63], peers[64]]);
    const snapshot = committeeSnapshot(scheduled, peers);
    const expected = [
        { peer: peers[63], registered: true },
        { peer: peers[0], registered: false },
        { peer: peers[64], registered: true },
        { peer: peers[1], registered: false },
    ];

    const first = committeeChanges(snapshot, selected);
    const second = committeeChanges(snapshot, selected);
    assert.deepEqual(first, expected);
    assert.deepEqual(second, expected);
    assert.deepEqual(intermediateCommitteeSizes(first, 63), [64, 63, 64, 63]);
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

function committeeSnapshot(scheduled: readonly string[], available: readonly string[]) {
    return parseCommitteeResponse({
        ...response(),
        current: scheduled,
        scheduled,
        available: available.map((candidate, index) => ({
            peer: candidate,
            address: `validator-${index}:9000`,
            connected: true,
        })),
    });
}

function peer(index: number): string {
    return `ed25519:${index.toString(16).padStart(64, '0')}`;
}

function changeWithoutPlanFields({
    peer: changedPeer,
    registered,
}: {
    readonly peer: string;
    readonly registered: boolean;
}) {
    return { peer: changedPeer, registered };
}

function intermediateCommitteeSizes(
    changes: readonly { readonly registered: boolean }[],
    initialSize: number,
): number[] {
    let size = initialSize;
    return changes.map(({ registered }) => {
        size += registered ? 1 : -1;
        assert.ok(size >= 1 && size <= 64);
        return size;
    });
}
