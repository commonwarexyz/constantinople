import assert from 'node:assert/strict';
import test from 'node:test';

import {
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
    fetchCommittee,
    planCommitteeTransactions,
    reconcileCommitteeSelection,
    validateCommitteeSelection,
    type CommitteeSnapshot,
} from '../src/committee.ts';
import type { DecodedQueryResult } from '@exowarexyz/sql';

const PEER_A = '11'.repeat(32);
const PEER_B = '22'.repeat(32);
const PEER_C = '33'.repeat(32);

test('committee reads finalized snapshots and eligible peers from SQL', async () => {
    const queries: string[] = [];
    const snapshot = await fetchCommittee('http://indexer.invalid', undefined, {
        async query(sql: string): Promise<DecodedQueryResult> {
            queries.push(sql);
            if (sql.includes('FROM block_meta')) {
                return result({ height: 17_890n, epoch: 139n });
            }
            if (sql.includes('FROM committee_meta') && sql.includes('<= 141')) {
                // Epoch 141 has no explicit row yet, so the index query carries
                // forward the most recent materialized committee.
                return result({ epoch: 140n, members: peerBytes(PEER_A, PEER_C) });
            }
            if (sql.includes('FROM committee_meta') && sql.includes('<= 140')) {
                return result({ epoch: 140n, members: peerBytes(PEER_A, PEER_B) });
            }
            if (sql.includes('FROM committee_meta')) {
                return result({ epoch: 139n, members: peerBytes(PEER_A, PEER_C) });
            }
            if (sql.includes('FROM eligible_peer')) {
                return result(
                    { peer: peerBytes(PEER_A), address: 'validator-a:9000' },
                    { peer: peerBytes(PEER_B), address: 'validator-b:9000' },
                    { peer: peerBytes(PEER_C), address: 'validator-c:9000' },
                );
            }
            throw new Error(`unexpected SQL: ${sql}`);
        },
    });

    assert.equal(snapshot.height, 17_890n);
    assert.equal(snapshot.epoch, 139n);
    assert.equal(snapshot.targetEpoch, 141n);
    assert.equal(snapshot.lockHeight, 17_918n);
    assert.equal(snapshot.updatesOpen, true);
    assert.deepEqual(snapshot.next, [PEER_A, PEER_B]);
    assert.deepEqual(snapshot.available.map(({ peer }) => peer), [PEER_A, PEER_B, PEER_C]);
    assert.equal(queries.length, 5);
    assert.ok(queries.some((query) => query.includes('FROM committee_meta')));
    assert.ok(queries.some((query) => query.includes('FROM eligible_peer')));
});

test('selection diff includes every indexed eligible peer', () => {
    const snapshot = response();
    const selected = new Set([PEER_A, PEER_B]);

    assert.deepEqual(committeeChanges(snapshot, selected), [
        { peer: PEER_B, registered: true },
        { peer: PEER_C, registered: false },
    ]);
    assert.equal(validateCommitteeSelection(new Set()), 'committee must contain at least one peer');
    assert.equal(
        validateCommitteeSelection(new Set(Array.from({ length: 65 }, (_, index) => peer(index)))),
        'committee must contain at most 64 peers',
    );
});

test('selection reconciliation preserves edits across height-only refreshes', () => {
    const previous = response();
    const next = { ...previous, height: previous.height + 1n };

    assert.deepEqual(
        reconcileCommitteeSelection(previous, next, new Set([PEER_A, PEER_B])),
        new Set([PEER_A, PEER_B]),
    );
});

test('selection reconciliation rebases edits onto same-target schedule changes', () => {
    const previous = committeeSnapshot([PEER_A], [PEER_A, PEER_B, PEER_C]);
    const next = committeeSnapshot([PEER_A, PEER_C], [PEER_A, PEER_B, PEER_C]);

    assert.deepEqual(
        reconcileCommitteeSelection(previous, next, new Set([PEER_A, PEER_B])),
        new Set([PEER_A, PEER_B, PEER_C]),
    );
});

test('selection reconciliation resets at a target epoch change', () => {
    const previous = committeeSnapshot([PEER_A], [PEER_A, PEER_B, PEER_C]);
    const next = {
        ...committeeSnapshot([PEER_C], [PEER_A, PEER_B, PEER_C]),
        targetEpoch: previous.targetEpoch + 1n,
    };

    assert.deepEqual(
        reconcileCommitteeSelection(previous, next, new Set([PEER_A, PEER_B])),
        new Set([PEER_C]),
    );
});

test('selection reconciliation discards unsendable edits when submissions close', () => {
    const previous = committeeSnapshot([PEER_A], [PEER_A, PEER_B, PEER_C]);
    const next = { ...previous, updatesOpen: false };

    assert.deepEqual(
        reconcileCommitteeSelection(previous, next, new Set([PEER_A, PEER_B])),
        new Set([PEER_A]),
    );
});

test('lock model names both rejecting blocks and the last accepted block', () => {
    const snapshot = response();

    assert.equal(blocksUntilCommitteeLock(snapshot), 27n);
    assert.equal(
        committeeLockDetail(snapshot),
        'final two blocks 17918 and 17919 reject updates; accepted through block 17917',
    );
});

test('submissions remain open after height 124 so updates can land in block 125', async () => {
    const snapshot = await fetchCommitteeAtHeight(124n, 0n);

    assert.equal(snapshot.lockHeight, 126n);
    assert.equal(snapshot.updatesOpen, true);
    assert.equal(blocksUntilCommitteeLock(snapshot), 1n);
});

test('submissions close after final mutable block 125 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(125n, 0n);

    assert.equal(snapshot.lockHeight, 126n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions remain closed after first rejecting block 126 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(126n, 0n);

    assert.equal(snapshot.lockHeight, 126n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions remain closed after final rejecting block 127 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(127n, 0n);

    assert.equal(snapshot.lockHeight, 126n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions reopen after height 128 starts the next epoch', async () => {
    const snapshot = await fetchCommitteeAtHeight(128n, 1n);

    assert.equal(snapshot.lockHeight, 254n);
    assert.equal(snapshot.updatesOpen, true);
    assert.equal(blocksUntilCommitteeLock(snapshot), 125n);
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

function response(): CommitteeSnapshot {
    return {
        height: 17_890n,
        epoch: 139n,
        targetEpoch: 141n,
        updatesOpen: true,
        lockHeight: 17_918n,
        current: [PEER_A, PEER_C],
        next: [PEER_A, PEER_C],
        scheduled: [PEER_A, PEER_C],
        available: [
            { peer: PEER_A, address: 'validator-a:9000' },
            { peer: PEER_B, address: 'validator-b:9000' },
            { peer: PEER_C, address: 'validator-c:9000' },
        ],
    };
}

async function fetchCommitteeAtHeight(height: bigint, epoch: bigint): Promise<CommitteeSnapshot> {
    return fetchCommittee('http://indexer.invalid', undefined, {
        async query(sql: string): Promise<DecodedQueryResult> {
            if (sql.includes('FROM block_meta')) {
                return result({ height, epoch });
            }
            if (sql.includes('FROM committee_meta')) {
                return result({ epoch: 0n, members: peerBytes(PEER_A) });
            }
            if (sql.includes('FROM eligible_peer')) {
                return result({ peer: peerBytes(PEER_A), address: 'validator-a:9000' });
            }
            throw new Error(`unexpected SQL: ${sql}`);
        },
    });
}

function committeeSnapshot(scheduled: readonly string[], available: readonly string[]) {
    return {
        ...response(),
        current: scheduled,
        next: scheduled,
        scheduled,
        available: available.map((candidate, index) => ({
            peer: candidate,
            address: `validator-${index}:9000`,
        })),
    };
}

function result(...values: Record<string, bigint | string | Uint8Array>[]): DecodedQueryResult {
    return {
        columns: values.length === 0 ? [] : Object.keys(values[0]),
        rows: values.map((row) => ({ values: row, cells: Object.values(row) })),
    };
}

function peerBytes(...peers: string[]): Uint8Array {
    return Uint8Array.from(
        peers.flatMap((peer) => peer.match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []),
    );
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
