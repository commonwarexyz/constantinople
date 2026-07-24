import assert from 'node:assert/strict';
import test from 'node:test';

import {
    applyFinalizedCommitteeOverlay,
    blocksUntilCommitteeLock,
    committeeChanges,
    committeeLockDetail,
    committeeTargetEpochAtHeight,
    createFinalizedCommitteeOverlay,
    createCommitteeDraft,
    fetchCommittee,
    fetchIndexedCommitteeTransactions,
    indexedCommitteeOverlayAdopted,
    mergeCommitteeRoster,
    mergeFinalizedCommitteeOverlay,
    planCommitteeTransactions,
    reconcileCommitteeDrafts,
    reconcileFinalizedCommitteeOverlay,
    reconcileCommitteeSelection,
    reserveAttemptedCommitteeNonce,
    validateCommitteeSelection,
    type CommitteeSnapshot,
} from '../src/committee.ts';
import type { DecodedQueryResult } from '@exowarexyz/sql';

const PEER_A = '11'.repeat(32);
const PEER_B = '22'.repeat(32);
const PEER_C = '33'.repeat(32);
const DIGEST_A = 'aa'.repeat(32);
const DIGEST_B = 'bb'.repeat(32);

test('committee reads finalized snapshots and eligible peers from SQL', async () => {
    const queries: string[] = [];
    const snapshot = await fetchCommittee('http://indexer.invalid', undefined, {
        async query(sql: string): Promise<DecodedQueryResult> {
            queries.push(sql);
            if (sql.includes('FROM block_meta')) {
                return result({ height: 8_930n, epoch: 139n });
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
                    { peer: peerBytes(PEER_A), address: '192.0.2.1:9000' },
                    { peer: peerBytes(PEER_B), address: '192.0.2.2:9000' },
                    { peer: peerBytes(PEER_C), address: '[2001:db8::3]:9000' },
                );
            }
            throw new Error(`unexpected SQL: ${sql}`);
        },
    });

    assert.equal(snapshot.height, 8_930n);
    assert.equal(snapshot.epoch, 139n);
    assert.equal(snapshot.targetEpoch, 141n);
    assert.equal(snapshot.lockHeight, 8_958n);
    assert.equal(snapshot.updatesOpen, true);
    assert.deepEqual(snapshot.next, [PEER_A, PEER_B]);
    assert.deepEqual(snapshot.available.map(({ peer }) => peer), [PEER_A, PEER_B, PEER_C]);
    assert.equal(queries.length, 5);
    assert.ok(queries.some((query) => query.includes('FROM committee_meta')));
    assert.ok(queries.some((query) => query.includes('FROM eligible_peer')));
});

test('committee rejects duplicate indexed peers', async () => {
    await assert.rejects(
        fetchCommittee('http://indexer.invalid', undefined, {
            async query(sql: string): Promise<DecodedQueryResult> {
                if (sql.includes('FROM block_meta')) return result({ height: 1n, epoch: 0n });
                if (sql.includes('FROM committee_meta')) {
                    return result({ epoch: 0n, members: peerBytes(PEER_A) });
                }
                if (sql.includes('FROM eligible_peer')) {
                    return result(
                        { peer: peerBytes(PEER_A), address: '192.0.2.1:9000' },
                        { peer: peerBytes(PEER_A), address: '192.0.2.2:9000' },
                    );
                }
                throw new Error(`unexpected SQL: ${sql}`);
            },
        }),
        /duplicate peers/,
    );
});

test('draft creation rejects indexed and already-local peers', () => {
    const roster = response().available;
    const draft = createCommitteeDraft(roster, `ED25519:${'44'.repeat(32)}`, '192.0.2.44:09000');

    assert.deepEqual(draft, {
        peer: '44'.repeat(32),
        address: '192.0.2.44:9000',
    });
    assert.throws(
        () => createCommitteeDraft(roster, PEER_A.toUpperCase(), '192.0.2.99:9000'),
        /already exists/,
    );
    assert.throws(
        () => createCommitteeDraft([...roster, draft], draft.peer, '[::1]:9000'),
        /already exists/,
    );
});

test('selection diff includes every indexed eligible peer', () => {
    const snapshot = response();
    const selected = new Set([PEER_A, PEER_B]);

    assert.deepEqual(committeeChanges(snapshot, selected), [
        { peer: PEER_B, address: '192.0.2.2:9000' },
        { peer: PEER_C, address: null },
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

test('draft peers persist across heights and reconcile when the index adopts them', () => {
    const previous = response();
    const draft = { peer: '44'.repeat(32), address: '192.0.2.44:9000' };
    const heightRefresh = { ...previous, height: previous.height + 1n };

    assert.deepEqual(reconcileCommitteeDrafts(previous, heightRefresh, [draft]), [draft]);
    assert.deepEqual(
        mergeCommitteeRoster(heightRefresh.available, [draft]).at(-1),
        draft,
    );

    const adopted = {
        ...heightRefresh,
        available: [...heightRefresh.available, draft],
    };
    assert.deepEqual(reconcileCommitteeDrafts(heightRefresh, adopted, [draft]), []);
    assert.equal(mergeCommitteeRoster(adopted.available, [draft]).length, adopted.available.length);
});

test('draft peers reset on target epoch and lock transitions', () => {
    const previous = response();
    const draft = { peer: '44'.repeat(32), address: '192.0.2.44:9000' };

    assert.deepEqual(
        reconcileCommitteeDrafts(previous, { ...previous, targetEpoch: 142n }, [draft]),
        [],
    );
    assert.deepEqual(
        reconcileCommitteeDrafts(previous, { ...previous, updatesOpen: false }, [draft]),
        [],
    );
});

test('new peer planning uses its supplied canonical address', () => {
    const snapshot = response();
    const draft = { peer: '44'.repeat(32), address: '[2001:db8::44]:9000' };
    const effective = {
        ...snapshot,
        available: mergeCommitteeRoster(snapshot.available, [draft]),
    };
    const changes = committeeChanges(effective, new Set([...snapshot.scheduled, draft.peer]));

    assert.deepEqual(changes, [draft]);
    assert.equal(
        planCommitteeTransactions(changes, { base: 3n, bitmap: 0n }, 2)
            .transactions[0].address,
        draft.address,
    );
});

test('lock model names both rejecting blocks and the last accepted block', () => {
    const snapshot = response();

    assert.equal(blocksUntilCommitteeLock(snapshot), 27n);
    assert.equal(
        committeeLockDetail(snapshot),
        'final two blocks 8958 and 8959 reject updates; accepted through block 8957',
    );
});

test('submissions remain open after height 60 so updates can land in block 61', async () => {
    const snapshot = await fetchCommitteeAtHeight(60n, 0n);

    assert.equal(snapshot.lockHeight, 62n);
    assert.equal(snapshot.updatesOpen, true);
    assert.equal(blocksUntilCommitteeLock(snapshot), 1n);
});

test('submissions close after final mutable block 61 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(61n, 0n);

    assert.equal(snapshot.lockHeight, 62n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions remain closed after first rejecting block 62 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(62n, 0n);

    assert.equal(snapshot.lockHeight, 62n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions remain closed after final rejecting block 63 is finalized', async () => {
    const snapshot = await fetchCommitteeAtHeight(63n, 0n);

    assert.equal(snapshot.lockHeight, 62n);
    assert.equal(snapshot.updatesOpen, false);
    assert.equal(blocksUntilCommitteeLock(snapshot), 0n);
});

test('submissions reopen after height 64 starts the next epoch', async () => {
    const snapshot = await fetchCommitteeAtHeight(64n, 1n);

    assert.equal(snapshot.lockHeight, 126n);
    assert.equal(snapshot.updatesOpen, true);
    assert.equal(blocksUntilCommitteeLock(snapshot), 61n);
});

test('per-peer actions reserve sequential nonces before signing', () => {
    const changes = [
        { peer: PEER_B, address: '192.0.2.2:9000' },
        { peer: PEER_C, address: null },
        { peer: PEER_A, address: null },
    ];

    const plan = planCommitteeTransactions(changes, { base: 7n, bitmap: 0n }, 2);

    assert.deepEqual(plan.transactions, [
        { ...changes[0], nonce: 7n },
        { ...changes[1], nonce: 8n },
        { ...changes[2], nonce: 9n },
    ]);
    assert.deepEqual(plan.nextNonceState, { base: 10n, bitmap: 0n });
});

test('attempted committee nonces remain reserved while unsent suffixes are released', () => {
    const initial = { base: 0n, bitmap: 0n };
    const plan = planCommitteeTransactions(
        [
            { peer: PEER_A, address: null },
            { peer: PEER_B, address: '192.0.2.2:9000' },
            { peer: PEER_C, address: null },
        ],
        initial,
        2,
    );
    const retained = plan.transactions.slice(0, 2).reduce(
        (state, transaction) => reserveAttemptedCommitteeNonce(state, transaction.nonce),
        initial,
    );

    assert.deepEqual(retained, { base: 2n, bitmap: 0n });
    assert.deepEqual(plan.nextNonceState, { base: 3n, bitmap: 0n });
});

test('planning does not depend on the indexed target epoch', () => {
    const first = committeeSnapshot([PEER_A], [PEER_A, PEER_B]);
    const second = { ...first, targetEpoch: first.targetEpoch + 1n };
    const selected = new Set([PEER_B]);
    const plan = (snapshot: CommitteeSnapshot) =>
        planCommitteeTransactions(
            committeeChanges(snapshot, selected),
            { base: 10n, bitmap: 0n },
            snapshot.scheduled.length,
        );

    assert.deepEqual(plan(first), plan(second));
});

test('finalized height determines the actual mutable target epoch', () => {
    assert.equal(committeeTargetEpochAtHeight(0n), 2n);
    assert.equal(committeeTargetEpochAtHeight(63n), 2n);
    assert.equal(committeeTargetEpochAtHeight(64n), 3n);
    assert.equal(committeeTargetEpochAtHeight(127n), 3n);
    assert.equal(committeeTargetEpochAtHeight(128n), 4n);
    assert.throws(() => committeeTargetEpochAtHeight(-1n), /height must fit in u64/);
});

test('finalized overlay applies new peers and removals to stale indexed state', () => {
    const snapshot = committeeSnapshot([PEER_A, PEER_C], [PEER_A, PEER_C]);
    const overlay = createFinalizedCommitteeOverlay(
        [
            { peer: PEER_A, address: null },
            { peer: PEER_B, address: '[2001:db8::2]:9000' },
        ],
        64n,
        DIGEST_A,
    );

    const applied = applyFinalizedCommitteeOverlay(snapshot, overlay);

    assert.equal(applied.targetEpoch, 3n);
    assert.deepEqual(applied.scheduled, [PEER_C, PEER_B]);
    assert.deepEqual(applied.available, [
        ...snapshot.available,
        { peer: PEER_B, address: '[2001:db8::2]:9000' },
    ]);
});

test('finalized overlay remains until its transaction row is indexed', () => {
    const overlay = createFinalizedCommitteeOverlay(
        [
            { peer: PEER_A, address: null },
            { peer: PEER_B, address: '192.0.2.2:9000' },
        ],
        100n,
        DIGEST_A,
    );
    const pending = new Set<string>();
    const indexed = new Set([DIGEST_A]);

    assert.equal(indexedCommitteeOverlayAdopted(overlay, pending), false);
    assert.equal(indexedCommitteeOverlayAdopted(overlay, indexed), true);
    assert.strictEqual(
        reconcileFinalizedCommitteeOverlay(overlay, pending),
        overlay,
    );
    assert.equal(reconcileFinalizedCommitteeOverlay(overlay, indexed), null);
});

test('newer finalized feedback supersedes an older change for the same peer', () => {
    const first = createFinalizedCommitteeOverlay(
        [{ peer: PEER_B, address: '192.0.2.2:9000' }],
        61n,
        DIGEST_A,
    );
    const second = createFinalizedCommitteeOverlay(
        [{ peer: PEER_B, address: null }],
        64n,
        DIGEST_B,
    );

    assert.deepEqual(mergeFinalizedCommitteeOverlay([first], second), [second]);
});

test('per-transaction overlays preserve epochs across a submission boundary', () => {
    const beforeBoundary = createFinalizedCommitteeOverlay(
        [{ peer: PEER_B, address: '192.0.2.2:9000' }],
        61n,
        DIGEST_A,
    );
    const afterBoundary = createFinalizedCommitteeOverlay(
        [{ peer: PEER_A, address: null }],
        64n,
        DIGEST_B,
    );

    assert.equal(beforeBoundary.targetEpoch, 2n);
    assert.equal(afterBoundary.targetEpoch, 3n);
    const initial: CommitteeSnapshot = committeeSnapshot([PEER_A], [PEER_A]);
    assert.deepEqual(
        [beforeBoundary, afterBoundary].reduce<CommitteeSnapshot>(
            (snapshot, overlay) => applyFinalizedCommitteeOverlay(snapshot, overlay),
            initial,
        ).scheduled,
        [PEER_B],
    );
});

test('indexed committee transaction lookup returns only visible digests', async () => {
    const indexed = await fetchIndexedCommitteeTransactions(
        'http://indexer.invalid',
        [DIGEST_A, DIGEST_B],
        undefined,
        {
            async query(sql: string): Promise<DecodedQueryResult> {
                assert.match(sql, /FROM tx_meta/);
                assert.match(sql, new RegExp(`X'${DIGEST_A}'`));
                assert.match(sql, new RegExp(`X'${DIGEST_B}'`));
                return result({ tx_digest: peerBytes(DIGEST_B) });
            },
        },
    );

    assert.deepEqual(indexed, new Set([DIGEST_B]));
});

test('sole-member replacement adds before removing the last member', () => {
    const snapshot = committeeSnapshot([PEER_A], [PEER_A, PEER_B]);
    const expected = [
        { peer: PEER_B, address: '192.0.2.2:9000' },
        { peer: PEER_A, address: null },
    ];

    assert.deepEqual(committeeChanges(snapshot, new Set([PEER_B])), expected);

    const plan = planCommitteeTransactions(
        [...expected].reverse(),
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
        { peer: peers[0], address: null },
        { peer: peers[64], address: '192.0.2.65:9000' },
    ];

    assert.deepEqual(committeeChanges(snapshot, selected), expected);

    const plan = planCommitteeTransactions(
        [...expected].reverse(),
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
        { peer: peers[63], address: '192.0.2.64:9000' },
        { peer: peers[0], address: null },
        { peer: peers[64], address: '192.0.2.65:9000' },
        { peer: peers[1], address: null },
    ];

    const first = committeeChanges(snapshot, selected);
    const second = committeeChanges(snapshot, selected);
    assert.deepEqual(first, expected);
    assert.deepEqual(second, expected);
    assert.deepEqual(intermediateCommitteeSizes(first, 63), [64, 63, 64, 63]);
});

function response(): CommitteeSnapshot {
    return {
        height: 8_930n,
        epoch: 139n,
        targetEpoch: 141n,
        updatesOpen: true,
        lockHeight: 8_958n,
        current: [PEER_A, PEER_C],
        next: [PEER_A, PEER_C],
        scheduled: [PEER_A, PEER_C],
        available: [
            { peer: PEER_A, address: '192.0.2.1:9000' },
            { peer: PEER_B, address: '192.0.2.2:9000' },
            { peer: PEER_C, address: '[2001:db8::3]:9000' },
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
                return result({ peer: peerBytes(PEER_A), address: '192.0.2.1:9000' });
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
            address: `192.0.2.${index + 1}:9000`,
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
    address,
}: {
    readonly peer: string;
    readonly address: string | null;
}) {
    return { peer: changedPeer, address };
}

function intermediateCommitteeSizes(
    changes: readonly { readonly address: string | null }[],
    initialSize: number,
): number[] {
    let size = initialSize;
    return changes.map(({ address }) => {
        size += address === null ? -1 : 1;
        assert.ok(size >= 1 && size <= 64);
        return size;
    });
}
