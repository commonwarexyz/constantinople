import assert from 'node:assert/strict';
import test from 'node:test';
import {
    activeReconciliations,
    wakeCoveredReconciliations,
    type TransactionReconciliation,
} from '../src/reconciliationQueue.ts';

function entry(timer: number | null, waitingForHeight: bigint | null): TransactionReconciliation {
    return { controller: new AbortController(), timer, waitingForHeight };
}

test('backoff releases slots without making waiting transactions eligible again', () => {
    const reconciliations = new Map([
        ['active', entry(null, null)],
        ['coverage', entry(1, 42n)],
        ['aged', entry(2, null)],
    ]);

    assert.equal(activeReconciliations(reconciliations), 1);
    assert.equal(reconciliations.has('coverage'), true);
    assert.equal(reconciliations.has('aged'), true);
});

test('a covering target removes only target-fixable waits before rescheduling them', () => {
    const reconciliations = new Map([
        ['active', entry(null, null)],
        ['covered', entry(1, 42n)],
        ['future', entry(2, 44n)],
        ['aged', entry(3, null)],
    ]);
    const cleared: number[] = [];
    const resumed: string[] = [];
    const wake = (height: bigint) => wakeCoveredReconciliations(
        reconciliations,
        height,
        (timer) => cleared.push(timer),
        (digest) => {
            assert.equal(reconciliations.has(digest), false);
            resumed.push(digest);
        },
    );

    wake(41n);
    assert.deepEqual(resumed, []);
    wake(42n);
    wake(43n);
    assert.deepEqual(cleared, [1]);
    assert.deepEqual(resumed, ['covered']);
    assert.deepEqual([...reconciliations.keys()], ['active', 'future', 'aged']);

    wake(50n);
    assert.deepEqual(cleared, [1, 2]);
    assert.deepEqual(resumed, ['covered', 'future']);
    assert.equal(reconciliations.has('aged'), true);
});

test('a target received during an attempt also wakes its subsequently registered wait', () => {
    const reconciliations = new Map([['racing', entry(null, null)]]);
    const latestHeight = 42n;
    const waiting = reconciliations.get('racing')!;
    waiting.timer = 1;
    waiting.waitingForHeight = 42n;
    let resumed = false;

    wakeCoveredReconciliations(reconciliations, latestHeight, () => {}, () => { resumed = true; });

    assert.equal(resumed, true);
    assert.equal(reconciliations.size, 0);
});
