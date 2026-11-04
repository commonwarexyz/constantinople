import assert from 'node:assert/strict';
import test from 'node:test';
import { blockRecency, startRecencyClock } from '../src/blockRecency.ts';

test('an unknown head stays neutral regardless of the local clock', () => {
    assert.deepEqual(blockRecency(null, 0), { kind: 'unknown', text: 'unknown' });
    assert.deepEqual(blockRecency(null, 1_000_000), blockRecency(null, 0));
});

test('the local stale policy starts strictly after sixty seconds', () => {
    assert.equal(blockRecency(1_000n, 60_999).kind, 'recent');
    assert.deepEqual(blockRecency(1_000n, 61_000), { kind: 'recent', text: '1m ago' });
    assert.deepEqual(blockRecency(1_000n, 61_001), { kind: 'stale', text: '1m ago' });
});

test('clock mismatch starts strictly beyond five seconds ahead', () => {
    assert.deepEqual(blockRecency(6_000n, 1_000), { kind: 'recent', text: '5s ahead' });
    assert.deepEqual(blockRecency(6_001n, 1_000), { kind: 'ahead', text: '5s ahead' });
    assert.equal(blockRecency(5_999n, 1_000).kind, 'recent');
});

test('new delivery and progress through old backlog cannot reset timestamp age', () => {
    const deliveredAt = 100_000;
    assert.equal(blockRecency(10_000n, deliveredAt).kind, 'stale');
    assert.equal(blockRecency(20_000n, deliveredAt + 1_000).kind, 'stale');
    assert.equal(blockRecency(30_000n, deliveredAt + 2_000).kind, 'stale');
});

test('equal valid block timestamps keep aging while a newer timestamp recovers', () => {
    assert.equal(blockRecency(10_000n, 69_000).kind, 'recent');
    assert.equal(blockRecency(10_000n, 71_000).kind, 'stale');
    assert.equal(blockRecency(71_000n, 71_000).kind, 'recent');
    assert.equal(blockRecency(71_000n, 132_000).kind, 'stale');
});

test('age formatting stays compact for long stalls and protocol-bound timestamps', () => {
    assert.equal(blockRecency(0n, 120_000).text, '2m ago');
    assert.equal(blockRecency(0n, 7_200_000).text, '2h ago');
    assert.equal(blockRecency(0n, 172_800_000).text, '2d ago');
    assert.equal(blockRecency(7_258_118_400_000n, 0).kind, 'ahead');
});

test('clock ticks age a stalled head, recover after progress, and stop on disposal', (context) => {
    context.mock.timers.enable({ apis: ['Date', 'setInterval'], now: 10_000 });
    let timestamp = 10_000n;
    const states: string[] = [];
    const dispose = startRecencyClock(() => states.push(blockRecency(timestamp, Date.now()).kind));
    context.mock.timers.tick(60_000);
    assert.equal(states.length, 60);
    assert.equal(states.at(-1), 'recent');
    context.mock.timers.tick(1_000);
    assert.equal(states.at(-1), 'stale');
    timestamp = BigInt(Date.now());
    context.mock.timers.tick(1_000);
    assert.equal(states.at(-1), 'recent');
    dispose();
    const count = states.length;
    context.mock.timers.tick(60_000);
    assert.equal(states.length, count);
});
