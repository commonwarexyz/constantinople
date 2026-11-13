import assert from 'node:assert/strict';
import test from 'node:test';
import { EMPTY_PACE, paceBatch, shownBlocks, type FeedPace } from '../src/feedPace.ts';

/** Feeds batches of [arrival time, block count] and returns the pace with the blocks observed. */
function feed(batches: readonly (readonly [number, number])[], pace: FeedPace = EMPTY_PACE, observed = 0) {
    for (const [at, count] of batches) {
        pace = paceBatch(pace, observed, count, at);
        observed += count;
    }
    return { pace, observed };
}

test('the first batch is shown whole and an empty feed holds nothing back', () => {
    assert.equal(shownBlocks(EMPTY_PACE, 0, 5_000), 0);
    const { pace, observed } = feed([[1_000, 64]]);
    assert.equal(shownBlocks(pace, observed, 1_000), 64);
});

test('a block that arrives with nothing waiting is shown at once', () => {
    const { pace, observed } = feed([[0, 10], [2_000, 1], [4_000, 1]]);
    assert.equal(shownBlocks(pace, observed, 4_000), 12);
});

test('a batch is released one block at a time and completely within a second', () => {
    const { pace, observed } = feed([[0, 10], [5_000, 50]]);
    assert.equal(shownBlocks(pace, observed, 5_000), 11);
    let previous = 11;
    for (let now = 5_000; now <= 6_000; now += 10) {
        const shown = shownBlocks(pace, observed, now);
        assert.ok(shown >= previous && shown - previous <= 1, `${previous} to ${shown} at ${now}`);
        previous = shown;
    }
    assert.equal(previous, observed);
});

test('steady batches are released evenly at their arrival rate', () => {
    // Twenty-four blocks every half second is the batch shape of a chain making 48 blocks a second.
    const warm = feed(Array.from({ length: 40 }, (_, index) => [index * 500, 24] as const));
    let { pace, observed } = warm;
    const released: number[] = [];
    for (let batch = 40; batch < 60; batch++) {
        const at = batch * 500;
        const before = shownBlocks(pace, observed, at);
        ({ pace, observed } = feed([[at, 24]], pace, observed));
        for (let step = 1; step <= 5; step++) {
            released.push(shownBlocks(pace, observed, at + step * 100) - (step === 1 ? before : shownBlocks(pace, observed, at + (step - 1) * 100)));
        }
        assert.ok(observed - shownBlocks(pace, observed, at + 500) <= 2, 'a batch is nearly released before the next arrives');
    }
    // An even release shows 4.8 blocks in each tenth of a second.
    assert.ok(Math.min(...released) >= 3 && Math.max(...released) <= 7, released.join(' '));
});

test('a backlog beyond the bound shows its oldest blocks immediately', () => {
    const { pace, observed } = feed([[0, 10], [1_000, 500]]);
    assert.equal(shownBlocks(pace, observed, 1_000), 510 - 128);
    assert.equal(shownBlocks(pace, observed, 2_000), 510);
});

test('time before the newest batch never hides a block already shown', () => {
    const { pace, observed } = feed([[0, 10], [1_000, 20]]);
    assert.equal(shownBlocks(pace, observed, 500), shownBlocks(pace, observed, 1_000));
});
