/** Time constant in milliseconds of the smoothed block arrival rate. */
const ARRIVAL_WINDOW_MS = 3_000;

/** Time over which waiting blocks are released when they outnumber what the arrival rate clears. */
const CATCH_UP_MS = 1_000;

/** Most blocks held back at once. A larger backlog shows its oldest blocks immediately. */
const MAX_WAITING = 128;

/**
 * How the homepage releases observed blocks. Batches carry many blocks at once, and showing a
 * whole batch in one step replaces every visible row. Blocks are instead released one at a time at
 * the rate they have been arriving.
 */
export interface FeedPace {
    /** Blocks shown as of `at`. */
    readonly shown: number;
    /** Blocks released per millisecond after `at`. */
    readonly rate: number;
    /** Smoothed arrival rate in blocks per millisecond. */
    readonly arrival: number;
    /** When the newest batch arrived, or null before the first. */
    readonly at: number | null;
}

export const EMPTY_PACE: FeedPace = { shown: 0, rate: 0, arrival: 0, at: null };

/** How many of the `observed` blocks are shown at `now`. */
export function shownBlocks(pace: FeedPace, observed: number, now: number): number {
    if (pace.at === null) return observed;
    const elapsed = Math.max(0, now - pace.at);
    return Math.min(observed, pace.shown + Math.floor(elapsed * pace.rate));
}

/** Schedules a batch of `count` blocks that arrived at `now`, after `observed` earlier blocks. */
export function paceBatch(pace: FeedPace, observed: number, count: number, now: number): FeedPace {
    const total = observed + count;

    // The first batch is history the indexer already held, so it says nothing about the rate.
    if (pace.at === null) return { shown: total, rate: 0, arrival: 0, at: now };

    const elapsed = Math.max(0, now - pace.at);
    const arrival = pace.arrival * Math.exp(-elapsed / ARRIVAL_WINDOW_MS) + count / ARRIVAL_WINDOW_MS;

    // A block that arrives with nothing waiting is shown at once, so a slow chain is never delayed.
    const before = shownBlocks(pace, observed, now);
    const shown = Math.max(before === observed ? observed + 1 : before, total - MAX_WAITING);

    // The arrival rate keeps steady batches flowing evenly. The floor clears a backlog when blocks
    // arrive faster than they have been.
    return { shown, arrival, rate: Math.max(arrival, (total - shown) / CATCH_UP_MS), at: now };
}
