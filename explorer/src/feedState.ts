import type { VerifiedBlock, VerifiedBlockBatch } from './indexer.ts';
import { EMPTY_PACE, paceBatch, shownBlocks, type FeedPace } from './feedPace.ts';

export interface FeedState {
    readonly blocks: VerifiedBlock[];
    readonly totalTxObserved: number;
    readonly totalBlocksObserved: number;
    readonly observedRateWindow: {
        readonly firstBlockAt: number | null;
        readonly latestBlockAt: number | null;
    };
    readonly publishedProofTarget: VerifiedBlockBatch['target'] | null;
    readonly pace: FeedPace;
}

export const EMPTY_FEED: FeedState = {
    blocks: [],
    totalTxObserved: 0,
    totalBlocksObserved: 0,
    observedRateWindow: { firstBlockAt: null, latestBlockAt: null },
    publishedProofTarget: null,
    pace: EMPTY_PACE,
};

// The verifier emits only new ascending heights. Publish all derived UI state together.
export function appendVerifiedBatch(current: FeedState, batch: VerifiedBlockBatch): FeedState {
    if (batch.blocks.length === 0) return current;
    return {
        blocks: [...batch.blocks].reverse().concat(current.blocks).slice(0, 360),
        totalTxObserved: current.totalTxObserved + batch.blocks.reduce((sum, block) => sum + block.txCount, 0),
        totalBlocksObserved: current.totalBlocksObserved + batch.blocks.length,
        observedRateWindow: {
            firstBlockAt: current.observedRateWindow.firstBlockAt ?? batch.receivedAt,
            latestBlockAt: batch.receivedAt,
        },
        publishedProofTarget: batch.target,
        pace: paceBatch(current.pace, current.totalBlocksObserved, batch.blocks.length, batch.receivedAt),
    };
}

/** The blocks and totals the homepage shows while its newest blocks are still being released. */
export interface ShownFeed {
    readonly blocks: VerifiedBlock[];
    readonly totalTxObserved: number;
    readonly totalBlocksObserved: number;
}

/** How many observed blocks the homepage shows at `now`. */
export function shownCount(current: FeedState, now: number): number {
    return shownBlocks(current.pace, current.totalBlocksObserved, now);
}

/** The feed with all but its first `shown` observed blocks held back from its rows and totals. */
export function shownFeed(current: FeedState, shown: number): ShownFeed {
    const waiting = current.blocks.slice(0, current.totalBlocksObserved - shown);
    return {
        blocks: current.blocks.slice(waiting.length),
        totalTxObserved: current.totalTxObserved - waiting.reduce((sum, block) => sum + block.txCount, 0),
        totalBlocksObserved: shown,
    };
}
