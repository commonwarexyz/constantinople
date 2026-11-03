import type { VerifiedBlock, VerifiedBlockBatch } from './indexer.ts';

export interface FeedState {
    readonly blocks: VerifiedBlock[];
    readonly totalTxObserved: number;
    readonly totalBlocksObserved: number;
    readonly observedRateWindow: {
        readonly firstBlockAt: number | null;
        readonly latestBlockAt: number | null;
    };
    readonly publishedProofTarget: VerifiedBlockBatch['target'] | null;
}

export const EMPTY_FEED: FeedState = {
    blocks: [],
    totalTxObserved: 0,
    totalBlocksObserved: 0,
    observedRateWindow: { firstBlockAt: null, latestBlockAt: null },
    publishedProofTarget: null,
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
    };
}
