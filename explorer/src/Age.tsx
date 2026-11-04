import { memo, useEffect, useReducer } from 'react';
import { blockRecency, startRecencyClock } from './blockRecency';

/**
 * How far an authenticated timestamp sits from the browser clock. The judgement colors only this
 * text: a stale or mismatched clock never changes the styling of the proof it accompanies.
 */
export const Age = memo(function Age({ timestampMs }: { timestampMs: bigint | null }) {
    const [, refresh] = useReducer((tick: number) => tick + 1, 0);
    const hasHead = timestampMs !== null;
    useEffect(() => {
        if (!hasHead) return;
        return startRecencyClock(refresh);
    }, [hasHead]);
    const recency = blockRecency(timestampMs, Date.now());
    return <span className={`age age--${recency.kind}`}>{recency.text}</span>;
});
