const STALE_AFTER_MS = 60_000n;
const MAX_CLOCK_LEAD_MS = 5_000n;

export interface BlockRecency {
    readonly kind: 'unknown' | 'recent' | 'stale' | 'ahead';
    readonly text: string;
}

/** Compares an authenticated block timestamp with the browser's local clock. */
export function blockRecency(timestampMs: bigint | null, nowMs: number): BlockRecency {
    if (timestampMs === null) return { kind: 'unknown', text: 'unknown' };
    const age = BigInt(Math.trunc(nowMs)) - timestampMs;
    if (age < -MAX_CLOCK_LEAD_MS) {
        return { kind: 'ahead', text: `${duration(-age)} ahead` };
    }
    if (age > STALE_AFTER_MS) return { kind: 'stale', text: `${duration(age)} ago` };
    return { kind: 'recent', text: age < 0n ? `${duration(-age)} ahead` : `${duration(age)} ago` };
}

function duration(milliseconds: bigint): string {
    const seconds = milliseconds / 1_000n;
    if (seconds < 60n) return `${seconds}s`;
    if (seconds < 3_600n) return `${seconds / 60n}m`;
    if (seconds < 86_400n) return `${seconds / 3_600n}h`;
    return `${seconds / 86_400n}d`;
}

/** Owns the clock updates independently of incoming block messages. */
export function startRecencyClock(refresh: () => void): () => void {
    const interval = setInterval(refresh, 1_000);
    return () => clearInterval(interval);
}
