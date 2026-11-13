/**
 * The one clock format shown anywhere in the explorer: 24-hour local time with milliseconds,
 * for block timestamps and local submission times alike. Values outside the Date range are
 * shown as raw milliseconds.
 */
const CLOCK = new Intl.DateTimeFormat(undefined, {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
});

export function formatClock(timestampMs: bigint | number): string {
    const value = typeof timestampMs === 'bigint' ? timestampMs : BigInt(Math.trunc(timestampMs));
    return value >= 0n && value <= 8_640_000_000_000_000n ? CLOCK.format(Number(value)) : `${value} ms`;
}
