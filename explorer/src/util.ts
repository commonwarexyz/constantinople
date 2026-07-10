// Small shared helpers with no wire-format knowledge (those live in
// codec.ts, which the fixture suite treats as the TS mirror of the Rust
// codec).

/// Abbreviates a hex value for display.
export function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

/// Resolves after `ms` — the explorer's shared retry/backoff sleep.
export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

export function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

/// Reads and validates a JSON value persisted in localStorage; any failure
/// (missing key, parse error, shape mismatch) is null.
export function readStoredJson<T>(key: string, isValid: (value: unknown) => value is T): T | null {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    try {
        const parsed: unknown = JSON.parse(raw);
        return isValid(parsed) ? parsed : null;
    } catch {
        return null;
    }
}
