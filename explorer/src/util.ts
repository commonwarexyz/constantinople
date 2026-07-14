// Small shared helpers with no wire-format knowledge (those live in
// codec.ts, which the fixture suite treats as the TS mirror of the Rust
// codec).

/// Abbreviates a hex value for display.
export function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}…${value.slice(-8)}`;
}

/// The human-readable message of any thrown value.
export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/// Resolves after `ms`, or rejects when `signal` aborts.
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        if (signal?.aborted) {
            reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
            return;
        }
        const onAbort = () => {
            clearTimeout(timeout);
            signal?.removeEventListener('abort', onAbort);
            reject(signal?.reason ?? new DOMException('aborted', 'AbortError'));
        };
        const timeout = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort);
            resolve();
        }, ms);
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();
    });
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
