const RETRYABLE_PROOF_ERROR =
    /tx_meta missing|tx digest .* (missing at height|is not finalized yet)|finalization missing|QMDB transaction proof response missing|out_of_range|unavailable|aborted|consistency_not_ready|fetch/i;

const RETRYABLE_ACCOUNT_PROOF_ERRORS = [
    /consistency_not_ready/,
    /\[unavailable\]/i,
    /(?:^|:\s)(?:failed to fetch|fetch failed|load failed|networkerror when attempting to fetch resource\.?)$/i,
    /^finalization missing at height \d+$/,
    /^tx digest .+ missing from raw transaction index$/,
    /^account location \d+ is outside finalized state range$/,
    /^transaction location \d+ is not yet covered by a provable finalization$/,
    /^\[out_of_range\] requested proof tip is not published yet$/,
    /^\[out_of_range\] requested location \d+ is above published writer watermark \d+$/,
];

const ACCOUNT_RETRY_INITIAL_DELAY_MS = 350;
const ACCOUNT_RETRY_DELAY_STEP_MS = 150;
const ACCOUNT_RETRY_MAX_DELAY_MS = 2_000;

type RetryWait = (delayMs: number, signal: AbortSignal) => Promise<void>;

export function isRetryableProofError(detail: string): boolean {
    return RETRYABLE_PROOF_ERROR.test(detail);
}

export function isMissingAccountProofError(detail: string): boolean {
    return /^account .+ is not indexed$/.test(detail);
}

export function isRetryableSequenceConsistencyError(detail: string): boolean {
    return detail.includes('consistency_not_ready');
}

export function isRetryableAccountProofError(detail: string): boolean {
    return RETRYABLE_ACCOUNT_PROOF_ERRORS.some((pattern) => pattern.test(detail));
}

export async function retryAccountWork<T>(
    run: () => Promise<T>,
    signal: AbortSignal,
    isRetryable: (detail: string) => boolean,
    wait: RetryWait = waitForRetry,
): Promise<T> {
    let failures = 0;
    while (true) {
        throwIfCancelled(signal);
        try {
            return await run();
        } catch (error) {
            throwIfCancelled(signal);
            const detail = error instanceof Error ? error.message : String(error);
            if (!isRetryable(detail)) {
                throw error;
            }
            await wait(retryDelay(failures), signal);
            failures += 1;
        }
    }
}

function retryDelay(failures: number): number {
    return Math.min(
        ACCOUNT_RETRY_INITIAL_DELAY_MS + failures * ACCOUNT_RETRY_DELAY_STEP_MS,
        ACCOUNT_RETRY_MAX_DELAY_MS,
    );
}

function waitForRetry(delayMs: number, signal: AbortSignal): Promise<void> {
    throwIfCancelled(signal);
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            signal.removeEventListener('abort', onAbort);
            resolve();
        }, delayMs);
        const onAbort = () => {
            clearTimeout(timeout);
            reject(cancelledError());
        };
        signal.addEventListener('abort', onAbort, { once: true });
    });
}

function throwIfCancelled(signal: AbortSignal): void {
    if (signal.aborted) {
        throw cancelledError();
    }
}

function cancelledError(): Error {
    return new Error('account lookup cancelled');
}
