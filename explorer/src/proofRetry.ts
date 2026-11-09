import { Code, ConnectError } from '@connectrpc/connect';

// Fetch and response-body failures have different messages across runtimes.
// Older Safari reports the underlying system error description.
const NETWORK_FAILURE_MESSAGE =
    /^(?:failed to fetch|fetch failed|load failed|network error|terminated|error in (?:body|input) stream|networkerror when attempting to fetch resource\.?|the internet connection appears to be offline\.|the network connection was lost\.)$/i;

// Bounds the walk so a cyclic cause chain cannot hang classification.
const MAX_CAUSE_DEPTH = 8;

export const NETWORK_RECONNECT_DELAY_MS = 5_000;

const ACCOUNT_RETRY_INITIAL_DELAY_MS = 350;
const ACCOUNT_RETRY_DELAY_STEP_MS = 150;
const ACCOUNT_RETRY_MAX_DELAY_MS = 2_000;

type RetryWait = (delayMs: number, signal: AbortSignal) => Promise<boolean>;

export interface RetryOptions {
    readonly wait?: RetryWait;
    readonly onRetry?: (error: unknown) => void;
}

export type AccountRetryReason = 'retrying after service error';

export function isRetryableProofError(error: unknown): boolean {
    return accountRetryReason(error) !== undefined;
}

export function isRetryableAccountProofError(error: unknown): boolean {
    return accountRetryReason(error) !== undefined;
}

// Unavailable covers both publication lag and service outages. Transport
// deadlines and locally recognized connection failures can also clear on retry.
export function accountRetryReason(error: unknown): AccountRetryReason | undefined {
    const connect = connectError(error);
    if (connect?.code === Code.Unavailable || connect?.code === Code.DeadlineExceeded || isTransportFailure(connect)) {
        return 'retrying after service error';
    }
    return undefined;
}

// Connect retains the local cause of fetch failures and streams missing their
// end marker. A truncated envelope has a distinct local InvalidArgument error.
function isTransportFailure(connect: ConnectError | undefined): boolean {
    return (
        (connect?.code === Code.InvalidArgument && connect.rawMessage === 'protocol error: incomplete envelope') ||
        (connect?.code === Code.Unknown &&
            (connect.cause === 'missing EndStreamResponse' ||
                (connect.cause instanceof TypeError && NETWORK_FAILURE_MESSAGE.test(connect.cause.message))))
    );
}

export async function retryAccountWork<T>(
    run: () => Promise<T>,
    signal: AbortSignal,
    isRetryable: (error: unknown) => boolean,
    { wait = waitForRetry, onRetry }: RetryOptions = {},
): Promise<T> {
    let failures = 0;
    while (true) {
        throwIfCancelled(signal);
        try {
            const result = await run();
            throwIfCancelled(signal);
            return result;
        } catch (error) {
            throwIfCancelled(signal);
            if (!isRetryable(error)) {
                throw error;
            }
            onRetry?.(error);
            if (!(await wait(retryDelay(failures), signal))) throw cancelledError();
            failures += 1;
        }
    }
}

export function waitForRetry(ms: number, signal?: AbortSignal): Promise<boolean> {
    if (signal?.aborted) return Promise.resolve(false);

    return new Promise((resolve) => {
        const finish = (completed: boolean) => {
            clearTimeout(timeout);
            signal?.removeEventListener('abort', onAbort);
            resolve(completed);
        };
        const onAbort = () => finish(false);
        const timeout = setTimeout(() => finish(true), ms);
        signal?.addEventListener('abort', onAbort, { once: true });
    });
}

export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

// Proof failures can acquire context while preserving the original transport cause.
function connectError(error: unknown): ConnectError | undefined {
    let current = error;
    for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
        if (current instanceof ConnectError) return current;
        current = current.cause;
    }
    return undefined;
}

function retryDelay(failures: number): number {
    return Math.min(
        ACCOUNT_RETRY_INITIAL_DELAY_MS + failures * ACCOUNT_RETRY_DELAY_STEP_MS,
        ACCOUNT_RETRY_MAX_DELAY_MS,
    );
}

function throwIfCancelled(signal: AbortSignal): void {
    if (signal.aborted) {
        throw cancelledError();
    }
}

function cancelledError(): Error {
    return new Error('account lookup cancelled');
}
