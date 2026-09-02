import { Code, ConnectError } from '@connectrpc/connect';
import { HttpError } from '@exowarexyz/sdk';

const ERROR_INFO_TYPE = 'google.rpc.ErrorInfo';
const CONSISTENCY_NOT_READY = 'CONSISTENCY_NOT_READY';
const CONSISTENCY_NOT_READY_BYTES = new TextEncoder().encode(CONSISTENCY_NOT_READY);
const CONSISTENCY_NOT_READY_FIELD = new Uint8Array([
    0x0a,
    CONSISTENCY_NOT_READY_BYTES.length,
    ...CONSISTENCY_NOT_READY_BYTES,
]);
const SERIALIZED_CONSISTENCY_NOT_READY =
    /^(?:HTTP error: 409 )?\[aborted\] (?:consistency_not_ready\b|minimum consistency token is not yet visible\b)/i;
const RETRYABLE_PROOF_ERROR =
    /tx_meta missing|tx digest .* (missing at height|is not finalized yet)|finalization missing|QMDB transaction proof response missing|out_of_range|unavailable|fetch/i;

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

export function isRetryableProofError(error: unknown): boolean {
    return isConsistencyNotReadyError(error) || RETRYABLE_PROOF_ERROR.test(errorDetail(error));
}

export function isMissingAccountProofError(detail: string): boolean {
    return /^account .+ is not indexed$/.test(detail);
}

export function isRetryableSequenceConsistencyError(error: unknown): boolean {
    return isConsistencyNotReadyError(error);
}

export function isRetryableAccountProofError(error: unknown): boolean {
    const detail = errorDetail(error);
    return (
        isConsistencyNotReadyError(error) ||
        RETRYABLE_ACCOUNT_PROOF_ERRORS.some((pattern) => pattern.test(detail))
    );
}

export async function retryAccountWork<T>(
    run: () => Promise<T>,
    signal: AbortSignal,
    isRetryable: (error: unknown) => boolean,
    wait: RetryWait = waitForRetry,
): Promise<T> {
    let failures = 0;
    while (true) {
        throwIfCancelled(signal);
        try {
            return await run();
        } catch (error) {
            throwIfCancelled(signal);
            if (!isRetryable(error)) {
                throw error;
            }
            await wait(retryDelay(failures), signal);
            failures += 1;
        }
    }
}

function isConsistencyNotReadyError(error: unknown): boolean {
    const connectError = asConnectError(error);
    if (connectError) {
        return (
            connectError.code === Code.Aborted &&
            (connectError.rawMessage.toUpperCase().includes(CONSISTENCY_NOT_READY) ||
                connectError.details.some(isConsistencyNotReadyDetail))
        );
    }
    return SERIALIZED_CONSISTENCY_NOT_READY.test(errorDetail(error));
}

function asConnectError(error: unknown): ConnectError | undefined {
    if (error instanceof ConnectError) return error;
    if (
        error instanceof HttpError &&
        error.connectCode === Code.Aborted &&
        error.cause instanceof ConnectError
    ) {
        return error.cause;
    }
    return undefined;
}

function isConsistencyNotReadyDetail(detail: unknown): boolean {
    if (!isRecord(detail)) return false;

    const descriptor = detail.desc;
    const value = detail.value;
    if (isRecord(descriptor) && descriptor.typeName === ERROR_INFO_TYPE && isRecord(value)) {
        return isConsistencyNotReadyReason(value.reason);
    }

    if (detail.type !== ERROR_INFO_TYPE) return false;
    if (isRecord(detail.debug) && isConsistencyNotReadyReason(detail.debug.reason)) return true;
    return value instanceof Uint8Array && containsBytes(value, CONSISTENCY_NOT_READY_FIELD);
}

function isConsistencyNotReadyReason(reason: unknown): boolean {
    return typeof reason === 'string' && reason.toUpperCase() === CONSISTENCY_NOT_READY;
}

function containsBytes(bytes: Uint8Array, expected: Uint8Array): boolean {
    for (let start = 0; start <= bytes.length - expected.length; start++) {
        if (expected.every((byte, offset) => bytes[start + offset] === byte)) return true;
    }
    return false;
}

function errorDetail(error: unknown): string {
    if (typeof error === 'string') return error;
    return error instanceof Error ? error.message : String(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
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
