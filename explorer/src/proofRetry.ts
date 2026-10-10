import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError } from '@connectrpc/connect';
import { HttpError } from '@exowarexyz/sdk';

const ERROR_INFO_TYPE = 'google.rpc.ErrorInfo';
const CONSISTENCY_NOT_READY = 'CONSISTENCY_NOT_READY';
const SERIALIZED_CONSISTENCY_NOT_READY =
    /^(?:HTTP error: 409 )?\[aborted\] minimum consistency token is not yet visible\b/i;
const RETRYABLE_PROOF_ERROR =
    /tx_meta missing|tx digest .* (missing at height|is not finalized yet)|finalization missing|QMDB transaction proof response missing|not yet covered by a provable finalization|out_of_range|unavailable/i;
const RETRYABLE_FETCH_ERROR =
    /(?:^|:\s)(?:failed to fetch|fetch failed|load failed|networkerror when attempting to fetch resource\.?)$/i;

const RETRYABLE_ACCOUNT_PROOF_ERRORS = [
    /\[unavailable\]/i,
    RETRYABLE_FETCH_ERROR,
    /^finalization missing at height \d+$/,
    /^tx digest .+ missing from raw transaction index$/,
    /^account location \d+ is outside finalized state range$/,
    /^transaction location \d+ is not yet covered by a provable finalization$/,
    /^\[out_of_range\] requested proof tip is not published yet$/,
    /^\[out_of_range\] requested location \d+ is above published writer watermark \d+$/,
];

export const NETWORK_RECONNECT_DELAY_MS = 5_000;

const ACCOUNT_RETRY_INITIAL_DELAY_MS = 350;
const ACCOUNT_RETRY_DELAY_STEP_MS = 150;
const ACCOUNT_RETRY_MAX_DELAY_MS = 2_000;

type RetryWait = (delayMs: number, signal: AbortSignal) => Promise<boolean>;

export interface ErrorInfo {
    readonly reason: string;
    readonly domain: string;
}

export function isRetryableProofError(error: unknown): boolean {
    const detail = errorMessage(error);
    return (
        isConsistencyNotReadyError(error) ||
        RETRYABLE_PROOF_ERROR.test(detail) ||
        RETRYABLE_FETCH_ERROR.test(detail)
    );
}

export function isMissingAccountProofError(detail: string): boolean {
    return /^account .+ is not indexed$/.test(detail);
}

export function isRetryableAccountProofError(error: unknown): boolean {
    const detail = errorMessage(error);
    return (
        isConsistencyNotReadyError(error) ||
        RETRYABLE_ACCOUNT_PROOF_ERRORS.some((pattern) => pattern.test(detail))
    );
}

// Proof errors can be rethrown with added context, so the serialized server
// message is accepted alongside the structured reason.
export function isConsistencyNotReadyError(error: unknown): boolean {
    return (
        errorInfos(error, Code.Aborted).some(({ reason }) => reason === CONSISTENCY_NOT_READY) ||
        SERIALIZED_CONSISTENCY_NOT_READY.test(errorMessage(error))
    );
}

export function errorInfos(error: unknown, code: Code): ErrorInfo[] {
    const cause = error instanceof HttpError ? error.cause : error;
    if (!(cause instanceof ConnectError) || cause.code !== code) return [];

    return cause.details.flatMap((detail) => {
        if (!('type' in detail) || detail.type !== ERROR_INFO_TYPE) return [];
        try {
            return [decodeErrorInfo(detail.value)];
        } catch {
            return [];
        }
    });
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

function decodeErrorInfo(value: Uint8Array): ErrorInfo {
    const reader = new BinaryReader(value);
    let reason = '';
    let domain = '';

    while (reader.pos < reader.len) {
        const [fieldNumber, wireType] = reader.tag();
        if (wireType === WireType.LengthDelimited && fieldNumber === 1) {
            reason = reader.string();
        } else if (wireType === WireType.LengthDelimited && fieldNumber === 2) {
            domain = reader.string();
        } else {
            reader.skip(wireType, fieldNumber);
        }
    }
    return { reason, domain };
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
