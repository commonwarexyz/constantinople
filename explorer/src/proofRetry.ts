import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError } from '@connectrpc/connect';

const ERROR_INFO_TYPE = 'google.rpc.ErrorInfo';
const CONSISTENCY_NOT_READY = 'CONSISTENCY_NOT_READY';
const SERIALIZED_CONSISTENCY_NOT_READY =
    /^(?:HTTP error: 409 )?\[aborted\] minimum consistency token is not yet visible\b/i;
const ACCOUNT_SERVICE_ERROR = /\[unavailable\]/i;

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

export type AccountRetryReason = 'waiting for indexer' | 'retrying after service error';

export interface ErrorInfo {
    readonly reason: string;
    readonly domain: string;
}

export function isRetryableProofError(error: unknown): boolean {
    return accountRetryReason(error) !== undefined;
}

export function isRetryableAccountProofError(error: unknown): boolean {
    return accountRetryReason(error) !== undefined;
}

// Lagging reads resolve once the indexer catches up, while service errors
// depend on the backend recovering. Anything else is terminal.
export function accountRetryReason(error: unknown): AccountRetryReason | undefined {
    const detail = errorMessage(error);
    if (isConsistencyNotReadyError(error)) {
        return 'waiting for indexer';
    }
    if (isTransportFailure(error) || ACCOUNT_SERVICE_ERROR.test(detail)) {
        return 'retrying after service error';
    }
    return undefined;
}

// Proof errors can be rethrown with added context, so the serialized server
// message is accepted alongside the structured reason.
export function isConsistencyNotReadyError(error: unknown): boolean {
    return (
        errorInfos(error, Code.Aborted).some(({ reason }) => reason === CONSISTENCY_NOT_READY) ||
        SERIALIZED_CONSISTENCY_NOT_READY.test(errorMessage(error))
    );
}

// Local transport failures retain their cause, unlike server-sent Unknown
// errors. Connect gives a string cause when a stream ends early or when an SDK
// retry reuses the request a failed first response already consumed. A body
// that ends inside a frame is a local InvalidArgument, though the request
// itself is valid. Bare SDK Wasm initialization failures stay terminal because
// the SDK caches the rejected promise until reload.
function isTransportFailure(error: unknown): boolean {
    const connect = connectError(error);
    return (
        (connect?.code === Code.InvalidArgument && connect.rawMessage === 'protocol error: incomplete envelope') ||
        (connect?.code === Code.Unknown &&
            (connect.cause === 'missing EndStreamResponse' ||
                connect.cause === 'missing request message' ||
                (connect.cause instanceof TypeError && NETWORK_FAILURE_MESSAGE.test(connect.cause.message))))
    );
}

// Long-lived subscriptions reconnect on failures that can clear without a
// client change. Internal covers forwarded upstream resets and HTTP 400.
// Unknown without a cause covers proxy pages and HTTP statuses Connect does not
// map, so a misconfigured endpoint also keeps reconnecting. Unknown errors that
// carry a local cause, such as an invalid URL, stay terminal.
export function isRetryableServiceError(error: unknown): boolean {
    const connect = connectError(error);
    return (
        isTransportFailure(error) ||
        (connect?.code === Code.Unknown && connect.cause === undefined) ||
        connect?.code === Code.Internal ||
        connect?.code === Code.Unavailable ||
        isConsistencyNotReadyError(error) ||
        isBatchEvicted(error)
    );
}

export function isBatchEvicted(error: unknown): boolean {
    return errorInfos(error, Code.OutOfRange).some(
        ({ reason, domain }) => reason === 'BATCH_EVICTED' && domain === 'log.stream',
    );
}

export function errorInfos(error: unknown, code: Code): ErrorInfo[] {
    const connect = connectError(error);
    if (connect?.code !== code) return [];

    return connect.details.flatMap((detail) => {
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
    { wait = waitForRetry, onRetry }: RetryOptions = {},
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

// Store errors arrive as HttpError and proof errors can be rethrown with added
// context, so the RPC failure is found by following the cause chain.
function connectError(error: unknown): ConnectError | undefined {
    let current = error;
    for (let depth = 0; depth < MAX_CAUSE_DEPTH && current instanceof Error; depth += 1) {
        if (current instanceof ConnectError) return current;
        current = current.cause;
    }
    return undefined;
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
