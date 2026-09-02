import { create } from '@bufbuild/protobuf';
import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError } from '@connectrpc/connect';
import {
    Client,
    HttpError,
    SelectorSchema,
    StoreKeyPrefix,
    TraversalMode,
    type QueryResult,
    type StoreBatch,
    type StoreClient,
} from '@exowarexyz/sdk';

const PROVABLE_TARGET_STORE_PREFIX = new Uint8Array([0x04]);
const PROVABLE_TARGET_HEIGHT_BYTES = 8;
const BLOCK_DIGEST_BYTES = 32;
const NETWORK_RECONNECT_DELAY_MS = 5_000;
const TARGET_KEY_REGEX = `(?s-u)^.{${PROVABLE_TARGET_HEIGHT_BYTES}}$`;
const ERROR_INFO_TYPE = 'google.rpc.ErrorInfo';
const STORE_STREAM_ERROR_DOMAIN = 'log.stream';
const BATCH_EVICTED_REASON = 'BATCH_EVICTED';

export interface PublishedProofTarget {
    readonly height: bigint;
    readonly blockDigest: Uint8Array;
    readonly sequenceNumber: bigint;
}

export interface SubscribeProofTargetsOptions {
    readonly signal?: AbortSignal;
    readonly reconnectDelayMs?: number;
    readonly onError?: (message: string) => void;
}

interface SequencedQueryResult extends QueryResult {
    readonly sequenceNumber: bigint;
}

class MalformedProofTargetError extends Error {}

export type PublishedProofTargetStore = Pick<StoreClient, 'query' | 'subscribe'>;

export function decodePublishedProofTarget(
    key: Uint8Array,
    value: Uint8Array,
    sequenceNumber = 0n,
): PublishedProofTarget {
    if (key.length !== PROVABLE_TARGET_HEIGHT_BYTES) {
        throw new MalformedProofTargetError(
            `provable target key must be ${PROVABLE_TARGET_HEIGHT_BYTES} bytes`,
        );
    }
    if (value.length !== BLOCK_DIGEST_BYTES) {
        throw new MalformedProofTargetError(
            `provable target digest must be ${BLOCK_DIGEST_BYTES} bytes`,
        );
    }

    let height = 0n;
    for (const byte of key) {
        height = (height << 8n) | BigInt(byte);
    }
    return { height, blockDigest: value.slice(), sequenceNumber };
}

export async function fetchLatestPublishedProofTarget(
    storeUrl: string,
    signal?: AbortSignal,
): Promise<PublishedProofTarget> {
    const result = await fetchLatestFromStore(createProofTargetStore(storeUrl), signal);
    if (!result.target) {
        throw new Error('latest provable target is missing');
    }
    return result.target;
}

export async function* subscribePublishedProofTargets(
    storeUrl: string,
    options: SubscribeProofTargetsOptions = {},
): AsyncGenerator<PublishedProofTarget, void, void> {
    yield* subscribePublishedProofTargetsFromStore(createProofTargetStore(storeUrl), options);
}

export async function* subscribePublishedProofTargetsFromStore(
    store: PublishedProofTargetStore,
    options: SubscribeProofTargetsOptions = {},
): AsyncGenerator<PublishedProofTarget, void, void> {
    const signal = options.signal;
    const reconnectDelayMs = options.reconnectDelayMs ?? NETWORK_RECONNECT_DELAY_MS;
    let nextSequence: bigint | undefined;
    let latestHeight: bigint | undefined;

    while (!signal?.aborted) {
        try {
            if (nextSequence === undefined) {
                const bootstrap = await fetchLatestFromStore(store, signal);
                nextSequence = bootstrap.sequenceNumber + 1n;
                if (bootstrap.target && isNewer(bootstrap.target, latestHeight)) {
                    latestHeight = bootstrap.target.height;
                    yield bootstrap.target;
                }
            }

            const stream = store.subscribe(
                {
                    selectors: [
                        create(SelectorSchema, {
                            prefix: new Uint8Array(),
                            payloadRegex: TARGET_KEY_REGEX,
                        }),
                    ],
                    sinceSequenceNumber: nextSequence,
                },
                { signal },
            );

            for await (const batch of stream) {
                const target = latestTargetInBatch(batch);
                nextSequence = batch.sequenceNumber + 1n;
                if (!target || !isNewer(target, latestHeight)) continue;
                latestHeight = target.height;
                yield target;
            }

            if (signal?.aborted) return;
            options.onError?.('provable target subscription ended');
        } catch (error) {
            if (signal?.aborted) return;
            if (error instanceof MalformedProofTargetError) {
                options.onError?.(errorMessage(error));
                throw error;
            }
            if (isBatchEvicted(error)) {
                nextSequence = undefined;
            }
            options.onError?.(errorMessage(error));
        }

        if (!(await waitForRetry(reconnectDelayMs, signal))) return;
    }
}

function createProofTargetStore(storeUrl: string): StoreClient {
    return new Client(storeUrl.replace(/\/+$/, '')).store(
        new StoreKeyPrefix(PROVABLE_TARGET_STORE_PREFIX),
    );
}

async function fetchLatestFromStore(
    store: PublishedProofTargetStore,
    signal?: AbortSignal,
): Promise<{ target: PublishedProofTarget | null; sequenceNumber: bigint }> {
    const result = (await withAbort(
        () =>
            store.query(
                undefined,
                undefined,
                1,
                1,
                TraversalMode.REVERSE,
                undefined,
                { signal },
            ),
        signal,
    )) as SequencedQueryResult;

    if (result.sequenceNumber === undefined) {
        throw new Error('Store query did not return its evaluated sequence');
    }
    const row = result.results[0];
    return {
        target: row
            ? decodePublishedProofTarget(row.key, row.value, result.sequenceNumber)
            : null,
        sequenceNumber: result.sequenceNumber,
    };
}

function latestTargetInBatch(batch: StoreBatch): PublishedProofTarget | null {
    let latest: PublishedProofTarget | null = null;
    for (const entry of batch.entries) {
        const target = decodePublishedProofTarget(
            entry.key,
            entry.value,
            batch.sequenceNumber,
        );
        if (!latest || target.height > latest.height) {
            latest = target;
        }
    }
    return latest;
}

function isNewer(target: PublishedProofTarget, latestHeight: bigint | undefined): boolean {
    return latestHeight === undefined || target.height > latestHeight;
}

function isBatchEvicted(error: unknown): boolean {
    if (!(error instanceof HttpError) || error.connectCode !== Code.OutOfRange) return false;
    if (!(error.cause instanceof ConnectError)) return false;

    return error.cause.details.some((detail) => {
        if (!('type' in detail) || detail.type !== ERROR_INFO_TYPE) return false;
        try {
            const info = decodeErrorInfo(detail.value);
            return (
                info.reason === BATCH_EVICTED_REASON &&
                info.domain === STORE_STREAM_ERROR_DOMAIN
            );
        } catch {
            return false;
        }
    });
}

function decodeErrorInfo(value: Uint8Array): { reason: string; domain: string } {
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

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

function withAbort<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    if (!signal) return operation();
    if (signal.aborted) return Promise.reject(signal.reason);

    return new Promise<T>((resolve, reject) => {
        let settled = false;
        const finish = () => {
            if (settled) return false;
            settled = true;
            signal.removeEventListener('abort', onAbort);
            return true;
        };
        const onAbort = () => {
            if (finish()) reject(signal.reason);
        };

        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) {
            onAbort();
            return;
        }

        try {
            operation().then(
                (value) => {
                    if (finish()) resolve(value);
                },
                (error: unknown) => {
                    if (finish()) reject(error);
                },
            );
        } catch (error) {
            if (finish()) reject(error);
        }
    });
}

export function waitForRetry(ms: number, signal?: AbortSignal): Promise<boolean> {
    return new Promise((resolve) => {
        let settled = false;
        let timeout: ReturnType<typeof setTimeout> | undefined;
        const finish = (completed: boolean) => {
            if (settled) return;
            settled = true;
            if (timeout !== undefined) clearTimeout(timeout);
            signal?.removeEventListener('abort', onAbort);
            resolve(completed);
        };
        const onAbort = () => finish(false);

        if (signal?.aborted) {
            resolve(false);
            return;
        }

        timeout = setTimeout(() => finish(true), ms);
        signal?.addEventListener('abort', onAbort, { once: true });
        if (signal?.aborted) onAbort();
    });
}
