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
const BOOTSTRAP_HEIGHT_SLACK = 8n;
const MAX_QUEUED_TARGETS = 4096;
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
    readonly lastKnownHeight?: bigint;
}

export interface SharedProofTargets {
    subscribe(options?: { signal?: AbortSignal }): AsyncIterableIterator<PublishedProofTarget>;
    close(): void;
}

export function createSharedProofTargets(
    storeUrl: string,
    options: SubscribeProofTargetsOptions = {},
): SharedProofTargets {
    const storageKey = `constantinople:proof-target-height:v1:${storeUrl.replace(/\/+$/, '')}`;
    let storedHeight: bigint | undefined;

    // Storage is only a read hint. Browser privacy settings must not stop the feed.
    try {
        const value = globalThis.localStorage?.getItem(storageKey);
        if (value && /^\d{1,20}$/.test(value)) {
            const height = BigInt(value);
            if (height <= 0xffff_ffff_ffff_ffffn) storedHeight = height;
        }
    } catch {
        storedHeight = undefined;
    }

    return shareProofTargets(createProofTargetStore(storeUrl), {
        ...options,
        lastKnownHeight: options.lastKnownHeight ?? storedHeight,
    }, (target) => {
        try {
            globalThis.localStorage?.setItem(storageKey, target.height.toString());
        } catch {
            // A full or disabled store only makes the next bootstrap scan wider.
        }
    });
}

export function createSharedProofTargetsFromStore(
    store: PublishedProofTargetStore,
    options: SubscribeProofTargetsOptions = {},
): SharedProofTargets {
    return shareProofTargets(store, options);
}

function shareProofTargets(
    store: PublishedProofTargetStore,
    options: SubscribeProofTargetsOptions,
    onTarget?: (target: PublishedProofTarget) => void,
): SharedProofTargets {
    const controller = new AbortController();
    const listeners = new Set<{
        push(target: PublishedProofTarget): void;
        finish(error?: unknown): void;
    }>();
    let started = false;
    let closed = false;
    let failure: unknown;
    let latest: PublishedProofTarget | undefined;

    const finish = (error?: unknown) => {
        if (closed) return;
        closed = true;
        failure = error;
        controller.abort();
        options.signal?.removeEventListener('abort', close);
        for (const listener of listeners) listener.finish(error);
        listeners.clear();
    };
    const close = () => finish();
    options.signal?.addEventListener('abort', close, { once: true });
    if (options.signal?.aborted) close();

    const run = async () => {
        try {
            for await (const target of subscribePublishedProofTargetsFromStore(store, {
                ...options,
                signal: controller.signal,
            })) {
                if (closed) return;
                latest = target;
                for (const listener of listeners) listener.push(target);
                onTarget?.(target);
            }
            finish();
        } catch (error) {
            finish(error);
        }
    };

    return {
        close,
        subscribe({ signal } = {}) {
            const queue: PublishedProofTarget[] = [];
            const pending: Array<{
                resolve(value: IteratorResult<PublishedProofTarget>): void;
                reject(error: unknown): void;
            }> = [];
            let stopped = false;
            let error: unknown;
            const stop = (reason?: unknown) => {
                if (stopped) return;
                stopped = true;
                error = reason;
                queue.length = 0;
                signal?.removeEventListener('abort', abort);
                listeners.delete(listener);
                for (const waiter of pending.splice(0)) {
                    if (error !== undefined) waiter.reject(error);
                    else waiter.resolve({ done: true, value: undefined });
                }
            };
            const abort = () => stop();
            const listener = {
                push(target: PublishedProofTarget) {
                    // Bound outages without silently losing blocks for a slow consumer.
                    if (queue.length >= MAX_QUEUED_TARGETS) {
                        stop(new Error(`proof target consumer exceeded ${MAX_QUEUED_TARGETS} queued targets`));
                        return;
                    }
                    const copy = { ...target, blockDigest: target.blockDigest.slice() };
                    const waiter = pending.shift();
                    if (waiter) waiter.resolve({ done: false, value: copy });
                    else queue.push(copy);
                },
                finish: stop,
            };
            signal?.addEventListener('abort', abort, { once: true });
            if (closed || signal?.aborted) stop(signal?.aborted ? undefined : failure);
            else {
                listeners.add(listener);
                if (latest) listener.push(latest);

                // Pump independently so a consumer waiting on SQL cannot delay proofs.
                if (!started) {
                    started = true;
                    void run();
                }
            }

            return {
                [Symbol.asyncIterator]() { return this; },
                next() {
                    if (error !== undefined) return Promise.reject(error);
                    if (stopped) return Promise.resolve({ done: true as const, value: undefined });
                    const target = queue.shift();
                    if (target) return Promise.resolve({ done: false as const, value: target });
                    return new Promise<IteratorResult<PublishedProofTarget>>((resolve, reject) => {
                        pending.push({ resolve, reject });
                    });
                },
                return() {
                    stop();
                    return Promise.resolve({ done: true as const, value: undefined });
                },
            };
        },
    };
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
                const bootstrap = await fetchLatestFromStore(
                    store,
                    signal,
                    latestHeight ?? options.lastKnownHeight,
                );
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
                // One barrier commit publishes every height of a contiguous
                // prefix in a single batch, so every target is yielded in
                // height order rather than only the newest.
                for (const target of targetsInBatch(batch)) {
                    if (!isNewer(target, latestHeight)) continue;
                    latestHeight = target.height;
                    yield target;
                }
                nextSequence = batch.sequenceNumber + 1n;
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
    lastKnownHeight?: bigint,
): Promise<{ target: PublishedProofTarget | null; sequenceNumber: bigint }> {
    const lowerHeight = lastKnownHeight !== undefined && lastKnownHeight <= 0xffff_ffff_ffff_ffffn &&
        lastKnownHeight > BOOTSTRAP_HEIGHT_SLACK
        ? lastKnownHeight - BOOTSTRAP_HEIGHT_SLACK
        : 0n;
    const start = new Uint8Array(PROVABLE_TARGET_HEIGHT_BYTES);
    new DataView(start.buffer).setBigUint64(0, lowerHeight);
    let result = (await withAbort(
        () =>
            store.query(
                start,
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

    // A hint can belong to an older deployment. Retry once across the prefix
    // so an empty narrowed range cannot hide its current publication target.
    if (result.results.length === 0 && lowerHeight > 0n) {
        result = (await withAbort(
            () => store.query(
                new Uint8Array(PROVABLE_TARGET_HEIGHT_BYTES),
                undefined,
                1,
                1,
                TraversalMode.REVERSE,
                result.sequenceNumber,
                { signal },
            ),
            signal,
        )) as SequencedQueryResult;
    }

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

function targetsInBatch(batch: StoreBatch): PublishedProofTarget[] {
    return batch.entries
        .map((entry) =>
            decodePublishedProofTarget(entry.key, entry.value, batch.sequenceNumber),
        )
        .sort((a, b) => (a.height < b.height ? -1 : a.height > b.height ? 1 : 0));
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

export function withAbort<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
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
