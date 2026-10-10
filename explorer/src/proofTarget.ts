import { create } from '@bufbuild/protobuf';
import { Code } from '@connectrpc/connect';
import {
    Client,
    SelectorSchema,
    StoreKeyPrefix,
    TraversalMode,
    type StoreBatch,
    type StoreClient,
} from '@exowarexyz/sdk';
import { errorInfos, errorMessage, NETWORK_RECONNECT_DELAY_MS, waitForRetry } from './proofRetry.ts';

const PROVABLE_TARGET_STORE_PREFIX = new Uint8Array([0x04]);
const PROVABLE_TARGET_HEIGHT_BYTES = 8;
const BLOCK_DIGEST_BYTES = 32;
const MAX_HEIGHT = 0xffff_ffff_ffff_ffffn;
const BOOTSTRAP_HEIGHT_SLACK = 8n;
const MAX_QUEUED_TARGETS = 4096;
const TARGET_KEY_REGEX = `(?s-u)^.{${PROVABLE_TARGET_HEIGHT_BYTES}}$`;
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
    const url = storeUrl.replace(/\/+$/, '');
    const storageKey = `constantinople:proof-target-height:v1:${url}`;
    let storedHeight: bigint | undefined;

    // Storage is only a read hint. Browser privacy settings must not stop the feed.
    try {
        const value = globalThis.localStorage?.getItem(storageKey);
        if (value && /^\d{1,20}$/.test(value)) {
            const height = BigInt(value);
            if (height <= MAX_HEIGHT) storedHeight = height;
        }
    } catch {
        storedHeight = undefined;
    }

    const store = new Client(url).store(new StoreKeyPrefix(PROVABLE_TARGET_STORE_PREFIX));
    return shareProofTargets(store, {
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

export function shareProofTargets(
    store: PublishedProofTargetStore,
    options: SubscribeProofTargetsOptions = {},
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
                    const copy = { ...target, blockDigest: target.blockDigest.slice() };
                    const waiter = pending.shift();
                    if (waiter) {
                        waiter.resolve({ done: false, value: copy });
                        return;
                    }

                    // Bound memory behind a stalled consumer. Targets are
                    // independent, so dropping the oldest only skips heights.
                    if (queue.length >= MAX_QUEUED_TARGETS) queue.shift();
                    queue.push(copy);
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

class MalformedProofTargetError extends Error {}

export type PublishedProofTargetStore = Pick<StoreClient, 'query' | 'subscribe'>;

export function decodePublishedProofTarget(
    key: Uint8Array,
    value: Uint8Array,
    sequenceNumber: bigint,
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
                // One barrier commit can publish several heights. Yield each in height order.
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

async function fetchLatestFromStore(
    store: PublishedProofTargetStore,
    signal?: AbortSignal,
    lastKnownHeight?: bigint,
): Promise<{ target: PublishedProofTarget | null; sequenceNumber: bigint }> {
    const lowerHeight = lastKnownHeight !== undefined && lastKnownHeight <= MAX_HEIGHT &&
        lastKnownHeight > BOOTSTRAP_HEIGHT_SLACK
        ? lastKnownHeight - BOOTSTRAP_HEIGHT_SLACK
        : 0n;
    const start = new Uint8Array(PROVABLE_TARGET_HEIGHT_BYTES);
    new DataView(start.buffer).setBigUint64(0, lowerHeight);
    let result = await store.query(start, undefined, 1, 1, TraversalMode.REVERSE, undefined, { signal });

    // A hint can belong to an older deployment. Retry once across the prefix
    // so an empty narrowed range cannot hide its current publication target.
    if (result.results.length === 0 && lowerHeight > 0n) {
        result = await store.query(
            new Uint8Array(PROVABLE_TARGET_HEIGHT_BYTES),
            undefined,
            1,
            1,
            TraversalMode.REVERSE,
            result.sequenceNumber,
            { signal },
        );
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
    return errorInfos(error, Code.OutOfRange).some(
        ({ reason, domain }) =>
            reason === BATCH_EVICTED_REASON && domain === STORE_STREAM_ERROR_DOMAIN,
    );
}
