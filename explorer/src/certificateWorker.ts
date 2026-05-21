import { Client as ExowareClient, type StoreClient } from '@exowarexyz/sdk';
import { finalizedByHeightKey } from '@exowarexyz/simplex';
import initCrypto, { verifyBlockCertificate } from './crypto-wasm/constantinople_explorer_crypto';
import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
    CertificateWorkerResult,
    WatchedBlockCertificate,
} from './certificateWorkerTypes';

const FETCH_BATCH_SIZE = 32;
const FETCH_DEBOUNCE_MS = 25;
const FETCH_RETRY_DELAY_MS = 1_000;

interface CertificateWorkerConfig {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

interface FinalizedTransactionTarget {
    readonly view: bigint;
}

const wanted = new Map<number, Uint8Array>();
const verified = new Set<number>();
const queuedFetches = new Set<number>();
const fetchQueue: number[] = [];
let cryptoReady: Promise<unknown> | null = null;
let config: CertificateWorkerConfig | null = null;
let store: StoreClient | null = null;
let fetchTimer: number | null = null;
let fetching = false;

const workerScope = self as unknown as {
    onmessage: ((event: MessageEvent<CertificateWorkerRequest>) => void) | null;
    postMessage: (message: CertificateWorkerResponse) => void;
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
};

workerScope.onmessage = (event) => {
    const request = event.data;
    if (request.kind === 'configure') {
        configure({
            storeUrl: request.storeUrl,
            simplexVerificationMaterial: request.simplexVerificationMaterial,
        });
        return;
    }

    watchBlocks(request.blocks);
};

function configure(nextConfig: CertificateWorkerConfig) {
    config = nextConfig;
    store = new ExowareClient(trimTrailingSlash(nextConfig.storeUrl)).store();
    wanted.clear();
    verified.clear();
    queuedFetches.clear();
    fetchQueue.length = 0;
    fetching = false;

    if (fetchTimer !== null) {
        workerScope.clearTimeout(fetchTimer);
        fetchTimer = null;
    }
}

function watchBlocks(blocks: readonly WatchedBlockCertificate[]) {
    for (const block of blocks) {
        const { height, digest } = block;
        if (!Number.isSafeInteger(height) || height < 0 || digest.length !== 32) continue;
        if (verified.has(height)) continue;
        wanted.set(height, digest);
        enqueueFetch(height);
    }
}

function enqueueFetch(height: number) {
    if (verified.has(height) || queuedFetches.has(height)) return;
    queuedFetches.add(height);
    fetchQueue.push(height);
    scheduleFetch(FETCH_DEBOUNCE_MS);
}

function scheduleFetch(delayMs: number) {
    if (fetching || fetchTimer !== null) return;
    fetchTimer = workerScope.setTimeout(() => {
        fetchTimer = null;
        void processFetchQueue();
    }, delayMs);
}

async function processFetchQueue() {
    const activeConfig = config;
    const activeStore = store;
    if (!activeConfig || !activeStore || fetching) return;

    fetching = true;
    try {
        await loadCrypto();
        while (config === activeConfig && store === activeStore && fetchQueue.length > 0) {
            const heights = takeFetchBatch();
            if (heights.length === 0) continue;
            await fetchAndVerifyBatch(activeConfig, activeStore, heights);
            await yieldToWorker();
        }
    } finally {
        fetching = false;
        if (fetchQueue.length > 0) {
            scheduleFetch(0);
        }
    }
}

function takeFetchBatch(): number[] {
    const heights: number[] = [];
    while (heights.length < FETCH_BATCH_SIZE) {
        const height = fetchQueue.shift();
        if (height === undefined) break;
        queuedFetches.delete(height);
        if (!wanted.has(height) || verified.has(height)) continue;
        heights.push(height);
    }
    return heights;
}

async function fetchAndVerifyBatch(
    activeConfig: CertificateWorkerConfig,
    activeStore: StoreClient,
    heights: readonly number[],
) {
    const keys = heights.map(finalizedByHeightKey);

    try {
        const results = await activeStore.getMany(keys, FETCH_BATCH_SIZE);
        const byKey = new Map(results.map((result) => [bytesKey(result.key), result.value]));
        const responses: CertificateWorkerResult[] = [];
        for (let index = 0; index < heights.length; index++) {
            const height = heights[index];
            const finalized = byKey.get(bytesKey(keys[index]));
            if (!finalized) {
                retryFetch(height);
                continue;
            }
            const response = verifyFetchedFinalization(activeConfig, height, finalized);
            if (response) {
                responses.push(response);
            }
        }
        postResults(responses);
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (isRetryableCertificateError(detail)) {
            for (const height of heights) {
                retryFetch(height);
            }
            return;
        }
        postResults(
            heights.map((height) => {
                wanted.delete(height);
                return { kind: 'error', height, detail };
            }),
        );
    }
}

function verifyFetchedFinalization(
    activeConfig: CertificateWorkerConfig,
    height: number,
    finalized: Uint8Array,
): CertificateWorkerResult | null {
    const expectedDigest = wanted.get(height);
    if (!expectedDigest || verified.has(height)) return null;

    try {
        const target = verifyBlockCertificate(
            fromHex(activeConfig.simplexVerificationMaterial),
            finalized,
            expectedDigest,
        ) as FinalizedTransactionTarget;
        verified.add(height);
        wanted.delete(height);
        return {
            kind: 'verified',
            height,
            view: target.view.toString(),
        };
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        wanted.delete(height);
        return { kind: 'error', height, detail };
    }
}

function postResults(results: readonly CertificateWorkerResult[]) {
    if (results.length === 0) return;
    if (results.length === 1) {
        workerScope.postMessage(results[0]);
        return;
    }
    workerScope.postMessage({ kind: 'batch', results });
}

function retryFetch(height: number) {
    if (!wanted.has(height) || verified.has(height)) return;
    workerScope.setTimeout(() => enqueueFetch(height), FETCH_RETRY_DELAY_MS);
}

async function loadCrypto() {
    cryptoReady ??= initCrypto();
    await cryptoReady;
}

function isRetryableCertificateError(detail: string): boolean {
    return /finalization missing|not found|missing proof|failed to decode Simplex identity|failed to decode Simplex verification material|Simplex verification material contains trailing bytes|out_of_range|unavailable|fetch/i.test(
        detail,
    );
}

function fromHex(value: string): Uint8Array {
    const normalized = value.trim().replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
        throw new Error('invalid hex');
    }

    const bytes = new Uint8Array(normalized.length / 2);
    for (let index = 0; index < bytes.length; index++) {
        bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

function bytesKey(bytes: Uint8Array): string {
    let key = '';
    for (const byte of bytes) {
        key += String.fromCharCode(byte);
    }
    return key;
}

function yieldToWorker(): Promise<void> {
    return new Promise((resolve) => workerScope.setTimeout(resolve, 0));
}
