import { SimplexClient, SimplexRecordKind } from '@exowarexyz/simplex';
import initCrypto, { verifyBlockCertificate } from './crypto-wasm/constantinople_explorer_crypto';
import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
    WatchedBlockCertificate,
} from './certificateWorkerTypes';

const STREAM_RETRY_DELAY_MS = 1_000;
const RAW_CACHE_LIMIT = 4_096;

interface CertificateWorkerConfig {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

interface FinalizedTransactionTarget {
    readonly view: bigint;
}

const wanted = new Map<number, Uint8Array>();
const verified = new Set<number>();
const queued = new Set<number>();
const rawByHeight = new Map<number, Uint8Array>();
const verifyQueue: number[] = [];
let cryptoReady: Promise<unknown> | null = null;
let config: CertificateWorkerConfig | null = null;
let streamController: AbortController | null = null;
let streamRetryTimer: number | null = null;
let verifying = false;

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
    wanted.clear();
    verified.clear();
    queued.clear();
    rawByHeight.clear();
    verifyQueue.length = 0;
    verifying = false;

    streamController?.abort();
    streamController = null;
    if (streamRetryTimer !== null) {
        workerScope.clearTimeout(streamRetryTimer);
        streamRetryTimer = null;
    }
    startStream(nextConfig);
}

function watchBlocks(blocks: readonly WatchedBlockCertificate[]) {
    for (const block of blocks) {
        const { height, digest } = block;
        if (!Number.isSafeInteger(height) || height < 0 || digest.length !== 32) continue;
        if (verified.has(height)) continue;
        wanted.set(height, digest);
        if (rawByHeight.has(height)) {
            enqueueVerification(height);
        }
    }
    scheduleVerification();
}

function startStream(activeConfig: CertificateWorkerConfig) {
    streamController = new AbortController();
    void runStream(activeConfig, streamController.signal);
}

async function runStream(activeConfig: CertificateWorkerConfig, signal: AbortSignal) {
    try {
        await loadCrypto();
        const simplex = new SimplexClient(trimTrailingSlash(activeConfig.storeUrl));
        for await (const batch of simplex.subscribeRaw(
            SimplexRecordKind.FinalizedByHeight,
            {},
            { signal },
        )) {
            for (const entry of batch.entries) {
                if (entry.type !== 'finalization' || entry.index !== 'height') continue;
                const height = Number(entry.height);
                if (!Number.isSafeInteger(height) || height < 0 || verified.has(height)) continue;
                rememberRawFinalization(height, entry.finalized);
            if (wanted.has(height)) {
                enqueueVerification(height);
            }
            }
            scheduleVerification();
        }
        if (!signal.aborted) {
            scheduleStreamRetry(activeConfig);
        }
    } catch (error) {
        if (signal.aborted) return;
        const detail = error instanceof Error ? error.message : String(error);
        if (!isRetryableCertificateError(detail)) {
            workerScope.postMessage({ kind: 'error', height: 0, detail });
            return;
        }
        scheduleStreamRetry(activeConfig);
    }
}

function rememberRawFinalization(height: number, finalized: Uint8Array) {
    rawByHeight.set(height, finalized);
    while (rawByHeight.size > RAW_CACHE_LIMIT) {
        let evicted = false;
        for (const cachedHeight of rawByHeight.keys()) {
            if (wanted.has(cachedHeight) && !verified.has(cachedHeight)) continue;
            rawByHeight.delete(cachedHeight);
            evicted = true;
            break;
        }
        if (!evicted) return;
    }
}

function enqueueVerification(height: number) {
    if (verified.has(height) || queued.has(height)) return;
    queued.add(height);
    verifyQueue.push(height);
}

function scheduleVerification() {
    if (verifying) return;
    verifying = true;
    void processVerificationQueue();
}

async function processVerificationQueue() {
    for (;;) {
        const height = verifyQueue.shift();
        if (height === undefined) {
            verifying = false;
            return;
        }
        queued.delete(height);
        await verifyHeight(height);
        await yieldToWorker();
    }
}

async function verifyHeight(height: number) {
    const activeConfig = config;
    const finalized = rawByHeight.get(height);
    const expectedDigest = wanted.get(height);
    if (!activeConfig || !finalized || !expectedDigest || verified.has(height)) return;

    try {
        const target = verifyBlockCertificate(
            fromHex(activeConfig.simplexVerificationMaterial),
            finalized,
            expectedDigest,
        ) as FinalizedTransactionTarget;
        verified.add(height);
        wanted.delete(height);
        rawByHeight.delete(height);
        workerScope.postMessage({
            kind: 'verified',
            height,
            view: target.view.toString(),
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        wanted.delete(height);
        rawByHeight.delete(height);
        workerScope.postMessage({ kind: 'error', height, detail });
    }
}

function scheduleStreamRetry(activeConfig: CertificateWorkerConfig) {
    if (streamRetryTimer !== null) return;
    streamRetryTimer = workerScope.setTimeout(() => {
        streamRetryTimer = null;
        if (config !== activeConfig) return;
        startStream(activeConfig);
    }, STREAM_RETRY_DELAY_MS);
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

function yieldToWorker(): Promise<void> {
    return new Promise((resolve) => workerScope.setTimeout(resolve, 0));
}
