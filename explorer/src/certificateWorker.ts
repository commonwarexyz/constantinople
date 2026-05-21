import { SimplexClient } from '@exowarexyz/simplex';
import initCrypto, { verifyFinalization } from './crypto-wasm/constantinople_explorer_crypto';
import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
} from './certificateWorkerTypes';

const RETRY_DELAY_MS = 1_000;
const MAX_PENDING_HEIGHTS = 512;

interface CertificateWorkerConfig {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly simplex: SimplexClient;
}

interface FinalizedTransactionTarget {
    readonly height: bigint;
    readonly view: bigint;
}

const verified = new Set<number>();
const pending = new Set<number>();
const queued: number[] = [];
const retryTimers = new Map<number, number>();
let cryptoReady: Promise<unknown> | null = null;
let config: CertificateWorkerConfig | null = null;
let processing = false;

const workerScope = self as unknown as {
    onmessage: ((event: MessageEvent<CertificateWorkerRequest>) => void) | null;
    postMessage: (message: CertificateWorkerResponse) => void;
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
};

workerScope.onmessage = (event) => {
    const request = event.data;
    if (request.kind === 'configure') {
        configure(request.storeUrl, request.simplexVerificationMaterial);
        return;
    }

    enqueueHeights(request.heights);
};

function configure(storeUrl: string, simplexVerificationMaterial: string) {
    config = {
        storeUrl,
        simplexVerificationMaterial,
        simplex: new SimplexClient(trimTrailingSlash(storeUrl)),
    };
    verified.clear();
    pending.clear();
    queued.length = 0;
    for (const timer of retryTimers.values()) {
        workerScope.clearTimeout(timer);
    }
    retryTimers.clear();
}

function enqueueHeights(heights: readonly number[]) {
    for (const height of heights) {
        enqueueHeight(height);
    }
    queued.sort((left, right) => right - left);
    while (queued.length > MAX_PENDING_HEIGHTS) {
        pending.delete(queued.pop() ?? 0);
    }
    scheduleProcessing();
}

function enqueueHeight(height: number) {
    if (!Number.isSafeInteger(height) || height < 0) return;
    if (verified.has(height) || pending.has(height)) return;
    pending.add(height);
    queued.push(height);
}

function scheduleProcessing() {
    if (processing) return;
    processing = true;
    void processQueue();
}

async function processQueue() {
    for (;;) {
        const height = queued.shift();
        if (height === undefined) {
            processing = false;
            return;
        }
        await verifyHeight(height);
        await yieldToWorker();
    }
}

async function verifyHeight(height: number) {
    const activeConfig = config;
    if (!activeConfig) {
        pending.delete(height);
        return;
    }

    try {
        await loadCrypto();
        const finalized = await activeConfig.simplex.getFinalizationByHeightRaw(BigInt(height));
        if (!finalized) {
            retryHeight(height);
            return;
        }

        const target = verifyFinalization(
            fromHex(activeConfig.simplexVerificationMaterial),
            finalized,
        ) as FinalizedTransactionTarget;
        const verifiedHeight = Number(target.height);
        verified.add(verifiedHeight);
        pending.delete(height);
        pending.delete(verifiedHeight);
        workerScope.postMessage({
            kind: 'verified',
            height: verifiedHeight,
            view: target.view.toString(),
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (isRetryableCertificateError(detail)) {
            retryHeight(height);
            return;
        }

        pending.delete(height);
        workerScope.postMessage({ kind: 'error', height, detail });
    }
}

function retryHeight(height: number) {
    if (!pending.has(height) || retryTimers.has(height)) return;
    const timer = workerScope.setTimeout(() => {
        retryTimers.delete(height);
        if (!pending.has(height) || verified.has(height)) {
            pending.delete(height);
            return;
        }
        queued.push(height);
        queued.sort((left, right) => right - left);
        scheduleProcessing();
    }, RETRY_DELAY_MS);
    retryTimers.set(height, timer);
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
