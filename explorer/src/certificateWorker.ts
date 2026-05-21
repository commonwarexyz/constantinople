import { SimplexClient } from '@exowarexyz/simplex';
import initCrypto, { verifyFinalization } from './crypto-wasm/constantinople_explorer_crypto';
import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
} from './certificateWorkerTypes';

const RETRY_DELAY_MS = 1_000;

interface CertificateJob {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly height: number;
}

interface FinalizedTransactionTarget {
    readonly height: bigint;
    readonly view: bigint;
}

const queued = new Map<number, CertificateJob>();
const verified = new Set<number>();
const inFlight = new Set<number>();
const retryTimers = new Map<number, number>();
let active = false;
let cryptoReady: Promise<unknown> | null = null;

const workerScope = self as unknown as {
    onmessage: ((event: MessageEvent<CertificateWorkerRequest>) => void) | null;
    postMessage: (message: CertificateWorkerResponse) => void;
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
};

workerScope.onmessage = (event) => {
    const request = event.data;
    for (const height of request.heights) {
        if (verified.has(height) || queued.has(height) || inFlight.has(height)) continue;
        queued.set(height, {
            storeUrl: request.storeUrl,
            simplexVerificationMaterial: request.simplexVerificationMaterial,
            height,
        });
    }
    drainQueue();
};

async function drainQueue() {
    if (active) return;
    active = true;
    try {
        while (queued.size > 0) {
            const job = nextJob();
            if (!job) return;
            queued.delete(job.height);
            if (verified.has(job.height)) continue;
            inFlight.add(job.height);
            retryTimers.delete(job.height);
            try {
                await verifyJob(job);
            } finally {
                inFlight.delete(job.height);
            }
        }
    } finally {
        active = false;
    }
}

function nextJob(): CertificateJob | null {
    const first = queued.values().next();
    return first.done ? null : first.value;
}

async function verifyJob(job: CertificateJob) {
    try {
        await loadCrypto();
        const simplex = new SimplexClient(trimTrailingSlash(job.storeUrl));
        const finalized = await simplex.getFinalizationByHeightRaw(String(job.height));
        if (!finalized) {
            throw new Error(`finalization missing at height ${job.height}`);
        }
        const target = verifyFinalization(
            fromHex(job.simplexVerificationMaterial),
            finalized,
        ) as FinalizedTransactionTarget;
        verified.add(job.height);
        workerScope.postMessage({
            kind: 'verified',
            height: Number(target.height),
            view: target.view.toString(),
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (isRetryableCertificateError(detail)) {
            scheduleRetry(job);
            return;
        }
        workerScope.postMessage({ kind: 'error', height: job.height, detail });
    }
}

function scheduleRetry(job: CertificateJob) {
    if (retryTimers.has(job.height)) return;
    const timer = workerScope.setTimeout(() => {
        retryTimers.delete(job.height);
        if (!verified.has(job.height)) {
            queued.set(job.height, job);
            drainQueue();
        }
    }, RETRY_DELAY_MS);
    retryTimers.set(job.height, timer);
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
