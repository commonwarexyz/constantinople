import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
} from './certificateWorkerTypes';

type CertificateListener = (response: CertificateWorkerResponse) => void;

let certificateWorker: Worker | null = null;
const listeners = new Set<CertificateListener>();

export function enqueueCertificateVerification({
    storeUrl,
    simplexVerificationMaterial,
    heights,
}: {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly heights: number[];
}) {
    if (heights.length === 0) return;
    const request: CertificateWorkerRequest = {
        kind: 'enqueue',
        storeUrl,
        simplexVerificationMaterial,
        heights,
    };
    getCertificateWorker().postMessage(request);
}

export function subscribeCertificateVerification(
    listener: CertificateListener,
): () => void {
    listeners.add(listener);
    getCertificateWorker();
    return () => {
        listeners.delete(listener);
    };
}

function getCertificateWorker(): Worker {
    if (certificateWorker) {
        return certificateWorker;
    }

    certificateWorker = new Worker(new URL('./certificateWorker.ts', import.meta.url), {
        type: 'module',
    });
    certificateWorker.onmessage = (event: MessageEvent<CertificateWorkerResponse>) => {
        for (const listener of listeners) {
            listener(event.data);
        }
    };
    certificateWorker.onerror = (event) => {
        const detail = event.message || 'certificate worker failed';
        for (const listener of listeners) {
            listener({ kind: 'error', height: 0, detail });
        }
        certificateWorker?.terminate();
        certificateWorker = null;
    };
    return certificateWorker;
}
