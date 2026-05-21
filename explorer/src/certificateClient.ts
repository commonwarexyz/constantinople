import type {
    CertificateWorkerRequest,
    CertificateWorkerResponse,
    WatchedBlockCertificate,
} from './certificateWorkerTypes';

type CertificateListener = (response: CertificateWorkerResponse) => void;

let certificateWorker: Worker | null = null;
let activeConfigKey = '';
const listeners = new Set<CertificateListener>();

export function configureCertificateVerification({
    storeUrl,
    simplexVerificationMaterial,
}: {
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}) {
    const configKey = `${storeUrl}\n${simplexVerificationMaterial}`;
    if (activeConfigKey === configKey) return;
    activeConfigKey = configKey;

    const request: CertificateWorkerRequest = {
        kind: 'configure',
        storeUrl,
        simplexVerificationMaterial,
    };
    getCertificateWorker().postMessage(request);
}

export function watchBlockCertificates(blocks: readonly WatchedBlockCertificate[]) {
    if (blocks.length === 0) return;
    getCertificateWorker().postMessage({
        kind: 'watch',
        blocks,
    } satisfies CertificateWorkerRequest);
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
        activeConfigKey = '';
    };
    return certificateWorker;
}
