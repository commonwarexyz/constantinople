import { toArrayBuffer } from './codec';
import {
    TransactionSubmissionError,
    classifySubmissionResponse,
    parseTxStatus,
    type SubmissionResult,
} from './submissionResponse';
import { boundedSubmissionSignal, SUBMISSION_TIMEOUT_MS } from './submissionRequest';

export interface AccountView {
    readonly balance: number;
    readonly nonce: NonceView;
}

export interface NonceView {
    readonly base: number;
    readonly bitmap: number;
}

export async function fetchAccount(baseUrl: string, publicKeyHex: string): Promise<AccountView | null> {
    const response = await fetch(`${trimTrailingSlash(baseUrl)}/account/${publicKeyHex}`);
    if (response.status === 404) {
        return null;
    }
    if (!response.ok) {
        throw new Error(`account lookup failed with HTTP ${response.status}`);
    }
    return response.json();
}

export async function submitTransactions(
    baseUrl: string,
    batch: Uint8Array,
    signal?: AbortSignal,
    timeoutMs = SUBMISSION_TIMEOUT_MS,
): Promise<SubmissionResult> {
    const request = boundedSubmissionSignal(signal, timeoutMs);
    try {
        const response = await fetch(`${trimTrailingSlash(baseUrl)}/transactions`, {
            method: 'POST',
            headers: { 'content-type': 'application/octet-stream' },
            body: toArrayBuffer(batch),
            signal: request.signal,
        });

        const kind = classifySubmissionResponse(response.status);
        if (kind === 'status') {
            try {
                return parseTxStatus(await response.json());
            } catch (error) {
                const detail = error instanceof Error ? error.message : String(error);
                throw new TransactionSubmissionError(
                    'ambiguous',
                    `transaction submission returned an invalid status. ${detail}`,
                );
            }
        }
        if (kind === 'pending') return { status: 'pending' };

        throw new TransactionSubmissionError(
            kind,
            `transaction submission failed with HTTP ${response.status}`,
        );
    } finally {
        request.dispose();
    }
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
