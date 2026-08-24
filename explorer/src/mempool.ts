import { toArrayBuffer } from './codec';
import {
    TransactionSubmissionError,
    classifySubmissionResponse,
} from './submissionResponse';

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
): Promise<void> {
    const response = await fetch(`${trimTrailingSlash(baseUrl)}/transactions`, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: toArrayBuffer(batch),
        signal,
    });

    const kind = classifySubmissionResponse(response.status);
    if (kind === 'accepted') {
        return;
    }

    throw new TransactionSubmissionError(
        kind,
        `transaction submission failed with HTTP ${response.status}`,
    );
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
