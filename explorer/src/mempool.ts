import { toArrayBuffer } from './codec';

export interface AccountView {
    readonly balance: number;
    readonly nonce: NonceView;
}

export interface NonceView {
    readonly base: number;
    readonly bitmap: number;
}

export type TxStatus =
    | { readonly status: 'finalized'; readonly height: number }
    | {
          readonly status: 'partially_finalized';
          readonly height: number;
          readonly included: number;
          readonly filtered: number;
      }
    | { readonly status: 'dropped' };

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
): Promise<TxStatus> {
    const response = await fetch(`${trimTrailingSlash(baseUrl)}/transactions`, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: toArrayBuffer(batch),
        signal,
    });

    if (!response.ok) {
        const detail = await response.text();
        const suffix = detail ? `: ${detail}` : '';
        throw new Error(`transaction submission failed with HTTP ${response.status}${suffix}`);
    }
    return response.json();
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}
