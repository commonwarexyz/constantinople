import { Code, ConnectError } from '@connectrpc/connect';
import { bytesEqual, fromHex, parseAccountKeyHex, toHex } from './codec.ts';
import { SearchKind } from './gen/constantinople/explorer/v1/explorer_pb.ts';
import { createExplorerClient } from './rpc.ts';

export interface SearchMatch {
    readonly kind: 'account' | 'transaction';
    readonly value: string;
}

export function normalizeSearchQuery(value: string): string {
    return toHex(parseAccountKeyHex(value.trim().replace(/^0x/i, '')));
}

/** Returns a navigation hint. Destination pages authenticate their own evidence. */
export async function searchIndexer(endpoint: string, query: string, signal: AbortSignal): Promise<SearchMatch> {
    signal.throwIfAborted();
    const value = normalizeSearchQuery(query);
    try {
        const match = await createExplorerClient(endpoint).search({ value: fromHex(value) }, { signal });
        signal.throwIfAborted();
        if (!bytesEqual(match.value, fromHex(value)) || (match.kind !== SearchKind.ACCOUNT && match.kind !== SearchKind.TRANSACTION)) {
            throw new Error('invalid search result');
        }
        return { kind: match.kind === SearchKind.ACCOUNT ? 'account' : 'transaction', value };
    } catch (error) {
        signal.throwIfAborted();
        if (error instanceof ConnectError && error.code === Code.NotFound) return { kind: 'account', value };
        throw error;
    }
}
