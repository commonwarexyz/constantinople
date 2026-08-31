export const BLOCK_META_TABLE = 'block_meta';
export const BLOCK_META_HEIGHT = 'height';
export const BLOCK_META_TRANSACTIONS_TIP = 'transactions_tip';

export function transactionHeightPredecessorQuery(location: bigint): string {
    return `
        SELECT ${BLOCK_META_HEIGHT}
        FROM ${BLOCK_META_TABLE}
        WHERE ${BLOCK_META_TRANSACTIONS_TIP} <= ${location.toString()}
        ORDER BY ${BLOCK_META_HEIGHT} DESC
        LIMIT 1
    `;
}

export function containingTransactionHeight(predecessorHeight: bigint | null): bigint {
    return predecessorHeight === null ? 0n : predecessorHeight + 1n;
}
