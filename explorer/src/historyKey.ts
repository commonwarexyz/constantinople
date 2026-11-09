export interface HistoryScope {
    readonly indexerUrl: string;
    readonly simplexVerificationMaterial: string;
}

const HISTORY_KEY_PREFIX = 'constantinople.submitted-transactions.v4';

export function submittedTransactionHistoryKey(
    scope: HistoryScope,
    walletAccountKeyHex: string | null,
): string | null {
    if (walletAccountKeyHex === null) return null;

    return [
        HISTORY_KEY_PREFIX,
        normalizeScopeValue(scope.indexerUrl),
        normalizeScopeValue(scope.simplexVerificationMaterial),
        normalizeScopeValue(walletAccountKeyHex),
    ].join(':');
}

function normalizeScopeValue(value: string): string {
    return encodeURIComponent(value.trim().replace(/\/+$/, '').toLowerCase());
}
