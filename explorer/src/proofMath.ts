export function transactionProofTip(transactionsRangeEnd: bigint): bigint {
    if (transactionsRangeEnd === 0n) {
        throw new Error('transaction operation range is empty');
    }
    return transactionsRangeEnd - 1n;
}
