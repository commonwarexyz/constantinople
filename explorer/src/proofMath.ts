export function transactionProofTip(transactionsRangeEnd: bigint): bigint {
    if (transactionsRangeEnd === 0n) {
        throw new Error('transaction operation range is empty');
    }
    return transactionsRangeEnd - 1n;
}

export function assertTransactionLocationBeforeTip(location: bigint, transactionsRangeEnd: bigint) {
    if (location >= transactionsRangeEnd) {
        throw new Error(`transaction location ${location} is outside finalized transaction range`);
    }
}
