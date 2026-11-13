import { bytesEqual } from './codec.ts';
import { readU64Be, TRANSACTION_PAGE, type AccountTransactionPage } from './qmdb.ts';

export interface AccountHistoryTransaction {
    readonly digest: string;
    readonly sender: string;
    readonly recipient: string;
    readonly value: bigint;
    readonly nonce: bigint;
    readonly location: bigint;
    readonly senderIndex: bigint;
    readonly recipientIndex: bigint;
    readonly role?: number;
}

export function accountCursor(end: bigint): Uint8Array {
    if (end < 0n || end > (1n << 64n) - 1n) throw new Error('invalid account cursor boundary');
    const cursor = new Uint8Array(8);
    new DataView(cursor.buffer).setBigUint64(0, end);
    return cursor;
}

/** Checks a complete interval of authenticated transaction history entries. */
export function accountHistoryPage(
    account: string,
    count: bigint,
    cursor: Uint8Array | null,
    claimedNext: Uint8Array | null,
    transactions: readonly AccountHistoryTransaction[],
): AccountTransactionPage {
    if (cursor && cursor.length !== 8) throw new Error('invalid account cursor');
    const end = cursor ? readU64Be(cursor, 0) : count;
    if (end > count) throw new Error('account cursor exceeds authenticated count');
    const lower = end > TRANSACTION_PAGE ? end - TRANSACTION_PAGE : 0n;
    if (transactions.length !== Number(end - lower)) throw new Error('account page does not cover the authenticated count interval');
    const nextCursor = lower > 0n ? accountCursor(lower) : null;
    if ((nextCursor === null) !== (claimedNext === null) || (nextCursor && !bytesEqual(nextCursor, claimedNext!))) {
        throw new Error('account next cursor does not match the authenticated count interval');
    }
    const digests = new Set<string>();
    let previousLocation: bigint | undefined;
    const rows = transactions.map((transaction, index) => {
        const sent = transaction.sender === account;
        const received = transaction.recipient === account;
        if (!sent && !received) throw new Error('transaction does not involve requested account');
        if (transaction.role !== (sent ? 0 : 1)) throw new Error('transaction has incorrect account role');
        if (sent && received && transaction.senderIndex !== transaction.recipientIndex) throw new Error('self-transfer has unequal participant indices');
        const accountIndex = sent ? transaction.senderIndex : transaction.recipientIndex;
        if (accountIndex !== end - 1n - BigInt(index)) throw new Error('account history indices are not the exact descending interval');
        if (digests.has(transaction.digest) || (previousLocation !== undefined && transaction.location >= previousLocation)) {
            throw new Error('account history repeats or reorders a transaction');
        }
        digests.add(transaction.digest);
        previousLocation = transaction.location;
        return {
            digest: transaction.digest, direction: sent ? 'sent' as const : 'received' as const,
            counterparty: sent ? transaction.recipient : transaction.sender,
            value: transaction.value, nonce: transaction.nonce, location: transaction.location,
            accountIndex, senderIndex: transaction.senderIndex, recipientIndex: transaction.recipientIndex,
        };
    });
    return { rows, nextCursor };
}
