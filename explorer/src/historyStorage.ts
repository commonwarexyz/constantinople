import { restoreSubmittedTransaction, type SubmittedTransaction } from './submissionHistory.ts';

export function readStoredHistory(key: string, storage: Storage): SubmittedTransaction[] {
    const raw = storage.getItem(key);
    if (raw === null) {
        const [version, , committee, wallet, ...extra] = key.split(':');
        if (version !== 'constantinople.submitted-transactions.v4' || !committee || !wallet || extra.length) return [];

        // Committee and wallet bind old reservations to this chain identity. Retired service
        // addresses do not change which pending transactions may have consumed its nonces.
        const transactions = new Map<string, SubmittedTransaction>();
        for (let index = 0; index < storage.length; index++) {
            const legacy = storage.key(index);
            if (!legacy) continue;
            const parts = legacy.split(':');
            if (parts.length !== 7 || parts[0] !== 'constantinople.submitted-transactions.v3' ||
                parts[5] !== committee || parts[6] !== wallet) continue;
            for (const transaction of readStoredHistory(legacy, storage)) {
                if (!transactions.has(transaction.digest)) transactions.set(transaction.digest, transaction);
            }
        }
        // Persist even an empty result so clearing current history never revives older entries.
        const migrated = [...transactions.values()].sort((left, right) => right.submittedAt - left.submittedAt);
        storage.setItem(key, JSON.stringify(migrated));
        return migrated;
    }
    try {
        const parsed: unknown = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.flatMap((item: unknown) => {
            const transaction = restoreSubmittedTransaction(item);
            return transaction ? [transaction] : [];
        }) : [];
    } catch {
        return [];
    }
}
