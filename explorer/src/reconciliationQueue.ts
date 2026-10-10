export interface TransactionReconciliation {
    readonly controller: AbortController;
    timer: number | null;
    waitingForHeight: bigint | null;
}

export function wakeCoveredReconciliations(
    reconciliations: Map<string, TransactionReconciliation>,
    height: bigint,
    clearTimer: (timer: number) => void,
    resume: (digest: string) => void,
): void {
    for (const [digest, reconciliation] of reconciliations) {
        if (
            reconciliation.timer === null ||
            reconciliation.waitingForHeight === null ||
            reconciliation.waitingForHeight > height
        ) {
            continue;
        }
        clearTimer(reconciliation.timer);
        reconciliations.delete(digest);
        resume(digest);
    }
}
