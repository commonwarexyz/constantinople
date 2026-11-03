import type { VerifiedTransactionBundle } from './proofBundle.ts';

export type SubmittedTransactionStatus = 'reconciling' | 'finalized' | 'rejected';

export type BlockCertificateState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | {
          readonly status: 'verified';
          readonly detail: string;
          readonly height: string;
          readonly view: string;
      }
    | { readonly status: 'error'; readonly detail: string }
    | { readonly status: 'unavailable'; readonly detail: string };

export type TransactionProofState =
    | { readonly status: 'waiting'; readonly detail: string }
    | { readonly status: 'fetching'; readonly detail: string }
    | {
          readonly status: 'verified';
          readonly detail: string;
          readonly location: string;
          readonly tip: string;
          readonly proofSizeBytes: number;
      }
    | { readonly status: 'error'; readonly detail: string }
    | { readonly status: 'unavailable'; readonly detail: string };

export interface SubmittedTransaction {
    readonly reconciliationVersion: 2;
    readonly sender: string;
    readonly digest: string;
    readonly to: string;
    readonly value: string;
    readonly nonce: string;
    readonly submittedAt: number;
    readonly finalizationObservedInMs: number | null;
    readonly proofObservedInMs: number | null;
    readonly status: SubmittedTransactionStatus;
    readonly detail: string;
    readonly finalizedHeight: number | null;
    readonly certificate: BlockCertificateState;
    readonly proof: TransactionProofState;
}

// Saved submission fields must match the body authenticated by the digest lookup.
export function assertSubmittedTransactionMatches(
    local: SubmittedTransaction,
    verified: { readonly digest: string; readonly sender: string; readonly recipient: string; readonly value: bigint; readonly nonce: bigint },
): void {
    if (local.digest !== verified.digest || local.sender !== verified.sender ||
        local.to !== verified.recipient || BigInt(local.value) !== verified.value ||
        BigInt(local.nonce) !== verified.nonce) {
        throw new Error('saved submission fields do not match the verified transaction');
    }
}

export const WAITING_FINALIZATION_CERTIFICATE = {
    status: 'waiting',
    detail: 'queued for finalized metadata',
} satisfies BlockCertificateState;

export const WAITING_FINALIZATION_PROOF = {
    status: 'waiting',
    detail: 'queued for finalized metadata',
} satisfies TransactionProofState;

const REJECTED_STATE = {
    status: 'rejected',
    finalizationObservedInMs: null,
    proofObservedInMs: null,
    finalizedHeight: null,
    certificate: { status: 'unavailable', detail: 'transaction rejected' },
    proof: { status: 'unavailable', detail: 'transaction rejected' },
} as const;

export function prependTransaction(
    transaction: SubmittedTransaction,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return compactHistory([
        transaction,
        ...current.filter((item) => item.digest !== transaction.digest),
    ]);
}

export function markSubmissionReconciling(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateReconciling(digest, current, (tx) => ({ ...tx, detail }));
}

export function markValidatorFinalizationObserved(
    digest: string,
    height: number,
    _observedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateReconciling(digest, current, (tx) => ({
        ...tx,
        detail: `reported h${height}`,
    }));
}

export function markSubmissionRejected(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) =>
        tx.status === 'finalized'
            ? tx
            : {
                  ...tx,
                  ...REJECTED_STATE,
                  detail,
              },
    );
}

export function markReconciliationFetching(
    digest: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return markProofState(digest, current, { status: 'fetching', detail: 'fetching finalized metadata' });
}

export function markReconciliationWaiting(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return markProofState(digest, current, { status: 'waiting', detail });
}

export function markReconciliationError(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return markProofState(digest, current, { status: 'error', detail });
}

export function markTransactionFinalized(
    verified: VerifiedTransactionBundle,
    observedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    const height = Number(verified.height);
    return updateReconciling(verified.transaction.digest, current, (tx) => {
        try {
            assertSubmittedTransactionMatches(tx, verified.transaction);
            if (!Number.isSafeInteger(height)) {
                throw new Error('finalized transaction height exceeds Number.MAX_SAFE_INTEGER');
            }
        } catch (error) {
            const detail = error instanceof Error ? error.message : String(error);
            return {
                ...tx,
                detail,
                finalizedHeight: null,
                finalizationObservedInMs: null,
                proofObservedInMs: null,
                certificate: { status: 'error', detail },
                proof: { status: 'error', detail },
            };
        }
        const elapsed = Math.max(0, observedAt - tx.submittedAt);
        return {
            ...tx,
            status: 'finalized',
            detail: `finalized h${height}`,
            finalizationObservedInMs: tx.finalizationObservedInMs ?? elapsed,
            proofObservedInMs: tx.proofObservedInMs ?? elapsed,
            finalizedHeight: height,
            certificate: {
                status: 'verified',
                detail: `verified at height ${verified.target.height}`,
                height: verified.target.height.toString(),
                view: verified.target.view.toString(),
            },
            proof: {
                status: 'verified',
                detail: `verified at height ${verified.height}`,
                location: verified.location.toString(),
                tip: verified.tip.toString(),
                proofSizeBytes: verified.proofSizeBytes,
            },
        };
    });
}

export function shouldReconcileTransaction(
    tx: SubmittedTransaction,
    signedInSender: string | null,
    foregroundSubmissions?: ReadonlySet<string>,
): boolean {
    return (
        signedInSender !== null &&
        tx.sender === signedInSender &&
        tx.status === 'reconciling' &&
        tx.proof.status === 'waiting' &&
        !foregroundSubmissions?.has(tx.digest)
    );
}

export function assignReconciliationOrder(
    transactions: readonly SubmittedTransaction[],
    order: Map<string, number>,
    sequence: number,
): number {
    for (const transaction of transactions) {
        if (order.has(transaction.digest)) continue;
        sequence += 1;
        order.set(transaction.digest, sequence);
    }
    return sequence;
}

export function reconciliationRetryDelay(
    failures: number,
    elapsedAgeMs: number,
    random: () => number = Math.random,
): number {
    if (elapsedAgeMs < 10_000) return 300;

    const exponent = Math.min(Math.max(failures - 1, 0), 5);
    const exponentialBase = Math.min(30_000, 1_000 * 2 ** exponent);
    const base = elapsedAgeMs < 60_000 ? Math.min(5_000, exponentialBase) : exponentialBase;
    const maximum = elapsedAgeMs < 60_000 ? 5_000 : 30_000;
    return Math.min(maximum, Math.round(base * (0.75 + random() * 0.5)));
}

export function selectReconciliations(
    eligible: readonly SubmittedTransaction[],
    reconciliations: ReadonlyMap<string, { readonly timer: number | null }>,
    order: ReadonlyMap<string, number>,
    limit: number,
): SubmittedTransaction[] {
    const active = [...reconciliations.values()].filter((job) => job.timer === null).length;
    const available = limit - active;
    if (available <= 0) return [];

    return eligible
        .filter((tx) => !reconciliations.has(tx.digest))
        .sort((left, right) => (order.get(left.digest) ?? 0) - (order.get(right.digest) ?? 0))
        .slice(0, available);
}

// Saved rows retain local submission details and observation durations.
// Chain status requires fresh proof verification.
export function restoreSubmittedTransaction(value: unknown): SubmittedTransaction | null {
    if (typeof value !== 'object' || value === null) return null;

    const transaction = value as Record<string, unknown>;
    if (
        typeof transaction.sender !== 'string' ||
        !isAccountKeyHex(transaction.sender) ||
        typeof transaction.digest !== 'string' ||
        !isAccountKeyHex(transaction.digest) ||
        typeof transaction.to !== 'string' ||
        !isAccountKeyHex(transaction.to) ||
        typeof transaction.value !== 'string' ||
        !isU64Decimal(transaction.value) ||
        typeof transaction.nonce !== 'string' ||
        !isU64Decimal(transaction.nonce) ||
        typeof transaction.submittedAt !== 'number' ||
        !Number.isFinite(transaction.submittedAt) ||
        transaction.submittedAt < 0
    ) {
        return null;
    }

    return {
        reconciliationVersion: 2,
        sender: transaction.sender,
        digest: transaction.digest,
        to: transaction.to,
        value: transaction.value,
        nonce: transaction.nonce,
        submittedAt: transaction.submittedAt,
        status: 'reconciling',
        detail: 'saved submission',
        finalizedHeight: null,
        finalizationObservedInMs: storedDuration(transaction.finalizationObservedInMs),
        proofObservedInMs: storedDuration(transaction.proofObservedInMs),
        certificate: WAITING_FINALIZATION_CERTIFICATE,
        proof: WAITING_FINALIZATION_PROOF,
    };
}

export function isAccountKeyHex(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
}

function markProofState(
    digest: string,
    current: SubmittedTransaction[],
    proof: { status: 'fetching' | 'waiting' | 'error'; detail: string },
): SubmittedTransaction[] {
    return updateReconciling(digest, current, (tx) => ({
        ...tx,
        detail: proof.status === 'error' ? 'finalized proof verification failed' : tx.detail,
        certificate: proof,
        proof,
    }));
}

function updateReconciling(
    digest: string,
    current: SubmittedTransaction[],
    update: (transaction: SubmittedTransaction) => SubmittedTransaction,
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) => tx.status === 'reconciling' ? update(tx) : tx);
}

function updateTransaction(
    digest: string,
    current: SubmittedTransaction[],
    update: (transaction: SubmittedTransaction) => SubmittedTransaction,
): SubmittedTransaction[] {
    let changed = false;
    const next = current.map((tx) => {
        if (tx.digest !== digest) return tx;
        changed = true;
        return update(tx);
    });
    return changed ? compactHistory(next) : current;
}

function compactHistory(current: SubmittedTransaction[]): SubmittedTransaction[] {
    let terminalCount = 0;
    return current.filter((tx) => tx.status === 'reconciling' || terminalCount++ < 100);
}

function isU64Decimal(value: string): boolean {
    if (!/^(0|[1-9]\d{0,19})$/.test(value)) return false;
    return BigInt(value) <= (1n << 64n) - 1n;
}

function storedDuration(value: unknown): number | null {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
