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
    readonly admittedInMs: number | null;
    readonly finalizationObservedInMs: number | null;
    readonly proofObservedInMs: number | null;
    readonly status: SubmittedTransactionStatus;
    readonly detail: string;
    readonly finalizedHeight: number | null;
    readonly certificate: BlockCertificateState;
    readonly proof: TransactionProofState;
}

export const WAITING_FINALIZATION_CERTIFICATE = {
    status: 'waiting',
    detail: 'queued for finalized metadata',
} satisfies BlockCertificateState;

export const WAITING_FINALIZATION_PROOF = {
    status: 'waiting',
    detail: 'queued for finalized metadata',
} satisfies TransactionProofState;

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
    return updateTransaction(digest, current, (tx) =>
        tx.status === 'reconciling'
            ? {
                  ...tx,
                  detail,
              }
            : tx,
    );
}

export function markSubmissionAdmitted(
    digest: string,
    detail: string,
    admittedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) => {
        if (tx.status === 'rejected') return tx;
        return {
            ...tx,
            admittedInMs: tx.admittedInMs ?? Math.max(0, admittedAt - tx.submittedAt),
            detail: tx.status === 'reconciling' ? detail : tx.detail,
        };
    });
}

export function markValidatorFinalizationObserved(
    digest: string,
    height: number,
    observedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) => {
        if (tx.status !== 'reconciling') return tx;
        const observedInMs = Math.max(0, observedAt - tx.submittedAt);
        return {
            ...tx,
            admittedInMs: tx.admittedInMs ?? observedInMs,
            finalizationObservedInMs: tx.finalizationObservedInMs ?? observedInMs,
            finalizedHeight: height,
            detail: `validator reported finalized at ${height}`,
        };
    });
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
                  status: 'rejected',
                  detail,
                  admittedInMs: null,
                  finalizationObservedInMs: null,
                  proofObservedInMs: null,
                  finalizedHeight: null,
                  certificate: { status: 'unavailable', detail: 'transaction rejected' },
                  proof: { status: 'unavailable', detail: 'transaction rejected' },
              },
    );
}

export function markReconciliationFetching(
    digest: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) =>
        tx.status === 'reconciling'
            ? {
                  ...tx,
                  certificate:
                      tx.certificate.status === 'verified'
                          ? tx.certificate
                          : { status: 'fetching', detail: 'fetching finalized metadata' },
                  proof: { status: 'fetching', detail: 'fetching finalized metadata' },
              }
            : tx,
    );
}

export function markReconciliationCertificate(
    digest: string,
    height: number,
    certificate: BlockCertificateState,
    observedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) => {
        if (tx.status !== 'reconciling' || certificate.status !== 'verified') return tx;
        return {
            ...tx,
            finalizedHeight: height,
            finalizationObservedInMs:
                tx.finalizationObservedInMs ?? Math.max(0, observedAt - tx.submittedAt),
            certificate,
            proof: { status: 'fetching', detail: 'fetching QMDB proof' },
        };
    });
}

export function markReconciliationWaiting(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) =>
        tx.status === 'reconciling'
            ? {
                  ...tx,
                  certificate:
                      tx.certificate.status === 'verified'
                          ? tx.certificate
                          : { status: 'waiting', detail },
                  proof: { status: 'waiting', detail },
              }
            : tx,
    );
}

export function markReconciliationError(
    digest: string,
    detail: string,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) =>
        tx.status === 'reconciling'
            ? {
                  ...tx,
                  detail: 'finalized proof verification failed',
                  certificate:
                      tx.certificate.status === 'verified'
                          ? tx.certificate
                          : { status: 'error', detail },
                  proof: { status: 'error', detail },
              }
            : tx,
    );
}

export function markTransactionFinalized(
    digest: string,
    height: number,
    certificate: BlockCertificateState,
    proof: TransactionProofState,
    proofObservedAt: number,
    current: SubmittedTransaction[],
): SubmittedTransaction[] {
    return updateTransaction(digest, current, (tx) => {
        if (tx.status !== 'reconciling' || proof.status !== 'verified') return tx;
        return {
            ...tx,
            status: 'finalized',
            detail: `finalized at ${height}`,
            proofObservedInMs: Math.max(0, proofObservedAt - tx.submittedAt),
            finalizedHeight: height,
            certificate,
            proof,
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

export function normalizeSubmittedTransaction(value: unknown): SubmittedTransaction | null {
    if (typeof value !== 'object' || value === null) return null;

    const transaction = value as Record<string, unknown>;
    if (
        typeof transaction.sender !== 'string' ||
        !isAccountKeyHex(transaction.sender) ||
        typeof transaction.digest !== 'string' ||
        !isDigestHex(transaction.digest) ||
        typeof transaction.to !== 'string' ||
        !isAccountKeyHex(transaction.to) ||
        typeof transaction.value !== 'string' ||
        typeof transaction.nonce !== 'string' ||
        !isU64Decimal(transaction.nonce) ||
        typeof transaction.submittedAt !== 'number' ||
        typeof transaction.status !== 'string' ||
        typeof transaction.detail !== 'string'
    ) {
        return null;
    }

    if (transaction.reconciliationVersion === 2) {
        return normalizeCurrentTransaction(transaction);
    }
    if (transaction.reconciliationVersion === 1) return migrateVersionOneTransaction(transaction);
    return migrateLegacyTransaction(transaction);
}

export function isAccountKeyHex(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
}

function normalizeCurrentTransaction(
    transaction: Record<string, unknown>,
): SubmittedTransaction | null {
    if (!isSubmittedTransactionStatus(transaction.status)) return null;

    const status = transaction.status;
    const finalizedHeight = safeOptionalNumber(transaction.finalizedHeight);
    const admittedInMs = safeOptionalNumber(transaction.admittedInMs);
    const finalizationObservedInMs = safeOptionalNumber(transaction.finalizationObservedInMs);
    const proofObservedInMs = safeOptionalNumber(transaction.proofObservedInMs);
    const certificate = normalizeBlockCertificate(transaction.certificate, finalizedHeight);
    const proof = normalizeTransactionProof(transaction.proof);

    if (status === 'rejected') {
        return baseTransaction(transaction, {
            status,
            finalizedHeight: null,
            admittedInMs: null,
            finalizationObservedInMs: null,
            proofObservedInMs: null,
            certificate: { status: 'unavailable', detail: 'transaction rejected' },
            proof: { status: 'unavailable', detail: 'transaction rejected' },
        });
    }
    if (status === 'finalized' && proof.status !== 'verified') return null;

    return baseTransaction(transaction, {
        status,
        finalizedHeight,
        admittedInMs,
        finalizationObservedInMs:
            finalizedHeight === null ? null : finalizationObservedInMs,
        proofObservedInMs: status === 'finalized' ? proofObservedInMs : null,
        certificate,
        proof,
    });
}

function migrateVersionOneTransaction(
    transaction: Record<string, unknown>,
): SubmittedTransaction | null {
    if (!isSubmittedTransactionStatus(transaction.status)) return null;

    const status = transaction.status;
    const finalizedHeight = safeOptionalNumber(transaction.finalizedHeight);
    const certificate = normalizeBlockCertificate(transaction.certificate, finalizedHeight);
    const proof = normalizeTransactionProof(transaction.proof);

    if (status === 'rejected') {
        return baseTransaction(transaction, {
            status,
            finalizedHeight: null,
            admittedInMs: null,
            finalizationObservedInMs: null,
            proofObservedInMs: null,
            certificate: { status: 'unavailable', detail: 'transaction rejected' },
            proof: { status: 'unavailable', detail: 'transaction rejected' },
        });
    }
    if (status === 'finalized' && proof.status !== 'verified') return null;

    return baseTransaction(transaction, {
        status,
        finalizedHeight,
        admittedInMs: null,
        finalizationObservedInMs: null,
        proofObservedInMs:
            status === 'finalized' ? safeOptionalNumber(transaction.finalizedInMs) : null,
        certificate,
        proof,
    });
}

function migrateLegacyTransaction(
    transaction: Record<string, unknown>,
): SubmittedTransaction {
    const legacyProof = normalizeTransactionProof(transaction.proof);
    if (legacyProof.status === 'verified') {
        return baseTransaction(transaction, {
            status: 'finalized',
            finalizedHeight: safeOptionalNumber(transaction.finalizedHeight),
            admittedInMs: null,
            finalizationObservedInMs: null,
            proofObservedInMs: null,
            certificate: normalizeBlockCertificate(
                transaction.certificate,
                safeOptionalNumber(transaction.finalizedHeight),
            ),
            proof: legacyProof,
        });
    }
    return baseTransaction(transaction, {
        status: 'reconciling',
        finalizedHeight: null,
        admittedInMs: null,
        finalizationObservedInMs: null,
        proofObservedInMs: null,
        certificate: WAITING_FINALIZATION_CERTIFICATE,
        proof: WAITING_FINALIZATION_PROOF,
    });
}

function baseTransaction(
    transaction: Record<string, unknown>,
    state: Pick<
        SubmittedTransaction,
        | 'status'
        | 'finalizedHeight'
        | 'admittedInMs'
        | 'finalizationObservedInMs'
        | 'proofObservedInMs'
        | 'certificate'
        | 'proof'
    >,
): SubmittedTransaction {
    return {
        reconciliationVersion: 2,
        sender: transaction.sender as string,
        digest: transaction.digest as string,
        to: transaction.to as string,
        value: transaction.value as string,
        nonce: transaction.nonce as string,
        submittedAt: transaction.submittedAt as number,
        detail: transaction.detail as string,
        ...state,
    };
}

function normalizeBlockCertificate(
    value: unknown,
    finalizedHeight: number | null,
): BlockCertificateState {
    if (typeof value !== 'object' || value === null) {
        return defaultBlockCertificate(finalizedHeight);
    }
    const certificate = value as Record<string, unknown>;
    if (
        certificate.status === 'verified' &&
        typeof certificate.detail === 'string' &&
        typeof certificate.height === 'string' &&
        typeof certificate.view === 'string'
    ) {
        return {
            status: 'verified',
            detail: certificate.detail,
            height: certificate.height,
            view: certificate.view,
        };
    }
    if (
        (certificate.status === 'waiting' ||
            certificate.status === 'error' ||
            certificate.status === 'unavailable') &&
        typeof certificate.detail === 'string'
    ) {
        return { status: certificate.status, detail: certificate.detail };
    }
    return defaultBlockCertificate(finalizedHeight);
}

function defaultBlockCertificate(finalizedHeight: number | null): BlockCertificateState {
    if (finalizedHeight === null) return WAITING_FINALIZATION_CERTIFICATE;
    return { status: 'waiting', detail: 'queued for block certificate' };
}

function normalizeTransactionProof(value: unknown): TransactionProofState {
    if (typeof value !== 'object' || value === null) return WAITING_FINALIZATION_PROOF;

    const proof = value as Record<string, unknown>;
    if (proof.status === 'verified' && typeof proof.detail === 'string') {
        return {
            status: 'verified',
            detail: proof.detail,
            location: typeof proof.location === 'string' ? proof.location : '',
            tip: typeof proof.tip === 'string' ? proof.tip : '',
            proofSizeBytes: typeof proof.proofSizeBytes === 'number' ? proof.proofSizeBytes : 0,
        };
    }
    if (
        (proof.status === 'waiting' ||
            proof.status === 'error' ||
            proof.status === 'unavailable') &&
        typeof proof.detail === 'string'
    ) {
        return { status: proof.status, detail: proof.detail };
    }
    return WAITING_FINALIZATION_PROOF;
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

function isSubmittedTransactionStatus(value: unknown): value is SubmittedTransactionStatus {
    return value === 'reconciling' || value === 'finalized' || value === 'rejected';
}

function isDigestHex(value: string): boolean {
    return /^[0-9a-f]{64}$/.test(value);
}

function isU64Decimal(value: string): boolean {
    if (!/^(0|[1-9]\d*)$/.test(value)) return false;
    return BigInt(value) <= (1n << 64n) - 1n;
}

function safeOptionalNumber(value: unknown): number | null {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
