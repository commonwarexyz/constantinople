export type TxStatus =
    | { readonly status: 'finalized'; readonly height: number }
    | {
          readonly status: 'partially_finalized';
          readonly height: number;
          readonly included: number;
          readonly filtered: number;
      }
    | { readonly status: 'dropped' };

export type SubmissionResult = TxStatus | { readonly status: 'pending' };

export type SingleTransactionOutcome =
    | { readonly kind: 'finalized'; readonly height: number }
    | { readonly kind: 'dropped' }
    | { readonly kind: 'ambiguous'; readonly detail: string };

export type SubmissionResponseKind = 'status' | 'pending' | 'rejected' | 'ambiguous';

export class TransactionSubmissionError extends Error {
    readonly kind: Extract<SubmissionResponseKind, 'rejected' | 'ambiguous'>;

    constructor(
        kind: Extract<SubmissionResponseKind, 'rejected' | 'ambiguous'>,
        message: string,
    ) {
        super(message);
        this.name = 'TransactionSubmissionError';
        this.kind = kind;
    }
}

export function classifySubmissionResponse(status: number): SubmissionResponseKind {
    if (status === 200) return 'status';
    if (status === 202) return 'pending';
    if (status === 400 || status === 413) return 'rejected';
    return 'ambiguous';
}

export function parseTxStatus(value: unknown): TxStatus {
    if (typeof value !== 'object' || value === null) {
        throw new Error('transaction status response must be an object');
    }

    const status = value as Record<string, unknown>;
    if (status.status === 'dropped') return { status: 'dropped' };
    if (status.status === 'finalized' && isUnsignedSafeInteger(status.height)) {
        return { status: 'finalized', height: status.height };
    }
    if (
        status.status === 'partially_finalized' &&
        isUnsignedSafeInteger(status.height) &&
        isUnsignedSafeInteger(status.included) &&
        isUnsignedSafeInteger(status.filtered)
    ) {
        return {
            status: 'partially_finalized',
            height: status.height,
            included: status.included,
            filtered: status.filtered,
        };
    }

    throw new Error('transaction status response is invalid');
}

export function singleTransactionOutcome(status: TxStatus): SingleTransactionOutcome {
    if (status.status === 'finalized') {
        return { kind: 'finalized', height: status.height };
    }
    if (status.status === 'dropped') return { kind: 'dropped' };
    if (status.included === 1 && status.filtered === 0) {
        return { kind: 'finalized', height: status.height };
    }
    if (status.included === 0 && status.filtered === 1) {
        return { kind: 'dropped' };
    }
    return {
        kind: 'ambiguous',
        detail: 'partial finalization counts do not identify the submitted transaction',
    };
}

export function isDeterministicSubmissionRejection(error: unknown): boolean {
    return error instanceof TransactionSubmissionError && error.kind === 'rejected';
}

function isUnsignedSafeInteger(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}
