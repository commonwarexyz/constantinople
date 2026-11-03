// Relayer reports do not establish transaction inclusion or non-inclusion.
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
    | { readonly kind: 'ambiguous'; readonly detail: string };

type SubmissionFailureKind = 'rejected' | 'ambiguous';

export class TransactionSubmissionError extends Error {
    readonly kind: SubmissionFailureKind;

    constructor(
        kind: SubmissionFailureKind,
        message: string,
    ) {
        super(message);
        this.name = 'TransactionSubmissionError';
        this.kind = kind;
    }
}

export function singleTransactionOutcome(status: TxStatus): SingleTransactionOutcome {
    if (status.status === 'finalized') {
        return { kind: 'finalized', height: status.height };
    }
    if (status.status === 'dropped') {
        return {
            kind: 'ambiguous',
            detail: 'indexer reported transaction dropped; transaction inclusion is unknown',
        };
    }
    if (status.included === 1 && status.filtered === 0) {
        return { kind: 'finalized', height: status.height };
    }
    if (status.included === 0) {
        return {
            kind: 'ambiguous',
            detail: 'indexer reported no included transaction; transaction inclusion is unknown',
        };
    }
    return {
        kind: 'ambiguous',
        detail: 'partial finalization counts do not identify the submitted transaction',
    };
}

export function isDeterministicSubmissionRejection(error: unknown): boolean {
    return error instanceof TransactionSubmissionError && error.kind === 'rejected';
}
