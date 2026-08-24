export type SubmissionResponseKind = 'accepted' | 'rejected' | 'ambiguous';

export class TransactionSubmissionError extends Error {
    readonly kind: Exclude<SubmissionResponseKind, 'accepted'>;

    constructor(kind: Exclude<SubmissionResponseKind, 'accepted'>, message: string) {
        super(message);
        this.name = 'TransactionSubmissionError';
        this.kind = kind;
    }
}

export function classifySubmissionResponse(status: number): SubmissionResponseKind {
    if (status === 202) return 'accepted';
    if (status === 400 || status === 413) return 'rejected';
    return 'ambiguous';
}

export function isDeterministicSubmissionRejection(error: unknown): boolean {
    return error instanceof TransactionSubmissionError && error.kind === 'rejected';
}
