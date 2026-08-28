const RETRYABLE_PROOF_ERROR =
    /tx_meta missing|tx digest .* (missing at height|is not finalized yet)|finalization missing|QMDB transaction proof response missing|out_of_range|unavailable|fetch/i;

export function isRetryableProofError(detail: string): boolean {
    return RETRYABLE_PROOF_ERROR.test(detail);
}

export function isMissingAccountProofError(detail: string): boolean {
    return /^account .+ is not indexed$/.test(detail);
}

export function isRetryableAccountProofError(detail: string): boolean {
    return (
        !isMissingAccountProofError(detail) &&
        (
            detail.includes('outside finalized state range') ||
            detail.includes('not yet covered by a provable finalization') ||
            detail.includes('[out_of_range]') ||
            detail.includes('[unavailable]') ||
            detail.includes('QMDB') ||
            detail.includes('missing')
        )
    );
}
