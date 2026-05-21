const RETRYABLE_PROOF_ERROR =
    /tx_meta missing|tx digest .* missing at height|finalization missing|QMDB transaction proof response missing|failed to decode Simplex identity|failed to decode Simplex verification material|Simplex verification material contains trailing bytes|out_of_range|unavailable|fetch/i;

export function isRetryableProofError(detail: string): boolean {
    return RETRYABLE_PROOF_ERROR.test(detail);
}
