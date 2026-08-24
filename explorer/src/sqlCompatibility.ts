import { Code, ConnectError } from '@connectrpc/connect';

export function isMissingTransactionProofMetadataTable(error: unknown): boolean {
    return (
        error instanceof ConnectError &&
        error.code === Code.Internal &&
        error.rawMessage ===
            "Error during planning: table 'datafusion.public.tx_proof_meta' not found"
    );
}
