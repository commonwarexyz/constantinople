import assert from 'node:assert/strict';
import test from 'node:test';

import { Code, ConnectError } from '@connectrpc/connect';
import { isMissingTransactionProofMetadataTable } from '../src/sqlCompatibility.ts';

const missingTable = "Error during planning: table 'datafusion.public.tx_proof_meta' not found";

test('only a missing legacy sidecar table enables compatibility fallback', () => {
    assert.equal(
        isMissingTransactionProofMetadataTable(
            new ConnectError(missingTable, Code.Internal),
        ),
        true,
    );
    assert.equal(
        isMissingTransactionProofMetadataTable(
            new ConnectError(missingTable, Code.Unavailable),
        ),
        false,
    );
    assert.equal(
        isMissingTransactionProofMetadataTable(
            new ConnectError('unrelated SQL failure', Code.Internal),
        ),
        false,
    );
});
