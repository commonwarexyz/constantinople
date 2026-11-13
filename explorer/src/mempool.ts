import {
    TransactionSubmissionError,
    type SubmissionResult,
} from './submissionResponse.ts';
import { boundedSubmissionSignal, SUBMISSION_TIMEOUT_MS } from './submissionRequest.ts';
import { createExplorerClient } from './rpc.ts';

export async function submitTransactions(
    baseUrl: string,
    batch: Uint8Array,
    signal?: AbortSignal,
    timeoutMs = SUBMISSION_TIMEOUT_MS,
): Promise<SubmissionResult> {
    if (batch.byteLength > 4 * 1024 * 1024 + 5) {
        throw new TransactionSubmissionError('rejected', 'transaction batch exceeds size limit');
    }
    const request = boundedSubmissionSignal(signal, timeoutMs);
    try {
        const response = await createExplorerClient(baseUrl).submitTransaction({ batch }, {
            signal: request.signal, timeoutMs,
        });
        if (response.outcome.case === 'ambiguous') {
            throw new TransactionSubmissionError('ambiguous', response.outcome.value.reason || 'transaction delivery is uncertain');
        }
        if (response.outcome.case !== 'completed') throw new TransactionSubmissionError('ambiguous', 'transaction response is missing its outcome');
        const completed = response.outcome.value;
        const result = completed.result;
        if (completed.body.length > 64 * 1024) throw new TransactionSubmissionError('ambiguous', 'transaction response exceeds size limit');
        if ((completed.httpStatus === 400 || completed.httpStatus === 413) && result.case === 'rejected') {
            throw new TransactionSubmissionError('ambiguous', `indexer reported rejection (HTTP ${completed.httpStatus}); transaction inclusion is unknown`);
        }
        if (completed.httpStatus === 202 && result.case === 'pending') return { status: 'pending' };
        if (completed.httpStatus !== 200) throw new TransactionSubmissionError('ambiguous', `transaction returned HTTP ${completed.httpStatus}`);
        if (result.case === 'dropped') return { status: 'dropped' };
        if (result.case === 'finalized') {
            const { height, evidence } = result.value;
            return { status: 'finalized', height: safeNumber(height), ...(evidence && { evidence }) };
        }
        if (result.case === 'partiallyFinalized') return {
            status: 'partially_finalized', height: safeNumber(result.value.height),
            included: safeNumber(result.value.included), filtered: safeNumber(result.value.filtered),
        };
        throw new TransactionSubmissionError('ambiguous', 'transaction response has no valid status');
    } catch (error) {
        if (error instanceof TransactionSubmissionError && error.kind === 'ambiguous') throw error;
        throw new TransactionSubmissionError('ambiguous', error instanceof Error ? error.message : String(error));
    } finally {
        request.dispose();
    }
}

function safeNumber(value: bigint): number {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new TransactionSubmissionError('ambiguous', 'transaction status exceeds safe integer range');
    }
    return Number(value);
}
