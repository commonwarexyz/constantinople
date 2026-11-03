import { Code, ConnectError } from '@connectrpc/connect';
import { errorMessage, isRetryableProofError, NETWORK_RECONNECT_DELAY_MS, waitForRetry } from './proofRetry.ts';
import { createBlockBatchVerifier, type VerifiedBlockBatch } from './proofBundle.ts';
import { createExplorerClient } from './rpc.ts';

export type { VerifiedBlock, VerifiedBlockBatch } from './proofBundle.ts';

export interface SubscribeBlocksOptions {
    readonly simplexVerificationMaterial: string;
    readonly after?: 0n;
    readonly signal?: AbortSignal;
    readonly reconnectDelayMs?: number;
    readonly onError?: (message: string) => void;
    readonly onReconnect?: () => void;
}

export async function* subscribeBlocks(
    indexerUrl: string,
    options: SubscribeBlocksOptions,
): AsyncGenerator<VerifiedBlockBatch, void, void> {
    if (options.signal?.aborted) return;
    const verifier = createBlockBatchVerifier(options.simplexVerificationMaterial, options.after);
    const client = createExplorerClient(indexerUrl);
    const controller = new AbortController();
    const abort = () => controller.abort(options.signal?.reason);
    options.signal?.addEventListener('abort', abort, { once: true });

    try {
        while (!controller.signal.aborted) {
            options.onReconnect?.();
            try {
                const blocks = client.watchBlocks(
                    verifier.after === undefined ? {} : { after: verifier.after },
                    { signal: controller.signal },
                );
                for await (const message of blocks) {
                    if (controller.signal.aborted) return;
                    const batch = await verifier.verify(message, controller.signal);
                    if (controller.signal.aborted) return;
                    if (batch) yield batch;
                }
                if (controller.signal.aborted) return;
                throw new ConnectError('block feed closed', Code.Unavailable);
            } catch (error) {
                if (controller.signal.aborted) return;
                options.onError?.(errorMessage(error));
                if (!isRetryableProofError(error)) throw error;
            }
            if (!(await waitForRetry(options.reconnectDelayMs ?? NETWORK_RECONNECT_DELAY_MS, controller.signal))) return;
        }
    } finally {
        options.signal?.removeEventListener('abort', abort);
        abort();
    }
}
