export const SUBMISSION_TIMEOUT_MS = 12_000;

export function boundedSubmissionSignal(
    callerSignal: AbortSignal | undefined,
    timeoutMs: number,
): { readonly signal: AbortSignal; readonly dispose: () => void } {
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort(callerSignal?.reason);
    if (callerSignal?.aborted) {
        abortFromCaller();
    } else {
        callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
    }
    const timer = globalThis.setTimeout(
        () => controller.abort(new Error('transaction submission request timed out')),
        timeoutMs,
    );

    return {
        signal: controller.signal,
        dispose: () => {
            globalThis.clearTimeout(timer);
            callerSignal?.removeEventListener('abort', abortFromCaller);
        },
    };
}
