export interface RefreshQueueOptions<T> {
    readonly load: (signal: AbortSignal) => Promise<T>;
    readonly onResult: (result: T) => void;
    readonly onError: (error: unknown) => void;
    readonly onLoading: (loading: boolean) => void;
}

export interface RefreshQueue {
    /** Request a refresh and wait until a load covering it completes. */
    request: () => Promise<void>;
    /** Abort the active load and ignore any late completion. */
    dispose: () => void;
}

/**
 * Run at most one refresh at a time, coalescing bursts into one trailing load.
 * Successful intermediate loads are published so a sustained event stream
 * cannot starve the UI; serialization ensures a late older load can never
 * overwrite a newer result.
 */
export function createRefreshQueue<T>(options: RefreshQueueOptions<T>): RefreshQueue {
    const controller = new AbortController();
    const waiters: Array<{ generation: number; resolve: () => void }> = [];
    let requestedGeneration = 0;
    let completedGeneration = 0;
    let running = false;
    let disposed = false;

    const settleThrough = (generation: number) => {
        while (waiters[0]?.generation <= generation) {
            waiters.shift()?.resolve();
        }
    };

    const run = async () => {
        if (running || disposed) return;
        running = true;
        options.onLoading(true);

        try {
            while (!disposed && completedGeneration < requestedGeneration) {
                const generation = requestedGeneration;
                let outcome: { readonly result: T } | { readonly error: unknown };

                try {
                    outcome = { result: await options.load(controller.signal) };
                } catch (caught) {
                    outcome = { error: caught };
                }

                completedGeneration = generation;
                if (disposed) break;

                if ('result' in outcome) {
                    options.onResult(outcome.result);
                } else if (
                    generation === requestedGeneration &&
                    !controller.signal.aborted
                ) {
                    options.onError(outcome.error);
                }
                settleThrough(generation);
            }
        } finally {
            running = false;
            if (disposed) return;
            if (completedGeneration < requestedGeneration) {
                void run();
                return;
            }
            options.onLoading(false);
        }
    };

    const request = (): Promise<void> => {
        if (disposed) return Promise.resolve();

        requestedGeneration++;
        const generation = requestedGeneration;
        const completed = new Promise<void>((resolve) => {
            waiters.push({ generation, resolve });
        });
        void run();
        return completed;
    };

    const dispose = () => {
        if (disposed) return;
        disposed = true;
        controller.abort();
        settleThrough(Number.POSITIVE_INFINITY);
        if (running) options.onLoading(false);
    };

    return { request, dispose };
}
