import { createClient, type Client as ConnectClient, type Interceptor, Code, ConnectError } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { StoreClient, type StoreKeyPrefix } from './store.js';
import { Service as CompactService } from './gen/ts/store/v1/compact_pb.js';
import { Service as IngestService } from './gen/ts/store/v1/ingest_pb.js';
import { Service as QueryService } from './gen/ts/store/v1/query_pb.js';
import { Service as StreamService } from './gen/ts/store/v1/stream_pb.js';

export type RetryConfig = {
    maxAttempts: number;
    initialBackoffMs: number;
    maxBackoffMs: number;
};

const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxAttempts: 3,
    initialBackoffMs: 100,
    maxBackoffMs: 2000,
};

const RETRYABLE_CODES = new Set<Code>([
    Code.Aborted,
    Code.Unavailable,
    Code.ResourceExhausted,
]);

function retryBackoffDelay(attempt: number, config: RetryConfig): number {
    const exponent = Math.min(Math.max(attempt - 1, 0), 20);
    const baseMs = config.initialBackoffMs * (1 << exponent);
    const cappedMs = Math.min(baseMs, config.maxBackoffMs);
    const jitter = cappedMs * (0.5 + 0.5 * Math.random());
    return Math.round(jitter);
}

function makeRetryInterceptor(config: RetryConfig): Interceptor {
    const maxAttempts = Math.max(config.maxAttempts, 1);
    return (next) => async (req) => {
        let attempt = 1;
        for (;;) {
            try {
                return await next(req);
            } catch (err) {
                if (
                    attempt < maxAttempts &&
                    err instanceof ConnectError &&
                    RETRYABLE_CODES.has(err.code)
                ) {
                    const delay = retryBackoffDelay(attempt, config);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                    attempt++;
                    continue;
                }
                throw err;
            }
        }
    };
}

export type ClientOptions = {
    token?: string;
    retry?: RetryConfig;
};

function normalizeClientOptions(tokenOrOptions?: string | ClientOptions): ClientOptions {
    return typeof tokenOrOptions === 'string' ? { token: tokenOrOptions } : tokenOrOptions ?? {};
}

export function createTransport(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
    const opts = normalizeClientOptions(tokenOrOptions);
    const retryConfig = opts.retry ?? DEFAULT_RETRY_CONFIG;
    const interceptors: Interceptor[] = [];
    if (opts.token !== undefined) {
        const token = opts.token;
        interceptors.push((next) => async (req) => {
            req.header.set('Authorization', `Bearer ${token}`);
            return next(req);
        });
    }
    interceptors.push(makeRetryInterceptor(retryConfig));
    return createConnectTransport({
        baseUrl: baseUrl.replace(/\/$/, ''),
        interceptors,
    });
}

export class Client {
    public readonly baseUrl: string;
    public readonly compact: ConnectClient<typeof CompactService>;
    public readonly ingest: ConnectClient<typeof IngestService>;
    public readonly query: ConnectClient<typeof QueryService>;
    public readonly stream: ConnectClient<typeof StreamService>;
    public readonly retryConfig: RetryConfig;

    constructor(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
        const opts = normalizeClientOptions(tokenOrOptions);
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.retryConfig = opts.retry ?? DEFAULT_RETRY_CONFIG;
        const transport = createTransport(this.baseUrl, opts);
        this.compact = createClient(CompactService, transport);
        this.ingest = createClient(IngestService, transport);
        this.query = createClient(QueryService, transport);
        this.stream = createClient(StreamService, transport);
    }

    public store(prefix?: StoreKeyPrefix): StoreClient {
        return new StoreClient(this, prefix);
    }
}
