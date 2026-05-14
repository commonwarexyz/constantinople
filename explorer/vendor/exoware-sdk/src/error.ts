import type { Code, ConnectError } from '@connectrpc/connect';

/**
 * The base error type for the SDK.
 */
export class ExowareError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'ExowareError';
    }
}

/**
 * An error representing an HTTP error response from the server.
 * Access `.connectCode` for the original connect-rpc error code
 * and `.cause` for the full `ConnectError` with structured details.
 */
export class HttpError extends ExowareError {
    public readonly connectCode: Code;

    constructor(public status: number, message: string, connectCode: Code, cause: ConnectError) {
        super(`HTTP error: ${status} ${message}`, { cause });
        this.name = 'HttpError';
        this.connectCode = connectCode;
    }
}
