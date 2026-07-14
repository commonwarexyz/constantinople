// HTTP/SSE client for the channel operator (the I/O half of the paid-stream
// demo; the decisions live in paidStream.ts). Follows the operator's retry
// contract: 400 is permanent, 503 is transient, and 402 on /stream means
// "no servable channel".

import { toHex } from './codec';
import {
    OperatorAdvertisement,
    OperatorStatsSnapshot,
    STREAM_CHUNK_EVENT,
    STREAM_END_EVENT,
    STREAM_PAYMENT_REQUIRED_EVENT,
    SettleOutcome,
    StreamChunk,
    StreamEnd,
    StreamMeter,
    parseAdvertisement,
    parseRegisterCapability,
    parseSettleOutcome,
    parseStats,
    parseStreamChunk,
    parseStreamEnd,
    parseStreamMeter,
    registerRequestBody,
    settleRequestBody,
    streamRequestQuery,
    voucherRequestBody,
} from './paidStream';
import { sleep, trimTrailingSlash } from './util';

/// Registration retry discipline: an interactive local deployment may need
/// several blocks for the finalized open to reach the operator's indexer.
/// Give it thirty seconds before handing the retry back to the user.
const REGISTRATION_ATTEMPTS = 60;
const REGISTRATION_BACKOFF_MS = 500;
/// Consecutive EventSource reconnect failures before a stream is abandoned.
const MAX_STREAM_RECONNECTS = 3;

export class OperatorRequestError extends Error {
    constructor(
        message: string,
        /// Whether a retry of the same request may succeed.
        readonly transient: boolean,
    ) {
        super(message);
    }
}

async function requestJson(url: string, init?: RequestInit): Promise<unknown> {
    let response: Response;
    try {
        response = await fetch(url, init);
    } catch (error) {
        throw new OperatorRequestError(`operator unreachable: ${String(error)}`, true);
    }
    const body: unknown = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error =
            typeof body === 'object' && body !== null && 'error' in body
                ? String((body as { error: unknown }).error)
                : `operator answered ${response.status}`;
        throw new OperatorRequestError(error, response.status >= 500);
    }
    return body;
}

export async function fetchAdvertisement(operatorUrl: string): Promise<OperatorAdvertisement> {
    const body = await requestJson(`${trimTrailingSlash(operatorUrl)}/public-key`);
    return parseAdvertisement(body);
}

export async function fetchStats(operatorUrl: string): Promise<OperatorStatsSnapshot> {
    const body = await requestJson(`${trimTrailingSlash(operatorUrl)}/stats`);
    return parseStats(body);
}

/// Registers a finalized channel open, retrying through indexer lag. The
/// operator derives the channel from the verified open; the zero-voucher
/// signature proves this client holds the channel's voucher key and gives
/// the operator a starting voucher.
export async function registerChannel(
    operatorUrl: string,
    request: {
        openTxDigestHex: string;
        zeroVoucherSignature: Uint8Array;
    },
): Promise<string> {
    const payload = registerRequestBody({
        openTxDigestHex: request.openTxDigestHex,
        zeroVoucherSignatureHex: toHex(request.zeroVoucherSignature),
    });
    for (let attempt = 1; ; attempt++) {
        try {
            const body = await requestJson(`${trimTrailingSlash(operatorUrl)}/channels`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: payload,
            });
            return parseRegisterCapability(body);
        } catch (error) {
            const retryable =
                error instanceof OperatorRequestError &&
                error.transient &&
                attempt < REGISTRATION_ATTEMPTS;
            if (!retryable) {
                throw error;
            }
            await sleep(REGISTRATION_BACKOFF_MS);
        }
    }
}

export async function postVoucher(
    operatorUrl: string,
    request: { channel: Uint8Array; cumulative: bigint; signature: Uint8Array },
): Promise<void> {
    await requestJson(`${trimTrailingSlash(operatorUrl)}/vouchers`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: voucherRequestBody({
            channelHex: toHex(request.channel),
            cumulative: request.cumulative,
            signatureHex: toHex(request.signature),
        }),
    });
}

export async function settleChannel(
    operatorUrl: string,
    channel: Uint8Array,
    capability: string,
): Promise<SettleOutcome> {
    const body = await requestJson(`${trimTrailingSlash(operatorUrl)}/settle`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: settleRequestBody(toHex(channel), capability),
    });
    return parseSettleOutcome(body);
}

export interface StreamHandlers {
    readonly onChunk: (chunk: StreamChunk) => void;
    readonly onPaymentRequired: (meter: StreamMeter) => void;
    readonly onEnd: (end: StreamEnd) => void;
    /// Transport-level failure (the operator vanished mid-stream).
    readonly onError: (message: string) => void;
}

/// Opens the metered SSE stream. Returns a close function; the stream also
/// closes itself after the terminal `end` event.
export function openStream(
    operatorUrl: string,
    channel: Uint8Array,
    capability: string,
    handlers: StreamHandlers,
): () => void {
    const query = streamRequestQuery(toHex(channel), capability);
    const source = new EventSource(`${trimTrailingSlash(operatorUrl)}/stream?${query}`);
    const guarded = (parse: (data: string) => void) => (event: MessageEvent<string>) => {
        try {
            parse(event.data);
        } catch (error) {
            source.close();
            handlers.onError(String(error));
        }
    };
    source.addEventListener(
        STREAM_CHUNK_EVENT,
        guarded((data) => handlers.onChunk(parseStreamChunk(data))),
    );
    source.addEventListener(
        STREAM_PAYMENT_REQUIRED_EVENT,
        guarded((data) => handlers.onPaymentRequired(parseStreamMeter(data))),
    );
    source.addEventListener(
        STREAM_END_EVENT,
        guarded((data) => {
            source.close();
            handlers.onEnd(parseStreamEnd(data));
        }),
    );
    // A non-200 response (the 402 handshake included) fails the connection
    // outright (CLOSED). Network-level failures instead put EventSource in
    // CONNECTING and it retries forever — resume is safe (the server derives
    // content position from the channel's persistent meter), but the user
    // must not be left watching a live cursor while the operator is gone, so
    // give up after a few consecutive failures.
    let failures = 0;
    source.onopen = () => {
        failures = 0;
    };
    source.onerror = () => {
        if (source.readyState === EventSource.CLOSED) {
            handlers.onError('stream connection closed');
            return;
        }
        failures += 1;
        if (failures >= MAX_STREAM_RECONNECTS) {
            source.close();
            handlers.onError('operator unreachable — stream abandoned');
        }
    };
    return () => source.close();
}
