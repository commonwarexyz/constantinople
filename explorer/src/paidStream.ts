// Pure logic of the paid-stream client: how the browser prices channels,
// paces vouchers against the operator's advertised debt limit, and parses
// the stream's SSE payloads. Kept free of fetch/EventSource so `node --test`
// covers every decision (the I/O lives in operatorClient.ts).

/// Blocks of slack added over the operator's margins when picking a channel
/// expiry. Interactive sessions are human-paced, so the runway must survive
/// minutes of reading (and pauses), not a spammer's tight loop. After the
/// expiry the payer can reclaim any unsettled remainder unilaterally.
export const CHANNEL_EXPIRY_SLACK = 7_200n;

/// The operator's `/public-key` advertisement, parsed.
export interface OperatorAdvertisement {
    readonly publicKeyHex: string;
    readonly accountHex: string;
    readonly height: bigint;
    readonly minRunway: bigint;
    readonly settleMargin: bigint;
    readonly pricePerToken: bigint;
    readonly debtLimit: bigint;
}

/// Parses the `/public-key` response, rejecting advertisements that miss a
/// knob (a zero-default would silently misprice the session).
export function parseAdvertisement(body: unknown): OperatorAdvertisement {
    const record = asRecord(body, 'operator advertisement');
    return {
        publicKeyHex: stringField(record, 'public_key'),
        accountHex: stringField(record, 'account'),
        height: numberField(record, 'height'),
        minRunway: numberField(record, 'min_runway'),
        settleMargin: numberField(record, 'settle_margin'),
        pricePerToken: numberField(record, 'price_per_token'),
        debtLimit: numberField(record, 'debt_limit'),
    };
}

/// Picks an expiry for a fresh channel from the operator's advertised
/// margins (mirrors the spammer's `channel_expiry_runway`, with interactive
/// slack).
export function channelExpiry(advertisement: OperatorAdvertisement): bigint {
    return (
        advertisement.height +
        advertisement.minRunway +
        advertisement.settleMargin +
        CHANNEL_EXPIRY_SLACK
    );
}

/// Everything the voucher decision depends on.
export interface VoucherPolicyInputs {
    /// Tokens the operator reports served.
    readonly served: bigint;
    /// Cumulative of the last voucher the operator acknowledged.
    readonly paid: bigint;
    /// Highest cumulative this client already signed. An accepted post may
    /// not be reflected in `paid` yet, so the policy never signs below it —
    /// the operator rejects non-monotonic vouchers.
    readonly lastSigned: bigint;
    /// A cumulative the operator permanently rejected; signing it again
    /// would just repeat the rejection on every chunk.
    readonly deadTarget: bigint | null;
    readonly debtLimit: bigint;
    readonly deposit: bigint;
}

/// Decides whether the payer should sign a fresh voucher, and for how much.
///
/// Policy: once the unpaid debt reaches half the operator's window, pay up
/// to half a window *ahead* of what was served, so payment stays in front of
/// the stream and the pause path only triggers when payments actually stop.
/// The cumulative never exceeds the deposit (the chain would reject the
/// voucher). Returns the new cumulative to sign, or null if no voucher is
/// due.
export function voucherTopUp(inputs: VoucherPolicyInputs): bigint | null {
    const paid = inputs.paid > inputs.lastSigned ? inputs.paid : inputs.lastSigned;
    const debt = inputs.served > paid ? inputs.served - paid : 0n;
    if (debt * 2n < inputs.debtLimit) {
        return null;
    }
    let target = inputs.served + inputs.debtLimit / 2n;
    if (target > inputs.deposit) {
        target = inputs.deposit;
    }
    if (target <= paid || target === inputs.deadTarget) {
        return null;
    }
    return target;
}

/// An account's nonce state, as the relayer facade reports it.
export interface NonceState {
    readonly base: bigint;
    /// Used future nonces relative to `base`: bit 0 records `base + 1`, bit
    /// 63 records `base + 64` (the mirror of `Nonce` in `account.rs`).
    readonly bitmap: bigint;
}

/// Whether `nonce` has already been consumed by the account: below the base,
/// or recorded in the run-ahead bitmap (the mirror of `Nonce::is_consumed`).
export function nonceConsumed(state: NonceState, nonce: bigint): boolean {
    if (nonce < state.base) {
        return true;
    }
    const delta = nonce - state.base;
    return delta !== 0n && delta <= 64n && ((state.bitmap >> (delta - 1n)) & 1n) === 1n;
}

/// Serializes the `POST /channels` body (`RegisterRequest` in
/// `operator_api.rs`); pinned to the Rust wire contract by the fixture
/// suite, like the parsers below.
export function registerRequestBody(request: {
    readonly channelHex: string;
    readonly payerHex: string;
    readonly openNonce: bigint;
    readonly openTxDigestHex: string;
}): string {
    return JSON.stringify({
        channel: request.channelHex,
        payer: request.payerHex,
        open_nonce: wireU64('open_nonce', request.openNonce),
        open_tx_digest: request.openTxDigestHex,
    });
}

/// Serializes the `POST /vouchers` body (`VoucherRequest`).
export function voucherRequestBody(request: {
    readonly channelHex: string;
    readonly cumulative: bigint;
    readonly signatureHex: string;
}): string {
    return JSON.stringify({
        channel: request.channelHex,
        cumulative: wireU64('cumulative', request.cumulative),
        signature: request.signatureHex,
    });
}

/// Serializes the `POST /settle` body (`SettleRequest`).
export function settleRequestBody(channelHex: string): string {
    return JSON.stringify({ channel: channelHex });
}

/// Serializes a u64 wire field: JSON carries u64s as numbers, so a value
/// past 2^53 fails loudly instead of silently rounding (the outbound mirror
/// of `numberField`).
function wireU64(field: string, value: bigint): number {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${field} is outside the JSON-safe integer range`);
    }
    return Number(value);
}

/// SSE event names on `GET /stream`, pinned to the Rust wire contract
/// (`operator_api.rs`) by the fixture suite.
export const STREAM_CHUNK_EVENT = 'chunk';
export const STREAM_PAYMENT_REQUIRED_EVENT = 'payment-required';
export const STREAM_END_EVENT = 'end';
/// Every way a stream can end, exactly as the wire spells it (serde
/// snake_case of `StreamEndReason`) — pinned by the fixture suite.
export const STREAM_END_REASONS = [
    'complete',
    'payment_timeout',
    'deposit_exhausted',
    'channel_closed',
] as const;

/// One `chunk` SSE event: the next slice of content plus the meter.
export interface StreamChunk {
    readonly text: string;
    readonly served: bigint;
    readonly paid: bigint;
}

/// The `payment-required` SSE event: the stream paused at the debt limit.
export interface StreamMeter {
    readonly served: bigint;
    readonly paid: bigint;
}

/// The terminal `end` SSE event.
export interface StreamEnd {
    readonly reason: (typeof STREAM_END_REASONS)[number];
    readonly served: bigint;
    readonly paid: bigint;
}

export function parseStreamChunk(data: string): StreamChunk {
    const record = asRecord(JSON.parse(data), 'stream chunk');
    const text = record.text;
    if (typeof text !== 'string') {
        throw new Error('stream chunk text must be a string');
    }
    return { text, ...parseMeter(record) };
}

export function parseStreamMeter(data: string): StreamMeter {
    return parseMeter(asRecord(JSON.parse(data), 'stream meter'));
}

export function parseStreamEnd(data: string): StreamEnd {
    const record = asRecord(JSON.parse(data), 'stream end');
    const reason = record.reason;
    if (
        typeof reason !== 'string' ||
        !(STREAM_END_REASONS as readonly string[]).includes(reason)
    ) {
        throw new Error(`unknown stream end reason: ${String(reason)}`);
    }
    return { reason: reason as StreamEnd['reason'], ...parseMeter(record) };
}

/// The `POST /settle` response.
export interface SettleOutcome {
    readonly settled: boolean;
    readonly cumulative: bigint;
}

export function parseSettleOutcome(body: unknown): SettleOutcome {
    const record = asRecord(body, 'settle outcome');
    const settled = record.settled;
    if (typeof settled !== 'boolean') {
        throw new Error('settled must be a boolean');
    }
    return { settled, cumulative: numberField(record, 'cumulative') };
}

function parseMeter(record: Record<string, unknown>): StreamMeter {
    return {
        served: numberField(record, 'served'),
        paid: numberField(record, 'paid'),
    };
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${what} must be a JSON object`);
    }
    return value as Record<string, unknown>;
}

function stringField(record: Record<string, unknown>, field: string): string {
    const value = record[field];
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${field} must be a non-empty string`);
    }
    return value;
}

/// Wire u64s arrive as JSON numbers; a value past 2^53 fails the safe-integer
/// check loudly instead of rounding.
function numberField(record: Record<string, unknown>, field: string): bigint {
    const value = record[field];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${field} must be an unsigned integer`);
    }
    return BigInt(value);
}
