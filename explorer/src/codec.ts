const PUBLIC_KEY_BYTES = 34;
const ACCOUNT_KEY_BYTES = 32;
const ED25519_SCHEME = 0;
const U64_BYTES = 8;
const VOUCHER_SIGNATURE_BYTES = 64;
/// Operation tag for a transfer (matches `TRANSFER_TAG` in the Rust codec).
const TRANSFER_TAG = 0;
const OPEN_CHANNEL_TAG = 1;
const CLOSE_CHANNEL_TAG = 2;
const TIMEOUT_CHANNEL_TAG = 3;
const MINT_TAG = 4;
const MAX_U64 = (1n << 64n) - 1n;
/// Largest amount a single mint may credit (matches
/// `Operation::MAX_MINT_AMOUNT` in the Rust codec); the chain rejects
/// larger mints at decode.
export const MAX_MINT_AMOUNT = 1_000_000n;

export interface TransactionDraft {
    readonly senderPublicKey: Uint8Array;
    readonly toAccountKey: Uint8Array;
    readonly value: bigint;
    readonly nonce: bigint;
}

export interface EncodedTransaction {
    readonly digestHex: string;
    readonly bytes: Uint8Array;
}

export function parseAccountKeyHex(value: string): Uint8Array {
    const normalized = value.trim().replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error('expected a 32-byte account key');
    }
    return fromHex(normalized);
}

export function parseU64(value: string, field: string): bigint {
    if (!/^\d+$/.test(value.trim())) {
        throw new Error(`${field} must be an unsigned integer`);
    }

    const parsed = BigInt(value.trim());
    if (parsed > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }
    return parsed;
}

export async function encodeSignedTransaction(
    draft: TransactionDraft,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    if (draft.value === 0n) {
        throw new Error('value must be greater than zero');
    }

    return signEncodedBody(encodeTransactionBody(draft), sign);
}

/// The signing tail every transaction encoder shares: digest the body,
/// hand the digest to the signer, and append the returned scheme-tagged
/// signature.
async function signEncodedBody(
    body: Uint8Array,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body)));
    const signature = await sign(digest);
    return {
        digestHex: toHex(digest),
        bytes: bytesConcat(body, signature),
    };
}

export interface MintDraft {
    readonly senderPublicKey: Uint8Array;
    readonly amount: bigint;
    readonly nonce: bigint;
}

// A mint credits the sender out of thin air — the chain's only token source
// (accounts start empty). Wire layout matches the Rust codec: sender, nonce,
// tag, amount.
export async function encodeSignedMintTransaction(
    draft: MintDraft,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    if (draft.amount === 0n) {
        throw new Error('mint amount must be greater than zero');
    }
    if (draft.amount > MAX_MINT_AMOUNT) {
        throw new Error(`mint amount must be at most ${MAX_MINT_AMOUNT}`);
    }
    assertByteLength(draft.senderPublicKey, PUBLIC_KEY_BYTES, 'sender public key');

    const body = bytesConcat(
        draft.senderPublicKey,
        encodeU64(draft.nonce),
        Uint8Array.of(MINT_TAG),
        encodeU64(draft.amount),
    );
    return signEncodedBody(body, sign);
}

export function encodeTransactionBatch(transactions: Uint8Array[]): Uint8Array {
    return bytesConcat(encodeUsize(transactions.length), ...transactions);
}

/// Namespace every transaction signature commits to (matches
/// `TRANSACTION_NAMESPACE` in the Rust codec). The passkey path signs the raw
/// digest as its WebAuthn challenge; the ed25519 path must sign
/// `unionUnique(TRANSACTION_NAMESPACE, digest)`.
export const TRANSACTION_NAMESPACE = 'constantinople-tx';
/// Namespace every voucher signature commits to (matches `VOUCHER_NAMESPACE`).
export const VOUCHER_NAMESPACE = 'constantinople-voucher';
/// Domain separator of the channel address derivation (matches
/// `CHANNEL_ADDRESS_DOMAIN`; `-v2` marks the delegated-voucher-key
/// derivation).
const CHANNEL_ADDRESS_DOMAIN = 'constantinople-channel-v2';

/// The commonware namespace framing: `varint(len(namespace)) || namespace ||
/// message`. Ed25519 signers sign this; the chain verifies against it.
export function unionUnique(namespace: string, message: Uint8Array): Uint8Array {
    const namespaceBytes = new TextEncoder().encode(namespace);
    return bytesConcat(encodeUsize(namespaceBytes.length), namespaceBytes, message);
}

/// Wraps a raw 64-byte ed25519 signature into the chain's scheme-tagged
/// transaction signature tail.
export function ed25519TransactionSignature(rawSignature: Uint8Array): Uint8Array {
    assertByteLength(rawSignature, VOUCHER_SIGNATURE_BYTES, 'ed25519 signature');
    return bytesConcat(Uint8Array.of(ED25519_SCHEME), rawSignature);
}

/// Derives a channel's account address (matches `channel_address` in the
/// Rust codec): SHA-256 over the domain, payer, receiver, and operator
/// account keys, the delegated voucher key, and the open nonce.
export async function channelAddress(
    payerAccountKey: Uint8Array,
    receiverAccountKey: Uint8Array,
    operatorAccountKey: Uint8Array,
    voucherPublicKey: Uint8Array,
    openNonce: bigint,
): Promise<Uint8Array> {
    assertByteLength(payerAccountKey, ACCOUNT_KEY_BYTES, 'payer account key');
    assertByteLength(receiverAccountKey, ACCOUNT_KEY_BYTES, 'receiver account key');
    assertByteLength(operatorAccountKey, ACCOUNT_KEY_BYTES, 'operator account key');
    assertByteLength(voucherPublicKey, ACCOUNT_KEY_BYTES, 'voucher public key');
    const preimage = bytesConcat(
        new TextEncoder().encode(CHANNEL_ADDRESS_DOMAIN),
        payerAccountKey,
        receiverAccountKey,
        operatorAccountKey,
        voucherPublicKey,
        encodeU64(openNonce),
    );
    return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(preimage)));
}

/// The exact bytes a voucher's ed25519 signature must be made over,
/// including the namespace framing (matches `voucher_message` +
/// `VOUCHER_NAMESPACE` in the Rust codec).
export function voucherSigningPayload(channel: Uint8Array, cumulative: bigint): Uint8Array {
    assertByteLength(channel, ACCOUNT_KEY_BYTES, 'channel account key');
    return unionUnique(VOUCHER_NAMESPACE, bytesConcat(channel, encodeU64(cumulative)));
}

export interface OpenChannelDraft {
    readonly senderPublicKey: Uint8Array;
    readonly receiverAccountKey: Uint8Array;
    readonly operatorAccountKey: Uint8Array;
    /// The delegated ed25519 key that will sign this channel's vouchers.
    readonly voucherPublicKey: Uint8Array;
    readonly deposit: bigint;
    readonly expiry: bigint;
    readonly nonce: bigint;
}

/// Encodes and signs an OpenChannel transaction. Wire layout matches the
/// Rust codec: sender, nonce, tag, receiver, operator, voucher key, deposit,
/// expiry. The `sign` callback receives the body digest (like the transfer
/// encoder); an ed25519 signer must namespace it itself via
/// `unionUnique(TRANSACTION_NAMESPACE, digest)`.
export async function encodeSignedOpenChannelTransaction(
    draft: OpenChannelDraft,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    if (draft.deposit === 0n) {
        throw new Error('deposit must be greater than zero');
    }
    assertByteLength(draft.senderPublicKey, PUBLIC_KEY_BYTES, 'sender public key');
    assertByteLength(draft.receiverAccountKey, ACCOUNT_KEY_BYTES, 'receiver account key');
    assertByteLength(draft.operatorAccountKey, ACCOUNT_KEY_BYTES, 'operator account key');
    assertByteLength(draft.voucherPublicKey, ACCOUNT_KEY_BYTES, 'voucher public key');

    const body = bytesConcat(
        draft.senderPublicKey,
        encodeU64(draft.nonce),
        Uint8Array.of(OPEN_CHANNEL_TAG),
        draft.receiverAccountKey,
        draft.operatorAccountKey,
        draft.voucherPublicKey,
        encodeU64(draft.deposit),
        encodeU64(draft.expiry),
    );
    return signEncodedBody(body, sign);
}

export interface TimeoutChannelDraft {
    readonly senderPublicKey: Uint8Array;
    readonly receiverAccountKey: Uint8Array;
    readonly operatorAccountKey: Uint8Array;
    /// The delegated voucher key the channel was opened with.
    readonly voucherPublicKey: Uint8Array;
    readonly openNonce: bigint;
    readonly nonce: bigint;
}

/// Encodes and signs a TimeoutChannel transaction — the payer (sender)
/// reclaiming an expired channel's escrow. Wire layout matches the Rust
/// codec: sender, nonce, tag, receiver, operator, voucher key, open nonce.
export async function encodeSignedTimeoutChannelTransaction(
    draft: TimeoutChannelDraft,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    assertByteLength(draft.senderPublicKey, PUBLIC_KEY_BYTES, 'sender public key');
    assertByteLength(draft.receiverAccountKey, ACCOUNT_KEY_BYTES, 'receiver account key');
    assertByteLength(draft.operatorAccountKey, ACCOUNT_KEY_BYTES, 'operator account key');
    assertByteLength(draft.voucherPublicKey, ACCOUNT_KEY_BYTES, 'voucher public key');

    const body = bytesConcat(
        draft.senderPublicKey,
        encodeU64(draft.nonce),
        Uint8Array.of(TIMEOUT_CHANNEL_TAG),
        draft.receiverAccountKey,
        draft.operatorAccountKey,
        draft.voucherPublicKey,
        encodeU64(draft.openNonce),
    );
    return signEncodedBody(body, sign);
}

export function toHex(bytes: Uint8Array): string {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(bytes.length);
    copy.set(bytes);
    return copy.buffer;
}

export function fromHex(value: string): Uint8Array {
    const bytes = new Uint8Array(value.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

export function signedTransactionBodyLength(bytes: Uint8Array): number {
    const common = PUBLIC_KEY_BYTES + U64_BYTES;
    if (bytes.length <= common) {
        throw new Error('SQL transaction body is truncated');
    }

    switch (bytes[common]) {
        // Transfer: recipient account key + value.
        case TRANSFER_TAG:
            return common + 1 + ACCOUNT_KEY_BYTES + U64_BYTES;
        // TimeoutChannel: receiver account key + operator account key +
        // voucher key + open nonce.
        case TIMEOUT_CHANNEL_TAG:
            return common + 1 + ACCOUNT_KEY_BYTES * 3 + U64_BYTES;
        // OpenChannel: receiver account key + operator account key +
        // voucher key + deposit + expiry.
        case OPEN_CHANNEL_TAG:
            return common + 1 + ACCOUNT_KEY_BYTES * 3 + U64_BYTES + U64_BYTES;
        // Mint: amount only.
        case MINT_TAG:
            return common + 1 + U64_BYTES;
        // CloseChannel: payer account key + receiver account key + voucher
        // key + open nonce + cumulative + voucher signature.
        case CLOSE_CHANNEL_TAG:
            return (
                common +
                1 +
                ACCOUNT_KEY_BYTES * 3 +
                U64_BYTES +
                U64_BYTES +
                VOUCHER_SIGNATURE_BYTES
            );
        default:
            throw new Error('SQL transaction body has unknown operation tag');
    }
}

function encodeTransactionBody(draft: TransactionDraft): Uint8Array {
    assertByteLength(draft.senderPublicKey, PUBLIC_KEY_BYTES, 'sender public key');
    assertByteLength(draft.toAccountKey, ACCOUNT_KEY_BYTES, 'recipient account key');

    // Wire layout must match the Rust codec (crates/primitives/src/transaction.rs):
    // sender, nonce, then the tagged operation. A transfer is tag 0 followed by
    // the recipient account key and the value.
    return bytesConcat(
        draft.senderPublicKey,
        encodeU64(draft.nonce),
        Uint8Array.of(TRANSFER_TAG),
        draft.toAccountKey,
        encodeU64(draft.value),
    );
}

export async function accountKeyFromPublicKey(publicKey: Uint8Array): Promise<Uint8Array> {
    assertByteLength(publicKey, PUBLIC_KEY_BYTES, 'public key');
    if (publicKey[0] === ED25519_SCHEME) {
        return publicKey.slice(1, 1 + ACCOUNT_KEY_BYTES);
    }
    return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(publicKey)));
}

function encodeU64(value: bigint): Uint8Array {
    if (value < 0n || value > MAX_U64) {
        throw new Error('u64 value out of range');
    }

    const bytes = new Uint8Array(U64_BYTES);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

function encodeUsize(value: number): Uint8Array {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
        throw new Error('usize value out of range');
    }

    const bytes: number[] = [];
    let next = value;
    while (next >= 0x80) {
        bytes.push((next & 0x7f) | 0x80);
        next = Math.floor(next / 0x80);
    }
    bytes.push(next);
    return new Uint8Array(bytes);
}

function bytesConcat(...chunks: Uint8Array[]): Uint8Array {
    const len = chunks.reduce((total, chunk) => total + chunk.length, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function assertByteLength(bytes: Uint8Array, expected: number, label: string) {
    if (bytes.length !== expected) {
        throw new Error(`${label} must be ${expected} bytes`);
    }
}
