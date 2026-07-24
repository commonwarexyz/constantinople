const TRANSACTION_PUBLIC_KEY_BYTES = 34;
const ACCOUNT_KEY_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SCHEME = 0;
const U64_BYTES = 8;
const MAX_U64 = (1n << 64n) - 1n;
const TRANSACTION_HEADER_BYTES = TRANSACTION_PUBLIC_KEY_BYTES + U64_BYTES + 1;
const TRANSFER_TAG = 0;
const SET_COMMITTEE_MEMBER_TAG = 1;

export interface TransactionDraft {
    readonly senderPublicKey: Uint8Array;
    readonly toAccountKey: Uint8Array;
    readonly value: bigint;
    readonly nonce: bigint;
}

export interface CommitteeTransactionDraft {
    readonly senderPublicKey: Uint8Array;
    readonly nonce: bigint;
    readonly targetEpoch: bigint;
    readonly peer: string;
    readonly registered: boolean;
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

export function parseEd25519Peer(value: string): Uint8Array {
    const normalized = value.trim().replace(/^ed25519:/i, '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
        throw new Error('eligible peer must be a 32-byte Ed25519 public key');
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
    return encodeSignedBody(encodeTransferTransactionBody(draft), sign);
}

export async function encodeSignedCommitteeTransaction(
    draft: CommitteeTransactionDraft,
    sign: (message: Uint8Array) => Promise<Uint8Array>,
): Promise<EncodedTransaction> {
    return encodeSignedBody(encodeCommitteeTransactionBody(draft), sign);
}

/** Encode the canonical Rust `Action::Transfer` transaction body. */
export function encodeTransferTransactionBody(draft: TransactionDraft): Uint8Array {
    assertByteLength(
        draft.toAccountKey,
        ACCOUNT_KEY_BYTES,
        'recipient account key',
    );
    if (draft.value === 0n) {
        throw new Error('value must be greater than zero');
    }

    return bytesConcat(
        encodeTransactionHeader(draft.senderPublicKey, draft.nonce, TRANSFER_TAG),
        draft.toAccountKey,
        encodeU64Be(draft.value, 'value'),
    );
}

/** Encode the canonical Rust `Action::SetCommitteeMember` transaction body. */
export function encodeCommitteeTransactionBody(
    draft: CommitteeTransactionDraft,
): Uint8Array {
    const peer = parseEd25519Peer(draft.peer);
    return bytesConcat(
        encodeTransactionHeader(
            draft.senderPublicKey,
            draft.nonce,
            SET_COMMITTEE_MEMBER_TAG,
        ),
        encodeU64Varint(draft.targetEpoch, 'target epoch'),
        peer,
        Uint8Array.of(draft.registered ? 1 : 0),
    );
}

/**
 * Locate the consensus body within raw signed transaction bytes.
 *
 * Transfer bodies are fixed-width. Committee bodies contain a canonical u64
 * varint epoch, so their end must be decoded before hashing the body digest.
 */
export function transactionBodyFromSignedTransaction(
    signedTransaction: Uint8Array,
): Uint8Array {
    if (signedTransaction.length < TRANSACTION_HEADER_BYTES) {
        throw new Error('SQL transaction body is truncated');
    }

    const tag = signedTransaction[TRANSACTION_HEADER_BYTES - 1];
    let bodyEnd: number;
    if (tag === TRANSFER_TAG) {
        bodyEnd = TRANSACTION_HEADER_BYTES + ACCOUNT_KEY_BYTES + U64_BYTES;
        assertAvailable(signedTransaction, bodyEnd);
        if (readU64Be(signedTransaction, bodyEnd - U64_BYTES) === 0n) {
            throw new Error('SQL transfer transaction has zero value');
        }
    } else if (tag === SET_COMMITTEE_MEMBER_TAG) {
        const epochEnd = readCanonicalU64VarintEnd(
            signedTransaction,
            TRANSACTION_HEADER_BYTES,
        );
        bodyEnd = epochEnd + ED25519_PUBLIC_KEY_BYTES + 1;
        assertAvailable(signedTransaction, bodyEnd);
        const registered = signedTransaction[bodyEnd - 1];
        if (registered !== 0 && registered !== 1) {
            throw new Error('SQL committee transaction has invalid registered flag');
        }
    } else {
        throw new Error(`SQL transaction body has unknown action tag ${tag}`);
    }

    return signedTransaction.slice(0, bodyEnd);
}

export function encodeTransactionBatch(transactions: Uint8Array[]): Uint8Array {
    return bytesConcat(encodeUsize(transactions.length), ...transactions);
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

export async function accountKeyFromPublicKey(publicKey: Uint8Array): Promise<Uint8Array> {
    assertByteLength(publicKey, TRANSACTION_PUBLIC_KEY_BYTES, 'public key');
    if (publicKey[0] === ED25519_SCHEME) {
        return publicKey.slice(1, 1 + ACCOUNT_KEY_BYTES);
    }
    return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(publicKey)));
}

async function encodeSignedBody(
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

function encodeTransactionHeader(
    senderPublicKey: Uint8Array,
    nonce: bigint,
    tag: number,
): Uint8Array {
    assertByteLength(
        senderPublicKey,
        TRANSACTION_PUBLIC_KEY_BYTES,
        'sender public key',
    );
    return bytesConcat(
        senderPublicKey,
        encodeU64Be(nonce, 'nonce'),
        Uint8Array.of(tag),
    );
}

function encodeU64Be(value: bigint, field: string): Uint8Array {
    if (value < 0n || value > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }

    const bytes = new Uint8Array(U64_BYTES);
    new DataView(bytes.buffer).setBigUint64(0, value, false);
    return bytes;
}

function encodeU64Varint(value: bigint, field: string): Uint8Array {
    if (value < 0n || value > MAX_U64) {
        throw new Error(`${field} must fit in u64`);
    }

    const bytes: number[] = [];
    let remaining = value;
    while (remaining >= 0x80n) {
        bytes.push(Number(remaining & 0x7fn) | 0x80);
        remaining >>= 7n;
    }
    bytes.push(Number(remaining));
    return new Uint8Array(bytes);
}

function readCanonicalU64VarintEnd(bytes: Uint8Array, offset: number): number {
    for (let index = 0; index < 10; index++) {
        const position = offset + index;
        if (position >= bytes.length) {
            throw new Error('SQL committee transaction epoch is truncated');
        }

        const byte = bytes[position];
        if (index > 0 && byte === 0) {
            throw new Error('SQL committee transaction epoch is not canonical');
        }
        if (index === 9 && byte > 1) {
            throw new Error('SQL committee transaction epoch does not fit in u64');
        }
        if ((byte & 0x80) === 0) {
            return position + 1;
        }
    }
    throw new Error('SQL committee transaction epoch does not fit in u64');
}

function readU64Be(bytes: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let index = 0; index < U64_BYTES; index++) {
        value = (value << 8n) | BigInt(bytes[offset + index]);
    }
    return value;
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

function bytesConcat(...chunks: readonly Uint8Array[]): Uint8Array {
    const len = chunks.reduce((total, chunk) => total + chunk.length, 0);
    const out = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}

function assertAvailable(bytes: Uint8Array, end: number) {
    if (bytes.length < end) {
        throw new Error('SQL transaction body is truncated');
    }
}

function assertByteLength(bytes: Uint8Array, expected: number, label: string) {
    if (bytes.length !== expected) {
        throw new Error(`${label} must be ${expected} bytes`);
    }
}
