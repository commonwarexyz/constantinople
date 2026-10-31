import { bytesEqual, fromHex, toArrayBuffer } from './codec.ts';
import type { VerifiedSimplexCertificate, SimplexCertificateVerifier } from '@exowarexyz/simplex';
import { createWasmSimplexVerifier } from '@exowarexyz/simplex/wasm';

const CONSENSUS_NAMESPACE = new TextEncoder().encode('constantinople_CONSENSUS');
const SIMPLEX_SCHEME = 'bls12381-threshold-standard-min-sig';
const DIGEST_BYTES = 32;
const COMMITMENT_BYTES = 3 * DIGEST_BYTES + 4;
const ED25519_PUBLIC_KEY_BYTES = 32;
const ACCOUNT_VALUE_BYTES = 24;
const U64_BYTES = 8;

export interface VerifiedTransactionProof {
    readonly location: bigint;
    readonly tip: bigint;
    readonly height: bigint;
    readonly view: bigint;
    readonly proofSizeBytes: number;
}

export interface VerifiedFinalizationTarget {
    readonly height: bigint;
    readonly view: bigint;
}

interface FinalizedTransactionTarget {
    readonly height: bigint;
    readonly view: bigint;
    readonly blockDigest: Uint8Array;
    readonly stateRoot: Uint8Array;
    readonly stateStart: bigint;
    readonly stateTip: bigint;
    readonly transactionsRoot: Uint8Array;
    readonly transactionsStart: bigint;
    readonly transactionsTip: bigint;
}

export interface LatestProofTarget extends FinalizedTransactionTarget {
    readonly sequenceNumber: bigint;
}

export type AccountActivityMode = 'all' | 'sent' | 'received';

export interface AccountTransactionRow {
    readonly digest: string;
    readonly direction: 'sent' | 'received';
    readonly counterparty: string;
    readonly value: bigint;
    readonly nonce: bigint;
    readonly height: bigint;
    readonly blockIndex: number;
    readonly location: bigint;
}

export interface AccountTransactionPage {
    readonly rows: AccountTransactionRow[];
    readonly nextCursor: Uint8Array | null;
}

export interface VerifiedAccountProof {
    readonly balance: bigint;
    readonly nonce: bigint;
    readonly nonceBitmap: bigint;
    readonly location: bigint;
    readonly tip: bigint;
    readonly proofSizeBytes: number;
}

// The parent digest authenticates ancestor headers and exact transaction bounds.
interface AuthenticatedTarget extends FinalizedTransactionTarget {
    readonly parentDigest: Uint8Array;
}

export async function authenticatedHeader(
    bytes: Uint8Array,
    digest: Uint8Array,
    height: bigint,
): Promise<DecodedBlockHeader> {
    const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes)));
    if (!bytesEqual(actual, digest)) {
        throw new Error(`block header at height ${height} does not match its certified digest`);
    }
    const header = decodeBlockHeader(bytes, 0);
    if (header.endOffset !== bytes.length) {
        throw new Error(`block header at height ${height} has trailing bytes`);
    }
    if (header.height !== height) {
        throw new Error(`block header height ${header.height} does not match chain height ${height}`);
    }
    return header;
}

export function simplexFinalizationVerifier(
    simplexVerificationMaterial: string,
): Promise<SimplexCertificateVerifier<VerifiedSimplexCertificate, VerifiedSimplexCertificate>> {
    return createWasmSimplexVerifier({
        scheme: SIMPLEX_SCHEME,
        payload: 'coding-commitment',
        identity: 'ed25519',
        namespace: CONSENSUS_NAMESPACE,
        verificationMaterial: fromHex(simplexVerificationMaterial),
    });
}

export async function finalizedTargetFromCertificate(
    certificate: VerifiedSimplexCertificate,
): Promise<AuthenticatedTarget> {
    const certified = certificate.header;
    if (certificate.payload.length !== COMMITMENT_BYTES) {
        throw new Error(`certified commitment must be ${COMMITMENT_BYTES} bytes`);
    }
    if (certified.length <= COMMITMENT_BYTES) {
        throw new Error('finalized artifact is missing certified header bytes');
    }
    const encodedCommitment = certified.slice(0, COMMITMENT_BYTES);
    if (!bytesEqual(encodedCommitment, certificate.payload)) {
        throw new Error('finalized artifact commitment does not match certificate payload');
    }

    const blockStart = COMMITMENT_BYTES;
    const header = decodeBlockHeader(certified, blockStart);
    if (header.endOffset !== certified.length) {
        throw new Error('finalized block header has trailing bytes');
    }
    const headerDigest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', toArrayBuffer(certified.slice(blockStart, header.endOffset))),
    );
    const blockDigest = certificate.payload.slice(0, DIGEST_BYTES);
    if (!bytesEqual(headerDigest, blockDigest)) {
        throw new Error('certified commitment does not match finalized block header digest');
    }

    return {
        height: header.height,
        view: certificate.view,
        transactionsRoot: header.transactionsRoot,
        transactionsStart: header.transactionsStart,
        transactionsTip: header.transactionsTip,
        stateRoot: header.stateRoot,
        stateStart: header.stateStart,
        stateTip: header.stateTip,
        blockDigest,
        parentDigest: header.parentDigest,
    };
}

export interface DecodedBlockHeader {
    readonly view: bigint;
    readonly parentDigest: Uint8Array;
    readonly height: bigint;
    readonly stateRoot: Uint8Array;
    readonly stateStart: bigint;
    readonly stateTip: bigint;
    readonly transactionsRoot: Uint8Array;
    readonly transactionsStart: bigint;
    readonly transactionsTip: bigint;
    readonly endOffset: number;
}

// Header<Commitment, Sha256, Ed25519> encodes its context (round epoch and view,
// leader, and parent view and commitment), then the parent digest, height,
// timestamp, state target, and transaction target. This parser stays narrow.
// Callers bind the exact encoded bytes to a certified digest before trusting fields.
function decodeBlockHeader(bytes: Uint8Array, offset: number): DecodedBlockHeader {
    const epoch = readVarint(bytes, offset);
    const view = readVarint(bytes, epoch.offset);
    offset = skip(bytes, view.offset, ED25519_PUBLIC_KEY_BYTES);
    offset = readVarint(bytes, offset).offset;
    offset = skip(bytes, offset, COMMITMENT_BYTES);

    const parentDigest = readBytes(bytes, offset, DIGEST_BYTES);
    offset = skip(bytes, offset, DIGEST_BYTES);
    const height = readHeaderU64(bytes, offset);
    const timestamp = readHeaderU64(bytes, height.offset);
    offset = timestamp.offset;

    const stateRoot = readBytes(bytes, offset, DIGEST_BYTES);
    offset = skip(bytes, offset, DIGEST_BYTES);
    const stateStart = readHeaderU64(bytes, offset);
    const stateTip = readHeaderU64(bytes, stateStart.offset);
    offset = stateTip.offset;

    const transactionsRoot = readBytes(bytes, offset, DIGEST_BYTES);
    offset = skip(bytes, offset, DIGEST_BYTES);
    const transactionsStart = readHeaderU64(bytes, offset);
    const transactionsTip = readHeaderU64(bytes, transactionsStart.offset);
    offset = transactionsTip.offset;

    if (stateStart.value >= stateTip.value || transactionsStart.value >= transactionsTip.value) {
        throw new Error('finalized block contains an empty QMDB range');
    }
    return {
        view: view.value,
        parentDigest,
        height: height.value,
        stateRoot,
        stateStart: stateStart.value,
        stateTip: stateTip.value,
        transactionsRoot,
        transactionsStart: transactionsStart.value,
        transactionsTip: transactionsTip.value,
        endOffset: offset,
    };
}

function readHeaderU64(bytes: Uint8Array, offset: number): { value: bigint; offset: number } {
    const next = skip(bytes, offset, U64_BYTES);
    return { value: readU64Be(bytes, offset), offset: next };
}

function readBytes(bytes: Uint8Array, offset: number, length: number): Uint8Array {
    skip(bytes, offset, length);
    return bytes.slice(offset, offset + length);
}

function skip(bytes: Uint8Array, offset: number, length: number): number {
    const next = offset + length;
    if (offset < 0 || next > bytes.length) {
        throw new Error('finalized block header is truncated');
    }
    return next;
}

function readVarint(bytes: Uint8Array, offset: number): { value: bigint; offset: number } {
    let value = 0n;
    let shift = 0n;
    for (let count = 0; count < 10; count++) {
        if (offset >= bytes.length) {
            throw new Error('finalized block header is truncated');
        }
        const byte = bytes[offset++];
        if (count === 9 && (byte & 0xfe) !== 0) {
            throw new Error('finalized block header varint exceeds u64');
        }
        value |= BigInt(byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) {
            if (count > 0 && byte === 0) {
                throw new Error('finalized block header varint is not canonical');
            }
            return { value, offset };
        }
        shift += 7n;
    }
    throw new Error('finalized block header varint is too long');
}

export function decodeAccountValue(
    value: Uint8Array,
): Pick<VerifiedAccountProof, 'balance' | 'nonce' | 'nonceBitmap'> {
    if (value.length !== ACCOUNT_VALUE_BYTES) {
        throw new Error('malformed account proof value');
    }
    return {
        balance: readU64Be(value, 0),
        nonce: readU64Be(value, 8),
        nonceBitmap: readU64Be(value, 16),
    };
}

export function readU64Be(bytes: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
        value = (value << 8n) | BigInt(bytes[offset + i]);
    }
    return value;
}
