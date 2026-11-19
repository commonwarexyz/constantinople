// Verifies Simplex certificates of the chain's vote scheme.
//
// A validator's vote is an ed25519 signature over the vote's subject followed by the
// voter's report on the block's transactions that are authenticated by tags. A
// certificate lists the validators that voted and holds each vote. The chain tolerates
// f faults among n >= 5f + 1 validators, and a certificate needs n - f votes.
//
// The stock verifiers of @exowarexyz/simplex know the built-in schemes only, so this
// module implements the package's verifier interface for this one.

import type {
    SimplexCertificateVerifier,
    SimplexFinalizationVerificationContext,
    SimplexNotarizationVerificationContext,
} from '@exowarexyz/simplex';

const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;
const NOTARIZE_SUFFIX = '_NOTARIZE';
const FINALIZE_SUFFIX = '_FINALIZE';

// A report covers at most this many transactions (`constantinople_auth::MAX_ENTRIES`).
const MAX_REPORT_ENTRIES = 1 << 18;

export interface VerifiedCertificate {
    readonly epoch: bigint;
    readonly view: bigint;
    // View of the parent proposal.
    readonly parent: bigint;
    // The certified payload: the block's coding commitment.
    readonly payload: Uint8Array;
    // The validators whose votes the certificate holds, by index.
    readonly signers: readonly number[];
    // The encoded report of each vote, in signer order. Empty reports for finalizations.
    readonly reports: readonly Uint8Array[];
    // What follows the certificate in the stored artifact.
    readonly header: Uint8Array;
}

export interface CertificateVerifierOptions {
    // The consensus namespace, without a vote suffix.
    readonly namespace: Uint8Array;
    // The validators' ed25519 public keys, concatenated in participant order.
    readonly validators: Uint8Array;
    // Length of a certified payload in bytes.
    readonly payloadBytes: number;
}

type Kind = 'notarization' | 'finalization';

export function createCertificateVerifier(
    options: CertificateVerifierOptions,
): SimplexCertificateVerifier<VerifiedCertificate, VerifiedCertificate> {
    if (options.validators.length === 0 || options.validators.length % PUBLIC_KEY_BYTES !== 0) {
        throw new Error('Simplex verification material must hold one 32-byte key per validator');
    }
    const validators: Uint8Array[] = [];
    for (let offset = 0; offset < options.validators.length; offset += PUBLIC_KEY_BYTES) {
        validators.push(options.validators.slice(offset, offset + PUBLIC_KEY_BYTES));
    }
    // Keys are imported when the first certificate arrives, so that a key the
    // platform refuses fails that verification instead of the caller's setup.
    let imported: Promise<CryptoKey>[] | undefined;
    const keys = () => {
        imported ??= validators.map((key) =>
            crypto.subtle.importKey('raw', toArrayBuffer(key), 'Ed25519', false, ['verify']),
        );
        return imported;
    };
    const verify = (kind: Kind) => async (
        bytes: Uint8Array,
        context: SimplexNotarizationVerificationContext | SimplexFinalizationVerificationContext,
    ): Promise<VerifiedCertificate | null> => {
        const certificate = await verifyCertificate(bytes, kind, options, keys());
        if (certificate === null) return null;
        if (context.kind === 'notarization' || context.index === 'round') {
            if (certificate.view !== context.view || certificate.epoch !== context.epoch) return null;
        }
        return certificate;
    };
    return {
        verifyNotarization: verify('notarization'),
        verifyFinalization: verify('finalization'),
    };
}

// Number of faults n validators tolerate, and the votes a certificate needs.
export function quorum(validators: number): number {
    return validators - Math.floor((validators - 1) / 5);
}

async function verifyCertificate(
    bytes: Uint8Array,
    kind: Kind,
    options: CertificateVerifierOptions,
    keys: readonly Promise<CryptoKey>[],
): Promise<VerifiedCertificate | null> {
    let parsed: ParsedCertificate;
    try {
        parsed = parseCertificate(bytes, options.payloadBytes, keys.length);
    } catch {
        return null;
    }
    if (parsed.signers.length < quorum(keys.length)) return null;

    // Only a vote for a block reports on its transactions.
    if (kind === 'finalization' && parsed.reports.some((report) => !isEmptyReport(report))) {
        return null;
    }

    const suffix = kind === 'notarization' ? NOTARIZE_SUFFIX : FINALIZE_SUFFIX;
    const namespace = concat(options.namespace, new TextEncoder().encode(suffix));
    const prefix = concat(encodeVarint(BigInt(namespace.length)), namespace, parsed.proposal);
    const verified = await Promise.all(
        parsed.signers.map(async (signer, index) =>
            crypto.subtle.verify(
                'Ed25519',
                await keys[signer],
                toArrayBuffer(parsed.signatures[index]),
                toArrayBuffer(concat(prefix, parsed.reports[index])),
            ),
        ),
    );
    if (!verified.every(Boolean)) return null;

    return {
        epoch: parsed.epoch,
        view: parsed.view,
        parent: parsed.parent,
        payload: parsed.payload,
        signers: parsed.signers,
        reports: parsed.reports,
        header: parsed.header,
    };
}

interface ParsedCertificate {
    readonly epoch: bigint;
    readonly view: bigint;
    readonly parent: bigint;
    readonly payload: Uint8Array;
    // The encoded proposal, which every vote signs.
    readonly proposal: Uint8Array;
    readonly signers: number[];
    readonly reports: Uint8Array[];
    readonly signatures: Uint8Array[];
    readonly header: Uint8Array;
}

// A stored artifact is a proposal (epoch, view, parent view, payload), a certificate
// (signer bitmap, then one vote per signer) and the certified header.
function parseCertificate(bytes: Uint8Array, payloadBytes: number, validators: number): ParsedCertificate {
    const epoch = readVarint(bytes, 0);
    const view = readVarint(bytes, epoch.offset);
    const parent = readVarint(bytes, view.offset);
    const payload = take(bytes, parent.offset, payloadBytes);
    let offset = parent.offset + payloadBytes;
    const proposal = bytes.slice(0, offset);

    // The bitmap has one bit per validator, least significant bit first.
    const bits = new DataView(take(bytes, offset, 8).buffer).getBigUint64(0);
    offset += 8;
    if (bits !== BigInt(validators)) throw new Error('signer bitmap does not match the validator set');
    const bitmap = take(bytes, offset, Math.ceil(validators / 8));
    offset += bitmap.length;
    const signers: number[] = [];
    for (let index = 0; index < bitmap.length * 8; index += 1) {
        if ((bitmap[index >> 3] & (1 << (index & 7))) === 0) continue;
        if (index >= validators) throw new Error('signer bitmap has a bit past the validator set');
        signers.push(index);
    }

    const count = readVarint(bytes, offset);
    offset = count.offset;
    if (count.value !== BigInt(signers.length)) throw new Error('signers and votes counts differ');
    const reports: Uint8Array[] = [];
    const signatures: Uint8Array[] = [];
    for (let index = 0; index < signers.length; index += 1) {
        const end = reportEnd(bytes, offset);
        reports.push(bytes.slice(offset, end));
        signatures.push(take(bytes, end, SIGNATURE_BYTES));
        offset = end + SIGNATURE_BYTES;
    }

    return {
        epoch: epoch.value,
        view: view.value,
        parent: parent.value,
        payload,
        proposal,
        signers,
        reports,
        signatures,
        header: bytes.slice(offset),
    };
}

// A report starts with a varint. If its lowest bit is clear, the rest counts rejected
// positions, each a varint gap. Otherwise the rest counts bits, and that many bits follow.
function reportEnd(bytes: Uint8Array, offset: number): number {
    const header = readVarint(bytes, offset);
    const length = header.value >> 1n;
    if (length > BigInt(MAX_REPORT_ENTRIES)) throw new Error('report covers too many transactions');
    if ((header.value & 1n) === 1n) {
        const end = header.offset + Math.ceil(Number(length) / 8);
        if (end > bytes.length) throw new Error('truncated report');
        return end;
    }
    let end = header.offset;
    for (let index = 0n; index < length; index += 1n) {
        end = readVarint(bytes, end).offset;
    }
    return end;
}

function isEmptyReport(report: Uint8Array): boolean {
    return report.length === 1 && report[0] === 0;
}

// Whether each of `entries` transactions is approved by an encoded report, or null if
// the report does not fit a block with that many: it then approves nothing.
export function reportVerdicts(report: Uint8Array, entries: number): boolean[] | null {
    const header = readVarint(report, 0);
    const length = Number(header.value >> 1n);
    if ((header.value & 1n) === 1n) {
        if (length !== entries) return null;
        return Array.from({ length: entries }, (_, position) =>
            (report[header.offset + (position >> 3)] & (0x80 >> (position & 7))) !== 0,
        );
    }
    const verdicts = Array.from({ length: entries }, () => true);
    let offset = header.offset;
    let next = 0n;
    for (let index = 0; index < length; index += 1) {
        const gap = readVarint(report, offset);
        const position = next + gap.value;
        if (position >= BigInt(entries)) return null;
        verdicts[Number(position)] = false;
        next = position + 1n;
        offset = gap.offset;
    }
    return verdicts;
}

// Whether each of `entries` tagged transactions of a block is authentic, given the
// reports of a notarization of the block by `validators` validators: at least 2f + 1
// of them must approve it.
export function status(reports: readonly Uint8Array[], validators: number, entries: number): boolean[] {
    const threshold = 2 * Math.floor((validators - 1) / 5) + 1;
    const approvals = Array.from({ length: entries }, () => 0);
    for (const report of reports) {
        const verdicts = reportVerdicts(report, entries);
        if (verdicts === null) continue;
        verdicts.forEach((approved, position) => {
            if (approved) approvals[position] += 1;
        });
    }
    return approvals.map((count) => count >= threshold);
}

function readVarint(bytes: Uint8Array, offset: number): { value: bigint; offset: number } {
    let value = 0n;
    let shift = 0n;
    for (;;) {
        if (offset >= bytes.length) throw new Error('truncated varint');
        const byte = bytes[offset];
        offset += 1;
        value |= BigInt(byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) return { value, offset };
        shift += 7n;
        if (shift > 63n) throw new Error('varint is too long');
    }
}

function encodeVarint(value: bigint): Uint8Array {
    const bytes: number[] = [];
    do {
        const byte = Number(value & 0x7fn);
        value >>= 7n;
        bytes.push(value === 0n ? byte : byte | 0x80);
    } while (value !== 0n);
    return Uint8Array.from(bytes);
}

function take(bytes: Uint8Array, offset: number, length: number): Uint8Array {
    if (offset + length > bytes.length) throw new Error('truncated certificate');
    return bytes.slice(offset, offset + length);
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
