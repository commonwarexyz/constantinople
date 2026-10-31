import { initQmdbWasm, QmdbProofVerifier } from '@exowarexyz/qmdb';
import { type SimplexCertificateVerifier, type VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { Code, ConnectError } from '@connectrpc/connect';
import { accountKeyFromPublicKey, bytesEqual, fromHex, parseAccountKeyHex, toArrayBuffer, toHex } from './codec.ts';
import {
    authenticatedHeader, decodeAccountValue, finalizedTargetFromCertificate,
    readU64Be, simplexFinalizationVerifier,
    type AccountActivityMode, type AccountTransactionPage, type DecodedBlockHeader,
    type LatestProofTarget, type VerifiedAccountProof, type VerifiedFinalizationTarget,
    type VerifiedTransactionProof,
} from './qmdb.ts';

const MAX_U64 = (1n << 64n) - 1n;
const MAX_BODY_BYTES = 8 * 1024 * 1024;
const MAX_PROOF_BYTES = 1024 * 1024;
const MAX_HEADERS = 4096;
const TRANSACTION_BODY_BYTES = 82;
// Mirrors Transaction::SIZE + TransactionSignature::MAX_SIZE in the Rust primitives crate.
const MAX_TRANSACTION_BYTES = 919;
const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });
type CertificateVerifier = SimplexCertificateVerifier<VerifiedSimplexCertificate, VerifiedSimplexCertificate>;
const certificateInitializations = new Map<string, Promise<CertificateVerifier>>();

interface CommonOptions {
    readonly qmdbUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly signal?: AbortSignal;
    readonly onFinalizationVerified?: (target: VerifiedFinalizationTarget) => void;
}

export interface AccountBundleOptions extends CommonOptions {
    readonly account: string;
    readonly mode?: AccountActivityMode;
    readonly cursor?: Uint8Array | string | null;
    readonly at?: { readonly height: bigint; readonly blockDigest: Uint8Array };
    readonly includeTransactions?: boolean;
}

export interface BlockBundleOptions extends CommonOptions {
    readonly height: bigint;
    readonly offset?: bigint;
}

export interface TransactionBundleOptions extends CommonOptions {
    readonly digest: string;
}

interface TransactionRow {
    readonly location: bigint;
    readonly body: Uint8Array;
    readonly height: bigint;
    readonly index: number;
    readonly role?: number;
}

interface Envelope {
    readonly certificate: Uint8Array;
    readonly headers: Uint8Array[];
    readonly sequenceNumber: bigint;
    readonly account: { readonly location: bigint; readonly proof: Uint8Array } | null;
    readonly transactions: TransactionRow[];
    readonly transactionsProof: Uint8Array | null;
    readonly nextCursor: string | null;
}

type CertifiedTarget = LatestProofTarget & Pick<DecodedBlockHeader, 'parentDigest'>;

interface CanonicalTransaction {
    readonly digest: string;
    readonly sender: string;
    readonly recipient: string;
    readonly value: bigint;
    readonly nonce: bigint;
    readonly location: bigint;
}

/** Historical inclusion under one snapshot; activity heights and indices are pagination hints. */
export interface VerifiedAccountBundle {
    readonly target: LatestProofTarget;
    /** Null means the indexer supplied no account update. */
    readonly account: VerifiedAccountProof | null;
    readonly page: AccountTransactionPage;
    readonly transactionProofs: VerifiedTransactionProof[];
}

export interface VerifiedBlockBundle {
    readonly target: LatestProofTarget;
    readonly block: { readonly height: bigint; readonly blockDigest: Uint8Array; readonly view: bigint; readonly transactionCount: bigint };
    readonly transactions: Array<CanonicalTransaction & { readonly proof: VerifiedTransactionProof }>;
    readonly nextOffset: bigint | null;
}

export async function prewarmProofVerification(material: string): Promise<void> {
    await Promise.all([certificateVerifier(material), initQmdbWasm()]);
}

export async function loadAccountBundle(options: AccountBundleOptions): Promise<VerifiedAccountBundle> {
    const request = accountRequest(options);
    return verifyAccountBundle(request, await loadEnvelope(request, accountPath(request)));
}

export async function loadBlockBundle(options: BlockBundleOptions): Promise<VerifiedBlockBundle> {
    const request = blockRequest(options);
    return verifyBlockBundle(request, await loadEnvelope(request, `/explorer/blocks/${request.height}?offset=${request.offset}`));
}

export async function loadTransactionBundle(options: TransactionBundleOptions): Promise<VerifiedTransactionProof> {
    const request = transactionRequest(options);
    return verifyTransactionBundle(request, await loadEnvelope(request, `/explorer/transactions/${request.digest}`));
}

export async function verifyAccountBundle(options: AccountBundleOptions, raw: unknown): Promise<VerifiedAccountBundle> {
    const request = accountRequest(options);
    const envelope = parseEnvelope(raw, 10);
    if (envelope.headers.length !== 0) throw new Error('account bundle must use a directly certified snapshot');
    const target = await certifiedTarget(request, envelope);
    if (request.at && (target.height !== request.at.height || !bytesEqual(target.blockDigest, request.at.blockDigest))) {
        throw new Error('account bundle does not match requested snapshot');
    }
    if (!request.includeTransactions && (envelope.transactions.length !== 0 || envelope.nextCursor !== null)) {
        throw new Error('balance-only bundle contains activity');
    }
    const cursor = request.cursor === null ? null : decodeCursor(request.cursor);
    const tuples = envelope.transactions.map((row) => {
        if (row.role !== 0 && row.role !== 1) throw new Error('invalid account activity role');
        if ((request.mode === 'sent' && row.role !== 0) || (request.mode === 'received' && row.role !== 1)) {
            throw new Error('account activity does not match requested mode');
        }
        return [row.height, BigInt(row.index), BigInt(row.role)] as const;
    });
    let previous = cursor;
    for (const tuple of tuples) {
        if (previous && compareCursor(tuple, previous) >= 0) throw new Error('account activity is not strictly after requested cursor');
        previous = tuple;
    }
    const locations = new Map<bigint, TransactionRow>();
    for (const row of envelope.transactions) {
        const prior = locations.get(row.location);
        if (prior && (prior.height !== row.height || prior.index !== row.index || prior.role === row.role || !bytesEqual(prior.body, row.body))) {
            throw new Error('conflicting account activity at one location');
        }
        locations.set(row.location, row);
    }
    const nextCursor = envelope.nextCursor === null ? null : hex(envelope.nextCursor, 'account cursor', 24, 24);
    if (nextCursor && (tuples.length !== 10 || !previous || compareCursor(decodeCursor(nextCursor), previous) !== 0)) {
        throw new Error('account next cursor does not match last page row');
    }
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: target.height, view: target.view });
    const [account, transactions] = await Promise.all([
        verifyAccount(envelope, target, fromHex(request.account)),
        verifyTransactions(envelope, target),
    ]);
    const rows = transactions.map((transaction, index) => {
        const row = envelope.transactions[index]!;
        const sent = row.role === 0;
        if ((sent ? transaction.sender : transaction.recipient) !== request.account) {
            throw new Error('transaction body does not involve the requested account in its claimed role');
        }
        return {
            digest: transaction.digest, direction: sent ? 'sent' as const : 'received' as const,
            counterparty: sent ? transaction.recipient : transaction.sender,
            value: transaction.value, nonce: transaction.nonce,
            height: row.height, blockIndex: row.index, location: row.location,
        };
    });
    request.signal?.throwIfAborted();
    return { target, account, page: { rows, nextCursor }, transactionProofs: transactions.map((tx) => tx.proof) };
}

export async function verifyBlockBundle(options: BlockBundleOptions, raw: unknown): Promise<VerifiedBlockBundle> {
    const request = blockRequest(options);
    const envelope = parseEnvelope(raw, 50);
    if (envelope.account !== null) throw new Error('block bundle contains account proof');
    const target = await certifiedTarget(request, envelope);
    const { block, blockDigest, start, end } = await owningBlock(target, envelope, request.height, request.signal);
    const count = end - start;
    if (request.offset > count) throw new Error('block offset exceeds transaction count');
    const expectedCount = Number(count - request.offset < 50n ? count - request.offset : 50n);
    if (envelope.transactions.length !== expectedCount) throw new Error('block page does not cover the expected append interval');
    for (let index = 0; index < expectedCount; index++) {
        const row = envelope.transactions[index]!;
        if (row.height !== request.height || row.location !== start + request.offset + BigInt(index) || BigInt(row.index) !== request.offset + BigInt(index)) {
            throw new Error('block row does not match its exact append position');
        }
    }
    const nextOffset = request.offset + BigInt(expectedCount) < count ? request.offset + BigInt(expectedCount) : null;
    if ((envelope.nextCursor === null ? null : decimal(envelope.nextCursor, 'block next offset')) !== nextOffset) {
        throw new Error('block next offset does not match the authenticated transaction count');
    }
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: target.height, view: target.view });
    const transactions = (await verifyTransactions(envelope, target)).map((transaction) => ({
        ...transaction, proof: { ...transaction.proof, height: block.height, view: block.view },
    }));
    request.signal?.throwIfAborted();
    return { target, block: { height: block.height, blockDigest, view: block.view, transactionCount: count }, transactions, nextOffset };
}

export async function verifyTransactionBundle(options: TransactionBundleOptions, raw: unknown): Promise<VerifiedTransactionProof> {
    const request = transactionRequest(options);
    const envelope = parseEnvelope(raw, 1);
    if (envelope.account !== null || envelope.transactions.length !== 1 || envelope.nextCursor !== null) {
        throw new Error('single transaction bundle has invalid cardinality');
    }
    const target = await certifiedTarget(request, envelope);
    const row = envelope.transactions[0]!;
    const { block, start, end } = await owningBlock(target, envelope, row.height, request.signal);
    if (row.location < start || row.location >= end || BigInt(row.index) !== row.location - start) {
        throw new Error('transaction is not at its claimed owning-block append position');
    }
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: block.height, view: block.view });
    const [transaction] = await verifyTransactions(envelope, target);
    if (transaction!.digest !== request.digest) throw new Error('transaction body does not match requested digest');
    request.signal?.throwIfAborted();
    return { ...transaction!.proof, height: block.height, view: block.view };
}

async function loadEnvelope(options: CommonOptions, path: string): Promise<unknown> {
    options.signal?.throwIfAborted();
    const ready = prewarmProofVerification(options.simplexVerificationMaterial);
    // Observe initialization failure even when transport fails first.
    const initialization = ready.then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    const response = await fetch(`${options.qmdbUrl.replace(/\/+$/, '')}${path}`, { signal: options.signal, cache: 'no-store' })
        .catch((error: unknown) => { throw error instanceof TypeError ? ConnectError.from(error) : error; });
    if (!response.ok) {
        await response.body?.cancel();
        if (response.status === 502 || response.status === 503 || response.status === 504) throw new ConnectError('aggregate proof unavailable', Code.Unavailable);
        throw new Error(`aggregate proof request failed (HTTP ${response.status})`);
    }
    const declared = response.headers.get('content-length');
    if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
        await response.body?.cancel();
        throw new Error('aggregate response exceeds size limit');
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error('aggregate response body is missing');
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let text = '';
    let size = 0;
    try {
        while (true) {
            options.signal?.throwIfAborted();
            const chunk = await reader.read()
                .catch((error: unknown) => { throw error instanceof TypeError ? ConnectError.from(error) : error; });
            if (chunk.done) break;
            size += chunk.value.byteLength;
            if (size > MAX_BODY_BYTES) throw new Error('aggregate response exceeds size limit');
            text += decoder.decode(chunk.value, { stream: true });
        }
        text += decoder.decode();
    } catch (error) {
        await reader.cancel().catch(() => undefined);
        throw error;
    } finally {
        reader.releaseLock();
    }
    options.signal?.throwIfAborted();
    const raw: unknown = JSON.parse(text);
    const initialized = await initialization;
    if (!initialized.ok) throw initialized.error;
    options.signal?.throwIfAborted();
    return raw;
}

async function certifiedTarget(options: CommonOptions, envelope: Envelope): Promise<CertifiedTarget> {
    options.signal?.throwIfAborted();
    const certificates = await certificateVerifier(options.simplexVerificationMaterial);
    options.signal?.throwIfAborted();
    const certificate = await certificates.verifyFinalization(envelope.certificate, {
        kind: 'finalization', index: 'latest', height: 0n,
        key: new Uint8Array(), value: envelope.certificate, source: 'get',
    });
    if (!certificate) throw new Error('aggregate finalization certificate is invalid');
    const target = await finalizedTargetFromCertificate(certificate);
    if (target.height === 0n || certificate.header.length > 100 + 512) throw new Error('invalid certified execution header');
    options.signal?.throwIfAborted();
    return { ...target, sequenceNumber: envelope.sequenceNumber };
}

async function owningBlock(target: CertifiedTarget, envelope: Envelope, height: bigint, signal?: AbortSignal) {
    if (height === 0n || height > target.height) throw new Error('invalid owning block height');
    const lowest = height === 1n ? height : height - 1n;
    if (BigInt(envelope.headers.length) !== target.height - lowest) throw new Error('aggregate ancestry does not cover the exact owning block and parent');
    let current: DecodedBlockHeader = { ...target, endOffset: 0 };
    let digest = target.blockDigest;
    let block = current;
    let blockDigest = digest;
    let parent: DecodedBlockHeader | undefined;
    for (const bytes of envelope.headers) {
        signal?.throwIfAborted();
        digest = current.parentDigest;
        current = await authenticatedHeader(bytes, digest, current.height - 1n);
        if (current.height === height) { block = current; blockDigest = digest; }
        if (current.height === height - 1n) parent = current;
    }
    const start = height === 1n ? block.transactionsStart + 1n : parent!.transactionsTip;
    const end = block.transactionsTip - 1n;
    if (start > end || end > target.transactionsTip - 1n) {
        throw new Error('owning-block append interval is invalid');
    }
    return { block, blockDigest, start, end };
}

async function verifyAccount(envelope: Envelope, target: LatestProofTarget, account: Uint8Array): Promise<VerifiedAccountProof | null> {
    if (envelope.account === null) return null;
    const { location, proof } = envelope.account;
    if (location < target.stateStart || location >= target.stateTip - 1n) throw new Error('account update is outside certified state interval');
    const verified = await verifier.verifyFixedUnorderedUpdate(proof, { tip: target.stateTip - 1n, startLocation: location, maxLocations: 1 }, target.stateRoot, location, account, 24);
    return { ...decodeAccountValue(verified.value), location, tip: target.stateTip - 1n, proofSizeBytes: verified.proofSizeBytes };
}

async function verifyTransactions(envelope: Envelope, target: LatestProofTarget): Promise<Array<CanonicalTransaction & { proof: VerifiedTransactionProof }>> {
    if (envelope.transactions.length === 0) {
        if (envelope.transactionsProof !== null) throw new Error('empty transaction page contains a proof');
        return [];
    }
    if (envelope.transactionsProof === null) throw new Error('transaction page is missing its multiproof');
    const transactions = await Promise.all(envelope.transactions.map(decodeTransaction));
    const expectations = new Map<bigint, string>();
    for (let index = 0; index < transactions.length; index++) {
        const transaction = transactions[index]!;
        const row = envelope.transactions[index]!;
        if (row.height === 0n || row.height > target.height || row.location >= target.transactionsTip - 1n) {
            throw new Error('transaction is outside certified history');
        }
        const previous = expectations.get(row.location);
        if (previous !== undefined && previous !== transaction.digest) throw new Error('conflicting transaction bodies at one location');
        expectations.set(row.location, transaction.digest);
    }
    const expected = [...expectations].sort(([left], [right]) => left < right ? -1 : 1).map(([location, digest]) => ({ location, value: fromHex(digest) }));
    const proof = await verifier.verifyFixedKeylessAppendMany(envelope.transactionsProof, { tip: target.transactionsTip - 1n }, target.transactionsRoot, expected);
    return transactions.map((transaction) => ({ ...transaction, proof: {
        location: transaction.location, tip: target.transactionsTip - 1n,
        height: target.height, view: target.view, proofSizeBytes: proof.proofSizeBytes,
    } }));
}

async function decodeTransaction(row: TransactionRow): Promise<CanonicalTransaction> {
    const body = row.body;
    if (body.length < TRANSACTION_BODY_BYTES + 65) throw new Error('signed transaction is truncated');
    const key = body.slice(0, 34);
    if ((key[0] === 0 && key[33] !== 0) || (key[0] !== 0 && key[0] !== 1)) throw new Error('transaction sender encoding is invalid');
    if (body[82] !== key[0]) throw new Error('transaction signature scheme does not match sender');
    if (key[0] === 0 && body.length !== 147) throw new Error('Ed25519 transaction has trailing bytes');
    if (key[0] === 1) {
        if (key[1] !== 2 && key[1] !== 3) throw new Error('invalid compressed P-256 sender');
        const signature = new DataView(body.buffer, body.byteOffset, body.byteLength);
        if (body.length < 151) throw new Error('WebAuthn transaction is truncated');
        const authLength = signature.getUint16(147);
        const jsonOffset = 149 + authLength;
        if (authLength > 256 || jsonOffset + 2 > body.length) throw new Error('WebAuthn authenticator data is truncated');
        const jsonLength = signature.getUint16(jsonOffset);
        if (jsonLength > 512 || jsonOffset + 2 + jsonLength !== body.length) throw new Error('WebAuthn client data length is invalid');
    }
    const value = readU64Be(body, 66);
    if (value === 0n) throw new Error('transaction value must be nonzero');
    const [digest, sender] = await Promise.all([
        crypto.subtle.digest('SHA-256', toArrayBuffer(body.slice(0, TRANSACTION_BODY_BYTES))),
        accountKeyFromPublicKey(key),
    ]);
    return { digest: toHex(new Uint8Array(digest)), sender: toHex(sender), recipient: toHex(body.slice(34, 66)), value, nonce: readU64Be(body, 74), location: row.location };
}

function parseEnvelope(raw: unknown, pageSize: number): Envelope {
    const value = record(raw, 'aggregate response');
    const headers = array(value.headers, 'headers', MAX_HEADERS).map((entry) => hex(entry, 'execution header', 1, 512));
    const transactions = array(value.transactions, 'transactions', pageSize).map((entry) => {
        const row = record(entry, 'transaction row');
        if (!Number.isInteger(row.index) || (row.index as number) < 0 || (row.index as number) > 0xffffffff) throw new Error('invalid transaction index');
        if (row.role !== undefined && row.role !== 0 && row.role !== 1) throw new Error('invalid transaction role');
        return { location: decimal(row.location, 'transaction location'), body: hex(row.body, 'signed transaction', 1, MAX_TRANSACTION_BYTES), height: decimal(row.height, 'transaction height'), index: row.index as number, role: row.role as number | undefined };
    });
    const account = value.account === null ? null : record(value.account, 'account proof');
    if (value.nextCursor !== null && (typeof value.nextCursor !== 'string' || value.nextCursor.length > 48)) throw new Error('invalid next cursor');
    return {
        certificate: hex(value.certificate, 'certificate', 1, 16 * 1024), headers,
        sequenceNumber: decimal(value.sequenceNumber, 'Store sequence'),
        account: account === null ? null : { location: decimal(account.location, 'account location'), proof: hex(account.proof, 'account proof', 1, MAX_PROOF_BYTES) },
        transactions, transactionsProof: value.transactionsProof === null ? null : hex(value.transactionsProof, 'transaction multiproof', 1, MAX_PROOF_BYTES),
        nextCursor: value.nextCursor as string | null,
    };
}

function certificateVerifier(material: string): Promise<CertificateVerifier> {
    const key = material.trim().toLowerCase();
    if (!/^(?:[0-9a-f]{2})+$/.test(key) || key.length > 2 * 1024 * 1024) throw new Error('invalid Simplex verification material');
    let pending = certificateInitializations.get(key);
    if (!pending) {
        pending = simplexFinalizationVerifier(key);
        certificateInitializations.set(key, pending);
        pending.catch(() => { if (certificateInitializations.get(key) === pending) certificateInitializations.delete(key); });
        if (certificateInitializations.size > 4) certificateInitializations.delete(certificateInitializations.keys().next().value!);
    }
    return pending;
}

function accountRequest(options: AccountBundleOptions) {
    const mode = options.mode ?? 'all';
    if (mode !== 'all' && mode !== 'sent' && mode !== 'received') throw new Error('invalid activity mode');
    const cursor = options.cursor == null ? null : typeof options.cursor === 'string'
        ? hex(options.cursor, 'account cursor', 24, 24) : options.cursor.slice();
    if (cursor) {
        const [, , role] = decodeCursor(cursor);
        if ((mode === 'sent' && role !== 0n) || (mode === 'received' && role !== 1n)) throw new Error('account cursor does not match activity mode');
    }
    const at = options.at === undefined ? undefined : { height: u64(options.at.height, 'snapshot height', true), blockDigest: options.at.blockDigest.slice() };
    if (at && at.blockDigest.length !== 32) throw new Error('invalid snapshot digest');
    if (cursor && !at) throw new Error('account pagination requires a fixed snapshot');
    return { ...options, account: toHex(parseAccountKeyHex(options.account)), mode, cursor, at, includeTransactions: options.includeTransactions ?? true };
}

function blockRequest(options: BlockBundleOptions) {
    return { ...options, height: u64(options.height, 'block height', true), offset: u64(options.offset ?? 0n, 'block offset') };
}

function transactionRequest(options: TransactionBundleOptions) {
    return { ...options, digest: toHex(parseAccountKeyHex(options.digest)) };
}

function accountPath(request: ReturnType<typeof accountRequest>): string {
    const query = new URLSearchParams({ mode: request.mode });
    if (request.cursor) query.set('cursor', toHex(request.cursor));
    if (request.at) { query.set('at', request.at.height.toString()); query.set('digest', toHex(request.at.blockDigest)); }
    if (!request.includeTransactions) query.set('activity', 'false');
    return `/explorer/accounts/${request.account}?${query}`;
}

function record(value: unknown, label: string): Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error(`invalid ${label}`);
    return value as Record<string, unknown>;
}

function array(value: unknown, label: string, max: number): unknown[] {
    if (!Array.isArray(value) || value.length > max) throw new Error(`invalid or oversized ${label}`);
    return value;
}

function hex(value: unknown, label: string, min: number, max: number): Uint8Array {
    if (typeof value !== 'string' || value.length < min * 2 || value.length > max * 2 || !/^(?:[0-9a-f]{2})*$/.test(value)) throw new Error(`invalid or oversized ${label}`);
    return fromHex(value);
}

function decimal(value: unknown, label: string): bigint {
    if (typeof value !== 'string' || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`invalid ${label}`);
    return u64(BigInt(value), label);
}

function u64(value: bigint, label: string, positive = false): bigint {
    if (typeof value !== 'bigint' || value < (positive ? 1n : 0n) || value > MAX_U64) throw new Error(`invalid ${label}`);
    return value;
}

function decodeCursor(cursor: Uint8Array): readonly [bigint, bigint, bigint] {
    if (cursor.length !== 24) throw new Error('invalid account cursor');
    const tuple = [readU64Be(cursor, 0), readU64Be(cursor, 8), readU64Be(cursor, 16)] as const;
    if (tuple[0] === 0n || tuple[1] > 0xffffffffn || tuple[2] > 1n) throw new Error('invalid account cursor');
    return tuple;
}

function compareCursor(left: readonly bigint[], right: readonly bigint[]): number {
    for (let index = 0; index < 3; index++) {
        if (left[index]! < right[index]!) return -1;
        if (left[index]! > right[index]!) return 1;
    }
    return 0;
}
