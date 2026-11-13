import { accountHistoryPage } from './accountPage.ts';
import { initQmdbWasm, QmdbProofVerifier } from '@exowarexyz/qmdb';
import { initAccountProofWasm, verifyCurrentAccount } from './accountProof.ts';
import { type SimplexCertificateVerifier, type VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { createExplorerClient } from './rpc.ts';
import { type ProofBundle, type WatchBlocksResponse } from './gen/constantinople/explorer/v1/explorer_pb.ts';
import { accountKeyFromPublicKey, bytesEqual, fromHex, parseAccountKeyHex, toArrayBuffer, toHex } from './codec.ts';
import {
    authenticatedHeader, decodeAccountValue, finalizedTargetFromCertificate,
    readU64Be, simplexFinalizationVerifier,
    MAX_ANCESTRY_HEADERS, MAX_EXECUTION_HEADER_BYTES, MAX_FINALIZATION_CERTIFICATE_BYTES,
    type AccountTransactionPage, type DecodedBlockHeader,
    type LatestProofTarget, type VerifiedAccountProof, type VerifiedFinalizationTarget,
    type VerifiedTransactionProof,
} from './qmdb.ts';

const MAX_U64 = (1n << 64n) - 1n;

/** Maximum decoded size in bytes of one account proof or transaction multiproof. */
const MAX_PROOF_BYTES = 1024 * 1024;

/** Maximum number of ancestry headers between a covering certificate and the requested block. */
const MAX_HEADERS = MAX_ANCESTRY_HEADERS;

/** Size of the unsigned transaction body whose SHA-256 hash is the transaction digest. */
const TRANSACTION_BODY_BYTES = 82;

/** Size of an encoded fixed account update: tag, 32-byte key and 32-byte account value. */
const ACCOUNT_OPERATION_BYTES = 65;

/**
 * Maximum signed transaction size. Mirrors `Transaction::SIZE + TransactionSignature::MAX_SIZE` in
 * the Rust primitives crate.
 */
const MAX_TRANSACTION_BYTES = 919;

/** Verifies the SHA-256 MMR transaction log proofs. */
const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });

type CertificateVerifier = SimplexCertificateVerifier<VerifiedSimplexCertificate, VerifiedSimplexCertificate>;
interface CertificateContext {
    readonly verifier: CertificateVerifier;

    /** Last verified certificate and target, reused while later responses repeat its bytes. */
    lastVerified?: { readonly certificate: Uint8Array; readonly target: Omit<CertifiedTarget, 'sequenceNumber'> };
}

/** Verifier initializations keyed by normalized verification material, at most four. */
const certificateInitializations = new Map<string, Promise<CertificateContext>>();

interface CommonOptions {
    readonly indexerUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly signal?: AbortSignal;
    readonly onFinalizationVerified?: (target: VerifiedFinalizationTarget) => void;
}

export interface AccountBundleOptions extends CommonOptions {
    readonly account: string;
    readonly cursor?: Uint8Array | string | null;
    readonly at?: { readonly height: bigint; readonly blockDigest: Uint8Array };
    readonly includeTransactions?: boolean;
    readonly accountLocation?: bigint;
    readonly expectedTxCount?: bigint;
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
    readonly senderIndex: bigint;
    readonly recipientIndex: bigint;

    /** Position is authenticated by the owning block for block and transaction views. */
    readonly height: bigint;
    readonly index: number;

    /** Account activity role, 0 for sent and 1 for received. */
    readonly role?: number;
}

/** Unverified combined indexer response after size and syntax checks. */
interface Envelope {
    readonly certificate: Uint8Array;
    readonly headers: Uint8Array[];
    readonly sequenceNumber: bigint;
    readonly account: { readonly location: bigint; readonly proof: Uint8Array; readonly writeHeight: bigint; readonly encodedOperation: Uint8Array } | null;
    readonly transactions: TransactionRow[];
    readonly transactionsProof: Uint8Array | null;
    readonly nextCursor: string | null;
}

type CertifiedTarget = LatestProofTarget & Pick<DecodedBlockHeader, 'parentDigest'>;

export interface VerifiedBlock {
    readonly height: bigint;
    readonly digest: Uint8Array;
    readonly txCount: number;
    readonly timestampMs: bigint;
    readonly finality: {
        readonly certifiedHeight: bigint;
        readonly certificateView: bigint;
    };
}

export interface VerifiedBlockBatch {
    readonly blocks: readonly VerifiedBlock[];
    readonly target: Omit<LatestProofTarget, 'sequenceNumber'>;
    readonly sequenceNumberHint: bigint;
    readonly receivedAt: number;
}

/** Owns one material-bound stream cursor independently of the certificate memo. */
export function createBlockBatchVerifier(simplexVerificationMaterial: string, after?: 0n) {
    if (after !== undefined && after !== 0n) throw new Error('a new block feed can only resume from canonical genesis');
    const material = simplexVerificationMaterial.trim().toLowerCase();
    let cursor: { readonly height: bigint; readonly digest: Uint8Array } | undefined;
    return {
        get after(): bigint | undefined { return cursor?.height ?? after; },
        async verify(message: WatchBlocksResponse, signal?: AbortSignal): Promise<VerifiedBlockBatch | null> {
            signal?.throwIfAborted();
            if (message.certificate.length === 0 || message.certificate.length > MAX_FINALIZATION_CERTIFICATE_BYTES) {
                throw new Error('invalid or oversized certificate');
            }
            if (message.headers.length > MAX_HEADERS) throw new Error('invalid or oversized headers');
            for (const header of message.headers) {
                if (header.length === 0 || header.length > MAX_EXECUTION_HEADER_BYTES) throw new Error('invalid or oversized execution header');
            }
            const envelope = {
                certificate: message.certificate.slice(), headers: message.headers.map((header) => header.slice()),
                sequenceNumber: u64(message.sequenceNumber, 'Store sequence'),
            };
            const target = await certifiedTarget({ simplexVerificationMaterial: material, signal }, envelope);
            signal?.throwIfAborted();
            if (cursor && target.height <= cursor.height) {
                if (target.height === cursor.height && !bytesEqual(target.blockDigest, cursor.digest)) {
                    throw new Error('block feed conflicts with its accepted head');
                }
                return null;
            }

            const first = cursor ? cursor.height + 1n : after === 0n ? 1n : target.height;
            const lowest = cursor?.height ?? (first === 1n ? 1n : first - 1n);
            if (target.height - first + 1n > BigInt(MAX_HEADERS)) throw new Error('block feed gap exceeds header limit');
            const chain = await authenticatedChain(target, envelope.headers, lowest, signal);
            if (cursor && !bytesEqual(chain.at(-1)!.digest, cursor.digest)) {
                throw new Error('block feed ancestry does not match its accepted head');
            }

            const finality = Object.freeze({ certifiedHeight: target.height, certificateView: target.view });
            const blocks: VerifiedBlock[] = [];
            for (let index = chain.length - 1; index >= 0; index--) {
                const entry = chain[index]!;
                if (entry.header.height < first) continue;
                const { start, end } = appendInterval(entry.header, chain[index + 1]?.header);
                const count = end - start;
                if (count > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('block transaction count exceeds a safe integer');
                blocks.push(Object.freeze({
                    height: entry.header.height, digest: entry.digest.slice(), txCount: Number(count),
                    timestampMs: entry.header.timestampMs, finality,
                }));
            }
            const { sequenceNumber, parentDigest: _parentDigest, ...authenticated } = target;
            const batch: VerifiedBlockBatch = {
                blocks: Object.freeze(blocks), target: authenticated,
                sequenceNumberHint: sequenceNumber, receivedAt: Date.now(),
            };
            signal?.throwIfAborted();
            cursor = { height: target.height, digest: target.blockDigest.slice() };
            return batch;
        },
    };
}

interface CanonicalTransaction {
    readonly digest: string;
    readonly sender: string;
    readonly recipient: string;
    readonly value: bigint;
    readonly nonce: bigint;
    readonly location: bigint;
}

/** Account state and a complete history interval at one certified root. */
export interface VerifiedAccountBundle {
    readonly target: LatestProofTarget;
    readonly account: VerifiedAccountProof;
    readonly page: AccountTransactionPage;
    readonly transactionProofs: VerifiedTransactionProof[];
}

export interface VerifiedBlockBundle {
    readonly target: LatestProofTarget;
    readonly block: { readonly height: bigint; readonly blockDigest: Uint8Array; readonly view: bigint; readonly transactionCount: bigint };
    readonly transactions: Array<CanonicalTransaction & { readonly proof: VerifiedTransactionProof }>;
    readonly nextOffset: bigint | null;
}

/** A verified body and exact position under a certified transaction root. */
export interface VerifiedTransactionBundle extends VerifiedTransactionProof {
    readonly target: LatestProofTarget;
    readonly transaction: CanonicalTransaction & { readonly index: number };
    readonly blockDigest: Uint8Array;
}

/** Starts verifier and QMDB WebAssembly initialization before the first proof arrives. */
export async function prewarmProofVerification(material: string): Promise<void> {
    await Promise.all([certificateContext(material), initQmdbWasm()]);
}

/** Fetches and verifies one page of account state and activity. */
export async function loadAccountBundle(options: AccountBundleOptions): Promise<VerifiedAccountBundle> {
    const request = accountRequest(options);
    return verifyAccountBundle(request, await loadEnvelope(request, () => createExplorerClient(request.indexerUrl).getAccount({
        account: fromHex(request.account),
        cursor: request.cursor ?? undefined, at: request.at?.height, digest: request.at?.blockDigest,
        activity: request.includeTransactions, accountLocation: request.accountLocation,
    }, { signal: request.signal }), 'account'));
}

/** Fetches and verifies one page of a block's transactions. */
export async function loadBlockBundle(options: BlockBundleOptions): Promise<VerifiedBlockBundle> {
    const request = blockRequest(options);
    return verifyBlockBundle(request, await loadEnvelope(request, () => createExplorerClient(request.indexerUrl).getBlock({ height: request.height, offset: request.offset }, { signal: request.signal }), 'block'));
}

/** Fetches and verifies one transaction at its exact inclusion height and block index. */
export async function loadTransactionBundle(options: TransactionBundleOptions): Promise<VerifiedTransactionBundle> {
    const request = transactionRequest(options);
    return verifyTransactionBundle(request, await loadEnvelope(request, () => createExplorerClient(request.indexerUrl).getTransaction({ digest: fromHex(request.digest) }, { signal: request.signal }), 'transaction'));
}

export async function verifyAccountBundle(options: AccountBundleOptions, raw: unknown): Promise<VerifiedAccountBundle> {
    const request = accountRequest(options);
    const envelope = parseEnvelope(raw, 10);
    const target = await certifiedTarget(request, envelope);
    if (request.at && (target.height !== request.at.height || !bytesEqual(target.blockDigest, request.at.blockDigest))) {
        throw new Error('account bundle does not match requested snapshot');
    }
    if (!request.includeTransactions && (envelope.transactions.length !== 0 || envelope.transactionsProof !== null || envelope.nextCursor !== null)) {
        throw new Error('balance-only bundle contains activity');
    }
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: target.height, view: target.view });
    request.signal?.throwIfAborted();
    const account = await verifyAccount(envelope, target, fromHex(request.account), request.signal);
    if (request.accountLocation !== undefined && account.location !== request.accountLocation) {
        throw new Error('account bundle does not match pinned account location');
    }
    if (request.expectedTxCount !== undefined && account.txCount !== request.expectedTxCount) {
        throw new Error('account bundle does not match pinned transaction count');
    }
    const transactions = await verifyTransactions(envelope, target);
    if (transactions.some((transaction) => transaction.location >= account.transactionEnd)) {
        throw new Error('account history is newer than its authenticated account version');
    }
    const page = request.includeTransactions ? accountHistoryPage(
        request.account, account.txCount, request.cursor,
        envelope.nextCursor === null ? null : hex(envelope.nextCursor, 'account cursor', 8, 8),
        transactions.map((transaction, index) => ({ ...transaction, ...envelope.transactions[index] })),
    ) : { rows: [], nextCursor: null };
    request.signal?.throwIfAborted();
    const { transactionEnd: _transactionEnd, ...verifiedAccount } = account;
    return { target, account: verifiedAccount, page, transactionProofs: transactions.map((tx) => tx.proof) };
}

export async function verifyBlockBundle(options: BlockBundleOptions, raw: unknown): Promise<VerifiedBlockBundle> {
    // Authenticate the ancestry from the covering certificate to the block's parent. Those headers
    // fix the block's own append interval.
    const request = blockRequest(options);
    const envelope = parseEnvelope(raw, 50);
    if (envelope.account !== null) throw new Error('block bundle contains account proof');
    const target = await certifiedTarget(request, envelope);
    const { block, blockDigest, start, end } = await owningBlock(target, envelope, request.height, request.signal);
    const count = end - start;

    // The page must fill the interval from the offset, one row per consecutive location, so the
    // indexer cannot omit or reorder transactions.
    if (request.offset > count) throw new Error('block offset exceeds transaction count');
    const expectedCount = Number(count - request.offset < 50n ? count - request.offset : 50n);
    if (envelope.transactions.length !== expectedCount) throw new Error('block page does not cover the expected append interval');
    for (let index = 0; index < expectedCount; index++) {
        const row = envelope.transactions[index]!;
        if (row.height !== request.height || row.location !== start + request.offset + BigInt(index) || BigInt(row.index) !== request.offset + BigInt(index)) {
            throw new Error('block row does not match its exact append position');
        }
    }

    // The next offset follows from the authenticated transaction count, not the indexer's claim.
    const nextOffset = request.offset + BigInt(expectedCount) < count ? request.offset + BigInt(expectedCount) : null;
    if ((envelope.nextCursor === null ? null : decimal(envelope.nextCursor, 'block next offset')) !== nextOffset) {
        throw new Error('block next offset does not match the authenticated transaction count');
    }

    // Report the covering certificate, then attribute each verified proof to the owning block.
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: target.height, view: target.view });
    const transactions = (await verifyTransactions(envelope, target)).map((transaction) => ({
        ...transaction, proof: { ...transaction.proof, height: block.height, view: block.view },
    }));
    request.signal?.throwIfAborted();
    return { target, block: { height: block.height, blockDigest, view: block.view, transactionCount: count }, transactions, nextOffset };
}

export async function verifyTransactionBundle(options: TransactionBundleOptions, raw: unknown): Promise<VerifiedTransactionBundle> {
    // Bind the row to its owning block's append interval to authenticate its height and index.
    const request = transactionRequest(options);
    const envelope = parseEnvelope(raw, 1);
    if (envelope.account !== null || envelope.transactions.length !== 1 || envelope.nextCursor !== null) {
        throw new Error('single transaction bundle has invalid cardinality');
    }
    const target = await certifiedTarget(request, envelope);
    const row = envelope.transactions[0]!;
    const { block, blockDigest, start, end } = await owningBlock(target, envelope, row.height, request.signal);
    if (row.location < start || row.location >= end || BigInt(row.index) !== row.location - start) {
        throw new Error('transaction is not at its claimed owning-block append position');
    }

    const [transaction] = await verifyTransactions(envelope, target);
    if (transaction!.digest !== request.digest) throw new Error('transaction body does not match requested digest');
    request.signal?.throwIfAborted();
    request.onFinalizationVerified?.({ height: block.height, view: block.view });
    const { proof, ...body } = transaction!;
    return { ...proof, height: block.height, view: block.view, target,
        transaction: { ...body, index: row.index }, blockDigest };
}

type BundleKind = 'account' | 'block' | 'transaction';

async function loadEnvelope(options: CommonOptions, load: () => Promise<ProofBundle>, kind: BundleKind): Promise<unknown> {
    options.signal?.throwIfAborted();
    const initialization = Promise.all([
        prewarmProofVerification(options.simplexVerificationMaterial),
        ...(kind === 'account' ? [initAccountProofWasm()] : []),
    ]).then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    const bundle = await load();
    options.signal?.throwIfAborted();
    const raw = proofBundleInput(bundle, kind);
    const initialized = await initialization;
    if (!initialized.ok) throw initialized.error;
    options.signal?.throwIfAborted();
    return raw;
}

/** Converts bounded protobuf fields to the verifier's canonical inputs without trusting metadata. */
export function proofBundleInput(bundle: ProofBundle, kind: BundleKind): unknown {
    const bytes = (value: Uint8Array, label: string, maximum: number) => {
        if (!(value instanceof Uint8Array) || value.length > maximum) throw new Error(`invalid or oversized ${label}`);
        return toHex(value);
    };
    if (bundle.headers.length > MAX_HEADERS || bundle.transactions.length > 50) throw new Error('oversized proof bundle');
    const next = bundle.nextCursor;
    if (next.case !== undefined && next.case !== (kind === 'account' ? 'activityCursor' : kind === 'block' ? 'blockOffset' : undefined)) {
        throw new Error('proof bundle cursor does not match requested view');
    }
    return {
        certificate: bytes(bundle.certificate, 'certificate', MAX_FINALIZATION_CERTIFICATE_BYTES),
        headers: bundle.headers.map((header) => bytes(header, 'execution header', MAX_EXECUTION_HEADER_BYTES)),
        sequenceNumber: u64(bundle.sequenceNumber, 'Store sequence').toString(),
        account: bundle.account ? {
            location: u64(bundle.account.location, 'account location').toString(),
            proof: bytes(bundle.account.proof, 'account proof', MAX_PROOF_BYTES),
            writeHeight: u64(bundle.account.writeHeight, 'account write height').toString(),
            encodedOperation: bytes(bundle.account.encodedOperation, 'account operation', ACCOUNT_OPERATION_BYTES),
        } : null,
        transactions: bundle.transactions.map((row) => ({
            location: u64(row.location, 'transaction location').toString(),
            body: bytes(row.body, 'signed transaction', MAX_TRANSACTION_BYTES),
            height: u64(row.height, 'transaction height').toString(), index: row.index, role: row.role,
            senderIndex: u64(row.senderIndex, 'sender index').toString(), recipientIndex: u64(row.recipientIndex, 'recipient index').toString(),
        })),
        transactionsProof: bundle.transactionsProof === undefined ? null : bytes(bundle.transactionsProof, 'transaction multiproof', MAX_PROOF_BYTES),
        nextCursor: next.case === 'activityCursor' ? bytes(next.value, 'account cursor', 8)
            : next.case === 'blockOffset' ? u64(next.value, 'block offset').toString() : null,
    };
}

async function certifiedTarget(
    options: Pick<CommonOptions, 'simplexVerificationMaterial' | 'signal'>,
    envelope: Pick<Envelope, 'certificate' | 'sequenceNumber'>,
): Promise<CertifiedTarget> {
    options.signal?.throwIfAborted();
    const context = await certificateContext(options.simplexVerificationMaterial);
    options.signal?.throwIfAborted();
    let verified = context.lastVerified;

    // Reuse the cached target only for byte-identical certificates, since the certificate bytes
    // include the execution header bound to the signed commitment.
    if (!verified || !bytesEqual(verified.certificate, envelope.certificate)) {
        const certificate = await context.verifier.verifyFinalization(envelope.certificate, {
            kind: 'finalization', index: 'latest', height: 0n,
            key: new Uint8Array(), value: envelope.certificate, source: 'get',
        });
        if (!certificate) throw new Error('aggregate finalization certificate is invalid');
        const target = await finalizedTargetFromCertificate(certificate);

        if (target.height === 0n) throw new Error('invalid certified execution header');
        verified = { certificate: envelope.certificate.slice(), target };
    }

    // Callers receive copies so they cannot mutate the cached target. The sequence comes from this
    // response because it is not part of the certificate.
    options.signal?.throwIfAborted();
    context.lastVerified = verified;
    const target = verified.target;
    return {
        ...target, blockDigest: target.blockDigest.slice(), parentDigest: target.parentDigest.slice(),
        stateRoot: target.stateRoot.slice(), transactionsRoot: target.transactionsRoot.slice(),
        sequenceNumber: envelope.sequenceNumber,
    };
}

/**
 * Authenticates headers from the certified target back to the parent of `height` and returns the
 * block's own transaction append interval `[start, end)`.
 */
async function owningBlock(target: CertifiedTarget, envelope: Envelope, height: bigint, signal?: AbortSignal) {
    if (height === 0n || height > target.height) throw new Error('invalid owning block height');
    const lowest = height === 1n ? height : height - 1n;
    const chain = await authenticatedChain(target, envelope.headers, lowest, signal);
    const index = Number(target.height - height);
    const { header: block, digest: blockDigest } = chain[index]!;
    const { start, end } = appendInterval(block, chain[index + 1]?.header);
    if (end > target.transactionsTip - 1n) throw new Error('owning-block append interval is invalid');
    return { block, blockDigest, start, end };
}

/** Authenticates an exact descending chain, including its terminal overlap header. */
async function authenticatedChain(target: CertifiedTarget, headers: readonly Uint8Array[], lowest: bigint, signal?: AbortSignal) {
    if (lowest < 1n || lowest > target.height || BigInt(headers.length) !== target.height - lowest) {
        throw new Error('aggregate ancestry does not cover the exact owning block and parent');
    }
    let current: DecodedBlockHeader = { ...target, view: target.contextView, endOffset: 0 };
    let digest = target.blockDigest;
    const chain = [{ header: current, digest }];
    for (const bytes of headers) {
        signal?.throwIfAborted();
        digest = current.parentDigest;
        const parent = await authenticatedHeader(bytes, digest, current.height - 1n);
        if (parent.timestampMs > current.timestampMs) throw new Error('block timestamp precedes its parent');
        appendInterval(current, parent);
        stateAppendInterval(current, parent);
        current = parent;
        chain.push({ header: current, digest });
    }
    signal?.throwIfAborted();
    return chain;
}

/** One Commit follows every block's appends; genesis contributes the initial Commit. */
function appendInterval(block: DecodedBlockHeader, parent?: DecodedBlockHeader) {
    if (block.height === 1n && block.transactionsStart !== 0n) throw new Error('block one has a noncanonical transaction floor');
    const start = block.height === 1n ? 1n : parent?.transactionsTip;
    const end = block.transactionsTip - 1n;
    if (start === undefined || start > end) throw new Error('owning-block append interval is invalid');
    return { start, end };
}

function stateAppendInterval(block: DecodedBlockHeader, parent?: DecodedBlockHeader) {
    const start = block.height === 1n ? 1n : parent?.stateTip;
    const end = block.stateTip - 1n;
    if (start === undefined || start > end) throw new Error('owning-block state interval is invalid');
    return { start, end };
}

/** Verifies the account's active update and the history end of the block that wrote it. */
async function verifyAccount(envelope: Envelope, target: CertifiedTarget, account: Uint8Array, signal?: AbortSignal): Promise<VerifiedAccountProof & { transactionEnd: bigint }> {
    if (envelope.account === null) throw new Error('missing account proof');
    const { location, proof, writeHeight, encodedOperation } = envelope.account;
    const verified = await verifyCurrentAccount(proof, target.stateRoot, account, target.stateTip - 1n, encodedOperation);
    signal?.throwIfAborted();
    if (verified.location !== location) throw new Error('account proof location does not match its operation');
    if (writeHeight === 0n || writeHeight > target.height) throw new Error('invalid account write height');
    if (location < target.stateStart || location >= target.stateTip - 1n) throw new Error('account update is outside certified state interval');
    const lowest = writeHeight === 1n ? 1n : writeHeight - 1n;
    const chain = await authenticatedChain(target, envelope.headers, lowest, signal);
    const index = Number(target.height - writeHeight);
    const writer = chain[index]!.header;
    const { start, end } = stateAppendInterval(writer, chain[index + 1]?.header);
    if (location < start || location >= end) throw new Error('account location is outside its writing block');
    return { ...decodeAccountValue(verified.value), location, tip: target.stateTip - 1n,
        writeHeight, timestampMs: writer.timestampMs, transactionEnd: writer.transactionsTip - 1n,
        proofSizeBytes: verified.proofSizeBytes };
}

async function verifyTransactions(envelope: Envelope, target: LatestProofTarget): Promise<Array<CanonicalTransaction & { proof: VerifiedTransactionProof }>> {
    if (envelope.transactions.length === 0) {
        if (envelope.transactionsProof !== null) throw new Error('empty transaction page contains a proof');
        return [];
    }
    if (envelope.transactionsProof === null) throw new Error('transaction page is missing its multiproof');

    // The history commitment binds the body digest and both participant indices.
    const transactions = await Promise.all(envelope.transactions.map(decodeTransaction));
    const expectations = new Map<bigint, Uint8Array>();
    for (let index = 0; index < transactions.length; index++) {
        const transaction = transactions[index]!;
        const row = envelope.transactions[index]!;
        if (row.location === 0n || row.location >= target.transactionsTip - 1n) {
            throw new Error('transaction is outside certified history');
        }
        const value = new Uint8Array(48);
        value.set(fromHex(transaction.digest));
        const indices = new DataView(value.buffer);
        indices.setBigUint64(32, row.senderIndex);
        indices.setBigUint64(40, row.recipientIndex);
        const previous = expectations.get(row.location);
        if (previous !== undefined && !bytesEqual(previous, value)) throw new Error('conflicting transaction entries at one location');
        expectations.set(row.location, value);
    }
    const expected = [...expectations].sort(([left], [right]) => left < right ? -1 : 1).map(([location, value]) => ({ location, value }));
    const proof = await verifier.verifyFixedKeylessAppendMany(envelope.transactionsProof, { tip: target.transactionsTip - 1n }, target.transactionsRoot, expected);
    return transactions.map((transaction) => ({ ...transaction, proof: {
        location: transaction.location, tip: target.transactionsTip - 1n,
        height: target.height, view: target.view, proofSizeBytes: proof.proofSizeBytes,
    } }));
}

async function decodeTransaction(row: TransactionRow): Promise<CanonicalTransaction> {
    // Check the sender scheme's signature encoding. Ed25519 signatures are fixed size, while
    // WebAuthn signatures carry bounded authenticator data and client JSON with no trailing bytes.
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

    // The digest covers only the unsigned body, and the sender account derives from its public key.
    const value = readU64Be(body, 66);
    if (value === 0n) throw new Error('transaction value must be nonzero');
    const [digest, sender] = await Promise.all([
        crypto.subtle.digest('SHA-256', toArrayBuffer(body.slice(0, TRANSACTION_BODY_BYTES))),
        accountKeyFromPublicKey(key),
    ]);
    return { digest: toHex(new Uint8Array(digest)), sender: toHex(sender), recipient: toHex(body.slice(34, 66)), value, nonce: readU64Be(body, 74), location: row.location };
}

/** Checks the response shape and every size bound before any cryptographic work. */
function parseEnvelope(raw: unknown, pageSize: number): Envelope {
    const value = record(raw, 'aggregate response');
    const headers = array(value.headers, 'headers', MAX_HEADERS).map((entry) => hex(entry, 'execution header', 1, MAX_EXECUTION_HEADER_BYTES));
    const transactions = array(value.transactions, 'transactions', pageSize).map((entry) => {
        const row = record(entry, 'transaction row');
        if (!Number.isInteger(row.index) || (row.index as number) < 0 || (row.index as number) > 0xffffffff) throw new Error('invalid transaction index');
        if (row.role !== undefined && row.role !== 0 && row.role !== 1) throw new Error('invalid transaction role');
        return { location: decimal(row.location, 'transaction location'), body: hex(row.body, 'signed transaction', 1, MAX_TRANSACTION_BYTES), height: decimal(row.height, 'transaction height'), index: row.index as number, role: row.role as number | undefined, senderIndex: decimal(row.senderIndex, 'sender index'), recipientIndex: decimal(row.recipientIndex, 'recipient index') };
    });
    const account = value.account === null ? null : record(value.account, 'account proof');
    if (value.nextCursor !== null && (typeof value.nextCursor !== 'string' || value.nextCursor.length > 48)) throw new Error('invalid next cursor');
    return {
        certificate: hex(value.certificate, 'certificate', 1, MAX_FINALIZATION_CERTIFICATE_BYTES), headers,
        sequenceNumber: decimal(value.sequenceNumber, 'Store sequence'),
        account: account === null ? null : { location: decimal(account.location, 'account location'), proof: hex(account.proof, 'account proof', 1, MAX_PROOF_BYTES), writeHeight: decimal(account.writeHeight, 'account write height'),
            encodedOperation: hex(account.encodedOperation, 'account operation', ACCOUNT_OPERATION_BYTES, ACCOUNT_OPERATION_BYTES) },
        transactions, transactionsProof: value.transactionsProof === null ? null : hex(value.transactionsProof, 'transaction multiproof', 1, MAX_PROOF_BYTES),
        nextCursor: value.nextCursor as string | null,
    };
}

function certificateContext(material: string): Promise<CertificateContext> {
    const key = material.trim().toLowerCase();
    if (!/^(?:[0-9a-f]{2})+$/.test(key) || key.length > 2 * 1024 * 1024) throw new Error('invalid Simplex verification material');
    let pending = certificateInitializations.get(key);

    // Share one initialization per material. A failure is evicted so the next request retries, and
    // the oldest entry is evicted beyond four.
    if (!pending) {
        pending = simplexFinalizationVerifier(key).then((verifier) => ({ verifier }));
        certificateInitializations.set(key, pending);
        pending.catch(() => { if (certificateInitializations.get(key) === pending) certificateInitializations.delete(key); });
        if (certificateInitializations.size > 4) certificateInitializations.delete(certificateInitializations.keys().next().value!);
    }
    return pending;
}

function accountRequest(options: AccountBundleOptions) {
    const cursor = options.cursor == null ? null : typeof options.cursor === 'string'
        ? hex(options.cursor, 'account cursor', 8, 8) : options.cursor.slice();
    if (cursor && cursor.length !== 8) throw new Error('invalid account cursor');
    const at = options.at === undefined ? undefined : { height: u64(options.at.height, 'snapshot height', true), blockDigest: options.at.blockDigest.slice() };
    if (at && at.blockDigest.length !== 32) throw new Error('invalid snapshot digest');
    const accountLocation = options.accountLocation === undefined ? undefined : u64(options.accountLocation, 'account location');
    const expectedTxCount = options.expectedTxCount === undefined ? undefined : u64(options.expectedTxCount, 'transaction count');
    if (cursor && (!at || accountLocation === undefined || expectedTxCount === undefined)) {
        throw new Error('account pagination requires a fixed snapshot, account location and transaction count');
    }
    if (accountLocation !== undefined && !at) throw new Error('account location requires a fixed snapshot');
    if (cursor && readU64Be(cursor, 0) > expectedTxCount!) throw new Error('account cursor exceeds authenticated count');
    if (options.includeTransactions === false && cursor) throw new Error('balance-only request cannot include a cursor');
    return { ...options, account: toHex(parseAccountKeyHex(options.account)), cursor, at, accountLocation, expectedTxCount, includeTransactions: options.includeTransactions ?? true };
}

function blockRequest(options: BlockBundleOptions) {
    return { ...options, height: u64(options.height, 'block height', true), offset: u64(options.offset ?? 0n, 'block offset') };
}

function transactionRequest(options: TransactionBundleOptions) {
    return { ...options, digest: toHex(parseAccountKeyHex(options.digest)) };
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
