import { fromHex, toArrayBuffer } from './codec.ts';
import { assertTransactionLocationBeforeTip, transactionProofTip } from './proofMath.ts';
import type { PublishedProofTarget } from './proofTarget.ts';
import {
    BLOCK_META_HEIGHT,
    containingTransactionHeight,
    transactionHeightPredecessorQuery,
} from './transactionHeight.ts';
import {
    SqlClient,
    type CellValue,
    type DecodedQueryResult,
    type DecodedRow,
} from '@exowarexyz/sql';
import { Client, StoreKeyPrefix } from '@exowarexyz/sdk';
import {
    SimplexClient,
    type VerifiedSimplexCertificate,
    type SimplexCertificateVerifier,
} from '@exowarexyz/simplex';
import { createWasmSimplexVerifier } from '@exowarexyz/simplex/wasm';
import {
    QmdbOperationLogClient,
    type VerifiedFixedKeylessAppendProof,
    type VerifiedFixedUnorderedUpdateProof,
} from '@exowarexyz/qmdb';

const CONSENSUS_NAMESPACE = new TextEncoder().encode('constantinople_CONSENSUS');
const SIMPLEX_SCHEME = 'bls12381-threshold-standard-min-sig';
const SIMPLEX_STORE_PREFIX = new Uint8Array([0x02]);
const ACCOUNT_PAGE_SIZE = 10;
const ACCOUNT_KEY_BYTES = 32;
const DIGEST_BYTES = 32;
const COMMITMENT_BYTES = 3 * DIGEST_BYTES + 4;
const ED25519_PUBLIC_KEY_BYTES = 32;
const TRANSACTION_PUBLIC_KEY_BYTES = 34;
const TRANSACTION_VALUE_BYTES = 8;
const TRANSACTION_NONCE_BYTES = 8;
const TRANSACTION_BODY_BYTES =
    TRANSACTION_PUBLIC_KEY_BYTES + ACCOUNT_KEY_BYTES + TRANSACTION_VALUE_BYTES + TRANSACTION_NONCE_BYTES;
const ACCOUNT_VALUE_BYTES = 24;
const ACCOUNT_CURSOR_BYTES = 24;

const TX_META_TABLE = 'tx_meta';
const TX_META_DIGEST = 'tx_digest';
const TX_META_QMDB_LOCATION = 'qmdb_location';
const TX_META_BODY = 'body';

const TX_ACTIVITY_TABLE = 'tx_activity';
const TX_ACTIVITY_ACCOUNT = 'account';
const TX_ACTIVITY_HEIGHT = 'height';
const TX_ACTIVITY_INDEX = 'index';
const TX_ACTIVITY_ROLE = 'role';
const TX_ACTIVITY_DIGEST = 'tx_digest';
const TX_ACTIVITY_COUNTERPARTY = 'counterparty';
const TX_ACTIVITY_VALUE = 'value';
const TX_ACTIVITY_NONCE = 'nonce';
const TX_ACTIVITY_ROLE_SENDER = 0n;
const TX_ACTIVITY_ROLE_RECEIVER = 1n;

const ACCOUNT_META_TABLE = 'account_meta';
const ACCOUNT_META_ACCOUNT = 'account';
const ACCOUNT_META_BALANCE = 'balance';
const ACCOUNT_META_NONCE_BASE = 'nonce_base';
const ACCOUNT_META_NONCE_BITMAP = 'nonce_bitmap';
const ACCOUNT_META_QMDB_LOCATION = 'qmdb_location';

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

interface TransactionProofMetadata {
    readonly height: bigint;
    readonly location: bigint;
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

export async function fetchAndVerifyTransactionProof({
    qmdbUrl,
    storeUrl,
    sqlUrl,
    simplexVerificationMaterial,
    digest,
    publishedTarget,
    signal,
    onFinalizationVerified,
}: {
    qmdbUrl: string;
    storeUrl: string;
    sqlUrl: string;
    simplexVerificationMaterial: string;
    digest: string;
    publishedTarget: PublishedProofTarget;
    signal?: AbortSignal;
    onFinalizationVerified?: (target: VerifiedFinalizationTarget) => void;
}): Promise<VerifiedTransactionProof> {
    const proofTarget = await fetchLatestProofTarget({
        storeUrl,
        simplexVerificationMaterial,
        publishedTarget,
        signal,
    });
    const metadata = await fetchTransactionProofMetadata(
        sqlUrl,
        digest,
        proofTarget.sequenceNumber,
        signal,
    );
    if (metadata.location >= proofTarget.transactionsTip) {
        throw new Error(
            `transaction location ${metadata.location} is not yet covered by a provable finalization`,
        );
    }
    const target = await finalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        metadata.height,
        proofTarget.sequenceNumber,
        signal,
    );
    onFinalizationVerified?.(target);
    if (metadata.location < target.transactionsStart || metadata.location >= target.transactionsTip) {
        throw new Error(`transaction location ${metadata.location} is outside finalized block range`);
    }

    const tip = transactionProofTip(target.transactionsTip);
    let verification: VerifiedFixedKeylessAppendProof;
    try {
        verification = await fetchFixedKeylessAppendProof(
            `${trimTrailingSlash(qmdbUrl)}/transactions`,
            metadata.location,
            tip,
            target.transactionsRoot,
            fromHex(digest),
            proofTarget.sequenceNumber,
            signal,
        );
    } catch (error) {
        throw new Error(transactionProofErrorDetail(error, target, metadata));
    }

    return {
        location: metadata.location,
        tip,
        height: target.height,
        view: target.view,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

// The published target is committed atomically with the state and transaction
// QMDB publication boundary. The certificate read authenticates its digest
// and supplies the roots used for subsequent proofs.
export async function fetchLatestProofTarget({
    storeUrl,
    simplexVerificationMaterial,
    publishedTarget,
    signal,
}: {
    storeUrl: string;
    simplexVerificationMaterial: string;
    publishedTarget: PublishedProofTarget;
    signal?: AbortSignal;
}): Promise<LatestProofTarget> {
    const target = await finalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        publishedTarget.height,
        publishedTarget.sequenceNumber,
        signal,
    );
    if (!bytesEqual(target.blockDigest, publishedTarget.blockDigest)) {
        throw new Error(
            `provable target digest does not match finalized certificate at height ${publishedTarget.height}`,
        );
    }
    return { ...target, sequenceNumber: publishedTarget.sequenceNumber };
}

export async function fetchAccountTransactionsPage({
    sqlUrl,
    account,
    cursor,
    mode = 'all',
    minSequenceNumber,
    maxHeight,
    signal,
}: {
    sqlUrl: string;
    account: string;
    cursor?: Uint8Array | null;
    mode?: AccountActivityMode;
    minSequenceNumber: bigint;
    maxHeight: bigint;
    signal?: AbortSignal;
}): Promise<AccountTransactionPage> {
    const accountBytes = parseAccountBytes(account);
    const rows = await fetchAccountActivityRows(
        sqlUrl,
        accountBytes,
        cursor ?? null,
        mode,
        minSequenceNumber,
        maxHeight,
        signal,
    );
    const visible = rows.slice(0, ACCOUNT_PAGE_SIZE);
    const last = visible[visible.length - 1];
    return {
        rows: visible.map(decodeAccountActivityRow),
        nextCursor: rows.length > ACCOUNT_PAGE_SIZE && last ? encodeActivityCursor(last) : null,
    };
}

export async function fetchAndVerifyAccountProof({
    qmdbUrl,
    sqlUrl,
    account,
    target,
    signal,
}: {
    qmdbUrl: string;
    sqlUrl: string;
    account: string;
    target: LatestProofTarget;
    signal?: AbortSignal;
}): Promise<VerifiedAccountProof> {
    const accountBytes = parseAccountBytes(account);
    const stateEnd = target.stateTip;
    // account_meta keeps one row per state operation, so the account's value
    // at this certificate is its newest row below the certificate's state tip.
    // Rows written after the target are simply not visible to this proof.
    const row = await fetchAccountProofRow(
        sqlUrl,
        accountBytes,
        stateEnd,
        target.sequenceNumber,
        signal,
    );
    if (row.location < target.stateStart) {
        throw new Error(`account location ${row.location} is outside finalized state range`);
    }

    const tip = transactionProofTip(stateEnd);
    const verification = await fetchFixedUnorderedUpdateProof(
        `${trimTrailingSlash(qmdbUrl)}/state`,
        row.location,
        tip,
        target.stateRoot,
        accountBytes,
        ACCOUNT_VALUE_BYTES,
        target.sequenceNumber,
        signal,
    );
    const accountValue = decodeAccountValue(verification.value);

    if (
        accountValue.balance !== row.balance ||
        accountValue.nonce !== row.nonce ||
        accountValue.nonceBitmap !== row.nonceBitmap
    ) {
        throw new Error('account proof value does not match account index row');
    }

    return {
        balance: accountValue.balance,
        nonce: accountValue.nonce,
        nonceBitmap: accountValue.nonceBitmap,
        location: row.location,
        tip,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

export async function fetchAndVerifyTransactionRowProof({
    qmdbUrl,
    sqlUrl,
    row,
    target,
    signal,
}: {
    qmdbUrl: string;
    sqlUrl: string;
    row: AccountTransactionRow;
    target: LatestProofTarget;
    signal?: AbortSignal;
}): Promise<VerifiedTransactionProof> {
    const digestBytes = fromHex(row.digest);
    assertByteLength(digestBytes, DIGEST_BYTES, 'transaction digest');
    const location = await fetchVerifiedSqlTransactionMetadata(
        sqlUrl,
        digestBytes,
        target.sequenceNumber,
        signal,
    );

    if (location >= target.transactionsTip) {
        throw new Error(
            `transaction location ${location} is not yet covered by a provable finalization`,
        );
    }
    assertTransactionLocationBeforeTip(location, target.transactionsTip);

    const tip = transactionProofTip(target.transactionsTip);
    const verification = await fetchFixedKeylessAppendProof(
        `${trimTrailingSlash(qmdbUrl)}/transactions`,
        location,
        tip,
        target.transactionsRoot,
        digestBytes,
        target.sequenceNumber,
        signal,
    );

    return {
        location,
        tip,
        height: target.height,
        view: target.view,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

async function fetchVerifiedSqlTransactionMetadata(
    sqlUrl: string,
    digest: Uint8Array,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<bigint> {
    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT ${TX_META_QMDB_LOCATION}, ${TX_META_BODY}
            FROM ${TX_META_TABLE}
            WHERE ${TX_META_DIGEST} = ${fixedBinaryLiteral(digest)}
            LIMIT 1
        `,
        minSequenceNumber,
        signal,
    );
    const row = result.rows[0];
    if (!row) {
        throw new Error(`tx digest ${shortHex(toHex(digest))} missing from raw transaction index`);
    }

    const location = expectBigint(row.values[TX_META_QMDB_LOCATION], TX_META_QMDB_LOCATION);
    const signedTransaction = expectVariableBytes(row.values[TX_META_BODY], TX_META_BODY);
    if (signedTransaction.length < TRANSACTION_BODY_BYTES) {
        throw new Error('SQL transaction body is truncated');
    }
    const transactionBody = signedTransaction.slice(0, TRANSACTION_BODY_BYTES);
    const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(transactionBody)));
    if (!bytesEqual(actual, digest)) {
        throw new Error('SQL transaction body does not match transaction digest');
    }
    return location;
}

async function fetchTransactionProofMetadata(
    sqlUrl: string,
    digest: string,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<TransactionProofMetadata> {
    const digestBytes = fromHex(digest);
    assertByteLength(digestBytes, DIGEST_BYTES, 'transaction digest');
    let location: bigint;
    try {
        location = await fetchVerifiedSqlTransactionMetadata(
            sqlUrl,
            digestBytes,
            minSequenceNumber,
            signal,
        );
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        if (detail.includes('missing from raw transaction index')) {
            throw new Error(`tx digest ${shortHex(digest)} is not finalized yet`);
        }
        throw error;
    }
    const result = await sqlQuery(
        sqlUrl,
        transactionHeightPredecessorQuery(location),
        minSequenceNumber,
        signal,
    );
    const row = result.rows[0];
    return {
        height: containingTransactionHeight(
            row ? expectBigint(row.values[BLOCK_META_HEIGHT], BLOCK_META_HEIGHT) : null,
        ),
        location,
    };
}

function transactionProofErrorDetail(
    error: unknown,
    target: FinalizedTransactionTarget,
    metadata: TransactionProofMetadata,
): string {
    const reason = error instanceof Error ? error.message : String(error);
    return [
        reason,
        `height ${target.height.toString()}`,
        `location ${metadata.location.toString()}`,
        `tip ${transactionProofTip(target.transactionsTip).toString()}`,
        `proof start ${metadata.location.toString()}`,
        'ops 1',
    ].join(' · ');
}

async function fetchFixedKeylessAppendProof(
    serviceUrl: string,
    location: bigint,
    tip: bigint,
    expectedRoot: Uint8Array,
    expectedValue: Uint8Array,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
) {
    const client = new QmdbOperationLogClient(serviceUrl);
    const proof = await client.getFixedKeylessAppend(
        {
            tip,
            startLocation: location,
            maxLocations: 1,
            minSequenceNumber,
        },
        expectedRoot,
        location,
        expectedValue,
        { signal },
    );
    assertEvaluatedSequence(
        proof.sequenceNumber,
        minSequenceNumber,
        'QMDB transaction proof',
    );
    return proof;
}

async function fetchFixedUnorderedUpdateProof(
    serviceUrl: string,
    location: bigint,
    tip: bigint,
    expectedRoot: Uint8Array,
    expectedKey: Uint8Array,
    valueSize: number,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<VerifiedFixedUnorderedUpdateProof> {
    const client = new QmdbOperationLogClient(serviceUrl);
    const proof = await client.getFixedUnorderedUpdate(
        {
            tip,
            startLocation: location,
            maxLocations: 1,
            minSequenceNumber,
        },
        expectedRoot,
        location,
        expectedKey,
        valueSize,
        { signal },
    );
    assertEvaluatedSequence(proof.sequenceNumber, minSequenceNumber, 'QMDB account proof');
    return proof;
}

function finalizedTransactionTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    return fetchFinalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        height,
        minSequenceNumber,
        signal,
    );
}

async function fetchFinalizedTransactionTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    const simplex = await verifiedSimplexClient(storeUrl, simplexVerificationMaterial);
    const certificate = await simplex.getFinalizationByHeight(
        height.toString(),
        minSequenceNumber,
        { signal },
    );
    if (!certificate) {
        throw new Error(`finalization missing at height ${height} while Simplex catches up`);
    }
    const target = await finalizedTargetFromCertificate(certificate);
    if (target.height !== height) {
        throw new Error(`finalized certificate height ${target.height} does not match requested height ${height}`);
    }
    return target;
}

async function verifiedSimplexClient(
    storeUrl: string,
    simplexVerificationMaterial: string,
): Promise<SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>> {
    if (simplexVerificationMaterial.trim().length === 0) {
        throw new Error('Simplex verification material is not configured');
    }
    const store = new Client(trimTrailingSlash(storeUrl)).store(
        new StoreKeyPrefix(SIMPLEX_STORE_PREFIX),
    );
    return new SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>(store, {
        verifier: await simplexFinalizationVerifier(simplexVerificationMaterial),
    });
}

function simplexFinalizationVerifier(
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

async function finalizedTargetFromCertificate(
    certificate: VerifiedSimplexCertificate,
): Promise<FinalizedTransactionTarget> {
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
    };
}

interface DecodedBlockHeader {
    readonly height: bigint;
    readonly stateRoot: Uint8Array;
    readonly stateStart: bigint;
    readonly stateTip: bigint;
    readonly transactionsRoot: Uint8Array;
    readonly transactionsStart: bigint;
    readonly transactionsTip: bigint;
    readonly endOffset: number;
}

function decodeBlockHeader(bytes: Uint8Array, offset: number): DecodedBlockHeader {
    // Header<Commitment, Sha256, Ed25519>: Context, parent digest, height,
    // timestamp, state target, and transaction target. We keep this parser
    // narrow and verify the exact encoded header hash before trusting fields.
    offset = readVarint(bytes, offset).offset; // context.round.epoch
    offset = readVarint(bytes, offset).offset; // context.round.view
    offset = skip(bytes, offset, ED25519_PUBLIC_KEY_BYTES); // context.leader
    offset = readVarint(bytes, offset).offset; // context.parent.view
    offset = skip(bytes, offset, COMMITMENT_BYTES); // context.parent.digest
    offset = skip(bytes, offset, DIGEST_BYTES); // header.parent
    const height = readU64Be(bytes, offset);
    offset = skip(bytes, offset, 8);
    offset = skip(bytes, offset, 8); // header.timestamp
    const stateRoot = readBytes(bytes, offset, DIGEST_BYTES);
    offset = skip(bytes, offset, DIGEST_BYTES);
    const stateStart = readU64Be(bytes, offset);
    offset = skip(bytes, offset, 8);
    const stateTip = readU64Be(bytes, offset);
    offset = skip(bytes, offset, 8);
    const transactionsRoot = readBytes(bytes, offset, DIGEST_BYTES);
    offset = skip(bytes, offset, DIGEST_BYTES);
    const transactionsStart = readU64Be(bytes, offset);
    offset = skip(bytes, offset, 8);
    const transactionsTip = readU64Be(bytes, offset);
    offset = skip(bytes, offset, 8);
    if (stateStart >= stateTip || transactionsStart >= transactionsTip) {
        throw new Error('finalized block contains an empty QMDB range');
    }
    return {
        height,
        stateRoot,
        stateStart,
        stateTip,
        transactionsRoot,
        transactionsStart,
        transactionsTip,
        endOffset: offset,
    };
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
        value |= BigInt(byte & 0x7f) << shift;
        if ((byte & 0x80) === 0) {
            return { value, offset };
        }
        shift += 7n;
    }
    throw new Error('finalized block header varint is too long');
}

async function fetchAccountActivityRows(
    sqlUrl: string,
    account: Uint8Array,
    cursor: Uint8Array | null,
    mode: AccountActivityMode,
    minSequenceNumber: bigint,
    maxHeight: bigint,
    signal?: AbortSignal,
): Promise<DecodedRow[]> {
    const predicates = [
        `${TX_ACTIVITY_ACCOUNT} = ${fixedBinaryLiteral(account)}`,
    ];
    const role = activityModeRole(mode);
    if (role !== null) {
        predicates.push(`${TX_ACTIVITY_ROLE} = ${role.toString()}`);
    }
    if (cursor) {
        predicates.push(activityCursorPredicate(decodeActivityCursor(cursor)));
    }
    predicates.push(`${TX_ACTIVITY_HEIGHT} <= ${maxHeight.toString()}`);

    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT
                ${TX_ACTIVITY_HEIGHT},
                ${TX_ACTIVITY_INDEX},
                ${TX_ACTIVITY_ROLE},
                ${TX_ACTIVITY_DIGEST},
                ${TX_ACTIVITY_COUNTERPARTY},
                ${TX_ACTIVITY_VALUE},
                ${TX_ACTIVITY_NONCE}
            FROM ${TX_ACTIVITY_TABLE}
            WHERE ${predicates.join(' AND ')}
            ORDER BY ${TX_ACTIVITY_HEIGHT} DESC,
                     ${TX_ACTIVITY_INDEX} DESC,
                     ${TX_ACTIVITY_ROLE} DESC
            LIMIT ${ACCOUNT_PAGE_SIZE + 1}
        `,
        minSequenceNumber,
        signal,
    );
    return result.rows;
}

function decodeAccountActivityRow(row: DecodedRow): AccountTransactionRow {
    const role = expectBigint(row.values[TX_ACTIVITY_ROLE], TX_ACTIVITY_ROLE);
    const digest = expectBytes(row.values[TX_ACTIVITY_DIGEST], TX_ACTIVITY_DIGEST, DIGEST_BYTES);
    const counterparty = expectBytes(
        row.values[TX_ACTIVITY_COUNTERPARTY],
        TX_ACTIVITY_COUNTERPARTY,
        ACCOUNT_KEY_BYTES,
    );
    return {
        digest: toHex(digest),
        direction: role === TX_ACTIVITY_ROLE_RECEIVER ? 'received' : 'sent',
        counterparty: toHex(counterparty),
        value: expectBigint(row.values[TX_ACTIVITY_VALUE], TX_ACTIVITY_VALUE),
        nonce: expectBigint(row.values[TX_ACTIVITY_NONCE], TX_ACTIVITY_NONCE),
        height: expectBigint(row.values[TX_ACTIVITY_HEIGHT], TX_ACTIVITY_HEIGHT),
        blockIndex: expectSafeNumber(row.values[TX_ACTIVITY_INDEX], TX_ACTIVITY_INDEX),
    };
}

async function fetchAccountProofRow(
    sqlUrl: string,
    account: Uint8Array,
    beforeLocation: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AccountProofRow> {
    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT
                ${ACCOUNT_META_BALANCE},
                ${ACCOUNT_META_NONCE_BASE},
                ${ACCOUNT_META_NONCE_BITMAP},
                ${ACCOUNT_META_QMDB_LOCATION}
            FROM ${ACCOUNT_META_TABLE}
            WHERE ${ACCOUNT_META_ACCOUNT} = ${fixedBinaryLiteral(account)}
                AND ${ACCOUNT_META_QMDB_LOCATION} < ${beforeLocation.toString()}
            ORDER BY ${ACCOUNT_META_QMDB_LOCATION} DESC
            LIMIT 1
        `,
        minSequenceNumber,
        signal,
    );
    const row = result.rows[0];
    if (!row) {
        throw new Error(`account ${shortHex(toHex(account))} is not indexed`);
    }
    return {
        balance: expectBigint(row.values[ACCOUNT_META_BALANCE], ACCOUNT_META_BALANCE),
        nonce: expectBigint(row.values[ACCOUNT_META_NONCE_BASE], ACCOUNT_META_NONCE_BASE),
        nonceBitmap: expectBigint(
            row.values[ACCOUNT_META_NONCE_BITMAP],
            ACCOUNT_META_NONCE_BITMAP,
        ),
        location: expectBigint(row.values[ACCOUNT_META_QMDB_LOCATION], ACCOUNT_META_QMDB_LOCATION),
    };
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}...${value.slice(-8)}`;
}

async function sqlQuery(
    sqlUrl: string,
    query: string,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<DecodedQueryResult> {
    const sql = new SqlClient(trimTrailingSlash(sqlUrl));
    const result = await sql.query(
        query.replace(/\s+/g, ' ').trim(),
        { signal, minSequenceNumber },
    );
    assertEvaluatedSequence(result.sequenceNumber, minSequenceNumber, 'SQL query');
    return result;
}

function assertEvaluatedSequence(
    evaluated: bigint,
    minimum: bigint,
    operation: string,
): void {
    if (evaluated < minimum) {
        throw new Error(`${operation} evaluated before the requested Store sequence`);
    }
}

function fixedBinaryLiteral(bytes: Uint8Array): string {
    return `X'${toHex(bytes)}'`;
}

function activityModeRole(mode: AccountActivityMode): bigint | null {
    if (mode === 'sent') return TX_ACTIVITY_ROLE_SENDER;
    if (mode === 'received') return TX_ACTIVITY_ROLE_RECEIVER;
    return null;
}

interface ActivityCursor {
    readonly height: bigint;
    readonly index: bigint;
    readonly role: bigint;
}

function activityCursorPredicate(cursor: ActivityCursor): string {
    const height = cursor.height.toString();
    const index = cursor.index.toString();
    const role = cursor.role.toString();
    return `(
        ${TX_ACTIVITY_HEIGHT} < ${height}
        OR (${TX_ACTIVITY_HEIGHT} = ${height} AND ${TX_ACTIVITY_INDEX} < ${index})
        OR (
            ${TX_ACTIVITY_HEIGHT} = ${height}
            AND ${TX_ACTIVITY_INDEX} = ${index}
            AND ${TX_ACTIVITY_ROLE} < ${role}
        )
    )`;
}

function encodeActivityCursor(row: DecodedRow): Uint8Array {
    const cursor = new Uint8Array(ACCOUNT_CURSOR_BYTES);
    writeU64Be(cursor, 0, expectBigint(row.values[TX_ACTIVITY_HEIGHT], TX_ACTIVITY_HEIGHT));
    writeU64Be(cursor, 8, expectBigint(row.values[TX_ACTIVITY_INDEX], TX_ACTIVITY_INDEX));
    writeU64Be(cursor, 16, expectBigint(row.values[TX_ACTIVITY_ROLE], TX_ACTIVITY_ROLE));
    return cursor;
}

function decodeActivityCursor(cursor: Uint8Array): ActivityCursor {
    if (cursor.length !== ACCOUNT_CURSOR_BYTES) {
        throw new Error('malformed account activity cursor');
    }
    return {
        height: readU64Be(cursor, 0),
        index: readU64Be(cursor, 8),
        role: readU64Be(cursor, 16),
    };
}

function expectBigint(value: CellValue, column: string): bigint {
    if (typeof value !== 'bigint') {
        throw new Error(`SQL column ${column} must be UInt64`);
    }
    return value;
}

function expectSafeNumber(value: CellValue | bigint, column: string): number {
    const bigint = expectBigint(value, column);
    if (bigint > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`SQL column ${column} exceeds Number.MAX_SAFE_INTEGER`);
    }
    return Number(bigint);
}

function expectBytes(value: CellValue, column: string, length: number): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`SQL column ${column} must be FixedSizeBinary(${length})`);
    }
    assertByteLength(value, length, column);
    return value;
}

function expectVariableBytes(value: CellValue, column: string): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`SQL column ${column} must be Binary`);
    }
    return value;
}

function assertByteLength(bytes: Uint8Array, length: number, field: string) {
    if (bytes.length !== length) {
        throw new Error(`${field} must be ${length} bytes`);
    }
}

function decodeAccountValue(
    value: Uint8Array,
): Pick<AccountProofRow, 'balance' | 'nonce' | 'nonceBitmap'> {
    if (value.length !== ACCOUNT_VALUE_BYTES) {
        throw new Error('malformed account proof value');
    }
    return {
        balance: readU64Be(value, 0),
        nonce: readU64Be(value, 8),
        nonceBitmap: readU64Be(value, 16),
    };
}

function parseAccountBytes(account: string): Uint8Array {
    const normalized = account.trim().replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error('expected a 32-byte hex account key');
    }
    return fromHex(normalized);
}

function readU64Be(bytes: Uint8Array, offset: number): bigint {
    let value = 0n;
    for (let i = 0; i < 8; i++) {
        value = (value << 8n) | BigInt(bytes[offset + i]);
    }
    return value;
}

function writeU64Be(bytes: Uint8Array, offset: number, value: bigint) {
    let remaining = value;
    for (let index = 7; index >= 0; index--) {
        bytes[offset + index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

function toHex(bytes: Uint8Array): string {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

interface AccountProofRow {
    readonly balance: bigint;
    readonly nonce: bigint;
    readonly nonceBitmap: bigint;
    readonly location: bigint;
}
