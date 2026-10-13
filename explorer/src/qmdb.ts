import { bytesEqual, fromHex, toArrayBuffer } from './codec.ts';
import { transactionProofTip } from './proofMath.ts';
import { errorMessage } from './proofRetry.ts';
import type { PublishedProofTarget } from './proofTarget.ts';
import {
    SqlClient,
    type DecodedQueryResult,
} from '@exowarexyz/sql';
import { Client, StoreKeyPrefix, TraversalMode, type StoreClient } from '@exowarexyz/sdk';
import {
    SimplexClient,
    SimplexRecordKind,
    finalizedByHeightKey,
    headerByDigestKey,
    rangeForKind,
    type VerifiedSimplexCertificate,
    type SimplexCertificateVerifier,
} from '@exowarexyz/simplex';
import { createWasmSimplexVerifier } from '@exowarexyz/simplex/wasm';
import {
    QmdbOperationLogClient,
    type VerifiedFixedKeylessAppendProof,
    type VerifiedFixedUnorderedUpdateProof,
} from '@exowarexyz/qmdb';
import { columnValue, firstTableRow, tableRows, type SqlRow } from './sqlTable.ts';
import {
    BLOCK_META_DIGEST,
    BLOCK_META_HEIGHT,
    BLOCK_META_TABLE,
    BLOCK_META_TRANSACTIONS_TIP,
    BLOCK_META_TX_COUNT,
    containingTransactionHeight,
    transactionHeightPredecessorQuery,
} from './transactionHeight.ts';

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

export interface TransactionRowMetadata {
    readonly location: bigint;
    readonly sequenceNumber: bigint;
}

// Missing rows may still be indexing, while invalid rows can never verify.
export type TransactionRowMetadataResult =
    | { readonly status: 'indexed'; readonly metadata: TransactionRowMetadata }
    | { readonly status: 'missing'; readonly error: Error }
    | { readonly status: 'invalid'; readonly error: Error };

export interface AccountProofMetadata extends AccountProofRow {
    readonly sequenceNumber: bigint;
}

export async function prefetchFinalizedCertificate({
    storeUrl,
    sqlUrl,
    simplexVerificationMaterial,
    height,
    signal,
}: {
    storeUrl: string;
    sqlUrl: string;
    simplexVerificationMaterial: string;
    height: bigint;
    signal?: AbortSignal;
}): Promise<void> {
    await finalizedTransactionTarget(
        { storeUrl, sqlUrl, simplexVerificationMaterial },
        height,
        0n,
        signal,
    );
}

export function fetchAccountProofMetadata({
    sqlUrl,
    account,
    minSequenceNumber,
    signal,
}: {
    sqlUrl: string;
    account: string;
    minSequenceNumber: bigint;
    signal?: AbortSignal;
}): Promise<AccountProofMetadata> {
    return fetchAccountProofRow(sqlUrl, parseAccountBytes(account), undefined, minSequenceNumber, signal);
}

// Each digest's body is validated on its own, so one bad or lagging row cannot
// withhold metadata from the rest of the page. Failures that cannot be
// attributed to a requested digest still reject the whole batch.
export async function fetchTransactionRowMetadata({
    sqlUrl,
    rows,
    minSequenceNumber,
    signal,
}: {
    sqlUrl: string;
    rows: readonly AccountTransactionRow[];
    minSequenceNumber: bigint;
    signal?: AbortSignal;
}): Promise<ReadonlyMap<string, TransactionRowMetadataResult>> {
    const digests = new Map(rows.map(({ digest }) => {
        const bytes = fromHex(digest);
        assertByteLength(bytes, DIGEST_BYTES, 'transaction digest');
        return [toHex(bytes), bytes];
    }));
    if (digests.size === 0) return new Map();

    const result = await sqlQuery(
        sqlUrl,
        `SELECT ${TX_META_DIGEST}, ${TX_META_QMDB_LOCATION}, ${TX_META_BODY}
         FROM ${TX_META_TABLE}
         WHERE ${TX_META_DIGEST} IN (${[...digests.values()].map(fixedBinaryLiteral).join(', ')})`,
        minSequenceNumber,
        signal,
    );

    const matches = new Map<string, SqlRow[]>();
    for (const row of tableRows(result.table)) {
        const hex = toHex(expectVariableBytes(columnValue(row, TX_META_DIGEST), TX_META_DIGEST));
        if (!digests.has(hex)) throw new Error('SQL transaction metadata contains an unexpected digest');
        matches.set(hex, [...matches.get(hex) ?? [], row]);
    }

    return new Map(await Promise.all([...digests].map(async ([hex, digest]) => [
        hex,
        await transactionRowMetadataResult(matches.get(hex) ?? [], digest, result.sequenceNumber),
    ] as const)));
}

async function transactionRowMetadataResult(
    rows: readonly SqlRow[],
    digest: Uint8Array,
    sequenceNumber: bigint,
): Promise<TransactionRowMetadataResult> {
    const [row, duplicate] = rows;
    if (!row) return { status: 'missing', error: missingTransactionMetadataError(digest) };
    if (duplicate) {
        return { status: 'invalid', error: new Error('SQL transaction metadata contains a duplicate digest') };
    }
    try {
        const location = await verifiedTransactionLocation(row, digest);
        return { status: 'indexed', metadata: { location, sequenceNumber } };
    } catch (error) {
        return { status: 'invalid', error: error instanceof Error ? error : new Error(String(error)) };
    }
}

export async function fetchAndVerifyTransactionProof({
    qmdbUrl,
    storeUrl,
    sqlUrl,
    simplexVerificationMaterial,
    digest,
    publishedTarget,
    finalizedHeight,
    signal,
    onFinalizationVerified,
}: {
    qmdbUrl: string;
    storeUrl: string;
    sqlUrl: string;
    simplexVerificationMaterial: string;
    digest: string;
    publishedTarget: PublishedProofTarget;
    finalizedHeight?: bigint;
    signal?: AbortSignal;
    onFinalizationVerified?: (target: VerifiedFinalizationTarget) => void;
}): Promise<VerifiedTransactionProof> {
    const coveredHeightHint = finalizedHeight !== undefined && finalizedHeight <= publishedTarget.height
        ? finalizedHeight
        : undefined;
    const source = { storeUrl, sqlUrl, simplexVerificationMaterial };

    const controller = new AbortController();
    signal = signal ? AbortSignal.any([signal, controller.signal]) : controller.signal;
    try {
        // A covered hint starts certificate verification early. An ahead-of-target
        // report must not prevent SQL from identifying the owning block.
        const targetHeight = coveredHeightHint ?? publishedTarget.height;
        const [proofTarget, metadata] = await Promise.all([
            targetHeight === publishedTarget.height
                ? fetchLatestProofTarget({
                    storeUrl,
                    sqlUrl,
                    simplexVerificationMaterial,
                    publishedTarget,
                    signal,
                })
                : finalizedTransactionTarget(
                    source,
                    targetHeight,
                    publishedTarget.sequenceNumber,
                    signal,
                ),
            fetchTransactionProofMetadata(
                sqlUrl,
                digest,
                publishedTarget.sequenceNumber,
                signal,
            ),
        ]);
        if (metadata.height > publishedTarget.height) {
            throw uncoveredError(`transaction height ${metadata.height}`);
        }
        if (coveredHeightHint === undefined && metadata.location >= proofTarget.transactionsTip) {
            throw uncoveredError(`transaction location ${metadata.location}`);
        }
        const target = metadata.height === proofTarget.height
            ? proofTarget
            : await finalizedTransactionTarget(
                source,
                metadata.height,
                publishedTarget.sequenceNumber,
                signal,
            );
        if (metadata.location < target.transactionsStart || metadata.location >= target.transactionsTip) {
            throw new Error(`transaction location ${metadata.location} is outside finalized block range`);
        }
        onFinalizationVerified?.(target);

        const tip = transactionProofTip(target.transactionsTip);
        let verification: VerifiedFixedKeylessAppendProof;
        try {
            verification = await fetchFixedKeylessAppendProof(
                `${trimTrailingSlash(qmdbUrl)}/transactions`,
                metadata.location,
                tip,
                target.transactionsRoot,
                fromHex(digest),
                publishedTarget.sequenceNumber,
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
    } finally {
        controller.abort();
    }
}

// The published target is committed atomically with the state and transaction
// QMDB publication boundary. Finalization of the target height, either directly
// or through a certified descendant, authenticates its digest and supplies the
// roots used for subsequent proofs.
export async function fetchLatestProofTarget({
    storeUrl,
    sqlUrl,
    simplexVerificationMaterial,
    publishedTarget,
    signal,
}: {
    storeUrl: string;
    sqlUrl: string;
    simplexVerificationMaterial: string;
    publishedTarget: PublishedProofTarget;
    signal?: AbortSignal;
}): Promise<LatestProofTarget> {
    const target = await finalizedTransactionTarget(
        { storeUrl, sqlUrl, simplexVerificationMaterial },
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
    metadata,
    signal,
}: {
    qmdbUrl: string;
    sqlUrl: string;
    account: string;
    target: LatestProofTarget;
    metadata?: AccountProofMetadata;
    signal?: AbortSignal;
}): Promise<VerifiedAccountProof> {
    const accountBytes = parseAccountBytes(account);
    const stateEnd = target.stateTip;

    // Floor raises can move an idle account past this certificate's tip.
    // Reuse speculative SQL only while its location and read floor still fit.
    const row = metadata &&
        metadata.sequenceNumber >= target.sequenceNumber &&
        metadata.location >= target.stateStart && metadata.location < stateEnd
        ? metadata
        : await fetchAccountProofRow(
            sqlUrl,
            accountBytes,
            stateEnd,
            target.sequenceNumber,
            signal,
        );
    if (row.location < target.stateStart || row.location >= stateEnd) {
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
    metadata,
    signal,
}: {
    qmdbUrl: string;
    sqlUrl: string;
    row: AccountTransactionRow;
    target: LatestProofTarget;
    metadata?: TransactionRowMetadata;
    signal?: AbortSignal;
}): Promise<VerifiedTransactionProof> {
    const digestBytes = fromHex(row.digest);
    assertByteLength(digestBytes, DIGEST_BYTES, 'transaction digest');
    const location = metadata && metadata.sequenceNumber >= target.sequenceNumber
        ? metadata.location
        : await fetchVerifiedSqlTransactionMetadata(
            sqlUrl,
            digestBytes,
            target.sequenceNumber,
            signal,
        );

    if (location >= target.transactionsTip) {
        throw uncoveredError(`transaction location ${location}`);
    }

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
    const row = firstTableRow(result.table);
    if (!row) {
        throw missingTransactionMetadataError(digest);
    }

    return verifiedTransactionLocation(row, digest);
}

function missingTransactionMetadataError(digest: Uint8Array): Error {
    return new Error(`tx digest ${shortHex(toHex(digest))} missing from raw transaction index`);
}

async function verifiedTransactionLocation(row: SqlRow, digest: Uint8Array): Promise<bigint> {
    const location = expectBigint(columnValue(row, TX_META_QMDB_LOCATION), TX_META_QMDB_LOCATION);
    const signedTransaction = expectVariableBytes(columnValue(row, TX_META_BODY), TX_META_BODY);
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
        if (errorMessage(error).includes('missing from raw transaction index')) {
            throw new Error(`tx digest ${shortHex(digest)} is not finalized yet`);
        }
        throw error;
    }

    // A bounded seek on the covered tip index finds the last block boundary
    // at or before the location. Ranges are contiguous, so the next height owns it.
    const predecessors = await sqlQuery(
        sqlUrl,
        transactionHeightPredecessorQuery(location),
        minSequenceNumber,
        signal,
    );
    const predecessor = firstTableRow(predecessors.table);
    const height = containingTransactionHeight(
        predecessor ? expectBigint(columnValue(predecessor, BLOCK_META_HEIGHT), BLOCK_META_HEIGHT) : null,
    );
    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT ${BLOCK_META_TRANSACTIONS_TIP}, ${BLOCK_META_TX_COUNT}
            FROM ${BLOCK_META_TABLE}
            WHERE ${BLOCK_META_HEIGHT} = ${height.toString()}
            LIMIT 1
        `,
        minSequenceNumber,
        signal,
    );
    const row = firstTableRow(result.table);
    if (!row) {
        throw new Error(`tx digest ${shortHex(digest)} is not finalized yet`);
    }

    // The tip is the trailing commit location. A later certified range can
    // retain this transaction without identifying its original block.
    const tip = expectBigint(columnValue(row, BLOCK_META_TRANSACTIONS_TIP), BLOCK_META_TRANSACTIONS_TIP);
    const count = expectBigint(columnValue(row, BLOCK_META_TX_COUNT), BLOCK_META_TX_COUNT);
    if (location < tip - count || location >= tip) {
        throw new Error(`tx digest ${shortHex(digest)} is not finalized yet in the selected block range`);
    }
    return { height, location };
}

function uncoveredError(subject: string): Error {
    return new Error(`${subject} is not yet covered by a provable finalization`);
}

function transactionProofErrorDetail(
    error: unknown,
    target: FinalizedTransactionTarget,
    metadata: TransactionProofMetadata,
): string {
    return [
        errorMessage(error),
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
    return client.getFixedKeylessAppend(
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
    return client.getFixedUnorderedUpdate(
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
}

const FINALIZED_TARGET_CACHE_SIZE = 128;
const FINALIZED_ANCESTOR_BATCH = 128n;
const MAX_U64 = (1n << 64n) - 1n;
const U64_BYTES = 8;
const finalizedTargets = new Map<string, AuthenticatedTarget>();
const pendingFinalizedTargets = new Map<string, PendingFinalizedTarget>();

interface FinalizationSource {
    readonly storeUrl: string;
    readonly sqlUrl: string;
    readonly simplexVerificationMaterial: string;
}

// The parent digest lets a cached descendant anchor later ancestor checks.
interface AuthenticatedTarget extends FinalizedTransactionTarget {
    readonly parentDigest: Uint8Array;
}

interface PendingFinalizedTarget {
    readonly controller: AbortController;
    readonly promise: Promise<AuthenticatedTarget>;
    readonly minSequenceNumber: bigint;
    readonly settled: () => boolean;
    callers: number;
}

async function finalizedTransactionTarget(
    source: FinalizationSource,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    signal?.throwIfAborted();
    if (height < 0n) throw new Error('finalized height must be non-negative');

    const cacheKey = finalizedTargetKey(source, height);
    const cached = cachedFinalizedTarget(cacheKey);
    if (cached) return publicFinalizedTarget(cached);

    // A verified target does not depend on SQL hints, but a failed attempt can.
    // Callers join an attempt only when it uses their SQL service and covers
    // their read floor, so a stale miss is never shared with a newer caller.
    const key = `${cacheKey} ${trimTrailingSlash(source.sqlUrl)}`;
    let pending = pendingFinalizedTargets.get(key);
    if (!pending || pending.minSequenceNumber < minSequenceNumber) {
        const controller = new AbortController();
        let settled = false;
        const promise = fetchFinalizedTransactionTarget(
            source,
            height,
            minSequenceNumber,
            controller.signal,
        ).then((target) => {
            // A verified target is immutable across publication barriers.
            // SQL and QMDB reads still use each caller's covering sequence floor.
            controller.signal.throwIfAborted();
            cacheFinalizedTarget(cacheKey, target);
            return target;
        }).finally(() => {
            settled = true;
            if (pendingFinalizedTargets.get(key)?.controller === controller) {
                pendingFinalizedTargets.delete(key);
            }
        });
        pending = { controller, promise, minSequenceNumber, settled: () => settled, callers: 0 };
        pendingFinalizedTargets.set(key, pending);
    }
    const shared = pending;
    shared.callers++;

    // Each waiter owns only its subscription. Stop the shared request when
    // its last caller leaves so a cancelled page does not retain network work.
    // A request replaced by a higher floor still stops with its own callers.
    const target = await new Promise<AuthenticatedTarget>((resolve, reject) => {
        let settled = false;
        const finish = (error: unknown, value?: AuthenticatedTarget) => {
            if (settled) return;
            settled = true;
            signal?.removeEventListener('abort', abort);
            shared.callers--;
            if (shared.callers === 0 && !shared.settled()) {
                if (pendingFinalizedTargets.get(key) === shared) {
                    pendingFinalizedTargets.delete(key);
                }
                shared.controller.abort();
            }
            if (value) resolve(value);
            else reject(error);
        };
        const abort = () => finish(signal!.reason);
        signal?.addEventListener('abort', abort, { once: true });
        shared.promise.then((value) => finish(undefined, value), (error) => finish(error));
    });
    return publicFinalizedTarget(copyFinalizedTarget(target));
}

// The parent digest only anchors ancestor checks, so callers get the public shape.
function publicFinalizedTarget(target: AuthenticatedTarget): FinalizedTransactionTarget {
    const { parentDigest: _parentDigest, ...finalized } = target;
    return finalized;
}

// URLs cannot contain spaces, so the material suffix is unambiguous.
function finalizedTargetKey(source: FinalizationSource, height: bigint): string {
    return `${height} ${trimTrailingSlash(source.storeUrl)} ${source.simplexVerificationMaterial}`;
}

function cachedFinalizedTarget(key: string): AuthenticatedTarget | undefined {
    const cached = finalizedTargets.get(key);
    if (!cached) return undefined;
    finalizedTargets.delete(key);
    finalizedTargets.set(key, cached);
    return copyFinalizedTarget(cached);
}

function cacheFinalizedTarget(key: string, target: AuthenticatedTarget) {
    finalizedTargets.set(key, target);
    if (finalizedTargets.size > FINALIZED_TARGET_CACHE_SIZE) {
        finalizedTargets.delete(finalizedTargets.keys().next().value!);
    }
}

function copyFinalizedTarget(target: AuthenticatedTarget): AuthenticatedTarget {
    return {
        ...target,
        blockDigest: target.blockDigest.slice(),
        parentDigest: target.parentDigest.slice(),
        stateRoot: target.stateRoot.slice(),
        transactionsRoot: target.transactionsRoot.slice(),
    };
}

async function fetchFinalizedTransactionTarget(
    source: FinalizationSource,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AuthenticatedTarget> {
    const simplex = await verifiedSimplexClient(source.storeUrl, source.simplexVerificationMaterial);
    signal?.throwIfAborted();
    const target = await certifiedTarget(simplex, height, minSequenceNumber, signal);
    if (target) return target;

    // Capture can permanently omit a height's certificate, and a missing row
    // alone cannot distinguish that from upload lag. A later finalization also
    // finalizes its ancestors, so try to authenticate this header through one.
    return descendantFinalizedTarget(source, simplex, height, minSequenceNumber, signal);
}

async function certifiedTarget(
    simplex: SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AuthenticatedTarget | null> {
    const certificate = await simplex.getFinalizationByHeight(
        height.toString(),
        minSequenceNumber,
        { signal },
    );
    if (!certificate) return null;
    const target = await finalizedTargetFromCertificate(certificate);
    if (target.height !== height) {
        throw new Error(`finalized certificate height ${target.height} does not match requested height ${height}`);
    }
    return target;
}

async function descendantFinalizedTarget(
    source: FinalizationSource,
    simplex: SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AuthenticatedTarget> {
    if (height >= MAX_U64) throw missingFinalization(height);

    // Height keys are big endian, so a forward range finds the nearest
    // certificate above the requested height. The row only locates a candidate.
    const store = simplexStore(source.storeUrl);
    const nearest = await store.query(
        finalizedByHeightKey(height + 1n),
        rangeForKind(SimplexRecordKind.FinalizedByHeight).end,
        1,
        1,
        TraversalMode.FORWARD,
        minSequenceNumber,
        { signal },
    );
    assertEvaluatedSequence(nearest.sequenceNumber, minSequenceNumber, 'Simplex descendant query');
    const row = nearest.results[0];
    if (!row) throw missingFinalization(height);
    const descendantHeight = finalizedHeightFromKey(row.key);
    if (descendantHeight <= height) {
        throw new Error(`Simplex descendant query returned height ${descendantHeight} at or below ${height}`);
    }

    // The exact read verifies the certificate. Flooring it and the header reads
    // at the range's evaluated sequence keeps them at least as fresh as the row.
    const descendant = await descendantTarget(
        source,
        simplex,
        descendantHeight,
        nearest.sequenceNumber,
        signal,
    );
    if (!descendant) throw missingFinalization(height);
    return ancestorTarget(
        source.sqlUrl,
        store,
        descendant,
        height,
        minSequenceNumber,
        nearest.sequenceNumber,
        signal,
    );
}

async function descendantTarget(
    source: FinalizationSource,
    simplex: SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>,
    height: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AuthenticatedTarget | null> {
    const key = finalizedTargetKey(source, height);
    const cached = cachedFinalizedTarget(key);
    if (cached) return cached;

    const target = await certifiedTarget(simplex, height, minSequenceNumber, signal);
    if (target) {
        signal?.throwIfAborted();
        cacheFinalizedTarget(key, target);
    }
    return target;
}

// Walk back from the certified descendant one bounded batch at a time. SQL
// supplies candidate digests so each batch needs one Store read rather than
// one read per parent. Only recomputed header hashes and contiguous heights
// establish the chain, so a wrong hint fails the lookup closed and never extends it.
// Intermediate heights are not cached. The certified descendant is, and transient
// heights would evict live targets from the small cache.
async function ancestorTarget(
    sqlUrl: string,
    store: StoreClient,
    descendant: AuthenticatedTarget,
    height: bigint,
    sqlFloor: bigint,
    headerFloor: bigint,
    signal?: AbortSignal,
): Promise<AuthenticatedTarget> {
    let expected = descendant.parentDigest;
    let top = descendant.height - 1n;
    while (true) {
        const bottom = top - height >= FINALIZED_ANCESTOR_BATCH
            ? top - FINALIZED_ANCESTOR_BATCH + 1n
            : height;
        const hints = bottom < top
            ? await blockDigestHints(sqlUrl, bottom, top, height, sqlFloor, signal)
            : [];
        const digests = [...hints, expected];
        const headers = await headersByDigest(store, digests, headerFloor, signal);

        for (let index = digests.length - 1; index >= 0; index--) {
            const blockHeight = bottom + BigInt(index);
            if (!bytesEqual(digests[index]!, expected)) {
                throw new Error(`SQL block digest at height ${blockHeight} does not match its certified child`);
            }
            const bytes = headers[index];
            if (!bytes) throw missingFinalization(height);
            const header = await authenticatedHeader(bytes, expected, blockHeight);
            if (blockHeight === height) {
                // An ancestor has no certificate of its own, so report the view it
                // was proposed in rather than the descendant certificate's view.
                // Without epoch changes there are no re-proposals, so this matches
                // the view a direct finalization would carry.
                return {
                    height,
                    view: header.view,
                    blockDigest: expected,
                    parentDigest: header.parentDigest,
                    stateRoot: header.stateRoot,
                    stateStart: header.stateStart,
                    stateTip: header.stateTip,
                    transactionsRoot: header.transactionsRoot,
                    transactionsStart: header.transactionsStart,
                    transactionsTip: header.transactionsTip,
                };
            }
            expected = header.parentDigest;
        }
        top = bottom - 1n;
    }
}

async function blockDigestHints(
    sqlUrl: string,
    bottom: bigint,
    top: bigint,
    requestedHeight: bigint,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<Uint8Array[]> {
    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT ${BLOCK_META_HEIGHT}, ${BLOCK_META_DIGEST}
            FROM ${BLOCK_META_TABLE}
            WHERE ${BLOCK_META_HEIGHT} >= ${bottom.toString()} AND ${BLOCK_META_HEIGHT} < ${top.toString()}
            ORDER BY ${BLOCK_META_HEIGHT}
            LIMIT ${(top - bottom).toString()}
        `,
        minSequenceNumber,
        signal,
    );
    const digests = new Map<bigint, Uint8Array>();
    for (const row of tableRows(result.table)) {
        const blockHeight = expectBigint(columnValue(row, BLOCK_META_HEIGHT), BLOCK_META_HEIGHT);
        const digest = expectBytes(columnValue(row, BLOCK_META_DIGEST), BLOCK_META_DIGEST, DIGEST_BYTES);
        if (blockHeight < bottom || blockHeight >= top || digests.has(blockHeight)) {
            throw new Error(`SQL block digest hints contain unexpected height ${blockHeight}`);
        }
        digests.set(blockHeight, digest);
    }

    // A missing row may only be indexing lag, so it remains retryable.
    const hints: Uint8Array[] = [];
    for (let blockHeight = bottom; blockHeight < top; blockHeight++) {
        const digest = digests.get(blockHeight);
        if (!digest) throw missingFinalization(requestedHeight);
        hints.push(digest);
    }
    return hints;
}

// Header values are unauthenticated. Results are matched by key, so a missing
// or extra row cannot shift a value onto another digest.
async function headersByDigest(
    store: StoreClient,
    digests: readonly Uint8Array[],
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<Array<Uint8Array | undefined>> {
    const keys = digests.map((digest) => headerByDigestKey(digest));

    // The SDK cannot cancel getMany, so an abandoned walk stops after this batch.
    const entries = await store.getMany(keys, keys.length, undefined, minSequenceNumber);
    signal?.throwIfAborted();
    const values = new Map<string, Uint8Array>();
    for (const { key, value } of entries) {
        if (value !== undefined) values.set(toHex(key), value);
    }
    return keys.map((key) => values.get(toHex(key)));
}

async function authenticatedHeader(
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

function finalizedHeightFromKey(key: Uint8Array): bigint {
    if (key.length !== 1 + U64_BYTES || key[0] !== SimplexRecordKind.FinalizedByHeight) {
        throw new Error('Simplex descendant query returned a malformed height key');
    }
    return readU64Be(key, 1);
}

function missingFinalization(height: bigint): Error {
    return new Error(`finalization missing at height ${height}`);
}

async function verifiedSimplexClient(
    storeUrl: string,
    simplexVerificationMaterial: string,
): Promise<SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>> {
    if (simplexVerificationMaterial.trim().length === 0) {
        throw new Error('Simplex verification material is not configured');
    }
    return new SimplexClient<VerifiedSimplexCertificate, VerifiedSimplexCertificate>(simplexStore(storeUrl), {
        verifier: await simplexFinalizationVerifier(simplexVerificationMaterial),
    });
}

function simplexStore(storeUrl: string): StoreClient {
    return new Client(trimTrailingSlash(storeUrl)).store(
        new StoreKeyPrefix(SIMPLEX_STORE_PREFIX),
    );
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

interface DecodedBlockHeader {
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
): Promise<SqlRow[]> {
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
    return tableRows(result.table);
}

function decodeAccountActivityRow(row: SqlRow): AccountTransactionRow {
    const role = expectBigint(columnValue(row, TX_ACTIVITY_ROLE), TX_ACTIVITY_ROLE);
    const digest = expectBytes(columnValue(row, TX_ACTIVITY_DIGEST), TX_ACTIVITY_DIGEST, DIGEST_BYTES);
    const counterparty = expectBytes(
        columnValue(row, TX_ACTIVITY_COUNTERPARTY),
        TX_ACTIVITY_COUNTERPARTY,
        ACCOUNT_KEY_BYTES,
    );
    return {
        digest: toHex(digest),
        direction: role === TX_ACTIVITY_ROLE_RECEIVER ? 'received' : 'sent',
        counterparty: toHex(counterparty),
        value: expectBigint(columnValue(row, TX_ACTIVITY_VALUE), TX_ACTIVITY_VALUE),
        nonce: expectBigint(columnValue(row, TX_ACTIVITY_NONCE), TX_ACTIVITY_NONCE),
        height: expectBigint(columnValue(row, TX_ACTIVITY_HEIGHT), TX_ACTIVITY_HEIGHT),
        blockIndex: expectSafeNumber(columnValue(row, TX_ACTIVITY_INDEX), TX_ACTIVITY_INDEX),
    };
}

async function fetchAccountProofRow(
    sqlUrl: string,
    account: Uint8Array,
    beforeLocation: bigint | undefined,
    minSequenceNumber: bigint,
    signal?: AbortSignal,
): Promise<AccountProofMetadata> {
    const predicates = [`${ACCOUNT_META_ACCOUNT} = ${fixedBinaryLiteral(account)}`];
    if (beforeLocation !== undefined) {
        predicates.push(`${ACCOUNT_META_QMDB_LOCATION} < ${beforeLocation.toString()}`);
    }

    const result = await sqlQuery(
        sqlUrl,
        `
            SELECT
                ${ACCOUNT_META_BALANCE},
                ${ACCOUNT_META_NONCE_BASE},
                ${ACCOUNT_META_NONCE_BITMAP},
                ${ACCOUNT_META_QMDB_LOCATION}
            FROM ${ACCOUNT_META_TABLE}
            WHERE ${predicates.join(' AND ')}
            ORDER BY ${ACCOUNT_META_QMDB_LOCATION} DESC
            LIMIT 1
        `,
        minSequenceNumber,
        signal,
    );
    const row = firstTableRow(result.table);
    if (!row) {
        throw new Error(`account ${shortHex(toHex(account))} is not indexed`);
    }
    return {
        sequenceNumber: result.sequenceNumber,
        balance: expectBigint(columnValue(row, ACCOUNT_META_BALANCE), ACCOUNT_META_BALANCE),
        nonce: expectBigint(columnValue(row, ACCOUNT_META_NONCE_BASE), ACCOUNT_META_NONCE_BASE),
        nonceBitmap: expectBigint(
            columnValue(row, ACCOUNT_META_NONCE_BITMAP),
            ACCOUNT_META_NONCE_BITMAP,
        ),
        location: expectBigint(columnValue(row, ACCOUNT_META_QMDB_LOCATION), ACCOUNT_META_QMDB_LOCATION),
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
        minSequenceNumber,
        { signal },
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

function encodeActivityCursor(row: SqlRow): Uint8Array {
    const cursor = new Uint8Array(ACCOUNT_CURSOR_BYTES);
    writeU64Be(cursor, 0, expectBigint(columnValue(row, TX_ACTIVITY_HEIGHT), TX_ACTIVITY_HEIGHT));
    writeU64Be(cursor, 8, expectBigint(columnValue(row, TX_ACTIVITY_INDEX), TX_ACTIVITY_INDEX));
    writeU64Be(cursor, 16, expectBigint(columnValue(row, TX_ACTIVITY_ROLE), TX_ACTIVITY_ROLE));
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

function expectBigint(value: unknown, column: string): bigint {
    if (typeof value !== 'bigint') {
        throw new Error(`SQL column ${column} must be UInt64`);
    }
    return value;
}

function expectSafeNumber(value: unknown, column: string): number {
    const bigint = expectBigint(value, column);
    if (bigint > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`SQL column ${column} exceeds Number.MAX_SAFE_INTEGER`);
    }
    return Number(bigint);
}

function expectBytes(value: unknown, column: string, length: number): Uint8Array {
    if (!(value instanceof Uint8Array)) {
        throw new Error(`SQL column ${column} must be FixedSizeBinary(${length})`);
    }
    assertByteLength(value, length, column);
    return value;
}

function expectVariableBytes(value: unknown, column: string): Uint8Array {
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
