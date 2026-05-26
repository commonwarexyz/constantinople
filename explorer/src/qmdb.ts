import { create } from '@bufbuild/protobuf';
import { createClient } from '@connectrpc/connect';
import {
    createTransport,
    Client,
    StoreKeyPrefix,
    TraversalMode,
} from '@exowarexyz/sdk';
import { fromHex } from './codec';
import { assertTransactionLocationBeforeTip, transactionProofTip } from './proofMath';
import { SimplexClient } from '@exowarexyz/simplex';
import { verifyAccountProof, verifyFinalization, verifyTransactionProof } from './crypto-wasm/constantinople_explorer_crypto';
import { loadCrypto } from './wallet';
import {
    GetOperationRangeRequestSchema,
    OperationLogService,
} from '../vendor/exoware-qmdb/src/generated/proto/qmdb/v1/operation_log_pb';

const TX_BY_HEIGHT_RESERVED_BITS = 4;
const TX_BY_HEIGHT_PREFIX = 0x6;
const TX_BY_SENDER_PREFIX = 0x7;
const ACCOUNT_PREFIX = 0xa;
const MAX_TX_BY_HEIGHT_ROWS = 100_000;
const ACCOUNT_PAGE_SIZE = 10;
const ACCOUNT_KEY_BYTES = 32;
const DIGEST_BYTES = 32;
const TX_BY_SENDER_KEY_BYTES = ACCOUNT_KEY_BYTES + 8 + 4;
const TX_BY_SENDER_ROW_BYTES = DIGEST_BYTES + ACCOUNT_KEY_BYTES + 8 + 8 + 8 + 8 + 4;
const ACCOUNT_ROW_BYTES = 16 + 8;

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
    readonly location: bigint;
    readonly height: bigint;
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

export interface LatestProofTarget extends FinalizedTransactionTarget {}

export interface AccountTransactionRow {
    readonly key: Uint8Array;
    readonly digest: string;
    readonly to: string;
    readonly value: bigint;
    readonly nonce: bigint;
    readonly qmdLocation: bigint;
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
    readonly location: bigint;
    readonly tip: bigint;
    readonly proofSizeBytes: number;
}

export async function fetchAndVerifyTransactionProof({
    qmdbUrl,
    storeUrl,
    simplexVerificationMaterial,
    digest,
    height,
    signal,
    onFinalizationVerified,
}: {
    qmdbUrl: string;
    storeUrl: string;
    simplexVerificationMaterial: string;
    digest: string;
    height: number;
    signal?: AbortSignal;
    onFinalizationVerified?: (target: VerifiedFinalizationTarget) => void;
}): Promise<VerifiedTransactionProof> {
    await loadCrypto();
    const target = await finalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        BigInt(height),
        signal,
    );
    onFinalizationVerified?.(target);
    const metadata = await fetchTransactionProofMetadata(storeUrl, digest, target);
    if (target.height !== metadata.height) {
        throw new Error(`finalized certificate height ${target.height} does not match tx height ${metadata.height}`);
    }
    if (metadata.location < target.transactionsStart || metadata.location >= target.transactionsTip) {
        throw new Error(`transaction location ${metadata.location} is outside finalized block range`);
    }

    const tip = transactionProofTip(target.transactionsTip);
    const proof = await fetchOperationProof(`${trimTrailingSlash(qmdbUrl)}/transactions`, metadata.location, tip, signal);
    const verification = verifyTransactionProof(
        target.transactionsRoot,
        proof.proof,
        proof.opsRoot,
        proof.opsRootWitness,
        proof.startLocation,
        proof.encodedOperations,
        metadata.location,
        fromHex(digest),
    ) as WasmTransactionProof;

    return {
        location: metadata.location,
        tip,
        height: target.height,
        view: target.view,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

export async function fetchLatestProofTarget({
    storeUrl,
    simplexVerificationMaterial,
    signal,
}: {
    storeUrl: string;
    simplexVerificationMaterial: string;
    signal?: AbortSignal;
}): Promise<LatestProofTarget> {
    await loadCrypto();
    return latestProofTarget(storeUrl, simplexVerificationMaterial, signal);
}

export async function fetchAccountTransactionsPage({
    storeUrl,
    account,
    cursor,
}: {
    storeUrl: string;
    account: string;
    cursor?: Uint8Array | null;
}): Promise<AccountTransactionPage> {
    const accountBytes = parseAccountBytes(account);
    const store = new Client(trimTrailingSlash(storeUrl)).store(
        new StoreKeyPrefix(TX_BY_HEIGHT_RESERVED_BITS, TX_BY_SENDER_PREFIX),
    );
    const start = cursor ?? txBySenderStart(accountBytes);
    const rows = await store.query(
        start,
        txBySenderEnd(accountBytes),
        ACCOUNT_PAGE_SIZE + 1,
        4096,
        TraversalMode.FORWARD,
        undefined,
    );
    const visible = rows.results.slice(0, ACCOUNT_PAGE_SIZE);
    const last = visible[visible.length - 1];
    return {
        rows: visible.map((row) => decodeTxBySenderRow(row.key, row.value)),
        nextCursor: rows.results.length > ACCOUNT_PAGE_SIZE && last ? nextLexicographicKey(last.key) : null,
    };
}

export async function fetchAndVerifyAccountProof({
    qmdbUrl,
    storeUrl,
    account,
    target,
    signal,
}: {
    qmdbUrl: string;
    storeUrl: string;
    account: string;
    target: LatestProofTarget;
    signal?: AbortSignal;
}): Promise<VerifiedAccountProof> {
    await loadCrypto();
    const accountBytes = parseAccountBytes(account);
    const row = await fetchAccountProofRow(storeUrl, accountBytes);
    const stateEnd = target.stateTip;
    if (row.location < target.stateStart || row.location >= stateEnd) {
        throw new Error(`account location ${row.location} is outside finalized state range`);
    }

    const tip = transactionProofTip(stateEnd);
    const proof = await fetchOperationProof(`${trimTrailingSlash(qmdbUrl)}/state`, row.location, tip, signal);
    const verification = verifyAccountProof(
        target.stateRoot,
        proof.proof,
        proof.opsRoot,
        proof.opsRootWitness,
        proof.startLocation,
        proof.encodedOperations,
        row.location,
        accountBytes,
    ) as WasmAccountProof;

    if (verification.balance !== row.balance || verification.nonce !== row.nonce) {
        throw new Error('account proof value does not match account index row');
    }

    return {
        balance: verification.balance,
        nonce: verification.nonce,
        location: row.location,
        tip,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

export async function fetchAndVerifyTransactionRowProof({
    qmdbUrl,
    row,
    target,
    signal,
}: {
    qmdbUrl: string;
    row: AccountTransactionRow;
    target: LatestProofTarget;
    signal?: AbortSignal;
}): Promise<VerifiedTransactionProof> {
    await loadCrypto();
    assertTransactionLocationBeforeTip(row.qmdLocation, target.transactionsTip);

    const tip = transactionProofTip(target.transactionsTip);
    const proof = await fetchOperationProof(`${trimTrailingSlash(qmdbUrl)}/transactions`, row.qmdLocation, tip, signal);
    const verification = verifyTransactionProof(
        target.transactionsRoot,
        proof.proof,
        proof.opsRoot,
        proof.opsRootWitness,
        proof.startLocation,
        proof.encodedOperations,
        row.qmdLocation,
        fromHex(row.digest),
    ) as WasmTransactionProof;

    return {
        location: row.qmdLocation,
        tip,
        height: target.height,
        view: target.view,
        proofSizeBytes: verification.proofSizeBytes,
    };
}

async function fetchTransactionProofMetadata(
    storeUrl: string,
    digest: string,
    target: FinalizedTransactionTarget,
): Promise<TransactionProofMetadata> {
    const digestBytes = fromHex(digest);
    const store = new Client(trimTrailingSlash(storeUrl)).store(
        new StoreKeyPrefix(TX_BY_HEIGHT_RESERVED_BITS, TX_BY_HEIGHT_PREFIX),
    );
    const rows = await store.query(
        txByHeightKeyPrefix(target.height, 0),
        txByHeightKeyPrefix(target.height, 0xff_ff_ff_ff),
        MAX_TX_BY_HEIGHT_ROWS,
        4096,
        TraversalMode.FORWARD,
        undefined,
    );
    const match = rows.results.find((row) => bytesEqual(row.value, digestBytes));
    if (!match) {
        throw new Error(`tx digest ${shortHex(digest)} missing at height ${target.height}`);
    }

    const txCount = BigInt(rows.results.length);
    const appendStart = target.transactionsTip - (txCount + 1n);
    const location = appendStart + BigInt(txIndexFromKey(match.key));

    return {
        location,
        height: target.height,
    };
}

async function fetchOperationProof(
    serviceUrl: string,
    location: bigint,
    tip: bigint,
    signal?: AbortSignal,
) {
    const rpc = createClient(OperationLogService, createTransport(serviceUrl));
    const response = await rpc.getOperationRange(
        create(GetOperationRangeRequestSchema, {
            tip,
            startLocation: location,
            maxLocations: 1,
        }),
        { signal },
    );
    if (!response.proof) {
        throw new Error('QMDB transaction proof response missing proof');
    }
    return response.proof;
}

const finalizedTargetCache = new Map<string, Promise<FinalizedTransactionTarget>>();

function finalizedTransactionTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    height: bigint,
    signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    const key = `${trimTrailingSlash(storeUrl)}:${simplexVerificationMaterial}:${height}`;
    const cached = finalizedTargetCache.get(key);
    if (cached) {
        return cached;
    }

    const target = fetchFinalizedTransactionTarget(
        storeUrl,
        simplexVerificationMaterial,
        height,
        signal,
    ).catch((error: unknown) => {
        finalizedTargetCache.delete(key);
        throw error;
    });
    finalizedTargetCache.set(key, target);
    return target;
}

function latestProofTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    signal?: AbortSignal,
): Promise<LatestProofTarget> {
    return fetchLatestFinalizedTarget(storeUrl, simplexVerificationMaterial, signal);
}

async function fetchFinalizedTransactionTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    height: bigint,
    _signal?: AbortSignal,
): Promise<FinalizedTransactionTarget> {
    if (simplexVerificationMaterial.trim().length === 0) {
        throw new Error('Simplex verification material is not configured');
    }
    const simplex = new SimplexClient(trimTrailingSlash(storeUrl));
    const finalized = await simplex.getFinalizationByHeightRaw(height.toString());
    if (!finalized) {
        throw new Error(`finalization missing at height ${height}`);
    }
    return verifyFinalization(fromHex(simplexVerificationMaterial), finalized) as FinalizedTransactionTarget;
}

async function fetchLatestFinalizedTarget(
    storeUrl: string,
    simplexVerificationMaterial: string,
    _signal?: AbortSignal,
): Promise<LatestProofTarget> {
    if (simplexVerificationMaterial.trim().length === 0) {
        throw new Error('Simplex verification material is not configured');
    }
    const simplex = new SimplexClient(trimTrailingSlash(storeUrl));
    const finalized = await simplex.latestFinalizationRaw();
    if (!finalized) {
        throw new Error('latest finalization missing');
    }
    return verifyFinalization(fromHex(simplexVerificationMaterial), finalized) as LatestProofTarget;
}

async function fetchAccountProofRow(storeUrl: string, account: Uint8Array): Promise<AccountProofRow> {
    const store = new Client(trimTrailingSlash(storeUrl)).store(
        new StoreKeyPrefix(TX_BY_HEIGHT_RESERVED_BITS, ACCOUNT_PREFIX),
    );
    const rows = await store.query(account, account, 1, 4096, TraversalMode.FORWARD, undefined);
    const row = rows.results.find((entry) => bytesEqual(entry.key, account));
    if (!row) {
        throw new Error(`account ${shortHex(toHex(account))} is not indexed`);
    }
    return decodeAccountRow(row.value);
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function txByHeightKeyPrefix(height: bigint, index: number): Uint8Array {
    const key = new Uint8Array(12);
    writeU64Be(key, 0, height);
    writeU32Be(key, 8, index);
    return key;
}

function txBySenderStart(account: Uint8Array): Uint8Array {
    const key = new Uint8Array(TX_BY_SENDER_KEY_BYTES);
    key.set(account, 0);
    return key;
}

function txBySenderEnd(account: Uint8Array): Uint8Array {
    const key = new Uint8Array(TX_BY_SENDER_KEY_BYTES);
    key.set(account, 0);
    key.fill(0xff, ACCOUNT_KEY_BYTES);
    return key;
}

function decodeTxBySenderRow(key: Uint8Array, value: Uint8Array): AccountTransactionRow {
    if (key.length !== TX_BY_SENDER_KEY_BYTES) {
        throw new Error('malformed TX_BY_SENDER key');
    }
    if (value.length !== TX_BY_SENDER_ROW_BYTES) {
        throw new Error('malformed TX_BY_SENDER row');
    }
    return {
        key,
        digest: toHex(value.slice(0, 32)),
        to: toHex(value.slice(32, 64)),
        value: readU64Be(value, 64),
        nonce: readU64Be(value, 72),
        qmdLocation: readU64Be(value, 80),
        height: readU64Be(value, 88),
        blockIndex: readU32Be(value, 96),
    };
}

function decodeAccountRow(value: Uint8Array): AccountProofRow {
    if (value.length !== ACCOUNT_ROW_BYTES) {
        throw new Error('malformed account proof row');
    }
    return {
        balance: readU64Be(value, 0),
        nonce: readU64Be(value, 8),
        location: readU64Be(value, 16),
    };
}

function parseAccountBytes(account: string): Uint8Array {
    const normalized = account.trim().replace(/^0x/i, '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error('expected a 32-byte hex account public key');
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

function readU32Be(bytes: Uint8Array, offset: number): number {
    return (
        bytes[offset] * 0x1_00_00_00 +
        bytes[offset + 1] * 0x1_00_00 +
        bytes[offset + 2] * 0x1_00 +
        bytes[offset + 3]
    );
}

function nextLexicographicKey(key: Uint8Array): Uint8Array | null {
    const next = new Uint8Array(key);
    for (let i = next.length - 1; i >= 0; i--) {
        if (next[i] === 0xff) continue;
        next[i] += 1;
        next.fill(0, i + 1);
        return next;
    }
    return null;
}

function txIndexFromKey(key: Uint8Array): number {
    if (key.length < 12) {
        throw new Error('malformed TX_BY_H key');
    }
    return (
        key[8] * 0x1_00_00_00 +
        key[9] * 0x1_00_00 +
        key[10] * 0x1_00 +
        key[11]
    );
}

function writeU64Be(bytes: Uint8Array, offset: number, value: bigint) {
    let remaining = value;
    for (let index = 7; index >= 0; index--) {
        bytes[offset + index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
}

function writeU32Be(bytes: Uint8Array, offset: number, value: number) {
    bytes[offset] = (value >>> 24) & 0xff;
    bytes[offset + 1] = (value >>> 16) & 0xff;
    bytes[offset + 2] = (value >>> 8) & 0xff;
    bytes[offset + 3] = value & 0xff;
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

interface WasmTransactionProof {
    readonly proofSizeBytes: number;
}

interface WasmAccountProof {
    readonly balance: bigint;
    readonly nonce: bigint;
    readonly proofSizeBytes: number;
}

interface AccountProofRow {
    readonly balance: bigint;
    readonly nonce: bigint;
    readonly location: bigint;
}
