import { create } from '@bufbuild/protobuf';
import { createClient } from '@connectrpc/connect';
import {
    createTransport,
    Client,
    StoreKeyPrefix,
    TraversalMode,
} from '@exowarexyz/sdk';
import { fromHex } from './codec';
import { transactionProofTip } from './proofMath';
import { SimplexClient } from '@exowarexyz/simplex';
import { verifyFinalization, verifyTransactionProof } from './crypto-wasm/constantinople_explorer_crypto';
import { loadCrypto } from './wallet';
import {
    GetOperationRangeRequestSchema,
    OperationLogService,
} from '../vendor/exoware-qmdb/src/generated/proto/qmdb/v1/operation_log_pb';

const TX_BY_HEIGHT_RESERVED_BITS = 4;
const TX_BY_HEIGHT_PREFIX = 0x6;
const MAX_TX_BY_HEIGHT_ROWS = 100_000;

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
    readonly transactionsRoot: Uint8Array;
    readonly transactionsStart: bigint;
    readonly transactionsTip: bigint;
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
    const proof = await fetchOperationProof(qmdbUrl, metadata.location, tip, signal);
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
    qmdbUrl: string,
    location: bigint,
    tip: bigint,
    signal?: AbortSignal,
) {
    const rpc = createClient(OperationLogService, createTransport(`${trimTrailingSlash(qmdbUrl)}/transactions`));
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

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function txByHeightKeyPrefix(height: bigint, index: number): Uint8Array {
    const key = new Uint8Array(12);
    writeU64Be(key, 0, height);
    writeU32Be(key, 8, index);
    return key;
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

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

interface WasmTransactionProof {
    readonly proofSizeBytes: number;
}
