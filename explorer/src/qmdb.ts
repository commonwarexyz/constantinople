import { create } from '@bufbuild/protobuf';
import { createClient } from '@connectrpc/connect';
import { createTransport } from '@exowarexyz/sdk';
import { fromHex, toHex } from './codec';
import { verifyTransactionProof } from './crypto-wasm/constantinople_explorer_crypto';
import { loadCrypto } from './wallet';
import { type DecodedRow, SqlClient } from '@exowarexyz/sql';
import {
    GetOperationRangeRequestSchema,
    OperationLogService,
} from '../vendor/exoware-qmdb/src/generated/proto/qmdb/v1/operation_log_pb';

const TX_META_TABLE = 'tx_meta';
const TX_META_HEIGHT = 'height';
const TX_META_DIGEST = 'tx_digest';
const TX_META_QMDB_LOCATION = 'qmdb_location';
const BLOCK_META_TABLE = 'block_meta';
const BLOCK_META_HEIGHT = 'height';
const BLOCK_META_TRANSACTIONS_ROOT = 'transactions_root';
const BLOCK_META_TRANSACTIONS_TIP = 'transactions_tip';

export interface VerifiedTransactionProof {
    readonly location: bigint;
    readonly tip: bigint;
    readonly proofSizeBytes: number;
    readonly mmr: MmrProofVisualization;
}

export interface MmrProofVisualization {
    readonly leaves: string;
    readonly inactivePeaks: number;
    readonly targetPosition: string;
    readonly peaks: MmrPeak[];
    readonly nodes: MmrNode[];
}

export interface MmrPeak {
    readonly position: string;
    readonly height: number;
}

export interface MmrNode {
    readonly position: string;
    readonly height: number;
    readonly digest: string;
    readonly kind: 'target' | 'proof';
}

interface TransactionProofMetadata {
    readonly location: bigint;
    readonly root: Uint8Array;
    readonly tip: bigint;
}

export async function fetchAndVerifyTransactionProof({
    sqlUrl,
    qmdbUrl,
    digest,
    height,
    signal,
}: {
    sqlUrl: string;
    qmdbUrl: string;
    digest: string;
    height: number;
    signal?: AbortSignal;
}): Promise<VerifiedTransactionProof> {
    await loadCrypto();
    const metadata = await fetchTransactionProofMetadata(sqlUrl, digest, height, signal);
    const proof = await fetchOperationProof(qmdbUrl, metadata, signal);
    const verification = verifyTransactionProof(
        metadata.root,
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
        tip: metadata.tip,
        proofSizeBytes: verification.proofSizeBytes,
        mmr: normalizeMmrVisualization(verification.mmr),
    };
}

async function fetchTransactionProofMetadata(
    sqlUrl: string,
    digest: string,
    height: number,
    signal?: AbortSignal,
): Promise<TransactionProofMetadata> {
    const sql = new SqlClient(sqlUrl);
    const txRows = await sql.query(
        `SELECT ${TX_META_DIGEST}, ${TX_META_QMDB_LOCATION} FROM ${TX_META_TABLE} WHERE ${TX_META_HEIGHT} = ${height}`,
        { signal },
    );
    const tx = txRows.rows.find((row) => cellDigestHex(row, TX_META_DIGEST) === digest);
    if (!tx) {
        throw new Error(`tx_meta missing ${shortHex(digest)} at height ${height}`);
    }

    const location = bigintCell(tx, TX_META_QMDB_LOCATION);
    const blockRows = await sql.query(
        `SELECT ${BLOCK_META_TRANSACTIONS_ROOT}, ${BLOCK_META_TRANSACTIONS_TIP} FROM ${BLOCK_META_TABLE} WHERE ${BLOCK_META_HEIGHT} = ${height}`,
        { signal },
    );
    const block = blockRows.rows[0];
    if (!block) {
        throw new Error(`block_meta missing height ${height}`);
    }

    return {
        location,
        root: bytesCell(block, BLOCK_META_TRANSACTIONS_ROOT),
        tip: bigintCell(block, BLOCK_META_TRANSACTIONS_TIP),
    };
}

async function fetchOperationProof(
    qmdbUrl: string,
    metadata: TransactionProofMetadata,
    signal?: AbortSignal,
) {
    const rpc = createClient(OperationLogService, createTransport(`${trimTrailingSlash(qmdbUrl)}/transactions`));
    const response = await rpc.getOperationRange(
        create(GetOperationRangeRequestSchema, {
            tip: metadata.tip,
            startLocation: metadata.location,
            maxLocations: 1,
        }),
        { signal },
    );
    if (!response.proof) {
        throw new Error('QMDB transaction proof response missing proof');
    }
    return response.proof;
}

function bytesCell(row: DecodedRow, column: string): Uint8Array {
    const value = row.values[column];
    if (!(value instanceof Uint8Array)) {
        throw new Error(`${column} was not bytes`);
    }
    return value;
}

function bigintCell(row: DecodedRow, column: string): bigint {
    const value = row.values[column];
    if (typeof value !== 'bigint') {
        throw new Error(`${column} was not u64`);
    }
    return value;
}

function cellDigestHex(row: DecodedRow, column: string): string {
    return toHex(bytesCell(row, column));
}

function shortHex(value: string): string {
    return value.length <= 18 ? value : `${value.slice(0, 10)}...${value.slice(-8)}`;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

interface WasmTransactionProof {
    readonly proofSizeBytes: number;
    readonly mmr: {
        readonly leaves: bigint;
        readonly inactivePeaks: number;
        readonly targetPosition: bigint;
        readonly peaks: {
            readonly position: bigint;
            readonly height: number;
        }[];
        readonly nodes: {
            readonly position: bigint;
            readonly height: number;
            readonly digest: Uint8Array;
            readonly kind: 'target' | 'proof';
        }[];
    };
}

function normalizeMmrVisualization(value: WasmTransactionProof['mmr']): MmrProofVisualization {
    return {
        leaves: value.leaves.toString(),
        inactivePeaks: value.inactivePeaks,
        targetPosition: value.targetPosition.toString(),
        peaks: value.peaks.map((peak) => ({
            position: peak.position.toString(),
            height: peak.height,
        })),
        nodes: value.nodes.map((node) => ({
            position: node.position.toString(),
            height: node.height,
            digest: toHex(node.digest),
            kind: node.kind,
        })),
    };
}
