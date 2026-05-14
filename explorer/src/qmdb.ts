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
const TX_META_HEIGHT_SEARCH_WINDOW = 16;

export interface VerifiedTransactionProof {
    readonly location: bigint;
    readonly tip: bigint;
    readonly proofSizeBytes: number;
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
    };
}

async function fetchTransactionProofMetadata(
    sqlUrl: string,
    digest: string,
    height: number,
    signal?: AbortSignal,
): Promise<TransactionProofMetadata> {
    const sql = new SqlClient(sqlUrl);
    const minHeight = Math.max(0, height - TX_META_HEIGHT_SEARCH_WINDOW);
    const maxHeight = height + TX_META_HEIGHT_SEARCH_WINDOW;
    const digestLiteral = fixedBinarySqlLiteral(digest);
    const txRows = await sql.query(
        `SELECT ${TX_META_HEIGHT}, ${TX_META_DIGEST}, ${TX_META_QMDB_LOCATION} FROM ${TX_META_TABLE} WHERE ${TX_META_DIGEST} = ${digestLiteral} AND ${TX_META_HEIGHT} >= ${minHeight} AND ${TX_META_HEIGHT} <= ${maxHeight}`,
        { signal },
    );
    const tx = txRows.rows.find((row) => cellDigestHex(row, TX_META_DIGEST) === digest);
    if (!tx) {
        throw new Error(`tx_meta missing ${shortHex(digest)} near height ${height}`);
    }

    const location = bigintCell(tx, TX_META_QMDB_LOCATION);
    const actualHeight = Number(bigintCell(tx, TX_META_HEIGHT));
    const blockRows = await sql.query(
        `SELECT ${BLOCK_META_TRANSACTIONS_ROOT}, ${BLOCK_META_TRANSACTIONS_TIP} FROM ${BLOCK_META_TABLE} WHERE ${BLOCK_META_HEIGHT} = ${actualHeight}`,
        { signal },
    );
    const block = blockRows.rows[0];
    if (!block) {
        throw new Error(`block_meta missing height ${actualHeight}`);
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

function fixedBinarySqlLiteral(value: string): string {
    if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
        throw new Error(`invalid fixed binary hex literal ${shortHex(value)}`);
    }
    return `X'${value.toUpperCase()}'`;
}

function trimTrailingSlash(value: string): string {
    return value.replace(/\/+$/, '');
}

interface WasmTransactionProof {
    readonly proofSizeBytes: number;
}
