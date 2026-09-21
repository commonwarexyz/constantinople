import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { QmdbOperationLogClient, type OperationRangeRequest } from '@exowarexyz/qmdb';
import { SqlClient, type CellValue, type DecodedQueryResult } from '@exowarexyz/sql';
import { SimplexClient, type VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import { toArrayBuffer, toHex } from '../src/codec.ts';
import { isRetryableProofError } from '../src/proofRetry.ts';
import { fetchAndVerifyTransactionProof } from '../src/qmdb.ts';

const HEIGHT = 7n;
const LOCATION = 4n;
const TRANSACTIONS_ROOT = new Uint8Array(32).fill(0x52);

test.before(async () => {
    const wasm = await readFile(new URL(
        './generated/wasm/exoware_simplex_wasm_bg.wasm',
        import.meta.resolve('@exowarexyz/simplex/wasm'),
    ));
    await ensureSimplexWasm({ module_or_path: wasm });
});

test('submission proofs discover a height through existing SQL tables and bind the certified range', async (t) => {
    const { body, digest } = await transaction();
    const certificate = await finalizedCertificate(HEIGHT);
    const reads: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) => {
        if (sql.includes('FROM tx_meta')) {
            reads.push('transaction');
            assert.ok(sql.includes(digest));
            return queryResult({ qmdb_location: LOCATION, body });
        }
        reads.push('block');
        assert.match(sql, /FROM block_meta/);
        assert.match(sql, /WHERE transactions_tip > 4/);
        assert.match(sql, /ORDER BY height ASC/);
        return queryResult({ height: HEIGHT, transactions_tip: 7n, tx_count: 3n });
    });
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) => {
        reads.push('certificate');
        assert.equal(height, HEIGHT.toString());
        return certificate;
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        reads.push('proof');
        assert.deepEqual(request, { tip: 7n, startLocation: LOCATION, maxLocations: 1 });
        assert.equal(location, LOCATION);
        assert.equal(toHex(value), digest);
        assert.deepEqual(root, TRANSACTIONS_ROOT);
        return { location, value, root, proofSizeBytes: 12, operationCount: 1 };
    });

    const proof = await fetchAndVerifyTransactionProof({
        ...proofOptions(digest),
        onFinalizationVerified: (target) => {
            reads.push('verified');
            assert.equal(target.height, HEIGHT);
        },
    });

    assert.deepEqual(proof, { location: LOCATION, tip: 7n, height: HEIGHT, view: 9n, proofSizeBytes: 12 });
    assert.deepEqual(reads, ['transaction', 'block', 'certificate', 'verified', 'proof']);
});

for (const missing of ['transaction', 'block']) {
    test(`submission proofs retry when the ${missing} metadata is not published yet`, async (t) => {
        const { body, digest } = await transaction();
        t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
            missing === 'block' && sql.includes('FROM tx_meta')
                ? queryResult({ qmdb_location: LOCATION, body })
                : { columns: [], rows: [] },
        );
        const certificate = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => {
            throw new Error('unexpected certificate request');
        });

        await assert.rejects(fetchAndVerifyTransactionProof(proofOptions(digest)), retryableError);
        assert.equal(certificate.mock.callCount(), 0);
    });
}

test('submission proofs reject SQL transaction bytes that do not match the requested digest', async (t) => {
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({
        qmdb_location: LOCATION,
        body: new Uint8Array(82).fill(0x33),
    }));
    const certificate = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => {
        throw new Error('unexpected certificate request');
    });

    await assert.rejects(fetchAndVerifyTransactionProof(proofOptions('11'.repeat(32))), /body does not match/);
    assert.equal(certificate.mock.callCount(), 0);
});

test('out of order block publication retries without reporting the wrong finalization', async (t) => {
    const { body, digest } = await transaction();
    const containing = await finalizedCertificate(HEIGHT);
    const later = await finalizedCertificate(HEIGHT + 1n, 4n, 12n);
    let blockPublished = false;
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
        sql.includes('FROM tx_meta')
            ? queryResult({ qmdb_location: LOCATION, body })
            : queryResult(blockPublished
                ? { height: HEIGHT, transactions_tip: 7n, tx_count: 3n }
                : { height: HEIGHT + 1n, transactions_tip: 11n, tx_count: 3n }),
    );
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) =>
        height === HEIGHT.toString() ? containing : later,
    );
    const proofRequest = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        _request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => ({ location, value, root, proofSizeBytes: 12, operationCount: 1 }));
    const finalizations: bigint[] = [];
    const options = {
        ...proofOptions(digest),
        onFinalizationVerified: (target: { height: bigint }) => { finalizations.push(target.height); },
    };

    await assert.rejects(fetchAndVerifyTransactionProof(options), retryableError);
    assert.deepEqual(finalizations, []);
    assert.equal(proofRequest.mock.callCount(), 0);

    blockPublished = true;
    const proof = await fetchAndVerifyTransactionProof(options);
    assert.equal(proof.height, HEIGHT);
    assert.deepEqual(finalizations, [HEIGHT]);
    assert.equal(proofRequest.mock.callCount(), 1);
});

function retryableError(error: unknown): boolean {
    assert.ok(error instanceof Error);
    assert.equal(isRetryableProofError(error.message), true);
    return true;
}

function proofOptions(digest: string) {
    return {
        qmdbUrl: 'http://qmdb',
        storeUrl: 'http://store',
        sqlUrl: 'http://sql',
        simplexVerificationMaterial: '11',
        digest,
    };
}

async function transaction() {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    return { body, digest };
}

function queryResult(values: Record<string, CellValue>): DecodedQueryResult {
    return { columns: Object.keys(values), rows: [{ values, cells: Object.values(values) }] };
}

async function finalizedCertificate(
    height: bigint,
    transactionsStart = 2n,
    transactionsTip = 8n,
): Promise<VerifiedSimplexCertificate> {
    const header = concat(
        new Uint8Array([0, 9]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), new Uint8Array(32), u64(height), u64(0n),
        new Uint8Array(32).fill(0x51), u64(1n), u64(10n),
        TRANSACTIONS_ROOT, u64(transactionsStart), u64(transactionsTip),
    );
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(header)));
    const payload = concat(digest, new Uint8Array(68));
    return {
        scheme: 'bls12381-threshold-standard-min-sig',
        view: 9n,
        parent: 8n,
        payload,
        certificate: new Uint8Array(),
        header: concat(payload, header),
    };
}

function u64(value: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value);
    return bytes;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
    const result = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return result;
}
