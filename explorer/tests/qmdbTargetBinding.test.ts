import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import type { CallOptions } from '@connectrpc/connect';

import {
    QmdbOperationLogClient,
    type BytesLike,
    type OperationRangeRequest,
    type VerifiedFixedKeylessAppendProof,
    type VerifiedFixedUnorderedUpdateProof,
} from '@exowarexyz/qmdb';
import {
    SqlClient,
    type DecodedQueryResult,
    type Table,
} from '@exowarexyz/sql';
import { SimplexClient, type VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import { StoreClient, TraversalMode, type GetManyResultItem, type QueryResult } from '@exowarexyz/sdk';
import { toArrayBuffer, toHex } from '../src/codec.ts';
import { normalizeSubmittedTransaction } from '../src/submissionHistory.ts';
import {
    isRetryableAccountProofError,
    isRetryableProofError,
    retryAccountWork,
} from '../src/proofRetry.ts';
import {
    fetchAccountTransactionsPage,
    fetchAndVerifyAccountProof,
    fetchAndVerifyTransactionRowProof,
    fetchAndVerifyTransactionProof,
    fetchLatestProofTarget,
    prefetchFinalizedCertificate,
    fetchAccountProofMetadata,
    type LatestProofTarget,
} from '../src/qmdb.ts';

const HEIGHT = 7n;
const FLOOR = 41n;
const LOCATION = 4n;

let storeId = 0;

test.beforeEach(() => { storeId++; });

test.before(async () => {
    const wasm = await readFile(new URL(
        './generated/wasm/exoware_simplex_wasm_bg.wasm',
        import.meta.resolve('@exowarexyz/simplex/wasm'),
    ));
    await ensureSimplexWasm({ module_or_path: wasm });
});

test('account target retries when publication precedes its Simplex certificate', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    let available = false;
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => {
        return available ? certificate : null;
    });
    mockNoDescendant(t);
    const controller = new AbortController();
    const target = await retryAccountWork(
        () => fetchLatestProofTarget({
            storeUrl: `http://store/${storeId}`,
            sqlUrl: 'http://sql',
            simplexVerificationMaterial: '11',
            publishedTarget: {
                height: HEIGHT,
                blockDigest: certificate.payload.slice(0, 32),
                sequenceNumber: FLOOR,
            },
            signal: controller.signal,
        }),
        controller.signal,
        isRetryableAccountProofError,
        {
            wait: async () => {
                available = true;
                return true;
            },
        },
    );

    assert.equal(read.mock.callCount(), 2);
    assert.equal(target.height, HEIGHT);
    assert.equal(target.sequenceNumber, FLOOR);
});

test('reported height starts certificate and metadata reads together and retains proof bindings', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    let metadataStarted!: () => void;
    const metadataReady = new Promise<void>((resolve) => { metadataStarted = resolve; });
    const reads: string[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string, floor: bigint) => {
        reads.push('certificate');
        assert.equal(height, HEIGHT.toString());
        assert.equal(floor, FLOOR);
        await metadataReady;
        return certificate;
    });
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, minSequenceNumber?: bigint) => {
        assert.equal(minSequenceNumber, FLOOR);
        reads.push('metadata');
        metadataStarted();
        return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        reads.push('proof');
        assert.equal(request.minSequenceNumber, FLOOR);
        assert.equal(request.tip, 7n);
        assert.equal(location, LOCATION);
        assert.equal(toHex(value), digest);
        assert.deepEqual(root, latestTarget().transactionsRoot);
        return keylessProof(request, root, location, value);
    });

    const proof = await fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT,
        onFinalizationVerified: (target) => {
            reads.push('verified');
            assert.equal(target.height, HEIGHT);
        },
    });

    assert.deepEqual(proof, {
        location: LOCATION,
        tip: 7n,
        height: HEIGHT,
        view: 9n,
        proofSizeBytes: 12,
    });
    assert.deepEqual(reads.slice(0, 2).sort(), ['certificate', 'metadata']);
    assert.deepEqual(reads.slice(2), ['verified', 'proof']);
});

for (const containingHeight of [1n, HEIGHT]) {
    test(`transaction proof reads height ${containingHeight} from tx_meta without a reported height`, async (t) => {
        const body = new Uint8Array(82).fill(0x33);
        const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
        const latest = await finalizedCertificate(HEIGHT + 1n);
        const containing = await finalizedCertificate(containingHeight);
        const heights: string[] = [];
        t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) => {
            heights.push(height);
            return height === containingHeight.toString() ? containing : latest;
        });
        const query = t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
            txMetaResult(sql, { qmdb_location: LOCATION, body, height: containingHeight }),
        );
        t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
            request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
        ) => keylessProof(request, root, location, value));
        const options = transactionProofOptions(digest);
        options.publishedTarget.blockDigest = latest.payload.slice(0, 32);

        const proof = await fetchAndVerifyTransactionProof(options);

        assert.equal(proof.height, containingHeight);
        assert.deepEqual(heights, [(HEIGHT + 1n).toString(), containingHeight.toString()]);
        assert.equal(query.mock.callCount(), 1);
    });
}

test('submission proofs retry when the transaction metadata is not published yet', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT + 1n);
    const options = transactionProofOptions(digest);
    options.publishedTarget.blockDigest = certificate.payload.slice(0, 32);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async () => emptyQueryResult());
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof');
    });
    const finalizations: bigint[] = [];

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...options,
        onFinalizationVerified: (target) => { finalizations.push(target.height); },
    }), isRetryableProofError);

    assert.deepEqual(finalizations, []);
    assert.equal(proof.mock.callCount(), 0);
});

for (const finalizedHeight of [undefined, HEIGHT + 1n]) {
    test(`owning-height proofs need no block_meta reads with hint ${finalizedHeight}`, async (t) => {
        const body = new Uint8Array(82).fill(0x33);
        const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
        const containing = await finalizedCertificate(HEIGHT);
        const later = await finalizedCertificate(HEIGHT + 1n, 4n, 12n);
        const options = transactionProofOptions(digest);
        options.publishedTarget.blockDigest = later.payload.slice(0, 32);
        const floors: Array<bigint | undefined> = [];
        t.mock.method(SqlClient.prototype, 'query', async (sql: string, minSequenceNumber?: bigint) => {
            floors.push(minSequenceNumber);
            return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
        });
        t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) =>
            height === HEIGHT.toString() ? containing : later,
        );
        const proofRequest = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
            request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
        ) => keylessProof(request, root, location, value));
        const finalizations: bigint[] = [];

        const proof = await fetchAndVerifyTransactionProof({
            ...options,
            finalizedHeight,
            onFinalizationVerified: (target: { height: bigint }) => { finalizations.push(target.height); },
        });

        assert.equal(proof.height, HEIGHT);
        assert.deepEqual(finalizations, [HEIGHT]);
        assert.equal(proofRequest.mock.callCount(), 1);
        assert.deepEqual(floors, [FLOOR]);
    });
}

test('transaction proof discovers its height despite an ahead-of-target report restored from history', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const restored = normalizeSubmittedTransaction(JSON.parse(JSON.stringify({
        reconciliationVersion: 2,
        sender: '11'.repeat(32),
        digest,
        to: '22'.repeat(32),
        value: '7',
        nonce: '2',
        submittedAt: 1_000,
        finalizationObservedInMs: 100,
        proofObservedInMs: null,
        status: 'reconciling',
        detail: 'validator reported finalized at 1000000',
        finalizedHeight: 1_000_000,
        certificate: { status: 'waiting', detail: 'waiting for certificate' },
        proof: { status: 'waiting', detail: 'waiting for publication' },
    })));
    assert.equal(restored?.finalizedHeight, 1_000_000);

    const latest = await finalizedCertificate(HEIGHT + 1n);
    const containing = await finalizedCertificate(HEIGHT);
    const options = transactionProofOptions(digest);
    options.publishedTarget.blockDigest = latest.payload.slice(0, 32);
    const heights: string[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string, floor: bigint) => {
        assert.equal(floor, FLOOR);
        heights.push(height);
        return height === HEIGHT.toString() ? containing : latest;
    });
    const query = t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
        assert.equal(floor, FLOOR);
        return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
    });
    const proofRequest = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        assert.equal(request.minSequenceNumber, FLOOR);
        assert.equal(request.tip, 7n);
        assert.equal(location, LOCATION);
        assert.equal(toHex(value), digest);
        assert.deepEqual(root, latestTarget().transactionsRoot);
        return keylessProof(request, root, location, value);
    });
    const finalizations: bigint[] = [];

    const proof = await fetchAndVerifyTransactionProof({
        ...options,
        finalizedHeight: BigInt(restored!.finalizedHeight!),
        onFinalizationVerified: (target) => { finalizations.push(target.height); },
    });

    assert.equal(proof.height, HEIGHT);
    assert.deepEqual(finalizations, [HEIGHT]);
    assert.deepEqual(heights, [(HEIGHT + 1n).toString(), HEIGHT.toString()]);
    assert.equal(query.mock.callCount(), 1);
    assert.equal(proofRequest.mock.callCount(), 1);
});

for (const hintState of ['missing', 'error', 'pending'] as const) {
    test(`transaction proof ignores a ${hintState} certificate for a different hinted height`, { timeout: 5_000 }, async (t) => {
        const body = new Uint8Array(82).fill(0x33);
        const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
        const certificate = await finalizedCertificate(HEIGHT);
        const hintStarted = deferred<void>();
        let hintSignal: AbortSignal | undefined;
        const heights: string[] = [];
        t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
            height: string, floor: bigint, options: { signal?: AbortSignal },
        ) => {
            assert.equal(floor, FLOOR);
            heights.push(height);
            if (height === HEIGHT.toString()) return certificate;
            assert.equal(height, (HEIGHT - 1n).toString());
            hintSignal = options.signal;
            hintStarted.resolve();
            if (hintState === 'missing') return null;
            if (hintState === 'error') throw new Error('hint certificate unavailable');
            return new Promise<VerifiedSimplexCertificate>((_resolve, reject) => {
                hintSignal!.addEventListener('abort', () => reject(hintSignal!.reason), { once: true });
            });
        });
        mockNoDescendant(t);
        t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
            assert.equal(floor, FLOOR);
            await hintStarted.promise;
            return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
        });
        const proofRequest = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
            request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
        ) => {
            assert.equal(request.minSequenceNumber, FLOOR);
            assert.equal(request.tip, 7n);
            assert.equal(location, LOCATION);
            assert.equal(toHex(value), digest);
            assert.deepEqual(root, latestTarget().transactionsRoot);
            return keylessProof(request, root, location, value);
        });
        const finalizations: bigint[] = [];

        const proof = await fetchAndVerifyTransactionProof({
            ...transactionProofOptions(digest),
            finalizedHeight: HEIGHT - 1n,
            signal: t.signal,
            onFinalizationVerified: (target) => { finalizations.push(target.height); },
        });

        assert.equal(proof.height, HEIGHT);
        assert.deepEqual(heights, [(HEIGHT - 1n).toString(), HEIGHT.toString()]);
        assert.deepEqual(finalizations, [HEIGHT]);
        assert.equal(proofRequest.mock.callCount(), 1);
        if (hintState === 'pending') assert.equal(hintSignal?.aborted, true);
    });
}

test('a certificate failure still rejects when SQL confirms the hinted height', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const failure = new Error('owning certificate is invalid');
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => {
        throw failure;
    });
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) => txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT }));
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof');
    });

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT,
    }), (error) => error === failure);

    assert.equal(read.mock.callCount(), 1);
    assert.equal(proof.mock.callCount(), 0);
});

test('cancellation stops the SQL-derived lookup after discarding a pending hint', { timeout: 5_000 }, async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const hintStarted = deferred<void>();
    const owningStarted = deferred<void>();
    const signals: AbortSignal[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        height: string, _floor: bigint, options: { signal?: AbortSignal },
    ) => new Promise<VerifiedSimplexCertificate>((_resolve, reject) => {
        const signal = options.signal!;
        signals.push(signal);
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
        if (height === HEIGHT.toString()) owningStarted.resolve();
        else hintStarted.resolve();
    }));
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) => {
        await hintStarted.promise;
        return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
    });
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof');
    });
    const controller = new AbortController();
    const cancellation = new Error('caller left');
    const pending = fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT - 1n,
        signal: AbortSignal.any([controller.signal, t.signal]),
    });
    const rejected = assert.rejects(pending, (error) => error === cancellation);

    await owningStarted.promise;
    assert.equal(signals[0]!.aborted, true);
    controller.abort(cancellation);
    await rejected;

    assert.equal(signals.length, 2);
    assert.equal(signals[1]!.aborted, true);
    assert.equal(proof.mock.callCount(), 0);
});

test('an ahead-of-target report still waits when the SQL-derived height is uncovered', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const latest = await finalizedCertificate(HEIGHT + 1n);
    const options = transactionProofOptions(digest);
    options.publishedTarget.blockDigest = latest.payload.slice(0, 32);
    const certificate = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => latest);
    const query = t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
        txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT + 2n }),
    );
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof');
    });
    const finalizations: bigint[] = [];

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...options,
        finalizedHeight: 1_000_000n,
        onFinalizationVerified: (target) => { finalizations.push(target.height); },
    }), /transaction height 9 is not yet covered by a provable finalization/);

    assert.deepEqual(finalizations, []);
    assert.equal(query.mock.callCount(), 1);
    assert.equal(certificate.mock.callCount(), 1);
    assert.equal(proof.mock.callCount(), 0);
});

test('a reported height cannot place a transaction outside its certified range', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
        txMetaResult(sql, { qmdb_location: 8n, body, height: HEIGHT }),
    );
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => { throw new Error('unexpected proof'); });
    let verified = false;

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT,
        onFinalizationVerified: () => { verified = true; },
    }), /outside finalized block range/);

    assert.equal(verified, false);
    assert.equal(proof.mock.callCount(), 0);
});

test('a reported height at the publication boundary still authenticates its digest', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT + 1n);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
        txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT + 1n }),
    );

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT + 1n,
    }), /provable target digest does not match/);
});

test('a lower hint cannot bypass the publication digest when SQL resolves to the tip', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const containing = await finalizedCertificate(HEIGHT);
    const lower = await finalizedCertificate(HEIGHT - 1n);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) =>
        height === HEIGHT.toString() ? containing : lower);
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) => txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT }));
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof');
    });
    const finalizations: bigint[] = [];

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        publishedTarget: { height: HEIGHT, blockDigest: new Uint8Array(32), sequenceNumber: FLOOR },
        finalizedHeight: HEIGHT - 1n,
        onFinalizationVerified: (target) => { finalizations.push(target.height); },
    }), /provable target digest does not match/);

    assert.deepEqual(finalizations, []);
    assert.equal(proof.mock.callCount(), 0);
});

test('reported-height proofs reject tampered transaction metadata', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({
        qmdb_location: LOCATION,
        body: new Uint8Array(82).fill(0x33),
        height: HEIGHT,
    }));

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions('11'.repeat(32)),
        finalizedHeight: HEIGHT,
    }), /body does not match transaction digest/);
});

test('reported-height proofs retain the request floor without response sequence metadata', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) =>
        txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT }),
    );
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        assert.equal(request.minSequenceNumber, FLOOR);
        return { ...keylessProof(request, root, location, value), sequenceNumber: 0n };
    });

    const result = await fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT,
    });
    assert.equal(result.height, HEIGHT);
    assert.equal(result.location, LOCATION);
});

test('a failed metadata read cancels its concurrent certificate request', async (t) => {
    let certificateStarted!: () => void;
    const ready = new Promise<void>((resolve) => { certificateStarted = resolve; });
    let certificateSignal: AbortSignal | undefined;
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        _height: string, _floor: bigint, options: { signal?: AbortSignal },
    ) => new Promise((_resolve, reject) => {
        certificateSignal = options.signal;
        certificateSignal!.addEventListener('abort', () => reject(certificateSignal!.reason), { once: true });
        certificateStarted();
    }));
    t.mock.method(SqlClient.prototype, 'query', async () => {
        await ready;
        throw new Error('metadata unavailable');
    });

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions('11'.repeat(32)),
        finalizedHeight: HEIGHT,
    }), /metadata unavailable/);

    assert.equal(certificateSignal?.aborted, true);
});

test('prefetched certificates share verification and retain each proof publication floor', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    const options = transactionProofOptions(digest);
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        _height: string, floor: bigint,
    ) => {
        assert.equal(floor, 0n);
        return certificate;
    });
    await prefetchFinalizedCertificate({ ...options, height: HEIGHT });
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
        assert.equal(floor, FLOOR);
        return txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT });
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        assert.equal(request.minSequenceNumber, FLOOR);
        return keylessProof(request, root, location, value);
    });
    await fetchAndVerifyTransactionProof({ ...options, finalizedHeight: HEIGHT });
    assert.equal(read.mock.callCount(), 1);
});

test('certificate cache is scoped by store, verification material, and height', async (t) => {
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) => {
        return finalizedCertificate(BigInt(height));
    });
    const options = { ...transactionProofOptions(''), height: HEIGHT };
    await prefetchFinalizedCertificate(options);
    await prefetchFinalizedCertificate({ ...options, storeUrl: `${options.storeUrl}/` });
    await prefetchFinalizedCertificate({ ...options, storeUrl: `${options.storeUrl}/other` });
    await prefetchFinalizedCertificate({ ...options, simplexVerificationMaterial: '22' });
    await prefetchFinalizedCertificate({ ...options, height: HEIGHT + 1n });
    assert.equal(read.mock.callCount(), 4);
});

for (const failure of ['missing', 'error', 'wrong height'] as const) {
    test(`certificate cache does not retain ${failure}`, async (t) => {
        const certificate = await finalizedCertificate(HEIGHT);
        let available = false;
        const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => {
            if (available) return certificate;
            if (failure === 'missing') return null;
            if (failure === 'error') throw new Error('certificate unavailable');
            return finalizedCertificate(HEIGHT + 1n);
        });
        mockNoDescendant(t);
        const options = { ...transactionProofOptions(''), height: HEIGHT };
        await assert.rejects(prefetchFinalizedCertificate(options));
        available = true;
        await prefetchFinalizedCertificate(options);
        await prefetchFinalizedCertificate(options);
        assert.equal(read.mock.callCount(), 2);
    });
}

test('cancelling one certificate waiter does not cancel a shared request', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    const ready = deferred<void>();
    const response = deferred<VerifiedSimplexCertificate>();
    let sharedSignal: AbortSignal | undefined;
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        _height: string, _floor: bigint, options: { signal?: AbortSignal },
    ) => {
        sharedSignal = options.signal;
        ready.resolve();
        return response.promise;
    });
    const options = { ...transactionProofOptions(''), height: HEIGHT };
    const first = new AbortController();
    const second = new AbortController();
    const cancelled = prefetchFinalizedCertificate({ ...options, signal: first.signal });
    const surviving = prefetchFinalizedCertificate({ ...options, signal: second.signal });
    await ready.promise;
    first.abort(new Error('first caller left'));
    await assert.rejects(cancelled, /first caller left/);
    assert.equal(sharedSignal?.aborted, false);
    response.resolve(certificate);
    await surviving;
    await prefetchFinalizedCertificate(options);
    assert.equal(read.mock.callCount(), 1);
});

test('last certificate waiter cancels promptly and a replacement ignores the abandoned result', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    const ready = deferred<void>();
    const abandoned = deferred<VerifiedSimplexCertificate>();
    const replacement = deferred<VerifiedSimplexCertificate>();
    const signals: AbortSignal[] = [];
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        _height: string, _floor: bigint, options: { signal?: AbortSignal },
    ) => {
        signals.push(options.signal!);
        ready.resolve();
        return signals.length === 1 ? abandoned.promise : replacement.promise;
    });
    const options = { ...transactionProofOptions(''), height: HEIGHT };
    const controller = new AbortController();
    const cancelled = prefetchFinalizedCertificate({ ...options, signal: controller.signal });
    await ready.promise;
    controller.abort(new Error('page left'));
    await assert.rejects(cancelled, /page left/);
    assert.equal(signals[0]!.aborted, true);
    const retry = prefetchFinalizedCertificate(options);
    abandoned.resolve(certificate);
    replacement.resolve(certificate);
    await retry;
    await prefetchFinalizedCertificate(options);
    assert.equal(read.mock.callCount(), 2);
    assert.equal(signals[1]!.aborted, false);
});

test('an already cancelled caller cannot use or initiate a cached certificate', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    const read = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    const options = { ...transactionProofOptions(''), height: HEIGHT };
    const signal = AbortSignal.abort(new Error('already cancelled'));
    await assert.rejects(prefetchFinalizedCertificate({ ...options, signal }), /already cancelled/);
    assert.equal(read.mock.callCount(), 0);
    await prefetchFinalizedCertificate(options);
    await assert.rejects(prefetchFinalizedCertificate({ ...options, signal }), /already cancelled/);
    assert.equal(read.mock.callCount(), 1);
});

test('cached target byte arrays cannot be changed through a caller result', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    const options = {
        ...transactionProofOptions(''),
        publishedTarget: { height: HEIGHT, blockDigest: certificate.payload.slice(0, 32), sequenceNumber: FLOOR },
    };
    const first = await fetchLatestProofTarget(options);
    first.stateRoot.fill(0);
    first.blockDigest.fill(0);
    const second = await fetchLatestProofTarget(options);
    assert.deepEqual(second.stateRoot, latestTarget().stateRoot);
    assert.deepEqual(second.blockDigest, certificate.payload.slice(0, 32));
});

function deferred<T>() {
    let resolve!: (value: T | PromiseLike<T>) => void;
    const promise = new Promise<T>((done) => { resolve = done; });
    return { promise, resolve };
}

function transactionProofOptions(digest: string) {
    return {
        qmdbUrl: 'http://qmdb',
        storeUrl: `http://store/${storeId}`,
        sqlUrl: 'http://sql',
        simplexVerificationMaterial: '11',
        digest,
        publishedTarget: { height: HEIGHT + 1n, blockDigest: new Uint8Array(32), sequenceNumber: FLOOR },
    };
}

async function finalizedCertificate(
    height: bigint,
    transactionsStart = latestTarget().transactionsStart,
    transactionsTip = latestTarget().transactionsTip,
): Promise<VerifiedSimplexCertificate> {
    const target = latestTarget();
    const header = concat(
        new Uint8Array([0, 9]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), new Uint8Array(32), u64(height), u64(0n),
        target.stateRoot, u64(target.stateStart), u64(target.stateTip),
        target.transactionsRoot, u64(transactionsStart), u64(transactionsTip),
    );
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(header)));
    const payload = concat(digest, new Uint8Array(68));
    return {
        scheme: 'bls12381-threshold-standard-min-sig',
        epoch: 0n,
        view: 9n,
        parent: 8n,
        payload,
        certificate: new Uint8Array(),
        header: concat(payload, header),
    };
}

test('account proof retains request floors without response sequence metadata', async (t) => {
    const target = { ...latestTarget(), stateStart: 2n };
    const sqlFloors: Array<bigint | undefined> = [];
    const sqlQueries: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, minSequenceNumber?: bigint) => {
        sqlQueries.push(sql);
        sqlFloors.push(minSequenceNumber);
        return queryResult({
            balance: 9n,
            nonce_base: 2n,
            nonce_bitmap: 3n,
            qmdb_location: LOCATION,
        });
    });

    const qmdbFloors: Array<bigint | undefined> = [];
    t.mock.method(
        QmdbOperationLogClient.prototype,
        'getFixedUnorderedUpdate',
        async (
            request: OperationRangeRequest,
            expectedRoot: BytesLike,
            expectedLocation: bigint,
            expectedKey: BytesLike,
        ) => {
            qmdbFloors.push(request.minSequenceNumber);
            return {
                ...unorderedProof(
                    request,
                    expectedRoot as Uint8Array,
                    expectedLocation,
                    expectedKey as Uint8Array,
                ),
                sequenceNumber: 0n,
            };
        },
    );

    await fetchAndVerifyAccountProof({
        qmdbUrl: 'http://qmdb',
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        target,
    });

    assert.deepEqual(sqlFloors, [FLOOR]);
    assert.match(sqlQueries[0] ?? '', /qmdb_location < 10 ORDER BY qmdb_location DESC/);
    assert.deepEqual(qmdbFloors, [FLOOR]);
});

test('account page retains the publication floor, height, and abort signal', async (t) => {
    const controller = new AbortController();
    const sqlOptions: CallOptions[] = [];
    const sqlFloors: Array<bigint | undefined> = [];
    const sqlQueries: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, minSequenceNumber?: bigint, options: CallOptions = {}) => {
        sqlQueries.push(sql);
        sqlOptions.push(options);
        sqlFloors.push(minSequenceNumber);
        return emptyQueryResult();
    });

    await fetchAccountTransactionsPage({
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        signal: controller.signal,
        minSequenceNumber: FLOOR,
        maxHeight: HEIGHT,
    });

    assert.equal(sqlOptions.length, 1);
    assert.equal(sqlOptions[0]?.signal, controller.signal);
    assert.deepEqual(sqlFloors, [FLOOR]);
    assert.match(sqlQueries[0] ?? '', /height <= 7/);
});

test('account page SQL request stops when its forwarded signal is aborted', async (t) => {
    const controller = new AbortController();
    t.mock.method(
        SqlClient.prototype,
        'query',
        async (_sql: string, _minSequenceNumber?: bigint, options: CallOptions = {}) =>
            new Promise<DecodedQueryResult>((_resolve, reject) => {
                const signal = options.signal;
                assert.ok(signal);
                signal.addEventListener('abort', () => reject(signal.reason), { once: true });
            }),
    );

    const page = fetchAccountTransactionsPage({
        sqlUrl: 'http://sql',
        account: '22'.repeat(32),
        signal: controller.signal,
        minSequenceNumber: FLOOR,
        maxHeight: HEIGHT,
    });
    controller.abort(new Error('account page cancelled'));

    await assert.rejects(page, /account page cancelled/);
});

test('account page decodes the activity row QMDB location', async (t) => {
    t.mock.method(SqlClient.prototype, 'query', async (sql: string) => {
        assert.match(sql, /FROM tx_activity/);
        assert.match(sql, /qmdb_location/);
        return queryResult({
            height: HEIGHT, index: 1n, role: 0n, tx_digest: new Uint8Array(32).fill(0x33),
            counterparty: new Uint8Array(32).fill(0x44), value: 5n, nonce: 2n, qmdb_location: LOCATION,
        });
    });

    const page = await fetchAccountTransactionsPage({
        sqlUrl: 'http://sql', account: '22'.repeat(32), minSequenceNumber: FLOOR, maxHeight: HEIGHT,
    });

    assert.equal(page.rows[0]?.location, LOCATION);
});

test('transaction row proof uses the activity location without SQL and retains the QMDB floor', async (t) => {
    const digest = '33'.repeat(32);
    const query = t.mock.method(SqlClient.prototype, 'query', async () => {
        throw new Error('unexpected SQL request');
    });
    const qmdbFloors: Array<bigint | undefined> = [];
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        qmdbFloors.push(request.minSequenceNumber);
        assert.equal(location, LOCATION);
        assert.equal(toHex(value), digest);
        return keylessProof(request, root, location, value);
    });

    const proof = await fetchAndVerifyTransactionRowProof({
        qmdbUrl: 'http://qmdb', row: activityRow(digest), target: latestTarget(),
    });

    assert.equal(proof.location, LOCATION);
    assert.equal(query.mock.callCount(), 0);
    assert.deepEqual(qmdbFloors, [FLOOR]);
});

test('transaction row proof waits for a target covering the activity location', async (t) => {
    const proofRequest = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async () => {
        throw new Error('unexpected proof request');
    });

    await assert.rejects(
        fetchAndVerifyTransactionRowProof({
            qmdbUrl: 'http://qmdb',
            row: { ...activityRow('33'.repeat(32)), location: latestTarget().transactionsTip },
            target: latestTarget(),
        }),
        /not yet covered by a provable finalization/,
    );
    assert.equal(proofRequest.mock.callCount(), 0);
});

for (const movedLocation of [LOCATION, 10n, 15n, 0n]) {
    test(`speculative account location ${movedLocation} is checked against both certified bounds`, async (t) => {
        const queries: string[] = [];
        t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
            queries.push(sql);
            assert.equal(floor, FLOOR);
            return queryResult({
                balance: 9n, nonce_base: 2n, nonce_bitmap: 3n,
                qmdb_location: queries.length === 1 ? movedLocation : LOCATION,
            });
        });
        t.mock.method(QmdbOperationLogClient.prototype, 'getFixedUnorderedUpdate', async (
            request: OperationRangeRequest, root: Uint8Array, location: bigint, key: Uint8Array,
        ) => {
            assert.equal(request.minSequenceNumber, FLOOR);
            assert.equal(location, LOCATION);
            return unorderedProof(request, root, location, key);
        });
        const metadata = await fetchAccountProofMetadata({
            sqlUrl: 'http://sql', account: '22'.repeat(32), minSequenceNumber: FLOOR,
        });
        const proof = await fetchAndVerifyAccountProof({
            qmdbUrl: 'http://qmdb', sqlUrl: 'http://sql', account: '22'.repeat(32), target: latestTarget(), metadata,
        });
        assert.equal(proof.location, LOCATION);
        assert.doesNotMatch(queries[0]!, /qmdb_location </);
        assert.equal(queries.length, movedLocation === LOCATION ? 1 : 2);
        if (queries.length === 2) assert.match(queries[1]!, /qmdb_location < 10/);
    });
}

test('speculative account SQL with an older floor is refreshed before proving', async (t) => {
    const queries: string[] = [];
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
        queries.push(sql);
        assert.equal(floor, FLOOR);
        return queryResult({ balance: 9n, nonce_base: 2n, nonce_bitmap: 3n, qmdb_location: LOCATION });
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedUnorderedUpdate', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, key: Uint8Array,
    ) => unorderedProof(request, root, location, key));
    await fetchAndVerifyAccountProof({
        qmdbUrl: 'http://qmdb', sqlUrl: 'http://sql', account: '22'.repeat(32), target: latestTarget(),
        metadata: {
            sequenceNumber: FLOOR - 1n, balance: 9n, nonce: 2n, nonceBitmap: 3n, location: LOCATION,
        },
    });
    assert.equal(queries.length, 1);
    assert.match(queries[0]!, /qmdb_location < 10/);
});

function activityRow(digest: string) {
    return {
        digest, direction: 'sent' as const, counterparty: '44'.repeat(32),
        value: 1n, nonce: 2n, height: HEIGHT, blockIndex: 0, location: LOCATION,
    };
}

function queryResult(values: Record<string, unknown>): DecodedQueryResult {
    return {
        sequenceNumber: FLOOR,
        table: testTable([values]),
    };
}

// Proof metadata comes from one tx_meta row; block_meta is never consulted.
function txMetaResult(sql: string, values: { qmdb_location: bigint; body: Uint8Array; height: bigint }): DecodedQueryResult {
    assert.match(sql, /FROM tx_meta/);
    assert.match(sql, /height/);
    return queryResult(values);
}

function emptyQueryResult(): DecodedQueryResult {
    return { sequenceNumber: FLOOR, table: testTable([]) };
}

function testTable(rows: readonly Record<string, unknown>[]): Table {
    return {
        numRows: rows.length,
        getChild(column: string) {
            if (!rows.some((row) => Object.hasOwn(row, column))) return null;
            return { get: (index: number) => rows[index]?.[column] };
        },
    } as unknown as Table;
}

function keylessProof(
    request: OperationRangeRequest,
    root: Uint8Array,
    location: bigint,
    value: Uint8Array,
): VerifiedFixedKeylessAppendProof {
    return {
        sequenceNumber: request.minSequenceNumber ?? 0n,
        location,
        value,
        root,
        proofSizeBytes: 12,
        operationCount: 1,
    };
}

function unorderedProof(
    request: OperationRangeRequest,
    root: Uint8Array,
    location: bigint,
    key: Uint8Array,
): VerifiedFixedUnorderedUpdateProof {
    return {
        sequenceNumber: request.minSequenceNumber ?? 0n,
        location,
        key,
        value: accountValue(9n, 2n, 3n),
        root,
        proofSizeBytes: 14,
        operationCount: 1,
    };
}

function latestTarget(): LatestProofTarget {
    return {
        height: HEIGHT,
        view: 9n,
        sequenceNumber: FLOOR,
        blockDigest: new Uint8Array(32),
        stateRoot: new Uint8Array(32).fill(0x51),
        stateStart: 1n,
        stateTip: 10n,
        transactionsRoot: new Uint8Array(32).fill(0x52),
        transactionsStart: 2n,
        transactionsTip: 8n,
    };
}

function accountValue(balance: bigint, nonce: bigint, nonceBitmap: bigint): Uint8Array {
    return concat(u64(balance), u64(nonce), u64(nonceBitmap));
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

const STORE_SEQUENCE = FLOOR + 5n;
const HINT_BATCH = 128;

interface ChainBlock {
    readonly height: bigint;
    readonly view: bigint;
    readonly digest: Uint8Array;
    readonly header: Uint8Array;
}

interface DescendantStore {
    readonly certificateReads: Array<{ height: bigint; floor: bigint }>;
    readonly rangeQueries: Array<{ from: bigint; floor: bigint | undefined }>;
    readonly headerReads: Array<{ count: number; floor: bigint | undefined }>;
    readonly hintQueries: Array<{ sql: string; floor: bigint | undefined }>;
}

interface DescendantStoreOptions {
    readonly blocks: ReadonlyMap<bigint, ChainBlock>;
    readonly certified: readonly bigint[];
    readonly hints?: (height: bigint) => Uint8Array[];
    readonly header?: (digest: Uint8Array) => Uint8Array | undefined;
    readonly certificate?: (height: bigint) => Promise<VerifiedSimplexCertificate | null>;
    readonly descendantKeyHeight?: (height: bigint) => bigint;
    readonly sql?: (sql: string) => DecodedQueryResult;
    readonly sqlSignal?: (signal: AbortSignal | undefined) => Promise<void>;
}

test('a missing exact certificate is authenticated through a certified descendant', async (t) => {
    const blocks = await blockChain(1n, 10n);
    const store = mockDescendantStore(t, { blocks, certified: [10n] });
    const requested = blocks.get(7n)!;

    const target = await fetchLatestProofTarget({
        ...transactionProofOptions(''),
        publishedTarget: { height: 7n, blockDigest: requested.digest, sequenceNumber: FLOOR },
    });

    assert.equal(target.height, 7n);
    assert.equal(target.view, requested.view);
    assert.equal(target.sequenceNumber, FLOOR);
    assert.equal('parentDigest' in target, false);
    assert.deepEqual(target.blockDigest, requested.digest);
    assert.deepEqual(target.stateRoot, chainStateRoot(7n));
    assert.deepEqual(target.transactionsRoot, chainTransactionsRoot(7n));
    assert.deepEqual(store.certificateReads, [
        { height: 7n, floor: FLOOR },
        { height: 10n, floor: STORE_SEQUENCE },
    ]);
    assert.deepEqual(store.rangeQueries, [{ from: 8n, floor: FLOOR }]);
    assert.equal(store.hintQueries.length, 1);
    assert.match(store.hintQueries[0]!.sql, /WHERE height >= 7 AND height < 9 ORDER BY height LIMIT 2/);
    assert.equal(store.hintQueries[0]!.floor, FLOOR);
    assert.deepEqual(store.headerReads, [{ count: 3, floor: STORE_SEQUENCE }]);

    // Both the requested ancestor and its certified descendant are reusable.
    const cached = await fetchLatestProofTarget({
        ...transactionProofOptions(''),
        publishedTarget: { height: 7n, blockDigest: requested.digest, sequenceNumber: FLOOR },
    });
    await prefetchFinalizedCertificate({ ...transactionProofOptions(''), height: 10n });
    assert.equal('parentDigest' in cached, false);
    assert.equal(store.certificateReads.length, 2);
    assert.equal(store.headerReads.length, 1);
});

test('an adjacent certified descendant needs no SQL digest hints', async (t) => {
    const blocks = await blockChain(1n, 8n);
    const store = mockDescendantStore(t, { blocks, certified: [8n] });

    await prefetchFinalizedCertificate({ ...transactionProofOptions(''), height: 7n });

    assert.equal(store.hintQueries.length, 0);
    assert.deepEqual(store.headerReads, [{ count: 1, floor: STORE_SEQUENCE }]);
});

test('large certificate gaps are authenticated in bounded batches', async (t) => {
    const blocks = await blockChain(1n, 301n);
    const store = mockDescendantStore(t, { blocks, certified: [301n] });

    const target = await fetchLatestProofTarget({
        ...transactionProofOptions(''),
        publishedTarget: { height: 1n, blockDigest: blocks.get(1n)!.digest, sequenceNumber: FLOOR },
    });

    assert.equal(target.height, 1n);
    assert.deepEqual(target.stateRoot, chainStateRoot(1n));
    assert.deepEqual(store.headerReads.map(({ count }) => count), [HINT_BATCH, HINT_BATCH, 44]);
    assert.equal(store.hintQueries.length, 3);
    for (const { sql } of store.hintQueries) {
        assert.ok(Number(/LIMIT (\d+)/.exec(sql)![1]) < HINT_BATCH);
    }
});

const invalidDescendantCases: Array<{
    readonly name: string;
    readonly error: RegExp;
    readonly setup: (blocks: Map<bigint, ChainBlock>) => Promise<Partial<DescendantStoreOptions>>;
}> = [
    {
        name: 'a wrong SQL digest hint',
        error: /SQL block digest at height 8 does not match its certified child/,
        setup: async (blocks) => ({
            hints: (height) => height === 8n ? [blocks.get(3n)!.digest] : [blocks.get(height)!.digest],
        }),
    },
    {
        name: 'a duplicate SQL digest hint',
        error: /SQL block digest hints contain unexpected height 8/,
        setup: async (blocks) => ({
            hints: (height) => height === 8n
                ? [blocks.get(8n)!.digest, blocks.get(8n)!.digest]
                : [blocks.get(height)!.digest],
        }),
    },
    {
        name: 'a tampered header',
        error: /block header at height 8 does not match its certified digest/,
        setup: async (blocks) => ({
            header: (digest) => {
                const block = [...blocks.values()].find((candidate) => bytesEqualTest(candidate.digest, digest));
                if (block?.height !== 8n) return block?.header;
                const tampered = block.header.slice();
                tampered[tampered.length - 1] ^= 1;
                return tampered;
            },
        }),
    },
    {
        name: 'a header with trailing bytes',
        error: /block header at height 8 has trailing bytes/,
        setup: async (blocks) => {
            const header = concat(chainHeader(8n, blocks.get(7n)!.digest), new Uint8Array([0]));
            await replaceBlock(blocks, 8n, header);
            await replaceBlock(blocks, 9n, chainHeader(9n, blocks.get(8n)!.digest));
            await replaceBlock(blocks, 10n, chainHeader(10n, blocks.get(9n)!.digest));
            return {};
        },
    },
    {
        name: 'a chain that skips a height',
        error: /block header height 7 does not match chain height 8/,
        setup: async (blocks) => {
            blocks.delete(8n);
            const header = chainHeader(9n, blocks.get(7n)!.digest);
            await replaceBlock(blocks, 9n, header);
            await replaceBlock(blocks, 10n, chainHeader(10n, blocks.get(9n)!.digest));
            return {
                hints: (height) => height === 8n ? [blocks.get(7n)!.digest] : [blocks.get(height)!.digest],
            };
        },
    },
    {
        name: 'a descendant certificate that fails verification',
        error: /simplex finalization verification failed/,
        setup: async () => ({
            certificate: async () => { throw new Error('simplex finalization verification failed'); },
        }),
    },
    {
        name: 'a descendant row at the requested height',
        error: /Simplex descendant query returned height 7 at or below 7/,
        setup: async () => ({ descendantKeyHeight: () => 7n }),
    },
];

for (const { name, error, setup } of invalidDescendantCases) {
    test(`descendant fallback fails closed on ${name}`, async (t) => {
        const blocks = await blockChain(1n, 10n);
        const overrides = await setup(blocks);
        const store = mockDescendantStore(t, { blocks, certified: [10n], ...overrides });

        const failure = await fetchLatestProofTarget({
            ...transactionProofOptions(''),
            publishedTarget: { height: 7n, blockDigest: blocks.get(7n)!.digest, sequenceNumber: FLOOR },
        }).then(() => assert.fail('expected an invalid descendant proof'), (reason: unknown) => reason);

        assert.match(String(failure), error);
        assert.equal(isRetryableProofError(failure), false);
        assert.equal(isRetryableAccountProofError(failure), false);
        assert.ok(store.certificateReads.length <= 2);
    });
}

test('descendant fallback still enforces the publication digest', async (t) => {
    const blocks = await blockChain(1n, 10n);
    mockDescendantStore(t, { blocks, certified: [10n] });

    await assert.rejects(fetchLatestProofTarget({
        ...transactionProofOptions(''),
        publishedTarget: { height: 7n, blockDigest: blocks.get(6n)!.digest, sequenceNumber: FLOOR },
    }), /provable target digest does not match finalized certificate at height 7/);
});

const unavailableDescendantCases: Array<{
    readonly name: string;
    readonly setup: (blocks: ReadonlyMap<bigint, ChainBlock>, available: () => boolean) => Partial<DescendantStoreOptions> & {
        readonly certified?: readonly bigint[];
    };
}> = [
    {
        name: 'no certified descendant',
        setup: (_blocks, available) => ({ certified: available() ? [10n] : [] }),
    },
    {
        name: 'a missing SQL digest hint',
        setup: (blocks, available) => ({
            hints: (height) => height === 8n && !available() ? [] : [blocks.get(height)!.digest],
        }),
    },
    {
        name: 'a missing ancestor header',
        setup: (blocks, available) => ({
            header: (digest) => {
                const block = [...blocks.values()].find((candidate) => bytesEqualTest(candidate.digest, digest));
                return block?.height === 8n && !available() ? undefined : block?.header;
            },
        }),
    },
];

for (const { name, setup } of unavailableDescendantCases) {
    test(`descendant fallback retries after ${name}`, async (t) => {
        const blocks = await blockChain(1n, 10n);
        let available = false;
        const stores: DescendantStore[] = [];
        const attempt = () => {
            t.mock.restoreAll();
            const options = setup(blocks, () => available);
            stores.push(mockDescendantStore(t, { blocks, certified: [10n], ...options }));
            return fetchLatestProofTarget({
                ...transactionProofOptions(''),
                publishedTarget: { height: 7n, blockDigest: blocks.get(7n)!.digest, sequenceNumber: FLOOR },
            });
        };

        const failure = await attempt().then(
            () => assert.fail('expected the fallback to wait'),
            (reason: unknown) => reason,
        );
        assert.match(String(failure), /^Error: finalization missing at height 7$/);
        assert.equal(isRetryableProofError(failure), true);
        assert.equal(isRetryableAccountProofError(failure), true);

        available = true;
        const target = await attempt();
        assert.equal(target.height, 7n);
        assert.deepEqual(target.blockDigest, blocks.get(7n)!.digest);
    });
}

test('transaction proofs use the requested ancestor root authenticated by the published target', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const blocks = await blockChain(1n, 8n);
    const store = mockDescendantStore(t, {
        blocks,
        certified: [8n],
        sql: (sql) => txMetaResult(sql, { qmdb_location: LOCATION, body, height: HEIGHT }),
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        assert.equal(request.minSequenceNumber, FLOOR);
        assert.equal(request.tip, 7n);
        assert.equal(location, LOCATION);
        assert.deepEqual(root, chainTransactionsRoot(7n));
        return keylessProof(request, root, location, value);
    });
    const finalizations: Array<{ height: bigint; view: bigint }> = [];

    const proof = await fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        publishedTarget: { height: 8n, blockDigest: blocks.get(8n)!.digest, sequenceNumber: FLOOR },
        onFinalizationVerified: ({ height, view }) => { finalizations.push({ height, view }); },
    });

    assert.equal(proof.height, 7n);
    assert.equal(proof.view, blocks.get(7n)!.view);
    assert.deepEqual(finalizations, [{ height: 7n, view: blocks.get(7n)!.view }]);
    assert.deepEqual(store.certificateReads.map(({ height }) => height), [8n, 7n]);
    assert.deepEqual(store.headerReads, [{ count: 1, floor: STORE_SEQUENCE }]);
});

test('cancelling descendant fallback aborts its pending SQL read', async (t) => {
    const blocks = await blockChain(1n, 10n);
    const started = deferred<void>();
    let sqlSignal: AbortSignal | undefined;
    const store = mockDescendantStore(t, {
        blocks,
        certified: [10n],
        sqlSignal: (signal) => {
            sqlSignal = signal;
            started.resolve();
            return new Promise((_resolve, reject) => {
                signal!.addEventListener('abort', () => reject(signal!.reason), { once: true });
            });
        },
    });
    const controller = new AbortController();

    const pending = fetchLatestProofTarget({
        ...transactionProofOptions(''),
        publishedTarget: { height: 7n, blockDigest: blocks.get(7n)!.digest, sequenceNumber: FLOOR },
        signal: controller.signal,
    });
    await started.promise;
    controller.abort(new Error('page left'));

    await assert.rejects(pending, /page left/);
    assert.equal(sqlSignal?.aborted, true);
    assert.equal(store.headerReads.length, 0);
});

test('a shared finalization attempt is joined only by callers it covers', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    const responses: Array<ReturnType<typeof deferred<VerifiedSimplexCertificate>>> = [];
    const floors: bigint[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (_height: string, floor: bigint) => {
        floors.push(floor);
        const response = deferred<VerifiedSimplexCertificate>();
        responses.push(response);
        return response.promise;
    });
    const options = { ...transactionProofOptions(''), height: HEIGHT };

    const stale = prefetchFinalizedCertificate(options);
    const latest = fetchLatestProofTarget({
        ...options,
        publishedTarget: { height: HEIGHT, blockDigest: certificate.payload.slice(0, 32), sequenceNumber: FLOOR },
    });
    const covered = prefetchFinalizedCertificate(options);
    await new Promise((resolve) => setImmediate(resolve));

    assert.deepEqual(floors, [0n, FLOOR]);
    for (const response of responses) response.resolve(certificate);
    await Promise.all([stale, latest, covered]);
    assert.equal(floors.length, 2);
});

test('a replaced lower-floor attempt stops with its own caller while the covering attempt survives', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    const responses: Array<ReturnType<typeof deferred<VerifiedSimplexCertificate>>> = [];
    const signals: AbortSignal[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (
        _height: string, _floor: bigint, options: { signal?: AbortSignal },
    ) => {
        signals.push(options.signal!);
        const response = deferred<VerifiedSimplexCertificate>();
        responses.push(response);
        return response.promise;
    });
    const options = { ...transactionProofOptions(''), height: HEIGHT };
    const controller = new AbortController();

    const stale = prefetchFinalizedCertificate({ ...options, signal: controller.signal });
    const latest = fetchLatestProofTarget({
        ...options,
        publishedTarget: { height: HEIGHT, blockDigest: certificate.payload.slice(0, 32), sequenceNumber: FLOOR },
    });
    await new Promise((resolve) => setImmediate(resolve));
    controller.abort(new Error('stale caller left'));
    await assert.rejects(stale, /stale caller left/);

    assert.equal(signals.length, 2);
    assert.equal(signals[0]!.aborted, true);
    assert.equal(signals[1]!.aborted, false);

    // A later low-floor caller still finds and joins the covering attempt.
    const joined = prefetchFinalizedCertificate(options);
    await new Promise((resolve) => setImmediate(resolve));
    for (const response of responses) response.resolve(certificate);
    const target = await latest;
    await joined;
    assert.equal(target.height, HEIGHT);
    assert.equal(signals.length, 2);
});

function mockNoDescendant(t: test.TestContext) {
    t.mock.method(StoreClient.prototype, 'query', async (): Promise<QueryResult> => ({
        sequenceNumber: FLOOR,
        results: [],
    }));
}

function mockDescendantStore(t: test.TestContext, options: DescendantStoreOptions): DescendantStore {
    const { blocks, certified } = options;
    const recorded: DescendantStore = {
        certificateReads: [],
        rangeQueries: [],
        headerReads: [],
        hintQueries: [],
    };
    const headers = new Map([...blocks.values()].map((block) => [toHex(block.digest), block.header]));

    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string, floor: bigint) => {
        recorded.certificateReads.push({ height: BigInt(height), floor });
        if (options.certificate && BigInt(height) !== 7n) return options.certificate(BigInt(height));
        return certified.includes(BigInt(height)) ? chainCertificate(blocks.get(BigInt(height))!) : null;
    });
    t.mock.method(StoreClient.prototype, 'query', async (
        start: Uint8Array,
        end: Uint8Array,
        limit: number,
        _batchSize: number,
        mode: TraversalMode,
        floor?: bigint,
    ): Promise<QueryResult> => {
        assert.equal(start[0], 5);
        assert.deepEqual(end, new Uint8Array([6]));
        assert.equal(limit, 1);
        assert.equal(mode, TraversalMode.FORWARD);
        const from = new DataView(start.buffer, start.byteOffset).getBigUint64(1);
        recorded.rangeQueries.push({ from, floor });
        const nearest = certified.filter((height) => height >= from).reduce<bigint | undefined>(
            (lowest, height) => lowest === undefined || height < lowest ? height : lowest,
            undefined,
        );
        const keyHeight = nearest === undefined ? undefined : options.descendantKeyHeight?.(nearest) ?? nearest;
        return {
            sequenceNumber: STORE_SEQUENCE,
            results: keyHeight === undefined
                ? []
                : [{ key: concat(new Uint8Array([5]), u64(keyHeight)), value: new Uint8Array([1]) }],
        };
    });
    t.mock.method(StoreClient.prototype, 'getMany', async (
        keys: Uint8Array[],
        _batchSize?: number,
        _onChunk?: unknown,
        floor?: bigint,
    ): Promise<GetManyResultItem[]> => {
        recorded.headerReads.push({ count: keys.length, floor });
        return keys.map((key) => {
            assert.equal(key[0], 1);
            const digest = key.slice(1);
            return { key, value: options.header ? options.header(digest) : headers.get(toHex(digest)) };
        });
    });
    t.mock.method(SqlClient.prototype, 'query', async (
        sql: string,
        floor?: bigint,
        callOptions: CallOptions = {},
    ): Promise<DecodedQueryResult> => {
        const range = /FROM block_meta WHERE height >= (\d+) AND height < (\d+)/.exec(sql);
        if (!range) return options.sql!(sql);
        recorded.hintQueries.push({ sql, floor });
        await options.sqlSignal?.(callOptions.signal);
        const rows: Record<string, unknown>[] = [];
        for (let height = BigInt(range[1]!); height < BigInt(range[2]!); height++) {
            const digests = options.hints ? options.hints(height) : [blocks.get(height)!.digest];
            for (const digest of digests) rows.push({ height, digest });
        }
        return { sequenceNumber: FLOOR, table: testTable(rows) };
    });
    return recorded;
}

async function blockChain(bottom: bigint, top: bigint): Promise<Map<bigint, ChainBlock>> {
    const blocks = new Map<bigint, ChainBlock>();
    let parent: Uint8Array = new Uint8Array(32);
    for (let height = bottom; height <= top; height++) {
        const block = await chainBlock(height, chainHeader(height, parent));
        blocks.set(height, block);
        parent = block.digest;
    }
    return blocks;
}

async function replaceBlock(blocks: Map<bigint, ChainBlock>, height: bigint, header: Uint8Array) {
    blocks.set(height, await chainBlock(height, header));
}

async function chainBlock(height: bigint, header: Uint8Array): Promise<ChainBlock> {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(header)));
    return { height, view: chainView(height), digest, header };
}

// Each height gets distinct roots and a view below the one-byte varint limit.
function chainHeader(height: bigint, parent: Uint8Array): Uint8Array {
    return concat(
        new Uint8Array([0, Number(chainView(height))]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), parent, u64(height), u64(0n),
        chainStateRoot(height), u64(1n), u64(10n),
        chainTransactionsRoot(height), u64(2n), u64(8n),
    );
}

function chainView(height: bigint): bigint {
    return 10n + height % 100n;
}

function chainStateRoot(height: bigint): Uint8Array {
    return new Uint8Array(32).fill(Number(height % 128n));
}

function chainTransactionsRoot(height: bigint): Uint8Array {
    return new Uint8Array(32).fill(128 + Number(height % 128n));
}

function chainCertificate(block: ChainBlock): VerifiedSimplexCertificate {
    const payload = concat(block.digest, new Uint8Array(68));
    return {
        scheme: 'bls12381-threshold-standard-min-sig',
        epoch: 0n,
        view: block.view,
        parent: block.view - 1n,
        payload,
        certificate: new Uint8Array(),
        header: concat(payload, block.header),
    };
}

function bytesEqualTest(left: Uint8Array, right: Uint8Array): boolean {
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
