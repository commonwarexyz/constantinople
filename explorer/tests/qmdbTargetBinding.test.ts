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
import { toArrayBuffer, toHex } from '../src/codec.ts';
import { isRetryableAccountProofError, retryAccountWork } from '../src/proofRetry.ts';
import {
    fetchAccountTransactionsPage,
    fetchAndVerifyAccountProof,
    fetchAndVerifyTransactionRowProof,
    fetchAndVerifyTransactionProof,
    fetchLatestProofTarget,
    prefetchFinalizedCertificate,
    fetchAccountProofMetadata,
    fetchTransactionRowMetadata,
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
    const controller = new AbortController();
    const target = await retryAccountWork(
        () => fetchLatestProofTarget({
            storeUrl: `http://store/${storeId}`,
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
        async () => { available = true; },
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
        reads.push('metadata');
        assert.match(sql, /FROM tx_meta/);
        assert.equal(minSequenceNumber, FLOOR);
        metadataStarted();
        return queryResult({ qmdb_location: LOCATION, body });
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

    assert.equal(proof.height, HEIGHT);
    assert.deepEqual(reads.slice(0, 2).sort(), ['certificate', 'metadata']);
    assert.deepEqual(reads.slice(2), ['verified', 'proof']);
});

for (const containingHeight of [1n, HEIGHT]) {
    test(`transaction proof discovers height ${containingHeight} without a reported height`, async (t) => {
        const body = new Uint8Array(82).fill(0x33);
        const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
        const latest = await finalizedCertificate(HEIGHT + 1n);
        const containing = await finalizedCertificate(containingHeight);
        const heights: string[] = [];
        t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: string) => {
            heights.push(height);
            return height === containingHeight.toString() ? containing : latest;
        });
        const queries: string[] = [];
        t.mock.method(SqlClient.prototype, 'query', async (sql: string) => {
            queries.push(sql);
            return sql.includes('FROM tx_meta')
                ? queryResult({ qmdb_location: LOCATION, body })
                : containingHeight === 1n
                    ? emptyQueryResult()
                    : queryResult({ height: containingHeight - 1n });
        });
        t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
            request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
        ) => keylessProof(request, root, location, value));
        const options = transactionProofOptions(digest);
        options.publishedTarget.blockDigest = latest.payload.slice(0, 32);

        const proof = await fetchAndVerifyTransactionProof(options);

        assert.equal(proof.height, containingHeight);
        assert.deepEqual(heights, [(HEIGHT + 1n).toString(), containingHeight.toString()]);
        assert.equal(queries.length, 2);
        assert.match(queries[1]!, /FROM block_meta/);
    });
}

test('transaction proof waits for publication without reads when the reported height is ahead', async (t) => {
    const query = t.mock.method(SqlClient.prototype, 'query', async () => { throw new Error('unexpected query'); });
    const certificate = t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => { throw new Error('unexpected certificate'); });

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions('11'.repeat(32)),
        finalizedHeight: HEIGHT + 2n,
    }), /not yet covered by a provable finalization/);

    assert.equal(query.mock.callCount(), 0);
    assert.equal(certificate.mock.callCount(), 0);
});

test('a reported height cannot place a transaction outside its certified range', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({ qmdb_location: 8n, body }));
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
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({ qmdb_location: LOCATION, body }));

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT + 1n,
    }), /provable target digest does not match/);
});

test('reported-height proofs reject tampered transaction metadata', async (t) => {
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({
        qmdb_location: LOCATION,
        body: new Uint8Array(82).fill(0x33),
    }));

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions('11'.repeat(32)),
        finalizedHeight: HEIGHT,
    }), /body does not match transaction digest/);
});

test('reported-height proofs reject a QMDB response below the publication floor', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const certificate = await finalizedCertificate(HEIGHT);
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async () => certificate);
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({ qmdb_location: LOCATION, body }));
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => ({ ...keylessProof(request, root, location, value), sequenceNumber: FLOOR - 1n }));

    await assert.rejects(fetchAndVerifyTransactionProof({
        ...transactionProofOptions(digest),
        finalizedHeight: HEIGHT,
    }), /evaluated before the requested Store sequence/);
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
    t.mock.method(SqlClient.prototype, 'query', async (_sql: string, floor?: bigint) => {
        assert.equal(floor, FLOOR);
        return queryResult({ qmdb_location: LOCATION, body });
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

async function finalizedCertificate(height: bigint): Promise<VerifiedSimplexCertificate> {
    const target = latestTarget();
    const header = concat(
        new Uint8Array([0, 9]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), new Uint8Array(32), u64(height), u64(0n),
        target.stateRoot, u64(target.stateStart), u64(target.stateTip),
        target.transactionsRoot, u64(target.transactionsStart), u64(target.transactionsTip),
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

test('account proof retains the publication floor for SQL and QMDB', async (t) => {
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
            return unorderedProof(
                request,
                expectedRoot as Uint8Array,
                expectedLocation,
                expectedKey as Uint8Array,
            );
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

test('transaction row proof retains the publication floor for SQL and QMDB', async (t) => {
    const target = latestTarget();
    const body = new Uint8Array(82).fill(0x33);
    const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', toArrayBuffer(body)),
    );
    const sqlFloors: Array<bigint | undefined> = [];
    t.mock.method(SqlClient.prototype, 'query', async (_sql: string, minSequenceNumber?: bigint) => {
        sqlFloors.push(minSequenceNumber);
        return queryResult({ qmdb_location: LOCATION, body });
    });

    const qmdbFloors: Array<bigint | undefined> = [];
    t.mock.method(
        QmdbOperationLogClient.prototype,
        'getFixedKeylessAppend',
        async (
            request: OperationRangeRequest,
            expectedRoot: BytesLike,
            expectedLocation: bigint,
            expectedValue: BytesLike,
        ) => {
            qmdbFloors.push(request.minSequenceNumber);
            return keylessProof(
                request,
                expectedRoot as Uint8Array,
                expectedLocation,
                expectedValue as Uint8Array,
            );
        },
    );

    await fetchAndVerifyTransactionRowProof({
        qmdbUrl: 'http://qmdb',
        sqlUrl: 'http://sql',
        row: {
            digest: toHex(digest),
            direction: 'sent',
            counterparty: '44'.repeat(32),
            value: 1n,
            nonce: 2n,
            height: HEIGHT,
            blockIndex: 0,
        },
        target,
    });

    assert.deepEqual(sqlFloors, [FLOOR]);
    assert.deepEqual(qmdbFloors, [FLOOR]);
});

test('batched transaction metadata authenticates bodies and skips row SQL reads', async (t) => {
    const bodies = [new Uint8Array(82).fill(0x33), new Uint8Array(82).fill(0x44)];
    const digests = await Promise.all(bodies.map(async (body) => new Uint8Array(
        await crypto.subtle.digest('SHA-256', toArrayBuffer(body)),
    )));
    const rows = digests.map((digest) => activityRow(toHex(digest)));
    const query = t.mock.method(SqlClient.prototype, 'query', async (sql: string, floor?: bigint) => {
        assert.match(sql, /WHERE tx_digest IN \(X'[a-f0-9]+', X'[a-f0-9]+'\)/);
        assert.equal(floor, FLOOR);
        return {
            sequenceNumber: FLOOR,
            table: testTable(bodies.map((body, index) => ({
                tx_digest: digests[index], qmdb_location: LOCATION + BigInt(index), body,
            }))),
        };
    });
    const metadata = await fetchTransactionRowMetadata({ sqlUrl: 'http://sql', rows, minSequenceNumber: FLOOR });
    const proof = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => {
        assert.equal(request.minSequenceNumber, FLOOR);
        return keylessProof(request, root, location, value);
    });
    await Promise.all(rows.map((row) => fetchAndVerifyTransactionRowProof({
        qmdbUrl: 'http://qmdb', sqlUrl: 'http://sql', row, target: latestTarget(), metadata: metadata.get(row.digest),
    })));
    assert.equal(query.mock.callCount(), 1);
    assert.equal(proof.mock.callCount(), 2);
});

test('batched transaction metadata rejects a body with a different digest', async (t) => {
    t.mock.method(SqlClient.prototype, 'query', async () => queryResult({
        tx_digest: new Uint8Array(32).fill(0x11), qmdb_location: LOCATION, body: new Uint8Array(82),
    }));
    await assert.rejects(fetchTransactionRowMetadata({
        sqlUrl: 'http://sql', rows: [activityRow('11'.repeat(32))], minSequenceNumber: FLOOR,
    }), /body does not match transaction digest/);
});

test('missing batch rows retain the retryable transaction index error', async (t) => {
    t.mock.method(SqlClient.prototype, 'query', async () => emptyQueryResult());
    await assert.rejects(fetchTransactionRowMetadata({
        sqlUrl: 'http://sql', rows: [activityRow('11'.repeat(32))], minSequenceNumber: FLOOR,
    }), /missing from raw transaction index/);
});

test('an empty activity page does not request transaction metadata', async (t) => {
    const query = t.mock.method(SqlClient.prototype, 'query', async () => emptyQueryResult());
    const metadata = await fetchTransactionRowMetadata({ sqlUrl: 'http://sql', rows: [], minSequenceNumber: FLOOR });
    assert.equal(metadata.size, 0);
    assert.equal(query.mock.callCount(), 0);
});

test('row metadata fetched at an older sequence is refreshed at the covering barrier', async (t) => {
    const body = new Uint8Array(82).fill(0x33);
    const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(body))));
    const query = t.mock.method(SqlClient.prototype, 'query', async (_sql: string, floor?: bigint) => {
        assert.equal(floor, FLOOR);
        return queryResult({ qmdb_location: LOCATION, body });
    });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppend', async (
        request: OperationRangeRequest, root: Uint8Array, location: bigint, value: Uint8Array,
    ) => keylessProof(request, root, location, value));
    const proof = await fetchAndVerifyTransactionRowProof({
        qmdbUrl: 'http://qmdb', sqlUrl: 'http://sql', row: activityRow(digest), target: latestTarget(),
        metadata: { digest, sqlUrl: 'http://sql', sequenceNumber: FLOOR - 1n, location: LOCATION + 1n },
    });
    assert.equal(query.mock.callCount(), 1);
    assert.equal(proof.location, LOCATION);
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
            account: '22'.repeat(32), sqlUrl: 'http://sql', sequenceNumber: FLOOR - 1n,
            balance: 9n, nonce: 2n, nonceBitmap: 3n, location: LOCATION,
        },
    });
    assert.equal(queries.length, 1);
    assert.match(queries[0]!, /qmdb_location < 10/);
});

function activityRow(digest: string) {
    return {
        digest, direction: 'sent' as const, counterparty: '44'.repeat(32),
        value: 1n, nonce: 2n, height: HEIGHT, blockIndex: 0,
    };
}

function queryResult(values: Record<string, unknown>): DecodedQueryResult {
    return {
        sequenceNumber: FLOOR,
        table: testTable([values]),
    };
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
