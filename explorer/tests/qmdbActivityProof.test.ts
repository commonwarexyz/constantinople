import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { fromBinary, toJsonString } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { QmdbOperationLogClient } from '@exowarexyz/qmdb';
import { fromHex } from '../src/codec.ts';
import {
    fetchAndVerifyTransactionRowProofs,
    type AccountTransactionRow,
    type LatestProofTarget,
} from '../src/qmdb.ts';
import {
    accountRetryReason,
    isRetryableAccountProofError,
    retryAccountWork,
} from '../src/proofRetry.ts';

type AppendManyArguments = Parameters<QmdbOperationLogClient['getFixedKeylessAppendMany']>;

const target: LatestProofTarget = {
    height: 7n,
    view: 9n,
    sequenceNumber: 41n,
    blockDigest: new Uint8Array(32),
    stateRoot: new Uint8Array(32).fill(0x51),
    stateStart: 1n,
    stateTip: 10n,
    transactionsRoot: new Uint8Array(32).fill(0x52),
    transactionsStart: 2n,
    transactionsTip: 2000n,
};

function row(location: bigint, digest = '33'.repeat(32)): AccountTransactionRow {
    return {
        digest, direction: 'sent', counterparty: '44'.repeat(32),
        value: 1n, nonce: 2n, height: target.height, blockIndex: 0, location,
    };
}

function verify(rows: readonly AccountTransactionRow[], signal?: AbortSignal) {
    return fetchAndVerifyTransactionRowProofs({ qmdbUrl: 'http://qmdb/', rows, target, signal });
}

test('one batch binds the certified root, tip, floor, signal and every sorted digest', async (t) => {
    const controller = new AbortController();
    const rows = [row(9n, '99'.repeat(32)), row(3n), row(9n, '99'.repeat(32))];
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async (
        ...[request, root, expected, options]: AppendManyArguments
    ) => {
        assert.deepEqual(request, { tip: 1999n, minSequenceNumber: 41n });
        assert.deepEqual(root, target.transactionsRoot);
        assert.equal(options?.signal, controller.signal);
        assert.deepEqual(expected, [
            { location: 3n, value: new Uint8Array(32).fill(0x33) },
            { location: 9n, value: new Uint8Array(32).fill(0x99) },
        ]);
        return { root: target.transactionsRoot, operations: [], proofSizeBytes: 123 };
    });

    const proofs = await verify(rows, controller.signal);

    assert.equal(request.mock.callCount(), 1);
    assert.deepEqual(proofs, rows.map(({ location }) => ({
        location, tip: 1999n, height: 7n, view: 9n, proofSizeBytes: 123,
    })));
});

test('duplicate locations with conflicting digests reject the page before requesting a proof', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany');
    await assert.rejects(verify([row(3n), row(3n, '44'.repeat(32))]), (error: unknown) => {
        assert.match(String(error), /conflicting transaction digests at location 3/);
        assert.equal(isRetryableAccountProofError(error), false);
        return true;
    });
    assert.equal(request.mock.callCount(), 0);
});

test('one uncovered location keeps the entire page unverified and retryable', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany');
    await assert.rejects(verify([row(3n), row(target.transactionsTip)]), (error: unknown) => {
        assert.match(String(error), /transaction location 2000 is not yet covered/);
        assert.equal(accountRetryReason(error), 'waiting for indexer');
        return true;
    });
    assert.equal(request.mock.callCount(), 0);
});

test('empty pages need no proof', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany');
    assert.deepEqual(await verify([]), []);
    assert.equal(request.mock.callCount(), 0);
});

test('the 1024-location cap applies after deduplication', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async (
        ...[_request, _root, expected]: AppendManyArguments
    ) => {
        assert.equal(expected.length, 1024);
        return { root: target.transactionsRoot, operations: [], proofSizeBytes: 123 };
    });
    const rows = Array.from({ length: 1024 }, (_, index) => row(BigInt(index)));
    const proofs = await verify([...rows, rows[0]!]);
    assert.equal(proofs.length, 1025);
    assert.equal(request.mock.callCount(), 1);

    await assert.rejects(verify([...rows, row(1024n)]), (error: unknown) => {
        assert.match(String(error), /exceeds 1024 proof locations/);
        assert.equal(isRetryableAccountProofError(error), false);
        return true;
    });
    assert.equal(request.mock.callCount(), 1);
});

test('malformed row digests fail before any request', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany');
    await assert.rejects(verify([row(3n, '33')]), /transaction digest must be 32 bytes/);
    assert.equal(request.mock.callCount(), 0);
});

test('an already aborted page never requests a proof', async (t) => {
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany');
    const controller = new AbortController();
    controller.abort(new Error('page changed'));
    await assert.rejects(verify([row(3n)], controller.signal), /page changed/);
    assert.equal(request.mock.callCount(), 0);
});

test('cancellation reaches a pending batch request', async (t) => {
    let started!: () => void;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async (
        ...[_request, _root, _expected, options]: AppendManyArguments
    ) => new Promise<never>((_resolve, reject) => {
        options?.signal?.addEventListener('abort', () => reject(options.signal?.reason), { once: true });
        started();
    }));
    const controller = new AbortController();
    const proof = verify([row(3n)], controller.signal);
    await ready;
    controller.abort(new Error('page changed'));
    await assert.rejects(proof, /page changed/);
});

test('a batch completing after cancellation cannot report verified rows', async (t) => {
    const controller = new AbortController();
    t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async () => {
        controller.abort(new Error('page changed'));
        return { root: target.transactionsRoot, operations: [], proofSizeBytes: 123 };
    });
    await assert.rejects(verify([row(3n)], controller.signal), /page changed/);
});

for (const error of [
    new ConnectError('query node unavailable', Code.Unavailable),
    new ConnectError('minimum consistency token is not yet visible', Code.Aborted),
    new ConnectError('requested proof tip is not published yet', Code.OutOfRange),
]) {
    test(`batch retries preserve all rows and the target: ${error.message}`, async (t) => {
        let attempts = 0;
        const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async () => {
            if (++attempts === 1) throw error;
            return { root: target.transactionsRoot, operations: [], proofSizeBytes: 123 };
        });
        let retries = 0;
        const controller = new AbortController();
        const proofs = await retryAccountWork(
            () => verify([row(3n), row(9n)], controller.signal),
            controller.signal,
            isRetryableAccountProofError,
            { wait: async () => true, onRetry: () => { retries++; } },
        );
        assert.equal(retries, 1);
        assert.equal(request.mock.callCount(), 2);
        assert.equal(proofs.length, 2);
        assert.deepEqual(request.mock.calls[0]?.arguments, request.mock.calls[1]?.arguments);
    });
}

test('verification failure is terminal for the entire batch', async (t) => {
    const error = new Error('operation at location 9 does not match expected value');
    const request = t.mock.method(QmdbOperationLogClient.prototype, 'getFixedKeylessAppendMany', async () => {
        throw error;
    });
    let retries = 0;
    const controller = new AbortController();
    await assert.rejects(retryAccountWork(
        () => verify([row(3n), row(9n)], controller.signal),
        controller.signal,
        isRetryableAccountProofError,
        { wait: async () => { retries++; return true; } },
    ), error);
    assert.equal(retries, 0);
    assert.equal(request.mock.callCount(), 1);
});

test('batch protocol and verification errors retain terminal retry classification', () => {
    for (const error of [
        new Error('qmdb getOperations response missing proof'),
        new Error('historical ops root did not match expected root'),
        new ConnectError('locations must be strictly ascending', Code.InvalidArgument),
        new ConnectError('method is not implemented', Code.Unimplemented),
    ]) {
        assert.equal(isRetryableAccountProofError(error), false, error.message);
    }
});

test('the WASM verifier authenticates every digest in the batch', async (t) => {
    const fixture = JSON.parse(await readFile(new URL(
        '../../tests/fixtures/transactionActivityProof.json', import.meta.url,
    ), 'utf8')) as {
        root: string;
        tip: string;
        proof: string;
        operations: { location: string; digest: string }[];
    };
    const packageUrl = import.meta.resolve('@exowarexyz/qmdb');
    const wasm = await import(new URL('./generated/wasm/exoware_qmdb_wasm.js', packageUrl).href);
    wasm.initSync({ module: await readFile(new URL(
        './generated/wasm/exoware_qmdb_wasm_bg.wasm', packageUrl,
    )) });
    const { HistoricalMultiProofSchema } = await import(new URL(
        './generated/proto/qmdb/v1/proof_pb.js', packageUrl,
    ).href);
    const response = JSON.stringify({ proof: JSON.parse(toJsonString(
        HistoricalMultiProofSchema,
        fromBinary(HistoricalMultiProofSchema, fromHex(fixture.proof)),
    )) });
    const request = t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        const sent = new Request(input, init);
        assert.equal(sent.url, 'http://qmdb/transactions/qmdb.v1.OperationLogService/GetOperations');
        return new Response(response, {
            headers: { 'content-type': 'application/json' },
        });
    });
    const proofTarget = {
        ...target,
        transactionsRoot: fromHex(fixture.root),
        transactionsTip: BigInt(fixture.tip) + 1n,
    };
    const rows = fixture.operations.map(({ location, digest }) => row(BigInt(location), digest)).reverse();
    const prove = (rows: readonly AccountTransactionRow[], selectedTarget = proofTarget) =>
        fetchAndVerifyTransactionRowProofs({ qmdbUrl: 'http://qmdb', rows, target: selectedTarget });

    const proofs = await prove(rows);
    assert.deepEqual(proofs.map(({ location }) => location), rows.map(({ location }) => location));
    assert.ok(proofs.every(({ proofSizeBytes }) => proofSizeBytes === fixture.proof.length / 2));

    const wrong = rows.map((entry, index) => index === 0 ? { ...entry, digest: 'ff'.repeat(32) } : entry);
    await assert.rejects(prove(wrong), (error: unknown) => {
        assert.match(String(error), /does not match expected value/);
        assert.equal(isRetryableAccountProofError(error), false);
        return true;
    });
    await assert.rejects(prove(rows, { ...proofTarget, transactionsRoot: new Uint8Array(32) }));
    await assert.rejects(prove(rows, { ...proofTarget, transactionsTip: proofTarget.transactionsTip + 1n }));
    await assert.rejects(prove(rows.map((entry, index) => index === 0 ? { ...entry, location: 2n } : entry)));
    assert.equal(request.mock.callCount(), 5);
});
