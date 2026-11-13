import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { create } from '@bufbuild/protobuf';
import { BinaryWriter, WireType } from '@bufbuild/protobuf/wire';
import { Code, ConnectError, type ServiceImpl } from '@connectrpc/connect';
import { initQmdbWasm } from '@exowarexyz/qmdb';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';

import { fromHex, toArrayBuffer, toHex } from '../src/codec.ts';
import {
    ExplorerService, WatchBlocksResponseSchema, type WatchBlocksResponse,
} from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';
import { subscribeBlocks, type VerifiedBlockBatch } from '../src/indexer.ts';
import { createBlockBatchVerifier } from '../src/proofBundle.ts';
import { simplexFinalizationVerifier } from '../src/qmdb.ts';
import { readFixture } from './fixtureSource.ts';
import { explorerFetch } from './rpcTest.ts';

const INDEXER = 'https://indexer.example';
let expectedDigests: string[];
type WatchBlocks = ServiceImpl<typeof ExplorerService>['watchBlocks'];
interface WireBundle { certificate: string; headers: string[]; sequenceNumber: string }
interface PublisherFixture {
    verificationMaterial: string;
    directBlock: WireBundle;
    emptyBlock: WireBundle;
    historicalBlock: WireBundle;
}
interface BlockFeedFixture {
    verificationMaterial: string;
    afterZero: WireBundle;
    bootstrap: WireBundle;
    resumed: WireBundle;
    first: WireBundle;
    emptyFirst: WireBundle;
    conflictingFirst: WireBundle;
}
let fixture: PublisherFixture;
let feedFixture: BlockFeedFixture;

function options(material = fixture.verificationMaterial) {
    return { simplexVerificationMaterial: material, reconnectDelayMs: 0 };
}

function frame(bundle: WireBundle, extra: Partial<WatchBlocksResponse> = {}): WatchBlocksResponse {
    return create(WatchBlocksResponseSchema, {
        certificate: fromHex(bundle.certificate), headers: bundle.headers.map(fromHex),
        sequenceNumber: BigInt(bundle.sequenceNumber), ...extra,
    });
}

function serve(context: TestContext, watchBlocks: WatchBlocks) {
    return context.mock.method(globalThis, 'fetch', explorerFetch({ watchBlocks }));
}

async function nextBatch(stream: AsyncGenerator<VerifiedBlockBatch, void, void>): Promise<VerifiedBlockBatch> {
    const next = await stream.next();
    assert.equal(next.done, false);
    assert.ok(next.value);
    return next.value;
}

function deferred() {
    let resolve!: () => void;
    const promise = new Promise<void>((done) => { resolve = done; });
    return { promise, resolve };
}

function waitForAbort(signal: AbortSignal): Promise<void> {
    if (signal.aborted) return Promise.resolve();
    return new Promise((resolve) => signal.addEventListener('abort', () => resolve(), { once: true }));
}

function terminalError(error: unknown) {
    assert.ok(error instanceof ConnectError);
    assert.equal(error.code, Code.FailedPrecondition);
    return true;
}

test.before(async () => {
    fixture = await readFixture<PublisherFixture>('proofBundle');
    feedFixture = await readFixture<BlockFeedFixture>('blockFeed');
    await Promise.all([
        initQmdbWasm(toArrayBuffer(await readFile(new URL('./generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.resolve('@exowarexyz/qmdb'))))),
        ensureSimplexWasm({ module_or_path: await readFile(new URL('./generated/wasm/exoware_simplex_wasm_bg.wasm', import.meta.resolve('@exowarexyz/simplex/wasm'))) }),
    ]);
    const certificateBytes = fromHex(fixture.historicalBlock.certificate);
    const certificate = await (await simplexFinalizationVerifier(fixture.verificationMaterial)).verifyFinalization(certificateBytes, {
        kind: 'finalization', index: 'latest', height: 0n, key: new Uint8Array(), value: certificateBytes, source: 'get',
    });
    assert.ok(certificate);
    const headerBytes = [...fixture.historicalBlock.headers].reverse().map(fromHex);
    headerBytes.push(certificate.header.subarray(certificate.payload.length));
    expectedDigests = headerBytes.map((header) => createHash('sha256').update(header).digest('hex'));
    assert.equal(expectedDigests.length, 3);
    assert.equal(expectedDigests[2], toHex(certificate.payload.subarray(0, 32)));
});

test('generated WatchBlocks authenticates the latest block using only its parent', async (context) => {
    let requestSignal: AbortSignal | undefined;
    const handler = explorerFetch({ async *watchBlocks(request) {
        assert.equal(request.after, undefined);
        yield frame(fixture.emptyBlock, { sequenceNumber: (1n << 64n) - 1n });
    } });
    context.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(String(input), `${INDEXER}/constantinople.explorer.v1.ExplorerService/WatchBlocks`);
        assert.equal(init?.method, 'POST');
        assert.equal(new Headers(init?.headers).get('Content-Type'), 'application/connect+proto');
        assert.equal(init?.redirect, 'error');
        requestSignal = init?.signal ?? undefined;
        return handler(input, init);
    });
    const stream = subscribeBlocks(`${INDEXER}/`, options());
    const before = Date.now();
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => ({ ...row, digest: toHex(row.digest) })), [{
        height: 3n, digest: expectedDigests[2], txCount: 0, timestampMs: 3n,
        finality: { certifiedHeight: 3n, certificateView: 3n },
    }]);
    assert.equal(batch.target.height, 3n);
    assert.equal(toHex(batch.target.blockDigest), expectedDigests[2]);
    assert.equal('sequenceNumber' in batch.target, false);
    assert.equal(batch.sequenceNumberHint, (1n << 64n) - 1n);
    assert.ok(batch.receivedAt >= before && batch.receivedAt <= Date.now());
    await stream.return();
    assert.equal(requestSignal?.aborted, true);
});

test('explicit genesis catch-up publishes one ascending batch with counts from parent ends', async (context) => {
    const fetch = serve(context, async function* (request) {
        assert.equal(request.after, 0n);
        yield frame(fixture.historicalBlock);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(), after: 0n });
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => row.height), [1n, 2n, 3n]);
    assert.deepEqual(batch.blocks.map((row) => toHex(row.digest)), expectedDigests);
    assert.deepEqual(batch.blocks.map((row) => row.txCount), [3, 55, 0]);
    assert.deepEqual(batch.blocks.map((row) => row.timestampMs), [1n, 2n, 3n]);
    assert.ok(batch.blocks.every((row) => row.finality.certifiedHeight === 3n && row.finality.certificateView === 3n));
    assert.equal(fetch.mock.callCount(), 1);
    await stream.return();
});

test('block one uses the canonical genesis tip without requesting a genesis header', async (context) => {
    serve(context, async function* (request) {
        assert.equal(request.after, 0n);
        yield frame(fixture.directBlock);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(), after: 0n });
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => [row.height, row.txCount]), [[1n, 3]]);
    await stream.return();
});

test('real equal-timestamp blocks preserve counts as the transaction floor advances', async (context) => {
    serve(context, async function* (request) {
        assert.equal(request.after, 0n);
        yield frame(feedFixture.afterZero);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(feedFixture.verificationMaterial), after: 0n });
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => row.height), [1n, 2n, 3n, 4n]);
    assert.deepEqual(batch.blocks.map((row) => row.txCount), [3, 0, 2, 1]);
    assert.deepEqual(batch.blocks.map((row) => row.timestampMs), [0n, 0n, 1n, 1n]);
    assert.ok(batch.blocks.every((row) => row.finality.certifiedHeight === 4n));
    await stream.return();
});

test('moving-floor bootstrap emits only the certified head and its own transaction count', async (context) => {
    serve(context, async function* (request) {
        assert.equal(request.after, undefined);
        yield frame(feedFixture.bootstrap);
    });
    const stream = subscribeBlocks(INDEXER, options(feedFixture.verificationMaterial));
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => [row.height, row.txCount, row.timestampMs]), [[4n, 1, 1n]]);
    await stream.return();
});

test('an empty certified block one derives zero transactions from the genesis tip', async (context) => {
    serve(context, async function* (request) {
        assert.equal(request.after, 0n);
        yield frame(feedFixture.emptyFirst);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(feedFixture.verificationMaterial), after: 0n });
    const batch = await nextBatch(stream);
    assert.deepEqual(batch.blocks.map((row) => [row.height, row.txCount, row.timestampMs]), [[1n, 0, 0n]]);
    await stream.return();
});

test('reconnect accepts equal timestamps while bridging the first moving-floor block', async (context) => {
    const cursors: Array<bigint | undefined> = [];
    serve(context, async function* (request) {
        cursors.push(request.after);
        yield frame(cursors.length === 1 ? feedFixture.first : feedFixture.resumed);
    });
    const stream = subscribeBlocks(INDEXER, options(feedFixture.verificationMaterial));
    const first = await nextBatch(stream);
    const resumed = await nextBatch(stream);
    assert.deepEqual(first.blocks.map((row) => [row.height, row.txCount]), [[1n, 3]]);
    assert.deepEqual(resumed.blocks.map((row) => [row.height, row.txCount]), [[2n, 0], [3n, 2], [4n, 1]]);
    assert.deepEqual(resumed.blocks.map((row) => row.timestampMs), [0n, 1n, 1n]);
    assert.deepEqual(cursors, [undefined, 1n]);
    await stream.return();
});

test('a valid conflicting certificate at the accepted height cannot replace the cursor', async () => {
    const verifier = createBlockBatchVerifier(feedFixture.verificationMaterial);
    const first = await verifier.verify(frame(feedFixture.first));
    assert.ok(first);
    await assert.rejects(verifier.verify(frame(feedFixture.conflictingFirst)), /conflicts with its accepted head/);
    assert.equal(verifier.after, 1n);
    assert.equal(await verifier.verify(frame(feedFixture.first)), null);
    const resumed = await verifier.verify(frame(feedFixture.resumed));
    assert.ok(resumed);
    assert.deepEqual(resumed.blocks.map((row) => row.height), [2n, 3n, 4n]);
    assert.equal(verifier.after, 4n);
});

test('a valid advancing certificate cannot bridge a different accepted block-one digest', async () => {
    const verifier = createBlockBatchVerifier(feedFixture.verificationMaterial);
    await verifier.verify(frame(feedFixture.conflictingFirst));
    await assert.rejects(verifier.verify(frame(feedFixture.resumed)), /ancestry does not match its accepted head/);
    assert.equal(verifier.after, 1n);
    assert.equal(await verifier.verify(frame(feedFixture.conflictingFirst)), null);
    await assert.rejects(verifier.verify(frame(feedFixture.first)), /conflicts with its accepted head/);
    assert.equal(verifier.after, 1n);
});

test('reconnect bridges the accepted digest independently of the shared certificate memo', async (context) => {
    const cursors: Array<bigint | undefined> = [];
    const errors: string[] = [];
    let reconnects = 0;
    serve(context, async function* (request) {
        cursors.push(request.after);
        if (cursors.length === 1) {
            yield frame(fixture.directBlock);
            throw new ConnectError('upstream unavailable', Code.Unavailable);
        }
        if (cursors.length === 2) {
            yield frame(fixture.historicalBlock);
            return;
        }
        yield frame(fixture.emptyBlock);
        yield frame(fixture.directBlock);
        throw new ConnectError('end of fixture', Code.FailedPrecondition);
    });
    const stream = subscribeBlocks(INDEXER, {
        ...options(), onError: (error) => errors.push(error), onReconnect: () => { reconnects++; },
    });
    const first = await nextBatch(stream);
    assert.deepEqual(first.blocks.map((row) => row.height), [1n]);
    await createBlockBatchVerifier(fixture.verificationMaterial).verify(frame(fixture.emptyBlock));
    const second = await nextBatch(stream);
    assert.deepEqual(second.blocks.map((row) => [row.height, row.txCount]), [[2n, 55], [3n, 0]]);
    await createBlockBatchVerifier(fixture.verificationMaterial).verify(frame(fixture.directBlock));
    await assert.rejects(stream.next(), terminalError);
    assert.deepEqual(cursors, [undefined, 1n, 3n]);
    assert.equal(reconnects, 3);
    assert.deepEqual(errors.slice(0, 2), ['[unavailable] upstream unavailable', '[unavailable] block feed closed']);
});

for (const mutation of ['corrupt oldest', 'truncate oldest', 'missing overlap', 'missing middle', 'reverse ancestry', 'corrupt certificate'] as const) {
    test(`invalid final evidence publishes no partial batch: ${mutation}`, async (context) => {
        const cursors: Array<bigint | undefined> = [];
        const message = frame(fixture.historicalBlock);
        if (mutation === 'corrupt oldest') message.headers[1]![message.headers[1]!.length - 1] ^= 1;
        if (mutation === 'truncate oldest') message.headers[1] = message.headers[1]!.slice(0, -1);
        if (mutation === 'missing overlap') message.headers.pop();
        if (mutation === 'missing middle') message.headers.shift();
        if (mutation === 'reverse ancestry') message.headers.reverse();
        if (mutation === 'corrupt certificate') message.certificate[0] ^= 1;
        const fetch = serve(context, async function* (request) {
            cursors.push(request.after);
            if (cursors.length === 1) yield frame(fixture.directBlock);
            else yield message;
        });
        const stream = subscribeBlocks(INDEXER, options());
        const accepted = await nextBatch(stream);
        const snapshot = structuredClone(accepted);
        await assert.rejects(stream.next());
        assert.deepEqual(accepted, snapshot);
        assert.deepEqual(cursors, [undefined, 1n]);
        assert.equal(fetch.mock.callCount(), 2);
        assert.deepEqual(await stream.next(), { done: true, value: undefined });
    });
}

test('rejected ancestry preserves the verifier cursor until a complete batch succeeds', async () => {
    const verifier = createBlockBatchVerifier(fixture.verificationMaterial);
    assert.equal(verifier.after, undefined);
    await verifier.verify(frame(fixture.directBlock));
    assert.equal(verifier.after, 1n);
    const bad = frame(fixture.historicalBlock);
    bad.headers[1]![bad.headers[1]!.length - 1] ^= 1;
    await assert.rejects(verifier.verify(bad), /header|digest/i);
    assert.equal(verifier.after, 1n);
    const batch = await verifier.verify(frame(fixture.historicalBlock));
    assert.ok(batch);
    assert.deepEqual(batch.blocks.map((row) => row.height), [2n, 3n]);
    assert.equal(verifier.after, 3n);
    assert.equal(await verifier.verify(frame(fixture.emptyBlock)), null);
    assert.equal(await verifier.verify(frame(fixture.directBlock)), null);
    assert.equal(verifier.after, 3n);
});

test('canceling the last ancestor hash leaves the same verifier able to resume', { timeout: 5_000 }, async (context) => {
    const verifier = createBlockBatchVerifier(fixture.verificationMaterial);
    await verifier.verify(frame(fixture.directBlock));
    const controller = new AbortController();
    const hashing = deferred();
    const release = deferred();
    context.after(() => release.resolve());
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    const spy = context.mock.method(crypto.subtle, 'digest', async (...[algorithm, bytes]: Parameters<SubtleCrypto['digest']>) => {
        if (toHex(new Uint8Array(bytes as ArrayBuffer)) === fixture.historicalBlock.headers[1]) {
            hashing.resolve();
            await release.promise;
        }
        return digest(algorithm, bytes);
    });
    const pending = verifier.verify(frame(fixture.historicalBlock), controller.signal);
    const rejected = assert.rejects(pending);
    await hashing.promise;
    controller.abort();
    release.resolve();
    await rejected;
    assert.equal(verifier.after, 1n);
    spy.mock.restore();
    const accepted = await verifier.verify(frame(fixture.historicalBlock));
    assert.ok(accepted);
    assert.deepEqual(accepted.blocks.map((row) => row.height), [2n, 3n]);
    assert.equal(verifier.after, 3n);
});

test('abort while hashing the final overlap header publishes no new rows', { timeout: 5_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    const hashing = deferred();
    const release = deferred();
    context.after(() => release.resolve());
    const cursors: Array<bigint | undefined> = [];
    const errors: string[] = [];
    serve(context, async function* (request) {
        cursors.push(request.after);
        yield frame(cursors.length === 1 ? fixture.directBlock : fixture.historicalBlock);
    });
    const stream = subscribeBlocks(INDEXER, {
        ...options(), signal: controller.signal, onError: (error) => errors.push(error),
    });
    const accepted = await nextBatch(stream);
    const snapshot = structuredClone(accepted);
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    context.mock.method(crypto.subtle, 'digest', async (...[algorithm, bytes]: Parameters<SubtleCrypto['digest']>) => {
        if (toHex(new Uint8Array(bytes as ArrayBuffer)) === fixture.historicalBlock.headers[1]) {
            hashing.resolve();
            await release.promise;
        }
        return digest(algorithm, bytes);
    });
    const pending = stream.next();
    await hashing.promise;
    controller.abort();
    release.resolve();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.deepEqual(accepted, snapshot);
    assert.deepEqual(cursors, [undefined, 1n]);
    assert.deepEqual(errors, ['[unavailable] block feed closed']);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('mutating published buffers cannot change the private resume digest or cached target', async (context) => {
    const cursors: Array<bigint | undefined> = [];
    serve(context, async function* (request) {
        cursors.push(request.after);
        yield frame(request.after === 1n ? fixture.historicalBlock
            : cursors.length === 1 ? fixture.directBlock : fixture.emptyBlock);
    });
    const settings = options();
    const stream = subscribeBlocks(INDEXER, settings);
    const first = await nextBatch(stream);
    const expectedTarget = structuredClone(first.target);
    settings.simplexVerificationMaterial = '00';
    first.blocks[0]!.digest.fill(0);
    for (const value of Object.values(first.target)) if (value instanceof Uint8Array) value.fill(0);
    const cached = await createBlockBatchVerifier(fixture.verificationMaterial).verify(frame(fixture.directBlock));
    assert.ok(cached);
    for (const key of ['blockDigest', 'stateRoot', 'transactionsRoot'] as const) {
        assert.deepEqual(cached.target[key], expectedTarget[key]);
    }
    const next = await nextBatch(stream);
    assert.deepEqual(next.blocks.map((row) => toHex(row.digest)), expectedDigests.slice(1));
    assert.equal(toHex(next.target.blockDigest), expectedDigests[2]);
    assert.deepEqual(cursors, [undefined, 1n]);
    await stream.return();
    const fresh = subscribeBlocks(INDEXER, options());
    assert.equal(toHex((await nextBatch(fresh)).target.blockDigest), expectedDigests[2]);
    await fresh.return();
});

test('a certificate cached under one verification context cannot authenticate another', async (context) => {
    serve(context, async function* () { yield frame(fixture.directBlock); });
    const first = subscribeBlocks(INDEXER, options());
    await nextBatch(first);
    await first.return();
    const foreignMaterial = fromHex(fixture.verificationMaterial);
    foreignMaterial[0] ^= 1;
    await assert.rejects(subscribeBlocks(INDEXER, {
        ...options(), simplexVerificationMaterial: toHex(foreignMaterial),
    }).next());
    const restored = subscribeBlocks(INDEXER, options());
    assert.equal(toHex((await nextBatch(restored)).blocks[0]!.digest), expectedDigests[0]);
    await restored.return();
});

for (const [name, mutate, expected] of [
    ['4097 headers', (message: WatchBlocksResponse) => { message.headers = Array.from({ length: 4097 }, () => new Uint8Array(1)); }, /header|ancestry/i],
    ['513-byte header', (message: WatchBlocksResponse) => { message.headers = [new Uint8Array(513)]; }, /header/i],
    ['16KiB+1 certificate', (message: WatchBlocksResponse) => { message.certificate = new Uint8Array(16 * 1024 + 1); }, /certificate/i],
] as const) {
    test(`feed rejects ${name} before hashing`, async (context) => {
        const message = frame(fixture.emptyBlock);
        mutate(message);
        const digest = context.mock.method(crypto.subtle, 'digest');
        const fetch = serve(context, async function* () { yield message; });
        await assert.rejects(subscribeBlocks(INDEXER, options()).next(), expected);
        assert.equal(digest.mock.callCount(), 0);
        assert.equal(fetch.mock.callCount(), 1);
        await assert.rejects(createBlockBatchVerifier('00').verify(message), expected);
        assert.equal(digest.mock.callCount(), 0);
    });
}

for (const [name, payload, expectedCode, expectedMessage] of [
    ['oversized certificate length', () => new BinaryWriter().tag(5, WireType.LengthDelimited).uint32(16 * 1024 + 1).finish(), Code.ResourceExhausted, /size limit/],
    ['oversized header length', () => new BinaryWriter().tag(6, WireType.LengthDelimited).uint32(513).finish(), Code.ResourceExhausted, /size limit/],
    ['4097 empty headers', () => {
        const writer = new BinaryWriter();
        for (let index = 0; index < 4097; index++) writer.tag(6, WireType.LengthDelimited).uint32(0);
        return writer.finish();
    }, Code.ResourceExhausted, /size limit/],
    ['wrong-wire sequence field', () => {
        const headers = new BinaryWriter();
        for (let index = 0; index < 4097; index++) headers.tag(6, WireType.LengthDelimited).uint32(0);
        return new BinaryWriter().tag(4, WireType.LengthDelimited).bytes(headers.finish()).finish();
    }, Code.InvalidArgument, /sequence encoding/],
] as const) {
    test(`raw Connect ${name} is rejected before generated decoding`, async (context) => {
        const data = payload();
        const envelope = new Uint8Array(5 + data.length);
        new DataView(envelope.buffer).setUint32(1, data.length);
        envelope.set(data, 5);
        const digest = context.mock.method(crypto.subtle, 'digest');
        const fetch = context.mock.method(globalThis, 'fetch', async () => new Response(envelope, {
            headers: { 'content-type': 'application/connect+proto' },
        }));
        await assert.rejects(subscribeBlocks(INDEXER, options()).next(), (error: unknown) => {
            assert.ok(error instanceof ConnectError);
            assert.equal(error.code, expectedCode);
            assert.match(error.rawMessage, expectedMessage);
            return true;
        });
        assert.equal(digest.mock.callCount(), 0);
        assert.equal(fetch.mock.callCount(), 1);
    });
}

test('component limits include 4096 headers, 512 header bytes, and 16KiB certificate bytes', async () => {
    const invalidContext = createBlockBatchVerifier('00');
    let materialError: unknown;
    try { await invalidContext.verify(frame(fixture.emptyBlock)); } catch (error) { materialError = error; }
    assert.notEqual(materialError, undefined);
    const materialMessage = String(materialError);
    for (const mutate of [
        (message: WatchBlocksResponse) => { message.headers = Array.from({ length: 4096 }, () => new Uint8Array(1)); },
        (message: WatchBlocksResponse) => { message.headers = [new Uint8Array(512)]; },
        (message: WatchBlocksResponse) => { message.certificate = new Uint8Array(16 * 1024); },
    ]) {
        const message = frame(fixture.emptyBlock);
        mutate(message);
        await assert.rejects(invalidContext.verify(message), (error: unknown) => {
            assert.equal(String(error), materialMessage);
            return true;
        });
        assert.equal(invalidContext.after, undefined);
    }
});

test('3MiB+1 Connect frame length is rejected before its payload or any crypto is read', { timeout: 5_000 }, async (context) => {
    const digest = context.mock.method(crypto.subtle, 'digest');
    let payloadRead = false;
    let canceled = false;
    context.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream<Uint8Array>({
        start(controller) {
            const envelope = new Uint8Array(5);
            new DataView(envelope.buffer).setUint32(1, 3 * 1024 * 1024 + 1);
            controller.enqueue(envelope);
        },
        pull() { payloadRead = true; },
        cancel() { canceled = true; },
    }, { highWaterMark: 0 }), { headers: { 'content-type': 'application/connect+proto' } }));
    await assert.rejects(subscribeBlocks(INDEXER, options()).next(), (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.ResourceExhausted);
        return true;
    });
    assert.equal(digest.mock.callCount(), 0);
    assert.equal(payloadRead, false);
    assert.equal(canceled, true);
});

test('an exact 3MiB frame waits for its payload and remains cancelable', { timeout: 5_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    const readingPayload = deferred();
    const digest = context.mock.method(crypto.subtle, 'digest');
    context.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream<Uint8Array>({
        start(source) {
            const envelope = new Uint8Array(5);
            new DataView(envelope.buffer).setUint32(1, 3 * 1024 * 1024);
            source.enqueue(envelope);
        },
        pull() { readingPayload.resolve(); },
    }, { highWaterMark: 0 }), { headers: { 'content-type': 'application/connect+proto' } }));
    const pending = subscribeBlocks(INDEXER, { ...options(), signal: controller.signal }).next();
    await readingPayload.promise;
    controller.abort();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.equal(digest.mock.callCount(), 0);
});

test('old unsigned protobuf summaries fail closed without an accepted cursor', async (context) => {
    const cursors: Array<bigint | undefined> = [];
    const fetch = serve(context, async function* (request) {
        cursors.push(request.after);
        yield create(WatchBlocksResponseSchema, { sequenceNumber: 9n });
    });
    await assert.rejects(subscribeBlocks(INDEXER, options()).next(), /certificate/i);
    assert.equal(fetch.mock.callCount(), 1);
    assert.deepEqual(cursors, [undefined]);
});

test('typed transient errors preserve the last accepted batch cursor', async (context) => {
    const cursors: Array<bigint | undefined> = [];
    const errors: string[] = [];
    serve(context, async function* (request) {
        cursors.push(request.after);
        if (cursors.length === 1) {
            yield frame(fixture.directBlock);
            throw new ConnectError('upstream unavailable', Code.Unavailable);
        }
        if (cursors.length === 2) throw new ConnectError('upstream timeout', Code.DeadlineExceeded);
        yield frame(fixture.historicalBlock);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(), onError: (error) => errors.push(error) });
    assert.deepEqual((await nextBatch(stream)).blocks.map((row) => row.height), [1n]);
    assert.deepEqual((await nextBatch(stream)).blocks.map((row) => row.height), [2n, 3n]);
    assert.deepEqual(cursors, [undefined, 1n, 1n]);
    assert.deepEqual(errors, ['[unavailable] upstream unavailable', '[deadline_exceeded] upstream timeout']);
    await stream.return();
});

for (const code of [
    Code.InvalidArgument, Code.PermissionDenied, Code.Unauthenticated, Code.Unimplemented,
    Code.DataLoss, Code.ResourceExhausted, Code.FailedPrecondition, Code.Internal, Code.Aborted,
    Code.Unknown, Code.Canceled,
]) {
    test(`permanent Connect error ${Code[code]} is terminal`, async (context) => {
        const fetch = serve(context, async function* () { throw new ConnectError('permanent failure', code); });
        await assert.rejects(subscribeBlocks(INDEXER, options()).next(), (error: unknown) => {
            assert.ok(error instanceof ConnectError);
            assert.equal(error.code, code);
            return true;
        });
        assert.equal(fetch.mock.callCount(), 1);
    });
}

test('a transport failure reconnects without inventing a resume height', async (context) => {
    const errors: string[] = [];
    const handler = explorerFetch({ async *watchBlocks(request) {
        assert.equal(request.after, undefined);
        yield frame(fixture.directBlock);
    } });
    let requests = 0;
    context.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        if (++requests === 1) throw new TypeError('Failed to fetch');
        return handler(input, init);
    });
    const stream = subscribeBlocks(INDEXER, { ...options(), onError: (error) => errors.push(error) });
    assert.equal((await nextBatch(stream)).blocks[0]!.height, 1n);
    assert.equal(requests, 2);
    assert.equal(errors.length, 1);
    await stream.return();
});

for (const partialBatch of [false, true]) {
    test(`truncated Connect ${partialBatch ? 'batch' : 'end envelope'} resumes from the last complete batch`, { timeout: 5_000 }, async (context) => {
        const cursors: Array<bigint | undefined> = [];
        const handler = explorerFetch({ async *watchBlocks(request) {
            cursors.push(request.after);
            yield frame(cursors.length === 1 ? fixture.directBlock : fixture.historicalBlock);
        } });
        let requests = 0;
        context.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
            const response = await handler(input, init);
            if (++requests > 1) return response;
            const bytes = new Uint8Array(await response.arrayBuffer());
            const firstEnvelopeEnd = 5 + new DataView(bytes.buffer, bytes.byteOffset).getUint32(1);
            return new Response(bytes.subarray(0, partialBatch ? firstEnvelopeEnd - 1 : bytes.length - 1), { headers: response.headers });
        });
        const stream = subscribeBlocks(INDEXER, { ...options(), after: 0n });
        const first = await nextBatch(stream);
        assert.deepEqual(first.blocks.map((row) => row.height), partialBatch ? [1n, 2n, 3n] : [1n]);
        if (!partialBatch) assert.deepEqual((await nextBatch(stream)).blocks.map((row) => row.height), [2n, 3n]);
        assert.deepEqual(cursors, [0n, partialBatch ? 0n : 1n]);
        await stream.return();
    });
}

test('abort cancels an active WatchBlocks read and releases the caller listener', { timeout: 5_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    const reading = deferred();
    let serverCanceled = false;
    serve(context, async function* (_request, rpc) {
        yield frame(fixture.directBlock);
        reading.resolve();
        await waitForAbort(rpc.signal);
        serverCanceled = true;
    });
    const stream = subscribeBlocks(INDEXER, { ...options(), signal: controller.signal });
    assert.equal((await nextBatch(stream)).blocks[0]!.height, 1n);
    const pending = stream.next();
    await reading.promise;
    controller.abort();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.equal(serverCanceled, true);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('iterator return cancels the generated streaming RPC', { timeout: 5_000 }, async (context) => {
    const canceled = deferred();
    serve(context, async function* (_request, rpc) {
        yield frame(fixture.directBlock);
        await waitForAbort(rpc.signal);
        canceled.resolve();
    });
    const stream = subscribeBlocks(INDEXER, options());
    assert.equal((await nextBatch(stream)).blocks[0]!.height, 1n);
    await stream.return();
    await canceled.promise;
});

test('abort cancels a pending fetch without reporting a service error', { timeout: 5_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    const started = deferred();
    const errors: string[] = [];
    context.mock.method(globalThis, 'fetch', async (_input: RequestInfo | URL, init?: RequestInit) => {
        started.resolve();
        await waitForAbort(init!.signal!);
        throw new Error('fetch canceled');
    });
    const pending = subscribeBlocks(INDEXER, {
        ...options(), signal: controller.signal, onError: (error) => errors.push(error),
    }).next();
    await started.promise;
    controller.abort();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.deepEqual(errors, []);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('abort interrupts reconnect backoff without opening another RPC', { timeout: 5_000 }, async (context) => {
    const controller = new AbortController();
    context.after(() => controller.abort());
    const failed = deferred();
    const fetch = serve(context, async function* () { throw new ConnectError('offline', Code.Unavailable); });
    const pending = subscribeBlocks(INDEXER, {
        ...options(), signal: controller.signal, reconnectDelayMs: 60_000, onError: () => failed.resolve(),
    }).next();
    await failed.promise;
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort();
    assert.deepEqual(await pending, { done: true, value: undefined });
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('an already aborted subscription opens no RPC', async (context) => {
    const controller = new AbortController();
    controller.abort();
    context.mock.method(globalThis, 'fetch', async () => { assert.fail('aborted feed fetched'); });
    assert.deepEqual(await subscribeBlocks(INDEXER, {
        ...options(), signal: controller.signal,
    }).next(), { done: true, value: undefined });
});
