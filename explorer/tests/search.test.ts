import assert from 'node:assert/strict';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';
import { fromHex, toHex } from '../src/codec.ts';
import { SearchKind } from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';
import { SEARCH_INPUT_INVALID, normalizeSearchQuery, searchIndexer } from '../src/search.ts';
import { explorerFetch } from './rpcTest.ts';

const digest = 'ab'.repeat(32);
const run = (signal = new AbortController().signal) => searchIndexer('https://indexer.example/', digest, signal);

test('search normalizes one identity and calls its generated RPC', async (t) => {
    assert.equal(normalizeSearchQuery(` 0x${digest.toUpperCase()} `), digest);
    const serve = explorerFetch({ search(request) {
        assert.equal(toHex(request.value), digest);
        return { kind: SearchKind.TRANSACTION, value: request.value };
    } });
    const fetch = t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(String(input), 'https://indexer.example/constantinople.explorer.v1.ExplorerService/Search');
        assert.equal(init?.redirect, 'error');
        assert.equal(init?.method, 'POST');
        return serve(input, init);
    });
    assert.deepEqual(await run(), { kind: 'transaction', value: digest });
    await assert.rejects(searchIndexer('https://indexer.example', 'invalid', new AbortController().signal), { message: SEARCH_INPUT_INVALID });
    assert.equal(SEARCH_INPUT_INVALID, 'not an address or transaction hash');
    assert.equal(fetch.mock.callCount(), 1);
});

test('search opens matches and routes an unindexed key to its account proof', async (t) => {
    let step = 0;
    t.mock.method(globalThis, 'fetch', explorerFetch({ search(request) {
        if (step++ === 0) return { kind: SearchKind.ACCOUNT, value: request.value };
        throw new ConnectError('not available', step === 2 ? Code.NotFound : Code.Unavailable);
    } }));
    assert.deepEqual(await run(), { kind: 'account', value: digest });
    assert.deepEqual(await run(), { kind: 'account', value: digest });
    await assert.rejects(run(), (error) => error instanceof ConnectError && error.code === Code.Unavailable);
});

test('search rejects a changed identity, unknown enum, and oversized protobuf result', async (t) => {
    for (const result of [
        { kind: SearchKind.TRANSACTION, value: fromHex('cd'.repeat(32)) },
        { kind: 9 as SearchKind, value: fromHex(digest) },
        { kind: SearchKind.TRANSACTION, value: new Uint8Array(16 * 1024 + 1) },
    ]) {
        t.mock.method(globalThis, 'fetch', explorerFetch({ search() { return result; } }));
        await assert.rejects(run(), /invalid search result|size limit/);
        t.mock.restoreAll();
    }
});

test('closing a search cancels a pending response body', async (t) => {
    const controller = new AbortController();
    let canceled = false;
    t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream<Uint8Array>({
        pull() { controller.abort(new Error('closed')); },
        cancel() { canceled = true; },
    }), { headers: { 'content-type': 'application/proto' } }));
    await assert.rejects(run(controller.signal));
    assert.equal(canceled, true);
});

test('an already canceled search makes no request', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected request'); });
    await assert.rejects(run(AbortSignal.abort(new Error('closed'))), /closed/);
    assert.equal(fetch.mock.callCount(), 0);
});
