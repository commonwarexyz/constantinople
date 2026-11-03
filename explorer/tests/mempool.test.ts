import assert from 'node:assert/strict';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';
import type { MessageInitShape } from '@bufbuild/protobuf';
import { CompletedSubmissionSchema, SubmitTransactionResponseSchema } from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';
import { submitTransactions } from '../src/mempool.ts';
import { TransactionSubmissionError, isDeterministicSubmissionRejection, singleTransactionOutcome } from '../src/submissionResponse.ts';
import { SUBMISSION_TIMEOUT_MS, boundedSubmissionSignal } from '../src/submissionRequest.ts';
import { explorerFetch } from './rpcTest.ts';

type ResponseInit = MessageInitShape<typeof SubmitTransactionResponseSchema>;
const batch = new Uint8Array([1, 2, 3]);
const completed = (httpStatus: number, result: MessageInitShape<typeof CompletedSubmissionSchema>['result']): ResponseInit => ({
    outcome: { case: 'completed', value: { httpStatus, result, body: new Uint8Array(), contentType: '' } },
});

test('typed submission replies retain relayer reports and send only once', async (t) => {
    const cases: Array<[ResponseInit, unknown]> = [
        [completed(200, { case: 'finalized', value: { height: 7n } }), { status: 'finalized', height: 7 }],
        [completed(200, { case: 'partiallyFinalized', value: { height: 8n, included: 1n, filtered: 2n } }), { status: 'partially_finalized', height: 8, included: 1, filtered: 2 }],
        [completed(200, { case: 'dropped', value: {} }), { status: 'dropped' }],
        [completed(202, { case: 'pending', value: {} }), { status: 'pending' }],
    ];
    for (const [response, expected] of cases) {
        const serve = explorerFetch({ submitTransaction(request) { assert.deepEqual(request.batch, batch); return response; } });
        const fetch = t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
            assert.equal(String(input), 'https://indexer.example/constantinople.explorer.v1.ExplorerService/SubmitTransaction');
            assert.equal(init?.redirect, 'error');
            assert.equal(init?.method, 'POST');
            assert.ok(new Headers(init?.headers).has('connect-timeout-ms'));
            return serve(input, init);
        });
        assert.deepEqual(await submitTransactions('https://indexer.example/', batch), expected);
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

test('unsigned admission rejection reports cannot release a nonce reservation', async (t) => {
    for (const status of [400, 413, 500, 502, 503, 504]) {
        const response = completed(status, { case: 'rejected', value: {} });
        const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ submitTransaction() { return response; } }));
        await assert.rejects(submitTransactions('https://indexer.example', batch), (error) => {
            assert.ok(error instanceof TransactionSubmissionError);
            assert.equal(error.kind, 'ambiguous');
            assert.equal(isDeterministicSubmissionRejection(error), false);
            return true;
        });
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

test('missing, contradictory, oversized, and uncertain results keep delivery ambiguous', async (t) => {
    const cases: ResponseInit[] = [
        {}, completed(200, undefined), completed(400, undefined), completed(202, {case:'rejected',value:{}}),
        completed(200, {case:'finalized',value:{height:1n << 63n}}),
        {outcome:{case:'ambiguous',value:{reason:'upstream reply incomplete',httpStatus:200}}},
        {outcome:{case:'completed',value:{httpStatus:200,result:{case:'dropped',value:{}},body:new Uint8Array(65537)}}},
    ];
    for (const response of cases) {
        const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ submitTransaction() { return response; } }));
        await assert.rejects(submitTransactions('https://indexer.example', batch), (error) => !isDeterministicSubmissionRejection(error));
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

test('a maximum bounded upstream body fits its protobuf response overhead', async (t) => {
    t.mock.method(globalThis, 'fetch', explorerFetch({ submitTransaction() {
        return {outcome:{case:'completed',value:{httpStatus:202,result:{case:'pending',value:{}},body:new Uint8Array(65536),contentType:'application/json'}}};
    } }));
    assert.deepEqual(await submitTransactions('https://indexer.example', batch), {status:'pending'});
});

test('all RPC errors after sending are ambiguous and never retried', async (t) => {
    for (const code of [Code.InvalidArgument, Code.ResourceExhausted, Code.Unavailable, Code.Internal, Code.DeadlineExceeded]) {
        const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ submitTransaction() { throw new ConnectError('failed',code); } }));
        await assert.rejects(submitTransactions('https://indexer.example', batch), (error) => !isDeterministicSubmissionRejection(error));
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

test('transport failure is ambiguous and not retried', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('Failed to fetch'); });
    await assert.rejects(submitTransactions('https://indexer.example', batch), (error) => !isDeterministicSubmissionRejection(error));
    assert.equal(fetch.mock.callCount(), 1);
});

test('browser deadline cancels a pending submission body without retry', async (t) => {
    let canceled = false;
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({ cancel(){canceled=true;} }), {headers:{'content-type':'application/proto'}}));
    await assert.rejects(submitTransactions('https://indexer.example', batch, undefined, 10), (error) => !isDeterministicSubmissionRejection(error));
    assert.equal(canceled,true);
    assert.equal(fetch.mock.callCount(),1);
});

test('oversized local batches are rejected before sending', async (t) => {
    const fetch = t.mock.method(globalThis,'fetch',async()=>{throw new Error('unexpected request');});
    await assert.rejects(submitTransactions('https://indexer.example',new Uint8Array(4*1024*1024+6)),isDeterministicSubmissionRejection);
    assert.equal(fetch.mock.callCount(),0);
});

test('single transaction outcomes preserve finalization as a report', () => {
    assert.deepEqual(singleTransactionOutcome({status:'finalized',height:8}),{kind:'finalized',height:8});
    assert.deepEqual(singleTransactionOutcome({status:'partially_finalized',height:8,included:1,filtered:0}),{kind:'finalized',height:8});
    assert.equal(singleTransactionOutcome({status:'partially_finalized',height:8,included:1,filtered:1}).kind,'ambiguous');
});

test('unsigned dropped and zero-included reports remain uncertain after dispatch', async (t) => {
    const reports: Array<MessageInitShape<typeof CompletedSubmissionSchema>['result']> = [
        { case: 'dropped', value: {} },
        { case: 'partiallyFinalized', value: { height: 8n, included: 0n, filtered: 1n } },
        { case: 'partiallyFinalized', value: { height: 8n, included: 0n, filtered: 0n } },
    ];
    for (const result of reports) {
        const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({
            submitTransaction() { return completed(200, result); },
        }));
        const report = await submitTransactions('https://indexer.example', batch);
        if (report.status === 'pending') assert.fail('unexpected pending report');
        const outcome = singleTransactionOutcome(report);
        if (outcome.kind !== 'ambiguous') assert.fail('unsigned report was treated as conclusive');
        assert.match(outcome.detail, /indexer reported/);
        assert.equal(fetch.mock.callCount(), 1);
        t.mock.restoreAll();
    }
});

test('submission deadline is twelve seconds and preserves caller cancellation', () => {
    assert.equal(SUBMISSION_TIMEOUT_MS,12_000);
    const caller=new AbortController();
    const request=boundedSubmissionSignal(caller.signal,60_000);
    const reason=new Error('caller canceled'); caller.abort(reason);
    assert.equal(request.signal.reason,reason); request.dispose();
});
