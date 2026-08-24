import assert from 'node:assert/strict';
import { getEventListeners, once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { subscribeBlocks } from '../src/indexer.ts';

test('block subscription retries backend errors until cancelled', async (context) => {
    let requests = 0;
    const server = createServer((_request, response) => {
        requests++;
        response.writeHead(500, { 'content-type': 'text/plain' });
        response.end('backend unavailable');
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    context.after(() => server.close());

    const address = server.address();
    assert(address !== null && typeof address !== 'string');

    const controller = new AbortController();
    const errors: string[] = [];
    const stream = subscribeBlocks(`http://127.0.0.1:${address.port}`, {
        signal: controller.signal,
        reconnectDelayMs: 0,
        onError: (message) => {
            errors.push(message);
            if (errors.length === 2) {
                assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
                controller.abort();
            }
        },
    });

    assert.deepEqual(await stream.next(), { done: true, value: undefined });
    assert.equal(requests, 2);
    assert.equal(errors.length, 2);
    assert.match(errors[0], /internal|HTTP 500/i);
});

test('block subscription backs off after a clean stream end', async (context) => {
    const payload = Buffer.from('{}');
    const endStream = Buffer.alloc(5 + payload.length);
    endStream[0] = 2;
    endStream.writeUInt32BE(payload.length, 1);
    payload.copy(endStream, 5);

    const requestTimes: number[] = [];
    const server = createServer((request, response) => {
        requestTimes.push(Date.now());
        response.writeHead(200, {
            'connect-protocol-version': '1',
            'content-type': request.headers['content-type'] ?? 'application/connect+proto',
        });
        response.end(endStream);
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    context.after(() => server.close());

    const address = server.address();
    assert(address !== null && typeof address !== 'string');

    const controller = new AbortController();
    const errors: string[] = [];
    const stream = subscribeBlocks(`http://127.0.0.1:${address.port}`, {
        signal: controller.signal,
        reconnectDelayMs: 20,
        onError: (message) => {
            errors.push(message);
            if (errors.length === 2) controller.abort();
        },
    });

    assert.deepEqual(await stream.next(), { done: true, value: undefined });
    assert.deepEqual(errors, ['block subscription ended', 'block subscription ended']);
    assert.equal(requestTimes.length, 2);
    assert(requestTimes[1] - requestTimes[0] >= 15);
});
