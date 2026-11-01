import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { Code, ConnectError } from '@connectrpc/connect';
import { initQmdbWasm, QmdbProofVerifier } from '@exowarexyz/qmdb';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import type { VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { fromHex, toArrayBuffer, toHex } from '../src/codec.ts';
import { authenticatedHeader, finalizedTargetFromCertificate } from '../src/qmdb.ts';
import {
    loadAccountBundle, loadBlockBundle, loadTransactionBundle,
    verifyAccountBundle, verifyBlockBundle, verifyTransactionBundle,
} from '../src/proofBundle.ts';
import { isRetryableAccountProofError, isRetryableProofError } from '../src/proofRetry.ts';

const options = { qmdbUrl: 'https://qmdb.example', simplexVerificationMaterial: '00' };
const account = '11'.repeat(32);
const empty = () => ({ certificate: '00', headers: [], sequenceNumber: '0', account: null, transactions: [], transactionsProof: null, nextCursor: null });

interface WireRow { location: string; body: string; height: string; index: number; role?: number }
interface WireBundle {
    certificate: string; headers: string[]; sequenceNumber: string;
    account: { location: string; proof: string } | null;
    transactions: WireRow[]; transactionsProof: string | null; nextCursor: string | null;
}
interface PublisherFixture {
    verificationMaterial: string; account: string; recipient: string; transactionDigest: string;
    directBlock: WireBundle; descendantBlock: WireBundle; descendantLastPage: WireBundle;
    emptyBlock: WireBundle; accountBundle: WireBundle; accountNext: WireBundle;
    accountStateOnly: WireBundle; recipientBundle: WireBundle; transactionBundle: WireBundle;
    webauthnBlock: WireBundle; webauthnBundle: WireBundle; webauthnDigest: string;
    historicalBlock: WireBundle; historicalTransaction: WireBundle; historicalDigest: string;
    accountWithHistory: WireBundle;
}

async function publisherFixture(): Promise<PublisherFixture> {
    return JSON.parse(await readFile(new URL('../../tests/fixtures/proofBundle.json', import.meta.url), 'utf8')) as PublisherFixture;
}

function fixtureOptions(fixture: PublisherFixture) {
    return { ...options, simplexVerificationMaterial: fixture.verificationMaterial };
}

test.before(async () => {
    await Promise.all([
        initQmdbWasm(toArrayBuffer(await readFile(new URL('./generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.resolve('@exowarexyz/qmdb'))))),
        ensureSimplexWasm({ module_or_path: await readFile(new URL('./generated/wasm/exoware_simplex_wasm_bg.wasm', import.meta.resolve('@exowarexyz/simplex/wasm'))) }),
    ]);
});

test('malformed request identities are rejected before any fetch', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected fetch'); });
    const cursor = new Uint8Array(24);
    cursor[7] = 1;
    for (const request of [
        () => loadAccountBundle({ ...options, account: 'ab' }),
        () => loadAccountBundle({ ...options, account, mode: 'wrong' as 'all' }),
        () => loadAccountBundle({ ...options, account, cursor }),
        () => loadAccountBundle({ ...options, account, at: { height: 1n, blockDigest: new Uint8Array(31) } }),
        () => loadBlockBundle({ ...options, height: 0n }),
        () => loadBlockBundle({ ...options, height: 1n, offset: -1n }),
        () => loadTransactionBundle({ ...options, digest: 'xyz' }),
    ]) await assert.rejects(request);
    assert.equal(fetch.mock.callCount(), 0);
});

test('hostile wire sizes and noncanonical numbers fail before certificate verification', async () => {
    const rows = [{ location: '1', body: '00', height: '1', index: 0, role: 0 }];
    const cases = [
        { ...empty(), certificate: '00'.repeat(16 * 1024 + 1) },
        { ...empty(), certificate: 'AA' },
        { ...empty(), sequenceNumber: '01' },
        { ...empty(), sequenceNumber: '18446744073709551616' },
        { ...empty(), headers: Array(4097).fill('00') },
        { ...empty(), headers: ['00'.repeat(513)] },
        { ...empty(), transactions: Array(11).fill(rows[0]) },
        { ...empty(), transactions: [{ ...rows[0], body: '00'.repeat(920) }] },
        { ...empty(), transactions: [{ ...rows[0], location: 1 }] },
        { ...empty(), transactions: [{ ...rows[0], role: 2 }] },
        { ...empty(), transactionsProof: '00'.repeat(1024 * 1024 + 1) },
        { ...empty(), nextCursor: '00'.repeat(25) },
    ];
    for (const raw of cases) await assert.rejects(verifyAccountBundle({ ...options, account }, raw), /invalid|oversized|exceeds/);
});

test('response byte limit applies while streaming without trusting content-length', async (t) => {
    let canceled = false;
    let emitted = false;
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
        pull(controller) {
            if (!emitted) { emitted = true; controller.enqueue(new Uint8Array(8 * 1024 * 1024 + 1)); }
        },
        cancel() { canceled = true; },
    })));
    await assert.rejects(loadAccountBundle({ ...options, account }), /response exceeds size limit/);
    assert.equal(fetch.mock.callCount(), 1);
    assert.equal(canceled, true);
});

test('aggregate availability is retryable while unsupported work is terminal', async (t) => {
    let status = 503;
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(null, { status }));
    await assert.rejects(loadTransactionBundle({ ...options, digest: account }), (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.Unavailable);
        assert.equal(isRetryableAccountProofError(error), true);
        assert.equal(isRetryableProofError(error), true);
        return true;
    });
    status = 422;
    await assert.rejects(loadTransactionBundle({ ...options, digest: account }), (error: unknown) => {
        assert.equal(isRetryableAccountProofError(error), false);
        assert.equal(isRetryableProofError(error), false);
        return true;
    });
    assert.equal(fetch.mock.callCount(), 2);
});

test('network failures in aggregate fetch and response streams remain retryable', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    let stage: 'fetch' | 'stream' = 'fetch';
    const failure = new TypeError('Failed to fetch');
    t.mock.method(globalThis, 'fetch', async () => {
        if (stage === 'fetch') throw failure;
        return new Response(new ReadableStream({ start(controller) { controller.error(failure); } }));
    });
    for (const current of ['fetch', 'stream'] as const) {
        stage = current;
        await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
            assert.ok(error instanceof ConnectError);
            assert.equal(error.cause, failure);
            assert.equal(isRetryableAccountProofError(error), true);
            assert.equal(isRetryableProofError(error), true);
            return true;
        });
    }
});

test('aggregate gateway failures retry while native invalid-data responses are terminal', async (t) => {
    let status = 502;
    t.mock.method(globalThis, 'fetch', async () => new Response(null, { status }));
    for (const entry of [[502, true], [503, true], [504, true], [500, false]] as const) {
        const [responseStatus, retryable] = entry;
        status = responseStatus;
        await assert.rejects(loadTransactionBundle({ ...options, digest: account }), (error: unknown) => {
            assert.equal(isRetryableAccountProofError(error), retryable);
            assert.equal(isRetryableProofError(error), retryable);
            return true;
        });
    }
});

test('aggregate transport classification preserves cancellation and invalid bodies', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const abort = new DOMException('caller canceled', 'AbortError');
    t.mock.method(globalThis, 'fetch', async () => { throw abort; });
    await assert.rejects(loadAccountBundle(opts), (error: unknown) => error === abort);
    t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('Invalid URL'); });
    await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
        assert.equal(isRetryableAccountProofError(error), false);
        assert.equal(isRetryableProofError(error), false);
        return true;
    });
    for (const body of ['{', new Uint8Array([0xff])]) {
        t.mock.method(globalThis, 'fetch', async () => new Response(body));
        await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
            assert.equal(isRetryableAccountProofError(error), false);
            assert.equal(isRetryableProofError(error), false);
            return true;
        });
    }
});

test('already canceled loads issue no request', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected fetch'); });
    const signal = AbortSignal.abort(new Error('account changed'));
    await assert.rejects(loadAccountBundle({ ...options, account, signal }), /account changed/);
    assert.equal(fetch.mock.callCount(), 0);
});

test('real publisher certificates and proofs authenticate direct, descendant, empty and paginated blocks', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const direct = await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(direct.target.height, 1n);
    assert.equal(direct.transactions.length, 3);
    assert.equal(direct.block.transactionCount, 3n);
    assert.deepEqual(await verifyBlockBundle({ ...opts, height: 1n, simplexVerificationMaterial: `\n${fixture.verificationMaterial.toUpperCase()}\n` }, fixture.directBlock), direct);
    const descendant = await verifyBlockBundle({ ...opts, height: 2n }, fixture.descendantBlock);
    assert.equal(descendant.target.height, 3n);
    assert.equal(descendant.block.height, 2n);
    assert.equal(descendant.block.view, 2n);
    assert.equal(descendant.block.transactionCount, 55n);
    assert.equal(descendant.transactions.length, 50);
    assert.equal(descendant.nextOffset, 50n);
    assert.ok(descendant.transactions.every((row) => row.proof.height === 2n && row.proof.view === 2n));
    const last = await verifyBlockBundle({ ...opts, height: 2n, offset: 50n }, fixture.descendantLastPage);
    assert.equal(last.transactions.length, 5);
    assert.equal(last.nextOffset, null);
    assert.equal(last.transactions[0]!.location, descendant.transactions.at(-1)!.location + 1n);
    const emptyBlock = await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    assert.equal(emptyBlock.block.transactionCount, 0n);
    assert.deepEqual(emptyBlock.transactions, []);
    const transaction = await verifyTransactionBundle({ ...opts, digest: fixture.transactionDigest }, fixture.transactionBundle);
    assert.equal(transaction.height, 2n);
    assert.equal(transaction.location, last.transactions.at(-1)!.location);
});

test('repeated certificates reuse only the last authenticated target and still hash transaction bodies', async (t) => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    const header = fixture.descendantBlock.headers.at(-1)!;
    assert.ok(fixture.directBlock.certificate.endsWith(header));
    const digest = t.mock.method(crypto.subtle, 'digest');
    const headerHashes = () => digest.mock.calls.filter(({ arguments: [, bytes] }) =>
        toHex(new Uint8Array(bytes as ArrayBuffer)) === header).length;
    const bodyHashes = () => digest.mock.calls.filter(({ arguments: [, bytes] }) => bytes.byteLength === 82).length;

    const first = await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(headerHashes(), 1);
    assert.equal(bodyHashes(), 3);
    const repeated = await verifyBlockBundle({ ...opts, height: 1n }, { ...fixture.directBlock, sequenceNumber: '10' });
    assert.equal(repeated.target.sequenceNumber, 10n);
    assert.equal(first.target.sequenceNumber, 9n);
    assert.equal(bodyHashes(), 6);
    assert.equal(headerHashes(), 1);

    await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(headerHashes(), 2);
    assert.equal(bodyHashes(), 9);
});

test('certificate reuse requires every signed and unsigned byte to match', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), height: 1n };
    const expected = await verifyBlockBundle(opts, fixture.directBlock);
    const changedSignature = fromHex(fixture.directBlock.certificate);
    changedSignature[0] ^= 1;
    const changedHeader = fromHex(fixture.directBlock.certificate);
    changedHeader[changedHeader.length - 1] ^= 1;
    for (const [certificate, error] of [
        [toHex(changedSignature), /finalization certificate verification failed/],
        [toHex(changedHeader), /header digest/],
        [`${fixture.directBlock.certificate}00`, /trailing bytes/],
    ] as const) {
        await assert.rejects(verifyBlockBundle(opts, { ...fixture.directBlock, certificate }), error);
        assert.deepEqual(await verifyBlockBundle(opts, fixture.directBlock), expected);
    }
});

test('returned target buffers cannot mutate a reused certificate target', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    const first = await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    const expected = structuredClone(first);
    for (const result of [first, await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock)]) {
        assert.deepEqual(result, expected);
        for (const value of Object.values(result.target)) {
            if (value instanceof Uint8Array) value.fill(0);
        }
        result.block.blockDigest.fill(0);
    }
    assert.deepEqual(await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock), expected);
});

test('single-transaction finalization reports its owning block before membership verification', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), digest: fixture.transactionDigest };
    const block = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 2n }, fixture.descendantBlock);
    assert.ok(block.target.height > block.block.height);
    const observed: Array<{ height: bigint; view: bigint }> = [];
    const onFinalizationVerified = (target: { height: bigint; view: bigint }) => { observed.push(target); };
    const proof = await verifyTransactionBundle({ ...opts, onFinalizationVerified }, fixture.transactionBundle);
    assert.deepEqual(observed, [{ height: block.block.height, view: block.block.view }]);
    assert.equal(proof.height, observed[0]!.height);
    const invalid = structuredClone(fixture.transactionBundle);
    const bytes = fromHex(invalid.transactionsProof!);
    bytes[bytes.length - 1] ^= 1;
    invalid.transactionsProof = toHex(bytes);
    observed.length = 0;
    await assert.rejects(verifyTransactionBundle({ ...opts, onFinalizationVerified }, invalid));
    assert.deepEqual(observed, [{ height: block.block.height, view: block.block.view }]);
});

test('historical block appends remain provable below a later inactivity floor', async () => {
    const fixture = await publisherFixture();
    const block = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 1n }, fixture.historicalBlock);
    assert.ok(block.target.height >= block.block.height + 2n);
    assert.equal(block.transactions.length, 3);
    assert.ok(block.transactions.every(({ location }) => location < block.target.transactionsStart));
});

test('historical single transactions remain provable below a later inactivity floor', async () => {
    const fixture = await publisherFixture();
    const proof = await verifyTransactionBundle({ ...fixtureOptions(fixture), digest: fixture.historicalDigest }, fixture.historicalTransaction);
    const covering = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 3n }, fixture.emptyBlock);
    assert.equal(proof.height, 1n);
    assert.ok(proof.location < covering.target.transactionsStart);
});

test('historical account activity remains provable below the snapshot inactivity floor', async () => {
    const fixture = await publisherFixture();
    const bundle = await verifyAccountBundle({ ...fixtureOptions(fixture), account: fixture.account }, fixture.accountWithHistory);
    assert.ok(bundle.target.height >= 4n);
    assert.equal(bundle.page.rows.length, fixture.accountWithHistory.transactions.length);
    assert.ok(bundle.page.rows.some(({ location }) => location < bundle.target.transactionsStart));
});

test('cached verifiers remain bound to their BLS verification material', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), height: 1n };
    const expected = await verifyBlockBundle(opts, fixture.directBlock);
    const wrongMaterial = fromHex(fixture.verificationMaterial);
    // Negating the compressed group key gives a valid point with a different signing identity.
    wrongMaterial[0] ^= 0x20;
    await assert.rejects(verifyBlockBundle({
        ...opts, simplexVerificationMaterial: Buffer.from(wrongMaterial).toString('hex'),
    }, fixture.directBlock), (error: unknown) => {
        assert.match(String(error), /finalization certificate verification failed/);
        return true;
    });
    assert.deepEqual(await verifyBlockBundle(opts, fixture.directBlock), expected);
});

test('canceling one concurrent aggregate load leaves the other caller independent', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = new AbortController();
    const second = new AbortController();
    const responses: Array<(response: Response) => void> = [];
    let started!: () => void;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    const fetch = t.mock.method(globalThis, 'fetch', async (_input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(init?.signal, responses.length === 0 ? first.signal : second.signal);
        return new Promise<Response>((resolve) => {
            responses.push(resolve);
            if (responses.length === 2) started();
        });
    });
    const canceled = loadAccountBundle({ ...opts, signal: first.signal });
    const rejected = assert.rejects(canceled, /first caller canceled/);
    const surviving = loadAccountBundle({ ...opts, signal: second.signal });
    await ready;
    first.abort(new Error('first caller canceled'));
    for (const respond of responses) respond(new Response(JSON.stringify(fixture.accountBundle)));
    await rejected;
    const verified = await surviving;
    assert.equal(verified.page.rows.length, 10);
    assert.ok(verified.account);
    assert.equal(second.signal.aborted, false);
    assert.equal(fetch.mock.callCount(), 2);
});

test('account rows derive fields from authenticated bodies and keep the snapshot across pages', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = await verifyAccountBundle(opts, fixture.accountBundle);
    assert.equal(first.target.height, 3n);
    assert.ok(first.account);
    assert.equal(first.page.rows.length, 10);
    assert.equal(first.page.rows[0]!.direction, 'sent');
    assert.equal(first.page.rows[0]!.counterparty, fixture.account);
    assert.equal(first.page.rows[0]!.value, 1n);
    const next = await verifyAccountBundle({ ...opts, cursor: first.page.nextCursor, at: { height: first.target.height, blockDigest: first.target.blockDigest } }, fixture.accountNext);
    assert.equal(next.page.rows[0]!.blockIndex, 44);
    assert.ok(next.page.rows.every((row) => !first.page.rows.some((prior) => prior.digest === row.digest)));
    const received = await verifyAccountBundle({ ...opts, account: fixture.recipient, mode: 'received' }, fixture.recipientBundle);
    assert.ok(received.page.rows.every((row) => row.direction === 'received' && row.counterparty === fixture.account));
    const onlyState = await verifyAccountBundle({ ...opts, includeTransactions: false }, fixture.accountStateOnly);
    assert.deepEqual(onlyState.page.rows, []);
    assert.deepEqual(onlyState.account, first.account);
    const unknown = await verifyAccountBundle(opts, { ...fixture.accountBundle, account: null });
    assert.equal(unknown.account, null);
    assert.equal(unknown.page.rows.length, 10);
    const laterFloor = await verifyAccountBundle(opts, { ...fixture.accountBundle, sequenceNumber: '18446744073709551615' });
    assert.deepEqual(laterFloor.account, first.account);
    assert.deepEqual(laterFloor.page, first.page);
});

test('the full supported WebAuthn encoding verifies at the 919-byte boundary', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const wire = fixture.webauthnBundle;
    assert.equal(wire.transactions[0]!.body.length / 2, 919);
    const proof = await verifyTransactionBundle({ ...opts, digest: fixture.webauthnDigest }, wire);
    assert.equal(proof.height, 4n);
    const block = await verifyBlockBundle({ ...opts, height: 4n }, fixture.webauthnBlock);
    const transaction = block.transactions.find(({ digest }) => digest === fixture.webauthnDigest)!;
    assert.ok(transaction);
    assert.equal(transaction.sender, transaction.recipient);
    assert.equal(transaction.location, proof.location);
    const malformed = structuredClone(wire);
    malformed.transactions[0]!.body += '00';
    await assert.rejects(verifyTransactionBundle({ ...opts, digest: fixture.webauthnDigest }, malformed), /oversized signed transaction/);
});

test('self-transfer roles share one proven location and SQL display hints cannot change authenticated fields', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const self = fixture.transactionBundle.transactions[0]!;
    const wire = {
        ...fixture.accountBundle,
        transactions: [{ ...self, role: 1 }, { ...self, role: 0 }],
        transactionsProof: fixture.transactionBundle.transactionsProof,
        nextCursor: null,
    };
    const verified = await verifyAccountBundle(opts, wire);
    assert.deepEqual(verified.page.rows.map(({ direction }) => direction), ['received', 'sent']);
    assert.ok(verified.page.rows.every(({ counterparty }) => counterparty === fixture.account));
    assert.equal(verified.transactionProofs[0]!.location, verified.transactionProofs[1]!.location);
    const hints = { ...wire, transactions: wire.transactions.map((row) => ({
        ...row, value: '999999', nonce: '999999', sender: 'ff'.repeat(32), recipient: 'ee'.repeat(32), digest: 'dd'.repeat(32),
    })) };
    assert.deepEqual(await verifyAccountBundle(opts, hints), verified);
    await assert.rejects(verifyAccountBundle(opts, { ...wire, transactions: [wire.transactions[1]!, wire.transactions[1]!] }));
    await assert.rejects(verifyAccountBundle(opts, { ...wire, transactions: [{ ...wire.transactions[0]!, index: self.index + 1 }, wire.transactions[1]!] }));
});

test('every aggregate view finishes with one fetch and no legacy proof or metadata requests', async (t) => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const responses = [fixture.accountBundle, fixture.descendantBlock, fixture.transactionBundle];
    const urls: string[] = [];
    t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(init?.cache, 'no-store');
        urls.push(String(input));
        const response = responses.shift();
        assert.ok(response, 'only one request per aggregate load');
        return new Response(JSON.stringify(response));
    });
    await loadAccountBundle({ ...opts, account: fixture.account });
    await loadBlockBundle({ ...opts, height: 2n });
    await loadTransactionBundle({ ...opts, digest: fixture.transactionDigest });
    assert.deepEqual(urls, [
        `${options.qmdbUrl}/explorer/accounts/${fixture.account}?mode=all`,
        `${options.qmdbUrl}/explorer/blocks/2?offset=0`,
        `${options.qmdbUrl}/explorer/transactions/${fixture.transactionDigest}`,
    ]);
    assert.deepEqual(responses, []);
});

test('real aggregate proofs reject altered certificates, ancestry, positions, bodies and cursors', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const mutated = (value: string, byte = 0) => {
        const bytes = fromHex(value); bytes[byte] ^= 1;
        return Buffer.from(bytes).toString('hex');
    };
    for (const mutate of [
        (wire: WireBundle) => { wire.certificate = mutated(wire.certificate); },
        (wire: WireBundle) => { wire.headers[0] = mutated(wire.headers[0]!); },
        (wire: WireBundle) => { wire.headers.reverse(); },
        (wire: WireBundle) => { wire.headers.pop(); },
        (wire: WireBundle) => { wire.transactions[0]!.location = '0'; },
        (wire: WireBundle) => { wire.transactions[0]!.height = '1'; },
        (wire: WireBundle) => { wire.transactions[0]!.index++; },
        (wire: WireBundle) => { wire.transactions[0]!.body = mutated(wire.transactions[0]!.body, 34); },
        (wire: WireBundle) => { wire.transactions[0]!.body = mutated(wire.transactions[0]!.body, 66); },
        (wire: WireBundle) => { wire.transactions[0]!.body = mutated(wire.transactions[0]!.body, 74); },
        (wire: WireBundle) => { wire.transactions[0]!.body = mutated(wire.transactions[0]!.body, 33); },
        (wire: WireBundle) => { wire.transactionsProof = mutated(wire.transactionsProof!); },
        (wire: WireBundle) => { wire.transactions.pop(); },
        (wire: WireBundle) => { wire.nextCursor = '49'; },
    ]) {
        const wire = structuredClone(fixture.descendantBlock);
        mutate(wire);
        await assert.rejects(verifyBlockBundle({ ...opts, height: 2n }, wire));
    }
    await assert.rejects(verifyTransactionBundle({ ...opts, digest: 'ff'.repeat(32) }, fixture.transactionBundle), /requested digest/);
    const accountOpts = { ...opts, account: fixture.account };
    const first = await verifyAccountBundle(accountOpts, fixture.accountBundle);
    await assert.rejects(verifyAccountBundle({ ...accountOpts, at: { height: 3n, blockDigest: new Uint8Array(32) } }, fixture.accountBundle), /requested snapshot/);
    await assert.rejects(verifyAccountBundle({ ...accountOpts, account: fixture.recipient }, fixture.accountBundle));
    await assert.rejects(verifyAccountBundle(accountOpts, { ...fixture.accountBundle, nextCursor: '00'.repeat(24) }), /cursor/);
    const changedState = structuredClone(fixture.accountBundle);
    changedState.account!.proof = mutated(changedState.account!.proof);
    await assert.rejects(verifyAccountBundle(accountOpts, changedState));
    const changedLocation = structuredClone(fixture.accountBundle);
    changedLocation.account!.location = '0';
    await assert.rejects(verifyAccountBundle(accountOpts, changedLocation));
    await assert.rejects(verifyAccountBundle({ ...accountOpts, cursor: first.page.nextCursor, at: { height: 3n, blockDigest: first.target.blockDigest } }, fixture.accountBundle), /after requested cursor/);
});

test('cancellation during finalization never returns a completed proof or account page', async () => {
    const fixture = await publisherFixture();
    const controller = new AbortController();
    let finalized = 0;
    await assert.rejects(verifyAccountBundle({
        ...fixtureOptions(fixture), account: fixture.account, signal: controller.signal,
        onFinalizationVerified: () => { finalized++; controller.abort(new Error('account switched')); },
    }, fixture.accountBundle), /account switched/);
    assert.equal(finalized, 1);
});

test('a fetch completing after cancellation cannot publish the previous request', async (t) => {
    const fixture = await publisherFixture();
    const controller = new AbortController();
    let respond!: (response: Response) => void;
    let started!: () => void;
    const fetching = new Promise<void>((resolve) => { started = resolve; });
    t.mock.method(globalThis, 'fetch', async (_input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(init?.signal, controller.signal);
        started();
        return new Promise<Response>((resolve) => { respond = resolve; });
    });
    const pending = loadAccountBundle({ ...fixtureOptions(fixture), account: fixture.account, signal: controller.signal });
    await fetching;
    controller.abort(new Error('page changed'));
    respond(new Response(JSON.stringify(fixture.accountBundle)));
    await assert.rejects(pending, /page changed/);
});

test('standalone WASM proves the existing multiproof without transport and rejects changed context', async () => {
    const fixture = JSON.parse(await readFile(new URL('../../tests/fixtures/transactionActivityProof.json', import.meta.url), 'utf8')) as {
        root: string; tip: string; proof: string; operations: Array<{ location: string; digest: string }>;
    };
    const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });
    const expected = fixture.operations.map((operation) => ({ location: BigInt(operation.location), value: fromHex(operation.digest) }));
    const prove = (root = fromHex(fixture.root), tip = BigInt(fixture.tip), entries = expected, proof = fromHex(fixture.proof)) =>
        verifier.verifyFixedKeylessAppendMany(proof, { tip }, root, entries);
    const verified = await prove();
    assert.equal(verified.proofSizeBytes, fixture.proof.length / 2);
    assert.deepEqual(verified.operations.map(({ location }) => location), expected.map(({ location }) => location));
    await assert.rejects(prove(new Uint8Array(32)));
    await assert.rejects(prove(undefined, BigInt(fixture.tip) + 1n));
    await assert.rejects(prove(undefined, undefined, expected.map((entry, index) => index === 0 ? { ...entry, location: 0n } : entry)));
    await assert.rejects(prove(undefined, undefined, expected.map((entry, index) => index === 0 ? { ...entry, value: new Uint8Array(32) } : entry)));
    const proof = fromHex(fixture.proof); proof[proof.length - 1] ^= 1;
    await assert.rejects(prove(undefined, undefined, undefined, proof));
});

test('certified header binding consumes every byte after the signed commitment', async () => {
    const header = executionHeader();
    const digest = await hash(header);
    const payload = concat(digest, new Uint8Array(68));
    const certificate: VerifiedSimplexCertificate = {
        epoch: 0n, view: 9n, parent: 8n, scheme: 'bls12381-threshold-standard-min-sig',
        payload, header: concat(payload, header), certificate: new Uint8Array(),
    };
    assert.equal((await finalizedTargetFromCertificate(certificate)).height, 1n);
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, header: concat(certificate.header, new Uint8Array([0])) }), /trailing bytes/);
    const wrong = payload.slice(); wrong[0] ^= 1;
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, payload: wrong }), /does not match certificate payload/);
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, payload: wrong, header: concat(wrong, header) }), /header digest/);
});

test('header decoding rejects noncanonical and overflowing varints even with matching hashes', async () => {
    for (const header of [
        executionHeader(new Uint8Array([0x80, 0])),
        executionHeader(new Uint8Array([...Array<number>(9).fill(0xff), 2])),
    ]) await assert.rejects(authenticatedHeader(header, await hash(header), 1n), /canonical|exceeds u64/);
    const header = executionHeader();
    await assert.rejects(authenticatedHeader(header, await hash(header), 2n), /chain height/);
    const mutated = header.slice(); mutated[mutated.length - 1] ^= 1;
    await assert.rejects(authenticatedHeader(mutated, await hash(header), 1n), /certified digest/);
});

function executionHeader(epoch = new Uint8Array([0])): Uint8Array {
    return concat(epoch, new Uint8Array([9]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), new Uint8Array(32), u64(1n), u64(0n),
        new Uint8Array(32), u64(0n), u64(3n), new Uint8Array(32), u64(0n), u64(3n));
}

function u64(value: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value);
    return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
    const bytes = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.length; }
    return bytes;
}

async function hash(bytes: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes)));
}
