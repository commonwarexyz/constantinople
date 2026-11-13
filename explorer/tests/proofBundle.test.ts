import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test, { type TestContext } from 'node:test';
import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { initQmdbWasm, QmdbProofVerifier } from '@exowarexyz/qmdb';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import type { VerifiedSimplexCertificate } from '@exowarexyz/simplex';
import { fromHex, toArrayBuffer, toHex } from '../src/codec.ts';
import { DEFAULT_ACCOUNT_BALANCE, authenticatedHeader, finalizedTargetFromCertificate } from '../src/qmdb.ts';
import { initAccountProofWasm } from '../src/accountProof.ts';
import {
    loadAccountBundle, loadBlockBundle, loadTransactionBundle,
    verifyAccountBundle, verifyBlockBundle, verifyTransactionBundle, verifyTransactionEvidence, proofBundleInput,
} from '../src/proofBundle.ts';
import { ACCOUNT_NOT_FOUND, accountLookupFailure, isRetryableAccountProofError, isRetryableProofError } from '../src/proofRetry.ts';
import { ProofBundleSchema, type ProofBundle, type TransactionRole } from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';
import { explorerFetch } from './rpcTest.ts';
import { accountCursor } from '../src/accountPage.ts';
import { nativeActivityFixtureIssue, nativeFixtureSkip, nativeProofFixtureIssue, readFixture } from './fixtureSource.ts';
import { assertSubmittedTransactionMatches, restoreSubmittedTransaction } from '../src/submissionHistory.ts';

const options = { indexerUrl: 'https://indexer.example', simplexVerificationMaterial: '00' };
const account = '11'.repeat(32);

/** Returns a syntactically valid empty account response for size and encoding cases. */
const empty = () => ({ certificate: '00', headers: [], sequenceNumber: '0', account: null, transactions: [], transactionsProof: null, nextCursor: null });

/** One transaction row as encoded on the wire. */
interface WireRow { location: string; body: string; height: string; index: number; role?: number; senderIndex: string; recipientIndex: string }

/** Combined indexer response as encoded on the wire. */
interface WireBundle {
    certificate: string; headers: string[]; sequenceNumber: string;
    account: { location: string; proof: string; writeHeight: string; encodedOperation: string } | null;
    transactions: WireRow[]; transactionsProof: string | null; nextCursor: string | null;
}

/** Responses and verification material produced by a real publisher and indexer. */
interface PublisherFixture {
    verificationMaterial: string; account: string; recipient: string; transactionDigest: string;
    defaultAccountBalance: string;
    directBlock: WireBundle; descendantBlock: WireBundle; descendantLastPage: WireBundle;
    emptyBlock: WireBundle; accountBundle: WireBundle; accountNext: WireBundle;
    accountStateOnly: WireBundle; recipientBundle: WireBundle; transactionBundle: WireBundle;
    webauthnBlock: WireBundle; webauthnBundle: WireBundle; webauthnDigest: string;
    submissionEvidence: WireBundle;
    historicalBlock: WireBundle; historicalTransaction: WireBundle; historicalDigest: string;
    accountWithHistory: WireBundle; accountOldest: WireBundle; accountExhausted: WireBundle;
}

const nativeFixture = await readFixture<PublisherFixture>('proofBundle');
const nativeSkip = nativeFixtureSkip(nativeProofFixtureIssue(nativeFixture));

async function publisherFixture(): Promise<PublisherFixture> {
    return nativeFixture;
}

function nativeTest(name: string, run: (context: TestContext) => Promise<void>): void {
    test(name, { skip: nativeSkip }, run);
}

nativeTest('the wallet default balance matches the chain default for an account without state', async () => {
    assert.equal(DEFAULT_ACCOUNT_BALANCE, BigInt(nativeFixture.defaultAccountBalance));
});

function rpcBundle(wire: WireBundle): ProofBundle {
    const nextCursor: ProofBundle['nextCursor'] = wire.nextCursor === null ? { case: undefined }
        : /^[0-9a-f]{16}$/.test(wire.nextCursor)
            ? { case: 'activityCursor', value: fromHex(wire.nextCursor) }
            : { case: 'blockOffset', value: BigInt(wire.nextCursor) };
    return create(ProofBundleSchema, {
        certificate: fromHex(wire.certificate), headers: wire.headers.map(fromHex),
        sequenceNumber: BigInt(wire.sequenceNumber),
        account: wire.account === null ? undefined : {
            location: BigInt(wire.account.location), proof: fromHex(wire.account.proof), writeHeight: BigInt(wire.account.writeHeight),
            encodedOperation: fromHex(wire.account.encodedOperation),
        },
        transactions: wire.transactions.map((row) => ({
            location: BigInt(row.location), body: fromHex(row.body), height: BigInt(row.height),
            index: row.index, role: row.role as TransactionRole | undefined,
            senderIndex: BigInt(row.senderIndex), recipientIndex: BigInt(row.recipientIndex),
        })),
        transactionsProof: wire.transactionsProof === null ? undefined : fromHex(wire.transactionsProof),
        nextCursor,
    });
}

function fixtureOptions(fixture: PublisherFixture) {
    return { ...options, simplexVerificationMaterial: fixture.verificationMaterial };
}

test.before(async () => {
    await Promise.all([
        initQmdbWasm(toArrayBuffer(await readFile(new URL('./generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.resolve('@exowarexyz/qmdb'))))),
        ensureSimplexWasm({ module_or_path: await readFile(new URL('./generated/wasm/exoware_simplex_wasm_bg.wasm', import.meta.resolve('@exowarexyz/simplex/wasm'))) }),
        initAccountProofWasm(toArrayBuffer(await readFile(new URL('../../src/gen/account_wasm/constantinople_account_proof_bg.wasm', import.meta.url)))),
    ]);
});

test('malformed request identities are rejected before any fetch', async (t) => {
    // Malformed identities and a cursor without a snapshot must all fail before fetch.
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected fetch'); });
    const cursor = new Uint8Array(8);
    cursor[7] = 1;
    for (const request of [
        () => loadAccountBundle({ ...options, account: 'ab' }),
        () => loadAccountBundle({ ...options, account, cursor }),
        () => loadAccountBundle({ ...options, account, cursor, at: { height: 1n, blockDigest: new Uint8Array(32) } }),
        () => loadAccountBundle({ ...options, account, cursor, at: { height: 1n, blockDigest: new Uint8Array(32) }, accountLocation: 1n }),
        () => loadAccountBundle({ ...options, account, cursor, at: { height: 1n, blockDigest: new Uint8Array(32) }, expectedTxCount: 1n }),
        () => loadAccountBundle({ ...options, account, cursor: accountCursor(2n), at: { height: 1n, blockDigest: new Uint8Array(32) }, accountLocation: 1n, expectedTxCount: 1n }),
        () => loadAccountBundle({ ...options, account, at: { height: 1n, blockDigest: new Uint8Array(31) } }),
        () => loadBlockBundle({ ...options, height: 0n }),
        () => loadBlockBundle({ ...options, height: 1n, offset: -1n }),
        () => loadTransactionBundle({ ...options, digest: 'xyz' }),
    ]) await assert.rejects(request);
    assert.equal(fetch.mock.callCount(), 0);
});

test('hostile wire sizes and noncanonical numbers fail before certificate verification', async () => {
    // Every case exceeds a size bound or uses a noncanonical encoding that parsing must reject.
    const rows = [{ location: '1', body: '00', height: '1', index: 0, role: 0, senderIndex: '0', recipientIndex: '0' }];
    const cases = [
        { ...empty(), certificate: '00'.repeat(16 * 1024 + 1) },
        { ...empty(), certificate: 'AA' },
        { ...empty(), sequenceNumber: '01' },
        { ...empty(), sequenceNumber: '18446744073709551616' },
        { ...empty(), headers: Array(4097).fill('00') },
        { ...empty(), headers: ['00'.repeat(513)] },
        { ...empty(), transactions: Array(51).fill(rows[0]) },
        { ...empty(), transactions: [{ ...rows[0], body: '00'.repeat(920) }] },
        { ...empty(), transactions: [{ ...rows[0], location: 1 }] },
        ...['-1', '01', '18446744073709551616'].flatMap((value) => [
            { ...empty(), transactions: [{ ...rows[0], senderIndex: value }] },
            { ...empty(), transactions: [{ ...rows[0], recipientIndex: value }] },
        ]),
        { ...empty(), transactions: [{ ...rows[0], role: 2 }] },
        { ...empty(), transactionsProof: '00'.repeat(1024 * 1024 + 1) },
        { ...empty(), nextCursor: '00'.repeat(25) },
    ];
    for (const raw of cases) await assert.rejects(verifyAccountBundle({ ...options, account }, raw), /invalid|oversized|exceeds/);
});

test('typed proof inputs enforce bounds before certificate verification', () => {
    const mutations: Array<(bundle: ProofBundle) => void> = [
        (bundle) => { bundle.certificate = new Uint8Array(16 * 1024 + 1); },
        (bundle) => { bundle.headers = Array.from({ length: 4097 }, () => new Uint8Array(1)); },
        (bundle) => { bundle.headers = [new Uint8Array(513)]; },
        (bundle) => { bundle.sequenceNumber = 1n << 64n; },
        (bundle) => { bundle.transactions = Array(51).fill(bundle.transactions[0]); },
        (bundle) => { bundle.transactions[0]!.body = new Uint8Array(920); },
        (bundle) => { bundle.transactions[0]!.location = -1n; },
        (bundle) => { bundle.transactions[0]!.senderIndex = -1n; },
        (bundle) => { bundle.transactions[0]!.recipientIndex = 1n << 64n; },
        (bundle) => { bundle.account!.writeHeight = -1n; },
        (bundle) => { bundle.account!.encodedOperation = new Uint8Array(66); },
        (bundle) => { bundle.account!.proof = new Uint8Array(1024 * 1024 + 1); },
        (bundle) => { bundle.transactionsProof = new Uint8Array(1024 * 1024 + 1); },
        (bundle) => { bundle.nextCursor = { case: 'activityCursor', value: new Uint8Array(25) }; },
    ];
    for (const mutate of mutations) {
        const bundle = rpcBundle({
            ...empty(), account: { location: '1', proof: '00', writeHeight: '1', encodedOperation: '00'.repeat(65) },
            transactions: [{ location: '1', body: '00', height: '1', index: 0, senderIndex: '0', recipientIndex: '0' }],
        });
        mutate(bundle);
        assert.throws(() => proofBundleInput(bundle, 'account'), /invalid|oversized|exceeds/);
    }
});

test('typed proof cursors must belong to the requested view', () => {
    const accountCursor: ProofBundle['nextCursor'] = { case: 'activityCursor', value: new Uint8Array(8) };
    const blockCursor: ProofBundle['nextCursor'] = { case: 'blockOffset', value: 50n };
    for (const [kind, cursor] of [
        ['account', blockCursor], ['block', accountCursor],
        ['transaction', accountCursor], ['transaction', blockCursor],
    ] as const) {
        const bundle = rpcBundle(empty());
        bundle.nextCursor = cursor;
        assert.throws(() => proofBundleInput(bundle, kind), /cursor does not match requested view/);
    }
    for (const kind of ['account', 'block', 'transaction'] as const) {
        assert.doesNotThrow(() => proofBundleInput(rpcBundle(empty()), kind));
    }
});

test('unknown typed transaction roles are rejected before finalization', async (t) => {
    const fixture = await publisherFixture();
    const bundle = rpcBundle({ ...empty(), transactions: [{ location: '1', body: '00', height: '1', index: 0, role: 0, senderIndex: '0', recipientIndex: '0' }] });
    bundle.transactions[0]!.role = 99 as TransactionRole;
    t.mock.method(globalThis, 'fetch', explorerFetch({ getAccount: () => bundle }));
    let finalized = false;
    await assert.rejects(loadAccountBundle({
        ...fixtureOptions(fixture), account: fixture.account,
        onFinalizationVerified: () => { finalized = true; },
    }), /invalid transaction role/);
    assert.equal(finalized, false);
});

test('response byte limit applies to a serialized protobuf body', async (t) => {
    const oversized = rpcBundle(empty());
    oversized.certificate = new Uint8Array(8 * 1024 * 1024 + 1);
    const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ getAccount: () => oversized }));
    await assert.rejects(loadAccountBundle({ ...options, account }), (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.ResourceExhausted);
        return true;
    });
    assert.equal(fetch.mock.callCount(), 1);
});

test('an account the indexer reports as missing surfaces as a terminal not-found report', async (t) => {
    const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ getAccount: () => {
        throw new ConnectError('account has no update at the certified state boundary', Code.NotFound);
    } }));
    await assert.rejects(loadAccountBundle({ ...options, account }), (error: unknown) => {
        assert.deepEqual(accountLookupFailure(error), { notFound: true, message: ACCOUNT_NOT_FOUND });
        assert.equal(isRetryableAccountProofError(error), false);
        return true;
    });
    assert.equal(fetch.mock.callCount(), 1);
});

test('aggregate availability is retryable while unsupported work is terminal', async (t) => {
    let code = Code.Unavailable;
    const fetch = t.mock.method(globalThis, 'fetch', explorerFetch({ getTransaction: () => {
        throw new ConnectError('aggregate unavailable', code);
    } }));
    for (const [failure, retryable] of [[Code.Unavailable, true], [Code.FailedPrecondition, false]] as const) {
        code = failure;
        await assert.rejects(loadTransactionBundle({ ...options, digest: account }), (error: unknown) => {
            assert.ok(error instanceof ConnectError);
            assert.equal(error.code, code);
            assert.equal(isRetryableAccountProofError(error), retryable);
            assert.equal(isRetryableProofError(error), retryable);
            return true;
        });
    }
    assert.equal(fetch.mock.callCount(), 2);
});

test('network failures in aggregate fetch and response streams remain retryable', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const handler = explorerFetch({ getAccount: () => rpcBundle(empty()) });
    let stage: 'fetch' | 'stream' = 'fetch';
    const failure = new TypeError('Failed to fetch');
    t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        if (stage === 'fetch') throw failure;
        const response = await handler(input, init);
        return new Response(new ReadableStream({ start(controller) { controller.error(failure); } }), {
            headers: response.headers,
        });
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

test('transient RPC failures retry while explicit bounds and invalid evidence are terminal', async (t) => {
    let code = Code.Unavailable;
    t.mock.method(globalThis, 'fetch', explorerFetch({ getTransaction: () => {
        throw new ConnectError('aggregate failure', code);
    } }));
    for (const [failure, retryable] of [
        [Code.Unavailable, true], [Code.DeadlineExceeded, true], [Code.Internal, false],
        [Code.ResourceExhausted, false], [Code.InvalidArgument, false],
    ] as const) {
        code = failure;
        await assert.rejects(loadTransactionBundle({ ...options, digest: account }), (error: unknown) => {
            assert.ok(error instanceof ConnectError);
            assert.equal(error.code, code);
            assert.equal(isRetryableAccountProofError(error), retryable);
            assert.equal(isRetryableProofError(error), retryable);
            return true;
        });
    }
});

test('aggregate transport classification preserves cancellation and rejects malformed protobuf', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const abort = new DOMException('caller canceled', 'AbortError');
    t.mock.method(globalThis, 'fetch', async () => { throw abort; });
    await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.Canceled);
        return true;
    });
    t.mock.restoreAll();
    t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('Invalid URL'); });
    await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
        assert.equal(isRetryableAccountProofError(error), false);
        assert.equal(isRetryableProofError(error), false);
        return true;
    });
    t.mock.restoreAll();

    const handler = explorerFetch({ getAccount: () => rpcBundle(empty()) });
    t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        const response = await handler(input, init);
        const body = new Uint8Array(await response.arrayBuffer());
        return new Response(body.subarray(0, body.length - 1), { headers: response.headers });
    });
    await assert.rejects(loadAccountBundle(opts), (error: unknown) => {
        assert.equal(isRetryableAccountProofError(error), false);
        assert.equal(isRetryableProofError(error), false);
        return true;
    });
});

test('already canceled loads issue no request', async (t) => {
    // A signal aborted before the load must reject with its reason before fetch.
    const fetch = t.mock.method(globalThis, 'fetch', async () => { throw new Error('unexpected fetch'); });
    const signal = AbortSignal.abort(new Error('account changed'));
    await assert.rejects(loadAccountBundle({ ...options, account, signal }), /account changed/);
    assert.equal(fetch.mock.callCount(), 0);
});

nativeTest('real publisher certificates and proofs authenticate direct, descendant, empty and paginated blocks', async () => {
    // Block 1 is certified directly, and verification material is normalized before use.
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const direct = await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(direct.target.height, 1n);
    assert.equal(direct.transactions.length, 3);
    assert.equal(direct.block.transactionCount, 3n);
    assert.deepEqual(await verifyBlockBundle({ ...opts, height: 1n, simplexVerificationMaterial: `\n${fixture.verificationMaterial.toUpperCase()}\n` }, fixture.directBlock), direct);

    // Block 2 is covered by the certificate for block 3, and its proofs are attributed to block 2.
    const descendant = await verifyBlockBundle({ ...opts, height: 2n }, fixture.descendantBlock);
    assert.equal(descendant.target.height, 3n);
    assert.equal(descendant.block.height, 2n);
    assert.equal(descendant.block.view, 2n);
    assert.equal(descendant.block.transactionCount, 55n);
    assert.equal(descendant.transactions.length, 50);
    assert.equal(descendant.nextOffset, 50n);
    assert.ok(descendant.transactions.every((row) => row.proof.height === 2n && row.proof.view === 2n));

    // The second page continues at the next location and ends pagination.
    const last = await verifyBlockBundle({ ...opts, height: 2n, offset: 50n }, fixture.descendantLastPage);
    assert.equal(last.transactions.length, 5);
    assert.equal(last.nextOffset, null);
    assert.equal(last.transactions[0]!.location, descendant.transactions.at(-1)!.location + 1n);

    // An empty block and a single transaction both authenticate against the same chain.
    const emptyBlock = await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    assert.equal(emptyBlock.block.transactionCount, 0n);
    assert.deepEqual(emptyBlock.transactions, []);
    const transaction = await verifyTransactionBundle({ ...opts, digest: fixture.transactionDigest }, fixture.transactionBundle);
    assert.equal(transaction.height, 2n);
    assert.equal(transaction.location, last.transactions.at(-1)!.location);
});

nativeTest('transaction details expose authenticated fields and exact owning block position', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const wire = structuredClone(fixture.transactionBundle);
    Object.assign(wire.transactions[0]!, { sender: 'ff'.repeat(32), recipient: 'ff'.repeat(32), value: '999', nonce: '999' });
    const details = await verifyTransactionBundle({ ...opts, digest: fixture.transactionDigest }, wire);
    const page = await verifyBlockBundle({ ...opts, height: details.height, offset: 50n }, fixture.descendantLastPage);
    const expected = page.transactions.at(-1)!;
    assert.equal(details.transaction.digest, fixture.transactionDigest);
    assert.equal(details.transaction.sender, expected.sender);
    assert.equal(details.transaction.recipient, expected.recipient);
    assert.equal(details.transaction.value, expected.value);
    assert.equal(details.transaction.nonce, expected.nonce);
    assert.equal(details.transaction.location, expected.location);
    assert.deepEqual(details.blockDigest, page.block.blockDigest);
    assert.equal(details.target.height, page.target.height);
});

nativeTest('repeated certificates reuse only the last authenticated target and still hash transaction bodies', async (t) => {
    // Prime the cache with a different certificate, then count header and body hashes. The
    // certified header for block 1 is the last bytes of its certificate.
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    const header = fixture.descendantBlock.headers.at(-1)!;
    assert.ok(fixture.directBlock.certificate.endsWith(header));
    const digest = t.mock.method(crypto.subtle, 'digest');
    const headerHashes = () => digest.mock.calls.filter(({ arguments: [, bytes] }) =>
        toHex(new Uint8Array(bytes as ArrayBuffer)) === header).length;
    const bodyHashes = () => digest.mock.calls.filter(({ arguments: [, bytes] }) => bytes.byteLength === 82).length;

    // Repeating a certificate skips header verification but still hashes every body, and the
    // sequence comes from each response.
    const first = await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(headerHashes(), 1);
    assert.equal(bodyHashes(), 3);
    const repeated = await verifyBlockBundle({ ...opts, height: 1n }, { ...fixture.directBlock, sequenceNumber: '10' });
    assert.equal(repeated.target.sequenceNumber, 10n);
    assert.equal(first.target.sequenceNumber, 9n);
    assert.equal(bodyHashes(), 6);
    assert.equal(headerHashes(), 1);

    // Only the most recent certificate is cached, so switching back verifies again.
    await verifyBlockBundle({ ...opts, height: 3n }, fixture.emptyBlock);
    await verifyBlockBundle({ ...opts, height: 1n }, fixture.directBlock);
    assert.equal(headerHashes(), 2);
    assert.equal(bodyHashes(), 9);
});

nativeTest('certificate reuse requires every signed and unsigned byte to match', async () => {
    // Flip a signature byte, a header byte, or append a byte. Each change must fail full
    // verification and leave the cached good certificate usable.
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

nativeTest('returned target buffers cannot mutate a reused certificate target', async () => {
    // Zero every buffer in a fresh result and a cached result, then verify again unchanged.
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

nativeTest('single-transaction finalization requires membership and the requested digest', async () => {
    // The covering certificate is above the block, yet finalization reports the owning block.
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), digest: fixture.transactionDigest };
    const block = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 2n }, fixture.descendantBlock);
    assert.ok(block.target.height > block.block.height);
    const observed: Array<{ height: bigint; view: bigint }> = [];
    const onFinalizationVerified = (target: { height: bigint; view: bigint }) => { observed.push(target); };
    const proof = await verifyTransactionBundle({ ...opts, onFinalizationVerified }, fixture.transactionBundle);
    assert.deepEqual(observed, [{ height: block.block.height, view: block.block.view }]);
    assert.equal(proof.height, observed[0]!.height);

    // A covering certificate alone cannot establish this transaction's finality.
    const invalid = structuredClone(fixture.transactionBundle);
    const bytes = fromHex(invalid.transactionsProof!);
    bytes[bytes.length - 1] ^= 1;
    invalid.transactionsProof = toHex(bytes);
    observed.length = 0;
    await assert.rejects(verifyTransactionBundle({ ...opts, onFinalizationVerified }, invalid));
    assert.deepEqual(observed, []);
    await assert.rejects(verifyTransactionBundle({
        ...opts, digest: fixture.historicalDigest, onFinalizationVerified,
    }, fixture.transactionBundle), /does not match requested digest/);
    assert.deepEqual(observed, []);
});

nativeTest('a real transaction proof does not authenticate altered saved submission fields', async () => {
    const fixture = await publisherFixture();
    const proof = await verifyTransactionBundle({
        ...fixtureOptions(fixture), digest: fixture.transactionDigest,
    }, fixture.transactionBundle);
    const saved = {
        ...proof.transaction, to: proof.transaction.recipient,
        value: proof.transaction.value.toString(), nonce: proof.transaction.nonce.toString(),
        submittedAt: 1, status: 'finalized',
        certificate: { status: 'verified' }, proof: { status: 'verified' },
    };
    const restored = restoreSubmittedTransaction(saved)!;
    assert.ok(restored);
    assert.doesNotThrow(() => assertSubmittedTransactionMatches(restored, proof.transaction));
    for (const changed of [
        { to: 'ff'.repeat(32) }, { value: (proof.transaction.value + 1n).toString() },
        { nonce: (proof.transaction.nonce + 1n).toString() },
    ]) {
        const altered = restoreSubmittedTransaction({ ...saved, ...changed })!;
        assert.ok(altered);
        assert.throws(() => assertSubmittedTransactionMatches(altered, proof.transaction), /do not match/);
        assert.equal(altered.status, 'reconciling');
        assert.equal(altered.certificate.status, 'waiting');
        assert.equal(altered.proof.status, 'waiting');
    }
});

nativeTest('historical block appends remain provable below a later inactivity floor', async () => {
    // Locations below the covering target's start remain provable through the transaction root.
    const fixture = await publisherFixture();
    const block = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 1n }, fixture.historicalBlock);
    assert.ok(block.target.height >= block.block.height + 2n);
    assert.equal(block.transactions.length, 3);
    assert.ok(block.transactions.every(({ location }) => location < block.target.transactionsStart));
});

nativeTest('historical single transactions remain provable below a later inactivity floor', async () => {
    // The proven location lies below the start of a later covering target.
    const fixture = await publisherFixture();
    const proof = await verifyTransactionBundle({ ...fixtureOptions(fixture), digest: fixture.historicalDigest }, fixture.historicalTransaction);
    const covering = await verifyBlockBundle({ ...fixtureOptions(fixture), height: 3n }, fixture.emptyBlock);
    assert.equal(proof.height, 1n);
    assert.ok(proof.location < covering.target.transactionsStart);
});

nativeTest('historical account activity remains provable below the snapshot inactivity floor', async () => {
    // At least one activity row lies below the snapshot's transaction range start.
    const fixture = await publisherFixture();
    const bundle = await verifyAccountBundle({ ...fixtureOptions(fixture), account: fixture.account }, fixture.accountWithHistory);
    assert.ok(bundle.target.height >= 4n);
    assert.equal(bundle.page.rows.length, fixture.accountWithHistory.transactions.length);
    assert.ok(bundle.page.rows.some(({ location }) => location < bundle.target.transactionsStart));
});

nativeTest('cached verifiers remain bound to their BLS verification material', async () => {
    // Cache a verifier for the real material, then try a valid but different group key.
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), height: 1n };
    const expected = await verifyBlockBundle(opts, fixture.directBlock);

    // Negating the compressed group key gives a valid point with a different signing identity. It
    // must fail without disturbing the verifier cached for the real material.
    const wrongMaterial = fromHex(fixture.verificationMaterial);
    wrongMaterial[0] ^= 0x20;
    await assert.rejects(verifyBlockBundle({
        ...opts, simplexVerificationMaterial: Buffer.from(wrongMaterial).toString('hex'),
    }, fixture.directBlock), (error: unknown) => {
        assert.match(String(error), /finalization certificate verification failed/);
        return true;
    });
    assert.deepEqual(await verifyBlockBundle(opts, fixture.directBlock), expected);
});

nativeTest('canceling one concurrent aggregate load leaves the other caller independent', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = new AbortController();
    const second = new AbortController();
    t.after(() => { first.abort(); second.abort(); });
    const releases: Array<() => void> = [];
    const signals: AbortSignal[] = [];
    let started!: () => void;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    const handler = explorerFetch({ getAccount: () => rpcBundle(fixture.accountBundle) });
    const fetch = t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        signals.push(init!.signal!);
        await new Promise<void>((resolve) => {
            releases.push(resolve);
            if (releases.length === 2) started();
        });
        return handler(input, init);
    });
    const canceled = loadAccountBundle({ ...opts, signal: first.signal });
    const rejected = assert.rejects(canceled, (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.Canceled);
        return true;
    });
    const surviving = loadAccountBundle({ ...opts, signal: second.signal });

    await ready;
    first.abort(new DOMException('first caller canceled', 'AbortError'));
    assert.equal(signals[0]!.aborted, true);
    assert.equal(signals[1]!.aborted, false);
    for (const release of releases) release();
    await rejected;
    const verified = await surviving;
    assert.equal(verified.page.rows.length, 50);
    assert.ok(verified.account);
    assert.equal(second.signal.aborted, false);
    assert.equal(fetch.mock.callCount(), 2);
});

nativeTest('account rows derive authenticated indices and pin the account version across pages', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = await verifyAccountBundle(opts, fixture.accountBundle);
    assert.equal(first.target.height, 3n);
    assert.ok(first.account);
    assert.equal(first.account.txCount, 58n);
    assert.equal(first.account.writeHeight, 3n);
    assert.equal(first.account.timestampMs, 3n);
    assert.equal(first.page.rows.length, 50);
    assert.equal(first.page.rows[0]!.direction, 'sent');
    assert.equal(first.page.rows[0]!.counterparty, fixture.account);
    assert.equal(first.page.rows[0]!.value, 1n);
    assert.equal(first.page.rows[0]!.accountIndex, 57n);
    assert.equal(first.page.rows[0]!.senderIndex, first.page.rows[0]!.recipientIndex);
    assert.equal(first.page.rows.filter((row) => row.digest === first.page.rows[0]!.digest).length, 1);
    assert.ok(first.page.rows.every((row) => !('height' in row) && !('blockIndex' in row)));
    assert.deepEqual(first.page.nextCursor, accountCursor(8n));
    const pinned = { ...opts, at: { height: first.target.height, blockDigest: first.target.blockDigest },
        accountLocation: first.account.location, expectedTxCount: first.account.txCount };
    const next = await verifyAccountBundle({ ...pinned, cursor: first.page.nextCursor }, fixture.accountNext);
    assert.deepEqual(next.page.rows.map((row) => row.accountIndex), [7n, 6n, 5n, 4n, 3n, 2n, 1n, 0n]);
    assert.equal(next.page.nextCursor, null);
    assert.ok(next.page.rows.every((row) => !first.page.rows.some((prior) => prior.digest === row.digest)));
    const oldest = await verifyAccountBundle({ ...pinned, cursor: accountCursor(3n) }, fixture.accountOldest);
    assert.deepEqual(oldest.page.rows.map((row) => row.accountIndex), [2n, 1n, 0n]);
    assert.equal(oldest.page.nextCursor, null);
    const exhausted = await verifyAccountBundle({ ...pinned, cursor: accountCursor(0n) }, fixture.accountExhausted);
    assert.deepEqual(exhausted.page, { rows: [], nextCursor: null });
    assert.deepEqual(exhausted.account, first.account);

    const received = await verifyAccountBundle({ ...opts, account: fixture.recipient }, fixture.recipientBundle);
    assert.ok(received.page.rows.every((row) => row.direction === 'received' && row.counterparty === fixture.account));
    assert.equal(received.account?.txCount, 56n);
    const onlyState = await verifyAccountBundle({ ...opts, includeTransactions: false }, fixture.accountStateOnly);
    assert.deepEqual(onlyState.page, { rows: [], nextCursor: null });
    assert.deepEqual(onlyState.account, first.account);
    await assert.rejects(verifyAccountBundle(opts, { ...fixture.accountBundle, account: null }), /missing account proof/);

    const laterSequence = await verifyAccountBundle(opts, { ...fixture.accountBundle, sequenceNumber: '18446744073709551615' });
    assert.deepEqual(laterSequence.account, first.account);
    assert.deepEqual(laterSequence.page, first.page);
});

nativeTest('native account proofs require the requested account update', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account, includeTransactions: false };
    const state = fixture.accountStateOnly;
    await assert.rejects(verifyAccountBundle({ ...opts, account: '00'.repeat(32) }, state));
    assert.notEqual(state.certificate, fixture.directBlock.certificate);
    await assert.rejects(verifyAccountBundle(opts, { ...state, certificate: fixture.directBlock.certificate }));
    const { encodedOperation: _encodedOperation, ...withoutOperation } = state.account!;
    await assert.rejects(verifyAccountBundle(opts, { ...state, account: withoutOperation }), /account operation/);
    await assert.rejects(verifyAccountBundle(opts, {
        ...state, account: { ...state.account!, encodedOperation: fixture.recipientBundle.account!.encodedOperation },
    }));
    await assert.rejects(verifyAccountBundle(opts, {
        ...state, account: { ...state.account!, encodedOperation: state.account!.encodedOperation.slice(0, -2) },
    }), /account operation/);
});

nativeTest('the full supported WebAuthn encoding verifies at the 919-byte boundary', async () => {
    // A maximum-size WebAuthn transaction verifies alone and within its block.
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

    // One extra byte exceeds the wire limit.
    const malformed = structuredClone(wire);
    malformed.transactions[0]!.body += '00';
    await assert.rejects(verifyTransactionBundle({ ...opts, digest: fixture.webauthnDigest }, malformed), /oversized signed transaction/);
});

nativeTest('evidence built from a finalized block verifies exactly as the indexer bundle for the same transaction', async () => {
    // Evidence from the submission path and the indexer's bundle authenticate the same facts.
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), digest: fixture.webauthnDigest };
    const evidence = fixture.submissionEvidence;
    assert.equal(evidence.sequenceNumber, '0');
    const verified = await verifyTransactionEvidence(opts, rpcBundle(evidence));
    const fetched = await verifyTransactionBundle(opts, fixture.webauthnBundle);
    assert.deepEqual(verified, { ...fetched, target: { ...fetched.target, sequenceNumber: 0n } });
    assert.equal(verified.height, 4n);
    assert.equal(verified.target.height, 4n);

    // Evidence for another transaction, or with any authenticated part changed, proves nothing.
    await assert.rejects(verifyTransactionEvidence({ ...opts, digest: fixture.transactionDigest }, rpcBundle(evidence)), /requested digest/);
    const changes: Array<(wire: WireBundle) => void> = [
        (wire) => { wire.certificate = fixture.transactionBundle.certificate; },
        (wire) => { wire.headers = []; },
        (wire) => { wire.headers = fixture.transactionBundle.headers; },
        (wire) => { wire.transactions[0]!.location = (BigInt(wire.transactions[0]!.location) - 1n).toString(); },
        (wire) => { wire.transactions[0]!.height = '3'; },
        (wire) => { wire.transactions[0]!.senderIndex = '1'; },
        (wire) => { wire.transactions[0]!.body = fixture.webauthnBlock.transactions[0]!.body; },
        (wire) => { wire.transactionsProof = fixture.webauthnBlock.transactionsProof; },
        (wire) => { wire.transactionsProof = null; },
    ];
    for (const change of changes) {
        const changed = structuredClone(evidence);
        change(changed);
        await assert.rejects(verifyTransactionEvidence(opts, rpcBundle(changed)));
    }
});

nativeTest('a self-transfer appears once and untrusted display hints cannot change authenticated fields', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const verified = await verifyAccountBundle(opts, fixture.accountBundle);
    const self = verified.page.rows[0]!;
    assert.equal(self.counterparty, fixture.account);
    assert.equal(self.direction, 'sent');
    const hints = structuredClone(fixture.accountBundle);
    Object.assign(hints.transactions[0]!, { value: '999999', nonce: '999999', sender: 'ff'.repeat(32), recipient: 'ee'.repeat(32), digest: 'dd'.repeat(32), height: '999', index: 999 });
    assert.deepEqual(await verifyAccountBundle(opts, hints), verified);
    const duplicate = structuredClone(fixture.accountBundle);
    duplicate.transactions[1] = { ...duplicate.transactions[0]! };
    await assert.rejects(verifyAccountBundle(opts, duplicate));
});

nativeTest('every aggregate view uses one typed RPC with locally verified evidence', async (t) => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const urls: string[] = [];
    const handler = explorerFetch({
        getAccount(request) {
            assert.deepEqual(request.account, fromHex(fixture.account));
            assert.equal(request.activity, true);
            assert.equal(request.cursor, undefined);
            assert.equal(request.at, undefined);
            assert.equal(request.digest, undefined);
            return rpcBundle(fixture.accountBundle);
        },
        getBlock(request) {
            assert.equal(request.height, 2n);
            assert.equal(request.offset, 0n);
            return rpcBundle(fixture.descendantBlock);
        },
        getTransaction(request) {
            assert.deepEqual(request.digest, fromHex(fixture.transactionDigest));
            return rpcBundle(fixture.transactionBundle);
        },
    });
    t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        assert.equal(init?.cache, 'no-store');
        assert.equal(init?.redirect, 'error');
        assert.equal(init?.method, 'POST');
        assert.equal(new Headers(init?.headers).get('Content-Type'), 'application/proto');
        urls.push(String(input));
        return handler(input, init);
    });
    const account = await loadAccountBundle({ ...opts, account: fixture.account });
    const block = await loadBlockBundle({ ...opts, height: 2n });
    const transaction = await loadTransactionBundle({ ...opts, digest: fixture.transactionDigest });
    assert.equal(account.page.rows.length, 50);
    assert.equal(block.block.height, 2n);
    assert.equal(transaction.transaction.digest, fixture.transactionDigest);
    assert.deepEqual(urls, ['GetAccount', 'GetBlock', 'GetTransaction'].map((method) =>
        `${options.indexerUrl}/constantinople.explorer.v1.ExplorerService/${method}`));
});

nativeTest('typed account continuation sends the first verified account location and snapshot', async (t) => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = await verifyAccountBundle(opts, fixture.accountBundle);
    assert.ok(first.account);
    let requests = 0;
    t.mock.method(globalThis, 'fetch', explorerFetch({ getAccount(request) {
        requests++;
        assert.deepEqual(request.cursor, first.page.nextCursor);
        assert.equal(request.at, first.target.height);
        assert.deepEqual(request.digest, first.target.blockDigest);
        assert.equal(request.accountLocation, first.account!.location);
        return rpcBundle(fixture.accountNext);
    } }));
    const next = await loadAccountBundle({ ...opts, cursor: first.page.nextCursor,
        at: { height: first.target.height, blockDigest: first.target.blockDigest },
        accountLocation: first.account.location, expectedTxCount: first.account.txCount });
    assert.equal(next.page.rows[0]!.accountIndex, 7n);
    assert.equal(requests, 1);
});

nativeTest('real aggregate proofs reject altered certificates, ancestry, positions, bodies and cursors', async () => {
    const fixture = await publisherFixture();
    const opts = fixtureOptions(fixture);
    const mutated = (value: string, byte = 0) => {
        const bytes = fromHex(value); bytes[byte] ^= 1;
        return Buffer.from(bytes).toString('hex');
    };

    // Each mutation of a block page breaks the certificate, the ancestry chain, a row position, a
    // signed body field, the multiproof, page coverage, or the next offset.
    for (const mutate of [
        (wire: WireBundle) => { wire.certificate = mutated(wire.certificate); },
        (wire: WireBundle) => { wire.headers[0] = mutated(wire.headers[0]!); },
        (wire: WireBundle) => { wire.headers.reverse(); },
        (wire: WireBundle) => { wire.headers.pop(); },
        (wire: WireBundle) => { wire.transactions[0]!.location = '0'; },
        (wire: WireBundle) => { wire.transactions[0]!.height = '1'; },
        (wire: WireBundle) => { wire.transactions[0]!.index++; },
        (wire: WireBundle) => { wire.transactions[0]!.senderIndex = (BigInt(wire.transactions[0]!.senderIndex) + 1n).toString(); },
        (wire: WireBundle) => { wire.transactions[0]!.recipientIndex = (BigInt(wire.transactions[0]!.recipientIndex) + 1n).toString(); },
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

    // Account pages reject a different snapshot, a different account, a forged cursor, a changed
    // state proof or location, and a page that does not follow the requested cursor.
    const accountOpts = { ...opts, account: fixture.account };
    const first = await verifyAccountBundle(accountOpts, fixture.accountBundle);
    await assert.rejects(verifyAccountBundle({ ...accountOpts, at: { height: 3n, blockDigest: new Uint8Array(32) } }, fixture.accountBundle), /requested snapshot/);
    await assert.rejects(verifyAccountBundle({ ...accountOpts, account: fixture.recipient }, fixture.accountBundle));
    await assert.rejects(verifyAccountBundle(accountOpts, { ...fixture.accountBundle, nextCursor: '00'.repeat(8) }), /cursor/);
    const changedState = structuredClone(fixture.accountBundle);
    changedState.account!.proof = mutated(changedState.account!.proof);
    await assert.rejects(verifyAccountBundle(accountOpts, changedState));
    const changedLocation = structuredClone(fixture.accountBundle);
    changedLocation.account!.location = '0';
    await assert.rejects(verifyAccountBundle(accountOpts, changedLocation));
    assert.ok(first.account);
    await assert.rejects(verifyAccountBundle({ ...accountOpts, cursor: first.page.nextCursor, at: { height: 3n, blockDigest: first.target.blockDigest }, accountLocation: first.account.location, expectedTxCount: first.account.txCount }, fixture.accountBundle), /count interval|descending interval/);
});

nativeTest('native account pages reject missing, repeated, reordered and hidden invalid history', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const baseline = await verifyAccountBundle(opts, fixture.accountBundle);
    assert.equal(baseline.page.rows.length, 50);
    for (const mutate of [
        (wire: WireBundle) => { wire.transactions.splice(4, 1); },
        (wire: WireBundle) => { wire.transactions[1] = { ...wire.transactions[0]! }; },
        (wire: WireBundle) => { [wire.transactions[1], wire.transactions[2]] = [wire.transactions[2]!, wire.transactions[1]!]; },
        (wire: WireBundle) => { wire.transactions[1]!.location = wire.transactions[0]!.location; },
        (wire: WireBundle) => { wire.transactions[0]!.senderIndex = (BigInt(wire.transactions[0]!.senderIndex) + 1n).toString(); },
        (wire: WireBundle) => { wire.transactions[0]!.recipientIndex = (BigInt(wire.transactions[0]!.recipientIndex) + 1n).toString(); },
        (wire: WireBundle) => { wire.transactions[0]!.role = 1; },
        (wire: WireBundle) => { wire.nextCursor = null; },
        (wire: WireBundle) => { wire.nextCursor = toHex(accountCursor(7n)); },
    ]) {
        const wire = structuredClone(fixture.accountBundle);
        mutate(wire);
        await assert.rejects(verifyAccountBundle(opts, wire));
    }
    await assert.rejects(verifyAccountBundle(opts, fixture.recipientBundle));
});

nativeTest('native account state binds its writer, snapshot, location and transaction count', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    const first = await verifyAccountBundle(opts, fixture.accountBundle);
    assert.ok(first.account);
    const pinned = { ...opts, at: { height: first.target.height, blockDigest: first.target.blockDigest },
        accountLocation: first.account.location, expectedTxCount: first.account.txCount, cursor: first.page.nextCursor };
    await assert.rejects(verifyAccountBundle({ ...pinned, accountLocation: first.account.location + 1n }, fixture.accountNext), /pinned account location/);
    for (const expectedTxCount of [57n, 59n, (1n << 64n) - 1n]) {
        await assert.rejects(verifyAccountBundle({ ...pinned, expectedTxCount }, fixture.accountNext), /pinned transaction count/);
    }
    await assert.rejects(verifyAccountBundle({ ...pinned, at: { ...pinned.at, height: 2n } }, fixture.accountNext), /requested snapshot/);
    await assert.rejects(verifyAccountBundle({ ...pinned, at: { ...pinned.at, blockDigest: new Uint8Array(32) } }, fixture.accountNext), /requested snapshot/);
    for (const writeHeight of ['0', '1', '2', '4']) {
        const wire = structuredClone(fixture.accountBundle);
        wire.account!.writeHeight = writeHeight;
        if (writeHeight === '1' || writeHeight === '2') wire.headers = [...fixture.descendantBlock.headers];
        await assert.rejects(verifyAccountBundle(opts, wire), /write height|writing block|height|integer/);
    }
});

nativeTest('cancellation while native account verification is pending returns no page', async () => {
    const fixture = await publisherFixture();
    const opts = { ...fixtureOptions(fixture), account: fixture.account };
    await verifyAccountBundle(opts, fixture.accountBundle);
    const controller = new AbortController();
    await assert.rejects(verifyAccountBundle({ ...opts, signal: controller.signal,
        onFinalizationVerified: () => { queueMicrotask(() => controller.abort(new Error('account switched during state proof'))); },
    }, fixture.accountBundle), /account switched during state proof/);
});

nativeTest('cancellation during finalization never returns a completed proof or account page', async () => {
    // Abort from the finalization callback. Verification must stop with that reason.
    const fixture = await publisherFixture();
    const controller = new AbortController();
    let finalized = 0;
    await assert.rejects(verifyAccountBundle({
        ...fixtureOptions(fixture), account: fixture.account, signal: controller.signal,
        onFinalizationVerified: () => { finalized++; controller.abort(new Error('account switched')); },
    }, fixture.accountBundle), /account switched/);
    assert.equal(finalized, 1);
});

nativeTest('a fetch completing after cancellation cannot publish the previous request', async (t) => {
    const fixture = await publisherFixture();
    const controller = new AbortController();
    t.after(() => controller.abort());
    let release!: () => void;
    let started!: () => void;
    const fetching = new Promise<void>((resolve) => { started = resolve; });
    const handler = explorerFetch({ getAccount: () => rpcBundle(fixture.accountBundle) });
    t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
        started();
        await new Promise<void>((resolve) => { release = resolve; });
        return handler(input, init);
    });
    let finalized = false;
    const pending = loadAccountBundle({
        ...fixtureOptions(fixture), account: fixture.account, signal: controller.signal,
        onFinalizationVerified: () => { finalized = true; },
    });
    const rejected = assert.rejects(pending, (error: unknown) => {
        assert.ok(error instanceof ConnectError);
        assert.equal(error.code, Code.Canceled);
        return true;
    });
    await fetching;
    controller.abort(new DOMException('page changed', 'AbortError'));
    release();
    await rejected;
    assert.equal(finalized, false);
});

test('standalone WASM verifies full history48 values and rejects changed context', async (t) => {
    // Native history values verify directly against the certified root and tip.
    const fixture = await readFixture<{
        root: string; tip: string; proof: string; operations: Array<{ location: string; digest: string; value: string }>;
    }>('transactionActivityProof');
    const skip = nativeFixtureSkip(nativeActivityFixtureIssue(fixture));
    if (skip) { t.skip(skip); return; }
    const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });
    const expected = fixture.operations.map((operation) => ({ location: BigInt(operation.location), value: fromHex(operation.value) }));
    const prove = (root = fromHex(fixture.root), tip = BigInt(fixture.tip), entries = expected, proof = fromHex(fixture.proof)) =>
        verifier.verifyFixedKeylessAppendMany(proof, { tip }, root, entries);
    const verified = await prove();
    assert.equal(verified.proofSizeBytes, fixture.proof.length / 2);
    assert.deepEqual(verified.operations.map(({ location }) => location), expected.map(({ location }) => location));

    // Changing the root, tip, a location, a full history value, or a proof byte must fail.
    await assert.rejects(prove(new Uint8Array(32)));
    await assert.rejects(prove(undefined, BigInt(fixture.tip) + 1n));
    await assert.rejects(prove(undefined, undefined, expected.map((entry, index) => index === 0 ? { ...entry, location: 0n } : entry)));
    await assert.rejects(prove(undefined, undefined, expected.map((entry, index) => index === 0 ? { ...entry, value: new Uint8Array(48) } : entry)));
    for (const offset of [32, 40]) {
        const entries = structuredClone(expected);
        entries[0]!.value[offset] ^= 1;
        await assert.rejects(prove(undefined, undefined, entries));
    }
    const proof = fromHex(fixture.proof); proof[proof.length - 1] ^= 1;
    await assert.rejects(prove(undefined, undefined, undefined, proof));
});

test('certified header binding consumes every byte after the signed commitment', async () => {
    // The certificate header is the commitment followed by the block header it commits to.
    const header = executionHeader();
    const digest = await hash(header);
    const payload = concat(digest, new Uint8Array(68));
    const certificate: VerifiedSimplexCertificate = {
        epoch: 0n, view: 77n, parent: 8n, scheme: 'bls12381-threshold-standard-min-sig',
        payload, header: concat(payload, header), certificate: new Uint8Array(),
    };
    const target = await finalizedTargetFromCertificate(certificate);
    assert.equal(target.height, 1n);
    assert.equal(target.view, 77n);
    assert.equal(target.contextView, 9n);
    assert.equal(target.timestampMs, 0n);

    // Trailing bytes, a commitment mismatch, and a header digest mismatch are each rejected.
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, header: concat(certificate.header, new Uint8Array([0])) }), /trailing bytes/);
    const wrong = payload.slice(); wrong[0] ^= 1;
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, payload: wrong }), /does not match certificate payload/);
    await assert.rejects(finalizedTargetFromCertificate({ ...certificate, payload: wrong, header: concat(wrong, header) }), /header digest/);
});

test('header decoding rejects noncanonical and overflowing varints even with matching hashes', async () => {
    // A matching digest does not excuse a noncanonical or overflowing epoch varint.
    for (const header of [
        executionHeader(new Uint8Array([0x80, 0])),
        executionHeader(new Uint8Array([...Array<number>(9).fill(0xff), 2])),
    ]) await assert.rejects(authenticatedHeader(header, await hash(header), 1n), /canonical|exceeds u64/);

    // A valid header must still match the expected height and digest.
    const header = executionHeader();
    await assert.rejects(authenticatedHeader(header, await hash(header), 2n), /chain height/);
    const mutated = header.slice(); mutated[mutated.length - 1] ^= 1;
    await assert.rejects(authenticatedHeader(mutated, await hash(header), 1n), /certified digest/);
});

test('header timestamps retain canonical milliseconds within the protocol bound', async () => {
    for (const timestamp of [0n, 7_258_118_400_000n]) {
        const header = executionHeader(undefined, timestamp);
        assert.equal((await authenticatedHeader(header, await hash(header), 1n)).timestampMs, timestamp);
    }
    const header = executionHeader(undefined, 7_258_118_400_001n);
    await assert.rejects(authenticatedHeader(header, await hash(header), 1n), /timestamp exceeds protocol maximum/);
});

/** Encodes a minimal block header at height 1 with nonempty state and transaction ranges. */
function executionHeader(epoch = new Uint8Array([0]), timestamp = 0n): Uint8Array {
    return concat(epoch, new Uint8Array([9]), new Uint8Array(32), new Uint8Array([8]),
        new Uint8Array(100), new Uint8Array(32), u64(1n), u64(timestamp),
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
