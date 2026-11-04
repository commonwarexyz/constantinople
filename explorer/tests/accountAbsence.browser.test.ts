import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';
import { build } from 'esbuild';
import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { fromHex, toHex } from '../src/codec.ts';
import { ProofBundleSchema } from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';
import { nativeProofFixtureIssue, readFixture } from './fixtureSource.ts';
import { explorerFetch } from './rpcTest.ts';

const cdp = process.env.CPL_BROWSER_CDP;
const playwright = process.env.EXPLORER_PLAYWRIGHT_MODULE;

/** The caller owns Chrome, its private quota, deadline and process cleanup. */
test('browser verifies native account absence before rendering both views', {
    skip: !cdp || !playwright ? 'Provide governed CPL_BROWSER_CDP and EXPLORER_PLAYWRIGHT_MODULE' : false,
    timeout: 45_000,
}, async () => {
    const fixture = await readFixture<Record<string, any>>('proofBundle');
    assert.equal(nativeProofFixtureIssue(fixture), undefined);
    const source = fileURLToPath(new URL('../../', import.meta.url));
    const sourceFiles = ['src/App.tsx', 'src/SearchForm.tsx', 'src/search.ts', 'src/Age.tsx', 'src/blockRecency.ts', 'src/accountProof.ts',
        'src/proofBundle.ts', 'src/qmdb.ts', 'src/styles.css', 'src/gen/constantinople/explorer/v1/explorer_pb.ts',
        'src/gen/account_wasm/constantinople_account_proof.js', 'src/gen/account_wasm/constantinople_account_proof_bg.wasm'];
    const pins = async () => Object.fromEntries(await Promise.all(sourceFiles.map(async file =>
        [file, createHash('sha256').update(await readFile(join(source, file))).digest('hex')])));
    const before = await pins();
    const bundle = await build({
        stdin: { contents: harness, loader: 'tsx', resolveDir: source, sourcefile: 'account-absence-browser.tsx' },
        bundle: true, write: false, platform: 'browser', format: 'esm', jsx: 'automatic',
        define: { 'import.meta.env': JSON.stringify({ VITE_INDEXER_URL: 'https://constantinople.invalid', VITE_SIMPLEX_VERIFICATION_MATERIAL: fixture.verificationMaterial }), 'process.env.NODE_ENV': '"production"' },
        plugins: [{ name: 'expose-view-components', setup(builder) {
            builder.onLoad({ filter: /\/src\/App\.tsx$/ }, async ({ path }) => ({
                contents: await readFile(path, 'utf8') + '\nexport { AccountPage, WalletPanel };\n', loader: 'tsx',
            }));
        } }],
    });
    const binary = async (path: URL) => (await readFile(path)).toString('base64');
    const binaries = await Promise.all([
        binary(new URL('./generated/wasm/exoware_qmdb_wasm_bg.wasm', import.meta.resolve('@exowarexyz/qmdb'))),
        binary(new URL('./generated/wasm/exoware_simplex_wasm_bg.wasm', import.meta.resolve('@exowarexyz/simplex/wasm'))),
        binary(new URL('../../src/gen/account_wasm/constantinople_account_proof_bg.wasm', import.meta.url)),
    ]);
    const { chromium } = await import(playwright!);
    const browser = await chromium.connectOverCDP(cdp!, { timeout: 5_000 });
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: 'block', acceptDownloads: false });
    const report: Record<string, unknown> = { fixture: process.env.EXPLORER_FIXTURE_DIR ?? 'checked-in', sourcePins: before, bundleSha256: createHash('sha256').update(bundle.outputFiles[0]!.contents).digest('hex'), cases: [] };
    const errors: string[] = [];
    const searchRequests: string[] = [];
    const searchRpc = explorerFetch({
        search(request) {
            assert.equal(toHex(request.value), '00'.repeat(32));
            searchRequests.push('Search');
            throw new ConnectError('no indexed match', Code.NotFound);
        },
        getAccount(request) {
            assert.equal(toHex(request.account), '00'.repeat(32));
            searchRequests.push('GetAccount');
            const wire = fixture.unknownAccount;
            return create(ProofBundleSchema, {
                certificate: fromHex(wire.certificate), headers: wire.headers.map(fromHex), sequenceNumber: BigInt(wire.sequenceNumber),
                account: { location: 0n, proof: fromHex(wire.account.proof), writeHeight: 0n, claim: { case: 'exclusion', value: true } },
            });
        },
    });
    try {
        await context.route('**/*', async (route: any) => {
            if (route.request().url() === 'https://constantinople.invalid/') {
                await route.fulfill({ contentType: 'text/html', body: '<!doctype html><html><body><div id="root"></div></body></html>' });
            } else if (/\/constantinople\.explorer\.v1\.ExplorerService\/(Search|GetAccount)$/.test(new URL(route.request().url()).pathname)) {
                const request = route.request();
                const response = await searchRpc(request.url(), { method: request.method(), headers: request.headers(), body: request.postDataBuffer() });
                const headers: Record<string, string> = {};
                response.headers.forEach((value, name) => { headers[name] = value; });
                await route.fulfill({ status: response.status, headers, body: Buffer.from(await response.arrayBuffer()) });
            } else await route.abort();
        });
        await context.routeWebSocket('**/*', (socket: any) => socket.close());
        const page = await context.newPage();
        page.on('pageerror', (error: Error) => errors.push(error.message));
        await page.goto('https://constantinople.invalid/', { waitUntil: 'domcontentloaded' });
        await page.addStyleTag({ content: await readFile(join(source, 'src/styles.css'), 'utf8') });
        await page.addScriptTag({ type: 'module', content: bundle.outputFiles[0]!.text });
        await page.waitForFunction(() => typeof (window as any).initialize === 'function');
        await page.evaluate((bytes: string[]) => (window as any).initialize(bytes), binaries);
        const render = (raw: unknown, key: string, delta = 0) => page.evaluate(
            (input: unknown) => (window as any).renderVerified(input), { raw, key, material: fixture.verificationMaterial, delta },
        );
        await render(fixture.unknownAccount, '00'.repeat(32));
        await page.waitForFunction(() => document.querySelectorAll('.age--recent').length === 2);
        const absence = page.locator('.account-proof-grid__cell').filter({ hasText: / loc \d+/ }).filter({ hasText: 'ACCOUNT PROOF' });
        assert.equal(await absence.count(), 2);
        assert.equal(await page.locator('.account-proof-grid__details .account-proof-grid__cell').filter({ hasText: 'balance' }).locator('strong').innerText(), '—');
        assert.equal(await page.locator('.wallet__cell').filter({ hasText: 'balance' }).locator('strong').innerText(), '—');
        assert.doesNotMatch(await page.locator('.account-proof-grid__details').innerText(), /nonce|txs/);
        assert.doesNotMatch(await page.locator('.wallet__grid').innerText(), /nonce \d|txs|loc \d+ \/ h/);
        assert.equal(await page.locator('.account-tx-row').count(), 0);
        assert.equal(await page.locator('.account-page__pager').count(), 0);
        assert.equal(await absence.first().innerText(), await absence.last().innerText());
        assert.match(await absence.first().innerText(), /ACCOUNT PROOF\n([0-9a-f]{4}…[0-9a-f]{4} ‹ [0-9a-f]{4}…[0-9a-f]{4}|empty state) \/ loc \d+$/);
        const certs = page.locator('.account-proof-grid__cell').filter({ hasText: 'BLOCK CERT' });
        assert.equal(await certs.count(), 2);
        assert.match(await certs.first().innerText(), /BLOCK CERT\nh\d+ \/ v\d+\s\(0s ago\)$/);
        const ageColors = () => page.locator('.age').evaluateAll((nodes: Element[]) => nodes.map(node => getComputedStyle(node).color));
        assert.deepEqual(await ageColors(), ['rgb(63, 185, 80)', 'rgb(63, 185, 80)']);
        for (const width of [1440, 390]) {
            await page.setViewportSize({ width, height: 1000 });
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        }
        await page.evaluate(() => { (window as any).clockNow += 61_000; });
        await page.waitForFunction(() => document.querySelectorAll('.age--stale').length === 2);
        assert.match(await certs.first().innerText(), /\(1m ago\)$/);
        assert.deepEqual(await ageColors(), ['rgb(255, 107, 107)', 'rgb(255, 107, 107)']);
        assert.deepEqual(await absence.locator('strong').evaluateAll((nodes: Element[]) => nodes.map(node => getComputedStyle(node).color)), ['rgb(63, 185, 80)', 'rgb(63, 185, 80)']);
        await render(fixture.unknownAccount, '00'.repeat(32), -6_000);
        await page.waitForFunction(() => document.querySelectorAll('.age--ahead').length === 2);
        assert.deepEqual(await ageColors(), ['rgb(255, 178, 0)', 'rgb(255, 178, 0)']);

        const wrongRoot = structuredClone(fixture.unknownAccount);
        wrongRoot.certificate = fixture.directBlock.certificate;
        const wrongType = structuredClone(fixture.unknownAccount);
        delete wrongType.account.exclusion;
        wrongType.account.encodedOperation = fixture.accountBundle.account.encodedOperation;
        const forgedProof = structuredClone(fixture.unknownAccount);
        forgedProof.account.proof = forgedProof.account.proof.slice(0, -2);
        for (const [name, raw, key] of [
            ['key', fixture.unknownAccount, fixture.account],
            ['root', wrongRoot, '00'.repeat(32)],
            ['type', wrongType, '00'.repeat(32)],
            ['proof', forgedProof, '00'.repeat(32)],
        ]) {
            await assert.rejects(render(raw, key));
            assert.equal(await absence.count(), 0, `${name} forgery rendered absence`);
        }
        await render(fixture.emptyAccount, '00'.repeat(32));
        assert.equal(await absence.count(), 2);
        await render(fixture.accountBundle, fixture.account);
        assert.equal(await absence.count(), 0);
        assert.match(await page.locator('.wallet__cell').filter({ hasText: 'balance' }).innerText(), /\nnonce \d+ \/ \d+ txs$/);
        assert.match(await page.locator('.wallet__evidence').innerText(), /ACCOUNT PROOF\nloc \d+ \/ h\d+$/);
        assert.equal(await page.locator('.account-tx-row').count(), 10);
        assert.equal(await page.locator('.account-page__pager').count(), 1);
        assert.equal(await page.getByRole('tablist').count(), 0);
        await render(fixture.unknownAccount, '00'.repeat(32));
        await page.evaluate(() => (window as any).startApp());
        await page.getByRole('textbox', { name: 'address or transaction hash' }).fill('00'.repeat(32));
        await page.getByRole('button', { name: 'search', exact: true }).click();
        await page.waitForFunction(() => document.querySelectorAll('.account-page .age--recent').length === 1);
        assert.equal(new URL(page.url()).searchParams.get('account'), '00'.repeat(32));
        assert.deepEqual(searchRequests, ['Search', 'GetAccount']);
        assert.match(await page.locator('.account-page .account-proof-grid__cell').filter({ hasText: 'ACCOUNT PROOF' }).innerText(), /ACCOUNT PROOF\n[0-9a-f]{4}…[0-9a-f]{4} ‹ [0-9a-f]{4}…[0-9a-f]{4} \/ loc \d+$/);
        assert.equal(await page.locator('.account-proof-grid__details .account-proof-grid__cell').filter({ hasText: 'balance' }).locator('strong').innerText(), '—');
        assert.equal(await page.locator('.account-tx-row').count(), 0);
        assert.equal(await page.locator('.account-page__pager').count(), 0);
        assert.equal(await page.getByRole('status').filter({ hasText: 'no indexed match' }).count(), 0);
        assert.equal(errors.length, 0, errors.join('\n'));
        assert.deepEqual(await pins(), before, 'source changed during browser verification');
        report.cases = ['recent', 'absence-no-account-values', 'stale-clock-tick', 'ahead', 'key-forgery', 'root-forgery', 'type-forgery', 'proof-forgery', 'empty-database', 'inclusion-history', 'search-submit-verified-absence'];
        report.searchRequests = searchRequests;
        report.passed = true;
        const artifacts = process.env.EXPLORER_BROWSER_ARTIFACT_DIR;
        if (artifacts) {
            await mkdir(artifacts, { recursive: true });
            await page.screenshot({ path: join(artifacts, 'search-absence-mobile.png') });
        }
    } finally {
        await context.close();
        await browser.close();
        report.contextClosed = true;
        const artifacts = process.env.EXPLORER_BROWSER_ARTIFACT_DIR;
        if (artifacts) {
            await mkdir(artifacts, { recursive: true });
            await writeFile(join(artifacts, 'account-absence-browser.json'), JSON.stringify(report, null, 2));
        }
    }
});

const harness = `
import React from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import App, { AccountPage, WalletPanel } from './src/App.tsx';
import { verifyAccountBundle } from './src/proofBundle.ts';
import { initAccountProofWasm } from './src/accountProof.ts';
import { initQmdbWasm } from '@exowarexyz/qmdb';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
const root = createRoot(document.getElementById('root'));
const noop = () => {};
window.initialize = async ([qmdb, simplex, account]) => {
    const bytes = input => Uint8Array.from(atob(input), char => char.charCodeAt(0));
    await Promise.all([initQmdbWasm(bytes(qmdb)), ensureSimplexWasm({ module_or_path: bytes(simplex) }), initAccountProofWasm(bytes(account))]);
};
Date.now = () => window.clockNow ?? 0;
window.startApp = () => {
    flushSync(() => root.render(null));
    flushSync(() => root.render(<App />));
};
window.renderVerified = async ({raw,key,material,delta}) => {
    flushSync(() => root.render(null));
    const bundle = await verifyAccountBundle({indexerUrl:'https://constantinople.invalid',simplexVerificationMaterial:material,account:key},raw);
    window.clockNow = Number(bundle.target.timestampMs) + delta;
    const proof = bundle.kind === 'exclusion' ? {status:'excluded',...bundle.absence} : {status:'verified',detail:'',...bundle.account};
    const wallet = {};
    const snapshot = {height:bundle.target.height,view:bundle.target.view,timestampMs:bundle.target.timestampMs};
    const account = bundle.kind === 'exclusion' ? {kind:'exclusion',wallet,accountKey:key,snapshot,absence:{location:bundle.absence.location,span:bundle.absence.span}}
        : {kind:'inclusion',wallet,accountKey:key,snapshot,...bundle.account,nonce:{base:bundle.account.nonce,bitmap:bundle.account.nonceBitmap}};
    flushSync(() => root.render(<main className="app__main">
      <AccountPage account={key} onCopy={noop} onOpenAddress={noop} onOpenTransaction={noop} pageNumber={1} pageRequestKey="proof" retainingPage={false}
        proof={proof} target={bundle.target} transactionProofs={bundle.transactionProofs} transactions={bundle.page.rows} activityError="" loading={false}
        hasPrevious={false} hasNext={!!bundle.page.nextCursor} onPrevious={noop} onNext={noop} onRefresh={noop}/>
      <WalletPanel wallet={wallet} walletAccountKey={key} walletMessage="" account={account} accountMessage="" toKey="" value="" nonce="0" submitMessage="" isSubmitting={false}
        canClearSubmittedTransactions={false} spinner="" onCreateWallet={noop} onSignIn={noop} onSignOut={noop} onRefreshAccount={noop}
        onClearSubmittedTransactions={noop} onCopy={noop} onToKeyChange={noop} onValueChange={noop} onSubmit={noop}/>
    </main>));
    return bundle.kind;
};
`;
