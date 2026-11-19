import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import type {
    SimplexFinalizationVerificationContext,
    SimplexNotarizationVerificationContext,
} from '@exowarexyz/simplex';

import { createCertificateVerifier, quorum, reportVerdicts, status } from '../src/certificate.ts';

// Certificates signed by the validators' vote scheme. A Rust test pins the same
// file (crates/auth/src/scheme.rs, certificates_match_the_shared_vectors).
const vectors = JSON.parse(
    readFileSync(new URL('../../../crates/auth/testdata/certificates.json', import.meta.url), 'utf8'),
) as { namespace: string; validators: string; payloadBytes: number; notarization: string; finalization: string };

const HEADER = new TextEncoder().encode('header');

function fromHex(hex: string): Uint8Array {
    return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function verifier(validators = fromHex(vectors.validators)) {
    return createCertificateVerifier({
        namespace: fromHex(vectors.namespace),
        validators,
        payloadBytes: vectors.payloadBytes,
    });
}

const finalizationContext = {
    kind: 'finalization', index: 'height', height: 1n, key: new Uint8Array(), value: new Uint8Array(), source: 'get',
} as SimplexFinalizationVerificationContext;

const notarizationContext = (view: bigint) => ({
    kind: 'notarization', epoch: 0n, view, key: new Uint8Array(), value: new Uint8Array(), source: 'get',
}) as SimplexNotarizationVerificationContext;

test('a finalization signed by five of six validators verifies', async () => {
    const certificate = await verifier().verifyFinalization(fromHex(vectors.finalization), finalizationContext);
    assert.ok(certificate);
    assert.equal(certificate.epoch, 0n);
    assert.equal(certificate.view, 2n);
    assert.equal(certificate.parent, 1n);
    assert.deepEqual(certificate.payload, new Uint8Array(32).fill(2));
    assert.deepEqual(certificate.signers, [0, 1, 2, 4, 5]);
    assert.deepEqual(certificate.header, HEADER);
    // Finalize votes report nothing.
    assert.ok(certificate.reports.every((report) => report.length === 1 && report[0] === 0));
});

test('a notarization carries the reports that fix the status of tagged transactions', async () => {
    const certificate = await verifier().verifyNotarization(fromHex(vectors.notarization), notarizationContext(2n));
    assert.ok(certificate);
    assert.deepEqual(certificate.signers, [0, 1, 2, 4, 5]);

    // All approve the first of three transactions, validators 0 to 2 the second and
    // validators 0 and 1 the third. Three approvals are needed.
    const verdicts = certificate.reports.map((report) => reportVerdicts(report, 3));
    assert.deepEqual(verdicts, [
        [true, true, true],
        [true, true, true],
        [true, true, false],
        [true, false, false],
        [true, false, false],
    ]);
    assert.deepEqual(status(certificate.reports, 6, 3), [true, true, false]);

    // A report for a block with fewer transactions approves nothing.
    assert.equal(reportVerdicts(certificate.reports[2], 2), null);
    assert.deepEqual(status(certificate.reports, 6, 2), [false, false]);
});

test('a certificate for another round does not answer a request by round', async () => {
    const bytes = fromHex(vectors.notarization);
    assert.equal(await verifier().verifyNotarization(bytes, notarizationContext(3n)), null);
});

test('a vote kind is not another', async () => {
    assert.equal(await verifier().verifyFinalization(fromHex(vectors.notarization), finalizationContext), null);
    assert.equal(await verifier().verifyNotarization(fromHex(vectors.finalization), notarizationContext(2n)), null);
});

test('tampering is rejected', async () => {
    const bytes = fromHex(vectors.finalization);
    const payloadStart = 3;
    const bitmap = payloadStart + vectors.payloadBytes + 8;
    const firstSignature = bitmap + 1 + 1 + 1;

    for (const offset of [0, 1, 2, payloadStart, firstSignature, firstSignature + 63]) {
        const tampered = bytes.slice();
        tampered[offset] ^= 1;
        assert.equal(await verifier().verifyFinalization(tampered, finalizationContext), null, `offset ${offset}`);
    }

    // Claiming a sixth signer without a sixth vote.
    const extra = bytes.slice();
    extra[bitmap] |= 1 << 3;
    assert.equal(await verifier().verifyFinalization(extra, finalizationContext), null);

    // The header is not signed: it is bound by the payload, which callers check.
    const header = bytes.slice();
    header[header.length - 1] ^= 1;
    assert.ok(await verifier().verifyFinalization(header, finalizationContext));

    for (const length of [0, 10, bitmap, firstSignature + 10]) {
        assert.equal(await verifier().verifyFinalization(bytes.slice(0, length), finalizationContext), null);
    }
});

test('another committee does not verify the certificate', async () => {
    const validators = fromHex(vectors.validators);
    // The same keys in another order: votes are attributed by index.
    const swapped = validators.slice();
    swapped.set(validators.slice(32, 64), 0);
    swapped.set(validators.slice(0, 32), 32);
    assert.equal(await verifier(swapped).verifyFinalization(fromHex(vectors.finalization), finalizationContext), null);

    // A committee of five has no sixth validator.
    assert.equal(
        await verifier(validators.slice(0, 5 * 32)).verifyFinalization(fromHex(vectors.finalization), finalizationContext),
        null,
    );
    assert.throws(() => verifier(validators.slice(0, 33)), /32-byte key per validator/);
});

test('a certificate needs n - f votes', () => {
    assert.deepEqual([1, 5, 6, 10, 11, 16, 50, 256].map(quorum), [1, 5, 5, 9, 9, 13, 41, 205]);
});
