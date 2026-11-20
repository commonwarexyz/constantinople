import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { SqlClient, type DecodedQueryResult, type Table } from '@exowarexyz/sql';
import { SimplexClient } from '@exowarexyz/simplex';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import { toArrayBuffer } from '../src/codec.ts';
import { fetchAndVerifyTransactionOutcome, outcomeBit } from '../src/qmdb.ts';
import { markTransactionOutcome, type SubmittedTransaction } from '../src/submissionHistory.ts';

const HEIGHT = 7n;
const FLOOR = 41n;

let storeId = 0;

test.beforeEach(() => { storeId++; });

test.before(async () => {
    const wasm = await readFile(new URL(
        './generated/wasm/exoware_simplex_wasm_bg.wasm',
        import.meta.resolve('@exowarexyz/simplex/wasm'),
    ));
    await ensureSimplexWasm({ module_or_path: wasm });
});

test('outcome bits are counted, then packed from the least significant bit', () => {
    // Ten transactions: 0, 2 and 9 were applied.
    const outcomes = encodeOutcomes([true, false, true, false, false, false, false, false, false, true]);
    assert.deepEqual([...outcomes], [0, 0, 0, 0, 0, 0, 0, 10, 0b0000_0101, 0b0000_0010]);
    assert.equal(outcomeBit(outcomes, 0n), true);
    assert.equal(outcomeBit(outcomes, 1n), false);
    assert.equal(outcomeBit(outcomes, 2n), true);
    assert.equal(outcomeBit(outcomes, 8n), false);
    assert.equal(outcomeBit(outcomes, 9n), true);

    assert.throws(() => outcomeBit(outcomes, 10n), /lists no transaction at index 10/);
    assert.throws(() => outcomeBit(outcomes.slice(0, 9), 0n), /do not match their count/);
    assert.throws(() => outcomeBit(outcomes.slice(0, 4), 0n), /truncated/);
});

test('a transaction outcome is read from the next block and bound to its header', async (t) => {
    const outcomes = encodeOutcomes([true, false, true]);
    const certificate = await childCertificate(HEIGHT + 1n, outcomes);
    const heights: string[] = [];
    t.mock.method(SimplexClient.prototype, 'getFinalizationByHeight', async (height: unknown) => {
        heights.push(String(height));
        return certificate;
    });
    let served = outcomes;
    t.mock.method(SqlClient.prototype, 'query', async (sql: string, minSequenceNumber?: bigint) => {
        assert.equal(minSequenceNumber, FLOOR);
        assert.match(sql, new RegExp(`SELECT parent_outcomes FROM block_meta WHERE height = ${HEIGHT + 1n} `));
        return queryResult({ parent_outcomes: served });
    });

    const outcome = (index: bigint, published = HEIGHT + 1n) => fetchAndVerifyTransactionOutcome({
        storeUrl: `http://store/${storeId}`,
        sqlUrl: 'http://sql',
        simplexVerificationMaterial: '11'.repeat(32),
        position: { height: HEIGHT, index },
        publishedTarget: { height: published, blockDigest: new Uint8Array(32), sequenceNumber: FLOOR },
    });

    assert.equal(await outcome(0n), 'applied');
    assert.equal(await outcome(1n), 'not applied');
    assert.equal(await outcome(2n), 'applied');
    assert.deepEqual([...new Set(heights)], [(HEIGHT + 1n).toString()]);
    await assert.rejects(outcome(3n), /lists no transaction at index 3/);

    // The next block is not covered yet: nothing is read and nothing is known.
    const reads = heights.length;
    assert.equal(await outcome(0n, HEIGHT), null);
    assert.equal(heights.length, reads);

    // Bits that the certified header does not commit to say nothing.
    served = encodeOutcomes([true, true, true]);
    await assert.rejects(outcome(1n), /do not match its certified header/);
});

test('a finalized transaction records its outcome', () => {
    const finalized = { digest: 'aa', status: 'finalized', finalizedHeight: 7, detail: 'finalized at 7' };
    const waiting = { digest: 'bb', status: 'reconciling', finalizedHeight: null, detail: 'waiting' };
    const history = [finalized, waiting] as unknown as SubmittedTransaction[];

    const applied = markTransactionOutcome('aa', 'applied', history);
    assert.equal(applied[0]!.detail, 'finalized at 7 · applied');
    assert.equal(applied[1], history[1]);
    const rejected = markTransactionOutcome('aa', 'not applied', applied);
    assert.equal(rejected[0]!.detail, 'finalized at 7 · not applied');

    // Only a finalized transaction has an outcome.
    assert.deepEqual(markTransactionOutcome('bb', 'applied', history), history);
});

function encodeOutcomes(bits: readonly boolean[]): Uint8Array {
    const encoded = new Uint8Array(8 + Math.ceil(bits.length / 8));
    new DataView(encoded.buffer).setBigUint64(0, BigInt(bits.length));
    bits.forEach((bit, index) => {
        if (bit) encoded[8 + (index >> 3)]! |= 1 << (index & 7);
    });
    return encoded;
}

// A finalization of the block at `height` whose header commits to `outcomes`.
async function childCertificate(height: bigint, outcomes: Uint8Array) {
    const sha256 = async (bytes: Uint8Array) =>
        new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes)));
    const header = concat(
        // Epoch, view, leader, parent view and parent commitment.
        new Uint8Array([0, 9]), new Uint8Array(32), new Uint8Array([8]), new Uint8Array(100),
        // Parent digest, height, timestamp.
        new Uint8Array(32), u64(height), u64(0n),
        // Digests of the parent's notarization and of the parent's outcome bits.
        new Uint8Array(32), await sha256(outcomes),
        // State and transaction targets.
        new Uint8Array(32).fill(1), u64(2n), u64(6n),
        new Uint8Array(32).fill(2), u64(2n), u64(8n),
    );
    const payload = concat(await sha256(header), new Uint8Array(68));
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

function queryResult(values: Record<string, unknown>): DecodedQueryResult {
    const table = {
        numRows: 1,
        getChild(column: string) {
            if (!Object.hasOwn(values, column)) return null;
            return { get: () => values[column] };
        },
    } as unknown as Table;
    return { sequenceNumber: FLOOR, table };
}

function u64(value: bigint): Uint8Array {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value);
    return bytes;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
    let offset = 0;
    for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
    }
    return out;
}
