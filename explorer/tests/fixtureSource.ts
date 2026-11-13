import { readFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';

type FixtureName = 'proofBundle' | 'transactionActivityProof' | 'blockFeed';
type RecordValue = Record<string, unknown>;

function record(value: unknown): RecordValue | undefined {
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : undefined;
}

const bundleNames = [
    'directBlock', 'descendantBlock', 'descendantLastPage', 'emptyBlock', 'accountBundle',
    'accountNext', 'accountOldest', 'accountExhausted', 'accountStateOnly', 'recipientBundle',
    'transactionBundle', 'webauthnBlock', 'webauthnBundle',
    'accountWithHistory', 'historicalBlock', 'historicalTransaction',
];

const decimal = (value: unknown) => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value) && BigInt(value) < (1n << 64n);

export function nativeProofFixtureIssue(value: unknown): string | undefined {
    const fixture = record(value);
    for (const name of bundleNames) {
        const bundle = record(fixture?.[name]);
        if (!bundle || !Array.isArray(bundle.transactions)) return `missing ${name} bundle`;
        if (bundle.account !== null) {
            const account = record(bundle.account);
            if (!account || !decimal(account.writeHeight)) return `${name} lacks account writeHeight`;
            if (typeof account.encodedOperation !== 'string') return `${name} lacks a current account update operation`;
        }
        for (const value of bundle.transactions) {
            const row = record(value);
            if (!row || !decimal(row.senderIndex) || !decimal(row.recipientIndex)) {
                return `${name} lacks decimal senderIndex/recipientIndex for history48`;
            }
        }
    }
    return undefined;
}

export function nativeActivityFixtureIssue(value: unknown): string | undefined {
    const fixture = record(value);
    if (!Array.isArray(fixture?.operations) || !fixture.operations.length) return 'missing history operations';
    for (const value of fixture.operations) {
        const operation = record(value);
        if (!operation || typeof operation.value !== 'string' || !/^[0-9a-f]{96}$/.test(operation.value)) {
            return 'operations lack the full 48-byte value';
        }
    }
    return undefined;
}

export async function readFixture<T>(name: FixtureName): Promise<T> {
    const directory = process.env.EXPLORER_FIXTURE_DIR;
    if (directory !== undefined && !isAbsolute(directory)) throw new Error('EXPLORER_FIXTURE_DIR must be an absolute path');
    const path = directory === undefined ? new URL(`../../tests/fixtures/${name}.json`, import.meta.url) : join(directory, `${name}.json`);
    let value: unknown;
    try {
        value = JSON.parse(await readFile(path, 'utf8'));
    } catch (error) {
        throw new Error(`Cannot load ${name}.json from ${directory ?? 'checked-in fixtures'}`, { cause: error });
    }
    if (directory !== undefined) {
        const issue = name === 'proofBundle' ? nativeProofFixtureIssue(value)
            : name === 'transactionActivityProof' ? nativeActivityFixtureIssue(value)
                : ['afterZero', 'bootstrap', 'resumed', 'first', 'emptyFirst', 'conflictingFirst']
                    .find((key) => !record(record(value)?.[key]));
        if (issue) throw new Error(`EXPLORER_FIXTURE_DIR ${name}.json is not a native account32/history48 fixture: ${issue}`);
    }
    return value as T;
}

export function nativeFixtureSkip(issue: string | undefined): string | false {
    return issue === undefined ? false : `Native account32/history48 fixture required: ${issue}. Set EXPLORER_FIXTURE_DIR to freshly exported fixtures.`;
}
