import { DataType, SqlClient, type Table } from '@exowarexyz/sql';

export const ANALYSIS_ROW_LIMIT = 1000;
export const ANALYSIS_SQL_LIMIT = 65535;
export const ANALYSIS_TIMEOUT_MS = 30000;

export type AnalysisKind = 'number' | 'time' | 'text' | 'binary' | 'boolean' | 'other';
export interface AnalysisColumn {
    readonly name: string;
    readonly type: string;
    readonly kind: AnalysisKind;
    readonly nullable: boolean;
}
export interface AnalysisCell {
    readonly value: string | number | bigint | boolean | null;
    readonly text: string;
    readonly numeric: number | null;
}
export interface AnalysisResult {
    readonly columns: AnalysisColumn[];
    readonly rows: AnalysisCell[][];
    readonly truncated: boolean;
    readonly stats: {
        readonly rowCount: number;
        readonly columnCount: number;
        readonly batchCount: number;
        readonly sequenceNumber: bigint | undefined;
        readonly elapsedMs: number;
    };
}
export interface AnalysisPreset {
    readonly id: string;
    readonly title: string;
    readonly description: string;
    readonly sql: string;
    readonly requiresAccount?: boolean;
}

const COMMANDS = new Set([
    'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE',
    'COPY', 'EXEC', 'EXECUTE', 'CALL', 'SET', 'RESET', 'PREPARE', 'DEALLOCATE',
    'GRANT', 'REVOKE', 'VACUUM', 'ANALYZE', 'ATTACH', 'DETACH', 'INSTALL',
    'LOAD', 'EXPORT', 'IMPORT', 'INTO', 'PRAGMA', 'KILL',
]);

/** Accepts one SELECT/WITH query with ANSI quotes; this is an editor guard, not access control. */
export function prepareAnalysisQuery(input: string): string {
    if (input.length > ANALYSIS_SQL_LIMIT) throw new Error('SQL exceeds 65,535 characters');
    const parts: string[] = [];
    let firstWord: string | undefined;
    let depth = 0;
    let ended = false;
    for (let i = 0; i < input.length;) {
        const char = input[i];
        if (/\s/.test(char)) { parts.push(char); i++; continue; }
        if (input.startsWith('--', i)) {
            const end = input.indexOf('\n', i + 2);
            i = end < 0 ? input.length : end;
            parts.push(' ');
            continue;
        }
        if (input.startsWith('/*', i)) {
            let comments = 1;
            i += 2;
            while (comments && i < input.length) {
                if (input.startsWith('/*', i)) { comments++; i += 2; }
                else if (input.startsWith('*/', i)) { comments--; i += 2; }
                else i++;
            }
            if (comments) throw new Error('Unclosed SQL comment');
            parts.push(' ');
            continue;
        }
        if (ended) throw new Error('Run one SELECT or WITH query at a time');
        if (char === "'" || char === '"') {
            const start = i++;
            let closed = false;
            while (i < input.length) {
                if (input[i] === '\\') throw new Error('Use doubled ANSI quotes instead of backslash escapes');
                if (input[i++] !== char) continue;
                if (input[i] === char) { i++; continue; }
                closed = true;
                break;
            }
            if (!closed) throw new Error('Unclosed SQL quote');
            parts.push(input.slice(start, i));
            continue;
        }
        if (/[A-Za-z_]/.test(char)) {
            const start = i++;
            while (i < input.length && /[A-Za-z_0-9]/.test(input[i])) i++;
            const word = input.slice(start, i).toUpperCase();
            firstWord ??= word;
            if (COMMANDS.has(word)) throw new Error(`The analysis editor does not run ${word} statements`);
            parts.push(input.slice(start, i));
            continue;
        }
        if (char === '(') depth++;
        if (char === ')' && --depth < 0) throw new Error('Unbalanced SQL parentheses');
        if (char === ';') {
            if (depth) throw new Error('Run one SELECT or WITH query at a time');
            ended = true;
            i++;
            continue;
        }
        if (char === '$' || char === '`' || char === '\\' || char.charCodeAt(0) < 32) {
            throw new Error('Use SELECT/WITH with ANSI single and double quotes');
        }
        parts.push(char);
        i++;
    }
    if (depth) throw new Error('Unbalanced SQL parentheses');
    if (firstWord !== 'SELECT' && firstWord !== 'WITH') throw new Error('Start with SELECT or WITH');
    const query = `SELECT * FROM (\n${parts.join('').trim()}\n) AS analysis_result LIMIT ${ANALYSIS_ROW_LIMIT + 1}`;
    if (query.length > ANALYSIS_SQL_LIMIT) throw new Error('SQL including the result limit exceeds 65,535 characters');
    return query;
}

function columnKind(type: DataType): AnalysisKind {
    if (DataType.isInt(type) || DataType.isFloat(type) || DataType.isDecimal(type)) return 'number';
    if (DataType.isTimestamp(type) || DataType.isDate(type)) return 'time';
    if (DataType.isBinary(type) || DataType.isLargeBinary(type) || DataType.isFixedSizeBinary(type)) return 'binary';
    if (DataType.isBool(type)) return 'boolean';
    if (DataType.isUtf8(type) || DataType.isLargeUtf8(type)) return 'text';
    return 'other';
}

function stringify(value: unknown): string {
    if (typeof value === 'string') return value;
    try {
        return JSON.stringify(value, (_key, item: unknown) => typeof item === 'bigint' ? item.toString() : item) ?? String(value);
    } catch { return String(value); }
}

function cell(value: unknown, type: DataType, kind: AnalysisKind): AnalysisCell {
    if (value === null || value === undefined) return { value: null, text: 'NULL', numeric: null };
    if (kind === 'binary' && value instanceof Uint8Array) {
        const text = '0x' + Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
        return { value: text, text, numeric: null };
    }
    if (DataType.isDecimal(type)) {
        const raw = String(value);
        const negative = raw.startsWith('-');
        const digits = (negative ? raw.slice(1) : raw).padStart(type.scale + 1, '0');
        const text = (negative ? '-' : '') + (type.scale > 0
            ? `${digits.slice(0, -type.scale)}.${digits.slice(-type.scale)}`
            : digits + '0'.repeat(-type.scale));
        return { value: text, text, numeric: null };
    }
    if (typeof value === 'bigint') {
        const numeric = value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
        return { value, text: value.toString(), numeric };
    }
    if (typeof value === 'number') {
        const finite = Number.isFinite(value);
        const date = kind === 'time' && finite ? new Date(value) : undefined;
        const text = date && Number.isFinite(date.getTime()) ? date.toISOString() : String(value);
        return { value, text, numeric: finite ? value : null };
    }
    if (typeof value === 'boolean') return { value, text: String(value), numeric: null };
    const text = stringify(value);
    return { value: text, text, numeric: null };
}

export function normalizeAnalysisResult(table: Table, sequenceNumber: bigint | undefined, elapsedMs: number): AnalysisResult {
    const columns = table.schema.fields.map(field => ({
        name: field.name, type: field.type.toString(), kind: columnKind(field.type), nullable: field.nullable,
    }));
    const vectors = columns.map((_column, index) => table.getChildAt(index));
    const rowCount = Math.min(table.numRows, ANALYSIS_ROW_LIMIT);
    const rows = Array.from({ length: rowCount }, (_row, row) => columns.map((column, index) =>
        cell(vectors[index]?.get(row), table.schema.fields[index].type, column.kind)));
    return {
        columns, rows, truncated: table.numRows > ANALYSIS_ROW_LIMIT,
        stats: { rowCount, columnCount: columns.length, batchCount: table.batches.length, sequenceNumber, elapsedMs },
    };
}

/** The duration includes the network request and Arrow decoding, not just server execution. */
export async function runAnalysis(endpoint: string, sql: string, signal: AbortSignal): Promise<AnalysisResult> {
    const query = prepareAnalysisQuery(sql);
    signal.throwIfAborted();
    const start = performance.now();
    const client = SqlClient.fixed(endpoint, undefined, {
        retry: { maxAttempts: 1, initialBackoffMs: 100, maxBackoffMs: 2000 },
    });
    const { table, sequenceNumber } = await client.query(query, undefined, { signal, timeoutMs: ANALYSIS_TIMEOUT_MS });
    signal.throwIfAborted();
    const result = normalizeAnalysisResult(table, sequenceNumber, 0);
    return { ...result, stats: { ...result.stats, elapsedMs: performance.now() - start } };
}

export function analysisPresets(latestHeight: bigint, account?: string): AnalysisPreset[] {
    if (latestHeight < 1n || latestHeight > (1n << 64n) - 1n) throw new Error('Height must fit a positive u64');
    const key = account?.trim().replace(/^0x/i, '');
    if (key !== undefined && !/^[0-9a-f]{64}$/i.test(key)) throw new Error('Account must be 32-byte hex');
    const accountFilter = key ? `account = X'${key.toLowerCase()}'` : 'FALSE';
    const lower = latestHeight > 99n ? latestHeight - 99n : 1n;
    const window = `height >= ${lower} AND height <= ${latestHeight}`;
    return [
        { id: 'blocks', title: 'Recent blocks', description: 'Transactions per block and the publisher’s observed finalization time.', sql: `SELECT height, tx_count, finalized_ts\nFROM block_meta WHERE ${window}\nORDER BY height DESC LIMIT 100` },
        { id: 'balance', title: 'Indexed balance history', requiresAccount: !key, description: (key ? '' : 'Choose an account to use this example. ') + 'Balance by state operation location; these rows have no wall-clock timestamp.', sql: `SELECT qmdb_location, balance, nonce_base\nFROM account_meta WHERE ${accountFilter}\nORDER BY qmdb_location DESC LIMIT 100` },
        { id: 'activity', title: 'Account transfers', requiresAccount: !key, description: (key ? '' : 'Choose an account to use this example. ') + 'Recent indexed activity: role 0 sent, role 1 received. Self-transfers have one sender row.', sql: `SELECT height, "index", role, value, nonce\nFROM tx_activity WHERE ${accountFilter}\nORDER BY height DESC, "index" DESC, role DESC LIMIT 100` },
        { id: 'summary', title: 'Recent block summary', description: 'Totals over the same bounded block-height window.', sql: `SELECT COUNT(*) AS blocks, SUM(tx_count) AS transactions\nFROM block_meta WHERE ${window}` },
        { id: 'transactions', title: 'Transaction sample', description: 'The first 100 indexed transactions in digest-key order, not the newest transactions.', sql: 'SELECT tx_digest, height, qmdb_location\nFROM tx_meta LIMIT 100' },
    ];
}
