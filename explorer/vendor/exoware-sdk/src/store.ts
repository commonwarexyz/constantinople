import { create, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { CallOptions } from '@connectrpc/connect';
import type { Client } from './client.js';
import { HttpError } from './error.js';
import { PruneRequestSchema } from './gen/ts/store/v1/compact_pb.js';
import type { Policy } from './gen/ts/store/v1/compact_pb.js';
import {
    BytesFilterSchema,
    KvEntrySchema,
    MatchKeySchema,
} from './gen/ts/store/v1/common_pb.js';
import type { MatchKey } from './gen/ts/store/v1/common_pb.js';
import { ErrorInfoSchema } from './gen/ts/google/rpc/error_details_pb.js';
import { PutRequestSchema } from './gen/ts/store/v1/ingest_pb.js';
import {
    GetManyRequestSchema,
    GetRequestSchema as QueryGetRequestSchema,
    RangeRequestSchema,
    ReduceRequestSchema,
    TraversalMode,
} from './gen/ts/store/v1/query_pb.js';
import type {
    Detail,
    KvExpr,
    KvFieldRef,
    KvPredicate,
    RangeReducerSpec,
    ReduceParams,
    ReduceResponse,
} from './gen/ts/store/v1/query_pb.js';
import {
    GetRequestSchema as StreamGetRequestSchema,
    SubscribeRequestSchema,
} from './gen/ts/store/v1/stream_pb.js';

const STREAM_SERVER_PAYLOAD_REGEX = '(?s-u).*';

type Buffer = Uint8Array;

type DetailObserver = (detail: Detail) => void;

export { TraversalMode };

export type { ReduceParams, ReduceResponse };

export interface GetResult {
    value: Uint8Array;
}

export interface GetManyResultItem {
    key: Uint8Array;
    value: Uint8Array | undefined;
}

export interface QueryResultItem {
    key: Uint8Array;
    value: Uint8Array;
}

export interface QueryResult {
    results: QueryResultItem[];
}

export interface StoreBatchEntry {
    key: Uint8Array;
    value: Uint8Array;
}

export interface StoreBatch {
    sequenceNumber: bigint;
    entries: StoreBatchEntry[];
}

const MAX_KEY_LEN = 254;

function prefixMask(bits: number): number {
    if (!Number.isInteger(bits) || bits < 0 || bits > 16) {
        throw new RangeError(`reservedBits must be an integer in [0, 16], got ${bits}`);
    }
    return bits === 0 ? 0 : (1 << bits) - 1;
}

function validatePrefix(reservedBits: number, prefix: number): void {
    const mask = prefixMask(reservedBits);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > mask) {
        throw new RangeError(`prefix ${prefix} does not fit in ${reservedBits} reserved bits`);
    }
}

function minKeyLenForPayload(reservedBits: number, payloadLen: number): number {
    return Math.ceil((reservedBits + payloadLen * 8) / 8);
}

function payloadCapacityForKeyLen(reservedBits: number, keyLen: number): number {
    return Math.floor((keyLen * 8 - reservedBits) / 8);
}

function readBitBe(bytes: Uint8Array, bitIdx: number): boolean {
    const byteIdx = Math.floor(bitIdx / 8);
    const bitInByte = 7 - (bitIdx % 8);
    return byteIdx < bytes.length && ((bytes[byteIdx] >> bitInByte) & 1) !== 0;
}

function writeBitBe(bytes: Uint8Array, bitIdx: number, value: boolean): void {
    const byteIdx = Math.floor(bitIdx / 8);
    const bitInByte = 7 - (bitIdx % 8);
    const mask = 1 << bitInByte;
    if (value) {
        bytes[byteIdx] |= mask;
    } else {
        bytes[byteIdx] &= ~mask;
    }
}

function writePrefixBits(bytes: Uint8Array, reservedBits: number, prefix: number): void {
    for (let bitIdx = 0; bitIdx < reservedBits; bitIdx++) {
        const shift = reservedBits - 1 - bitIdx;
        writeBitBe(bytes, bitIdx, ((prefix >> shift) & 1) !== 0);
    }
}

function readPrefixBits(bytes: Uint8Array, reservedBits: number): number {
    let prefix = 0;
    for (let bitIdx = 0; bitIdx < reservedBits; bitIdx++) {
        prefix <<= 1;
        if (readBitBe(bytes, bitIdx)) {
            prefix |= 1;
        }
    }
    return prefix;
}

function writeBitsFromBytes(
    dst: Uint8Array,
    dstBitOffset: number,
    src: Uint8Array,
    bitLen: number,
): void {
    for (let bitIdx = 0; bitIdx < bitLen; bitIdx++) {
        writeBitBe(dst, dstBitOffset + bitIdx, readBitBe(src, bitIdx));
    }
}

function readBitsToBytes(
    src: Uint8Array,
    srcBitOffset: number,
    dst: Uint8Array,
    bitLen: number,
): void {
    dst.fill(0);
    for (let bitIdx = 0; bitIdx < bitLen; bitIdx++) {
        writeBitBe(dst, bitIdx, readBitBe(src, srcBitOffset + bitIdx));
    }
}

export class StoreKeyPrefix {
    public readonly reservedBits: number;
    public readonly prefix: number;

    constructor(reservedBits: number, prefix: number) {
        validatePrefix(reservedBits, prefix);
        this.reservedBits = reservedBits;
        this.prefix = prefix;
    }

    maxLogicalKeyLen(): number {
        return Math.floor((MAX_KEY_LEN * 8 - this.reservedBits) / 8);
    }

    encodeKey(key: Uint8Array): Uint8Array {
        const maxPayloadLen = this.maxLogicalKeyLen();
        if (key.length > maxPayloadLen) {
            throw new RangeError(
                `logical key length ${key.length} exceeds prefixed capacity ${maxPayloadLen}`,
            );
        }
        const totalLen = minKeyLenForPayload(this.reservedBits, key.length);
        const out = new Uint8Array(totalLen);
        writePrefixBits(out, this.reservedBits, this.prefix);
        writeBitsFromBytes(out, this.reservedBits, key, key.length * 8);
        return out;
    }

    decodeKey(key: Uint8Array): Uint8Array {
        if (!this.matches(key)) {
            throw new RangeError('key does not belong to this store prefix');
        }
        const payloadLen = payloadCapacityForKeyLen(this.reservedBits, key.length);
        const out = new Uint8Array(payloadLen);
        readBitsToBytes(key, this.reservedBits, out, payloadLen * 8);
        return out;
    }

    matches(key: Uint8Array): boolean {
        return (
            key.length >= Math.ceil(this.reservedBits / 8) &&
            readPrefixBits(key, this.reservedBits) === this.prefix
        );
    }

    prefixBounds(): { start: Uint8Array; end: Uint8Array } {
        const start = new Uint8Array(Math.ceil(this.reservedBits / 8));
        writePrefixBits(start, this.reservedBits, this.prefix);
        const end = new Uint8Array(MAX_KEY_LEN);
        end.fill(0xff);
        writePrefixBits(end, this.reservedBits, this.prefix);
        return { start, end };
    }

    encodeRange(start?: Uint8Array, end?: Uint8Array): { start: Uint8Array; end: Uint8Array } {
        const physicalStart = this.encodeKey(start ?? new Uint8Array());
        let physicalEnd: Uint8Array;
        if (end === undefined || end.length === 0) {
            physicalEnd = this.prefixBounds().end;
        } else {
            const maxLen = this.maxLogicalKeyLen();
            physicalEnd = this.encodeKey(end.length > maxLen ? end.slice(0, maxLen) : end);
        }
        return { start: physicalStart, end: physicalEnd };
    }

    prefixMatchKey(matchKey: MessageInitShape<typeof MatchKeySchema>): MatchKey {
        return this.prefixMatchKeyWithRegex(matchKey, matchKey.payloadRegex ?? '');
    }

    prefixStreamMatchKey(matchKey: MessageInitShape<typeof MatchKeySchema>): MatchKey {
        return this.prefixMatchKeyWithRegex(matchKey, STREAM_SERVER_PAYLOAD_REGEX);
    }

    private prefixMatchKeyWithRegex(
        matchKey: MessageInitShape<typeof MatchKeySchema>,
        payloadRegex: string,
    ): MatchKey {
        const logicalReservedBits = matchKey.reservedBits ?? 0;
        const logicalPrefix = matchKey.prefix ?? 0;
        validatePrefix(logicalReservedBits, logicalPrefix);
        const reservedBits = this.reservedBits + logicalReservedBits;
        if (reservedBits > 16) {
            throw new RangeError(
                `combined reserved bits exceed 16: ${this.reservedBits} + ${logicalReservedBits}`,
            );
        }
        const prefix = (this.prefix << logicalReservedBits) | logicalPrefix;
        validatePrefix(reservedBits, prefix);
        return create(MatchKeySchema, {
            reservedBits,
            prefix,
            payloadRegex,
        });
    }
}

function toUint8Array(value: Uint8Array | Buffer): Uint8Array {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function copyBytes(value: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(toUint8Array(value));
}

function encodeStoreKey(prefix: StoreKeyPrefix | undefined, key: Uint8Array): Uint8Array {
    return prefix ? prefix.encodeKey(key) : key;
}

function decodeStoreKey(prefix: StoreKeyPrefix | undefined, key: Uint8Array): Uint8Array {
    return prefix ? prefix.decodeKey(key) : key;
}

function encodeStoreRange(
    prefix: StoreKeyPrefix | undefined,
    start?: Uint8Array,
    end?: Uint8Array,
): { start: Uint8Array; end: Uint8Array } {
    if (prefix) {
        return prefix.encodeRange(start, end);
    }
    return {
        start: start ?? new Uint8Array(),
        end: end ?? new Uint8Array(),
    };
}

export class StoreWriteBatch {
    private readonly kvs: StoreBatchEntry[] = [];

    push(client: StoreClient, key: Uint8Array, value: Uint8Array | Buffer): this {
        this.kvs.push({
            key: client.encodeStoreKey(key),
            value: copyBytes(value),
        });
        return this;
    }

    entries(): readonly StoreBatchEntry[] {
        return this.kvs;
    }

    get length(): number {
        return this.kvs.length;
    }

    clear(): void {
        this.kvs.length = 0;
    }

    async commit(client: StoreClient): Promise<bigint> {
        return client.putPrepared(this);
    }
}

function normalizeMinSequenceNumber(value?: bigint): bigint | undefined {
    return value !== undefined && value > 0n ? value : undefined;
}

function mapConnectToHttpError(err: unknown): never {
    if (err instanceof ConnectError) {
        const status = connectCodeToHttpStatus(err.code);
        throw new HttpError(status, err.message || String(err.code), err.code, err);
    }
    throw err;
}

function connectCodeToHttpStatus(code: Code): number {
    switch (code) {
        case Code.Canceled:
            return 499;
        case Code.Unknown:
            return 500;
        case Code.InvalidArgument:
            return 400;
        case Code.DeadlineExceeded:
            return 504;
        case Code.NotFound:
            return 404;
        case Code.AlreadyExists:
            return 409;
        case Code.PermissionDenied:
            return 403;
        case Code.ResourceExhausted:
            return 429;
        case Code.FailedPrecondition:
            return 400;
        case Code.Aborted:
            return 409;
        case Code.OutOfRange:
            return 400;
        case Code.Unimplemented:
            return 501;
        case Code.Internal:
            return 500;
        case Code.Unavailable:
            return 503;
        case Code.DataLoss:
            return 500;
        case Code.Unauthenticated:
            return 401;
        default:
            return 500;
    }
}

function isMissingBatchError(err: ConnectError): boolean {
    return err.findDetails(ErrorInfoSchema).some(
        (detail) =>
            detail.domain === 'store.stream' &&
            (detail.reason === 'BATCH_EVICTED' || detail.reason === 'BATCH_NOT_FOUND'),
    );
}

function toStoreBatch(
    response: {
        sequenceNumber: bigint;
        entries: { key: Uint8Array; value: Uint8Array }[];
    },
    prefix?: StoreKeyPrefix,
    logicalFilter?: ClientStreamFilter,
): StoreBatch {
    return {
        sequenceNumber: response.sequenceNumber,
        entries: response.entries.flatMap((entry) => {
            if (prefix && !prefix.matches(entry.key)) {
                return [];
            }
            return [
                {
                    key: decodeStoreKey(prefix, entry.key),
                    value: entry.value,
                },
            ];
        }).filter((entry) => !logicalFilter || logicalFilter.matches(entry.key)),
    };
}

function prefixPolicies(policies: Policy[], prefix?: StoreKeyPrefix): Policy[] {
    if (!prefix) return policies;
    return policies.map((policy) => {
        if (policy.scope.case !== 'keys') {
            return policy;
        }
        const scope = policy.scope.value;
        return {
            ...policy,
            scope: {
                case: 'keys',
                value: {
                    ...scope,
                    matchKey: scope.matchKey ? prefix.prefixMatchKey(scope.matchKey) : undefined,
                },
            },
        } as Policy;
    });
}

function prefixSubscribeFilters(
    filters: SubscribeFilters,
    prefix?: StoreKeyPrefix,
): SubscribeFilters {
    if (!prefix) return filters;
    return {
        ...filters,
        matchKeys: filters.matchKeys.map((matchKey) => prefix.prefixStreamMatchKey(matchKey)),
    };
}

function bytesToBinaryString(bytes: Uint8Array): string {
    let out = '';
    for (const byte of bytes) {
        out += String.fromCharCode(byte);
    }
    return out;
}

function compileRustBytesRegex(pattern: string): RegExp {
    if (pattern.trim() === '') {
        throw new RangeError('regex filter must not be empty');
    }
    let source = pattern;
    let flags = '';
    const inlineFlags = source.match(/^\(\?([A-Za-z-]+)\)/);
    if (inlineFlags) {
        const [enabled] = inlineFlags.slice(1);
        let disabling = false;
        for (const flag of enabled) {
            if (flag === '-') {
                disabling = true;
                continue;
            }
            if (flag === 's' || flag === 'i' || flag === 'm') {
                if (disabling) {
                    flags = flags.replace(flag, '');
                } else if (!flags.includes(flag)) {
                    flags += flag;
                }
                continue;
            }
            if (flag === 'u') {
                continue;
            }
            throw new RangeError(`unsupported regex flag '${flag}' in '${pattern}'`);
        }
        source = source.slice(inlineFlags[0].length);
    }
    source = source.replace(/\(\?P<([A-Za-z_][A-Za-z0-9_]*)>/g, '(?<$1>');
    try {
        return new RegExp(source, flags);
    } catch (e) {
        throw new RangeError(`invalid regex '${pattern}': ${e instanceof Error ? e.message : e}`);
    }
}

class ClientKeyMatcher {
    private readonly regex: RegExp;

    constructor(private readonly matchKey: MatchKey) {
        validatePrefix(matchKey.reservedBits, matchKey.prefix);
        this.regex = compileRustBytesRegex(matchKey.payloadRegex);
    }

    matches(key: Uint8Array): boolean {
        if (key.length < Math.ceil(this.matchKey.reservedBits / 8)) {
            return false;
        }
        if (readPrefixBits(key, this.matchKey.reservedBits) !== this.matchKey.prefix) {
            return false;
        }
        const payloadLen = payloadCapacityForKeyLen(this.matchKey.reservedBits, key.length);
        const payload = new Uint8Array(payloadLen);
        readBitsToBytes(key, this.matchKey.reservedBits, payload, payloadLen * 8);
        this.regex.lastIndex = 0;
        return this.regex.test(bytesToBinaryString(payload));
    }
}

class ClientStreamFilter {
    private readonly keyMatchers: ClientKeyMatcher[];

    constructor(filters: SubscribeFilters) {
        this.keyMatchers = filters.matchKeys.map(
            (matchKey) => new ClientKeyMatcher(create(MatchKeySchema, matchKey)),
        );
    }

    matches(key: Uint8Array): boolean {
        return this.keyMatchers.some((matcher) => matcher.matches(key));
    }
}

function shiftBitOffset(bitOffset: number, prefixBits: number): number {
    const shifted = bitOffset + prefixBits;
    if (shifted > 0xffff) {
        throw new RangeError(`key bit offset ${bitOffset} plus prefix bits ${prefixBits} exceeds u16`);
    }
    return shifted;
}

function prefixFieldRef(field: KvFieldRef, prefixBits: number): KvFieldRef {
    switch (field.field.case) {
        case 'key':
            return {
                ...field,
                field: {
                    case: 'key',
                    value: {
                        ...field.field.value,
                        bitOffset: shiftBitOffset(field.field.value.bitOffset, prefixBits),
                    },
                },
            } as KvFieldRef;
        case 'zOrderKey':
            return {
                ...field,
                field: {
                    case: 'zOrderKey',
                    value: {
                        ...field.field.value,
                        bitOffset: shiftBitOffset(field.field.value.bitOffset, prefixBits),
                    },
                },
            } as KvFieldRef;
        case 'value':
        case undefined:
            return field;
    }
}

function prefixExpr(expr: KvExpr, prefixBits: number): KvExpr {
    switch (expr.expr.case) {
        case 'field':
            return {
                ...expr,
                expr: {
                    case: 'field',
                    value: prefixFieldRef(expr.expr.value, prefixBits),
                },
            } as KvExpr;
        case 'add':
        case 'sub':
        case 'mul':
        case 'div':
            return {
                ...expr,
                expr: {
                    case: expr.expr.case,
                    value: {
                        ...expr.expr.value,
                        left: expr.expr.value.left
                            ? prefixExpr(expr.expr.value.left, prefixBits)
                            : undefined,
                        right: expr.expr.value.right
                            ? prefixExpr(expr.expr.value.right, prefixBits)
                            : undefined,
                    },
                },
            } as KvExpr;
        case 'lower':
        case 'dateTruncDay':
            return {
                ...expr,
                expr: {
                    case: expr.expr.case,
                    value: prefixExpr(expr.expr.value, prefixBits),
                },
            } as KvExpr;
        case 'literal':
        case undefined:
            return expr;
    }
}

function prefixPredicate(predicate: KvPredicate, prefixBits: number): KvPredicate {
    return {
        ...predicate,
        checks: predicate.checks.map((check) => ({
            ...check,
            field: check.field ? prefixFieldRef(check.field, prefixBits) : undefined,
        })),
    } as KvPredicate;
}

function prefixReducer(reducer: RangeReducerSpec, prefixBits: number): RangeReducerSpec {
    return {
        ...reducer,
        expr: reducer.expr ? prefixExpr(reducer.expr, prefixBits) : undefined,
    } as RangeReducerSpec;
}

function prefixReduceParams(params: ReduceParams, prefix?: StoreKeyPrefix): ReduceParams {
    if (!prefix) return params;
    return {
        ...params,
        reducers: params.reducers.map((reducer) => prefixReducer(reducer, prefix.reservedBits)),
        groupBy: params.groupBy.map((expr) => prefixExpr(expr, prefix.reservedBits)),
        filter: params.filter ? prefixPredicate(params.filter, prefix.reservedBits) : undefined,
    } as ReduceParams;
}

async function performGet(
    client: Client,
    key: Uint8Array,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): Promise<GetResult | null> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(QueryGetRequestSchema, {
        key: encodeStoreKey(prefix, key),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    try {
        const res = await client.query.get(req);
        if (res.detail) {
            detailObserver?.(res.detail);
        }
        if (res.value === undefined) {
            return null;
        }
        return { value: res.value };
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performGetMany(
    client: Client,
    keys: Uint8Array[],
    batchSize?: number,
    onChunk?: (entries: GetManyResultItem[]) => void,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): Promise<GetManyResultItem[]> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(GetManyRequestSchema, {
        keys: keys.map((key) => encodeStoreKey(prefix, key)),
        batchSize: batchSize ?? keys.length,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: GetManyResultItem[] = [];
    try {
        const stream = client.query.getMany(req);
        for await (const frame of stream) {
            const chunk: GetManyResultItem[] = [];
            for (const entry of frame.results) {
                chunk.push({
                    key: decodeStoreKey(prefix, entry.key),
                    value: entry.value,
                });
            }
            if (onChunk && chunk.length > 0) {
                onChunk(chunk);
            }
            results.push(...chunk);
            if (frame.detail) {
                detailObserver?.(frame.detail);
            }
        }
        return results;
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performQuery(
    client: Client,
    start?: Uint8Array,
    end?: Uint8Array,
    limit?: number,
    batchSize: number = 4096,
    mode: TraversalMode = TraversalMode.FORWARD,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): Promise<QueryResult> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const physicalRange = encodeStoreRange(prefix, start, end);
    const req = create(RangeRequestSchema, {
        start: physicalRange.start,
        end: physicalRange.end,
        batchSize,
        mode,
        ...(limit !== undefined ? { limit } : {}),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: QueryResultItem[] = [];
    try {
        const stream = client.query.range(req);
        for await (const frame of stream) {
            for (const row of frame.results) {
                results.push({ key: decodeStoreKey(prefix, row.key), value: row.value });
            }
            if (frame.detail) {
                detailObserver?.(frame.detail);
            }
        }
        return { results };
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performReduce(
    client: Client,
    start: Uint8Array,
    end: Uint8Array,
    params: ReduceParams,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): Promise<ReduceResponse> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const physicalRange = encodeStoreRange(prefix, start, end);
    const req = create(ReduceRequestSchema, {
        start: physicalRange.start,
        end: physicalRange.end,
        params: prefixReduceParams(params, prefix),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    try {
        const res = await client.query.reduce(req);
        if (res.detail) {
            detailObserver?.(res.detail);
        }
        return res;
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performGetBatch(
    client: Client,
    sequenceNumber: bigint,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<StoreBatch | null> {
    const req = create(StreamGetRequestSchema, { sequenceNumber });
    try {
        const res = await client.stream.get(req, options);
        return toStoreBatch(res, prefix);
    } catch (e) {
        if (
            e instanceof ConnectError &&
            (isMissingBatchError(e) || e.code === Code.NotFound || e.code === Code.OutOfRange)
        ) {
            return null;
        }
        mapConnectToHttpError(e);
    }
}

export interface SubscribeFilters {
    matchKeys: MessageInitShape<typeof MatchKeySchema>[];
    valueFilters?: MessageInitShape<typeof BytesFilterSchema>[];
    sinceSequenceNumber?: bigint;
}

async function* performSubscribe(
    client: Client,
    filters: SubscribeFilters,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): AsyncIterable<StoreBatch> {
    const logicalFilter = prefix ? new ClientStreamFilter(filters) : undefined;
    const prefixed = prefixSubscribeFilters(filters, prefix);
    const req = create(SubscribeRequestSchema, {
        matchKeys: prefixed.matchKeys,
        valueFilters: prefixed.valueFilters ?? [],
        ...(prefixed.sinceSequenceNumber !== undefined
            ? { sinceSequenceNumber: prefixed.sinceSequenceNumber }
            : {}),
    });
    try {
        const stream = client.stream.subscribe(req, options);
        for await (const frame of stream) {
            const batch = toStoreBatch(frame, prefix, logicalFilter);
            if (batch.entries.length === 0) {
                continue;
            }
            yield batch;
        }
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

export class SerializableReadSession {
    private sequence: bigint;
    private initGate = Promise.resolve();
    private gateLocked = false;

    constructor(
        private readonly client: Client,
        private readonly keyPrefix?: StoreKeyPrefix,
        initialSequence: bigint = 0n,
    ) {
        this.sequence = normalizeMinSequenceNumber(initialSequence) ?? 0n;
    }

    fixedSequence(): bigint | undefined {
        return normalizeMinSequenceNumber(this.sequence);
    }

    private async acquireInitGate(): Promise<() => void> {
        while (this.gateLocked) {
            await this.initGate;
        }
        this.gateLocked = true;
        let release!: () => void;
        this.initGate = new Promise<void>((resolve) => {
            release = resolve;
        });
        return () => {
            this.gateLocked = false;
            release();
        };
    }

    private async runRead<T>(
        seededCall: (sequence: bigint) => Promise<T>,
        unseededCall: (detailObserver: DetailObserver) => Promise<T>,
    ): Promise<T> {
        const fixed = this.fixedSequence();
        if (fixed !== undefined) {
            return seededCall(fixed);
        }

        const release = await this.acquireInitGate();
        try {
            const rechecked = this.fixedSequence();
            if (rechecked !== undefined) {
                return await seededCall(rechecked);
            }

            let observed = this.sequence;
            const result = await unseededCall((detail) => {
                if (detail.sequenceNumber > observed) {
                    observed = detail.sequenceNumber;
                }
            });
            if (observed > this.sequence) {
                this.sequence = observed;
            }
            return result;
        } finally {
            release();
        }
    }

    async get(key: Uint8Array): Promise<GetResult | null> {
        return this.runRead(
            (sequence) => performGet(this.client, key, sequence, undefined, this.keyPrefix),
            (detailObserver) =>
                performGet(this.client, key, undefined, detailObserver, this.keyPrefix),
        );
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
    ): Promise<GetManyResultItem[]> {
        return this.runRead(
            (sequence) =>
                performGetMany(
                    this.client,
                    keys,
                    batchSize,
                    onChunk,
                    sequence,
                    undefined,
                    this.keyPrefix,
                ),
            (detailObserver) =>
                performGetMany(
                    this.client,
                    keys,
                    batchSize,
                    onChunk,
                    undefined,
                    detailObserver,
                    this.keyPrefix,
                ),
        );
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
    ): Promise<QueryResult> {
        return this.runRead(
            (sequence) =>
                performQuery(
                    this.client,
                    start,
                    end,
                    limit,
                    batchSize,
                    mode,
                    sequence,
                    undefined,
                    this.keyPrefix,
                ),
            (detailObserver) =>
                performQuery(
                    this.client,
                    start,
                    end,
                    limit,
                    batchSize,
                    mode,
                    undefined,
                    detailObserver,
                    this.keyPrefix,
                ),
        );
    }

    async reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
    ): Promise<ReduceResponse> {
        return this.runRead(
            (sequence) =>
                performReduce(this.client, start, end, params, sequence, undefined, this.keyPrefix),
            (detailObserver) =>
                performReduce(
                    this.client,
                    start,
                    end,
                    params,
                    undefined,
                    detailObserver,
                    this.keyPrefix,
                ),
        );
    }
}

export class StoreClient {
    constructor(
        private readonly client: Client,
        private readonly keyPrefix?: StoreKeyPrefix,
    ) {}

    withKeyPrefix(prefix: StoreKeyPrefix): StoreClient {
        return new StoreClient(this.client, prefix);
    }

    withoutKeyPrefix(): StoreClient {
        return new StoreClient(this.client);
    }

    encodeStoreKey(key: Uint8Array): Uint8Array {
        return encodeStoreKey(this.keyPrefix, key);
    }

    decodeStoreKey(key: Uint8Array): Uint8Array {
        return decodeStoreKey(this.keyPrefix, key);
    }

    createSession(): SerializableReadSession {
        return new SerializableReadSession(this.client, this.keyPrefix);
    }

    createSessionWithSequence(sequence: bigint): SerializableReadSession {
        return new SerializableReadSession(this.client, this.keyPrefix, sequence);
    }

    async set(key: Uint8Array, value: Uint8Array | Buffer): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: [
                create(KvEntrySchema, {
                    key: this.encodeStoreKey(key),
                    value: toUint8Array(value),
                }),
            ],
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async setMany(kvs: { key: Uint8Array; value: Uint8Array | Buffer }[]): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: kvs.map((kv) =>
                create(KvEntrySchema, {
                    key: this.encodeStoreKey(kv.key),
                    value: toUint8Array(kv.value),
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async putPrepared(batch: StoreWriteBatch): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: batch.entries().map((kv) =>
                create(KvEntrySchema, {
                    key: kv.key,
                    value: kv.value,
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async get(key: Uint8Array, minSequenceNumber?: bigint): Promise<GetResult | null> {
        return performGet(this.client, key, minSequenceNumber, undefined, this.keyPrefix);
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
        minSequenceNumber?: bigint,
    ): Promise<GetManyResultItem[]> {
        return performGetMany(
            this.client,
            keys,
            batchSize,
            onChunk,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
        );
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
        minSequenceNumber?: bigint,
    ): Promise<QueryResult> {
        return performQuery(
            this.client,
            start,
            end,
            limit,
            batchSize,
            mode,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
        );
    }

    async prune(policies: Policy[]): Promise<void> {
        const req = create(PruneRequestSchema, { policies: prefixPolicies(policies, this.keyPrefix) });
        try {
            await this.client.compact.prune(req);
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
        minSequenceNumber?: bigint,
    ): Promise<ReduceResponse> {
        return performReduce(
            this.client,
            start,
            end,
            params,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
        );
    }

    async getBatch(sequenceNumber: bigint, options?: CallOptions): Promise<StoreBatch | null> {
        return performGetBatch(this.client, sequenceNumber, this.keyPrefix, options);
    }

    async *subscribe(
        filters: SubscribeFilters,
        options?: CallOptions,
    ): AsyncIterable<StoreBatch> {
        yield* performSubscribe(this.client, filters, this.keyPrefix, options);
    }
}
