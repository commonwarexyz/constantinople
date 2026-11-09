import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { transformJoinEnvelopes, transformSplitEnvelope, type EnvelopedMessage } from '@connectrpc/connect/protocol';
import { BinaryReader, WireType } from '@bufbuild/protobuf/wire';
import { ExplorerService } from './gen/constantinople/explorer/v1/explorer_pb.ts';
import { MAX_ANCESTRY_HEADERS, MAX_EXECUTION_HEADER_BYTES, MAX_FINALIZATION_CERTIFICATE_BYTES } from './qmdb.ts';

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_SUBMISSION_RESPONSE_BYTES = 65 * 1024;
const MAX_BLOCK_MESSAGE_BYTES = 3 * 1024 * 1024;

async function boundedFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const response = await globalThis.fetch(input, { ...init, redirect: 'error', cache: 'no-store' });
    const streaming = String(input).endsWith('/WatchBlocks') && response.ok;
    const path = new URL(String(input)).pathname;
    const limit = path.endsWith('/SubmitTransaction') ? MAX_SUBMISSION_RESPONSE_BYTES
        : path.endsWith('/Search') ? 16 * 1024 : MAX_RESPONSE_BYTES;
    const declared = response.headers.get('content-length');
    if (!streaming && declared !== null && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
        await response.body?.cancel();
        throw new ConnectError('indexer response exceeds size limit', Code.ResourceExhausted);
    }
    if (!response.body) return response;
    const reader = response.body.getReader();
    const signal = init?.signal;
    const abort = () => { void reader.cancel(signal?.reason).catch(() => {}); };
    signal?.addEventListener('abort', abort, { once: true });
    async function* chunks() {
        let size = 0;
        try {
            while (true) {
                signal?.throwIfAborted();
                const chunk = await reader.read();
                signal?.throwIfAborted();
                if (chunk.done) return;
                if (!streaming) {
                    size += chunk.value.byteLength;
                    if (size > limit) throw new ConnectError('indexer response exceeds size limit', Code.ResourceExhausted);
                }
                yield chunk.value;
            }
        } finally {
            signal?.removeEventListener('abort', abort);
            await reader.cancel().catch(() => {});
            reader.releaseLock();
        }
    }
    // connect-web does not expose a streaming decoder limit. Connect's own transforms enforce
    // the per-message bound before its browser parser allocates from an envelope length.
    const bytes = streaming
        ? transformJoinEnvelopes()(boundedBlockEnvelopes(transformSplitEnvelope(MAX_BLOCK_MESSAGE_BYTES)(chunks())))
        : chunks();
    const iterator = bytes[Symbol.asyncIterator]();
    const body = new ReadableStream<Uint8Array>({
        async pull(controller) {
            try {
                const next = await iterator.next();
                if (next.done) controller.close();
                else controller.enqueue(next.value);
            } catch (error) {
                controller.error(error);
            }
        },
        async cancel(reason) {
            await reader.cancel(reason).catch(() => {});
            await iterator.return?.();
        },
    });
    return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers });
}

/** Bounds repeated fields before the generated decoder allocates their array entries. */
async function* boundedBlockEnvelopes(envelopes: AsyncIterable<EnvelopedMessage>): AsyncGenerator<EnvelopedMessage> {
    for await (const envelope of envelopes) {
        if (envelope.flags === 0) {
            const reader = new BinaryReader(envelope.data);
            let headers = 0;
            while (reader.pos < reader.len) {
                const [field, wire] = reader.tag();
                if (wire === WireType.StartGroup || wire === WireType.EndGroup) {
                    throw new ConnectError('block feed contains an unsupported group', Code.InvalidArgument);
                }
                if (field === 4) {
                    if (wire !== WireType.Varint) throw new ConnectError('invalid block feed sequence encoding', Code.InvalidArgument);
                    reader.uint64();
                } else if (field === 5 || field === 6) {
                    if (wire !== WireType.LengthDelimited) throw new ConnectError('invalid block feed field encoding', Code.InvalidArgument);
                    const length = reader.uint32();
                    const maximum = field === 5 ? MAX_FINALIZATION_CERTIFICATE_BYTES : MAX_EXECUTION_HEADER_BYTES;
                    if (length > maximum || (field === 6 && ++headers > MAX_ANCESTRY_HEADERS)) {
                        throw new ConnectError(`block feed ${field === 5 ? 'certificate' : 'headers'} exceed size limit`, Code.ResourceExhausted);
                    }
                    if (length > reader.len - reader.pos) throw new ConnectError('truncated block feed field', Code.InvalidArgument);
                    reader.pos += length;
                } else {
                    reader.skip(wire, field);
                }
            }
        } else if (envelope.flags !== 2) {
            throw new ConnectError('unsupported block feed envelope flags', Code.InvalidArgument);
        }
        yield envelope;
    }
}

export function createExplorerClient(indexerUrl: string) {
    return createClient(ExplorerService, createConnectTransport({
        baseUrl: indexerUrl.replace(/\/+$/, ''),
        useBinaryFormat: true,
        binaryOptions: { readUnknownFields: false },
        fetch: boundedFetch,
    }));
}
