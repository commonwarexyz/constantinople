import { Client, StoreKeyPrefix, TraversalMode } from '@exowarexyz/sdk';

const PROVABLE_TARGET_STORE_PREFIX = new Uint8Array([0x04]);
const PROVABLE_TARGET_HEIGHT_BYTES = 8;
const BLOCK_DIGEST_BYTES = 32;

export interface PublishedProofTarget {
    readonly height: bigint;
    readonly blockDigest: Uint8Array;
}

export function decodePublishedProofTarget(
    key: Uint8Array,
    value: Uint8Array,
): PublishedProofTarget {
    if (key.length !== PROVABLE_TARGET_HEIGHT_BYTES) {
        throw new Error(`provable target key must be ${PROVABLE_TARGET_HEIGHT_BYTES} bytes`);
    }
    if (value.length !== BLOCK_DIGEST_BYTES) {
        throw new Error(`provable target digest must be ${BLOCK_DIGEST_BYTES} bytes`);
    }

    let height = 0n;
    for (const byte of key) {
        height = (height << 8n) | BigInt(byte);
    }
    return { height, blockDigest: value.slice() };
}

export async function fetchLatestPublishedProofTarget(
    storeUrl: string,
    signal?: AbortSignal,
): Promise<PublishedProofTarget> {
    signal?.throwIfAborted();
    const store = new Client(storeUrl.replace(/\/+$/, '')).store(
        new StoreKeyPrefix(PROVABLE_TARGET_STORE_PREFIX),
    );
    const result = await store.query(undefined, undefined, 1, 1, TraversalMode.REVERSE);
    signal?.throwIfAborted();

    const row = result.results[0];
    if (!row) {
        throw new Error('latest provable target is missing');
    }
    return decodePublishedProofTarget(row.key, row.value);
}
