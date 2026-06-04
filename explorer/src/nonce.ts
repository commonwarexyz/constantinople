const NONCE_BITMAP_CAPACITY = 64n;
const MAX_U64 = (1n << 64n) - 1n;

export interface NonceState {
    readonly base: bigint;
    readonly bitmap: bigint;
}

export function emptyNonceState(): NonceState {
    return { base: 0n, bitmap: 0n };
}

export function nextAvailableNonce(state: NonceState): bigint {
    return state.base;
}

export function consumeNonce(state: NonceState, nonce: bigint): NonceState | null {
    if (nonce < state.base) {
        return null;
    }
    if (nonce > MAX_U64) {
        return null;
    }

    const nextUsedNonce = nonce + 1n;
    if (nextUsedNonce > MAX_U64) {
        return null;
    }

    const delta = nonce - state.base;
    if (delta === 0n) {
        return consumeBaseNonce(state);
    }

    if (delta > NONCE_BITMAP_CAPACITY) {
        return { base: nextUsedNonce, bitmap: 0n };
    }

    const bit = 1n << (delta - 1n);
    if ((state.bitmap & bit) !== 0n) {
        return null;
    }

    return { base: state.base, bitmap: state.bitmap | bit };
}

export function mergeNonceStates(left: NonceState, right: NonceState): NonceState {
    let merged = left.base > right.base
        ? { base: left.base, bitmap: 0n }
        : { base: right.base, bitmap: 0n };

    for (const nonce of consumedBitmapNonces(left, merged.base)) {
        merged = consumeNonce(merged, nonce) ?? merged;
    }
    for (const nonce of consumedBitmapNonces(right, merged.base)) {
        merged = consumeNonce(merged, nonce) ?? merged;
    }

    return merged;
}

export function nonceStatesEqual(left: NonceState, right: NonceState): boolean {
    return left.base === right.base && left.bitmap === right.bitmap;
}

function consumeBaseNonce(state: NonceState): NonceState | null {
    let advance = 1n;
    while (advance <= NONCE_BITMAP_CAPACITY) {
        const bit = 1n << (advance - 1n);
        if ((state.bitmap & bit) === 0n) {
            break;
        }
        advance += 1n;
    }

    const base = state.base + advance;
    if (base > MAX_U64) {
        return null;
    }

    const bitmap = advance >= NONCE_BITMAP_CAPACITY ? 0n : state.bitmap >> advance;
    return { base, bitmap };
}

function* consumedBitmapNonces(state: NonceState, base: bigint): Iterable<bigint> {
    for (let offset = 0n; offset < NONCE_BITMAP_CAPACITY; offset += 1n) {
        const bit = 1n << offset;
        if ((state.bitmap & bit) === 0n) {
            continue;
        }

        const nonce = state.base + offset + 1n;
        if (nonce >= base) {
            yield nonce;
        }
    }
}
