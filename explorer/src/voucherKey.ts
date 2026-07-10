// The paid-stream demo's per-channel ed25519 voucher key.
//
// A channel names a delegated voucher key at open: the passkey wallet signs
// the one OpenChannel transaction (a deliberate user ceremony), and this key
// signs the high-frequency vouchers silently. It is an authority, not an
// account — it cannot transfer funds or open channels, and compromising it
// authorizes at most the deposits of the channels that name it, payable only
// to their fixed receivers. Each channel gets a fresh key, persisted inside
// the channel record (as an exported JWK) so a page reload does not strand a
// live stream.
//
// Storing an extractable key as plaintext JWK is a deliberate demo-posture
// tradeoff: any script on this origin can read it and sign vouchers against
// the channel's remaining deposit. A production client would keep a
// non-extractable CryptoKey in IndexedDB instead (structured-clone
// persistence without exposing key material).

import { fromHex, toArrayBuffer, toHex, voucherSigningPayload } from './codec';

export interface VoucherKey {
    /// The raw 32-byte ed25519 public key the channel commits to.
    readonly publicKey: Uint8Array;
    /// The private half, exported for persistence in the channel record.
    readonly privateJwk: JsonWebKey;
    /// Signs a voucher over `(channel, cumulative)`, returning the raw
    /// 64-byte signature the operator API carries.
    readonly signVoucher: (channel: Uint8Array, cumulative: bigint) => Promise<Uint8Array>;
}

/// Generates a fresh voucher key. Throws where WebCrypto cannot generate
/// ed25519 keys (needs Chrome 137+, Safari 17+, or Firefox 130+) — the only
/// reliable support probe is this very attempt.
export async function createVoucherKey(): Promise<VoucherKey> {
    const pair = (await crypto.subtle.generateKey('Ed25519', true, [
        'sign',
        'verify',
    ])) as CryptoKeyPair;
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    return activate(privateJwk, toHex(publicKey));
}

/// Reactivates a persisted voucher key from a channel record.
export async function importVoucherKey(
    privateJwk: JsonWebKey,
    publicKeyHex: string,
): Promise<VoucherKey> {
    return activate(privateJwk, publicKeyHex);
}

async function activate(privateJwk: JsonWebKey, publicKeyHex: string): Promise<VoucherKey> {
    const privateKey = await crypto.subtle.importKey('jwk', privateJwk, 'Ed25519', false, [
        'sign',
    ]);
    return {
        publicKey: fromHex(publicKeyHex),
        privateJwk,
        signVoucher: async (channel, cumulative) =>
            new Uint8Array(
                await crypto.subtle.sign(
                    'Ed25519',
                    privateKey,
                    toArrayBuffer(voucherSigningPayload(channel, cumulative)),
                ),
            ),
    };
}
