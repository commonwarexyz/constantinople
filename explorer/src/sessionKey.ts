// The paid-stream demo's in-browser ed25519 "session key".
//
// Vouchers are ed25519-only on the chain, and the passkey wallet signs
// secp256r1 WebAuthn assertions, so the wallet cannot pay a channel
// directly. Instead it funds a fresh WebCrypto ed25519 key that acts as the
// channel's payer and signs both the OpenChannel transaction and every
// voucher. The key persists in localStorage (as an exported JWK) so a page
// reload does not strand a funded channel.
//
// Storing an extractable key as plaintext JWK is a deliberate demo-posture
// tradeoff: any script on this origin can read it and spend whatever the
// wallet funded into the session account. A production client would keep a
// non-extractable CryptoKey in IndexedDB instead (structured-clone
// persistence without exposing key material).

import {
    TRANSACTION_NAMESPACE,
    accountKeyFromPublicKey,
    ed25519TransactionPublicKey,
    ed25519TransactionSignature,
    fromHex,
    toArrayBuffer,
    toHex,
    unionUnique,
    voucherSigningPayload,
} from './codec';
import { readStoredJson } from './util';

const SESSION_KEY_STORAGE_KEY = 'constantinople.stream-session-key.v1';

export interface SessionKey {
    /// The chain's 34-byte scheme-tagged transaction public key.
    readonly publicKey: Uint8Array;
    /// The 32-byte account the wallet funds and the channel names as payer.
    readonly accountKey: Uint8Array;
    /// Signs a transaction body digest, returning the scheme-tagged
    /// signature tail (unlike the passkey path, ed25519 signatures commit to
    /// the transaction namespace).
    readonly signTransaction: (digest: Uint8Array) => Promise<Uint8Array>;
    /// Signs a voucher, returning the raw 64-byte signature the operator
    /// API carries.
    readonly signVoucher: (channel: Uint8Array, cumulative: bigint) => Promise<Uint8Array>;
}

interface StoredSessionKey {
    readonly privateJwk: JsonWebKey;
    readonly publicKeyHex: string;
}

/// Restores the persisted session key, or generates and persists a fresh
/// one. Throws where WebCrypto cannot generate ed25519 keys (needs Chrome
/// 137+, Safari 17+, or Firefox 130+) — the only reliable support probe is
/// this very attempt.
export async function loadOrCreateSessionKey(): Promise<SessionKey> {
    const stored = readStoredJson(SESSION_KEY_STORAGE_KEY, isStoredSessionKey);
    if (stored) {
        try {
            return await activate(stored);
        } catch {
            // A stored key that no longer imports (or was hand-edited) is
            // useless; fall through and replace it.
            localStorage.removeItem(SESSION_KEY_STORAGE_KEY);
        }
    }

    const pair = (await crypto.subtle.generateKey('Ed25519', true, [
        'sign',
        'verify',
    ])) as CryptoKeyPair;
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    const fresh: StoredSessionKey = { privateJwk, publicKeyHex: toHex(rawPublic) };
    localStorage.setItem(SESSION_KEY_STORAGE_KEY, JSON.stringify(fresh));
    return activate(fresh);
}

function isStoredSessionKey(value: unknown): value is StoredSessionKey {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Partial<StoredSessionKey>;
    return Boolean(record.privateJwk) && typeof record.publicKeyHex === 'string';
}

async function activate(stored: StoredSessionKey): Promise<SessionKey> {
    const privateKey = await crypto.subtle.importKey(
        'jwk',
        stored.privateJwk,
        'Ed25519',
        false,
        ['sign'],
    );
    const publicKey = ed25519TransactionPublicKey(fromHex(stored.publicKeyHex));
    const accountKey = await accountKeyFromPublicKey(publicKey);
    const rawSign = async (payload: Uint8Array): Promise<Uint8Array> =>
        new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, toArrayBuffer(payload)));

    return {
        publicKey,
        accountKey,
        signTransaction: async (digest) =>
            ed25519TransactionSignature(await rawSign(unionUnique(TRANSACTION_NAMESPACE, digest))),
        signVoucher: (channel, cumulative) => rawSign(voucherSigningPayload(channel, cumulative)),
    };
}
