import { fromHex, toArrayBuffer, toHex } from './codec';

const META_STORAGE_KEY = 'constantinople.wallets.v1';
const SESSION_STORAGE_KEY = 'constantinople.session.v1';
const PASSKEY_TIMEOUT_MS = 90_000;
const SECP256R1_SCHEME = 1;
const RAW_P256_PUBLIC_KEY_BYTES = 65;
const COMPRESSED_P256_PUBLIC_KEY_BYTES = 33;
const TRANSACTION_PUBLIC_KEY_BYTES = 34;
const RAW_SIGNATURE_BYTES = 64;
const AUTHENTICATOR_DATA_BYTES = 256;
const CLIENT_DATA_JSON_BYTES = 512;
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

export interface WalletProfile {
    readonly publicKeyHex: string;
    readonly credentialId: string;
    readonly createdAt: number;
}

export interface ActiveWallet extends WalletProfile {
    readonly publicKey: Uint8Array;
    readonly sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export function listWallets(): WalletProfile[] {
    return readProfiles().sort((a, b) => b.createdAt - a.createdAt);
}

export function readSession(): string | null {
    return window.localStorage.getItem(SESSION_STORAGE_KEY);
}

export function clearSession() {
    window.localStorage.removeItem(SESSION_STORAGE_KEY);
}

export function restoreWalletSession(): ActiveWallet | null {
    const publicKeyHex = readSession();
    if (publicKeyHex === null) return null;

    const profile = readProfiles().find((candidate) => candidate.publicKeyHex === publicKeyHex);
    if (!profile) {
        clearSession();
        return null;
    }

    return activeWallet(profile);
}

export async function createWallet(): Promise<ActiveWallet> {
    assertWalletSupport();

    const credential = await createPasskey();
    const credentialId = encodeBase64Url(new Uint8Array(credential.rawId));
    const publicKey = await transactionPublicKey(credential);
    const publicKeyHex = toHex(publicKey);
    const profile = {
        publicKeyHex,
        credentialId,
        createdAt: Date.now(),
    };

    writeProfiles([profile, ...readProfiles().filter((item) => item.publicKeyHex !== publicKeyHex)]);
    writeSession(publicKeyHex);

    return activeWallet(profile);
}

export async function signInWithPasskey(): Promise<ActiveWallet> {
    assertWalletSupport();

    const profiles = readProfiles();
    if (profiles.length === 0) {
        throw new Error('create a passkey wallet first');
    }

    const assertion = await getPasskeyAssertion(profiles, randomChallenge());
    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey sign-in was cancelled');
    }

    const credentialId = encodeBase64Url(new Uint8Array(assertion.rawId));
    const profile = profiles.find((candidate) => candidate.credentialId === credentialId);
    if (!profile) {
        throw new Error('passkey is not linked to a local wallet');
    }

    writeSession(profile.publicKeyHex);
    return activeWallet(profile);
}

function activeWallet(profile: WalletProfile): ActiveWallet {
    const publicKey = fromHex(profile.publicKeyHex);
    return {
        ...profile,
        publicKey,
        sign: (message) => signWithPasskey(profile, message),
    };
}

async function createPasskey(): Promise<PublicKeyCredential> {
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: randomChallenge(),
            rp: { name: 'Constantinople Explorer' },
            user: {
                id: randomChallenge(),
                name: 'constantinople-wallet',
                displayName: 'Constantinople Wallet',
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                userVerification: 'required',
            },
            timeout: PASSKEY_TIMEOUT_MS,
            attestation: 'none',
        },
    });

    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error('passkey creation was cancelled');
    }
    return credential;
}

async function signWithPasskey(profile: WalletProfile, challenge: Uint8Array): Promise<Uint8Array> {
    const assertion = await getPasskeyAssertion([profile], toArrayBuffer(challenge));
    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey signing was cancelled');
    }

    const credentialId = encodeBase64Url(new Uint8Array(assertion.rawId));
    if (credentialId !== profile.credentialId) {
        throw new Error('passkey returned a different credential');
    }

    const response = assertion.response;
    if (!(response instanceof AuthenticatorAssertionResponse)) {
        throw new Error('passkey did not return an assertion');
    }

    return encodeTransactionSignature(
        normalizeP256Signature(parseDerSignature(new Uint8Array(response.signature))),
        new Uint8Array(response.authenticatorData),
        new Uint8Array(response.clientDataJSON),
    );
}

async function getPasskeyAssertion(
    profiles: WalletProfile[],
    challenge: ArrayBuffer,
): Promise<Credential | null> {
    return navigator.credentials.get({
        publicKey: {
            challenge,
            timeout: PASSKEY_TIMEOUT_MS,
            userVerification: 'required',
            allowCredentials: profiles.map((profile) => ({
                type: 'public-key',
                id: decodeBase64Url(profile.credentialId),
                transports: ['internal'],
            })),
        },
    });
}

async function transactionPublicKey(credential: PublicKeyCredential): Promise<Uint8Array> {
    const response = credential.response;
    if (!(response instanceof AuthenticatorAttestationResponse)) {
        throw new Error('passkey did not return attestation data');
    }

    const getPublicKey = response.getPublicKey?.bind(response);
    const spki = getPublicKey?.();
    if (!spki) {
        throw new Error('this browser cannot expose the passkey public key');
    }

    const key = await crypto.subtle.importKey(
        'spki',
        spki,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify'],
    );
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    if (raw.length !== RAW_P256_PUBLIC_KEY_BYTES || raw[0] !== 4) {
        throw new Error('passkey returned an invalid P-256 public key');
    }

    const compressed = compressP256PublicKey(raw);
    const publicKey = new Uint8Array(TRANSACTION_PUBLIC_KEY_BYTES);
    publicKey[0] = SECP256R1_SCHEME;
    publicKey.set(compressed, 1);
    return publicKey;
}

function compressP256PublicKey(raw: Uint8Array): Uint8Array {
    const compressed = new Uint8Array(COMPRESSED_P256_PUBLIC_KEY_BYTES);
    compressed[0] = raw[RAW_P256_PUBLIC_KEY_BYTES - 1] % 2 === 0 ? 2 : 3;
    compressed.set(raw.slice(1, 33), 1);
    return compressed;
}

function encodeTransactionSignature(
    rawSignature: Uint8Array,
    authenticatorData: Uint8Array,
    clientDataJSON: Uint8Array,
): Uint8Array {
    assertByteLength(rawSignature, RAW_SIGNATURE_BYTES, 'P-256 signature');
    if (authenticatorData.length > AUTHENTICATOR_DATA_BYTES) {
        throw new Error('passkey authenticator data is too large');
    }
    if (clientDataJSON.length > CLIENT_DATA_JSON_BYTES) {
        throw new Error('passkey client data JSON is too large');
    }

    const out = new Uint8Array(1 + RAW_SIGNATURE_BYTES + 2 + authenticatorData.length + 2 + clientDataJSON.length);
    out[0] = SECP256R1_SCHEME;
    out.set(rawSignature, 1);
    writeU16Be(out, 1 + RAW_SIGNATURE_BYTES, authenticatorData.length);
    const clientDataLengthOffset = 1 + RAW_SIGNATURE_BYTES + 2 + authenticatorData.length;
    out.set(authenticatorData, 1 + RAW_SIGNATURE_BYTES + 2);
    writeU16Be(out, clientDataLengthOffset, clientDataJSON.length);
    out.set(clientDataJSON, clientDataLengthOffset + 2);
    return out;
}

function parseDerSignature(signature: Uint8Array): Uint8Array {
    if (signature.length < 8 || signature[0] !== 0x30) {
        throw new Error('passkey returned a malformed ECDSA signature');
    }

    let offset = 2;
    if (signature[1] & 0x80) {
        const lengthBytes = signature[1] & 0x7f;
        if (lengthBytes !== 1) {
            throw new Error('passkey returned an unsupported ECDSA signature length');
        }
        offset = 3;
    }

    const r = readDerInteger(signature, offset);
    const s = readDerInteger(signature, r.nextOffset);
    if (s.nextOffset !== signature.length) {
        throw new Error('passkey returned a trailing ECDSA signature payload');
    }

    const raw = new Uint8Array(RAW_SIGNATURE_BYTES);
    raw.set(r.value, 32 - r.value.length);
    raw.set(s.value, 64 - s.value.length);
    return raw;
}

function readDerInteger(signature: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
    if (signature[offset] !== 0x02) {
        throw new Error('passkey returned a malformed ECDSA integer');
    }
    const length = signature[offset + 1];
    const start = offset + 2;
    const end = start + length;
    if (end > signature.length) {
        throw new Error('passkey returned a truncated ECDSA integer');
    }

    let value = signature.slice(start, end);
    while (value.length > 0 && value[0] === 0) {
        value = value.slice(1);
    }
    if (value.length > 32) {
        throw new Error('passkey returned an oversized ECDSA integer');
    }
    return { value, nextOffset: end };
}

function normalizeP256Signature(signature: Uint8Array): Uint8Array {
    const s = readBigEndian(signature.slice(32));
    const halfOrder = P256_ORDER / 2n;
    if (s <= halfOrder) {
        return signature;
    }

    const normalized = new Uint8Array(signature);
    writeBigEndian(normalized, 32, P256_ORDER - s);
    return normalized;
}

function assertWalletSupport() {
    if (!window.isSecureContext) {
        throw new Error('passkeys require a secure context');
    }
    if (!navigator.credentials || !window.PublicKeyCredential) {
        throw new Error('this browser does not expose passkeys');
    }
    if (!crypto.getRandomValues) {
        throw new Error('this browser does not expose secure randomness');
    }
    if (!crypto.subtle) {
        throw new Error('this browser does not expose WebCrypto');
    }
}

function randomChallenge(): ArrayBuffer {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    return challenge.buffer;
}

function readProfiles(): WalletProfile[] {
    const raw = window.localStorage.getItem(META_STORAGE_KEY);
    if (!raw) {
        return [];
    }

    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed.filter(isWalletProfile) : [];
    } catch {
        return [];
    }
}

function writeProfiles(profiles: WalletProfile[]) {
    window.localStorage.setItem(META_STORAGE_KEY, JSON.stringify(profiles));
}

function writeSession(publicKeyHex: string) {
    window.localStorage.setItem(SESSION_STORAGE_KEY, publicKeyHex);
}

function isWalletProfile(value: unknown): value is WalletProfile {
    return (
        typeof value === 'object' &&
        value !== null &&
        'publicKeyHex' in value &&
        'credentialId' in value &&
        'createdAt' in value &&
        typeof value.publicKeyHex === 'string' &&
        typeof value.credentialId === 'string' &&
        typeof value.createdAt === 'number' &&
        /^[0-9a-f]{68}$/i.test(value.publicKeyHex)
    );
}

function encodeBase64Url(bytes: Uint8Array): string {
    let value = '';
    for (const byte of bytes) {
        value += String.fromCharCode(byte);
    }
    return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value: string): ArrayBuffer {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    const raw = atob(padded);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes.buffer;
}

function assertByteLength(bytes: Uint8Array, expected: number, label: string) {
    if (bytes.length !== expected) {
        throw new Error(`${label} must be ${expected} bytes`);
    }
}

function writeU16Be(bytes: Uint8Array, offset: number, value: number) {
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint16(offset, value, false);
}

function readBigEndian(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
    }
    return value;
}

function writeBigEndian(bytes: Uint8Array, offset: number, value: bigint) {
    for (let i = 31; i >= 0; i--) {
        bytes[offset + i] = Number(value & 0xffn);
        value >>= 8n;
    }
}
