import initCrypto, { ChainKey } from './crypto-wasm/constantinople_explorer_crypto';
import { toHex } from './codec';

const textEncoder = new TextEncoder();
const META_STORAGE_KEY = 'constantinople.wallets.v1';
const SESSION_STORAGE_KEY = 'constantinople.session.v1';
const PASSKEY_TIMEOUT_MS = 90_000;
const PRF_INPUT = textEncoder.encode('constantinople:explorer:ed25519-prf:v1');
const HKDF_SALT = textEncoder.encode('constantinople:explorer:wallet-salt:v1');
const HKDF_INFO = textEncoder.encode('constantinople:ed25519-private-key:v1');
const ED25519_PRIVATE_KEY_BYTES = 32;

export interface WalletProfile {
    readonly publicKeyHex: string;
    readonly credentialId: string;
    readonly createdAt: number;
}

export interface ActiveWallet extends WalletProfile {
    readonly publicKey: Uint8Array;
    readonly sign: (namespace: Uint8Array, message: Uint8Array) => Promise<Uint8Array>;
}

interface PrfExtensionOutput {
    readonly enabled?: boolean;
    readonly results?: {
        readonly first?: ArrayBuffer;
    };
}

let cryptoReady: Promise<unknown> | null = null;

export function listWallets(): WalletProfile[] {
    return readProfiles().sort((a, b) => b.createdAt - a.createdAt);
}

export function readSession(): string | null {
    return window.localStorage.getItem(SESSION_STORAGE_KEY);
}

export function clearSession() {
    window.localStorage.removeItem(SESSION_STORAGE_KEY);
}

export async function createWallet(): Promise<ActiveWallet> {
    assertWalletSupport();
    await loadCrypto();

    const credential = await createPasskey();
    const prf = getPrfOutput(credential);
    if (!prf.results?.first && prf.enabled !== true) {
        throw new Error('this passkey does not support WebAuthn PRF');
    }

    const credentialId = encodeBase64Url(new Uint8Array(credential.rawId));
    const prfOutput = prf.results?.first ?? (await evaluateCredentialPrf(credentialId));
    const chainKey = ChainKey.fromSeed(await derivePrivateKeySeed(prfOutput));
    const publicKey = chainKey.publicKey();
    const publicKeyHex = toHex(publicKey);
    const profile = {
        publicKeyHex,
        credentialId,
        createdAt: Date.now(),
    };

    writeProfiles([profile, ...readProfiles().filter((item) => item.publicKeyHex !== publicKeyHex)]);
    writeSession(publicKeyHex);

    return activeWallet(profile, chainKey);
}

export async function signInWithPasskey(): Promise<ActiveWallet> {
    assertWalletSupport();
    await loadCrypto();

    const profiles = readProfiles();
    if (profiles.length === 0) {
        throw new Error('create a passkey wallet first');
    }

    const assertion = await getPasskeyAssertion(profiles);
    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey sign-in was cancelled');
    }

    const credentialId = encodeBase64Url(new Uint8Array(assertion.rawId));
    const profile = profiles.find((candidate) => candidate.credentialId === credentialId);
    if (!profile) {
        throw new Error('passkey is not linked to a local wallet');
    }

    const prfOutput = readPrfResult(assertion);
    const chainKey = ChainKey.fromSeed(await derivePrivateKeySeed(prfOutput));
    const publicKeyHex = toHex(chainKey.publicKey());
    if (publicKeyHex !== profile.publicKeyHex) {
        throw new Error('passkey derived a different account key');
    }
    writeSession(profile.publicKeyHex);
    return activeWallet(profile, chainKey);
}

function activeWallet(profile: WalletProfile, chainKey: ChainKey): ActiveWallet {
    const publicKey = chainKey.publicKey();
    return {
        ...profile,
        publicKey,
        sign: async (namespace, message) => chainKey.sign(namespace, message),
    };
}

async function loadCrypto() {
    cryptoReady ??= initCrypto();
    await cryptoReady;
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
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -8 },
            ],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                userVerification: 'required',
            },
            timeout: PASSKEY_TIMEOUT_MS,
            attestation: 'none',
            extensions: prfCreationExtensions(),
        },
    });

    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error('passkey creation was cancelled');
    }
    return credential;
}

async function getPasskeyAssertion(profiles: WalletProfile[]): Promise<Credential | null> {
    return navigator.credentials.get({
        publicKey: {
            challenge: randomChallenge(),
            timeout: PASSKEY_TIMEOUT_MS,
            userVerification: 'required',
            allowCredentials: profiles.map((profile) => ({
                type: 'public-key',
                id: decodeBase64Url(profile.credentialId),
                transports: ['internal'],
            })),
            extensions: prfRequestExtensions(profiles.map((profile) => profile.credentialId)),
        },
    });
}

async function evaluateCredentialPrf(credentialId: string): Promise<ArrayBuffer> {
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: randomChallenge(),
            timeout: PASSKEY_TIMEOUT_MS,
            userVerification: 'required',
            allowCredentials: [
                {
                    type: 'public-key',
                    id: decodeBase64Url(credentialId),
                    transports: ['internal'],
                },
            ],
            extensions: prfRequestExtensions([credentialId]),
        },
    });

    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey verification was cancelled');
    }
    return readPrfResult(assertion);
}

function readPrfResult(credential: PublicKeyCredential): ArrayBuffer {
    const prfOutput = getPrfOutput(credential);
    const result = prfOutput.results?.first;
    if (!result) {
        throw new Error('this passkey did not return WebAuthn PRF output');
    }
    return result;
}

function getPrfOutput(credential: PublicKeyCredential): PrfExtensionOutput {
    const results = credential.getClientExtensionResults() as { prf?: PrfExtensionOutput };
    return results.prf ?? {};
}

async function derivePrivateKeySeed(prfOutput: ArrayBuffer): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: HKDF_SALT,
            info: HKDF_INFO,
        },
        key,
        ED25519_PRIVATE_KEY_BYTES * 8,
    );
    return new Uint8Array(bits);
}

function prfCreationExtensions(): AuthenticationExtensionsClientInputs {
    return {
        prf: {
            eval: {
                first: PRF_INPUT,
            },
        },
    } as unknown as AuthenticationExtensionsClientInputs;
}

function prfRequestExtensions(credentialIds: string[]): AuthenticationExtensionsClientInputs {
    return {
        prf: {
            evalByCredential: Object.fromEntries(
                credentialIds.map((credentialId) => [credentialId, { first: PRF_INPUT }]),
            ),
        },
    } as unknown as AuthenticationExtensionsClientInputs;
}

function assertWalletSupport() {
    if (!window.isSecureContext) {
        throw new Error('passkeys and Ed25519 require a secure context');
    }
    if (!navigator.credentials || !window.PublicKeyCredential) {
        throw new Error('this browser does not expose passkeys');
    }
    if (!crypto.getRandomValues) {
        throw new Error('this browser does not expose secure randomness');
    }
    if (!crypto.subtle) {
        throw new Error('this browser does not expose WebCrypto key derivation');
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
        typeof value.createdAt === 'number'
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
