import init, { type InitInput, verify_current_account_lookup } from './gen/account_wasm/constantinople_account_proof.js';
import { bytesEqual } from './codec.ts';

type CurrentAccount = {
    readonly type: 'hit';
    readonly key: Uint8Array;
    readonly location: bigint;
    readonly value: Uint8Array;
} | {
    readonly type: 'miss';
    readonly key: Uint8Array;
    /** The operation whose key span excludes the key: the preceding account's active update, or
     *  the commit of an empty database. */
    readonly location: bigint;
    /** The adjacent active keys bracketing the key; absent when the database was empty. */
    readonly lower?: Uint8Array;
    readonly upper?: Uint8Array;
};

let initialization: Promise<unknown> | undefined;

export async function initAccountProofWasm(moduleOrPath?: InitInput): Promise<void> {
    if (!initialization) {
        const pending = init(moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath });
        initialization = pending;
        pending.catch(() => { if (initialization === pending) initialization = undefined; });
    }
    await initialization;
}

/** Verifies fixed account proofs at the exact current root and operation tip. */
export async function verifyCurrentAccount(
    proof: Uint8Array, root: Uint8Array, key: Uint8Array, tip: bigint,
    encodedOperation: Uint8Array | undefined, exclusion: boolean,
): Promise<CurrentAccount & { readonly proofSizeBytes: number }> {
    await initAccountProofWasm();
    const result = verify_current_account_lookup(proof, root, key, tip, encodedOperation, exclusion) as CurrentAccount;
    if (!bytesEqual(result.key, key) || (result.type === 'miss') !== exclusion) {
        throw new Error('account proof does not match the requested key and claim');
    }
    if (result.type === 'miss' && (result.lower === undefined) !== (result.upper === undefined)) {
        throw new Error('account exclusion span is incomplete');
    }
    return { ...result, proofSizeBytes: proof.length + (encodedOperation?.length ?? 0) };
}
