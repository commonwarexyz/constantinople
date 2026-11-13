import init, { type InitInput, verify_current_account_lookup } from './gen/account_wasm/constantinople_account_proof.js';
import { bytesEqual } from './codec.ts';

interface CurrentAccount {
    readonly key: Uint8Array;
    readonly location: bigint;
    readonly value: Uint8Array;
}

let initialization: Promise<unknown> | undefined;

export async function initAccountProofWasm(moduleOrPath?: InitInput): Promise<void> {
    if (!initialization) {
        const pending = init(moduleOrPath === undefined ? undefined : { module_or_path: moduleOrPath });
        initialization = pending;
        pending.catch(() => { if (initialization === pending) initialization = undefined; });
    }
    await initialization;
}

/** Verifies a fixed account update at the exact current root and operation tip. */
export async function verifyCurrentAccount(
    proof: Uint8Array, root: Uint8Array, key: Uint8Array, tip: bigint,
    encodedOperation: Uint8Array,
): Promise<CurrentAccount & { readonly proofSizeBytes: number }> {
    await initAccountProofWasm();
    const result = verify_current_account_lookup(proof, root, key, tip, encodedOperation) as CurrentAccount;
    if (!bytesEqual(result.key, key)) throw new Error('account proof does not match the requested key');
    return { ...result, proofSizeBytes: proof.length + encodedOperation.length };
}
