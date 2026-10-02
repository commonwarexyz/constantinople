import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import initQmdbWasm from '../node_modules/@exowarexyz/qmdb/dist/generated/wasm/exoware_qmdb_wasm.js';

// The pinned QMDB SDK does not export its initializer. Import the same module
// its proof client uses so page startup and verification share one instance.
export async function warmProofVerifiers(): Promise<void> {
    await Promise.all([ensureSimplexWasm(), initQmdbWasm()]);
}
