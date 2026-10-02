import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, searchForWorkspaceRoot } from 'vite';
import react from '@vitejs/plugin-react';

// Linked SDKs load verifier assets outside the explorer workspace.
const verifierDirectories = ['@exowarexyz/qmdb', '@exowarexyz/simplex/wasm'].map(
    (specifier) => dirname(fileURLToPath(import.meta.resolve(specifier))),
);

export default defineConfig({
    plugins: [react()],
    optimizeDeps: {
        exclude: ['@exowarexyz/qmdb', '@exowarexyz/simplex'],
    },
    server: {
        port: 5173,
        strictPort: false,
        fs: {
            allow: [
                searchForWorkspaceRoot(fileURLToPath(new URL('.', import.meta.url))),
                ...verifierDirectories,
            ],
        },
    },
});
