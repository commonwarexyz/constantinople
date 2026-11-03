import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    optimizeDeps: {
        exclude: ['@exowarexyz/qmdb', '@exowarexyz/simplex'],
    },
    server: {
        port: 5173,
        strictPort: false,
        // Linked proof packages load WASM assets from their distribution directories.
        fs: {
            allow: [
                fileURLToPath(new URL('.', import.meta.url)),
                ...['@exowarexyz/qmdb', '@exowarexyz/simplex'].map((name) =>
                    fileURLToPath(new URL('.', import.meta.resolve(name))),
                ),
            ],
        },
    },
});
