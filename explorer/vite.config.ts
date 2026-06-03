import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const explorerRoot = dirname(fileURLToPath(import.meta.url));

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        strictPort: false,
        fs: {
            allow: [
                explorerRoot,
                resolve(explorerRoot, '../../exoware-monorepo-experiment-with-ts'),
            ],
        },
    },
});
