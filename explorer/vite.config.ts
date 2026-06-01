import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const explorerRoot = dirname(fileURLToPath(import.meta.url));
const exowareSourceRoot = resolve(explorerRoot, '../../exoware-monorepo-faster-qmdb-uploads');

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    server: {
        port: 5173,
        strictPort: false,
        fs: {
            allow: [explorerRoot, exowareSourceRoot],
        },
    },
});
