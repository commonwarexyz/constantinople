import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
    plugins: [react()],
    optimizeDeps: {
        exclude: ['@exowarexyz/qmdb', '@exowarexyz/simplex'],
    },
    server: {
        port: 5173,
        strictPort: false,
    },
});
