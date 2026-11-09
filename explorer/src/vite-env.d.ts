/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_INDEXER_URL?: string;
    readonly VITE_SIMPLEX_VERIFICATION_MATERIAL?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
