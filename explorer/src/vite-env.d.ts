/// <reference types="vite/client" />

interface ImportMetaEnv {
    readonly VITE_SQL_URL?: string;
    readonly VITE_QMDB_URL?: string;
    readonly VITE_STORE_URL?: string;
    readonly VITE_MEMPOOL_URL?: string;
    readonly VITE_SIMPLEX_VERIFICATION_MATERIAL?: string;
    readonly VITE_VERIFY_CERTIFICATES?: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}
