import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import App from './App';
import './styles.css';

// Compile the certificate verifier before the first proof needs it.
void ensureSimplexWasm().catch(() => {});

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error('missing #root in index.html');
}

createRoot(rootElement).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
