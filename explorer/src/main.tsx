import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { ensureSimplexWasm } from '@exowarexyz/simplex/wasm';
import App from './App';
import './styles.css';

// Compile the certificate verifier before the first proof needs it.
void ensureSimplexWasm().catch(() => {});

// React's development build records every render as a User Timing measure and copies the props
// that changed into it. The browser keeps measures until they are cleared, and the live block
// feed renders many times a second, so they are dropped here before they exhaust memory.
if (import.meta.env.DEV) {
    setInterval(() => performance.clearMeasures(), 250);
}

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error('missing #root in index.html');
}

createRoot(rootElement).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
