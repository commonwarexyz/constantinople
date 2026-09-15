import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';
import { warmProofVerifiers } from './proofWarmup';

void warmProofVerifiers().catch(() => {});

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error('missing #root in index.html');
}

createRoot(rootElement).render(
    <StrictMode>
        <App />
    </StrictMode>,
);
