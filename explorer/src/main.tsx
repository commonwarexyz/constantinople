import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import ExplorerErrorBoundary from './ExplorerErrorBoundary';
import './styles.css';

const rootElement = document.getElementById('root');
if (!rootElement) {
    throw new Error('missing #root in index.html');
}

createRoot(rootElement).render(
    <StrictMode>
        <ExplorerErrorBoundary>
            <App />
        </ExplorerErrorBoundary>
    </StrictMode>,
);
