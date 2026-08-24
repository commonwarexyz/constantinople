import { Component, type ReactNode } from 'react';

interface ExplorerErrorBoundaryProps {
    readonly children: ReactNode;
}

interface ExplorerErrorBoundaryState {
    readonly message: string | null;
}

export default class ExplorerErrorBoundary extends Component<
    ExplorerErrorBoundaryProps,
    ExplorerErrorBoundaryState
> {
    state: ExplorerErrorBoundaryState = { message: null };

    static getDerivedStateFromError(error: unknown): ExplorerErrorBoundaryState {
        return {
            message: error instanceof Error ? error.message : String(error),
        };
    }

    render() {
        if (this.state.message === null) return this.props.children;

        return (
            <main className="fatal-error" role="alert">
                <h1>explorer unavailable</h1>
                <p>{this.state.message}</p>
                <button onClick={() => this.setState({ message: null })} type="button">
                    retry
                </button>
            </main>
        );
    }
}
