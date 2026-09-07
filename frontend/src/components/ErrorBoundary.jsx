import { Component } from 'react';
import Icon from './Icon.jsx';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background p-8">
          <div className="max-w-lg border border-border bg-card p-8">
            <div className="mb-4 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center border border-destructive bg-destructive/10">
                <Icon name="error" size={20} className="text-destructive" />
              </div>
              <div>
                <h2 className="font-mono-ui text-sm font-semibold text-foreground">Something went wrong</h2>
                <p className="font-mono-ui text-[10px] text-muted-foreground">The application encountered an unexpected error</p>
              </div>
            </div>
            <div className="mt-4 border border-border bg-background p-3">
              <pre className="font-mono-ui text-[10px] text-muted-foreground max-h-40 overflow-auto">
                {this.state.error?.message || 'Unknown error'}
              </pre>
            </div>
            {this.state.errorInfo?.componentStack && (
              <details className="mt-3">
                <summary className="font-mono-ui text-[9px] uppercase tracking-[0.1em] text-muted-foreground cursor-pointer">Component stack</summary>
                <pre className="mt-2 border border-border bg-background p-3 font-mono-ui text-[9px] text-muted-foreground max-h-32 overflow-auto">
                  {this.state.errorInfo.componentStack}
                </pre>
              </details>
            )}
            <div className="mt-6 flex gap-3">
              <button
                type="button"
                className="terminal-button inline-flex items-center gap-2 px-4 py-2 font-mono-ui text-[10px] uppercase tracking-[0.1em]"
                onClick={() => this.setState({ hasError: false, error: null, errorInfo: null })}
              >
                <Icon name="refresh" size={14} />
                Retry
              </button>
              <a
                href="/"
                className="ghost-button inline-flex items-center gap-2 border border-border px-4 py-2 font-mono-ui text-[10px] uppercase tracking-[0.1em] text-muted-foreground hover:text-foreground"
              >
                <Icon name="home" size={14} />
                Home
              </a>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
