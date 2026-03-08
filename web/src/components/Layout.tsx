import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { RegistryClient } from '../api/registry';
import { GuidedDemo } from './GuidedDemo';

const TABS = [
  { id: 'keygen', label: 'Keygen' },
  { id: 'aid', label: 'AIDs' },
  { id: 'dat', label: 'DATs' },
  { id: 'revocation', label: 'Revocation' },
  { id: 'receipt', label: 'Receipts' },
  { id: 'dashboard', label: 'Dashboard' },
] as const;

export type TabId = (typeof TABS)[number]['id'];

interface Props {
  activeTab: TabId;
  onTabChange: (tab: TabId) => void;
  registryUrl: string;
  onRegistryUrlChange: (url: string) => void;
  children: ReactNode;
}

export function Layout({ activeTab, onTabChange, registryUrl, onRegistryUrlChange, children }: Props) {
  const [connected, setConnected] = useState<boolean | null>(null);

  const checkHealth = useCallback(async () => {
    try {
      const client = new RegistryClient(registryUrl);
      await client.health();
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }, [registryUrl]);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-surface border-b border-border px-6 py-3 relative">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h1 className="text-xl font-bold text-text">IDProva <span className="text-accent">Demo</span></h1>
            <span className="text-xs text-text-muted bg-surface2 px-2 py-0.5 rounded">v0.1</span>
          </div>
          <div className="flex items-center gap-3">
            <GuidedDemo registryUrl={registryUrl} onTabChange={onTabChange} />
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${connected === true ? 'bg-success' : connected === false ? 'bg-danger' : 'bg-warning'}`} />
              <input
                type="text"
                value={registryUrl}
                onChange={e => onRegistryUrlChange(e.target.value)}
                className="text-xs w-56 px-2 py-1"
                placeholder="Registry URL"
              />
            </div>
          </div>
        </div>
      </header>

      {/* Tab Navigation */}
      <nav className="bg-surface border-b border-border px-6">
        <div className="max-w-7xl mx-auto flex gap-0">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-accent text-accent'
                  : 'border-transparent text-text-muted hover:text-text hover:border-border'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <main className="flex-1 px-6 py-6">
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
