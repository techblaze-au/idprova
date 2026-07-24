import { useState, useEffect, useCallback, type ReactNode } from 'react';
import { RegistryClient } from '../api/registry';
import { GuidedDemo } from './GuidedDemo';

const TABS = [
  { id: 'keygen', label: 'Keygen' },
  { id: 'aid', label: 'AIDs' },
  { id: 'dat', label: 'DATs' },
  { id: 'revocation', label: 'Revocation' },
  { id: 'receipt', label: 'Receipts' },
  { id: 'scenario', label: 'Governed Dev Agent' },
  { id: 'dashboard', label: 'Dashboard' },
] as const;

export type TabId = (typeof TABS)[number]['id'];

// Plain-language caption shown under the nav so the tab jargon is decoded for non-technical viewers.
const TAB_HINTS: Record<TabId, string> = {
  keygen: 'Keys — the cryptographic identity behind each participant.',
  aid: 'Agent identities — a verifiable ID (a W3C DID) for each agent, that anyone can check.',
  dat: 'Permissions — a signed token stating exactly what an agent may do, and for how long.',
  revocation: 'The off-switch — pull one agent’s authority instantly, without touching anything else.',
  receipt: 'Audit trail — a tamper-evident record of what was issued, used, and revoked.',
  scenario: 'A coding agent on our own hardware, whose every action is sanctioned by the cloud registry — overreach denied by construction.',
  dashboard: 'Live registry — real-time stats from the registry enforcing all of the above.',
};

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

      {/* Plain-language hero — what this is, for a non-technical viewer */}
      <div className="bg-bg border-b border-border px-6 py-4">
        <div className="max-w-7xl mx-auto">
          <p className="text-sm text-text">
            Every AI agent here gets a <span className="text-accent font-medium">verifiable identity</span> and a{' '}
            <span className="text-accent font-medium">scoped permission</span> — and this registry{' '}
            <span className="text-text font-medium">enforces it</span>, so a rogue agent can be shut off instantly.
          </p>
          <p className="text-xs text-text-muted mt-1">
            New here? Press <span className="text-accent">▶ Watch the 60-second story</span> (top right) to see a permission issued, used, then revoked.
          </p>
        </div>
      </div>

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

      {/* Per-tab plain-language caption */}
      <div className="bg-surface2 border-b border-border px-6 py-2">
        <div className="max-w-7xl mx-auto">
          <p className="text-xs text-text-muted">{TAB_HINTS[activeTab]}</p>
        </div>
      </div>

      {/* Content */}
      <main className="flex-1 px-6 py-6">
        <div className="max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
