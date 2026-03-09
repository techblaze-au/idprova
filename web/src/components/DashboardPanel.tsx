import { useState, useEffect, useCallback, useRef } from 'react';
import { RegistryClient } from '../api/registry';
import { JsonViewer } from './common';
import type { HealthResponse, MetaResponse, AidDocument, AidListEntry } from '../types';

// MCP receipt as returned by idprova-mcp-demo GET /receipts
interface McpReceipt {
  id: string;
  timestamp: string;
  tool: string;
  subject_did: string;
  scope: string;
  request_hash: string;
  prev_receipt_hash: string;
}

interface McpReceiptsResponse {
  total: number;
  receipts: McpReceipt[];
}

interface DemoStep {
  label: string;
  status: 'pending' | 'running' | 'ok' | 'error';
  detail?: string;
}

export function DashboardPanel({ registryUrl }: { registryUrl: string }) {
  // Registry health
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState('');
  const [lastChecked, setLastChecked] = useState('');

  // Meta
  const [meta, setMeta] = useState<MetaResponse | null>(null);

  // Agent list
  const [agents, setAgents] = useState<AidListEntry[]>([]);
  const [agentsTotal, setAgentsTotal] = useState(0);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState<AidDocument | null>(null);
  const [agentModalLoading, setAgentModalLoading] = useState(false);

  // MCP receipt log
  const [mcpUrl, setMcpUrl] = useState('http://localhost:3001');
  const [receipts, setReceipts] = useState<McpReceipt[]>([]);
  const [receiptsTotal, setReceiptsTotal] = useState(0);
  const [receiptsPollActive, setReceiptsPollActive] = useState(false);
  const [lastReceiptFetch, setLastReceiptFetch] = useState('');
  const receiptPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Demo flow
  const [demoSteps, setDemoSteps] = useState<DemoStep[]>([]);
  const [demoRunning, setDemoRunning] = useState(false);

  // ── Registry data fetchers ──────────────────────────────────────────────

  const fetchHealth = useCallback(async () => {
    if (!registryUrl) return;
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.health();
      setHealth(res);
      setHealthError('');
      setLastChecked(new Date().toLocaleTimeString());
    } catch (e) {
      setHealth(null);
      setHealthError(String(e));
      setLastChecked(new Date().toLocaleTimeString());
    }
  }, [registryUrl]);

  const fetchMeta = useCallback(async () => {
    if (!registryUrl) return;
    try {
      const client = new RegistryClient(registryUrl);
      setMeta(await client.meta());
    } catch { setMeta(null); }
  }, [registryUrl]);

  const fetchAgents = useCallback(async () => {
    if (!registryUrl) return;
    setAgentsLoading(true);
    try {
      const res = await fetch(`${registryUrl}/v1/aids`);
      if (!res.ok) throw new Error(`${res.status}`);
      const data = await res.json();
      setAgents(data.aids ?? []);
      setAgentsTotal(data.total ?? 0);
    } catch { setAgents([]); }
    finally { setAgentsLoading(false); }
  }, [registryUrl]);

  const fetchAgentDetail = useCallback(async (id: string) => {
    if (!registryUrl) return;
    setAgentModalLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const doc = await client.resolveAid(id);
      setSelectedAgent(doc);
    } catch (e) {
      setSelectedAgent({ id, error: String(e) } as unknown as AidDocument);
    } finally { setAgentModalLoading(false); }
  }, [registryUrl]);

  useEffect(() => {
    fetchHealth();
    fetchMeta();
    fetchAgents();
    const interval = setInterval(() => {
      fetchHealth();
      fetchAgents();
    }, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth, fetchMeta, fetchAgents]);

  // ── MCP receipt polling ─────────────────────────────────────────────────

  const fetchReceipts = useCallback(async () => {
    if (!mcpUrl) return;
    try {
      const res = await fetch(`${mcpUrl.replace(/\/$/, '')}/receipts`);
      if (!res.ok) throw new Error(`${res.status}`);
      const data: McpReceiptsResponse = await res.json();
      setReceipts(data.receipts ?? []);
      setReceiptsTotal(data.total ?? 0);
      setLastReceiptFetch(new Date().toLocaleTimeString());
    } catch { /* silent */ }
  }, [mcpUrl]);

  const toggleReceiptPoll = useCallback(() => {
    if (receiptPollRef.current) {
      clearInterval(receiptPollRef.current);
      receiptPollRef.current = null;
      setReceiptsPollActive(false);
    } else {
      fetchReceipts();
      receiptPollRef.current = setInterval(fetchReceipts, 3000);
      setReceiptsPollActive(true);
    }
  }, [fetchReceipts]);

  useEffect(() => {
    return () => {
      if (receiptPollRef.current) clearInterval(receiptPollRef.current);
    };
  }, []);

  // ── Demo flow ───────────────────────────────────────────────────────────

  const runDemoFlow = useCallback(async () => {
    if (!registryUrl) return;
    setDemoRunning(true);

    const steps: DemoStep[] = [
      { label: '1. Registry health check', status: 'pending' },
      { label: '2. Fetch protocol meta', status: 'pending' },
      { label: '3. List registered agents', status: 'pending' },
      { label: '4. MCP server check', status: 'pending' },
      { label: '5. Fetch receipt log', status: 'pending' },
    ];
    setDemoSteps([...steps]);

    const update = (i: number, status: DemoStep['status'], detail?: string) => {
      steps[i] = { ...steps[i], status, detail };
      setDemoSteps([...steps]);
    };

    // Step 1: health
    update(0, 'running');
    try {
      const res = await fetch(`${registryUrl}/health`);
      const data = await res.json();
      update(0, 'ok', `status=${data.status}, v${data.version}`);
    } catch (e) { update(0, 'error', String(e)); }

    // Step 2: meta
    update(1, 'running');
    try {
      const res = await fetch(`${registryUrl}/v1/meta`);
      const data = await res.json();
      update(1, 'ok', `protocol v${data.protocolVersion}, did:${data.didMethod}`);
    } catch (e) { update(1, 'error', String(e)); }

    // Step 3: list aids
    update(2, 'running');
    try {
      const res = await fetch(`${registryUrl}/v1/aids`);
      const data = await res.json();
      const count = data.total ?? 0;
      setAgents(data.aids ?? []);
      setAgentsTotal(count);
      update(2, 'ok', `${count} agent(s) registered`);
    } catch (e) { update(2, 'error', String(e)); }

    // Step 4: MCP health
    update(3, 'running');
    try {
      const res = await fetch(`${mcpUrl.replace(/\/$/, '')}/health`);
      const data = await res.json();
      update(3, 'ok', `MCP ${data.status}, ${data.service}`);
    } catch (e) { update(3, 'error', `MCP server not running at ${mcpUrl} — ${e}`); }

    // Step 5: receipts
    update(4, 'running');
    try {
      const res = await fetch(`${mcpUrl.replace(/\/$/, '')}/receipts`);
      const data: McpReceiptsResponse = await res.json();
      setReceipts(data.receipts ?? []);
      setReceiptsTotal(data.total ?? 0);
      update(4, 'ok', `${data.total} receipts in log`);
    } catch (e) { update(4, 'error', `${e}`); }

    setDemoRunning(false);
  }, [registryUrl, mcpUrl]);

  // ── Chain integrity helper ──────────────────────────────────────────────

  const getChainColor = (r: McpReceipt, prev: McpReceipt | null) => {
    if (r.prev_receipt_hash === 'genesis') return 'bg-accent';
    if (prev) return 'bg-success';
    return 'bg-warning';
  };

  // ── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold text-text">Registry Dashboard</h2>
        <button
          onClick={runDemoFlow}
          disabled={!registryUrl || demoRunning}
          className={`btn-primary ${demoRunning ? 'pulse-loading' : ''}`}
        >
          {demoRunning ? 'Running...' : '▶ Run Demo Flow'}
        </button>
      </div>

      {/* MCP URL field */}
      <div className="card">
        <div className="flex gap-3 items-end">
          <div className="flex-1">
            <label className="block text-xs text-text-muted mb-1">MCP Server URL</label>
            <input
              value={mcpUrl}
              onChange={e => setMcpUrl(e.target.value)}
              placeholder="http://localhost:3001"
              className="w-full"
            />
          </div>
          <button
            onClick={toggleReceiptPoll}
            className={receiptsPollActive ? 'btn-primary' : 'btn-secondary'}
          >
            {receiptsPollActive ? '⏸ Stop Polling' : '▶ Poll Receipts (3s)'}
          </button>
          {lastReceiptFetch && (
            <span className="text-xs text-text-muted self-end pb-2">Last: {lastReceiptFetch}</span>
          )}
        </div>
      </div>

      {/* Demo flow results */}
      {demoSteps.length > 0 && (
        <div className="card space-y-2">
          <h3 className="text-lg font-medium mb-3">Demo Flow Results</h3>
          {demoSteps.map((step, i) => (
            <div key={i} className="flex items-start gap-3 py-1">
              <span className={`text-sm font-mono mt-0.5 ${
                step.status === 'ok' ? 'text-success' :
                step.status === 'error' ? 'text-danger' :
                step.status === 'running' ? 'text-accent pulse-loading' :
                'text-text-muted'
              }`}>
                {step.status === 'ok' ? '✓' : step.status === 'error' ? '✗' : step.status === 'running' ? '…' : '○'}
              </span>
              <div>
                <span className="text-sm text-text">{step.label}</span>
                {step.detail && (
                  <span className="ml-2 text-xs text-text-muted">{step.detail}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Health + Meta cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-medium mb-4">Health Status</h3>
          {!registryUrl ? (
            <p className="text-text-muted text-sm">Set registry URL in the header.</p>
          ) : health ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-success" />
                <span className="text-success font-medium">Connected</span>
              </div>
              <div className="text-sm text-text-muted space-y-1">
                <p>Status: <span className="text-text">{health.status}</span></p>
                <p>Version: <span className="text-text">{health.version}</span></p>
                <p>Last checked: <span className="text-text">{lastChecked}</span></p>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-danger" />
                <span className="text-danger font-medium">Disconnected</span>
              </div>
              {healthError && <p className="text-sm text-danger/80">{healthError}</p>}
            </div>
          )}
          <button onClick={() => { fetchHealth(); fetchAgents(); }} className="btn-secondary mt-3 text-sm">
            Refresh
          </button>
        </div>

        <div className="card">
          <h3 className="text-lg font-medium mb-4">Protocol Meta</h3>
          {meta ? (
            <div className="text-sm text-text-muted space-y-1">
              <p>Protocol: <span className="text-text">{meta.protocolVersion}</span></p>
              <p>Registry: <span className="text-text">{meta.registryVersion}</span></p>
              <p>DID Method: <span className="text-accent">{meta.didMethod}</span></p>
              <p>Algorithms: <span className="text-text">{meta.supportedAlgorithms?.join(', ')}</span></p>
            </div>
          ) : (
            <p className="text-text-muted text-sm">No data. Connect to registry first.</p>
          )}
        </div>
      </div>

      {/* Agent list */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium">
            Registered Agents
            <span className="ml-2 text-sm text-text-muted font-normal">({agentsTotal} total)</span>
          </h3>
          <button onClick={fetchAgents} disabled={agentsLoading} className="btn-secondary text-sm">
            {agentsLoading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {agents.length === 0 ? (
          <p className="text-text-muted text-sm">
            {registryUrl ? 'No agents registered yet.' : 'Set registry URL to see agents.'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-text-muted text-left">
                  <th className="py-2 pr-4">DID</th>
                  <th className="py-2 pr-4">Version</th>
                  <th className="py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-border/20 transition-colors">
                    <td className="py-2 pr-4 font-mono text-xs text-accent">{agent.id}</td>
                    <td className="py-2 pr-4 text-text-muted">{agent.version ?? '—'}</td>
                    <td className="py-2">
                      <button
                        onClick={() => fetchAgentDetail(agent.id)}
                        className="text-xs btn-secondary py-1 px-2"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Agent detail modal */}
      {(selectedAgent || agentModalLoading) && (
        <div
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
          onClick={e => { if (e.target === e.currentTarget) setSelectedAgent(null); }}
        >
          <div className="card w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-medium">Agent Detail</h3>
              <button onClick={() => setSelectedAgent(null)} className="btn-secondary text-sm">✕ Close</button>
            </div>
            {agentModalLoading ? (
              <p className="text-text-muted text-sm">Loading...</p>
            ) : selectedAgent ? (
              <JsonViewer data={selectedAgent} title="AID Document" />
            ) : null}
          </div>
        </div>
      )}

      {/* MCP Receipt log */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-medium">
            MCP Receipt Log
            <span className="ml-2 text-sm text-text-muted font-normal">({receiptsTotal} total)</span>
            {receiptsPollActive && (
              <span className="ml-2 text-xs bg-accent/20 text-accent px-2 py-0.5 rounded-full">
                Live (3s)
              </span>
            )}
          </h3>
          <button onClick={fetchReceipts} className="btn-secondary text-sm">Fetch Now</button>
        </div>

        {receipts.length === 0 ? (
          <p className="text-text-muted text-sm">
            No receipts yet. Start idprova-mcp-demo and enable polling.
          </p>
        ) : (
          <div className="space-y-2">
            {/* Chain integrity bar */}
            <div className="flex gap-1 items-center mb-2">
              <span className="text-xs text-text-muted mr-1">Chain:</span>
              {receipts.map((r, i) => (
                <div
                  key={r.id}
                  className={`h-3 w-3 rounded-full ${getChainColor(r, receipts[i - 1] ?? null)}`}
                  title={`${r.tool} — prev: ${r.prev_receipt_hash.substring(0, 8)}…`}
                />
              ))}
              <span className="text-xs text-text-muted ml-1">
                ({receipts[0]?.prev_receipt_hash === 'genesis' ? 'genesis →' : '?'} {receipts.length} entries)
              </span>
            </div>

            {/* Receipt table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-text-muted text-left text-xs">
                    <th className="py-1.5 pr-3">Time</th>
                    <th className="py-1.5 pr-3">Tool</th>
                    <th className="py-1.5 pr-3">Subject</th>
                    <th className="py-1.5 pr-3">Prev Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {receipts.map((r, i) => (
                    <tr key={r.id} className="border-b border-border/50 text-xs">
                      <td className="py-1.5 pr-3 text-text-muted">
                        {new Date(r.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-1.5 pr-3">
                        <span className="text-accent font-mono">{r.tool}</span>
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-text-muted" style={{maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>
                        {r.subject_did}
                      </td>
                      <td className="py-1.5 pr-3 font-mono">
                        <span className={i === 0 ? 'text-accent' : 'text-success'}>
                          {r.prev_receipt_hash === 'genesis' ? 'genesis' : r.prev_receipt_hash.substring(0, 12) + '…'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
