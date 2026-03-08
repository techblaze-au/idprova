import { useState, useEffect, useCallback } from 'react';
import { RegistryClient } from '../api/registry';
import { JsonViewer } from './common';
import type { HealthResponse, MetaResponse, RevocationRecord, AidDocument } from '../types';

export function DashboardPanel({ registryUrl }: { registryUrl: string }) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState('');
  const [lastChecked, setLastChecked] = useState('');

  const [meta, setMeta] = useState<MetaResponse | null>(null);

  const [resolveId, setResolveId] = useState('');
  const [resolveResult, setResolveResult] = useState<AidDocument | { error: string } | null>(null);
  const [resolveLoading, setResolveLoading] = useState(false);

  const [listLimit, setListLimit] = useState(50);
  const [listOffset, setListOffset] = useState(0);
  const [revocations, setRevocations] = useState<RevocationRecord[]>([]);
  const [listLoading, setListLoading] = useState(false);

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

  useEffect(() => {
    fetchHealth();
    fetchMeta();
    const interval = setInterval(fetchHealth, 30000);
    return () => clearInterval(interval);
  }, [fetchHealth, fetchMeta]);

  const handleResolve = useCallback(async () => {
    if (!registryUrl || !resolveId) return;
    setResolveLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      setResolveResult(await client.resolveAid(resolveId));
    } catch (e) { setResolveResult({ error: String(e) }); }
    finally { setResolveLoading(false); }
  }, [registryUrl, resolveId]);

  const handleLoadRevocations = useCallback(async () => {
    if (!registryUrl) return;
    setListLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.listRevocations(listLimit, listOffset);
      setRevocations(res.revocations);
    } catch { setRevocations([]); }
    finally { setListLoading(false); }
  }, [registryUrl, listLimit, listOffset]);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text">Registry Dashboard</h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Health Card */}
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
                <p>Status: {health.status}</p>
                <p>Version: {health.version}</p>
                <p>Protocol: {health.protocol}</p>
                <p>Last checked: {lastChecked}</p>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <span className="w-3 h-3 rounded-full bg-danger" />
                <span className="text-danger font-medium">Disconnected</span>
              </div>
              {healthError && <p className="text-sm text-text-muted">{healthError}</p>}
              <p className="text-sm text-text-muted">Last checked: {lastChecked}</p>
            </div>
          )}
          <button onClick={fetchHealth} className="btn-secondary mt-3 text-sm">Refresh</button>
        </div>

        {/* Meta Card */}
        <div className="card">
          <h3 className="text-lg font-medium mb-4">Protocol Meta</h3>
          {meta ? (
            <div className="text-sm text-text-muted space-y-1">
              <p>Protocol Version: <span className="text-text">{meta.protocolVersion}</span></p>
              <p>Registry Version: <span className="text-text">{meta.registryVersion}</span></p>
              <p>DID Method: <span className="text-accent">{meta.didMethod}</span></p>
              <p>Algorithms: <span className="text-text">{meta.supportedAlgorithms.join(', ')}</span></p>
              <p>Hash Algorithms: <span className="text-text">{meta.supportedHashAlgorithms.join(', ')}</span></p>
            </div>
          ) : (
            <p className="text-text-muted text-sm">No data. Connect to registry first.</p>
          )}
        </div>
      </div>

      {/* AID Lookup */}
      <div className="card space-y-4">
        <h3 className="text-lg font-medium">AID Lookup</h3>
        <div className="flex gap-2">
          <input value={resolveId} onChange={e => setResolveId(e.target.value)} placeholder="example.com:agent-name (without did:idprova: prefix)" className="flex-1" />
          <button onClick={handleResolve} disabled={resolveLoading} className={`btn-primary ${resolveLoading ? 'pulse-loading' : ''}`}>
            {resolveLoading ? 'Resolving...' : 'Resolve'}
          </button>
        </div>
        {resolveResult && <JsonViewer data={resolveResult} title="Resolved AID" />}
      </div>

      {/* Revocations Table */}
      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Revocations</h3>
        <div className="flex gap-2 items-end">
          <div><label className="block text-xs text-text-muted">Limit</label><input type="number" value={listLimit} onChange={e => setListLimit(Number(e.target.value))} className="w-20" /></div>
          <div><label className="block text-xs text-text-muted">Offset</label><input type="number" value={listOffset} onChange={e => setListOffset(Number(e.target.value))} className="w-20" /></div>
          <button onClick={handleLoadRevocations} disabled={listLoading} className="btn-primary">Load</button>
        </div>
        {revocations.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-border text-text-muted text-left">
                <th className="py-2 pr-4">JTI</th><th className="py-2 pr-4">Reason</th><th className="py-2 pr-4">Revoked By</th><th className="py-2">Revoked At</th>
              </tr></thead>
              <tbody>
                {revocations.map((r, i) => (
                  <tr key={i} className="border-b border-border/50">
                    <td className="py-2 pr-4 font-mono text-xs">{r.jti}</td>
                    <td className="py-2 pr-4">{r.reason}</td>
                    <td className="py-2 pr-4">{r.revoked_by}</td>
                    <td className="py-2">{r.revoked_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-text-muted text-sm">No revocations loaded.</p>
        )}
      </div>
    </div>
  );
}
