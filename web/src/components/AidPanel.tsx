import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { buildAidDocument } from '../protocol/aid';
import { fromHex } from '../crypto/encoding';
import { RegistryClient } from '../api/registry';
import { JsonViewer, KeySelector } from './common';
import type { AidDocument } from '../types';

type SubTab = 'create' | 'register' | 'resolve';

export function AidPanel({ registryUrl }: { registryUrl: string }) {
  const { getKey } = useKeys();
  const [subTab, setSubTab] = useState<SubTab>('create');
  const [createdAids, setCreatedAids] = useState<AidDocument[]>([]);

  // Create form
  const [did, setDid] = useState('');
  const [name, setName] = useState('');
  const [controllerDid, setControllerDid] = useState('');
  const [model, setModel] = useState('');
  const [runtime, setRuntime] = useState('');
  const [selectedKey, setSelectedKey] = useState('');
  const [createResult, setCreateResult] = useState<AidDocument | { error: string } | null>(null);
  const [error, setError] = useState('');

  // Register
  const [registerIdx, setRegisterIdx] = useState(0);
  const [registerResult, setRegisterResult] = useState<string>('');
  const [registerLoading, setRegisterLoading] = useState(false);

  // Resolve
  const [resolveId, setResolveId] = useState('');
  const [resolveResult, setResolveResult] = useState<AidDocument | { error: string } | null>(null);
  const [resolveLoading, setResolveLoading] = useState(false);

  const handleCreate = useCallback(() => {
    setError('');
    if (!did || !name || !controllerDid || !selectedKey) {
      setError('DID, name, controller DID, and key are required');
      return;
    }
    const key = getKey(selectedKey);
    if (!key) { setError('Key not found'); return; }

    try {
      const doc = buildAidDocument({
        did, controllerDid, name,
        publicKey: fromHex(key.publicKeyHex),
        model: model || undefined,
        runtime: runtime || undefined,
      });
      setCreateResult(doc);
      setCreatedAids(prev => [...prev, doc]);
    } catch (e) {
      setError(String(e));
    }
  }, [did, name, controllerDid, model, runtime, selectedKey, getKey]);

  const handleRegister = useCallback(async () => {
    if (!registryUrl) { setRegisterResult('Registry URL not set'); return; }
    const doc = createdAids[registerIdx];
    if (!doc) { setRegisterResult('No AID selected'); return; }
    setRegisterLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const id = doc.id.replace('did:aid:', '');
      const res = await client.registerAid(id, doc);
      setRegisterResult(JSON.stringify(res, null, 2));
    } catch (e) {
      setRegisterResult(String(e));
    } finally { setRegisterLoading(false); }
  }, [registryUrl, createdAids, registerIdx]);

  const handleResolve = useCallback(async () => {
    if (!registryUrl) { setResolveResult({ error: 'Registry URL not set' }); return; }
    setResolveLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.resolveAid(resolveId);
      setResolveResult(res);
    } catch (e) {
      setResolveResult({ error: String(e) });
    } finally { setResolveLoading(false); }
  }, [registryUrl, resolveId]);

  const tabs: { id: SubTab; label: string }[] = [
    { id: 'create', label: 'Create' },
    { id: 'register', label: 'Register' },
    { id: 'resolve', label: 'Resolve' },
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text">Agent Identity Documents</h2>

      <div className="flex gap-0 border-b border-border">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setSubTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 ${subTab === t.id ? 'border-accent text-accent' : 'border-transparent text-text-muted hover:text-text'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {subTab === 'create' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Create AID Document</h3>
          <input value={did} onChange={e => setDid(e.target.value)} placeholder="did:aid:example.com:agent-name" className="w-full" />
          <input value={name} onChange={e => setName(e.target.value)} placeholder="Agent Name" className="w-full" />
          <input value={controllerDid} onChange={e => setControllerDid(e.target.value)} placeholder="Controller DID (e.g. did:aid:example.com:alice)" className="w-full" />
          <div className="grid grid-cols-2 gap-4">
            <input value={model} onChange={e => setModel(e.target.value)} placeholder="Model (optional)" />
            <input value={runtime} onChange={e => setRuntime(e.target.value)} placeholder="Runtime (optional)" />
          </div>
          <KeySelector value={selectedKey} onChange={setSelectedKey} label="Signing Key" />
          <button onClick={handleCreate} className="btn-primary">Create AID Document</button>
          {error && <p className="text-danger text-sm">{error}</p>}
          {createResult && <JsonViewer data={createResult} title="AID Document" />}
        </div>
      )}

      {subTab === 'register' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Register AID with Registry</h3>
          {createdAids.length === 0 ? (
            <p className="text-text-muted text-sm">Create an AID first.</p>
          ) : (
            <>
              <select value={registerIdx} onChange={e => setRegisterIdx(Number(e.target.value))} className="w-full">
                {createdAids.map((a, i) => <option key={i} value={i}>{a.id}</option>)}
              </select>
              <button onClick={handleRegister} disabled={registerLoading} className={`btn-primary ${registerLoading ? 'pulse-loading' : ''}`}>
                {registerLoading ? 'Registering...' : 'Register'}
              </button>
              {registerResult && <pre className="text-sm bg-bg p-3 rounded border border-border overflow-x-auto">{registerResult}</pre>}
            </>
          )}
        </div>
      )}

      {subTab === 'resolve' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Resolve AID</h3>
          <div className="flex gap-2">
            <input value={resolveId} onChange={e => setResolveId(e.target.value)} placeholder="example.com:agent-name" className="flex-1" />
            <button onClick={handleResolve} disabled={resolveLoading} className={`btn-primary ${resolveLoading ? 'pulse-loading' : ''}`}>
              {resolveLoading ? 'Resolving...' : 'Resolve'}
            </button>
          </div>
          {resolveResult && <JsonViewer data={resolveResult} title="Resolved AID" />}
        </div>
      )}
    </div>
  );
}
