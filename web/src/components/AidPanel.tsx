import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { buildAidDocument } from '../protocol/aid';
import { fromHex } from '../crypto/encoding';
import { RegistryClient } from '../api/registry';
import { JsonViewer, KeySelector } from './common';
import type { AidDocument } from '../types';

type SubTab = 'create' | 'register' | 'resolve';

const slugify = (s: string) =>
  s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'agent';
const deriveDid = (name: string) => `did:aid:demo.example:${slugify(name)}`;

export function AidPanel({ registryUrl }: { registryUrl: string }) {
  const { getKey, addKey } = useKeys();
  const [subTab, setSubTab] = useState<SubTab>('create');
  const [createdAids, setCreatedAids] = useState<AidDocument[]>([]);

  // Create form — pre-filled with the Northwind procurement agent (matches the hero story)
  const [name, setName] = useState('Northwind Procurement Agent');
  const [did, setDid] = useState('did:aid:demo.example:procurement-agent');
  const [didEdited, setDidEdited] = useState(false);
  const [controllerDid, setControllerDid] = useState('did:aid:demo.example:northwind');
  const [model, setModel] = useState('claude-opus-4');
  const [runtime, setRuntime] = useState('langgraph');
  const [selectedKey, setSelectedKey] = useState('');
  const [showCustomize, setShowCustomize] = useState(false);
  const [createStatus, setCreateStatus] = useState<'idle' | 'working' | 'done' | 'error'>('idle');
  const [createResult, setCreateResult] = useState<AidDocument | null>(null);
  const [registerResponse, setRegisterResponse] = useState('');
  const [registered, setRegistered] = useState(false);
  const [registerNote, setRegisterNote] = useState('');
  const [error, setError] = useState('');

  const onNameChange = (v: string) => {
    setName(v);
    if (!didEdited) setDid(deriveDid(v));   // DID auto-tracks the name until the user edits it
  };

  // Register
  const [registerIdx, setRegisterIdx] = useState(0);
  const [registerResult, setRegisterResult] = useState<string>('');
  const [registerLoading, setRegisterLoading] = useState(false);

  // Resolve
  const [resolveId, setResolveId] = useState('');
  const [resolveResult, setResolveResult] = useState<AidDocument | { error: string } | null>(null);
  const [resolveLoading, setResolveLoading] = useState(false);

  const handleCreate = useCallback(async () => {
    setError(''); setRegisterResponse(''); setRegistered(false); setRegisterNote('');
    if (!name.trim() || !did.trim() || !controllerDid.trim()) {
      setError('Name, DID, and controller DID are required');
      return;
    }
    setCreateStatus('working');
    try {
      // Auto-generate a signing key if the user hasn't picked one — removes the hidden prerequisite.
      let key = selectedKey ? getKey(selectedKey) : undefined;
      if (!key) {
        key = addKey(`${slugify(name)}-key`);
        setSelectedKey(key.label);
      }
      const doc = buildAidDocument({
        did, controllerDid, name,
        publicKey: fromHex(key.publicKeyHex),
        model: model || undefined,
        runtime: runtime || undefined,
      });
      setCreatedAids(prev => [...prev, doc]);
      setCreateResult(doc);
      setCreateStatus('done');
      // Register to the live registry in the same click — but a registry hiccup must NOT
      // discard the created agent. Treat it as a soft, retryable note, not a fatal error.
      if (registryUrl) {
        try {
          const client = new RegistryClient(registryUrl);
          const id = doc.id.replace('did:aid:', '');
          const res = await client.registerAid(id, doc);
          setRegisterResponse(typeof res === 'string' ? res : JSON.stringify(res, null, 2));
          setRegistered(true);
        } catch (regErr) {
          setRegistered(false);
          setRegisterNote(
            `Agent built and signed locally, but the registry could not be reached from this page ` +
            `(${String(regErr).replace(/^Error:\s*/, '')}). This usually means this origin isn’t on ` +
            `the registry’s allow-list. Use the Register tab to retry, or run from the production portal.`
          );
        }
      }
    } catch (e) {
      setError(String(e));
      setCreateStatus('error');
    }
  }, [name, did, controllerDid, model, runtime, selectedKey, getKey, addKey, registryUrl]);

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
          <h3 className="text-lg font-medium">Create an agent</h3>
          <p className="text-sm text-text-muted -mt-2">
            One click generates a signing key, builds the identity document, and registers it live.
            Everything is pre-filled — edit only what you want.
          </p>

          <div>
            <label className="block text-sm text-text-muted mb-1">Agent name</label>
            <input value={name} onChange={e => onNameChange(e.target.value)} placeholder="Agent name" className="w-full" />
            <p className="text-xs text-text-muted mt-1">Identity: <span className="text-accent">{did}</span></p>
          </div>

          <button type="button" onClick={() => setShowCustomize(v => !v)}
            className="text-xs text-text-muted hover:text-text underline">
            {showCustomize ? '– Hide options' : '+ Customize (controller, model, runtime, signing key)'}
          </button>

          {showCustomize && (
            <div className="space-y-3 border-l-2 border-border pl-4">
              <div>
                <label className="block text-sm text-text-muted mb-1">DID</label>
                <input value={did} onChange={e => { setDidEdited(true); setDid(e.target.value); }} className="w-full" />
              </div>
              <div>
                <label className="block text-sm text-text-muted mb-1">Controller DID</label>
                <input value={controllerDid} onChange={e => setControllerDid(e.target.value)} className="w-full" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-text-muted mb-1">Model</label>
                  <input value={model} onChange={e => setModel(e.target.value)} placeholder="Model (optional)" />
                </div>
                <div>
                  <label className="block text-sm text-text-muted mb-1">Runtime</label>
                  <input value={runtime} onChange={e => setRuntime(e.target.value)} placeholder="Runtime (optional)" />
                </div>
              </div>
              <KeySelector value={selectedKey} onChange={setSelectedKey} label="Signing key (leave blank to auto-generate)" />
            </div>
          )}

          <button onClick={handleCreate} disabled={createStatus === 'working'}
            className={`btn-primary ${createStatus === 'working' ? 'pulse-loading' : ''}`}>
            {createStatus === 'working' ? 'Creating…' : 'Create agent'}
          </button>

          {error && <p className="text-danger text-sm">{error}</p>}
          {createStatus === 'done' && (
            <p className="text-success text-sm">
              ✓ Agent created{registered ? ' and registered — resolvable now' : ''} as <span className="text-accent">{createResult?.id}</span>
            </p>
          )}
          {registerNote && (
            <p className="text-warning text-sm border border-warning/30 bg-warning/10 rounded p-2">{registerNote}</p>
          )}
          {createResult && <JsonViewer data={createResult} title="AID Document" />}
          {registerResponse && <pre className="text-xs bg-bg p-3 rounded border border-border overflow-x-auto">{registerResponse}</pre>}
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
