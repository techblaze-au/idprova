import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { issueDat, parseDat, verifyDatOffline } from '../protocol/dat';
import { explainScopeMatch } from '../protocol/scope';
import { fromHex } from '../crypto/encoding';
import { RegistryClient } from '../api/registry';
import { JsonViewer, CopyButton, StatusBadge, KeySelector } from './common';
import type { VerifyCheck } from '../protocol/dat';
import type { DatVerifyResponse } from '../types';

type SubTab = 'issue' | 'verify-offline' | 'verify-registry' | 'inspect' | 'scope';

export function DatPanel({ registryUrl }: { registryUrl: string }) {
  const { getKey } = useKeys();
  const [subTab, setSubTab] = useState<SubTab>('issue');

  // Issue state
  const [issuerDid, setIssuerDid] = useState('');
  const [subjectDid, setSubjectDid] = useState('');
  const [scopesStr, setScopesStr] = useState('');
  const [expiry, setExpiry] = useState(3600);
  const [issueKey, setIssueKey] = useState('');
  const [issuedToken, setIssuedToken] = useState('');
  const [issueError, setIssueError] = useState('');

  // Verify offline state
  const [verifyToken, setVerifyToken] = useState('');
  const [verifyKeyMode, setVerifyKeyMode] = useState<'select' | 'paste'>('select');
  const [verifyKeyLabel, setVerifyKeyLabel] = useState('');
  const [verifyKeyHex, setVerifyKeyHex] = useState('');
  const [verifyScope, setVerifyScope] = useState('');
  const [verifyChecks, setVerifyChecks] = useState<VerifyCheck[]>([]);

  // Verify registry state
  const [regToken, setRegToken] = useState('');
  const [regScope, setRegScope] = useState('');
  const [regResult, setRegResult] = useState<DatVerifyResponse | { error: string } | null>(null);
  const [regLoading, setRegLoading] = useState(false);

  // Inspect state
  const [inspectToken, setInspectToken] = useState('');
  const [inspectResult, setInspectResult] = useState<{ header: unknown; claims: unknown } | null>(null);
  const [inspectError, setInspectError] = useState('');

  // Scope playground
  const [grantedScopes, setGrantedScopes] = useState('');
  const [requestedScope, setRequestedScope] = useState('');
  const [scopeResult, setScopeResult] = useState<{ permitted: boolean; explanation: string } | null>(null);

  const handleIssue = useCallback(() => {
    setIssueError('');
    if (!issuerDid || !subjectDid || !scopesStr || !issueKey) {
      setIssueError('All fields required');
      return;
    }
    const key = getKey(issueKey);
    if (!key) { setIssueError('Key not found'); return; }
    try {
      const scopes = scopesStr.split(',').map(s => s.trim()).filter(Boolean);
      const token = issueDat({
        issuerDid, subjectDid, scopes,
        expiresInSeconds: expiry,
        privateKey: fromHex(key.privateKeyHex),
      });
      setIssuedToken(token);
    } catch (e) { setIssueError(String(e)); }
  }, [issuerDid, subjectDid, scopesStr, expiry, issueKey, getKey]);

  const handleVerifyOffline = useCallback(() => {
    let pubKey: Uint8Array;
    if (verifyKeyMode === 'select') {
      const key = getKey(verifyKeyLabel);
      if (!key) { setVerifyChecks([{ name: 'Key', passed: false, detail: 'Key not found' }]); return; }
      pubKey = fromHex(key.publicKeyHex);
    } else {
      try { pubKey = fromHex(verifyKeyHex); } catch {
        setVerifyChecks([{ name: 'Key', passed: false, detail: 'Invalid hex key' }]); return;
      }
    }
    const result = verifyDatOffline(verifyToken, pubKey, verifyScope || undefined);
    setVerifyChecks(result.checks);
  }, [verifyToken, verifyKeyMode, verifyKeyLabel, verifyKeyHex, verifyScope, getKey]);

  const handleVerifyRegistry = useCallback(async () => {
    if (!registryUrl) { setRegResult({ error: 'Registry URL not set' }); return; }
    setRegLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.verifyDat({ token: regToken, scope: regScope || undefined });
      setRegResult(res);
    } catch (e) { setRegResult({ error: String(e) }); }
    finally { setRegLoading(false); }
  }, [registryUrl, regToken, regScope]);

  const handleInspect = useCallback(() => {
    setInspectError('');
    try {
      const { header, claims } = parseDat(inspectToken);
      setInspectResult({ header, claims });
    } catch (e) { setInspectError(String(e)); setInspectResult(null); }
  }, [inspectToken]);

  const handleScopeCheck = useCallback(() => {
    const granted = grantedScopes.split('\n').map(s => s.trim()).filter(Boolean);
    if (!granted.length || !requestedScope.trim()) { setScopeResult(null); return; }
    setScopeResult(explainScopeMatch(granted, requestedScope.trim()));
  }, [grantedScopes, requestedScope]);

  const tabs: { id: SubTab; label: string }[] = [
    { id: 'issue', label: 'Issue' },
    { id: 'verify-offline', label: 'Verify Offline' },
    { id: 'verify-registry', label: 'Verify (Registry)' },
    { id: 'inspect', label: 'Inspect' },
    { id: 'scope', label: 'Scope Playground' },
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text">Delegation Attestation Tokens</h2>
      <div className="flex gap-0 border-b border-border overflow-x-auto">
        {tabs.map(t => (
          <button key={t.id} onClick={() => setSubTab(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 whitespace-nowrap ${subTab === t.id ? 'border-accent text-accent' : 'border-transparent text-text-muted hover:text-text'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {subTab === 'issue' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Issue DAT</h3>
          <input value={issuerDid} onChange={e => setIssuerDid(e.target.value)} placeholder="Issuer DID (did:idprova:...)" className="w-full" />
          <input value={subjectDid} onChange={e => setSubjectDid(e.target.value)} placeholder="Subject DID (did:idprova:...)" className="w-full" />
          <input value={scopesStr} onChange={e => setScopesStr(e.target.value)} placeholder="Scopes (comma-separated, e.g. mcp:tool:*:read)" className="w-full" />
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-text-muted mb-1">Expiry</label>
              <select value={expiry} onChange={e => setExpiry(Number(e.target.value))} className="w-full">
                <option value={900}>15 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={86400}>24 hours</option>
                <option value={604800}>7 days</option>
              </select>
            </div>
            <KeySelector value={issueKey} onChange={setIssueKey} label="Signing Key" />
          </div>
          <button onClick={handleIssue} className="btn-primary">Issue DAT</button>
          {issueError && <p className="text-danger text-sm">{issueError}</p>}
          {issuedToken && (
            <div>
              <div className="flex items-center gap-2 mb-2"><span className="text-sm text-text-muted">Compact JWS:</span><CopyButton text={issuedToken} /></div>
              <textarea readOnly value={issuedToken} rows={4} className="w-full font-mono text-xs" />
            </div>
          )}
        </div>
      )}

      {subTab === 'verify-offline' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Verify DAT (Offline)</h3>
          <textarea value={verifyToken} onChange={e => setVerifyToken(e.target.value)} placeholder="Paste compact JWS token..." rows={3} className="w-full font-mono text-xs" />
          <div className="flex gap-2 items-end">
            <label className="flex items-center gap-1 text-sm text-text-muted">
              <input type="radio" checked={verifyKeyMode === 'select'} onChange={() => setVerifyKeyMode('select')} /> Select key
            </label>
            <label className="flex items-center gap-1 text-sm text-text-muted">
              <input type="radio" checked={verifyKeyMode === 'paste'} onChange={() => setVerifyKeyMode('paste')} /> Paste hex
            </label>
          </div>
          {verifyKeyMode === 'select'
            ? <KeySelector value={verifyKeyLabel} onChange={setVerifyKeyLabel} label="Public Key" />
            : <input value={verifyKeyHex} onChange={e => setVerifyKeyHex(e.target.value)} placeholder="Public key (hex, 64 chars)" className="w-full font-mono" />
          }
          <input value={verifyScope} onChange={e => setVerifyScope(e.target.value)} placeholder="Required scope (optional, e.g. mcp:tool:filesystem:read)" className="w-full" />
          <button onClick={handleVerifyOffline} className="btn-primary">Verify</button>
          {verifyChecks.length > 0 && (
            <div className="space-y-2">
              {verifyChecks.map((c, i) => (
                <div key={i} className="flex items-start gap-2">
                  <StatusBadge status={c.passed ? 'pass' : 'fail'} label={c.name} />
                  <span className="text-sm text-text-muted">{c.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {subTab === 'verify-registry' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Verify DAT (via Registry)</h3>
          <textarea value={regToken} onChange={e => setRegToken(e.target.value)} placeholder="Paste compact JWS token..." rows={3} className="w-full font-mono text-xs" />
          <input value={regScope} onChange={e => setRegScope(e.target.value)} placeholder="Required scope (optional)" className="w-full" />
          <button onClick={handleVerifyRegistry} disabled={regLoading} className={`btn-primary ${regLoading ? 'pulse-loading' : ''}`}>
            {regLoading ? 'Verifying...' : 'Verify via Registry'}
          </button>
          {regResult && <JsonViewer data={regResult} title="Verification Result" />}
        </div>
      )}

      {subTab === 'inspect' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Inspect DAT (Decode Only)</h3>
          <textarea value={inspectToken} onChange={e => setInspectToken(e.target.value)} placeholder="Paste compact JWS token..." rows={3} className="w-full font-mono text-xs" />
          <button onClick={handleInspect} className="btn-primary">Inspect</button>
          {inspectError && <p className="text-danger text-sm">{inspectError}</p>}
          {inspectResult && (
            <div className="space-y-3">
              <JsonViewer data={inspectResult.header} title="Header" />
              <JsonViewer data={inspectResult.claims} title="Claims" />
            </div>
          )}
        </div>
      )}

      {subTab === 'scope' && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Scope Playground</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-text-muted mb-1">Granted Scopes (one per line)</label>
              <textarea value={grantedScopes} onChange={e => setGrantedScopes(e.target.value)}
                placeholder={"mcp:tool:*:read\nmcp:resource:data:*"} rows={5} className="w-full font-mono text-xs" />
            </div>
            <div>
              <label className="block text-sm text-text-muted mb-1">Requested Scope</label>
              <input value={requestedScope} onChange={e => setRequestedScope(e.target.value)}
                placeholder="mcp:tool:filesystem:read" className="w-full font-mono" />
              <button onClick={handleScopeCheck} className="btn-primary mt-2">Check</button>
            </div>
          </div>
          {scopeResult && (
            <div className={`p-4 rounded border ${scopeResult.permitted ? 'border-success/30 bg-success/10' : 'border-danger/30 bg-danger/10'}`}>
              <StatusBadge status={scopeResult.permitted ? 'pass' : 'fail'} label={scopeResult.permitted ? 'PERMITTED' : 'DENIED'} />
              <pre className="text-sm text-text-muted mt-2 whitespace-pre-wrap">{scopeResult.explanation}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
