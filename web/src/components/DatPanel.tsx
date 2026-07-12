import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { useIssuedDat } from '../store/issuedDat';
import { issueDat, parseDat, verifyDatOffline } from '../protocol/dat';
import { explainScopeMatch } from '../protocol/scope';
import { fromHex } from '../crypto/encoding';
import { RegistryClient } from '../api/registry';
import { JsonViewer, CopyButton, StatusBadge, KeySelector } from './common';
import type { VerifyCheck } from '../protocol/dat';
import type { DatVerifyResponse } from '../types';

type SubTab = 'issue' | 'verify-offline' | 'verify-registry' | 'inspect' | 'scope';

const EXPIRY_OPTIONS: { value: number; label: string }[] = [
  { value: 900, label: '15 minutes' },
  { value: 3600, label: '1 hour' },
  { value: 86400, label: '24 hours' },
  { value: 604800, label: '7 days' },
  { value: 7776000, label: '90 days' },
];
const expiryLabel = (secs: number) => EXPIRY_OPTIONS.find(o => o.value === secs)?.label ?? `${secs}s`;

export function DatPanel({ registryUrl }: { registryUrl: string }) {
  const { getKey, addKey } = useKeys();
  const { setIssued } = useIssuedDat();
  const [subTab, setSubTab] = useState<SubTab>('issue');

  // Issue state — pre-filled with the Northwind procurement permission (matches the hero story)
  const [issuerDid, setIssuerDid] = useState('did:aid:demo.example:northwind');
  const [subjectDid, setSubjectDid] = useState('did:aid:demo.example:procurement-agent');
  const [scopesStr, setScopesStr] = useState('orders:create');
  const [expiry, setExpiry] = useState(7776000);
  const [issueKey, setIssueKey] = useState('');
  const [showCustomize, setShowCustomize] = useState(false);
  const [issueStatus, setIssueStatus] = useState<'idle' | 'working' | 'done' | 'error'>('idle');
  const [issueChecks, setIssueChecks] = useState<VerifyCheck[]>([]);
  const [issueValid, setIssueValid] = useState(false);
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
    setIssueError(''); setIssueChecks([]); setIssueValid(false);
    if (!issuerDid.trim() || !subjectDid.trim() || !scopesStr.trim()) {
      setIssueError('Issuer, subject, and scope are required');
      return;
    }
    setIssueStatus('working');
    try {
      // Auto-generate an issuer signing key if none was picked — removes the hidden prerequisite.
      let key = issueKey ? getKey(issueKey) : undefined;
      if (!key) {
        key = addKey('northwind-issuer-key');
        setIssueKey(key.label);
      }
      const scopes = scopesStr.split(',').map(s => s.trim()).filter(Boolean);
      const token = issueDat({
        issuerDid, subjectDid, scopes,
        expiresInSeconds: expiry,
        privateKey: fromHex(key.privateKeyHex),
      });
      setIssuedToken(token);
      // Verify it immediately against the issuer's public key + the first granted scope.
      const result = verifyDatOffline(token, fromHex(key.publicKeyHex), scopes[0]);
      setIssueChecks(result.checks);
      setIssueValid(result.valid);
      setIssueStatus('done');
      // Share this permission so the Revocation step can target it directly (no JTI copy/paste).
      try {
        const jti = String((parseDat(token).claims as { jti?: string }).jti ?? '');
        setIssued({ token, jti, issuerDid, subjectDid, scopes, expiresInSeconds: expiry, issuerKeyLabel: key.label });
      } catch { /* jti extraction is best-effort; issuance already succeeded */ }
    } catch (e) { setIssueError(String(e)); setIssueStatus('error'); }
  }, [issuerDid, subjectDid, scopesStr, expiry, issueKey, getKey, addKey, setIssued]);

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
          <h3 className="text-lg font-medium">Grant a permission</h3>
          <p className="text-sm text-text">
            Grant the <span className="text-accent">{subjectDid.split(':').pop()}</span> permission to{' '}
            <span className="text-accent">{scopesStr || '—'}</span>, valid for{' '}
            <span className="text-accent">{expiryLabel(expiry)}</span>.
          </p>
          <p className="text-xs text-text-muted -mt-2">
            One click signs a scoped token (a DAT) and verifies it. Everything is pre-filled — edit only what you want.
          </p>

          <button type="button" onClick={() => setShowCustomize(v => !v)}
            className="text-xs text-text-muted hover:text-text underline">
            {showCustomize ? '– Hide options' : '+ Customize (issuer, subject, scope, expiry, key)'}
          </button>

          {showCustomize && (
            <div className="space-y-3 border-l-2 border-border pl-4">
              <div>
                <label className="block text-sm text-text-muted mb-1">Issuer DID (who grants the permission)</label>
                <input value={issuerDid} onChange={e => setIssuerDid(e.target.value)} className="w-full" />
              </div>
              <div>
                <label className="block text-sm text-text-muted mb-1">Subject DID (the agent receiving it)</label>
                <input value={subjectDid} onChange={e => setSubjectDid(e.target.value)} className="w-full" />
              </div>
              <div>
                <label className="block text-sm text-text-muted mb-1">Scope(s) — comma-separated</label>
                <input value={scopesStr} onChange={e => setScopesStr(e.target.value)} placeholder="orders:create" className="w-full" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-text-muted mb-1">Expiry</label>
                  <select value={expiry} onChange={e => setExpiry(Number(e.target.value))} className="w-full">
                    {EXPIRY_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <KeySelector value={issueKey} onChange={setIssueKey} label="Signing key (leave blank to auto-generate)" />
              </div>
            </div>
          )}

          <button onClick={handleIssue} disabled={issueStatus === 'working'}
            className={`btn-primary ${issueStatus === 'working' ? 'pulse-loading' : ''}`}>
            {issueStatus === 'working' ? 'Issuing…' : 'Issue permission'}
          </button>
          {issueError && <p className="text-danger text-sm">{issueError}</p>}

          {issueStatus === 'done' && (
            <p className={`text-sm ${issueValid ? 'text-success' : 'text-warning'}`}>
              {issueValid
                ? `✓ Permission issued and valid — scope ${scopesStr}, expires in ${expiryLabel(expiry)}`
                : '⚠ Permission issued, but verification did not pass — see checks below'}
            </p>
          )}
          {issueChecks.length > 0 && (
            <div className="space-y-1">
              {issueChecks.map((c, i) => (
                <div key={i} className="flex items-start gap-2">
                  <StatusBadge status={c.passed ? 'pass' : 'fail'} label={c.name} />
                  <span className="text-sm text-text-muted">{c.detail}</span>
                </div>
              ))}
            </div>
          )}
          {issuedToken && (
            <details>
              <summary className="text-sm text-text-muted cursor-pointer">Show the signed token (compact JWS)</summary>
              <div className="flex items-center gap-2 my-2"><CopyButton text={issuedToken} /></div>
              <textarea readOnly value={issuedToken} rows={4} className="w-full font-mono text-xs" />
            </details>
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
