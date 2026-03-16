import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { issueDat, verifyDatOffline } from '../protocol/dat';
import { fromHex } from '../crypto/encoding';
import { RegistryClient } from '../api/registry';
import { StatusBadge, JsonViewer } from './common';
import type { RevocationRecord } from '../types';

export function RevocationPanel({ registryUrl }: { registryUrl: string }) {
  const { addKey } = useKeys();

  // Revoke state
  const [revokeJti, setRevokeJti] = useState('');
  const [revokeReason, setRevokeReason] = useState('');
  const [revokeBy, setRevokeBy] = useState('');
  const [revokeToken, setRevokeToken] = useState('');
  const [revokeResult, setRevokeResult] = useState('');
  const [revokeLoading, setRevokeLoading] = useState(false);

  // Check state
  const [checkJti, setCheckJti] = useState('');
  const [checkResult, setCheckResult] = useState<{ revoked: boolean; reason?: string; revoked_by?: string; revoked_at?: string } | null>(null);
  const [checkLoading, setCheckLoading] = useState(false);

  // List state
  const [listLimit, setListLimit] = useState(50);
  const [listOffset, setListOffset] = useState(0);
  const [revocations, setRevocations] = useState<RevocationRecord[]>([]);
  const [listLoading, setListLoading] = useState(false);

  // Demo state
  const [demoLog, setDemoLog] = useState<string[]>([]);
  const [demoRunning, setDemoRunning] = useState(false);

  const handleRevoke = useCallback(async () => {
    if (!registryUrl) { setRevokeResult('Registry URL not set'); return; }
    if (!revokeJti) { setRevokeResult('JTI required'); return; }
    setRevokeLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.revokeDat({
        jti: revokeJti, reason: revokeReason, revoked_by: revokeBy,
        token: revokeToken || undefined,
      });
      setRevokeResult(JSON.stringify(res, null, 2));
    } catch (e) { setRevokeResult(String(e)); }
    finally { setRevokeLoading(false); }
  }, [registryUrl, revokeJti, revokeReason, revokeBy, revokeToken]);

  const handleCheck = useCallback(async () => {
    if (!registryUrl || !checkJti) return;
    setCheckLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.checkRevocation(checkJti);
      setCheckResult(res);
    } catch (e) { setCheckResult({ revoked: false, reason: String(e) }); }
    finally { setCheckLoading(false); }
  }, [registryUrl, checkJti]);

  const handleLoadList = useCallback(async () => {
    if (!registryUrl) return;
    setListLoading(true);
    try {
      const client = new RegistryClient(registryUrl);
      const res = await client.listRevocations(listLimit, listOffset);
      setRevocations(res.revocations);
    } catch { setRevocations([]); }
    finally { setListLoading(false); }
  }, [registryUrl, listLimit, listOffset]);

  const runDemo = useCallback(async () => {
    if (!registryUrl) { setDemoLog(['Error: Registry URL not set']); return; }
    setDemoRunning(true);
    setDemoLog([]);
    const log = (msg: string) => setDemoLog(prev => [...prev, msg]);
    try {
      log('Step 1: Generating demo keypair...');
      const key = addKey('demo-revoke-' + Date.now());
      log('  Key: ' + key.publicKeyMultibase.slice(0, 20) + '...');

      log('Step 2: Issuing DAT...');
      const token = issueDat({
        issuerDid: 'did:aid:demo.example:issuer',
        subjectDid: 'did:aid:demo.example:agent',
        scopes: ['mcp:tool:*:read'],
        expiresInSeconds: 3600,
        privateKey: fromHex(key.privateKeyHex),
      });
      log('  Token issued: ' + token.slice(0, 50) + '...');

      log('Step 3: Verify offline (should be VALID)...');
      const verifyResult = verifyDatOffline(token, fromHex(key.publicKeyHex));
      log('  Result: ' + (verifyResult.valid ? 'VALID' : 'INVALID'));

      log('Step 4: Extracting JTI and revoking...');
      const parts = token.split('.');
      let claimsB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (claimsB64.length % 4 !== 0) claimsB64 += '=';
      const claimsJson = JSON.parse(atob(claimsB64));
      const jti = claimsJson.jti;
      log('  JTI: ' + jti);

      const client = new RegistryClient(registryUrl);
      await client.revokeDat({ jti, reason: 'Demo revocation', revoked_by: 'demo-ui' });
      log('  Revoked successfully!');

      log('Step 5: Checking revocation status...');
      const checkRes = await client.checkRevocation(jti);
      log('  Revoked: ' + checkRes.revoked);

      log('Demo complete!');
    } catch (e) {
      log('Error: ' + String(e));
    } finally { setDemoRunning(false); }
  }, [registryUrl, addKey]);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text">DAT Revocation</h2>

      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Revoke DAT</h3>
        <input value={revokeJti} onChange={e => setRevokeJti(e.target.value)} placeholder="JTI (e.g. dat_01HXZ...)" className="w-full" />
        <div className="grid grid-cols-2 gap-4">
          <input value={revokeReason} onChange={e => setRevokeReason(e.target.value)} placeholder="Reason" />
          <input value={revokeBy} onChange={e => setRevokeBy(e.target.value)} placeholder="Revoked by" />
        </div>
        <textarea value={revokeToken} onChange={e => setRevokeToken(e.target.value)} placeholder="Original token (optional)" rows={2} className="w-full font-mono text-xs" />
        <button onClick={handleRevoke} disabled={revokeLoading} className={`btn-danger ${revokeLoading ? 'pulse-loading' : ''}`}>
          {revokeLoading ? 'Revoking...' : 'Revoke'}
        </button>
        {revokeResult && <pre className="text-sm bg-bg p-3 rounded border border-border overflow-x-auto">{revokeResult}</pre>}
      </div>

      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Check Revocation Status</h3>
        <div className="flex gap-2">
          <input value={checkJti} onChange={e => setCheckJti(e.target.value)} placeholder="JTI" className="flex-1" />
          <button onClick={handleCheck} disabled={checkLoading} className={`btn-primary ${checkLoading ? 'pulse-loading' : ''}`}>Check</button>
        </div>
        {checkResult && (
          <div className="flex items-start gap-2">
            <StatusBadge status={checkResult.revoked ? 'fail' : 'pass'} label={checkResult.revoked ? 'REVOKED' : 'NOT REVOKED'} />
            {checkResult.revoked && (
              <span className="text-sm text-text-muted">
                Reason: {checkResult.reason} | By: {checkResult.revoked_by} | At: {checkResult.revoked_at}
              </span>
            )}
          </div>
        )}
      </div>

      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Revocation List</h3>
        <div className="flex gap-2 items-end">
          <div><label className="block text-xs text-text-muted">Limit</label><input type="number" value={listLimit} onChange={e => setListLimit(Number(e.target.value))} className="w-20" /></div>
          <div><label className="block text-xs text-text-muted">Offset</label><input type="number" value={listOffset} onChange={e => setListOffset(Number(e.target.value))} className="w-20" /></div>
          <button onClick={handleLoadList} disabled={listLoading} className="btn-primary">Load</button>
        </div>
        {revocations.length > 0 && (
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
        )}
      </div>

      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Live Revocation Demo</h3>
        <p className="text-sm text-text-muted">Runs: Generate key, Issue DAT, Verify (valid), Revoke, Check (revoked)</p>
        <button onClick={runDemo} disabled={demoRunning} className={`btn-primary ${demoRunning ? 'pulse-loading' : ''}`}>
          {demoRunning ? 'Running...' : 'Run Demo'}
        </button>
        {demoLog.length > 0 && (
          <pre className="text-sm bg-bg p-3 rounded border border-border overflow-x-auto whitespace-pre-wrap">
            {demoLog.join('\n')}
          </pre>
        )}
      </div>
    </div>
  );
}
