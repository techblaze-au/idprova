import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { generateKeypair } from '../crypto/ed25519';
import { toHex, toMultibase, fromHex } from '../crypto/encoding';
import { buildAidDocument } from '../protocol/aid';
import { issueDat, verifyDatOffline } from '../protocol/dat';
import { RegistryClient } from '../api/registry';
import { StatusBadge } from './common';
import type { TabId } from './Layout';

interface DemoStep {
  label: string;
  tab: TabId;
  status: 'pending' | 'running' | 'done' | 'error';
  detail: string;
}

interface Props {
  registryUrl: string;
  onTabChange: (tab: TabId) => void;
}

export function GuidedDemo({ registryUrl, onTabChange }: Props) {
  const { addKey } = useKeys();
  const [running, setRunning] = useState(false);
  const [steps, setSteps] = useState<DemoStep[]>([]);
  const [showPanel, setShowPanel] = useState(false);

  const updateStep = (idx: number, update: Partial<DemoStep>) => {
    setSteps(prev => prev.map((s, i) => i === idx ? { ...s, ...update } : s));
  };

  const runDemo = useCallback(async () => {
    if (!registryUrl) {
      alert('Set the registry URL first');
      return;
    }

    setRunning(true);
    setShowPanel(true);

    const initialSteps: DemoStep[] = [
      { label: 'Generate 3 keypairs', tab: 'keygen', status: 'pending', detail: '' },
      { label: 'Create 3 AID documents', tab: 'aid', status: 'pending', detail: '' },
      { label: 'Register AIDs with registry', tab: 'aid', status: 'pending', detail: '' },
      { label: 'Issue DAT (delegation)', tab: 'dat', status: 'pending', detail: '' },
      { label: 'Verify DAT offline', tab: 'dat', status: 'pending', detail: '' },
      { label: 'Revoke DAT', tab: 'revocation', status: 'pending', detail: '' },
      { label: 'Verify revoked DAT', tab: 'revocation', status: 'pending', detail: '' },
    ];
    setSteps(initialSteps);

    const client = new RegistryClient(registryUrl);

    try {
      // Step 0: Generate 3 keypairs
      updateStep(0, { status: 'running' });
      onTabChange('keygen');
      const ts = Date.now();
      const key1 = addKey(`demo-issuer-${ts}`);
      const key2 = addKey(`demo-agent-${ts}`);
      const key3 = addKey(`demo-verifier-${ts}`);
      updateStep(0, { status: 'done', detail: `Keys: ${key1.label}, ${key2.label}, ${key3.label}` });

      // Step 1: Create 3 AIDs
      updateStep(1, { status: 'running' });
      onTabChange('aid');
      const aid1 = buildAidDocument({
        did: 'did:idprova:demo.example:issuer',
        controllerDid: 'did:idprova:demo.example:root',
        name: 'Demo Issuer',
        publicKey: fromHex(key1.publicKeyHex),
      });
      const aid2 = buildAidDocument({
        did: 'did:idprova:demo.example:agent',
        controllerDid: 'did:idprova:demo.example:issuer',
        name: 'Demo Agent',
        publicKey: fromHex(key2.publicKeyHex),
      });
      const aid3 = buildAidDocument({
        did: 'did:idprova:demo.example:verifier',
        controllerDid: 'did:idprova:demo.example:root',
        name: 'Demo Verifier',
        publicKey: fromHex(key3.publicKeyHex),
      });
      updateStep(1, { status: 'done', detail: '3 AID documents created' });

      // Step 2: Register AIDs
      updateStep(2, { status: 'running' });
      await client.registerAid('demo.example:issuer', aid1);
      await client.registerAid('demo.example:agent', aid2);
      await client.registerAid('demo.example:verifier', aid3);
      updateStep(2, { status: 'done', detail: '3 AIDs registered with registry' });

      // Step 3: Issue DAT
      updateStep(3, { status: 'running' });
      onTabChange('dat');
      const token = issueDat({
        issuerDid: 'did:idprova:demo.example:issuer',
        subjectDid: 'did:idprova:demo.example:agent',
        scopes: ['mcp:tool:*:read', 'mcp:resource:data:read'],
        expiresInSeconds: 3600,
        privateKey: fromHex(key1.privateKeyHex),
      });
      // Extract JTI from token
      const parts = token.split('.');
      let claimsB64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
      while (claimsB64.length % 4 !== 0) claimsB64 += '=';
      const jti = JSON.parse(atob(claimsB64)).jti;
      updateStep(3, { status: 'done', detail: `JTI: ${jti}` });

      // Step 4: Verify DAT offline
      updateStep(4, { status: 'running' });
      const verifyResult = verifyDatOffline(token, fromHex(key1.publicKeyHex), 'mcp:tool:filesystem:read');
      updateStep(4, {
        status: verifyResult.valid ? 'done' : 'error',
        detail: verifyResult.valid ? 'All checks passed (sig, timing, scope)' : 'Verification failed',
      });

      // Step 5: Revoke DAT
      updateStep(5, { status: 'running' });
      onTabChange('revocation');
      await client.revokeDat({ jti, reason: 'Demo: revoking for demonstration', revoked_by: 'demo-ui' });
      updateStep(5, { status: 'done', detail: `Revoked ${jti}` });

      // Step 6: Verify revoked
      updateStep(6, { status: 'running' });
      const revCheck = await client.checkRevocation(jti);
      updateStep(6, {
        status: revCheck.revoked ? 'done' : 'error',
        detail: revCheck.revoked ? 'Correctly shows as REVOKED' : 'Expected revoked but got active',
      });

    } catch (e) {
      setSteps(prev => prev.map(s => s.status === 'running' ? { ...s, status: 'error' as const, detail: String(e) } : s));
    } finally {
      setRunning(false);
    }
  }, [registryUrl, addKey, onTabChange]);

  return (
    <div>
      <button
        onClick={() => showPanel ? setShowPanel(false) : runDemo()}
        disabled={running}
        className={`text-xs px-3 py-1.5 rounded font-medium ${
          running ? 'bg-warning/20 text-warning pulse-loading' : 'bg-accent/20 text-accent hover:bg-accent/30'
        }`}
      >
        {running ? 'Demo Running...' : showPanel ? 'Close Demo' : 'Run Full Demo'}
      </button>

      {showPanel && steps.length > 0 && (
        <div className="absolute right-6 top-14 w-96 bg-surface border border-border rounded-lg shadow-2xl z-50 p-4">
          <h3 className="text-sm font-medium text-text mb-3">Guided Demo</h3>
          <div className="space-y-2">
            {steps.map((step, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className={`mt-0.5 w-5 h-5 flex items-center justify-center rounded-full text-xs font-bold ${
                  step.status === 'done' ? 'bg-success/20 text-success' :
                  step.status === 'running' ? 'bg-accent/20 text-accent pulse-loading' :
                  step.status === 'error' ? 'bg-danger/20 text-danger' :
                  'bg-surface2 text-text-muted'
                }`}>
                  {step.status === 'done' ? '\u2713' : step.status === 'error' ? '\u2717' : i + 1}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-text">{step.label}</p>
                  {step.detail && <p className="text-xs text-text-muted truncate">{step.detail}</p>}
                </div>
              </div>
            ))}
          </div>
          {!running && (
            <button onClick={runDemo} className="btn-primary text-xs mt-3 w-full">
              Run Again
            </button>
          )}
        </div>
      )}
    </div>
  );
}
