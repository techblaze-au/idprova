import { useState, useCallback } from 'react';
import { useKeys } from '../store/keys';
import { CopyButton } from './common';

export function KeygenPanel() {
  const { keys, addKey, removeKey } = useKeys();
  const [label, setLabel] = useState('');
  const [error, setError] = useState('');
  const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());

  const handleGenerate = useCallback(() => {
    const trimmed = label.trim();
    if (!trimmed) { setError('Label is required'); return; }
    if (keys.some(k => k.label === trimmed)) { setError('Label already exists'); return; }
    setError('');
    addKey(trimmed);
    setLabel('');
  }, [label, keys, addKey]);

  const toggleReveal = useCallback((lbl: string) => {
    setRevealedKeys(prev => {
      const next = new Set(prev);
      next.has(lbl) ? next.delete(lbl) : next.add(lbl);
      return next;
    });
  }, []);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text flex items-center gap-2">
        Key Generation
        {keys.length > 0 && (
          <span className="text-xs font-medium bg-accent/20 text-accent px-2 py-0.5 rounded-full">{keys.length}</span>
        )}
      </h2>

      <div className="card">
        <h3 className="text-lg font-medium mb-4">Generate Ed25519 Keypair</h3>
        <div className="flex gap-2">
          <input
            type="text"
            value={label}
            onChange={e => { setLabel(e.target.value); setError(''); }}
            onKeyDown={e => e.key === 'Enter' && handleGenerate()}
            placeholder="Key label (e.g. issuer-key)"
            className="flex-1"
          />
          <button onClick={handleGenerate} className="btn-primary whitespace-nowrap">
            Generate Keypair
          </button>
        </div>
        {error && <p className="text-danger text-sm mt-2">{error}</p>}
      </div>

      {keys.length === 0 ? (
        <p className="text-text-muted text-sm">No keys generated yet. Create one above.</p>
      ) : (
        <div className="space-y-3">
          {keys.map(key => {
            const revealed = revealedKeys.has(key.label);
            return (
              <div key={key.label} className="card">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-text font-medium">{key.label}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-text-muted">{new Date(key.createdAt).toLocaleTimeString()}</span>
                    <button onClick={() => removeKey(key.label)} className="text-text-muted hover:text-danger text-xs">Remove</button>
                  </div>
                </div>

                <div className="space-y-2">
                  <div>
                    <span className="text-text-muted text-xs block mb-1">Public Key (multibase)</span>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-accent bg-bg px-2 py-1 rounded border border-border flex-1 overflow-x-auto whitespace-nowrap">{key.publicKeyMultibase}</code>
                      <CopyButton text={key.publicKeyMultibase} />
                    </div>
                  </div>

                  <div>
                    <span className="text-text-muted text-xs block mb-1">Public Key (hex)</span>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-text bg-bg px-2 py-1 rounded border border-border flex-1 overflow-x-auto whitespace-nowrap">{key.publicKeyHex}</code>
                      <CopyButton text={key.publicKeyHex} />
                    </div>
                  </div>

                  <div>
                    <span className="text-text-muted text-xs block mb-1">Private Key (hex)</span>
                    <div className="flex items-center gap-2">
                      <code className="text-sm text-text bg-bg px-2 py-1 rounded border border-border flex-1 overflow-x-auto whitespace-nowrap">
                        {revealed ? key.privateKeyHex : '\u2022'.repeat(64)}
                      </code>
                      <button onClick={() => toggleReveal(key.label)} className="text-xs px-2 py-1 bg-surface2 border border-border rounded hover:bg-border text-text-muted">
                        {revealed ? 'Hide' : 'Show'}
                      </button>
                      {revealed && <CopyButton text={key.privateKeyHex} />}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
