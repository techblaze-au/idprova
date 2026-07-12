import { useState, useCallback } from 'react';
import { parseReceiptLog, verifyReceiptChain } from '../protocol/receipt';
import { JsonViewer, StatusBadge } from './common';
import type { Receipt } from '../types';
import type { ChainVerifyResult } from '../protocol/receipt';

// A sample audit trail for the Northwind procurement agent — three actions, hash-linked:
// a $3k order (allowed), a $9k order (denied, over limit), and a $3k retry after revocation (denied).
const SAMPLE_LOG = [
  {
    id: 'rcpt_0001', timestamp: '2026-07-13T09:00:00Z',
    agent: 'did:aid:demo.example:procurement-agent', dat: 'dat_northwind_orders',
    action: { type: 'orders:create', tool: 'create_order', inputHash: 'sha256:8f1c…order3000', outputHash: 'sha256:ab77…ok', status: 'success', durationMs: 142 },
    chain: { previousHash: 'genesis', sequenceNumber: 0 }, signature: 'z3demoSig01',
  },
  {
    id: 'rcpt_0002', timestamp: '2026-07-13T09:04:30Z',
    agent: 'did:aid:demo.example:procurement-agent', dat: 'dat_northwind_orders',
    action: { type: 'orders:create', tool: 'create_order', inputHash: 'sha256:5d2e…order9000', status: 'denied', durationMs: 38 },
    chain: { previousHash: 'sha256:7a90…rcpt0001', sequenceNumber: 1 }, signature: 'z3demoSig02',
  },
  {
    id: 'rcpt_0003', timestamp: '2026-07-13T09:10:12Z',
    agent: 'did:aid:demo.example:procurement-agent', dat: 'dat_northwind_orders',
    action: { type: 'orders:create', tool: 'create_order', inputHash: 'sha256:8f1c…order3000', status: 'denied', durationMs: 12 },
    chain: { previousHash: 'sha256:c418…rcpt0002', sequenceNumber: 2 }, signature: 'z3demoSig03',
  },
].map(r => JSON.stringify(r)).join('\n');

export function ReceiptPanel() {
  const [input, setInput] = useState('');
  const [receipts, setReceipts] = useState<Receipt[]>([]);
  const [result, setResult] = useState<ChainVerifyResult | null>(null);
  const [parseError, setParseError] = useState('');
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);

  const handleFileUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      setInput(text);
    };
    reader.readAsText(file);
  }, []);

  const handleVerify = useCallback(() => {
    setParseError('');
    setResult(null);
    setReceipts([]);
    try {
      const parsed = parseReceiptLog(input);
      setReceipts(parsed);
      const verifyResult = verifyReceiptChain(parsed);
      setResult(verifyResult);
    } catch (e) {
      setParseError(String(e));
    }
  }, [input]);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold text-text">Audit trail</h2>

      {/* Input */}
      <div className="card space-y-4">
        <p className="text-sm text-text">
          Every action an agent takes leaves a <span className="text-accent">tamper-evident receipt</span>, hash-linked to the one before it —
          so the whole history can be verified and nothing can be quietly inserted or removed.
        </p>
        <p className="text-xs text-text-muted -mt-2">
          New here? Click <span className="text-accent">Load sample audit trail</span>, then <span className="text-accent">Verify chain</span> — or paste/upload your own log.
        </p>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Paste a receipt log (one JSON object per line), or load the sample…"
          rows={8}
          className="w-full font-mono text-xs"
        />
        <div className="flex items-center gap-4">
          <button onClick={handleVerify} className="btn-primary">Verify chain</button>
          <button onClick={() => setInput(SAMPLE_LOG)} className="btn-secondary text-sm">Load sample audit trail</button>
          <label className="text-sm text-text-muted cursor-pointer hover:text-text">
            Upload log file
            <input type="file" accept=".jsonl,.json,.txt" onChange={handleFileUpload} className="hidden" />
          </label>
        </div>
        {parseError && <p className="text-danger text-sm">{parseError}</p>}
      </div>

      {/* Verification Result */}
      {result && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Chain Verification</h3>
          <div className="flex items-center gap-2">
            <StatusBadge
              status={result.valid ? 'pass' : 'fail'}
              label={result.valid ? 'CHAIN VALID' : 'CHAIN BROKEN'}
            />
            <span className="text-sm text-text-muted">{result.totalEntries} entries</span>
          </div>
          {!result.valid && result.errorIndex !== undefined && (
            <div className="p-3 bg-danger/10 border border-danger/30 rounded text-sm">
              <p className="text-danger font-medium">Error at entry #{result.errorIndex}</p>
              <p className="text-text-muted">{result.errorMessage}</p>
            </div>
          )}
        </div>
      )}

      {/* Stats */}
      {result && result.stats.totalEntries > 0 && (
        <div className="card space-y-4">
          <h3 className="text-lg font-medium">Statistics</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-surface2 rounded p-3">
              <p className="text-text-muted text-xs">Total Entries</p>
              <p className="text-2xl font-bold text-text">{result.stats.totalEntries}</p>
            </div>
            {result.stats.timeRange && (
              <div className="bg-surface2 rounded p-3">
                <p className="text-text-muted text-xs">Time Range</p>
                <p className="text-sm text-text">{new Date(result.stats.timeRange.first).toLocaleString()}</p>
                <p className="text-xs text-text-muted">to</p>
                <p className="text-sm text-text">{new Date(result.stats.timeRange.last).toLocaleString()}</p>
              </div>
            )}
            <div className="bg-surface2 rounded p-3">
              <p className="text-text-muted text-xs">Action Types</p>
              {Object.entries(result.stats.actionTypes).map(([type, count]) => (
                <p key={type} className="text-sm"><span className="text-accent">{type}</span>: {count}</p>
              ))}
            </div>
          </div>
          {Object.keys(result.stats.statuses).length > 0 && (
            <div>
              <p className="text-sm text-text-muted mb-2">Status Distribution</p>
              <div className="flex gap-3">
                {Object.entries(result.stats.statuses).map(([status, count]) => (
                  <span key={status} className="text-sm bg-surface2 px-2 py-1 rounded">
                    {status}: <span className="font-medium text-text">{count}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Individual Receipts */}
      {receipts.length > 0 && (
        <div className="card space-y-2">
          <h3 className="text-lg font-medium mb-2">Individual Receipts</h3>
          {receipts.map((r, i) => (
            <div key={i} className="border border-border rounded">
              <button
                onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
                className="w-full flex items-center justify-between px-4 py-2 text-sm hover:bg-surface2"
              >
                <span className="font-mono text-xs text-accent">{r.id}</span>
                <span className="flex items-center gap-3 text-text-muted">
                  <span>{r.action.type}</span>
                  <span className={r.action.status === 'success' ? 'text-success' : 'text-danger'}>{r.action.status}</span>
                  <span>#{r.chain.sequenceNumber}</span>
                  <span>{expandedIdx === i ? '-' : '+'}</span>
                </span>
              </button>
              {expandedIdx === i && (
                <div className="px-4 pb-4">
                  <JsonViewer data={r} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
