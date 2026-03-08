import { useState, useCallback } from 'react';
import { parseReceiptLog, verifyReceiptChain } from '../protocol/receipt';
import { JsonViewer, StatusBadge } from './common';
import type { Receipt } from '../types';
import type { ChainVerifyResult } from '../protocol/receipt';

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
      <h2 className="text-xl font-semibold text-text">Receipt Verification</h2>

      {/* Input */}
      <div className="card space-y-4">
        <h3 className="text-lg font-medium">Receipt Log Input</h3>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="Paste JSONL receipt log here (one JSON object per line)..."
          rows={8}
          className="w-full font-mono text-xs"
        />
        <div className="flex items-center gap-4">
          <button onClick={handleVerify} className="btn-primary">Verify Chain</button>
          <label className="text-sm text-text-muted cursor-pointer hover:text-text">
            Upload JSONL file
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
