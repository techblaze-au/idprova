import { useCallback, useMemo, useState } from 'react';

/**
 * ScenarioPanel — "Governed Dev Agent" console view.
 *
 * Renders one run of the on-prem governed dev agent (R710 CT204) against the
 * cloud registry (idprova-registry.fly.dev). It reads the JSONL event stream the
 * runner emits (agent/scenario.py -> receipts/scenario_events.jsonl):
 *
 *   { ts, tool, scope, decision, reason, verify_mode, receipt_seq }
 *
 * Shows the ON-PREM(agent) <-> CLOUD(registry) banner with a live verify_mode
 * badge, a timeline of the 3 ALLOW + 4 DENY steps, and a link to the receipt log.
 */

interface ScenarioEvent {
  ts: string;
  tool: string;
  scope: string;
  decision: 'ALLOW' | 'DENY';
  reason: string;
  verify_mode: 'online' | 'offline' | string;
  receipt_seq: number;
}

// Real transcript captured on CT204 (offline mode, LangChain executor).
// Also mirrored to web/public/scenario_events.jsonl for fetch('/scenario_events.jsonl').
const SAMPLE_EVENTS = `{"ts": "2026-07-13T13:42:20Z", "tool": "read_file", "scope": "repo:git:file:read", "decision": "ALLOW", "reason": "scope 'repo:git:file:read' granted", "verify_mode": "offline", "receipt_seq": 0}
{"ts": "2026-07-13T13:42:22Z", "tool": "run_tests", "scope": "ci:test:suite:run", "decision": "ALLOW", "reason": "scope 'ci:test:suite:run' granted", "verify_mode": "offline", "receipt_seq": 1}
{"ts": "2026-07-13T13:42:22Z", "tool": "open_pr", "scope": "repo:git:pr:create", "decision": "ALLOW", "reason": "scope 'repo:git:pr:create' granted", "verify_mode": "offline", "receipt_seq": 2}
{"ts": "2026-07-13T13:42:22Z", "tool": "deploy_prod", "scope": "deploy:env:prod:write", "decision": "DENY", "reason": "scope 'deploy:env:prod:write' not in granted scopes", "verify_mode": "offline", "receipt_seq": 3}
{"ts": "2026-07-13T13:42:22Z", "tool": "force_push", "scope": "repo:git:branch:force", "decision": "DENY", "reason": "scope 'repo:git:branch:force' not in granted scopes", "verify_mode": "offline", "receipt_seq": 4}
{"ts": "2026-07-13T13:42:22Z", "tool": "delete_branch", "scope": "repo:git:branch:delete", "decision": "DENY", "reason": "scope 'repo:git:branch:delete' not in granted scopes", "verify_mode": "offline", "receipt_seq": 5}
{"ts": "2026-07-13T13:42:22Z", "tool": "push_protected", "scope": "repo:git:branch:write-protected", "decision": "DENY", "reason": "scope 'repo:git:branch:write-protected' not in granted scopes", "verify_mode": "offline", "receipt_seq": 6}`;

const DEV_AGENT_AID = 'did:aid:techblaze.com.au:dev-agent';
const RECEIPT_LOG_PATH = '/root/governed-agents-demo/receipts/dev_agent.jsonl';

function parseEvents(text: string): { events: ScenarioEvent[]; error: string } {
  const events: ScenarioEvent[] = [];
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      if (e && typeof e.tool === 'string' && (e.decision === 'ALLOW' || e.decision === 'DENY')) {
        events.push(e as ScenarioEvent);
      }
    } catch {
      return { events: [], error: `Could not parse line: ${line.slice(0, 60)}…` };
    }
  }
  return { events, error: '' };
}

export function ScenarioPanel() {
  const [raw, setRaw] = useState(SAMPLE_EVENTS);
  const [source, setSource] = useState<string>('embedded sample (CT204 offline run)');
  const [eventsUrl, setEventsUrl] = useState('/scenario_events.jsonl');
  const [loadError, setLoadError] = useState('');

  const { events, error } = useMemo(() => parseEvents(raw), [raw]);

  const verifyMode = events[0]?.verify_mode ?? 'offline';
  const allow = events.filter(e => e.decision === 'ALLOW').length;
  const deny = events.filter(e => e.decision === 'DENY').length;

  const loadFromUrl = useCallback(async () => {
    setLoadError('');
    try {
      const res = await fetch(eventsUrl, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const text = await res.text();
      const parsed = parseEvents(text);
      if (parsed.error) throw new Error(parsed.error);
      if (parsed.events.length === 0) throw new Error('no events found');
      setRaw(text);
      setSource(`fetched from ${eventsUrl}`);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, [eventsUrl]);

  const onUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setRaw(String(reader.result));
      setSource(`uploaded ${file.name}`);
    };
    reader.readAsText(file);
  }, []);

  return (
    <div className="space-y-5">
      {/* ── ON-PREM <-> CLOUD banner ─────────────────────────────────── */}
      <div className="bg-surface border border-border rounded-lg p-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          {/* on-prem */}
          <div className="flex-1 min-w-[220px]">
            <div className="text-xs text-text-muted uppercase tracking-wide">On-prem (our hardware)</div>
            <div className="text-sm text-text font-medium mt-1">Dev agent · R710 CT204</div>
            <div className="text-xs text-accent font-mono mt-0.5 break-all">{DEV_AGENT_AID}</div>
          </div>

          {/* link */}
          <div className="flex flex-col items-center px-2">
            <span className="text-text-muted text-lg">↔</span>
            <span
              className={`mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                verifyMode === 'online'
                  ? 'bg-accent/20 text-accent border-accent/30'
                  : 'bg-warning/20 text-warning border-warning/30'
              }`}
            >
              verify: {verifyMode}
            </span>
            <span className="text-[10px] text-text-muted mt-1 text-center">
              {verifyMode === 'online' ? 'cloud round-trip per step' : 'air-gapped local check'}
            </span>
          </div>

          {/* cloud */}
          <div className="flex-1 min-w-[220px] text-right">
            <div className="text-xs text-text-muted uppercase tracking-wide">Cloud (public registry)</div>
            <div className="text-sm text-text font-medium mt-1">IDProva Registry</div>
            <div className="text-xs text-accent font-mono mt-0.5">idprova-registry.fly.dev</div>
          </div>
        </div>
        <p className="text-xs text-text-muted mt-3">
          The agent runs on our own hardware, but every action it takes is checked against a scoped
          permission (DAT). Overreach — deploy, force-push, delete, protected-push — is{' '}
          <span className="text-danger font-medium">denied by construction</span>, and every decision
          (allow <span className="text-success">and</span> deny) is written to a tamper-evident receipt.
        </p>
      </div>

      {/* ── summary chips ────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-success/20 text-success border-success/30">
          {allow} ALLOW
        </span>
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-danger/20 text-danger border-danger/30">
          {deny} DENY
        </span>
        <span className="text-xs text-text-muted">source: {source}</span>
      </div>

      {/* ── timeline ─────────────────────────────────────────────────── */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-2 border-b border-border text-xs text-text-muted uppercase tracking-wide">
          Timeline · {events.length} tool calls, each gated by the policy gateway
        </div>
        {error && <div className="px-4 py-3 text-sm text-danger">{error}</div>}
        <ol>
          {events.map((e, i) => {
            const allowed = e.decision === 'ALLOW';
            return (
              <li
                key={i}
                className={`flex items-start gap-3 px-4 py-3 border-b border-border last:border-b-0 ${
                  allowed ? '' : 'bg-danger/5'
                }`}
              >
                <span className="text-xs text-text-muted font-mono w-6 shrink-0 mt-0.5">#{e.receipt_seq}</span>
                <span
                  className={`inline-flex items-center justify-center px-2 py-0.5 rounded text-xs font-semibold border shrink-0 w-16 ${
                    allowed
                      ? 'bg-success/20 text-success border-success/30'
                      : 'bg-danger/20 text-danger border-danger/30'
                  }`}
                >
                  {e.decision}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm text-text font-medium font-mono">{e.tool}</span>
                    <span className="text-xs text-text-muted font-mono">{e.scope}</span>
                    {verifyMode === 'online' && (
                      <span className="text-[10px] text-accent">↗ verified against fly registry</span>
                    )}
                  </div>
                  <div className={`text-xs mt-0.5 ${allowed ? 'text-text-muted' : 'text-danger'}`}>{e.reason}</div>
                </div>
                <span className="text-[10px] text-text-muted font-mono shrink-0 mt-0.5">{e.ts}</span>
              </li>
            );
          })}
        </ol>
      </div>

      {/* ── receipt footer ───────────────────────────────────────────── */}
      <div className="bg-surface border border-border rounded-lg p-4 space-y-2">
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border bg-success/20 text-success border-success/30">
            verified offline ✓
          </span>
          <span className="text-xs text-text-muted">
            hash-chained receipt log ({events.length} entries) — verifies with the public key only
          </span>
        </div>
        <div className="text-xs text-text-muted">Receipt log (on CT204):</div>
        <code className="block text-xs bg-bg border border-border rounded px-3 py-2 text-text font-mono break-all">
          {RECEIPT_LOG_PATH}
        </code>
        <div className="text-xs text-text-muted">Verify the chain (no network, no secrets):</div>
        <code className="block text-xs bg-bg border border-border rounded px-3 py-2 text-accent font-mono break-all">
          idprova receipt verify {RECEIPT_LOG_PATH}
        </code>
      </div>

      {/* ── data source controls ─────────────────────────────────────── */}
      <details className="bg-surface2 border border-border rounded-lg p-4">
        <summary className="text-xs text-text-muted cursor-pointer">Load a different run (scenario_events.jsonl)</summary>
        <div className="mt-3 space-y-3">
          <div className="flex items-center gap-2 flex-wrap">
            <input
              type="text"
              value={eventsUrl}
              onChange={ev => setEventsUrl(ev.target.value)}
              className="text-xs flex-1 min-w-[220px] px-2 py-1"
              placeholder="/scenario_events.jsonl or https://…"
            />
            <button
              onClick={loadFromUrl}
              className="text-xs px-3 py-1 rounded border border-border text-accent hover:border-accent"
            >
              Fetch
            </button>
            <label className="text-xs px-3 py-1 rounded border border-border text-text-muted hover:text-text cursor-pointer">
              Upload…
              <input type="file" accept=".jsonl,.json,.txt" onChange={onUpload} className="hidden" />
            </label>
          </div>
          {loadError && <div className="text-xs text-danger">Load failed: {loadError}</div>}
          <textarea
            value={raw}
            onChange={ev => {
              setRaw(ev.target.value);
              setSource('pasted');
            }}
            rows={5}
            className="w-full text-xs font-mono px-2 py-1"
            spellCheck={false}
          />
        </div>
      </details>
    </div>
  );
}
