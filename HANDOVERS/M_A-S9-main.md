# Handover — Tracks M+A Session 9 (Main Agent)
**Date:** 2026-03-09 | **Agent:** MAIN | **Tests:** 163 | **Build:** clean | **Branch:** main

## GSD State

Progress: 70% (12 of 17 phases done)

Tracks completed this session: M (all 3 phases), A (both phases)
Workers running: B (Track S), D (Track D new docs)

## Completed This Session

- [x] M-1b: calculate tool (evalexpr, rejects >200 chars, div-by-zero), read_public_file (sandboxed to public/, path traversal blocked), public/readme.txt — 16 tests in mcp-demo, all passing
- [x] M-2: demo-mcp.ps1 — 10-step end-to-end MCP demo (registry → register → MCP → valid DAT → echo → calculate → expired DAT 401 → wrong-scope 403 → receipt log → BLAKE3 chain)
- [x] A-1a: demo-a2a.ps1 — Alice→Bob→Charlie delegation chain, scope narrowing, depth tracking, receipt audit trail
- [x] A-1b: test-tamper.ps1 — 4 tamper tests: tampered scope, flipped signature, wrong scope 403, JTI revocation
- [x] Workers B+D: restarted context-rotators after they died (both at 44e119f)

## Remaining

### For MAIN-AGENT (Next Session)
- [ ] Track I-1: Review/complete .github/workflows/ci.yml + add release.yml + README CI badge
- [ ] Track I-2: Review/complete Dockerfile + add docker-compose.yml
- [ ] Track I-3: fly.toml + DEPLOY.md — **STOP, DO NOT fly deploy without Pratyush approval**
- [ ] Track V-2: Dashboard polish — "Run Demo Flow" button, receipt viewer, DAT timeline (needs GET /receipts from MCP, now available)
- [ ] IDPROVA-MASTER.md update — mark M + A complete

### Workers Autonomous (parallel)
- Worker B (CT 202): Track S-1 — sdks/python/idprova_http.py + idprova_langchain.py + examples/python/
- Worker D (CT 203): Track D — openapi.yaml + docs/compliance.md + docs/mcp-auth.md + DEMO-VIDEO-SCRIPT.md

## Files Changed This Session

| File | Change |
|------|--------|
| `crates/idprova-mcp-demo/src/main.rs` | M-1b: +calculate, +read_public_file, +10 new tests (636 lines total, 16 tests) |
| `crates/idprova-mcp-demo/public/readme.txt` | New — sample public file for read_file tool |
| `crates/idprova-mcp-demo/Cargo.toml` | Added evalexpr = { workspace = true } |
| `Cargo.toml` | Added evalexpr = "11" to workspace.dependencies |
| `Cargo.lock` | Updated for evalexpr v11.3.1 |
| `demo-mcp.ps1` | New — Track M-2 end-to-end MCP demo (332 lines) |
| `demo-a2a.ps1` | New — Track A-1a Alice→Bob→Charlie delegation demo |
| `test-tamper.ps1` | New — Track A-1b tamper detection test suite |

## Test Baseline

**CT 204 test run: 163 passing, 0 failed**
- idprova-core: 126
- idprova-verify: 16
- idprova-registry: 5
- idprova-mcp-demo: 16
- (doc tests: pass)

## Key Commits (this session)

```
44e119f feat: Track A — demo-a2a.ps1 + test-tamper.ps1
49359f1 feat: Track M-2 — demo-mcp.ps1 end-to-end MCP demo script
5c8ad6f chore: update Cargo.lock for evalexpr dependency (Track M-1b)
a8e3ead feat: Track M-1b — calculate + read_public_file tools, 17 tests
```

## Decisions Made

- `read_public_file` tool uses env var `PUBLIC_DIR` (default: `./public`) — allows test isolation with TempDir
- `calculate` errors return JSON-RPC level errors (not HTTP 400) for graceful handling by MCP clients
- Demo scripts use PowerShell 5.1+ compatible syntax (no PS 7 features)
- Worker B/D context-rotators need periodic health check — they died between sessions (restart with nohup /path/context-rotator.sh {letter})

## Known Issues

- Workers B/D have separate `.planning/` dirs with their own STATE.md. They push to `/home/claude/idprova` (the push target), not directly to head. After workers complete, head needs `git fetch worker-{b,d} main` to pull their commits.
- `dat issue --max-delegation-depth` flag: verify it exists in the CLI (was added in M7 work). If not, remove from demo scripts.
- demo-a2a.ps1 uses `$tmpDir = New-TemporaryFile |...` pattern — works on PS 5.1+

## Resume Point

Milestone: I (Infrastructure) | Phase: I-1 (CI/CD)
Next: `cat HANDOVERS/M_A-S9-main.md` then start Track I-1
Also check: `git fetch worker-b main && git log --oneline worker-b/main -5` to see if Worker B committed anything
