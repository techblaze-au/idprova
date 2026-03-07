# CLAUDE.md — IDProva Track D: Documentation & Website

IDProva is an open protocol for AI agent identity — Rust core crate with Ed25519 crypto, Agent Identity Documents (AIDs), Delegation Attestation Tokens (DATs), hash-chained receipts, and RBAC constraint engine.

## Track Scope (STRICT)

**YOU MAY MODIFY:**
- `docs/` — all documentation files
- `README.md` — project readme
- `.planning/` — GSD state files

**YOU MUST NOT MODIFY:**
- `crates/` — any Rust source code
- `sdks/`
- `.github/`
- `Dockerfile`
- `Cargo.toml`
- `Cargo.lock`

## Autonomous Execution Mode

Run autonomously without waiting for user prompts:
- After reading the plan/handover, start executing immediately
- Execute each task sequentially
- After completing each task, move to the next without asking
- Only stop when:
  - A build or test failure you cannot resolve after 2 attempts
  - An architectural decision that changes the protocol
- Commit frequently — after each completed task
- Use `Authored-By: Pratyush <hello@techblaze.com.au>` in all commits
- **NEVER** use `Co-Authored-By: Claude`

## Context Window Management (MANDATORY)

You MUST maintain a live handover file at `.planning/HANDOVER.md` throughout execution.

### After EVERY completed task:
1. Update `.planning/HANDOVER.md` with:
   - Tasks completed (with commit hashes)
   - Current task in progress (if any)
   - Next task to execute
   - Key decisions made this session
   - Any blockers or issues found
   - The exact PLAN.md path being executed
   - Current plan progress (task X of Y)
2. Commit the handover: `git add .planning/HANDOVER.md && git commit -m "wip: handover update"`

### Session rotation rule:
- After completing 3 tasks in a single session, STOP.
- Write final HANDOVER.md update, commit it, then exit.
- Do NOT try to continue — a fresh session will pick up from HANDOVER.md.
- This keeps every session in the "fresh context" zone (~40-60% usage max).

### If you sense context degradation:
- Responses getting slower, tool calls failing, losing track of state
- IMMEDIATELY write HANDOVER.md and exit
- Do NOT wait to finish the current task — save partial state

### Track completion:
- When ALL tasks in the plan are done, write a final HANDOVER.md with status "COMPLETE"
- Then: `touch .planning/TRACK_COMPLETE`
- Then exit

## Project Structure Reference

```
crates/
  idprova-core/         # Core library (crypto, AID, DAT, receipts, policy, trust)
  idprova-cli/          # CLI tool (keygen, aid, dat, receipt commands)
  idprova-registry/     # Registry server (Axum + SQLite)
  idprova-verify/       # Verification library
  idprova-middleware/    # HTTP middleware
sdks/
  python/               # PyO3 bindings
  typescript/           # napi-rs bindings
docs/
  protocol-spec-v0.1.md # Protocol specification
  TRD.md               # Technical Reference Document
  STRIDE-THREAT-MODEL.md
  GAP-ANALYSIS.md
```

## Key Concepts for Documentation

- **AID** (Agent Identity Document): JSON document with DID, public key, capabilities, metadata
- **DAT** (Delegation Attestation Token): JWS-signed token for delegating permissions between agents
- **Scope grammar**: `namespace:resource:action` (3-part, colon-separated)
- **Trust levels**: L0 (anonymous) through L4 (hardware-attested)
- **Receipt chain**: Hash-chained action receipts for audit trail
- **Policy engine**: RBAC with 7 evaluators (scope, trust, time, rate, IP, delegation depth, custom)

## Git

- Branch: `idprova/track-d-docs-website`
- Commit messages: imperative mood, prefix with `docs:`
- **Always** `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT push — head node collects via fetch

## Documentation Standards

- Use clear, technical English
- Include code examples for every API endpoint and library function
- Show curl commands for HTTP endpoints
- Use mermaid diagrams for flows and architecture
- Reference the protocol spec (`docs/protocol-spec-v0.1.md`) for protocol details
