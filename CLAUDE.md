# CLAUDE.md — IDProva Track B: Registry Hardening

IDProva is an open protocol for AI agent identity — Rust core crate with Ed25519 crypto, Agent Identity Documents (AIDs), Delegation Attestation Tokens (DATs), hash-chained receipts, and RBAC constraint engine.

## Track Scope (STRICT)

**YOU MAY MODIFY:**
- `crates/idprova-registry/` — registry server (Axum + SQLite)
- `crates/idprova-core/src/error.rs` — shared error types (if adding new variants)
- `Cargo.toml` — workspace deps (if adding new registry deps)
- `Cargo.lock` — auto-updated by cargo
- `.planning/` — GSD state files

**YOU MUST NOT MODIFY:**
- `crates/idprova-core/` (except error.rs)
- `crates/idprova-cli/`
- `crates/idprova-verify/`
- `crates/idprova-middleware/`
- `sdks/`
- `docs/`
- `.github/`
- `Dockerfile`
- `README.md`

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
- Run `cargo test --workspace` after every change

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

## Commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p idprova-registry
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Workspace Dependencies (key ones)

| Crate | Version | Notes |
|-------|---------|-------|
| `axum` | `0.7` | Registry HTTP framework |
| `tower-http` | `0.5` | Has `cors` + `trace` + `limit` features |
| `rusqlite` | `0.31` | Registry SQLite (bundled) |
| `ed25519-dalek` | `=2.1.1` | Crypto |
| `thiserror` | `1` | Error handling |

## Coding Conventions

- All errors use `IdprovaError` enum via `thiserror`
- Use `rusqlite::params![]` for all SQL queries (parameterized — NEVER string interpolation)
- Validate all URLs before HTTP requests (SSRF prevention)
- `deny_unknown_fields` on all serde structs that process external input
- Commit messages: imperative mood, prefix with `feat:`, `fix:`, `refactor:`, `test:`

## Git

- Branch: `idprova/track-b-registry`
- Commit messages: imperative mood
- **Always** `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT push — head node collects via fetch
