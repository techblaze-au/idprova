# CLAUDE.md — IDProva Track E: Infrastructure & CI/CD

IDProva is an open protocol for AI agent identity — Rust core crate with Ed25519 crypto, Agent Identity Documents (AIDs), Delegation Attestation Tokens (DATs), hash-chained receipts, and RBAC constraint engine.

## Track Scope (STRICT)

**YOU MAY MODIFY:**
- `.github/` — CI/CD workflows and Actions
- `Dockerfile` — container build
- `docker-compose.yml` — multi-container setup (create if needed)
- `scripts/` — build/deploy scripts (create if needed)
- `.planning/` — GSD state files

**YOU MUST NOT MODIFY:**
- `crates/` — any Rust source code
- `sdks/`
- `docs/`
- `README.md`
- `Cargo.toml` (read-only reference)
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

## Commands

```bash
cargo build --workspace                    # Verify Rust builds
cargo test --workspace                     # Verify tests pass
cargo clippy --workspace -- -D warnings    # Lint check
cargo fmt --all -- --check                 # Format check
docker build -t idprova-registry .         # Build Docker image
```

## Workspace Structure

```
Cargo.toml          # Workspace manifest (7 members)
crates/
  idprova-core/     # Core library
  idprova-cli/      # CLI tool
  idprova-registry/ # Registry server (Axum + SQLite)
  idprova-verify/   # Verification library
  idprova-middleware/ # HTTP middleware
sdks/
  python/           # PyO3 bindings (needs PYO3_PYTHON env)
  typescript/       # napi-rs bindings
```

## CI/CD Design Notes

- Rust toolchain: `1.75` minimum (rust-version in Cargo.toml)
- Python SDK needs `PYO3_PYTHON` env var — skip in basic CI or set up properly
- TypeScript SDK needs Node.js + napi-rs build tools
- Workspace excludes for CI: `--exclude idprova-python --exclude idprova-typescript` (SDK crates need special setup)
- SQLite bundled via `rusqlite` `bundled` feature — no system dep needed
- Docker multi-stage build already exists in `Dockerfile`

## Git

- Branch: `idprova/track-e-infra`
- Commit messages: imperative mood, prefix with `ci:`, `infra:`, `docker:`
- **Always** `Authored-By: Pratyush <hello@techblaze.com.au>`
- Do NOT push — head node collects via fetch
