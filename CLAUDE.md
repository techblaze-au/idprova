# CLAUDE.md — IDProva Protocol

IDProva is an open protocol for AI agent identity — Rust core crate with Ed25519 crypto, Agent Identity Documents (AIDs), Delegation Attestation Tokens (DATs), hash-chained receipts, and RBAC constraint engine.

## Session Startup (MANDATORY — do this EVERY session)

```bash
# 1. Read the execution plan
cat HANDOVERS/NEXT-SESSION-PLAN.md

# 2. Read master board for track status
cat IDPROVA-MASTER.md

# 3. Find your resume point — read the LATEST handover
ls -t HANDOVERS/  # sorted by time, pick the newest for your track

# 4. Invoke skills
/rust-pro  # ALWAYS invoke this first
# Then invoke milestone-specific skills listed in NEXT-SESSION-PLAN.md

# 5. Verify green baseline BEFORE making any changes
cargo test --workspace

# 6. Resume from where the last session left off
```

**DO NOT** skip steps 1-5. The execution plan contains the full roadmap with 7 milestones and ~45 phases. Each milestone lists exact files, changes, and verification steps.

## Autonomous Execution Mode

**Run autonomously without waiting for user prompts.** Specifically:

- After reading the plan and handovers, **start executing immediately** — do not ask "should I start?" or "which milestone?"
- Execute each GSD phase sequentially within a milestone
- After completing each phase, move to the next one **without asking for permission**
- Only stop to ask the user when:
  - A decision is explicitly marked as "needs user input" in the plan
  - A build or test failure you cannot resolve after 2 attempts
  - You need to deploy (Vercel) or push to remote
- **Commit frequently** — after each completed phase, not just at milestone end
- Use `Authored-By: Pratyush <hello@techblaze.com.au>` in all commits — **NEVER** use `Co-Authored-By: Claude`

## Handover Protocol (CRITICAL — never skip)

**When your context window is getting large (~65% for complex work, ~90% otherwise):**

1. **STOP coding immediately** — do not try to squeeze in one more task
2. **Write a handover file:**
   ```
   HANDOVERS/{MILESTONE}-{SESSION}-{track}.md
   ```
3. **Include in the handover:**
   - Date and session identifier
   - What was completed (checklist with [x] marks)
   - What remains (checklist with [ ] marks)
   - All files changed with descriptions
   - Build status: `cargo test --workspace` result + test count
   - Known issues or warnings
   - **Exact resume point:** which milestone, which phase, which task
   - Skills to invoke in the next session
4. **Update IDPROVA-MASTER.md** — track status table with current phase/session
5. **Commit and push:**
   ```bash
   git add HANDOVERS/ IDPROVA-MASTER.md
   git commit -m "handover: {Milestone} {Session}"
   git push origin main
   ```
6. **Tell the user:** "Handover written. Next session should start with `cat HANDOVERS/NEXT-SESSION-PLAN.md`"

## Commands

```bash
# Build
cargo build --workspace                    # Build all crates
cargo build -p idprova-core                # Build specific crate
cargo build --workspace --exclude idprova-python --exclude idprova-typescript  # Skip SDK crates (need PYO3_PYTHON)

# Test
cargo test --workspace                     # Run all tests
cargo test -p idprova-core                 # Test specific crate
cargo test -- test_name                    # Run specific test

# Lint
cargo clippy --workspace -- -D warnings   # Strict clippy
cargo fmt --all -- --check                 # Format check

# Python SDK (needs special env)
PYO3_PYTHON="C:\Users\praty\AppData\Local\Programs\Python\Python313\python.exe" cargo build -p idprova-python

# TypeScript SDK
cargo build -p idprova-typescript

# Website (separate repo)
cd C:\Users\praty\toon_conversations\idprova-website
npm run build                              # Build docs site (32 pages)
npx vercel --prod --scope tech-blaze --yes # Deploy to idprova.dev
```

## Project Structure

```
aidspec/                          # Root workspace
  Cargo.toml                      # Workspace manifest with all deps
  IDPROVA-MASTER.md               # Master task board — source of truth
  HANDOVERS/                      # Session handover documents
    NEXT-SESSION-PLAN.md           # Full execution plan (7 milestones)
    P0-S1-track-a.md ... etc       # Completed session handovers
  crates/
    idprova-core/                  # Core library (crypto, AID, DAT, receipts, policy, trust)
      src/
        lib.rs                     # Module exports — NOTE: needs `pub mod policy;` added
        crypto/keys.rs             # Ed25519 KeyPair (generate, sign, verify)
        crypto/hash.rs             # BLAKE3 hashing (prefixed_blake3)
        aid/                       # Agent Identity Documents
        dat/                       # Delegation Attestation Tokens
          token.rs                 # Dat::issue(), Dat::verify(), JWS serialization
          scope.rs                 # 3-part scope grammar (namespace:resource:action)
          chain.rs                 # Delegation chain validation
          constraints.rs           # DatConstraints struct (11 constraint fields)
        receipt/                   # Hash-chained action receipts
        policy/                    # RBAC policy engine (7 evaluators, engine, inheritance, rate tracking)
        trust/                     # Trust levels L0-L4
    idprova-cli/                   # CLI tool (9 commands)
      src/
        main.rs                    # Clap-based CLI with config loading
        config.rs                  # ~/.idprova/config.toml support
        commands/                  # keygen, aid, dat, receipt subcommands
    idprova-registry/              # Registry server (Axum + SQLite)
      src/
        main.rs                    # HTTP server (6 endpoints, NO CORS yet)
        store.rs                   # SQLite store (aids + dat_revocations tables)
  sdks/
    python/                        # PyO3 bindings (AgentIdentity, KeyPair, Dat, ReceiptLog)
    typescript/packages/core/      # napi-rs bindings (same API surface)
```

## Workspace Dependencies (key ones)

| Crate | Version | Notes |
|-------|---------|-------|
| `ed25519-dalek` | `2` | **Needs: pin exact + add `zeroize` feature** (M2) |
| `blake3` | `1` | **Needs: pin exact** (M2) |
| `sha2` | `0.10` | **Needs: pin exact** (M2) |
| `hkdf` | `0.12` | **UNUSED — remove** (M2) |
| `axum` | `0.7` | Registry HTTP framework |
| `tower-http` | `0.5` | Has `cors` + `trace` features (CORS not yet used) |
| `reqwest` | `0.12` | In workspace deps but **not yet used** — for Phase 3 HTTP client |
| `rusqlite` | `0.31` | Registry SQLite (bundled) — uses parameterized queries |

## Coding Conventions

### Rust Patterns
- All errors use `IdprovaError` enum via `thiserror` (see `error.rs`)
- Use `Result<T>` (re-exported from `error.rs`, wraps `IdprovaError`)
- Canonical JSON: `serde_json_canonicalizer` for deterministic serialization
- Scope grammar: 3-part `namespace:resource:action` — uses `splitn(3, ':')`
- Receipt signing: serialize with empty signature field → sign → fill hex signature
- Identity persistence: directory-based `~/.idprova/identities/{name}/` with `secret.key` (hex), `aid.json`, `identity.json`

### Security Rules
- **NEVER** commit private keys (*.key, *.pem in .gitignore)
- Use `rusqlite::params![]` for all SQL queries (parameterized)
- Validate all URLs before HTTP requests (SSRF prevention)
- EdDSA-only — hard-reject any other algorithm in DAT verification
- `deny_unknown_fields` on all serde structs that process external input

### Git
- Branch naming: `idprova/{milestone-name}` for worktrees
- Commit messages: imperative mood, prefix with `feat:`, `fix:`, `refactor:`, `test:`, `docs:`
- **Always** `Authored-By: Pratyush <hello@techblaze.com.au>` — never Claude co-author
- Push to `origin main` — repo is `techblaze-au/idprova` (private)

## Known Issues

1. **`pub mod policy;` missing from lib.rs** — Phase 2 code exists but isn't exported (fix in M1)
2. **PyO3 build needs env var:** `PYO3_PYTHON="C:\Users\praty\AppData\Local\Programs\Python\Python313\python.exe"`
3. **CLI resolve/verify are placeholders** — print messages but don't make HTTP calls yet (fix in M4)
4. **Registry has no CORS, no auth, no rate limiting** — fix in M3 + M7
5. **Crypto crate versions not pinned** — minor bump could break things (fix in M2)
6. **Vercel auto-deploy not connected** — private org repo on Hobby plan; deploy manually with `npx vercel --prod`

## User Preferences (Pratyush)

- **Concise responses** — skip explanations unless asked
- **Action-oriented** — do the work, don't describe what you'll do
- **Always verify builds** — `cargo test --workspace` before saying "done"
- **11 PM hard stop** — remind once per session if working past 10:30 PM
- **Family time 6-8:30 PM** — unavailable
- **Pragmatic over perfect** — ship working solutions, iterate later
