# IDProva Master Task Board

> **Last Updated:** 2026-03-05
> **Plan File:** `C:\Users\praty\.claude\plans\rustling-roaming-peach.md` (full detail)
> **Notion:** Gap Analysis + Architecture Plan saved 2026-03-04

---

## Track Status

| Track | Branch | Current Phase | Session | Status | Unblocked By |
|-------|--------|--------------|---------|--------|-------------|
| **A** | `idprova/track-a-core-security` | Phase 2 | S3 | 🟢 P2 scaffolding DONE (63 tests) | Nothing |
| **B** | `idprova/track-b-registry` | Phase 6 | — | 🔴 BLOCKED | Track A Phase 4 done |
| **C** | `idprova/track-c-sdk-cli` | Phase 7 | — | 🟡 UNBLOCKED | Track A Phase 0 ✅ |
| **D** | `idprova/track-d-docs-website` | Doc stubs | S1 | 🟡 READY TO START | Nothing |
| **E** | `idprova/track-e-infra` | Phase 10 | — | 🔴 BLOCKED | A+B near complete |
| **F** | `idprova/track-f-advanced` | Phase 11+ | — | 🔴 BLOCKED | A+B complete |

---

## Phase Completion Gates

- [x] **P0 complete** → unlock Track C (SDK/CLI work) — ✅ 2026-03-05
- [x] **P1 complete** → Phase 2 (RBAC) can start on Track A — ✅ 2026-03-05
- [ ] **P4 complete** → unlock Track B (Registry hardening)
- [ ] **P5 complete** → unlock Track F (Advanced: A2A/SPIFFE)
- [ ] **P6 complete** → unlock Track E (Infra/Release)
- [ ] **All tracks (A-D) complete** → unlock Track F advanced phases

---

## Handovers

| File | Phase | Session | Track | Status |
|------|-------|---------|-------|--------|
| `HANDOVERS/P0-S1-track-a.md` | 0 | 1 | A | ✅ 2026-03-05 — S1/S2/S3/S4 fixed, 42 tests |
| `HANDOVERS/P1-S2-track-a.md` | 1 | 2 | A | ✅ 2026-03-05 — D2/SR-1/SR-3/SR-4/SR-8/S5/S6/S7, 54 tests |
| `HANDOVERS/P2-S3-track-a.md` | 2 | 3 | A | ✅ 2026-03-05 — Policy module scaffolding, 63 tests |

---

## Critical Path (Track A — MUST COMPLETE IN ORDER)

### Phase 0 — Pre-Launch Critical Fixes (2 sessions)

**Session A-1** ✅ DONE (2026-03-05) — see HANDOVERS/P0-S1-track-a.md:
- [x] **S1: JWS re-serialization** — raw_header_b64/raw_claims_b64 on Dat, verify uses original bytes
- [x] **S2: Receipt signatures never verified** — Receipt::verify_signature() + ReceiptLog::verify_integrity_with_key()
- [x] **S3: Receipt hash circular dep** — ReceiptSigningPayload excludes signature field
- [x] **S4: Non-canonical JSON** — serde_json_canonicalizer (RFC 8785 JCS) in to_canonical_json()

**Session A-2** (NEXT):
- [ ] **D1: Fix Quick Start API mismatch**
  - File: `idprova-website/src/content/docs/docs/quick-start.mdx`
  - Fix: Update all `DelegationToken::issue()` → `Dat::issue()`, fix Duration → DateTime<Utc>
- [ ] **D2: Scope grammar decision** (discuss with Pratyush first)
  - Options: (a) 3-part with literal colons in action names, (b) 4-part with path hierarchy
  - File: `crates/idprova-core/src/dat/scope.rs`

---

### Phase 1 — P0 Security Hardening (2 sessions)

**Session A-3**:
- [ ] **SR-1: Zeroize private keys** — enable `ed25519-dalek/zeroize`, derive `ZeroizeOnDrop` on `KeyPair`
- [ ] **S5: Remove `secret_bytes()` from public API** — `crates/idprova-core/src/crypto/keys.rs`
- [ ] **S6: Pin exact versions for crypto crates** — `Cargo.toml`
- [ ] **S7: Remove unused `hkdf` dependency** — `Cargo.toml`

**Session A-4**:
- [ ] **SR-3: Hard-reject non-EdDSA algorithms** — `crates/idprova-core/src/dat/token.rs`
- [ ] **SR-8: Max delegation depth** — `crates/idprova-core/src/dat/chain.rs`
- [ ] **S8: Registry CORS/CSRF** — `crates/idprova-registry/src/main.rs`
- [ ] **SR-4: Test deny_unknown_fields** — add injection tests

---

### Phase 2 — RBAC Policy Engine (4 sessions)

See plan file Phase 2 section for full detail.

---

### Phase 3 — SSRF + Secure HTTP (1 session)

See plan file Phase 3 section.

---

### Phase 4 — idprova-verify crate (2 sessions)

See plan file Phase 4 section.

---

### Phase 5 — idprova-middleware crate (2 sessions)

See plan file Phase 5 section.

---

## Track C — SDK & CLI (Starts After Phase 0)

### Phase 7 — SDK Fixes (2 sessions)

**Session C-1**:
- [ ] Python SDK: `AgentIdentity.save(path)` / `AgentIdentity.load(path)` (PyO3)
- [ ] Python SDK: Expose `ReceiptLog.append()` in bindings
- [ ] CLI: `~/.idprova/config.toml` support (registry URL, default key path)

**Session C-2**:
- [ ] TypeScript SDK: same persistence + receipt append (napi-rs)
- [ ] TypeScript SDK: config file support

---

## Track D — Docs & Website (Start Immediately)

### Session D-1 (start NOW, parallel with Track A):
- [ ] `cd C:\Users\praty\toon_conversations\aidspec && git init && git add . && git commit -m "chore: initial commit"`
- [ ] `cd C:\Users\praty\toon_conversations\idprova-website && git init && git add . && git commit -m "chore: initial commit"`
- [ ] In tech-blaze-web: `git add src/pages/idprova.astro && git commit -m "feat: add IDProva landing page"`
- [ ] Fix Windows-specific npm deps in `idprova-website/package.json`

### Sessions D-2 through D-5: Write all 10 doc stub pages

### Sessions D-6 through D-8: Deploy + Playground

---

## How to Start a New Session

```bash
# 1. Read this file
cat C:\Users\praty\toon_conversations\aidspec\IDPROVA-MASTER.md

# 2. Read latest handover for your track
ls C:\Users\praty\toon_conversations\aidspec\HANDOVERS\

# 3. Check out your worktree
cd C:\Users\praty\toon_conversations\aidspec
git worktree list

# 4. Verify green
cargo test --workspace

# 5. Start coding
```

## Handover Protocol

When context is ~65% full, stop coding and write:
```
HANDOVERS/P{phase}-S{session}-{track}.md
```

Then:
```bash
git add HANDOVERS/ && git commit -m "handover: Phase N Session M Track X"
git push
touch .agent-signals/handoffs/P{N}-S{M}-{track}.done
```

---

*Master board updated at each session start/end. Source of truth for all IDProva development.*