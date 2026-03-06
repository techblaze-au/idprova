# IDProva Master Task Board

> **Last Updated:** 2026-03-06
> **Plan File:** `C:\Users\praty\.claude\plans\rustling-roaming-peach.md` (full detail)
> **Notion:** Gap Analysis + Architecture Plan saved 2026-03-04

---

## Track Status

| Track | Branch | Current Phase | Session | Status | Unblocked By |
|-------|--------|--------------|---------|--------|-------------|
| **A** | `main` | **ALL MILESTONES DONE** | S8 | 🟢 **v0.1 FEATURE-COMPLETE** — 205 tests, all committed + pushed | — |
| **B** | `idprova/track-b-registry` | Phase 6 | — | 🟡 Partially done (M7 main hardening merged to A) | — |
| **C** | `idprova/track-c-sdk-cli` | Phase 7 | S1 | 🟢 Session C-1+C-2 DONE (persistence+config) | ✅ |
| **D** | `idprova/track-d-docs-website` | Doc stubs | S1 | 🟡 READY TO START | Nothing |
| **E** | `idprova/track-e-infra` | Phase 10 | — | 🟡 Unblocked — ready to start | ✅ |
| **F** | `idprova/track-f-advanced` | Phase 11+ | — | 🟡 Unblocked — ready to start | ✅ |

---

## Phase Completion Gates

- [x] **P0 complete** → unlock Track C (SDK/CLI work) — ✅ 2026-03-05
- [x] **P1 complete** → Phase 2 (RBAC) can start on Track A — ✅ 2026-03-05
- [x] **P2 complete** → RBAC Policy Engine fully implemented — ✅ 2026-03-06
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
| (no handover) | 2 | 4 | A | ✅ 2026-03-05 — RateLimit/IP/TrustLevel evaluators, 78 tests |
| `HANDOVERS/P2-S56-track-a.md` | 2 | 5-6 | A | ✅ 2026-03-06 — All evaluators + PolicyEvaluator + inheritance + RateTracker, 126 tests |
| `HANDOVERS/P7-S1-track-c.md` | 7 | 1 | C | ✅ 2026-03-05 — SDK persistence + CLI config, 81 tests |
| `HANDOVERS/M2-S7-track-a.md` | M2 | 7 | A | ✅ 2026-03-06 — M2 crypto pins in working tree |
| `HANDOVERS/M7-S8-track-a.md` | M7 | 8 | A | ✅ 2026-03-07 — ALL MILESTONES DONE, 205 tests |

---

## Critical Path (Track A — MUST COMPLETE IN ORDER)

### Phase 0 — Pre-Launch Critical Fixes ✅ DONE

- [x] **Session A-1** — JWS re-serialization, receipt sigs, hash dep, canonical JSON (42 tests)
- [x] **Session A-2** — 4-part scope grammar (`namespace:protocol:resource:action`), security hardening SR-1/SR-3/SR-4/SR-8/S5/S6/S7 (54 tests)

### Phase 1 — Security Hardening ✅ DONE

- [x] Zeroize private keys (ZeroizeOnDrop)
- [x] Hard-reject non-EdDSA algorithms
- [x] Max delegation depth (default 5, hard max 10)
- [x] Pin exact crypto crate versions
- [x] Remove unused hkdf dependency

### Phase 2 — RBAC Policy Engine ✅ DONE (2026-03-06)

- [x] **Session A-3** — EvaluationContext, PolicyDecision, ConstraintEvaluator trait + 7 stubs (63 tests)
- [x] **Session A-4** — RateLimitEvaluator, IpConstraintEvaluator, TrustLevelEvaluator (78 tests)
- [x] **Session A-5** — DelegationDepthEvaluator, GeofenceEvaluator, TimeWindowEvaluator, ConfigAttestationEvaluator (98 tests)
- [x] **Session A-6** — PolicyEvaluator engine, constraint inheritance validation, RateTracker (126 tests)

**Policy module structure:**
```
crates/idprova-core/src/policy/
  mod.rs          — re-exports
  context.rs      — EvaluationContext + builder
  decision.rs     — PolicyDecision, DenialReason (14 variants)
  constraints.rs  — ConstraintEvaluator trait + 7 implementations
  evaluator.rs    — PolicyEvaluator (scope→timing→constraints pipeline)
  inheritance.rs  — validate_constraint_inheritance()
  rate.rs         — RateTracker (thread-safe sliding-window counters)
```

### Phase 1 Leftovers (lower priority)
- [ ] **SR-10** — SQL injection test for registry store
- [ ] **S8** — Registry CORS
- [ ] **D1** — Fix Quick Start docs (`DelegationToken` → `Dat`)

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

**Session C-1** ✅ DONE (2026-03-05) — see HANDOVERS/P7-S1-track-c.md:
- [x] Python SDK: `AgentIdentity.save(path)` / `AgentIdentity.load(path)` (PyO3)
- [x] Python SDK: Expose `ReceiptLog.append()` in bindings
- [x] CLI: `~/.idprova/config.toml` support (registry URL, default key path)

**Session C-2** ✅ DONE (2026-03-05) — same handover:
- [x] TypeScript SDK: same persistence + receipt append (napi-rs)
- [ ] TypeScript SDK: config file support (deferred — config is CLI-focused)

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