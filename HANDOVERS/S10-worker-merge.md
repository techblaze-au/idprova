# Handover: Session 10 — Worker Merge In Progress
**Date:** 2026-03-09
**Session:** 10 (main agent)
**Status:** BUILD FAILING — needs fix before commit

---

## What Was Accomplished This Session

### Workers Authenticated & Run
- All 3 workers (CT 202/203/204) were authenticated via `claude auth login` as `dev` user
- Workers ran autonomously using context-rotator.sh

### Worker Results
| Worker | CT | Track | Status | Key Commits |
|--------|-----|-------|--------|-------------|
| B | 202 | Track S — Python SDK | COMPLETE | `4ef9777` (feat: Track S Python SDK complete) |
| D | 203 | Track D — Docs corrections (old plan) | COMPLETE | `728022b` |
| E | 204 | Track D — Docs corrections (old plan) | COMPLETE | `ad111c2` |

**Note:** Workers D and E both ran the OLD "Track D — Documentation & Website" plan that was git-tracked in the repo. They did NOT do the NEW tracks (openapi.yaml, compliance.md, fly.toml) — those still need to be done.

### What Workers Produced
- **Worker B**: `sdks/python/idprova_http.py`, `sdks/python/idprova_langchain.py`, `examples/python/` — Python SDK
- **Workers D & E**: Fixed docs accuracy: `docs/api-reference.md`, `docs/concepts.md`, `docs/core-api.md`, `docs/sdk-python.md`, `docs/sdk-typescript.md`, `docs/security.md` — corrected scope grammar (3→4-part), API accuracy

### Merge Status
Worker commits were merged to local main via git bundles from CT 201. Merge is done at `2ae342f`.

---

## CURRENT PROBLEM: BUILD FAILING

**7 tests fail** in `dat::token::tests` and `policy::evaluator::tests`:
```
test dat::token::tests::test_verify_config_attestation_pass ... FAILED
test dat::token::tests::test_verify_constraint_rate_limit_blocks ... FAILED
test dat::token::tests::test_verify_delegation_depth_at_limit_passes ... FAILED
test dat::token::tests::test_verify_delegation_depth_blocked ... FAILED
test dat::token::tests::test_verify_happy_path ... FAILED
test dat::token::tests::test_verify_wildcard_scope_passes ... FAILED
test policy::evaluator::tests::test_policy_evaluator_wildcard_scope ... FAILED
```

**Root cause:** Tests use 3-part scope strings (e.g. `"mcp:tool:read"`) but `scope.rs` now requires 4-part (`"namespace:protocol:resource:action"`). The scope.rs parse() already has:
```rust
if parts.len() != 4 {
    return Err(...);
}
```
And there's even a test `test_parse_scope_rejects_3_parts` confirming this.

### Files Restored During Merge (working state)
These were lost in the merge and had to be restored manually:
- `crates/idprova-core/src/dat/constraints.rs` — restored from origin/main ✅
- `crates/idprova-core/src/http.rs` — restored from origin/main ✅
- `crates/idprova-core/src/lib.rs` — `pub mod http;` re-added ✅
- `crates/idprova-core/Cargo.toml` — `zeroize` and `serde_json_canonicalizer` re-added ✅
- `crates/idprova-core/src/dat/mod.rs` — added `pub mod constraints;` ✅
- `crates/idprova-core/src/policy/constraints.rs` — restored from origin/main ✅
- `crates/idprova-core/src/policy/inheritance.rs` — restored from origin/main ✅
- `crates/idprova-core/src/policy/evaluator.rs` — restored from origin/main ✅
- `crates/idprova-verify/src/lib.rs` — restored from origin/main ✅
- `crates/idprova-registry/src/main.rs` line 187 — uses `dat::constraints::EvaluationContext::default()` (correct) ✅

### Currently Uncommitted Modified Files
These are staged/modified but NOT yet committed:
```
M  crates/idprova-cli/src/commands/dat.rs
M  crates/idprova-core/Cargo.toml
M  crates/idprova-core/src/dat/chain.rs
M  crates/idprova-core/src/dat/mod.rs
M  crates/idprova-core/src/dat/token.rs
M  crates/idprova-core/src/lib.rs
M  crates/idprova-core/src/policy/constraints.rs
M  crates/idprova-core/src/policy/evaluator.rs
M  crates/idprova-core/src/policy/inheritance.rs
M  crates/idprova-registry/src/main.rs
M  crates/idprova-registry/src/store.rs
M  crates/idprova-verify/src/lib.rs
M  web/vite.config.ts
```
Plus untracked: `WALKTHROUGH.md`, `dashboard/`, demo files, NCCoE docs.

---

## What To Do In Next Session

### Step 1: Fix the 7 Failing Tests (IMMEDIATE)

Find all test uses of 3-part scopes in token.rs and update to 4-part:

```bash
grep -n '"mcp:tool:read"\|"mcp:\*:\*"\|"a2a:agent:run"' crates/idprova-core/src/dat/token.rs
```

Change patterns like:
- `"mcp:tool:read"` → `"mcp:tool:filesystem:read"`
- `"mcp:*:*"` → `"mcp:*:*:*"`
- `"a2a:agent:run"` → `"a2a:agent:default:run"` (check actual 4-part format)

Also check and fix `policy/evaluator.rs` tests for same issue.

After fix: `cargo test --workspace --exclude idprova-python --exclude idprova-typescript` should be green (should reach 205+ tests passing).

### Step 2: Commit the Merge Fix
```bash
git add crates/ web/
git commit -m "fix: restore missing files lost in worker merge + fix 4-part scope in tests"
git push origin main
```

### Step 3: Remaining Tracks (NOT Done By Workers)

Workers did OLD docs plan. These NEW tracks were never executed:

| Track | Files to Create | Priority |
|-------|----------------|----------|
| Track D-new | `openapi.yaml` (OpenAPI 3.1.0, all 10 endpoints), `docs/compliance.md` (NIST+ISM), `docs/mcp-auth.md`, `DEMO-VIDEO-SCRIPT.md` | High |
| Track I | Dockerfile env fix (`IDPROVA_PORT`→`REGISTRY_PORT`), `docker-compose.yml`, `fly.toml`, `DEPLOY.md` | High |

**For Track I:** Check `Dockerfile` — does it use `IDPROVA_PORT` or `REGISTRY_PORT`? The binary uses `REGISTRY_PORT`. If wrong, fix it. Also create `docker-compose.yml` and `fly.toml`.

**For Track D-new:** `openapi.yaml` spec with all registry endpoints (GET /v1/aids, POST /v1/aids, GET /v1/aids/:id, POST /v1/dat/verify, POST /v1/dat/revoke, GET /receipts, etc.)

### Step 4: Session Startup Checklist
```bash
# 1. Read this handover
# 2. cargo test --workspace --exclude idprova-python --exclude idprova-typescript
# 3. Fix the 7 failing tests first
# 4. Then proceed to Track D-new and Track I
```

---

## Architecture Context

### Two EvaluationContext types (IMPORTANT)
- `idprova_core::dat::constraints::EvaluationContext` — simple, used by `Dat::verify()` and `idprova_verify::verify_dat()`
- `idprova_core::policy::EvaluationContext` — richer, used by `PolicyEvaluator`

The registry uses `dat::constraints::EvaluationContext` at line 187 for admin token verification (correct). The `verify_dat()` in idprova-verify also expects `dat::constraints::EvaluationContext`.

### Scope Format (IMPORTANT)
4-part required: `namespace:protocol:resource:action`
- ✅ `"mcp:tool:filesystem:read"`
- ✅ `"mcp:*:*:*"` (wildcard)
- ❌ `"mcp:tool:read"` (3-part — INVALID, will error)

### Worker Authentication
- Workers (CT 202/203/204) are now authenticated as `dev` user via OAuth
- To restart a worker: `ssh proxmox "pct exec 20X -- bash -c 'HOME=/home/dev su -l -c \"nohup /home/dev/context-rotator.sh {b|d|e} > /home/dev/swarm/logs/track-X.log 2>&1 &\" dev'"`
- Plans go in `/home/dev/idprova/.planning/phases/01/01-01-PLAN.md`
- Delete `.planning/TRACK_COMPLETE` before restart (it's no longer git-tracked)

### Git Topology
- Local Windows: `C:\Users\praty\toon_conversations\aidspec` — primary repo
- CT 201: `/root/idprova` — head dev VM, remotes: worker-b/d/e pointing to container IPs
- Workers: bundles via `pct exec CT -- git -C /home/dev/idprova bundle create ...` then `pct pull`
- Push: `git push origin main` → GitHub `techblaze-au/idprova`

---

## Skills to Invoke
```
/rust-pro
```
