# Handover: Phase 1, Session 2, Track A
**Date:** 2026-03-05
**Branch:** `idprova/track-a-core-security`
**Agent:** BE (Rust senior)
**Commit:** e4c86aa

---

## ✅ Completed This Session

### D2 — 4-Part Scope Grammar (BREAKING CHANGE — decided by Pratyush)
- **File:** `crates/idprova-core/src/dat/scope.rs`
- `Scope` struct now has 4 fields: `namespace`, `protocol`, `resource`, `action`
- Grammar: `namespace:protocol:resource:action` (e.g., `mcp:tool:filesystem:read`)
- `parse()` uses `splitn(5, ':')` and requires exactly 4 parts — 3-part scopes now return `Err`
- `covers()` checks all 4 fields
- All existing 3-part test scopes updated: `mcp:tool:read` → `mcp:tool:*:read`, `mcp:*:*` → `mcp:*:*:*`
- 5 new tests including `test_parse_scope_rejects_3_parts`, wildcard action-only, partial wildcard narrowing

### SR-1 — Zeroize Private Keys
- **Files:** `crates/idprova-core/src/crypto/keys.rs`, `Cargo.toml`, `crates/idprova-core/Cargo.toml`
- `ZeroizeOnDrop` derived on `KeyPair` — signing key bytes zeroed from memory on drop
- Added `zeroize = { version = "1", features = ["derive"] }` to workspace deps
- Added `"zeroize"` feature to `ed25519-dalek` dep

### SR-3 — Hard-Reject Non-EdDSA Algorithms
- **File:** `crates/idprova-core/src/dat/token.rs`
- `DatHeader::validate()` method added — rejects any `alg` != `"EdDSA"` (exact case)
- `from_compact()` calls `header.validate()` immediately after deserialization
- Tests: `test_sr3_rejects_non_eddsa_algorithms` — crafts compact JWS with each bad alg value

### SR-4 — Deny Unknown JWS Header Fields
- `deny_unknown_fields` already existed on `DatHeader`
- Added `test_sr4_rejects_unknown_header_fields` — injects `jwk`, `jku`, `x5u`, `crit`, `x5c`, `x5t`

### SR-8 — Maximum Delegation Depth
- **File:** `crates/idprova-core/src/dat/chain.rs`
- `ChainValidationConfig` struct with `max_depth: u32` (default 5, hard max `HARD_MAX_DEPTH = 10`)
- `with_max_depth(n)` clamps to `HARD_MAX_DEPTH` — config of 20 → 10
- `validate_chain_with_config(chain, &config)` — new with depth check
- `validate_chain(chain)` — unchanged signature, uses default config
- 4 new tests: depth-5 passes, depth-6 fails, custom depth-8, hard-max clamp

### S5 — Remove `secret_bytes()` from Public API
- **File:** `crates/idprova-core/src/crypto/keys.rs`
- Changed `pub fn secret_bytes()` → `pub(crate) fn secret_bytes()`
- External callers cannot access raw private key bytes; use `sign()` instead

### S6 — Pin Exact Crypto Crate Versions
- **File:** `Cargo.toml` (workspace)
- `ed25519-dalek = "=2.1.1"`, `blake3 = "=1.5.4"`, `sha2 = "=0.10.8"`

### S7 — Remove Unused `hkdf` Dependency
- Removed from `[workspace.dependencies]` and `crates/idprova-core/Cargo.toml`

---

## 🔄 In Progress (pick up here)

Nothing in progress — clean handover.

---

## ❌ Not Started (Phase 2 — RBAC Policy Engine)

**This is the next major phase.** See plan file for full detail.

### Phase 2 — RBAC Policy Engine (4 sessions, A-3 through A-6)

New module: `crates/idprova-core/src/policy/`

**Files to create:**
```
policy/
  mod.rs             — re-exports
  context.rs         — EvaluationContext struct
  constraints.rs     — ConstraintEvaluator trait + 7 built-in evaluators
  evaluator.rs       — PolicyEvaluator (main engine)
  decision.rs        — PolicyDecision, DenialReason
  rate.rs            — RateTracker (in-memory action counting)
  revocation.rs      — RevocationChecker trait + types
  inheritance.rs     — Constraint inheritance validation
```

**New dep needed:** `ipnet = "2"` (CIDR matching for IpConstraintEvaluator)

**Session A-3 target:** `context.rs` + `decision.rs` + `constraints.rs` (trait + stubs for 7 evaluators)
**Session A-4 target:** Implement `RateLimitEvaluator` + `IpConstraintEvaluator` + `TrustLevelEvaluator`
**Session A-5 target:** Implement `GeofenceEvaluator` + `TimeWindowEvaluator` + `ConfigAttestationEvaluator` + `DelegationDepthEvaluator`
**Session A-6 target:** `PolicyEvaluator` (main engine) + integration + constraint inheritance + 25-30 tests

**Also remaining (Phase 1 leftovers):**
- **SR-10** — SQL injection test for registry store (`cargo test -p idprova-registry`)
- **S8** — Registry CORS: configure allowed origins, require `X-IDProva-Request: 1` on writes
- **D1** — Fix Quick Start docs: `DelegationToken` → `Dat`, `Duration` → `DateTime<Utc>`

---

## 🧪 Test Status

- **Before Session A-2:** 47 tests passing
- **After Session A-2:** 54 tests passing (+7 new)
- **Failing:** None
- **New tests:**
  - `dat::scope::tests::test_parse_scope_rejects_3_parts`
  - `dat::scope::tests::test_scope_wildcard_action_only`
  - `dat::scope::tests::test_scope_set_narrowing_partial_wildcard`
  - `dat::scope::tests::test_scope_display`
  - `dat::token::tests::test_sr3_rejects_non_eddsa_algorithms`
  - `dat::token::tests::test_sr4_rejects_unknown_header_fields`
  - `dat::chain::tests::test_chain_depth_5_passes_default_config`
  - `dat::chain::tests::test_sr8_chain_depth_6_fails_default_config`
  - `dat::chain::tests::test_sr8_custom_depth_config`
  - `dat::chain::tests::test_sr8_hard_max_depth_10_cannot_be_exceeded`
  - `dat::chain::tests::test_chain_depth_10_passes_hard_max`

---

## 🔑 Key Decisions Made

1. **D2 scope grammar**: Chose 4-part `namespace:protocol:resource:action`. Breaking change approved by Pratyush. All existing 3-part scopes updated in tests.
2. **SR-8 default depth**: Set to 5 (covers `human → orchestrator → sub-agent → tool → tool-tool` but no deeper). Hard max of 10 cannot be bypassed.
3. **S5 approach**: Used `pub(crate)` rather than full removal, as `secret_bytes()` is still needed internally for key serialization (Phase 8 key encryption will add encrypted export).
4. **Web Playground confirmed**: Pratyush confirmed Phase 9 (browser playground) is in scope. Track D should prioritize this once docs are set up.

---

## 🚫 Blocking Issues

None. Track A ready for Phase 2.

---

## 📋 Next Session Instructions

```bash
# 1. Navigate to Track A worktree
cd C:\Users\praty\toon_conversations\aidspec\worktrees\track-a

# 2. Confirm branch and tests
git branch  # should show * idprova/track-a-core-security
cargo test -p idprova-core  # should show 54 passed

# 3. Read this handover

# 4. Session A-3: Start Phase 2 RBAC Policy Engine
#    a. Add `ipnet = "2"` to workspace Cargo.toml
#    b. Create `crates/idprova-core/src/policy/` directory
#    c. Create context.rs — EvaluationContext struct
#    d. Create decision.rs — PolicyDecision, DenialReason
#    e. Create constraints.rs — ConstraintEvaluator trait + 7 evaluator stubs
#    f. Create mod.rs — pub use everything
#    g. Add `pub mod policy;` to lib.rs
#    h. Write tests for EvaluationContext construction and PolicyDecision types
```

---

## 📁 Files Modified

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Pinned crypto versions, added zeroize, removed hkdf |
| `crates/idprova-core/Cargo.toml` | Removed hkdf, added zeroize |
| `crates/idprova-core/src/crypto/keys.rs` | ZeroizeOnDrop on KeyPair, secret_bytes() → pub(crate) |
| `crates/idprova-core/src/dat/scope.rs` | Full rewrite: 4-part grammar, new tests |
| `crates/idprova-core/src/dat/token.rs` | DatHeader::validate(), SR-3/SR-4 tests, scope strings updated |
| `crates/idprova-core/src/dat/chain.rs` | Full rewrite: ChainValidationConfig, validate_chain_with_config(), SR-8 tests |
