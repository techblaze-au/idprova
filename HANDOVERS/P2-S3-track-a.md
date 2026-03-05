# Handover: Phase 2, Session 3, Track A
**Date:** 2026-03-05
**Branch:** `idprova/track-a-core-security`
**Agent:** BE (Rust senior)
**Commit:** a7b593d

---

## Completed This Session

### Phase 2 RBAC Policy Engine — Scaffolding

**New module: `crates/idprova-core/src/policy/`**

1. **`context.rs`** — `EvaluationContext` struct with builder pattern
   - Fields: requested_scope, timestamp, source_ip, source_country, caller_trust_level, actions_this_hour/day, active_concurrent, delegation_depth, caller_config_attestation, extensions (HashMap)
   - `EvaluationContextBuilder` with fluent API

2. **`decision.rs`** — `PolicyDecision` enum + `DenialReason`
   - `PolicyDecision::Allow | Deny(DenialReason)`
   - 14 `DenialReason` variants: Expired, NotYetValid, ScopeNotCovered, Revoked, RateLimitExceeded, IpBlocked, InsufficientTrustLevel, DelegationDepthExceeded, GeofenceViolation, OutsideTimeWindow, ConfigAttestationMismatch, ChainValidationFailed, SignatureInvalid, Custom
   - `Display` impl on both types

3. **`constraints.rs`** — `ConstraintEvaluator` trait + 7 stub evaluators
   - Trait: `evaluate(&self, &DatConstraints, &EvaluationContext) -> PolicyDecision` + `name() -> &'static str`
   - Stubs (all return Allow): RateLimitEvaluator, IpConstraintEvaluator, TrustLevelEvaluator, DelegationDepthEvaluator, GeofenceEvaluator, TimeWindowEvaluator, ConfigAttestationEvaluator
   - `default_evaluators()` factory function returns all 7

4. **`mod.rs`** — re-exports all public types

5. **Extended `DatConstraints`** in `dat/token.rs`:
   - Added `Default` derive
   - Added `TimeWindow` struct (days, start_hour, end_hour)
   - 10 new fields: max_calls_per_hour, max_calls_per_day, max_concurrent, allowed_ips, denied_ips, required_trust_level, max_delegation_depth, geofence, time_windows, required_config_attestation
   - All with `#[serde(default, skip_serializing_if)]` for backward compat

6. **Added `ipnet = "2"`** to workspace + idprova-core deps

---

## In Progress (pick up here)

Nothing in-progress — clean handover.

---

## Not Started (remaining Phase 2)

### Session A-4: Implement 3 evaluators
- **RateLimitEvaluator** — check actions_this_hour/day/concurrent against max_calls_per_hour/day/concurrent
- **IpConstraintEvaluator** — parse CIDR via `ipnet`, check source_ip against allowed_ips/denied_ips
- **TrustLevelEvaluator** — parse required_trust_level, compare with caller_trust_level
- ~10-15 new tests

### Session A-5: Implement 4 evaluators
- **DelegationDepthEvaluator** — check delegation_depth against max_delegation_depth
- **GeofenceEvaluator** — check source_country against geofence country list
- **TimeWindowEvaluator** — check timestamp against time_windows day/hour restrictions
- **ConfigAttestationEvaluator** — compare caller_config_attestation against required hash
- ~10-15 new tests

### Session A-6: PolicyEvaluator integration
- Create `evaluator.rs` — `PolicyEvaluator` main engine (run all evaluators, short-circuit on deny)
- Create `inheritance.rs` — constraint inheritance validation (parent >= child)
- Create `rate.rs` — `RateTracker` (in-memory action counting)
- Integration tests: full DAT → context → evaluators → decision pipeline
- ~25-30 new tests

### Phase 1 leftovers (lower priority)
- **SR-10** — SQL injection test for registry store
- **S8** — Registry CORS
- **D1** — Fix Quick Start docs

---

## Test Status

- **Before Session A-3:** 54 tests passing
- **After Session A-3:** 63 tests passing (+9 new)
- **Failing:** None
- **New tests:**
  - `policy::context::tests::test_builder_defaults`
  - `policy::context::tests::test_builder_full`
  - `policy::decision::tests::test_policy_decision_allow`
  - `policy::decision::tests::test_policy_decision_deny`
  - `policy::decision::tests::test_denial_reason_display`
  - `policy::constraints::tests::test_all_stubs_return_allow`
  - `policy::constraints::tests::test_evaluator_names_are_unique`
  - `dat::token::tests::test_extended_constraints_roundtrip`
  - `dat::token::tests::test_backward_compat_constraints_deserialize`

---

## Key Decisions Made

1. **DatConstraints gets `Default` derive** — cleaner construction in tests and future code. All Option fields default to None.
2. **TimeWindow struct** — separate type for day/hour restrictions rather than a raw JSON object. Days are 0-6 (Mon-Sun), hours 0-23 UTC.
3. **DenialReason variants carry context** — e.g., `RateLimitExceeded { limit_type, limit, current }` rather than just a string. Better for logging and debugging.
4. **`default_evaluators()` factory** — returns `Vec<Box<dyn ConstraintEvaluator>>` for easy composition. Users can add/remove evaluators.

---

## Blocking Issues

None. Track A ready for Session A-4.

---

## Next Session Instructions

```bash
# 1. Navigate to Track A worktree
cd C:\Users\praty\toon_conversations\aidspec\worktrees\track-a

# 2. Confirm branch and tests
git branch  # should show * idprova/track-a-core-security
cargo test -p idprova-core  # should show 63 passed

# 3. Read this handover

# 4. Session A-4: Implement first 3 evaluators
#    a. RateLimitEvaluator — check rate counters
#    b. IpConstraintEvaluator — CIDR matching via ipnet crate
#    c. TrustLevelEvaluator — TrustLevel::from_str_repr + meets_minimum
#    d. Write 10-15 tests covering:
#       - Rate limit exceeded (hourly, daily, concurrent)
#       - Rate limit within limits
#       - IP in allowed CIDR
#       - IP in denied CIDR
#       - IP with both allow+deny (deny wins)
#       - Trust level sufficient
#       - Trust level insufficient
#       - Missing context fields (skip check)
```

---

## Files Modified

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Added `ipnet = "2"` |
| `Cargo.lock` | Updated with ipnet |
| `crates/idprova-core/Cargo.toml` | Added `ipnet.workspace = true` |
| `crates/idprova-core/src/lib.rs` | Added `pub mod policy;` |
| `crates/idprova-core/src/dat/token.rs` | TimeWindow type, Default on DatConstraints, 10 new constraint fields, 2 new tests |
| `crates/idprova-core/src/policy/mod.rs` | NEW — re-exports |
| `crates/idprova-core/src/policy/context.rs` | NEW — EvaluationContext + builder |
| `crates/idprova-core/src/policy/decision.rs` | NEW — PolicyDecision + DenialReason |
| `crates/idprova-core/src/policy/constraints.rs` | NEW — ConstraintEvaluator trait + 7 stubs |
