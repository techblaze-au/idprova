# Handover: Phase 2, Sessions 5-6, Track A
**Date:** 2026-03-06
**Branch:** `idprova/track-a-core-security`
**Agent:** Claude Opus 4.6

---

## ✅ Completed This Session

### Session A-5: 4 Remaining Constraint Evaluators

**File:** `crates/idprova-core/src/policy/constraints.rs`

1. **DelegationDepthEvaluator** — checks `delegation_depth > max_delegation_depth`
2. **GeofenceEvaluator** — fail-closed: requires `source_country` in allowed list; case-insensitive
3. **TimeWindowEvaluator** — supports overnight hour wrap (start > end), multiple windows, day-of-week
4. **ConfigAttestationEvaluator** — fail-closed: requires caller to present matching hash

20 new tests covering: depth limits, geofence allow/deny/fail-closed, time window inside/outside/overnight/multiple, config match/mismatch/missing.

### Session A-6: PolicyEvaluator + Inheritance + RateTracker

**New file: `crates/idprova-core/src/policy/evaluator.rs`**
- `PolicyEvaluator` — main engine: timing → scope → constraints (short-circuit on deny)
- `Default` impl uses `default_evaluators()`
- `with_evaluators()` for custom evaluator sets
- 8 tests: allow, deny-scope, deny-expired, deny-constraint, wildcard, short-circuit, empty-evaluators, multi-constraint

**New file: `crates/idprova-core/src/policy/inheritance.rs`**
- `validate_constraint_inheritance(parent, child)` — ensures child is at least as restrictive
- Validates: rate limits (<=), delegation depth (<=), trust level (>=), geofence (⊆), config attestation (==)
- 16 tests covering valid narrowing and invalid widening for every field

**New file: `crates/idprova-core/src/policy/rate.rs`**
- `RateTracker` — thread-safe (Mutex), sliding-window action counts per agent DID
- `record_action()`, `get_counts()` (hourly, daily, concurrent), `acquire/release_concurrent()`
- 4 tests including thread-safety test (10 threads × 100 actions)

---

## 🧪 Test Status

- **Before Session A-5:** 78 tests passing
- **After Session A-5:** 98 tests passing (+20)
- **After Session A-6:** 126 tests passing (+28)
- **Failing:** None
- **Clippy:** Clean (only pre-existing `secret_bytes` dead_code warning)

---

## 🔑 Key Decisions Made

1. **GeofenceEvaluator: fail-closed** — if geofence is set but no country in context, deny. Security-first.
2. **TimeWindowEvaluator: overnight wrap** — `start_hour > end_hour` wraps past midnight (e.g., 22-6).
3. **PolicyEvaluator order:** timing → scope → constraints. Timing is cheapest, constraints last.
4. **Inheritance: missing child = violation** — if parent sets a limit and child doesn't, that's a widening (rejected).
5. **RateTracker: not persistent** — resets on restart. DATs are short-lived, rate limits are best-effort.

---

## 📁 Files Modified/Created

| File | Changes |
|------|---------|
| `crates/idprova-core/src/policy/constraints.rs` | Implemented 4 evaluators, added chrono imports, 20 new tests |
| `crates/idprova-core/src/policy/evaluator.rs` | **NEW** — PolicyEvaluator engine + 8 tests |
| `crates/idprova-core/src/policy/inheritance.rs` | **NEW** — Constraint inheritance validation + 16 tests |
| `crates/idprova-core/src/policy/rate.rs` | **NEW** — RateTracker + 4 tests |
| `crates/idprova-core/src/policy/mod.rs` | Added evaluator, inheritance, rate modules + re-exports |
| `IDPROVA-MASTER.md` | Updated Track A status, Phase 2 marked complete |

---

## 🚫 Blocking Issues

None. Phase 2 is **complete**. Track A ready for Phase 3 (SSRF + Secure HTTP).

---

## 📋 Next Steps

### Phase 3 — SSRF + Secure HTTP (1 session)
- SSRF protection for registry URL resolution
- Secure HTTP client configuration

### Phase 4 — idprova-verify crate (2 sessions)
- Standalone verification library (no signing keys needed)
- Blocking for Track B (Registry hardening)

### Phase 1 Leftovers (can be done anytime)
- SR-10: SQL injection tests for registry
- S8: Registry CORS
- D1: Fix Quick Start docs
