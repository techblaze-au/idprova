# Handover: Phase 2, Session 4, Track A
**Date:** 2026-03-05
**Branch:** `idprova/track-a-core-security`
**Agent:** BE (Rust senior)
**Commit:** 5195329

---

## Completed This Session

### Session A-4: Implemented 3 Constraint Evaluators

**File: `crates/idprova-core/src/policy/constraints.rs`**

1. **`RateLimitEvaluator`** — Checks context counters against constraint limits:
   - `max_calls_per_hour` vs `actions_this_hour`
   - `max_calls_per_day` vs `actions_this_day`
   - `max_concurrent` vs `active_concurrent`
   - Returns `Deny(RateLimitExceeded { limit_type, limit, current })` on first violation
   - Uses `>=` comparison (limit of 100 means 0–99 are allowed, 100+ denied)

2. **`IpConstraintEvaluator`** — CIDR matching via `ipnet` crate:
   - Parses `denied_ips` and `allowed_ips` as `IpNet` CIDRs
   - Also accepts bare IPs (e.g., "192.168.1.1" → /32 host)
   - Deny-list checked first (deny wins over allow)
   - If allowed list present, IP must match at least one entry
   - No source IP in context → skip check (fail-open for missing context)
   - Invalid CIDR strings silently skipped (defensive)

3. **`TrustLevelEvaluator`** — Trust level comparison:
   - Parses `required_trust_level` via `TrustLevel::from_str_repr()`
   - Compares with `caller_trust_level` using `meets_minimum()`
   - No constraint → Allow (skip)
   - Invalid constraint string → Allow (skip gracefully)
   - Constraint present but no caller trust level → Deny (fail-closed)

---

## In Progress (pick up here)

Nothing in-progress — clean handover.

---

## Not Started (remaining Phase 2)

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

- **Before Session A-4:** 63 tests passing
- **After Session A-4:** 78 tests passing (+15 new: 13 evaluator + 2 existing stubs still valid)
- **Failing:** None (1 flaky chain timing test occasionally fails — pre-existing, not related to this work)
- **New tests:**
  - `policy::constraints::tests::test_rate_limit_hourly_exceeded`
  - `policy::constraints::tests::test_rate_limit_daily_exceeded`
  - `policy::constraints::tests::test_rate_limit_concurrent_exceeded`
  - `policy::constraints::tests::test_rate_limit_within_limits`
  - `policy::constraints::tests::test_rate_limit_no_constraints`
  - `policy::constraints::tests::test_ip_allowed`
  - `policy::constraints::tests::test_ip_denied`
  - `policy::constraints::tests::test_ip_deny_wins_over_allow`
  - `policy::constraints::tests::test_ip_not_in_allowed`
  - `policy::constraints::tests::test_ip_no_source_ip_skips`
  - `policy::constraints::tests::test_trust_level_sufficient`
  - `policy::constraints::tests::test_trust_level_exact_match`
  - `policy::constraints::tests::test_trust_level_insufficient`
  - `policy::constraints::tests::test_trust_level_no_constraint_skips`
  - `policy::constraints::tests::test_trust_level_missing_caller_level_denied`

---

## Key Decisions Made

1. **`>=` for rate limit comparison** — `actions >= limit` means the limit value is the ceiling (exclusive). If limit is 100, actions 0–99 are allowed, 100+ denied. This is the standard rate limiter pattern.
2. **Bare IP → IpNet conversion** — `IpConstraintEvaluator::parse_nets()` tries `IpNet` parse first, falls back to `IpAddr::from` (which yields /32 or /128). This handles both "10.0.0.0/8" and "192.168.1.1" in the same list.
3. **Silent skip on invalid CIDR** — Bad strings in `allowed_ips`/`denied_ips` are filtered out rather than causing errors. Defensive: a typo in one CIDR shouldn't break the entire evaluator.
4. **Fail-closed on missing caller trust** — If the constraint requires a trust level but the context has no `caller_trust_level`, the evaluator denies. This is the security-conservative choice: "if you don't tell me your trust level and I need one, you don't get in."
5. **Fail-open on invalid trust level string** — If `required_trust_level` is set to garbage like "X9", `from_str_repr` returns None and we skip. This matches the "don't crash on bad config" pattern.

---

## Blocking Issues

None. Track A ready for Session A-5.

---

## Next Session Instructions

```bash
# 1. Navigate to Track A worktree
cd C:\Users\praty\toon_conversations\aidspec\worktrees\track-a

# 2. Confirm branch and tests
git branch  # should show * idprova/track-a-core-security
cargo test -p idprova-core  # should show 78 passed

# 3. Read this handover

# 4. Session A-5: Implement remaining 4 evaluators
#    a. DelegationDepthEvaluator — check delegation_depth vs max_delegation_depth
#    b. GeofenceEvaluator — check source_country vs geofence list
#    c. TimeWindowEvaluator — check timestamp day/hour vs time_windows
#    d. ConfigAttestationEvaluator — compare attestation hashes
#    e. Write 10-15 tests covering:
#       - Depth exceeded / within limits
#       - Country allowed / blocked / missing
#       - Time inside / outside window / midnight wrap
#       - Attestation match / mismatch / missing
#       - Missing context fields (skip check)
```

---

## Files Modified

| File | Changes |
|------|---------|
| `crates/idprova-core/src/policy/constraints.rs` | Replaced 3 stub evaluators with real logic, added `ipnet`/`TrustLevel`/`DenialReason` imports, added helper `parse_nets()`, added 15 tests |
