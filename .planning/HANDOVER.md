# HANDOVER — Track D: Documentation & Website

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-b-registry`
**Progress:** Task 4 of 7 (in progress — session 2)

## Completed Tasks

### Task 1: README Overhaul (75f289b)
- Updated endpoint summary to include all 11 routes
- Added `idprova-verify` and `idprova-mcp-demo` to workspace crate listing

### Task 2: Getting Started Guide (verified, no changes needed)
- `docs/getting-started.md` already accurate at 329 lines

### Task 3: API Reference — Registry Endpoints (5be4f9a)
- Added `GET /ready` and `GET /v1/dat/revocations` to `docs/api-reference.md`

### Task 4: Core Library API Guide (0a13b6c)
- Fixed `docs/core-api.md` — 13 discrepancies against actual source code:
  - Scope grammar: 3-part → 4-part (namespace:protocol:resource:action)
  - DatConstraints: wrong field names (RateLimit struct, ip_allowlist, min_trust_level, allowed_countries, days_of_week, required_config_hash → actual: max_calls_per_hour, allowed_ips, required_trust_level, geofence, days, required_config_attestation)
  - Dat::verify() doesn't exist → verify_signature() + validate_timing()
  - Import paths: dat::constraints → dat::token
  - DenialReason variant names fixed (IpNotAllowed→IpBlocked, etc.)
  - Error enum: added 8 missing variants, fixed Serialization name
  - ConstraintEvaluator: added name() method
  - Added verify_integrity_with_key() to ReceiptLog section

## Next Tasks (this session)
- Task 5: Protocol Concepts Guide — verify/update `docs/concepts.md`
- Task 6: Security Model Documentation — verify/update `docs/security.md`

## Remaining Tasks (future session if needed)
- Task 7: SDK Quick-Start Guides — verify/update `docs/sdk-python.md` and `docs/sdk-typescript.md`

## Key Decisions
- All docs already exist with substantial content; tasks are verification + gap-filling
- Task 2 required no changes — guide was already accurate

## Environment Notes
- No `cargo` binary available — cannot run `cargo test --workspace`
- Documentation-only changes don't affect builds
