# HANDOVER — Track D: Documentation & Website

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-d-docs`
**Status:** COMPLETE (7 of 7 tasks done)

## Tasks Completed

### Task 1: README Overhaul (aa4fbde)
- Updated endpoint summary line to include all 11 registry endpoints

### Task 2: Getting Started Guide — NO CHANGES NEEDED
- `docs/getting-started.md` already existed and was complete

### Task 3: API Reference — Registry Endpoints (5372af6)
- Added missing `GET /ready` and `GET /v1/dat/revocations` endpoints

### Task 4: Core Library API Guide — FIXES (3c78dfa)
- Fixed: `dat.verify()` → `verify_signature()` (verify() doesn't exist on Dat)
- Fixed: DatConstraints field names (rate_limit → max_calls_per_hour, ip_allowlist → allowed_ips, etc.)
- Fixed: DenialReason variant names (IpNotAllowed → IpBlocked, TrustLevelInsufficient → InsufficientTrustLevel, etc.)
- Fixed: Added missing variants (Revoked, ChainValidationFailed, SignatureInvalid)
- Fixed: Scope grammar from 3-part to 4-part format
- Fixed: Import paths (dat::constraints:: → dat::token::)
- Fixed: Complete example to use correct APIs
- Fixed: Error enum to include all actual variants

### Task 5: Protocol Concepts Guide — FIXES (cf8eda0)
- Fixed: Scope grammar from 3-part to 4-part (namespace:protocol:resource:action)
- Fixed: Removed trust level numeric equivalents (0/25/50/75/100) — not in spec or code
- Fixed: Constraint evaluator table — 7 evaluators (not 8), correct field names
- Fixed: DatConstraints field names (min_trust_level → required_trust_level)
- Fixed: All scope examples throughout the document

### Task 6: Security Model Documentation — FIXES (f0a7dcb)
- Fixed: ML-DSA-65 presented as implemented → clarified as "Planned" (not yet in codebase)
- Fixed: Added status column to algorithm table
- Fixed: Scope examples to 4-part format
- Fixed: verify() reference → PolicyEvaluator::evaluate()

### Task 7: SDK Quick-Start Guides — FIXES (9cf7ff4)
- `docs/sdk-python.md` and `docs/sdk-typescript.md` already existed
- Fixed: Scope grammar from 3-part to 4-part in all examples
- Fixed: Documented DAT.verify() full pipeline with EvaluationContext (was showing only verify_signature)
- Fixed: Documented ReceiptLog.append() method (was incorrectly stated as CLI/registry-only)
- Fixed: Added EvaluationContext to API reference tables
- Fixed: Added save()/load() to AgentIdentity API reference

## Key Decisions

- All docs already existed from a prior session; this track focused on verifying accuracy against source code and fixing discrepancies
- Major finding: scope grammar is 4-part (namespace:protocol:resource:action) not 3-part — was wrong in all docs
- Major finding: Dat has no `verify()` method — only `verify_signature()` for sig checks, `PolicyEvaluator::evaluate()` for full pipeline
- ML-DSA-65 post-quantum crypto is planned but not implemented (commented out in Cargo.toml)
- SDK ReceiptLog exposes full append() API, not just read/verify

## Blockers

- None — track complete
