# HANDOVER — Track D: Documentation & Website

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-b-registry`
**Progress:** COMPLETE (7 of 7 tasks done)

## Completed Tasks

### Task 1: README Overhaul (75f289b)
- Updated endpoint summary to include all 11 routes
- Added `idprova-verify` and `idprova-mcp-demo` to workspace crate listing

### Task 2: Getting Started Guide (verified, no changes needed)
- `docs/getting-started.md` already accurate at 329 lines

### Task 3: API Reference — Registry Endpoints (5be4f9a)
- Added `GET /ready` and `GET /v1/dat/revocations` to `docs/api-reference.md`

### Task 4: Core Library API Guide (0a13b6c)
- Fixed `docs/core-api.md` — major fixes:
  - Scope grammar: 3-part → 4-part (namespace:protocol:resource:action)
  - DatConstraints: all field names corrected to match actual API
  - Dat::verify() → verify_signature() + validate_timing() (separate methods)
  - Import paths: dat::constraints → dat::token
  - DenialReason variants: fixed all names to match actual enum
  - Error enum: added 8 missing variants
  - ConstraintEvaluator: added name() method
  - Added verify_integrity_with_key() to ReceiptLog docs

### Task 5: Protocol Concepts Guide (4546f4a)
- Fixed `docs/concepts.md`:
  - Scope grammar: 3→4 part throughout
  - Trust level table: removed incorrect numeric equivalents
  - Constraint field names: corrected to match actual code
  - DAT claims example: fixed scope format and constraint field names
  - Delegation chain example: fixed scope format

### Task 6: Security Model Documentation (fbb3869)
- Fixed `docs/security.md`:
  - Scope format: 3-part → 4-part in scope containment table
  - dat.verify() → verify_signature() + PolicyEvaluator
  - Registry auth scope: idprova:registry:write → idprova:registry:aid:write

### Task 7: SDK Quick-Start Guides (146211a)
- Fixed `docs/sdk-python.md` and `docs/sdk-typescript.md`:
  - Scope grammar: 3-part → 4-part in all examples and descriptions
  - All scope string examples updated (e.g., `mcp:tool:read` → `mcp:mcp:tool:read`)
  - Wildcard examples updated (e.g., `mcp:*:*` → `mcp:*:*:*`)

## Key Decisions
- All docs already existed with substantial content; tasks were verification + gap-filling
- Task 2 required no changes — guide was already accurate
- Primary pattern: scope grammar was consistently wrong (3-part vs actual 4-part) across all docs
- DatConstraints field names were from an earlier API draft, not the actual implementation

## Environment Notes
- No `cargo` binary available — cannot run `cargo test --workspace`
- Documentation-only changes don't affect builds
