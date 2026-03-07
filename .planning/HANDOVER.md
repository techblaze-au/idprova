# HANDOVER — Track B: Registry Hardening

**Plan:** `.planning/phases/01/01-01-PLAN.md`
**Branch:** `idprova/track-b-registry`
**Session date:** 2026-03-07
**Status:** 3 tasks complete — session rotation, pick up at Task 3 (CORS verify) next

---

## Tasks Completed This Session

| # | Task | Commit |
|---|------|--------|
| 1 | `GET /ready` endpoint with SQLite liveness check (200/503) | `b28db2f` |
| 2 | `error.rs` — `ApiError` type with `error`/`code`/`request_id` (ULID); all handlers migrated | `1e3d072` |
| 5 | Input validation in `register_aid`: DID path consistency + Ed25519 pubkey decode check | `3017445` |

---

## Tasks Skipped (Already Implemented)

- **Task 3 (CORS):** `CorsLayer::new().allow_methods(Any).allow_headers(Any).allow_origin(Any)` already in `main.rs:99`
- **Task 4 (Request Size Limits):** `RequestBodyLimitLayer::new(1024 * 1024)` already in `main.rs:118`

---

## Next Tasks to Execute

| # | Task | Notes |
|---|------|-------|
| 6 | Request Tracing — `tower_http::trace::TraceLayer` + ULID request IDs per request | Add `ulid` use to generate per-request IDs; propagate to `ApiError::request_id` via extension |
| 7 | DAT Revocation Enhancement — validate DAT sig before accepting `POST /revoke`; add `GET /revocations` with pagination | Needs `store::list_revocations(limit, offset)` |

---

## Key Decisions

- `ApiError` generates a fresh ULID per error instance (no request-scoped ID yet; Task 6 will add that)
- `decode_multibase_pubkey` returns `[u8; 32]` so length is guaranteed by the type — just attempt decode
- DID consistency: `doc.id` must equal `did:idprova:{path}` — prevents mismatched registrations
- Tasks 3 & 4 were pre-existing — verified in code, no changes needed

## Environment Note

`cargo` is not available in this agent environment. Code changes are made via careful code review. The build/test CI pipeline will verify compilation.

---

## Files Modified

- `crates/idprova-registry/src/store.rs` — added `ping()` method
- `crates/idprova-registry/src/main.rs` — `/ready` handler, `ApiError` migration, input validation
- `crates/idprova-registry/src/error.rs` — **new file**, `ApiError` type
- `crates/idprova-registry/Cargo.toml` — added `ulid` workspace dep
