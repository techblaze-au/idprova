# Handover: Milestone 4 — Session 1 (Track A)

**Date:** 2026-03-06
**Session:** M4-S1
**Track:** A (core security + SSRF + HTTP client)

---

## What Was Completed This Session

### Milestone 2 — Crypto Hardening ✅ COMMITTED
- [x] Pinned exact crypto crate versions: `ed25519-dalek=2.1.1`, `blake3=1.5.5`, `sha2=0.10.8`, `rand=0.8.5`
- [x] Enabled `zeroize` feature on `ed25519-dalek` → `SigningKey` implements `ZeroizeOnDrop`
- [x] Added `#[doc(hidden)]` to `secret_bytes()` — hidden from public docs, still accessible by SDKs
- [x] Removed unused `hkdf` dependency from workspace + `idprova-core`
- [x] Added `test_zeroize_on_drop` test in `crypto/keys.rs`
- [x] Fixed ALL clippy `-D warnings`: dead_code on `is_revoked` + `Config` fields, `too_many_arguments` on SDK bindings (Python + TypeScript)
- **Commit:** `91dd944` — 151 tests

### Milestone 3 — Registry Security Hardening ✅ COMMITTED
- [x] `dat/chain.rs`: Added `MAX_DELEGATION_DEPTH = 10` constant, enforced in `validate_chain()`
- [x] `dat/chain.rs`: Tests — chain of 11 fails, chain of 10 passes, empty chain ok
- [x] `registry/main.rs`: CORS middleware via `CorsLayer` (allow any methods/headers/origins)
- [x] `registry/main.rs`: Security headers middleware — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-XSS-Protection`
- [x] `registry/main.rs`: Input validation on `POST /v1/dat/revoke` — jti ≤ 128 chars, reason ≤ 512, revoked_by ≤ 256
- [x] `store.rs`: `new_in_memory()` helper for testing; SQL injection safety test suite (6 payloads, unicode, 10KB)
- **Commit:** `b20e4ec` — 160 tests (155 core + 5 registry)

### Milestone 4 — SSRF + Secure HTTP (IN PROGRESS, NOT YET COMMITTED)
- [x] **M4-P1**: New file `crates/idprova-core/src/http.rs` — `validate_registry_url()` function
  - Rejects: `file://`, `gopher://`, `ldap://`, `ftp://`, `data:` schemes
  - Rejects: `127.x`, `10.x`, `172.16-31.x`, `192.168.x`, `169.254.x` (metadata), `::1`, `fc00::/7`, `fd00::/7`
  - Accepts: public IPv4 (1.1.1.1, 8.8.8.8), valid HTTPS URLs
  - 14 tests passing, 2 ignored (require DNS/network)
- [x] **M4-P1**: Exported `pub mod http;` in `lib.rs`
- [x] **M4-P1**: Added `url = "2"` to workspace deps + `idprova-core` deps
- [x] **M4-P2**: `build_registry_client()` fn in `http.rs` (behind `#[cfg(feature = "http")]`) — timeout=10s, connect_timeout=5s, redirect limit=5, https_only, user_agent
  - Added `[features] http = ["dep:reqwest"]` to `idprova-core/Cargo.toml`
  - Added `reqwest = { workspace = true, optional = true }` to idprova-core deps
- [x] **M4-P3**: CLI `aid::resolve()` — replaces placeholder with actual `GET {registry}/v1/aid/{id}`, validates URL first
- [x] **M4-P4**: CLI `dat::verify()` None branch — resolves issuer public key from registry via `GET {registry}/v1/aid/{issuer_did}/key`, then verifies DAT fully
- [x] **M4-P1 deps**: Added `reqwest = { version = "0.12", features = ["json", "blocking"] }` to workspace
- [ ] **NOT YET**: CLI build verified — was interrupted before `cargo build -p idprova-cli` completed
- [ ] **NOT YET**: M4-P5 SSRF test suite (already have 14 tests in http.rs, but plan wanted separate file verification)
- [ ] **NOT YET**: Full workspace test run after M4 changes
- [ ] **NOT YET**: Committed M4 changes

---

## Files Changed (Not Yet Committed)

| File | Change |
|------|--------|
| `Cargo.toml` | Added `url = "2"`, changed `reqwest` to add `blocking` feature |
| `crates/idprova-core/Cargo.toml` | Added `url.workspace`, optional `reqwest`, `[features] http` |
| `crates/idprova-core/src/lib.rs` | Added `pub mod http;` |
| `crates/idprova-core/src/http.rs` | NEW — SSRF validation + secure client builder |
| `crates/idprova-cli/src/commands/aid.rs` | `resolve()` now does real HTTP GET to registry |
| `crates/idprova-cli/src/commands/dat.rs` | `verify()` None branch now resolves issuer key from registry |

---

## Build Status

| Crate | Status | Tests |
|-------|--------|-------|
| `idprova-core` | ✅ 169 pass, 2 ignored | Last verified pre-M4 commit |
| `idprova-registry` | ✅ 5 pass | Last verified at M3 commit |
| `idprova-cli` | ⚠️ NOT VERIFIED | Build was interrupted |
| `idprova-python` | ✅ compiles (needs PYO3_PYTHON env) | 0 unit tests |
| `idprova-typescript` | ✅ compiles | 0 unit tests |

---

## Resume Point

**Next session starts at: M4 — verify + commit**

```bash
# 1. Read this handover
# 2. Invoke /rust-pro skill
# 3. Verify M4 builds:
cargo build -p idprova-cli
cargo test --workspace

# 4. If CLI build fails, fix the error (likely reqwest import or serde derive in dat.rs)
# 5. Run clippy:
cargo clippy --workspace -- -D warnings

# 6. Commit M4:
git add Cargo.toml Cargo.lock crates/idprova-core/Cargo.toml \
  crates/idprova-core/src/lib.rs crates/idprova-core/src/http.rs \
  crates/idprova-cli/src/commands/aid.rs crates/idprova-cli/src/commands/dat.rs
git commit -m "feat: Milestone 4 — SSRF URL validation, secure HTTP client, CLI registry integration"
git push origin main

# 7. Then proceed to Milestone 5: idprova-verify crate
```

---

## Known Issues / Watch Out For

1. **CLI dat.rs**: Uses `#[derive(serde::Deserialize)]` inline structs — this requires `serde` to be in scope. The crate already has `serde` dep, but if the build fails with a serde error, add `use serde::Deserialize;` at the top or move the structs outside the function.

2. **http.rs feature flag**: `build_registry_client()` is behind `#[cfg(feature = "http")]`. The CLI doesn't enable this feature — it uses `reqwest::blocking` directly. That's fine; `build_registry_client()` is for library consumers who opt in.

3. **reqwest in idprova-core**: Only needed for the optional `http` feature. The CLI's `aid.rs` and `dat.rs` use `reqwest::blocking` directly (it's a CLI dep, not a core dep).

4. **Hostname resolution tests**: 2 tests in `http.rs` are `#[ignore]`-d because they need DNS. Run with `cargo test -- --include-ignored` to test them with network access.

---

## Next Milestones After M4

```
M5 — idprova-verify crate (2 sessions)
M6 — idprova-middleware crate (2 sessions)
M7 — Registry hardening: DAT-based auth, rate limiting, connection pool (2 sessions)
```

**Skills for M5:** `/rust-pro`, `/api-design-principles`
**Worktree:** `idprova/m5-verify-crate`

---

## Test Count History

| Milestone | Tests |
|-----------|-------|
| P0 (Phase 0) | 42 |
| P1 (Security) | 54 |
| P2 (RBAC) | 126 (then 150 with pre-M2 additions) |
| M2 committed | 151 |
| M3 committed | 160 (155 core + 5 registry) |
| M4 (pre-commit) | ~174 (169 core + 2 ignored + 5 registry) |
