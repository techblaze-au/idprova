# IDProva v0.1 — Execution Plan for Next Sessions

> **Save this to:** `C:\Users\praty\toon_conversations\aidspec\HANDOVERS\NEXT-SESSION-PLAN.md`
> **Created:** 2026-03-06
> **Status:** Ready for execution — start with Milestone 1

---

## How to Start a New Session

```
1. Read this file: cat HANDOVERS/NEXT-SESSION-PLAN.md
2. Read master board: cat IDPROVA-MASTER.md
3. Read latest handover: ls HANDOVERS/ (pick most recent for your track)
4. Invoke skills: /rust-pro (always), then milestone-specific skills listed below
5. Verify green: cargo test --workspace
6. Use GSD for structured execution:
   /gsd:new-project "IDProva v0.1"
   /gsd:new-milestone "{milestone name}"
   /gsd:add-phase "{phase name}" (for each phase below)
   /gsd:plan-phase "{phase name}"
   /gsd:execute-plan
7. Create worktree if needed:
   git worktree add worktrees/{name} -b idprova/{name}
   cd worktrees/{name}
```

---

## Current State (as of 2026-03-06)

| What | Status | Tests |
|------|--------|-------|
| Phase 0 (Critical Fixes) | ✅ DONE | 42 |
| Phase 1 (Security Hardening) | ✅ DONE | 54 |
| Phase 2 (RBAC Policy Engine) | ✅ DONE | 126 |
| Track C (SDK/CLI Persistence) | ✅ DONE | 81 |
| Website (idprova.dev) | ✅ LIVE | 32 pages |
| GitHub repos | ✅ | techblaze-au/idprova + techblaze-au/idprova-website |

**Critical bug:** `pub mod policy;` is **MISSING** from `crates/idprova-core/src/lib.rs` — Phase 2 code exists but isn't exported. Fix this first in M1.

---

## Milestone 1: Quick Start Fix + Policy Export — Session A-2

**Skills:** `/rust-pro`, `/api-design-principles`
**Worktree:** `idprova/m1-quickstart-fix`

### Phase M1-P1: Export policy module
| Item | Detail |
|------|--------|
| File | `crates/idprova-core/src/lib.rs` |
| Change | Add `pub mod policy;` after line 18 |
| Verify | `cargo build -p idprova-core` compiles clean |

### Phase M1-P2: Fix Quick Start Rust examples
| Item | Detail |
|------|--------|
| File | `C:\Users\praty\toon_conversations\idprova-website\src\content\docs\docs\quick-start.mdx` |
| Fix 1 | All `DelegationToken::issue()` → `Dat::issue()` |
| Fix 2 | All `DelegationToken::verify()` → `Dat::verify(pub_key_bytes, scope, &EvaluationContext::default())` |
| Fix 3 | Scope: `"mcp:tool:*:read"` → `"mcp:tool:read"` (3-part grammar) |
| Fix 4 | Expiry type: must be `DateTime<Utc>` not `Duration` |

### Phase M1-P3: Fix Quick Start Python/TypeScript examples
| Item | Detail |
|------|--------|
| File | Same quick-start.mdx |
| Fix | Align with actual SDK API: `KeyPair.generate()`, `Dat.issue()`, 3-part scope |

### Phase M1-P4: Verify
```bash
cargo test --workspace  # 126+ tests
cd ../idprova-website && npm run build  # 32 pages
```

### Phase M1-P5: Deploy + commit
```bash
cd C:\Users\praty\toon_conversations\idprova-website
git add -A && git commit -m "fix: correct Quick Start API examples"
git push origin main
npx vercel --prod --scope tech-blaze --yes

cd C:\Users\praty\toon_conversations\aidspec
git add crates/idprova-core/src/lib.rs
git commit -m "fix: export policy module from lib.rs"
git push origin main
```

### Handover
Write `HANDOVERS/M1-A2-track-a.md` → update `IDPROVA-MASTER.md`

---

## Milestone 2: Crypto Hardening — Session A-3

**Skills:** `/rust-pro`, `/security-audit`
**Worktree:** `idprova/m2-crypto-hardening`

### Phase M2-P1: Enable ed25519-dalek zeroize
| Item | Detail |
|------|--------|
| File | `Cargo.toml` (workspace root, line 22) |
| Before | `ed25519-dalek = { version = "2", features = ["serde", "rand_core"] }` |
| After | `ed25519-dalek = { version = "2.1", features = ["serde", "rand_core", "zeroize"] }` |
| Note | `SigningKey` auto-implements `ZeroizeOnDrop` with this feature — no manual code |

### Phase M2-P2: Restrict secret_bytes() visibility
| Item | Detail |
|------|--------|
| File | `crates/idprova-core/src/crypto/keys.rs` (line 37-40) |
| Change | `pub fn secret_bytes()` → `#[doc(hidden)] pub fn secret_bytes()` |
| Why | SDKs (separate crates) still need access, but hidden from public docs |
| Test | Line 148-152 test still works (same crate) |

### Phase M2-P3: Pin exact crypto crate versions
| Item | Detail |
|------|--------|
| File | `Cargo.toml` (workspace root, lines 22-26) |
| Changes | `ed25519-dalek = "=2.1.1"`, `blake3 = "=1.5.5"`, `sha2 = "=0.10.8"`, `rand = "=0.8.5"` |
| After | Run `cargo update` to lock |

### Phase M2-P4: Remove unused hkdf
| Item | Detail |
|------|--------|
| File | `Cargo.toml` (workspace root, line 25) |
| Change | Delete `hkdf = "0.12"` — zero usage (grep confirmed) |

### Phase M2-P5: Zeroize test
| Item | Detail |
|------|--------|
| File | `crates/idprova-core/src/crypto/keys.rs` (new test) |
| Test | `KeyPair::generate()` drop doesn't panic; `from_secret_bytes` roundtrip works |

### Phase M2-P6: Verify
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo build --workspace
```

### Handover
Write `HANDOVERS/M2-A3-track-a.md` → update `IDPROVA-MASTER.md`

---

## Milestone 3: Registry Security + Hard Limits — Session A-4

**Skills:** `/rust-pro`, `/api-security-best-practices`, `/security-audit`
**Worktree:** `idprova/m3-registry-security`

### Phase M3-P1: Hard max delegation depth
| Item | Detail |
|------|--------|
| File | `crates/idprova-core/src/dat/chain.rs` |
| Add | `pub const MAX_DELEGATION_DEPTH: u32 = 10;` |
| Enforce | In `validate_chain()`: reject if `chain.len() > MAX_DELEGATION_DEPTH` |
| Also | In `DelegationDepthEvaluator` (policy/constraints): enforce even without constraint |
| Test | Chain of 11 fails, chain of 10 passes |

### Phase M3-P2: CORS middleware
| Item | Detail |
|------|--------|
| File | `crates/idprova-registry/src/main.rs` |
| Dep | `tower-http` with `cors` feature already in workspace deps (line 45) |
| Code | `CorsLayer::new().allow_methods([GET,POST,PUT,DELETE]).allow_headers(Any).allow_origin(Any)` |
| Apply | `.layer(cors)` on router before `.with_state(state)` |

### Phase M3-P3: Security response headers
| Item | Detail |
|------|--------|
| File | `crates/idprova-registry/src/main.rs` |
| Headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000` |
| Method | `tower_http::set_header::SetResponseHeaderLayer` or axum middleware |

### Phase M3-P4: Input validation on revocation
| Item | Detail |
|------|--------|
| File | `crates/idprova-registry/src/main.rs` (handler) or `store.rs` |
| Rules | JTI max 128 chars, reason max 512 chars, revoked_by max 256 chars |
| Error | 400 Bad Request with JSON error body |

### Phase M3-P5: SQL injection safety tests
| Item | Detail |
|------|--------|
| File | `crates/idprova-registry/src/store.rs` (new `#[cfg(test)]` block) |
| Payloads | `'; DROP TABLE aids; --`, `" OR 1=1`, Unicode, null bytes, 10KB strings |
| Expected | All safely handled (rusqlite::params! already parameterized) |

### Phase M3-P6: Verify
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

### Handover
Write `HANDOVERS/M3-A4-track-a.md` → update `IDPROVA-MASTER.md`

---

## Milestone 4: SSRF + Secure HTTP Client — Phase 3 (1 session)

**Skills:** `/rust-pro`, `/api-security-best-practices`
**Worktree:** `idprova/m4-http-client`

### Phase M4-P1: URL validation (SSRF prevention)
| Item | Detail |
|------|--------|
| New file | `crates/idprova-core/src/http.rs` |
| Function | `validate_registry_url(url: &str) -> Result<url::Url>` |
| Rejects | `file://`, `gopher://`, `ldap://`, `ftp://` schemes |
| Rejects | Private IPs: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Rejects | `169.254.169.254` (cloud metadata), `::1` (IPv6 loopback) |
| Export | Add `pub mod http;` to `lib.rs` |

### Phase M4-P2: Secure reqwest client
| Item | Detail |
|------|--------|
| File | `crates/idprova-core/src/http.rs` (same file) |
| Config | timeout=10s, connect_timeout=5s, redirect limit=5, https_only=true, user_agent |
| Feature | Add `reqwest` as optional dep under `"http"` feature in idprova-core Cargo.toml |

### Phase M4-P3: CLI aid resolve implementation
| Item | Detail |
|------|--------|
| File | `crates/idprova-cli/src/commands/aid.rs` |
| Replace | Placeholder in `resolve()` → actual GET `{registry}/v1/aid/{id}` |
| Parse | Response as `AidDocument`, pretty-print |

### Phase M4-P4: CLI dat verify with registry
| Item | Detail |
|------|--------|
| File | `crates/idprova-cli/src/commands/dat.rs` |
| Logic | If `--key` not provided → resolve issuer DID from registry → get public key → verify |

### Phase M4-P5: SSRF test suite
| Item | Detail |
|------|--------|
| Tests | Reject `file:///etc/passwd`, `http://127.0.0.1`, `http://169.254.169.254` |
| Tests | Accept `https://registry.idprova.dev` |

### Handover
Write `HANDOVERS/M4-P3-http.md` → update `IDPROVA-MASTER.md`

---

## Milestone 5: idprova-verify Crate — Phase 4 (2 sessions)

**Skills:** `/rust-pro`, `/api-design-principles`
**Worktree:** `idprova/m5-verify-crate`

### Phase M5-P1: Crate scaffold
| Item | Detail |
|------|--------|
| New dir | `crates/idprova-verify/` |
| Cargo.toml | Depends on `idprova-core` |
| Workspace | Add to `members` in root Cargo.toml |

### Phase M5-P2: verify_dat() API
```rust
pub fn verify_dat(compact_jws: &str, pub_key: &[u8; 32], scope: &str, ctx: &EvaluationContext) -> Result<Dat>;
```

### Phase M5-P3: verify_receipt_log() API
```rust
pub fn verify_receipt_log(receipts: &[Receipt]) -> Result<()>;
```

### Phase M5-P4: verify_dat_from_jws() (no constraint check)
```rust
pub fn verify_dat_from_jws(jws: &str, pub_key: &[u8; 32]) -> Result<Dat>;
```

### Phase M5-P5: Documentation + examples
### Phase M5-P6: Tests (unit + property-based with proptest)
### Phase M5-P7: Workspace integration + verify

### Handover
Write `HANDOVERS/M5-P4-verify.md`

---

## Milestone 6: idprova-middleware Crate — Phase 5 (2 sessions)

**Skills:** `/rust-pro`, `/api-design-principles`, `/api-security-best-practices`
**Worktree:** `idprova/m6-middleware`

### Phase M6-P1: Crate scaffold
| Item | Detail |
|------|--------|
| New dir | `crates/idprova-middleware/` |
| Deps | `idprova-verify`, `axum`, `tower`, `tower-http` |

### Phase M6-P2: DatVerificationLayer + Service
Tower Layer that wraps inner service, extracts Bearer token, verifies DAT.

### Phase M6-P3: Build EvaluationContext from request
Extract client IP from `X-Forwarded-For`, timestamp from system clock.

### Phase M6-P4: VerifiedDat request extension
On success: inject `VerifiedDat { dat, subject_did, scopes }` into request extensions.

### Phase M6-P5: Error responses
On failure: 401 Unauthorized or 403 Forbidden with JSON error body.

### Phase M6-P6: Integration tests
Spin up test axum server with middleware, make authenticated + unauthenticated requests.

### Phase M6-P7: Workspace + verify

### Handover
Write `HANDOVERS/M6-P5-middleware.md`

---

## Milestone 7: Registry Hardening — Track B (2 sessions)

**Skills:** `/rust-pro`, `/api-security-best-practices`, `/security-audit`, `/database-architect`
**Worktree:** `idprova/m7-registry-hardening`

### Phase M7-P1: DAT-based auth for write endpoints
PUT, DELETE, revoke require valid DAT. GET/resolve remain public.

### Phase M7-P2: Rate limiting middleware
Token bucket per client IP using tower middleware.

### Phase M7-P3: Connection pool
Replace `Arc<Mutex<AidStore>>` with `r2d2-sqlite` or `deadpool` pool.

### Phase M7-P4: Request size limits
Max body size (1MB), max header size, timeouts.

### Phase M7-P5: Integration tests
Concurrent PUT/GET races, malformed JSON, large payloads, auth failures.

### Phase M7-P6: Load test + verify

### Handover
Write `HANDOVERS/M7-B1-registry.md`

---

## Handover Protocol (EVERY SESSION)

**When context reaches ~90% OR session is ending:**

1. Stop coding
2. Write handover file:
```
HANDOVERS/{MILESTONE}-{SESSION}-{track}.md
```
Include: what was done, files changed, test count, build status, known issues, exact resume point.

3. Commit:
```bash
git add HANDOVERS/ IDPROVA-MASTER.md
git commit -m "handover: {Milestone} {Session}"
git push
```

4. Update IDPROVA-MASTER.md track status table

---

## Execution Priority

```
M1 → M2 → M3 → M4 → M5 → M6 → M7
 ↑
START HERE
```

**Total: 7 milestones, ~10 sessions, ~45 phases**
**Target: IDProva v0.1 feature-complete**
