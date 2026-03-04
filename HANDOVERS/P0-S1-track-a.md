# Handover: Phase 0, Session 1, Track A
**Date:** 2026-03-05
**Branch:** `idprova/track-a-core-security`
**Agent:** BE (Rust senior)
**Commit:** 8096684

---

## ✅ Completed This Session

### S1 — JWS Re-serialization Bug (CRITICAL)
- **File:** `crates/idprova-core/src/dat/token.rs`
- Added `raw_header_b64: Option<String>` and `raw_claims_b64: Option<String>` to `Dat` struct
- `from_compact()` stores original base64 segments; `issue()` populates them from freshly encoded bytes
- `verify_signature()` uses `match` on raw segments (RFC 7515 §5.2 compliant), falls back to re-serialization only for in-memory tokens
- Test: `test_s1_jws_verify_uses_original_segments` — round-trip through compact + verify with right/wrong key

### S2 — Receipt Signatures Never Verified (CRITICAL)
- **Files:** `crates/idprova-core/src/receipt/entry.rs`, `crates/idprova-core/src/receipt/log.rs`
- Added `Receipt::verify_signature(&pub_key_bytes)` — hex-decodes `self.signature`, calls `KeyPair::verify` on `signing_payload_bytes()`
- Added `ReceiptLog::verify_integrity_with_key(&pub_key_bytes)` — checks hash chain PLUS calls `verify_signature` on every entry
- `verify_integrity()` docstring updated to clarify it does NOT verify signatures (backwards compat preserved)
- Tests: `test_s2_forged_receipt_rejected_by_integrity_with_key`, `test_s2_receipt_signature_verification`, `test_verify_integrity_with_key_rejects_wrong_key`

### S3 — Receipt Hash Circular Dependency
- **File:** `crates/idprova-core/src/receipt/entry.rs`
- Added `ReceiptSigningPayload<'a>` struct (borrows all fields except `signature`)
- Added `signing_payload_bytes() -> Vec<u8>` — serializes `ReceiptSigningPayload` to JSON
- `compute_hash()` now calls `prefixed_blake3(&self.signing_payload_bytes())` instead of serializing full struct
- Test: `test_s3_hash_excludes_signature` — mutating `signature` after signing doesn't change hash

### S4 — Non-Canonical JSON for AID Signing
- **Files:** `crates/idprova-core/src/aid/document.rs`, `Cargo.toml` (workspace), `crates/idprova-core/Cargo.toml`
- Replaced `json-canonicalization = "0.1"` (wrong crate, doesn't exist) with `serde_json_canonicalizer = "0.3"`
- Import: `use serde_json_canonicalizer::to_vec as jcs_to_vec;`
- `to_canonical_json()`: serialize to `serde_json::Value` first, then `jcs_to_vec(&value)?` for RFC 8785 output
- Tests: `test_s4_canonical_json_is_deterministic`, `test_s4_canonical_json_excludes_proof`, `test_s4_canonical_json_keys_are_sorted`

---

## 🔄 In Progress (pick up here)

**Nothing in-progress — clean handover.**

---

## ❌ Not Started (remaining Phase 0)

These are from the plan's "Critical Gaps" section, higher priority than original Phase 1:

- **D1** — Quick Start code doesn't match actual API: docs show `DelegationToken::issue()` with `Duration`, actual code is `Dat::issue()` with `DateTime<Utc>`. Fix docs in idprova-website.
- **D2** — Scope grammar inconsistency: parser uses `splitn(3, ':')` so `mcp:tool:filesystem:read` parses as `namespace=mcp, resource=tool, action=filesystem:read`. Docs show 4-part scopes. **Decision needed** before Phase 1.

These are from the original Phase 1 security hardening (SR items):

- **SR-1** — Zeroize private keys: `ed25519-dalek/zeroize` feature, derive `ZeroizeOnDrop` on `KeyPair`
- **S5** — Remove `secret_bytes()` from public API
- **S6** — Pin exact versions for security crates (`ed25519-dalek = "=2.1.1"`, etc.)
- **S7** — Remove unused `hkdf` dependency
- **SR-3** — Hard-reject non-EdDSA algorithms in `DatHeader::validate()`
- **SR-4** — Deny unknown JWS header fields (test-only: `jwk`, `jku`, `x5u`, `crit`)
- **SR-8** — Max delegation depth: add `ChainValidationConfig::max_depth` (default 5, hard max 10)
- **SR-10** — SQL audit: test SQL injection on `store.get("'; DROP TABLE aids; --")`

---

## 🧪 Test Status

- **Before this session:** 33 tests passing
- **After this session:** 42 tests passing (+9 new security regression tests)
- **Failing:** None
- **New tests:**
  - `dat::token::tests::test_s1_jws_verify_uses_original_segments`
  - `receipt::entry::tests::test_s2_receipt_signature_verification`
  - `receipt::entry::tests::test_s3_hash_excludes_signature`
  - `receipt::log::tests::test_verify_integrity_passes_for_valid_chain`
  - `receipt::log::tests::test_verify_integrity_with_key_rejects_wrong_key`
  - `receipt::log::tests::test_s2_forged_receipt_rejected_by_integrity_with_key`
  - `aid::document::tests::test_s4_canonical_json_is_deterministic`
  - `aid::document::tests::test_s4_canonical_json_excludes_proof`
  - `aid::document::tests::test_s4_canonical_json_keys_are_sorted`

---

## 🔑 Key Decisions Made

1. **S4 crate:** `json-canonicalization = "0.1"` doesn't exist. Correct crate is `serde_json_canonicalizer = "0.3"`. API is `to_vec(&serde_json::Value)` not `to_string`.
2. **S3 approach:** Used a private `ReceiptSigningPayload<'a>` borrowing struct rather than a separate signing method that temporarily sets signature to "". This is cleaner and makes the signing contract explicit for SDK implementers.
3. **S2 backward compat:** Kept original `verify_integrity()` (no signature check) to avoid breaking existing callers. Added new `verify_integrity_with_key()` for full cryptographic verification. Callers must opt in.
4. **S1 fallback:** `verify_signature()` falls back to re-serialization for in-memory tokens (created via `issue()` but never round-tripped through `from_compact()`). This is safe because `issue()` also populates `raw_header_b64`/`raw_claims_b64` from the freshly-encoded bytes.

---

## 🚫 Blocking Issues

None. Track A is unblocked and ready for Session A-2 (Phase 0 completion: D1, D2, SR items).

---

## 📋 Next Session Instructions

```bash
# 1. Navigate to Track A worktree
cd C:\Users\praty\toon_conversations\aidspec\worktrees\track-a

# 2. Confirm branch
git branch  # should show * idprova/track-a-core-security

# 3. Run tests to confirm green
cargo test -p idprova-core  # should show 42 passed

# 4. Read this handover + IDPROVA-MASTER.md for context

# 5. Continue with Session A-2:
#    a. D2 — Make a decision on scope grammar (3-part vs 4-part) and document it
#    b. SR-1 — Zeroize: add zeroize = "1" dep, derive ZeroizeOnDrop on KeyPair
#    c. SR-3 — Reject non-EdDSA: add DatHeader::validate() with alg whitelist
#    d. SR-8 — Max depth: add ChainValidationConfig::max_depth to chain.rs
#    e. S5 — Remove secret_bytes() from public API (check if anything uses it first)
#    f. S6 — Pin security crate versions
```

---

## 📁 Files Modified

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Added `serde_json_canonicalizer = "0.3"`, removed `json-canonicalization = "0.1"` |
| `crates/idprova-core/Cargo.toml` | Switched dep from `json-canonicalization` to `serde_json_canonicalizer` |
| `crates/idprova-core/src/dat/token.rs` | S1 fix: raw_header_b64/raw_claims_b64 fields + verify_signature update + S1 test |
| `crates/idprova-core/src/receipt/entry.rs` | S2+S3 fix: ReceiptSigningPayload, signing_payload_bytes(), verify_signature(), compute_hash() fix + tests |
| `crates/idprova-core/src/receipt/log.rs` | S2 fix: verify_integrity_with_key() + tests |
| `crates/idprova-core/src/aid/document.rs` | S4 fix: JCS via serde_json_canonicalizer in to_canonical_json() + tests |
