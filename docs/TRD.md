# IDprova SDK — Technical Requirements Document (TRD)

**Version:** 1.0
**Date:** 2026-03-02
**Status:** Active — to be published to Notion when API recovers

---

## 1. Architecture — Four-Layer Stack

```
Layer 4: Framework Integrations (LangChain, CrewAI, Claude Agent SDK)
Layer 3: Protocol Bindings (MCP middleware, A2A binding, HTTP RFC 9421, SPIFFE bridge)
Layer 2: Core Protocol (AID, DAT, Receipt — idprova-core crate)
Layer 1: Cryptography (Ed25519 via ed25519-dalek, BLAKE3, SHA-256)
```

| Layer | Components | Implementation |
|-------|-----------|----------------|
| Layer 4 | LangChain, CrewAI, Claude Agent SDK | Python/TS wrappers (future) |
| Layer 3 | MCP middleware, A2A binding, HTTP RFC 9421, SPIFFE bridge | SDK packages |
| Layer 2 | AID, DAT, Receipt, Scope, TrustLevel | `idprova-core` Rust crate (100% complete, 33 tests) |
| Layer 1 | Ed25519 (ed25519-dalek v2), BLAKE3, SHA-256 | Rust crate dependencies |

---

## 2. Existing Rust API to Bind

All SDK types wrap existing Rust implementations from `idprova-core`. **No logic reimplementation.**

| Rust Type | Module | Python Class | TypeScript Class |
|-----------|--------|-------------|-----------------|
| `KeyPair` | crypto::keys | `idprova.KeyPair` | `KeyPair` |
| `PublicKey` | crypto::keys | `idprova.PublicKey` | `PublicKey` |
| `AidDocument` | aid::document | `idprova.AID` | `AID` |
| `AidBuilder` | aid::builder | `idprova.AIDBuilder` | `AIDBuilder` |
| `Dat` | dat::token | `idprova.DAT` | `DAT` |
| `DatClaims` | dat::token | `idprova.DATClaims` | `DATClaims` |
| `DatConstraints` | dat::token | `idprova.DATConstraints` | `DATConstraints` |
| `Scope` | dat::scope | `idprova.Scope` | `Scope` |
| `ActionReceipt` | receipt::entry | `idprova.ActionReceipt` | `ActionReceipt` |
| `ReceiptLog` | receipt::log | `idprova.ReceiptLog` | `ReceiptLog` |
| `TrustLevel` | trust::level | `idprova.TrustLevel` | `TrustLevel` |
| `IdprovaError` | error | `idprova.IdprovaError` | `IdprovaError` |

---

## 3. SDK Binding Strategy

### Python SDK (PyO3 + Maturin)

- `pyproject.toml` already exists with maturin config
- Add `#[pyclass]` / `#[pymethods]` annotations to Rust types
- Map `IdprovaError` variants to Python exception hierarchy:
  - `IdprovaError` (base)
  - `DatExpiredError`
  - `DatNotYetValidError`
  - `VerificationFailedError`
  - `InvalidAidError`
  - `InvalidDatError`
- Generate `.pyi` type stubs for IDE support
- `py.typed` marker (PEP 561)
- Publish to PyPI as `idprova`
- Platform wheels: manylinux2014_x86_64, manylinux2014_aarch64, macosx_x86_64, macosx_arm64, win_amd64

### TypeScript SDK (napi-rs)

- Monorepo with 3 packages:
  - `@idprova/core` — napi-rs native bindings to Rust core
  - `@idprova/mcp` — MCP authentication middleware
  - `@idprova/sdk` — High-level convenience API
- napi-rs generates `.d.ts` automatically
- Pure-TS fallback using `@noble/ed25519` for browser/Deno (Phase 2)
- Publish to npm

---

## 4. Protocol Bindings Design

### MCP Middleware

**Python client-side:**
```python
from idprova.bindings.mcp import IdprovaMiddleware
middleware = IdprovaMiddleware(agent_identity=aid, signing_key=keypair)
# Attaches X-IDProva-AID + X-IDProva-DAT headers to MCP tool calls
```

**TypeScript server-side:**
```typescript
import { createIdprovaMiddleware } from '@idprova/mcp';
const auth = createIdprovaMiddleware({
  registryUrl: 'https://registry.idprova.dev',
  requiredTrustLevel: 'L1'
});
```

**Transport support:**
- HTTP/SSE: `X-IDProva-AID` + `X-IDProva-DAT` headers
- stdio: JSON-RPC params extension field

### A2A Binding

- Extends AgentCard JSON with `idprova_identity` field (DID + trust level)
- Attaches DAT to task requests
- Verifies peer identity on task acceptance

### HTTP (RFC 9421)

- Signs HTTP requests with `Signature-Input` + `Signature` headers
- Signature base covers: `Content-Digest`, `Authorization`, `Host`
- Verification middleware for FastAPI, Express, Axum

### SPIFFE Bridge

- Convert SPIFFE SVID to IDprova AID (one-way, explicit mapping)
- Requires explicit config (SR-15) — no automatic conversion
- SPIRE plugin for IDprova identity issuance (Phase 2)

---

## 5. Security Requirements

Derived from STRIDE threat model (`aidspec/docs/STRIDE-THREAT-MODEL.md`).

### P0 — Must fix before SDK release

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SR-1 | Zeroize private keys after use | PyO3 `Drop` impl with `zeroize`; napi-rs keep key Rust-side |
| SR-9 | DATs must include iat/exp/jti | Already enforced in `Dat::issue()` |
| SEC-3 | Hard-reject any `alg` other than `"EdDSA"` | Add validation in `from_compact()` |
| SEC-4 | `#[serde(deny_unknown_fields)]` on `DatHeader` | Reject `jwk`/`jku`/`x5u` fields |

### P1 — Fix during SDK development

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SR-2 | Constant-time signature verification | Verify ed25519-dalek preserves through FFI |
| SR-3 | Strict subset scope inheritance in DAT chains | `Scope::is_subset_of()` in chain validation |
| SR-4 | Atomic receipt generation with action | Generate receipt before returning action result |
| SR-5 | TLS 1.3+ for DID resolution | Configure reqwest TLS 1.3 minimum |
| SR-6 | SSRF protection in DID resolver | Block private IPs, localhost, link-local, cloud metadata |
| SR-7 | Encrypt private keys at rest | AES-256-GCM; OS keychain integration |
| SR-10 | Parameterized SQL only | Audit all rusqlite queries use `params![]` |
| SR-11 | Pin crypto library versions | Cargo.lock + exact version specs |
| SR-13 | Fail-closed on revocation check failure | Reject DAT if revocation endpoint unreachable |

### P2 — Address post-launch

| ID | Requirement | Implementation |
|----|-------------|----------------|
| SR-8 | Max delegation chain depth = 5 | Reject DATs with `delegation_chain.len() > 5` |
| SR-12 | RFC 9421 covers Content-Digest | Signature base includes content-digest, host, authorization |
| SR-14 | Wildcards prohibited by default | Require `allow_wildcards: true` in verifier config |
| SR-15 | SPIFFE bridge = explicit config only | No automatic SVID-to-AID conversion |

---

## 6. Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| `KeyPair.generate()` | <50ms | Ed25519 key generation |
| `KeyPair.sign()` | <1ms | Ed25519 signature |
| `DAT.issue()` | <5ms | Serialize + sign |
| `DAT.verify_signature()` | <2ms | Ed25519 verify |
| `ReceiptLog.verify_integrity()` | <20ms / 1000 receipts | BLAKE3 chain verification |
| DID resolution | <5s timeout | HTTP with TLS + DNS |

---

## 7. Testing Strategy

### Cross-SDK Interop Testing
- Python signs → TypeScript verifies (and vice versa)
- All SDKs validate against shared test vectors in `aidspec/test-vectors/`
- Matrix: {Python, TypeScript, Rust CLI} × {sign, verify, chain}

### Property-Based Testing
- Python: `hypothesis` for crypto properties
- TypeScript: `fast-check` for crypto properties
- Properties: sign-verify roundtrip, scope subset transitivity, chain hash integrity

### CI Pipeline
- GitHub Actions matrix: Linux / macOS / Windows
- `cargo test --workspace` (Rust core + SDK crates)
- `pytest` (Python SDK)
- `vitest` (TypeScript SDK)

---

## 8. DX Targets

### First Operation in <2 Minutes

**Python:**
```bash
pip install idprova
python -c "from idprova import AgentIdentity; a = AgentIdentity.create('test'); print(a.did)"
```

**TypeScript:**
```bash
npm install @idprova/core
node -e "const { AgentIdentity } = require('@idprova/core'); console.log(AgentIdentity.create('test').did)"
```

### Error Messages
Every error includes: What happened, When (context), How to fix (actionable).

Example: `DatExpiredError: DAT expired 2 hours ago (exp: 2026-03-01T10:00:00Z, now: 2026-03-01T12:00:00Z). Fix: Issue a new DAT with a later expiration.`

### IDE Support
- Python: `.pyi` stub files with full type annotations + `py.typed` marker
- TypeScript: napi-rs auto-generates `.d.ts`; augmented with TSDoc comments

---

## Related Documents

- **PRD:** [Notion](https://www.notion.so/3174683942b08133b437e507e915c63e)
- **TRD Notion page:** [Notion](https://www.notion.so/3174683942b0818da72fe2cf3594dce3) (partial — API was down during creation)
- **STRIDE Threat Model:** `aidspec/docs/STRIDE-THREAT-MODEL.md`
- **Protocol Spec:** `aidspec/docs/protocol-spec-v0.1.md` (2,428 lines)
- **NIST CAISI Response:** `aidspec/docs/NIST-RFI-Response-Draft.md`
