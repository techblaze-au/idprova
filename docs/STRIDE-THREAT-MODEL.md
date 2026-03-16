# IDprova STRIDE Threat Model

**Version:** 1.0
**Date:** 2026-03-02
**Author:** Tech Blaze Consulting (generated via threat-modeling-expert skill)
**Status:** Active — referenced by security-audit skill, SDK development, NIST CAISI response

---

## 1. System Overview

IDprova is an open protocol for verifiable AI agent identity with three pillars:

1. **Agent Identity Documents (AIDs)** — W3C DID-based identity with Ed25519 + ML-DSA-65 hybrid crypto
2. **Delegation Attestation Tokens (DATs)** — JWS-format signed, scoped, time-bounded, chainable permission tokens
3. **Action Receipts** — BLAKE3 hash-chained tamper-evident audit trails mapped to compliance controls

### Trust Boundaries

```
┌──────────────────────────────────────────────────────┐
│ TB-1: Agent Runtime (untrusted)                      │
│   - AI agent process                                 │
│   - Agent configuration                              │
│   - Local key storage                                │
│                                                      │
│   ┌──────────────────────────────────────┐           │
│   │ TB-2: IDprova SDK (trusted library)  │           │
│   │   - KeyPair (Ed25519 signing)        │           │
│   │   - DAT issue/verify                 │           │
│   │   - Receipt generation               │           │
│   │   - AID document builder             │           │
│   └──────────────────────────────────────┘           │
│                                                      │
└────────────────────┬─────────────────────────────────┘
                     │ Network (TLS 1.3+)
                     ▼
┌──────────────────────────────────────────────────────┐
│ TB-3: IDprova Registry (semi-trusted)                │
│   - AID storage (SQLite/Postgres)                    │
│   - DID resolution endpoint                          │
│   - Health/meta endpoints                            │
└──────────────────────────────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────────┐
│ TB-4: External Services                              │
│   - MCP servers (tool providers)                     │
│   - A2A agent peers                                  │
│   - HTTP API endpoints                               │
│   - DNS (for DID domain resolution)                  │
└──────────────────────────────────────────────────────┘
```

---

## 2. Component-Level STRIDE Analysis

### 2.1 Agent Identity Documents (AIDs)

**Component:** `crates/idprova-core/src/aid/document.rs`, `aid/builder.rs`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| AID-S1 | **Spoofing** | Attacker creates an AID for a domain they don't control (`did:aid:target.com:evil-agent`) | **Critical** | Medium |
| AID-S2 | **Spoofing** | DNS hijack → attacker serves malicious DID document for a legitimate domain | **Critical** | Low |
| AID-T1 | **Tampering** | Registry compromise → modification of stored AID documents | **High** | Low |
| AID-T2 | **Tampering** | Man-in-the-middle modifies AID during DID resolution (if TLS downgraded) | **High** | Low |
| AID-R1 | **Repudiation** | Agent claims its AID was compromised and denies actions it performed | **Medium** | Medium |
| AID-I1 | **Info Disclosure** | AID document leaks agent model/runtime/config metadata to unauthorized parties | **Medium** | High |
| AID-I2 | **Info Disclosure** | Multibase-encoded public key enumeration reveals organizational agent inventory | **Low** | High |
| AID-D1 | **DoS** | Flood registry with AID registrations → storage exhaustion | **Medium** | Medium |
| AID-D2 | **DoS** | Malformed AID documents with deeply nested JSON → parsing CPU exhaustion | **Medium** | Medium |
| AID-E1 | **Elevation** | Attacker registers an AID with higher trust level than warranted (e.g., L0 claims L3) | **High** | Medium |

**Mitigations:**
- **AID-S1:** L1+ trust levels require DNS TXT record or `.well-known/did.json` verification
- **AID-S2:** DNSSEC validation recommended; pin registry TLS certificates
- **AID-T1:** AID documents are signed by controller — verify `proof.proofValue` on every resolution
- **AID-E1:** Trust level transitions (L0→L1, L1→L2) must be attested by the registry, not self-declared

### 2.2 Key Management

**Component:** `crates/idprova-core/src/crypto/keys.rs`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| KEY-S1 | **Spoofing** | Private key theft → attacker signs DATs/receipts as the legitimate agent | **Critical** | Medium |
| KEY-T1 | **Tampering** | Attacker modifies key material in storage (swap public key to their own) | **Critical** | Low |
| KEY-I1 | **Info Disclosure** | Private key leaked through memory dump, core file, or GC in Python/Node.js | **Critical** | Medium |
| KEY-I2 | **Info Disclosure** | Side-channel attack (timing) on Ed25519 signature reveals key bits | **High** | Low |
| KEY-D1 | **DoS** | Key generation entropy starvation on embedded/container systems | **Medium** | Low |
| KEY-E1 | **Elevation** | Attacker obtains signing key → can issue arbitrary DATs without scope limits | **Critical** | Low |

**Mitigations:**
- **KEY-S1:** Encrypt private keys at rest (AES-256-GCM); never export raw bytes across FFI boundary
- **KEY-I1 (P0 — SEC-1/SEC-2):** PyO3 wrapper must `zeroize` on Drop; napi-rs must never return key bytes to JS
- **KEY-I2:** ed25519-dalek uses constant-time operations; verify this property is preserved through FFI
- **KEY-E1:** Key rotation mechanism needed; short-lived keys recommended for agents

### 2.3 Delegation Attestation Tokens (DATs)

**Component:** `crates/idprova-core/src/dat/token.rs`, `dat/scope.rs`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| DAT-S1 | **Spoofing** | Algorithm confusion — `DatHeader.alg` parsed from untrusted input, attacker sets `"none"` or `"HS256"` | **Critical** | High |
| DAT-S2 | **Spoofing** | JWS header injection — extra fields (`jwk`, `jku`, `x5u`) inject attacker-controlled keys | **Critical** | Medium |
| DAT-T1 | **Tampering** | Scope escalation in delegation chain — child DAT claims broader scope than parent | **High** | Medium |
| DAT-T2 | **Tampering** | Replay attack — expired/revoked DAT re-presented to server that doesn't check exp/revocation | **High** | High |
| DAT-R1 | **Repudiation** | Delegator denies issuing a DAT (no receipt of delegation action) | **Medium** | Medium |
| DAT-I1 | **Info Disclosure** | DAT claims leak organizational structure (who delegates to whom) | **Low** | High |
| DAT-D1 | **DoS** | Deeply nested delegation chain (User→Agent1→Agent2→...→AgentN) — unbounded chain verification | **Medium** | Medium |
| DAT-E1 | **Elevation** | Wildcard scope (`mcp:*:*`) grants unintended permissions beyond what delegator intended | **High** | Medium |

**Mitigations:**
- **DAT-S1 (P0 — SEC-3):** Hard-reject any `alg` value other than `"EdDSA"`. Add validation in `from_compact()`
- **DAT-S2 (P0 — SEC-4):** Add `#[serde(deny_unknown_fields)]` on `DatHeader`. Explicitly reject `jwk`/`jku`/`x5u` fields
- **DAT-T1:** Verify strict subset: child scope MUST be a subset of parent scope at each delegation level
- **DAT-T2:** Servers MUST check `exp` and `nbf`; implement revocation (CRL or short-lived tokens)
- **DAT-D1 (SR-8):** Maximum delegation chain depth = 5
- **DAT-E1 (SR-14):** Wildcards prohibited by default; require explicit opt-in per scope namespace

### 2.4 Action Receipts

**Component:** `crates/idprova-core/src/receipt/entry.rs`, `receipt/log.rs`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| REC-T1 | **Tampering** | Receipt log truncation — attacker removes recent entries and re-creates chain from earlier point | **High** | Medium |
| REC-T2 | **Tampering** | Receipt backdating — generate receipt with false timestamp, signed with valid key | **Medium** | Medium |
| REC-R1 | **Repudiation** | Agent crashes mid-action → no receipt generated → action unaccounted for | **High** | High |
| REC-I1 | **Info Disclosure** | Receipt `inputHash`/`outputHash` insufficient protection — rainbow table attack on common inputs | **Medium** | Low |
| REC-D1 | **DoS** | Receipt storage exhaustion from verbose/frequent agent activity | **Medium** | Medium |
| REC-E1 | **Elevation** | Attacker generates fake receipts for actions they didn't perform (forge audit trail) | **High** | Low |

**Mitigations:**
- **REC-T1:** Anchor periodic receipt chain hashes to external timestamping service (RFC 3161 or blockchain)
- **REC-R1 (SR-4):** Receipt generation must be atomic with action execution — generate receipt BEFORE returning action result
- **REC-T2:** Use sequence numbers + monotonic clock; external timestamp witnesses for compliance scenarios
- **REC-E1:** Receipts are signed by agent key — verify signature against AID's verification method

### 2.5 Protocol Bindings

**Component:** SDKs — `sdks/python/`, `sdks/typescript/packages/mcp/`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| BIND-S1 | **Spoofing** | MCP header stripping — proxy/middleware removes `X-IDProva-AID` and `X-IDProva-DAT` headers | **High** | Medium |
| BIND-T1 | **Tampering** | Header injection — attacker injects forged IDProva headers in stdio JSON-RPC transport | **High** | Medium |
| BIND-I1 | **Info Disclosure** | SSRF via DID resolution — attacker's DID points to `http://169.254.169.254/` (cloud metadata) | **Critical** | High |
| BIND-I2 | **Info Disclosure** | RFC 9421 signature covers insufficient fields → partial request forgery | **High** | Medium |
| BIND-D1 | **DoS** | Verification-heavy middleware adds latency to every MCP tool call | **Medium** | Medium |
| BIND-E1 | **Elevation** | A2A AgentCard extension: peer agent claims higher trust level via forged `idprova_identity` field | **High** | Medium |

**Mitigations:**
- **BIND-I1 (P1 — SEC-5):** DID resolver MUST block private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), localhost, link-local (169.254.0.0/16), and cloud metadata (169.254.169.254)
- **BIND-I2 (SR-12):** RFC 9421 signature MUST cover `Content-Digest`, `Authorization`, `Host` at minimum
- **BIND-S1:** Require TLS for HTTP transport; for stdio, sign the entire JSON-RPC envelope
- **BIND-D1:** Cache AID resolution results (TTL 5 min); cache DAT verification results

### 2.6 Storage Backends

**Component:** `crates/idprova-registry/src/store.rs`

| Threat | Category | Description | Severity | Likelihood |
|--------|----------|-------------|----------|------------|
| STORE-T1 | **Tampering** | SQL injection in registry SQLite queries | **Critical** | Medium |
| STORE-I1 | **Info Disclosure** | Unauthorized read access to registry database → dump all AIDs | **High** | Medium |
| STORE-D1 | **DoS** | SQLite write contention under high concurrency | **Medium** | Medium |
| STORE-E1 | **Elevation** | Registry admin endpoint without authentication → unauthorized AID modifications | **High** | Medium |

**Mitigations:**
- **STORE-T1 (P1 — SEC-7):** Verify ALL queries use `params![]` parameterization. Add SQL injection test cases
- **STORE-I1:** Registry should require authentication for write operations; read may be public
- **STORE-D1:** Use WAL mode for SQLite; consider Postgres for production registries

---

## 3. Attack Trees

### 3.1 Attack Tree: Unauthorized Agent Impersonation

```
Goal: Impersonate a legitimate agent (sign as their DID)
├── 1. Steal private key [Critical]
│   ├── 1.1 Memory dump of Python process (KEY-I1) [Medium]
│   ├── 1.2 Access unencrypted key file (KEY-S1) [Medium]
│   ├── 1.3 Node.js Buffer not cleared (KEY-I1/SEC-2) [Medium]
│   └── 1.4 Supply chain: malicious PyNaCl/ed25519-dalek fork [Low]
├── 2. Algorithm confusion bypass (DAT-S1/SEC-3) [Critical]
│   ├── 2.1 Set alg="none" in JWS header [High likelihood if unfixed]
│   └── 2.2 Set alg="HS256" + use public key as HMAC secret [Medium]
├── 3. DNS hijack + fake AID (AID-S2) [High]
│   ├── 3.1 BGP hijack of domain's DNS [Low]
│   └── 3.2 DNS cache poisoning [Medium]
└── 4. Registry compromise (AID-T1) [High]
    ├── 4.1 SQL injection to modify AID (STORE-T1) [Medium]
    └── 4.2 Unauthorized admin access (STORE-E1) [Medium]
```

### 3.2 Attack Tree: Scope Escalation

```
Goal: Gain permissions beyond what was delegated
├── 1. Wildcard exploitation (DAT-E1) [High]
│   ├── 1.1 Delegator accidentally grants mcp:*:* [High likelihood]
│   └── 1.2 Wildcard scope covers new tools added later [Medium]
├── 2. Delegation chain manipulation (DAT-T1) [High]
│   ├── 2.1 Child DAT claims scope not in parent [Medium if unvalidated]
│   └── 2.2 Infinite delegation depth [Medium]
├── 3. JWS header injection (DAT-S2/SEC-4) [Critical]
│   ├── 3.1 Inject `jwk` field with attacker's public key [High if unfixed]
│   └── 3.2 Inject `jku` pointing to attacker's JWKS endpoint [Medium]
└── 4. Expired token replay (DAT-T2) [High]
    ├── 4.1 Server doesn't check exp claim [High]
    └── 4.2 Clock skew exploitation (>5 min tolerance) [Low]
```

### 3.3 Attack Tree: Audit Trail Evasion

```
Goal: Perform actions without detection in receipt log
├── 1. Receipt generation bypass (REC-R1) [High]
│   ├── 1.1 Crash agent after action, before receipt [High likelihood]
│   └── 1.2 Modify SDK to skip receipt generation [Medium]
├── 2. Receipt chain tampering (REC-T1) [High]
│   ├── 2.1 Truncate log and rebuild from earlier state [Medium]
│   └── 2.2 Fork chain — maintain parallel chain for auditors [Low]
├── 3. Timestamp manipulation (REC-T2) [Medium]
│   ├── 3.1 Set system clock back before generating receipt [Medium]
│   └── 3.2 Generate receipt with future timestamp [Low]
└── 4. Storage backend bypass (STORE-T1) [High]
    └── 4.1 Direct database modification (SQL injection) [Medium]
```

---

## 4. Risk Prioritization Matrix

| ID | Threat | Severity | Likelihood | Risk Score | Status |
|----|--------|----------|------------|------------|--------|
| DAT-S1 | Algorithm confusion (SEC-3) | Critical | High | **P0** | Open — fix before SDK release |
| DAT-S2 | JWS header injection (SEC-4) | Critical | Medium | **P0** | Open — fix before SDK release |
| KEY-I1 | Private key in GC memory (SEC-1/SEC-2) | Critical | Medium | **P0** | Open — fix in SDK bindings |
| BIND-I1 | SSRF in DID resolution (SEC-5) | Critical | High | **P1** | Open — fix during SDK dev |
| STORE-T1 | SQL injection in registry (SEC-7) | Critical | Medium | **P1** | Needs audit |
| DAT-T2 | Expired token replay | High | High | **P1** | Partial — exp check exists, no revocation |
| AID-S1 | Domain spoofing at L0 | Critical | Medium | **P1** | By design (L0 = self-declared) |
| DAT-T1 | Scope escalation in chain | High | Medium | **P2** | Not yet implemented |
| REC-R1 | Non-atomic receipt generation | High | High | **P2** | Design — needs atomic guarantee |
| DAT-E1 | Wildcard scope over-permission | High | Medium | **P2** | Design — needs default-deny wildcards |
| AID-E1 | Trust level self-elevation | High | Medium | **P2** | Needs registry-enforced transitions |
| BIND-I2 | Insufficient RFC 9421 coverage | High | Medium | **P2** | Not yet implemented |
| AID-D1 | Registration flood DoS | Medium | Medium | **P3** | Needs rate limiting |
| REC-T1 | Receipt chain truncation | High | Medium | **P3** | Needs external anchoring |
| KEY-I2 | Timing side-channel | High | Low | **P3** | ed25519-dalek is constant-time |

---

## 5. Security Requirements

Derived from STRIDE analysis, mapped to implementation.

| ID | Requirement | STRIDE Source | Priority | Implementation |
|----|-------------|---------------|----------|----------------|
| SR-1 | Zeroize private keys after use | KEY-I1 | P0 | PyO3 `Drop` impl with `zeroize` crate; napi-rs keep key Rust-side |
| SR-2 | Constant-time signature verification | KEY-I2 | P1 | Verify ed25519-dalek preserves through FFI; no early-return on partial match |
| SR-3 | Strict subset scope inheritance in DAT chains | DAT-T1 | P1 | `Scope::is_subset_of()` check in chain validation |
| SR-4 | Atomic receipt generation with action | REC-R1 | P1 | Generate receipt before returning action result |
| SR-5 | TLS 1.3+ for DID resolution | AID-T2 | P1 | Configure reqwest to require TLS 1.3 minimum |
| SR-6 | SSRF protection in DID resolver | BIND-I1 | P1 | Block private IPs, localhost, link-local, cloud metadata |
| SR-7 | Encrypt private keys at rest | KEY-S1 | P1 | AES-256-GCM encryption; prompt for passphrase or use OS keychain |
| SR-8 | Max delegation chain depth = 5 | DAT-D1 | P2 | Reject DATs with `delegation_chain.len() > 5` |
| SR-9 | DATs must include iat/exp/jti | DAT-T2 | P0 | Already enforced in `Dat::issue()` |
| SR-10 | Parameterized SQL only | STORE-T1 | P1 | Audit all rusqlite queries use `params![]` |
| SR-11 | Pin crypto library versions | KEY supply chain | P1 | Cargo.lock + `=` version specs for ed25519-dalek, blake3 |
| SR-12 | RFC 9421 must cover Content-Digest | BIND-I2 | P2 | Signature base includes `content-digest`, `host`, `authorization` |
| SR-13 | Fail-closed on revocation check failure | DAT-T2 | P1 | If revocation endpoint unreachable, reject DAT |
| SR-14 | Wildcards prohibited by default | DAT-E1 | P2 | Require `allow_wildcards: true` in verifier config |
| SR-15 | SPIFFE bridge = explicit config only | BIND-E1 | P2 | No automatic SVID→AID conversion; require mapping config |

---

## 6. Compliance Control Mapping

| Security Requirement | NIST 800-53 | Australian ISM | SOC 2 |
|---------------------|-------------|----------------|-------|
| SR-1: Key zeroization | SC-12(1) | ISM-0457 | CC6.1 |
| SR-2: Constant-time crypto | SC-13 | ISM-0459 | CC6.1 |
| SR-3: Scope inheritance | AC-6(3) | ISM-1526 | CC6.3 |
| SR-4: Atomic receipts | AU-12 | ISM-0580 | CC7.2 |
| SR-5: TLS 1.3+ | SC-8 | ISM-1139 | CC6.7 |
| SR-6: SSRF protection | SC-7 | ISM-1170 | CC6.6 |
| SR-7: Key encryption at rest | SC-12 | ISM-0460 | CC6.1 |
| SR-8: Chain depth limit | AC-6(1) | ISM-1525 | CC6.3 |
| SR-10: SQL parameterization | SI-10 | ISM-1246 | CC6.1 |
| SR-13: Fail-closed revocation | AC-3 | ISM-1173 | CC6.1 |

---

## 7. Residual Risks

After implementing all mitigations, these risks remain:

1. **Quantum threat to Ed25519** — Ed25519 is not quantum-resistant. ML-DSA-65 hybrid signatures are planned but not yet implemented. Risk accepted until hybrid crypto is operational.

2. **L0 self-declared identity** — Any entity can create an L0 AID. This is by design (low barrier to entry) but means L0 identity provides no assurance. Mitigated by trust level system — consumers should require L1+ for sensitive operations.

3. **Receipt chain integrity** — Without external anchoring (timestamping service, blockchain), a compromised agent with its own signing key can fabricate an entire receipt chain. Mitigated by cross-referencing with server-side logs and external witnesses.

4. **Supply chain attacks on crypto libraries** — Despite version pinning (SR-11), a compromised upstream release between audits could introduce vulnerabilities. Mitigated by hash verification of dependencies and periodic audit.

---

## 8. Review Schedule

| Event | Action |
|-------|--------|
| Before each SDK release | Review all P0/P1 items are resolved |
| Monthly | Scan for new CVEs in ed25519-dalek, blake3, reqwest, rusqlite |
| After architecture changes | Update trust boundaries and re-run STRIDE |
| After NIST CAISI feedback | Update threat model with any new attack vectors identified |
| Quarterly | Full threat model review with stakeholders |

---

## Appendix: Glossary

- **AID**: Agent Identity Document (W3C DID Document for AI agents)
- **DAT**: Delegation Attestation Token (signed permission grant)
- **DID**: Decentralized Identifier (W3C standard)
- **JWS**: JSON Web Signature (RFC 7515)
- **STRIDE**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
- **SSRF**: Server-Side Request Forgery
- **FFI**: Foreign Function Interface (Rust ↔ Python/TypeScript)
- **PQC**: Post-Quantum Cryptography
- **ML-DSA-65**: Module-Lattice-based Digital Signature Algorithm (FIPS 204)
