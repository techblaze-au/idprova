# NIST SP 800-53 Rev 5 Control Mapping

**Status:** v0.1 — operator-facing mapping reference
**Audience:** compliance officers, auditors, system security plan authors
**Supersedes:** `docs/compliance.md` (which covers NIST SP 800-207 Zero Trust + Australian ISM); this file covers **NIST 800-53 specifically**

---

## How to read this document

Each row in the mapping tables answers two questions:

1. **What does this control require?** (1-2 sentence summary; the authoritative text is the NIST SP 800-53 Rev 5 publication itself)
2. **How does IDprova satisfy it?** (specific protocol primitive, receipt field, or API endpoint that produces the evidence)

These mappings are factual — receipts carry the data fields named in the mapping. They are **not compliance attestations**. IDprova generates the cryptographic evidence; your organisation's System Security Plan (SSP), policies, and operational practices are what establish actual NIST 800-53 compliance.

A control marked **"Partially supported"** means IDprova provides primitives but additional organisational controls or external systems are required to fully satisfy the requirement.

---

## Summary by family

| Family | Controls mapped | Coverage |
|---|---|---|
| AU — Audit and Accountability | 9 | Strong — IDprova's primary alignment |
| IA — Identification and Authentication | 5 | Strong for non-person entities (NPEs / agents) |
| AC — Access Control | 4 | Partial — IDprova handles the cryptographic enforcement layer |
| SC — System and Communications Protection | 6 | Strong for crypto + transmission |
| SI — System and Information Integrity | 2 | Receipt integrity + audit log integrity |

---

## AU — Audit and Accountability

| Control | Title | IDprova mapping |
|---|---|---|
| **AU-2** | Event Logging | Action receipts capture every agent action. Receipt fields: `agent_aid`, `dat_jti`, `action`, `timestamp`, `result`. Configurable per `Scope`. |
| **AU-3** | Content of Audit Records | Receipt envelope includes: timestamp (RFC 3339), source identity (agent AID), event type (action verb), event outcome, scope evaluated. See `docs/protocol-spec-v0.1.md` §6 for full receipt schema. |
| **AU-3(1)** | Additional Audit Information | Optional receipt fields: `user_principal` (delegating party), `delegation_chain` (full DAT chain), `decision_context` (any inputs that influenced the action), `policy_evaluated`. |
| **AU-6** | Audit Record Review, Analysis, and Reporting | `IDProva Cloud` web dashboard provides receipt search/filter by AID/scope/timeframe. Self-hosted operators can use `idprova-cli receipts query`. **Partially supported** — full SIEM-style review is by integration (Splunk, Datadog, Sentinel; see Cloud SIEM connectors). |
| **AU-9** | Protection of Audit Information | Receipts are signed (Ed25519) and hash-chained (BLAKE3). Tampering breaks the chain at the tamper point and is detected by `ReceiptLog::verify_integrity()`. Independent verifiers can validate the chain without trusting the storage layer. |
| **AU-9(2)** | Store on Separate Physical Systems | Self-hosted operators choose registry storage backend (SQLite, Postgres, S3, sovereign object store). Receipt log can be replicated to write-once (WORM) storage. **Partially supported** — IDprova produces tamper-evident records; physical separation is operator's deployment choice. |
| **AU-10** | Non-repudiation | DATs are signed by the issuer's private key; receipts are signed by the agent's private key; both signatures are independently verifiable. Combined with AID identity proof and the receipt chain, no party can plausibly deny actions taken under their delegation. |
| **AU-11** | Audit Record Retention | Receipt log is append-only by design; retention is bounded by operator's storage lifecycle policy (no IDprova-imposed retention limit). Cloud tier defaults to 1-year retention; configurable. |
| **AU-12** | Audit Record Generation | Generation is automatic — every action under a valid DAT produces a receipt. No application code needs to opt-in beyond using the SDK's instrumented action wrappers. |

---

## IA — Identification and Authentication

| Control | Title | IDprova mapping |
|---|---|---|
| **IA-3** | Device Identification and Authentication | Each agent runtime is identified by an AID (`did:aid:domain:agent-name`). Authentication is via Ed25519 signature over the AID document `proof` field, validated at registry level. |
| **IA-5** | Authenticator Management | Key generation, distribution, storage, and revocation are governed by IDprova's key management procedures. See [key-rotation.md](key-rotation.md). 90-day rotation for Ed25519, 180-day for ML-DSA-65. |
| **IA-5(2)** | Public Key-Based Authentication | All agent authentication is public key-based (Ed25519 + optional ML-DSA-65 hybrid). No shared secrets, no passwords, no rotating tokens that aren't asymmetric. |
| **IA-9** | Service Identification and Authentication | Inter-service / inter-agent authentication uses DATs. The DAT's signature proves the issuing service's identity; the chain proves the full delegation history. |
| **IA-9(1)** | Information Exchange | DATs include scoped permissions (`namespace:protocol:resource:action`) that bound the delegation. Receipts capture the scope evaluated at action time. |

---

## AC — Access Control

| Control | Title | IDprova mapping |
|---|---|---|
| **AC-3** | Access Enforcement | DAT scope grammar enforces fine-grained, declarative access. Verification at the PEP (`/v1/dat/verify` or in-process via `idprova-verify`) checks scope match, expiry, revocation, and constraints (rate limit, IP allowlist, geofence) before authorising the action. |
| **AC-3(7)** | Role-Based Access Control | Cloud tier supports RBAC at the registry layer (operator → DAT issuer roles). Within DATs, scopes function as fine-grained capabilities — RBAC at the resource level. **Partially supported** — full RBAC is a Cloud feature; self-hosted operators implement role-to-scope mapping in their issuer service. |
| **AC-4** | Information Flow Enforcement | Delegation chains are explicit and auditable. A DAT can only delegate scopes it itself holds (subset rule); attempts to escalate are rejected at verification. Information flows that cross delegation boundaries leave receipts at each hop. |
| **AC-6** | Least Privilege | Scope grammar and the chain-subset rule enforce least privilege by construction. An issuer can only grant ≤ what it holds. Wildcards (`mcp:*:*`) are explicit and auditable. |

---

## SC — System and Communications Protection

| Control | Title | IDprova mapping |
|---|---|---|
| **SC-8** | Transmission Confidentiality and Integrity | Registry API is TLS 1.3 only. DATs themselves are JWS — self-contained and verifiable at any point, so transmission integrity is independent of transport. |
| **SC-12** | Cryptographic Key Establishment and Management | Keys are generated locally (never centrally distributed). Key rotation per [key-rotation.md](key-rotation.md). Hybrid Ed25519 + ML-DSA-65 for post-quantum readiness (FIPS 204). |
| **SC-13** | Cryptographic Protection | Approved algorithms only: Ed25519 (RFC 8032), ML-DSA-65 (FIPS 204), BLAKE3 (cryptographic hash). `verify_algorithm()` hard-rejects any algorithm not on the approved list (incl. `none`, `HS256`, `RS256` confusion attacks). |
| **SC-17** | Public Key Infrastructure Certificates | IDprova does not depend on X.509 PKI. Trust is rooted in DID Documents, with optional `.well-known/did.json` HTTPS attestation for L1+ trust levels. **Adapter available** for organisations requiring X.509 — see `idprova-x509-bridge` (planned v0.3). |
| **SC-23** | Session Authenticity | Receipts contain monotonically increasing sequence numbers within an agent's chain, plus BLAKE3 hash links to the previous receipt. Sessions cannot be reordered or replayed without breaking the chain. |
| **SC-28** | Protection of Information at Rest | Private keys MUST be encrypted at rest by the operator's runtime. The SDK enforces zeroization on key drop; OS-level encryption (LUKS, BitLocker, FileVault) covers the key file lifecycle. **Partially supported** — IDprova provides the primitives; storage encryption is operator-deployed. |

---

## SI — System and Information Integrity

| Control | Title | IDprova mapping |
|---|---|---|
| **SI-7** | Software, Firmware, and Information Integrity | Receipt log integrity (BLAKE3 hash chain) provides tamper-evident audit. Configuration attestation (optional) hashes runtime config into receipts so post-hoc tampering is detectable. |
| **SI-7(7)** | Integration of Detection and Response | Anomaly detection in IDprova Cloud surfaces receipt-pattern anomalies in real time (impossible chain links, reused JTIs, unexpected scope usage). **Partially supported** — Cloud tier only; self-hosted operators integrate via SIEM connectors. |

---

## What IDprova does NOT cover

A complete NIST 800-53 SSP requires controls IDprova does not address. These are operator's responsibility:

- **PE** (Physical and Environmental Protection) — your data centre / cloud region
- **AT** (Awareness and Training) — your training program for operators and developers
- **CM** (Configuration Management) — your runtime change control
- **CP** (Contingency Planning) — your DR / BC plans
- **IR** (Incident Response) — your IR runbook (though [key-rotation.md §7](key-rotation.md) provides the IDprova-specific compromise runbook)
- **PL** (Planning) — your SSP, security architecture, etc.
- **PM** (Program Management) — your governance and security programme
- **PS** (Personnel Security) — your hiring/screening/termination procedures
- **RA** (Risk Assessment) — your risk register and assessments
- **SA** (System and Services Acquisition) — your supply chain security
- **MP** (Media Protection) — your media handling policies

IDprova is one component of an overall SSP. Use this mapping to identify which controls IDprova evidence supports; document everything else through your organisation's policies and procedures.

---

## Selecting your baseline

For Australian Government / IRAP-aligned systems, NIST 800-53 typically maps as follows:

| Australian Context | NIST 800-53 Baseline |
|---|---|
| OFFICIAL: Sensitive | Moderate |
| PROTECTED | Moderate (with selected High enhancements) |
| SECRET / TOP SECRET | High |

IDprova's mapping above covers controls relevant up to the Moderate baseline cleanly, with enhancement-level support (AU-3(1), AU-9(2), AC-3(7), IA-5(2), SC-13, SI-7(7)) for Moderate/High deployments.

For US Federal systems, see also FedRAMP Moderate; the `compliance.md` neighbouring file's NIST SP 800-207 Zero Trust mapping is complementary to this 800-53 mapping.

---

## How to use this mapping in your SSP

For each NIST 800-53 control your system inherits IDprova's coverage of:

1. Cite this document as the implementation reference
2. Quote the specific receipt/AID/DAT field that provides evidence
3. Reference your operational procedure that uses IDprova to satisfy the control (e.g. "incident response — see internal IR-AGENT-001 which references this mapping for AU-9 evidence collection")
4. For **Partially supported** items, document the additional controls your organisation provides

Audit-ready evidence for IDprova-mapped controls is generated by:

```
idprova-cli compliance export --controls AU-2,AU-9,AU-10,AU-12 \
                              --period 2026-01-01..2026-03-31 \
                              --output audit-bundle.tar.gz
```

(v0.2 — currently the export pipeline produces JSON receipts; the bundled compliance package format is on the v0.2 roadmap.)

---

## References

- NIST SP 800-53 Rev 5 — *Security and Privacy Controls for Information Systems and Organizations*
- NIST SP 800-57 Part 1 Rev 5 — *Recommendation for Key Management*
- NIST SP 800-207 — *Zero Trust Architecture* (covered separately in `compliance.md`)
- FIPS 204 — *Module-Lattice-Based Digital Signature Standard* (ML-DSA)
- RFC 8032 — *Edwards-Curve Digital Signature Algorithm (EdDSA)*
- BLAKE3 specification
- W3C DID Core 1.0
- IDprova `protocol-spec-v0.1.md` §6 (Receipt schema)
- IDprova `key-rotation.md` (rotation procedures)
- IDprova `compliance.md` (NIST SP 800-207 + ISM mapping)
- IDprova `STRIDE-THREAT-MODEL.md` (threat model)
