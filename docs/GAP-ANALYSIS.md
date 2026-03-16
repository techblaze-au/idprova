# IDprova SDK — Gap Analysis

**Version:** 1.1
**Date:** 2026-03-14
**Status:** Active — most gaps resolved

---

## Summary

17 gaps identified originally, 10 now resolved. Remaining gaps are ecosystem/strategic items.

| Priority | Original | Resolved | Remaining |
|----------|----------|----------|-----------|
| URGENT | 3 | 3 | 0 |
| HIGH | 7 | 6 | 1 (SPIFFE bridge) |
| MEDIUM | 6 | 0 | 6 |
| LOW | 1 | 0 | 1 |

---

## URGENT — ~~This Week~~ RESOLVED

### Gap 1: No git commits in aidspec repo ✅ RESOLVED
Git repo initialized, code committed and pushed to GitHub.

### Gap 2: No GitHub repos created (404) ✅ RESOLVED
`techblaze-au/idprova` exists (currently private, pending public launch).

### Gap 3: idprova.dev not deployed ✅ RESOLVED
Live on Vercel with 25+ pages, SEO/OG tags, Cloudflare Turnstile CAPTCHA, and Google Analytics.

---

## HIGH Priority — Weeks 2-4

### Gap 4: SDKs are placeholder only ✅ RESOLVED
Python SDK (PyO3) and TypeScript SDK (napi-rs) both built from Rust core. Ready for PyPI and npm publish.

### Gap 5: No SPIFFE/OAuth bridge
Industry converging on SPIFFE for workload identity. No bridge from SPIFFE SVID to IDprova AID.
**Action:** Design one-way SPIFFE bridge with explicit mapping config. Implement month 3.

### Gap 6: No agent discovery mechanism ✅ RESOLVED
DID resolution implemented: local cache, `.well-known/did/idprova/{agent-name}/did.json`, registry lookup, universal resolver fallback.

### Gap 7: No DAT revocation system ✅ RESOLVED
Per-token revocation via `POST /v1/delegations/{jti}/revoke`, cascading revocation, short-lived DATs (24hr max for L0-L1).

### Gap 8: No key lifecycle management ✅ RESOLVED
Key rotation defined (Ed25519 every 90 days, ML-DSA-65 every 180 days), emergency rotation, key storage hierarchy (HSM > TPM > OS Keychain > Encrypted File).

### Gap 9: No multi-hop delegation verification ✅ RESOLVED
Delegation chain validation with scope narrowing rule enforced at every step. Cascading revocation implemented.

### Gap 10: Formal threat model ✅ RESOLVED
STRIDE threat model created and saved to `aidspec/docs/STRIDE-THREAT-MODEL.md`.
15 security requirements extracted, 3 attack trees documented.

---

## MEDIUM Priority — Months 2-3

### Gap 11: No observability/OTel integration
Only 21% of orgs track agent inventory. No OpenTelemetry spans/metrics for IDprova operations.
**Action:** Add OTel instrumentation to SDK (traces for sign/verify/resolve).

### Gap 12: No enterprise IAM bridge
SCIM/Entra/Okta integration missing. Enterprises need to manage agent identities through existing IAM.
**Action:** Design SCIM provisioning endpoint for agent identities. Month 4+.

### Gap 13: No Go SDK
Kubernetes/SPIFFE ecosystem primarily uses Go. Missing Go SDK limits adoption.
**Action:** Plan Go SDK using cgo or pure-Go reimplementation. Month 4+.

### Gap 14: No interop testing with competitors
AAIP, AGNTCY compatibility untested. No proof of protocol coexistence.
**Action:** Build interop test suite against AAIP and AGNTCY. Month 3.

### Gap 15: Test vectors directory empty
`aidspec/test-vectors/` has subdirectories but no actual test data. Blocks cross-SDK testing.
**Action:** Generate test vectors from Rust tests and save as JSON. Week 3.

### Gap 16: No monetization model
Protocol is Apache 2.0 open source. No revenue model for sustainability.
**Options:** Managed registry SaaS, enterprise support tiers, compliance certification service.

---

## LOW Priority — Month 4+

### Gap 17: No TEE/hardware attestation
NEAR IronClaw and Teleport support hardware attestation. IDprova only has software-based trust levels.
**Action:** Research TPM/SGX attestation integration for L3/L4 trust levels.

---

## Strategic Timeline (Updated March 14, 2026)

| Timeframe | Deliverables |
|-----------|-------------|
| ~~**This week**~~ | ~~Git init, GitHub repos, idprova.dev~~ ✅ ALL DONE |
| ~~**Weeks 2-4**~~ | ~~Python SDK, test vectors, CLI~~ ✅ SDKs DONE |
| **Now (Mar 14-21)** | Make repo public, publish packages, submit NCCoE feedback, CAISI registration |
| **Month 2 (April)** | SPIFFE bridge, OTel integration, NCCoE response deadline (Apr 2), W3C DIDs (Apr 5) |
| **Month 3-6** | Enterprise features, Go SDK, managed registry pilot, interop testing |

---

## Related Documents

- **PRD:** [Notion](https://www.notion.so/3174683942b08133b437e507e915c63e)
- **TRD:** `aidspec/docs/TRD.md`
- **STRIDE Threat Model:** `aidspec/docs/STRIDE-THREAT-MODEL.md`
- **Protocol Spec:** `aidspec/docs/protocol-spec-v0.1.md`
