# IDprova SDK — Gap Analysis

**Version:** 1.0
**Date:** 2026-03-02
**Status:** Active — to be published to Notion when API recovers

---

## Summary

17 gaps identified, prioritized by impact on SDK release and market positioning.

| Priority | Count | Category |
|----------|-------|----------|
| URGENT | 3 | Infrastructure (git, GitHub, docs site) |
| HIGH | 7 | Core functionality + security |
| MEDIUM | 6 | Ecosystem + testing + monetization |
| LOW | 1 | Hardware attestation |

---

## URGENT — This Week

### Gap 1: No git commits in aidspec repo
**Status:** Blocking everything
The aidspec directory has a complete Rust core (33 tests), CLI, registry, protocol spec, and NIST submission — but zero git commits. One accidental delete loses everything.
**Action:** `git init` + initial commit immediately.

### Gap 2: No GitHub repos created (404)
**Status:** No public presence
`techblaze-au/idprova` returns 404. No way for community or NIST reviewers to access the code.
**Action:** Create GitHub org repo, push initial commit, set up branch protection.

### Gap 3: idprova.dev not deployed
**Status:** Docs site built but not live
18/28 documentation pages are complete in the Astro/Starlight site, but the domain isn't serving content.
**Action:** Deploy to Vercel/Netlify, configure DNS for idprova.dev.

---

## HIGH Priority — Weeks 2-4

### Gap 4: SDKs are placeholder only
PyO3/napi-rs bindings not implemented. Only empty scaffolding exists at `sdks/python/` and `sdks/typescript/`.
**Action:** Implement PyO3 bindings (Python) weeks 2-3, napi-rs bindings (TypeScript) month 2.

### Gap 5: No SPIFFE/OAuth bridge
Industry converging on SPIFFE for workload identity. No bridge from SPIFFE SVID to IDprova AID.
**Action:** Design one-way SPIFFE bridge with explicit mapping config. Implement month 3.

### Gap 6: No agent discovery mechanism
A2A has AgentCard, AGNTCY has DID resolution. IDprova has no equivalent.
**Action:** Implement DID resolution endpoint in registry + `.well-known/did.json` discovery.

### Gap 7: No DAT revocation system
No CRL, OCSP, or short-lived token rotation. Compromised DATs remain valid until expiry.
**Action:** Implement short-lived tokens (default 1hr) + optional revocation list in registry.

### Gap 8: No key lifecycle management
Key rotation, escrow, and recovery are undefined. Single key compromise = full agent compromise.
**Action:** Define key rotation protocol, implement in CLI and SDKs.

### Gap 9: No multi-hop delegation verification
User→Agent→Sub-agent chain validation not implemented.
**Action:** Implement chain validation with strict scope subset inheritance (SR-3).

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

## Strategic Timeline

| Timeframe | Deliverables |
|-----------|-------------|
| **This week** | Git init + initial commit, create GitHub repos, deploy idprova.dev |
| **Weeks 2-4** | Python SDK (PyO3), populate test vectors, CLI `aid resolve` |
| **Month 2** | TypeScript SDK (napi-rs), MCP middleware, A2A binding |
| **Month 3** | SPIFFE bridge, revocation system, key lifecycle, NCCoE response (April 2 deadline) |
| **Month 4-6** | Enterprise features, Go SDK, managed registry pilot |

---

## Related Documents

- **PRD:** [Notion](https://www.notion.so/3174683942b08133b437e507e915c63e)
- **TRD:** `aidspec/docs/TRD.md`
- **STRIDE Threat Model:** `aidspec/docs/STRIDE-THREAT-MODEL.md`
- **Protocol Spec:** `aidspec/docs/protocol-spec-v0.1.md`
