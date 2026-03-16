# IDProva Protocol Specification

**Version:** 0.1.0-draft
**Date:** 2026-02-24
**Authors:** Tech Blaze Consulting Pty Ltd
**License:** Apache 2.0
**Specification URI:** https://idprova.dev/spec/v0.1

---

## Abstract

IDProva (AI Agent Identity Specification) is an open protocol for establishing verifiable identity, scoped delegation, and auditable action tracking for autonomous AI agents. Built on the W3C Decentralized Identifier (DID) standard, IDProva introduces the `did:aid:` method alongside a Delegation Attestation Token (DAT) format and hash-chained Action Receipts. The protocol employs a hybrid cryptographic scheme combining Ed25519 with ML-DSA-65 (FIPS 204) to provide both classical and post-quantum security from day one. IDProva is designed to integrate with existing agent communication protocols including the Model Context Protocol (MCP) and Agent-to-Agent (A2A) protocol, enabling any AI agent — regardless of vendor, runtime, or deployment model — to prove its identity, demonstrate its authority, and produce tamper-evident audit trails of its actions.

---

## Status of This Document

This document is a **Draft Specification (v0.1)** published by Tech Blaze Consulting Pty Ltd. It is intended for early review and implementation feedback. This specification is not yet stable; breaking changes may occur in subsequent versions prior to v1.0.

This work is licensed under the Apache License, Version 2.0. You may obtain a copy of the license at: http://www.apache.org/licenses/LICENSE-2.0

Feedback and contributions are welcome via the IDProva GitHub repository at https://github.com/techblaze-au/idprova.

### Document Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 1. Introduction

### 1.1 Problem Statement

The proliferation of autonomous AI agents presents an unprecedented identity crisis in computing. Industry projections estimate that by 2028, over 500 million AI agents will be operating across enterprise and consumer environments — scheduling meetings, executing code, managing infrastructure, processing financial transactions, and communicating with each other on behalf of humans and organisations.

Today, these agents lack any standardised mechanism to:

- **Prove who they are** to other agents, services, or humans.
- **Demonstrate what they are authorised to do** with cryptographic proof rather than implicit trust.
- **Produce tamper-evident records** of what they have done that satisfy regulatory and compliance requirements.

Current approaches are fragmented and insufficient:

| Approach | Limitation |
|----------|-----------|
| API keys / bearer tokens | No identity semantics; shared secrets; no delegation hierarchy |
| OAuth 2.0 client credentials | Designed for applications, not autonomous agents; no agent metadata |
| SPIFFE/SPIRE | Workload identity only; no delegation model; no agent-specific semantics |
| Custom per-vendor solutions | Vendor lock-in; no interoperability; no audit standard |

Without a universal identity layer, the agent ecosystem faces systemic risks: agents impersonating other agents, uncontrolled privilege escalation through opaque delegation chains, regulatory non-compliance due to absent audit trails, and an inability to establish trust across organisational boundaries.

IDProva addresses this gap by providing a protocol that is:

- **Standards-based:** Built on W3C DIDs, JWS (RFC 7515), and established cryptographic primitives.
- **Agent-native:** Designed specifically for the semantics of AI agent systems.
- **Post-quantum ready:** Hybrid classical/PQC cryptography from the initial version.
- **Interoperable:** Binding specifications for MCP, A2A, and HTTP transport.
- **Audit-complete:** Hash-chained action receipts that map to ISM, SOC 2, and NIST 800-53 controls.

### 1.2 Design Goals

The IDProva protocol is guided by the following design principles, listed in priority order:

1. **Security First:** All identity claims and delegations MUST be cryptographically verifiable. The protocol assumes a hostile network environment.

2. **Post-Quantum from Day One:** The hybrid signature scheme ensures that identities created today remain secure against future quantum computing threats, without sacrificing current performance.

3. **Progressive Trust:** Agents start at the lowest trust level (L0) and progressively prove trustworthiness through verifiable mechanisms. No agent is implicitly trusted.

4. **Minimal Disclosure:** Agents SHOULD disclose only the minimum information necessary for a given interaction. The protocol supports selective disclosure of capabilities and metadata.

5. **Decentralised by Default:** The protocol does not require a central authority. Self-hosted registries are first-class citizens alongside managed services.

6. **Protocol Composability:** IDProva layers on top of existing protocols (MCP, A2A, HTTP) rather than replacing them. It provides identity and delegation; the underlying protocol provides transport and semantics.

7. **Regulatory Alignment:** The audit trail format is designed to satisfy common compliance frameworks (ISM, SOC 2, NIST 800-53) out of the box.

8. **Developer Experience:** The protocol should be implementable by a single developer in a weekend for basic functionality, with clear upgrade paths to full compliance.

### 1.3 Terminology

| Term | Definition |
|------|-----------|
| **Agent** | An autonomous or semi-autonomous software entity that acts on behalf of a principal (human, organisation, or another agent). |
| **Principal** | The entity (human or organisation) that ultimately bears responsibility for an agent's actions. |
| **AID** | Agent Identity Document — a DID Document conforming to the IDProva profile. |
| **DAT** | Delegation Attestation Token — a signed token granting scoped authority from one DID to another. |
| **Action Receipt** | A signed, hash-chained record of an action performed by an agent. |
| **Trust Level** | A classification (L0–L4) indicating the degree of identity verification an agent has undergone. |
| **Scope** | A structured permission string defining what actions a delegated agent may perform. |
| **Config Attestation** | A cryptographic hash of an agent's configuration at a point in time, used to detect configuration drift. |
| **Delegation Chain** | An ordered sequence of DATs establishing a path of authority from a root principal to a leaf agent. |
| **Registry** | A service that stores and resolves IDProva DID Documents. |
| **Verifier** | Any party that validates an agent's identity, delegation, or action receipt. |
| **Resolver** | A component that retrieves and validates a DID Document given a DID URI. |

### 1.4 Relationship to Existing Standards

IDProva builds upon and integrates with several existing standards:

**W3C Decentralized Identifiers (DIDs) v1.0** — IDProva defines a new DID method (`did:aid:`) conforming to the W3C DID Core specification. AID Documents are valid DID Documents with additional agent-specific service extensions.

**W3C Verifiable Credentials Data Model v2.0** — Future versions of IDProva may express trust level attestations as Verifiable Credentials. The current version uses a simpler inline model.

**JSON Web Signature (JWS) — RFC 7515** — Delegation Attestation Tokens use JWS Compact Serialization as their wire format.

**JSON Web Token (JWT) — RFC 7519** — DAT payloads follow JWT claim conventions for interoperability with existing token validation infrastructure.

**JSON Web Key (JWK) — RFC 7517** — Key material in IDProva can be represented as JWK for interoperability, though the canonical format uses Multibase encoding.

**OAuth 2.0 — RFC 6749** — IDProva is not an OAuth profile, but its delegation model is informed by OAuth's scope and token patterns. IDProva DATs can be used alongside OAuth tokens in hybrid deployments.

**SPIFFE (Secure Production Identity Framework for Everyone)** — IDProva's DID format is inspired by SPIFFE IDs. Where SPIFFE provides workload identity, IDProva extends this concept to AI agent identity with delegation and audit semantics.

**Model Context Protocol (MCP)** — Section 8.1 defines how IDProva identities authenticate within MCP tool calls and resource access.

**Agent-to-Agent Protocol (A2A)** — Section 8.2 defines how IDProva identities authenticate in A2A agent communication.

**FIPS 204 (ML-DSA)** — IDProva's post-quantum signature component uses ML-DSA-65 as standardised in FIPS 204.

---

## 2. Protocol Overview

### 2.1 Architecture

IDProva is built on three pillars:

```
┌─────────────────────────────────────────────────────────┐
│                    IDProva Protocol                      │
├───────────────────┬──────────────────┬──────────────────┤
│    IDENTITY       │   DELEGATION     │     AUDIT        │
│                   │                  │                  │
│  DID Documents    │  Attestation     │  Action          │
│  (did:aid:)     │  Tokens (DAT)    │  Receipts        │
│                   │                  │                  │
│  - Key pairs      │  - Scoped perms  │  - Hash chains   │
│  - Agent metadata │  - Constraints   │  - Signatures    │
│  - Trust levels   │  - Chains        │  - Compliance    │
│  - Capabilities   │  - Revocation    │    mapping       │
├───────────────────┴──────────────────┴──────────────────┤
│               Cryptographic Foundation                   │
│         Ed25519 + ML-DSA-65 | BLAKE3 / SHA-256          │
├─────────────────────────────────────────────────────────┤
│                  Protocol Bindings                       │
│              MCP  |  A2A  |  HTTP                        │
└─────────────────────────────────────────────────────────┘
```

**Identity (Pillar 1):** Every agent is identified by a `did:aid:` DID with an associated DID Document containing public keys, agent metadata, and capability declarations. The DID Document is the root of trust for an agent.

**Delegation (Pillar 2):** Authority flows from principals to agents (and from agents to sub-agents) via Delegation Attestation Tokens. DATs are signed, scoped, time-bounded, and chain-able. A verifier can trace any delegation back to its root principal.

**Audit (Pillar 3):** Every significant action performed by an agent produces a signed Action Receipt. Receipts are hash-chained to form a tamper-evident log. Each receipt references the DAT that authorised the action, creating a complete audit trail from principal authority to agent action.

### 2.2 Trust Model

IDProva employs a **progressive trust** model. Agents are not trusted by default; they earn trust through verifiable mechanisms:

```
L0 (Unverified)  ──→  L1 (Domain-verified)  ──→  L2 (Org-verified)
                                                        │
                                                        ▼
                       L4 (Continuously monitored)  ←──  L3 (Third-party attested)
```

**Trust is directional.** Agent A may trust Agent B at L2 while Agent B trusts Agent A at only L1. Trust levels inform policy decisions but do not mandate them — a verifier MAY accept interactions from L0 agents if its policy permits.

**Trust is contextual.** An agent's trust level may vary by scope. An agent may be L3 for `mcp:tool:filesystem:read` but L1 for `mcp:tool:filesystem:write`.

**Trust is temporal.** Trust levels can be elevated or reduced based on ongoing behaviour, attestation expiry, or revocation events.

### 2.3 Cryptographic Agility

IDProva is designed for cryptographic agility while maintaining a strong default:

**REQUIRED algorithms (MUST be supported by all implementations):**
- Ed25519 (RFC 8032) for classical signatures
- ML-DSA-65 (FIPS 204) for post-quantum signatures
- BLAKE3 for content hashing
- SHA-256 for interoperability hashing

**OPTIONAL algorithms (MAY be supported):**
- Ed448 for higher-security classical signatures
- ML-DSA-87 for higher-security post-quantum signatures
- BLAKE2b-256 as an alternative hash

**Algorithm Negotiation:** When two agents interact, they MUST use the highest-security overlapping algorithm set. If both support ML-DSA-87, they SHOULD prefer it over ML-DSA-65. Algorithm negotiation details are specified in the protocol binding sections (Section 8).

**Deprecation Process:** Algorithms are deprecated through a three-phase process:
1. **Advisory:** Algorithm is flagged as weakening; implementations SHOULD begin migration.
2. **Warning:** Verifiers SHOULD reject the algorithm; a grace period is announced.
3. **Removal:** Algorithm is removed from the specification; implementations MUST NOT use it.

---

## 3. DID Method: `did:aid`

### 3.1 Method Syntax

The `did:aid:` method follows the W3C DID Core syntax:

```abnf
did-aid        = "did:aid:" method-specific-id
method-specific-id = authority ":" agent-name
authority        = domain / org-id
domain           = 1*( ALPHA / DIGIT / "." / "-" )
org-id           = 1*( ALPHA / DIGIT / "-" )
agent-name       = 1*( ALPHA / DIGIT / "-" / "_" )
```

**Examples:**

```
did:aid:example.com:kai-lead-agent
did:aid:example.com:pratyush
did:aid:techblaze.com.au:registry-agent
did:aid:localhost:dev-agent-01
did:aid:192-168-1-100:local-agent
```

**Authority Component:** The authority identifies the namespace owner. For domain-verified agents (L1+), this MUST be a domain name the controller can prove ownership of via DNS TXT records. For unverified agents (L0), any syntactically valid authority is accepted.

**Agent Name Component:** The agent name is a locally unique identifier within the authority namespace. Agent names MUST be lowercase and match the pattern `[a-z0-9][a-z0-9_-]*`. The maximum length of the full DID is 256 characters.

**Reserved Agent Names:** The following agent names are reserved and MUST NOT be used for regular agents:

| Name | Purpose |
|------|---------|
| `_registry` | Namespace registry agent |
| `_admin` | Administrative operations |
| `_root` | Root identity for the namespace |

### 3.2 DID Document Structure

An IDProva DID Document is a valid W3C DID Document with specific required and optional properties:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://idprova.dev/v1"
  ],
  "id": "did:aid:example.com:kai-lead-agent",
  "controller": "did:aid:example.com:pratyush",
  "created": "2026-02-24T00:00:00Z",
  "updated": "2026-02-24T00:00:00Z",
  "verificationMethod": [
    {
      "id": "did:aid:example.com:kai-lead-agent#key-ed25519-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aid:example.com:kai-lead-agent",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    },
    {
      "id": "did:aid:example.com:kai-lead-agent#key-mldsa65-1",
      "type": "MLDSA65VerificationKey2024",
      "controller": "did:aid:example.com:kai-lead-agent",
      "publicKeyMultibase": "z2Drjgb4TxNYuSiDBqd7pJAn5MfgF1YfNfsaHH3gZXQxqR7kW..."
    }
  ],
  "authentication": [
    "did:aid:example.com:kai-lead-agent#key-ed25519-1",
    "did:aid:example.com:kai-lead-agent#key-mldsa65-1"
  ],
  "assertionMethod": [
    "did:aid:example.com:kai-lead-agent#key-ed25519-1",
    "did:aid:example.com:kai-lead-agent#key-mldsa65-1"
  ],
  "capabilityDelegation": [
    "did:aid:example.com:kai-lead-agent#key-ed25519-1"
  ],
  "service": [
    {
      "id": "did:aid:example.com:kai-lead-agent#idprova-metadata",
      "type": "IDProvaAgentMetadata",
      "serviceEndpoint": {
        "name": "Kai Lead Agent",
        "description": "Primary orchestration agent for OpenClaw",
        "model": "acme-ai/agent-v2",
        "runtime": "openclaw/v2.1",
        "configAttestation": "blake3:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        "trustLevel": "L1",
        "capabilities": [
          "mcp:tool-call",
          "mcp:resource-read",
          "idprova:delegate"
        ],
        "maxDelegationDepth": 3
      }
    }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-24T00:00:00Z",
    "verificationMethod": "did:aid:example.com:pratyush#key-ed25519-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXQjecWg3dBGZBCY9KJTA..."
  }
}
```

**Required Properties:**

| Property | Description |
|----------|-----------|
| `@context` | MUST include the W3C DID v1 context and the IDProva v1 context. |
| `id` | The `did:aid:` DID for this agent. |
| `controller` | The DID of the entity that controls this agent. MAY be the same as `id` for self-sovereign agents. |
| `verificationMethod` | MUST contain at least one Ed25519 key. SHOULD contain at least one ML-DSA-65 key. |
| `authentication` | MUST reference at least one verification method. |

**Optional Properties:**

| Property | Description |
|----------|-----------|
| `created` | ISO 8601 timestamp of document creation. |
| `updated` | ISO 8601 timestamp of last update. |
| `assertionMethod` | Keys authorised to make assertions (sign receipts). |
| `capabilityDelegation` | Keys authorised to issue DATs. |
| `service` | Agent metadata and other service endpoints. |
| `proof` | Proof of document integrity by the controller. |

### 3.3 Agent Metadata Service Extension

The `IDProvaAgentMetadata` service type is an IDProva-specific extension that carries agent metadata within the DID Document.

```json
{
  "id": "#idprova-metadata",
  "type": "IDProvaAgentMetadata",
  "serviceEndpoint": {
    "name": "<string, REQUIRED>",
    "description": "<string, OPTIONAL>",
    "model": "<string, OPTIONAL>",
    "runtime": "<string, OPTIONAL>",
    "configAttestation": "<string, OPTIONAL>",
    "trustLevel": "<string, REQUIRED>",
    "capabilities": ["<string, ...>"],
    "maxDelegationDepth": "<integer, OPTIONAL>",
    "parentAgent": "<DID, OPTIONAL>",
    "organisationDID": "<DID, OPTIONAL>"
  }
}
```

**Field Definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name for the agent. Max 128 characters. |
| `description` | string | No | Human-readable description. Max 1024 characters. |
| `model` | string | No | AI model identifier in `vendor/model-name` format. |
| `runtime` | string | No | Runtime platform in `platform/version` format. |
| `configAttestation` | string | No | Hash of agent configuration: `algorithm:hex-digest`. |
| `trustLevel` | string | Yes | Current trust level: `L0`, `L1`, `L2`, `L3`, or `L4`. |
| `capabilities` | array | No | List of capability strings the agent declares. |
| `maxDelegationDepth` | integer | No | Maximum delegation chain depth this agent will accept. Default: 5. |
| `parentAgent` | DID | No | DID of the parent agent if this is a sub-agent. |
| `organisationDID` | DID | No | DID of the organisation this agent belongs to. |

**Config Attestation Format:**

The `configAttestation` field contains a hash of the agent's active configuration, enabling verifiers to detect configuration changes between interactions.

```
configAttestation = algorithm ":" hex-digest
algorithm         = "blake3" / "sha256"
hex-digest        = 64HEXDIG  ; for BLAKE3 (256-bit)
                  / 64HEXDIG  ; for SHA-256 (256-bit)
```

The input to the hash function is the canonical JSON serialization (RFC 8785 — JSON Canonicalization Scheme) of the agent's configuration object. The structure of this configuration object is runtime-specific but MUST be deterministic for a given agent configuration.

### 3.4 CRUD Operations

#### 3.4.1 Create

To create a new IDProva identity:

1. Generate an Ed25519 key pair.
2. Generate an ML-DSA-65 key pair (RECOMMENDED).
3. Construct the DID Document per Section 3.2.
4. If the agent has a controller different from itself, the controller MUST sign the document's `proof` field.
5. Register the DID Document with a registry (Section 9) or publish it at the DID's resolution endpoint.

**Self-sovereign creation (no external controller):**

```
Controller: did:aid:example.com:alice
Creates:    did:aid:example.com:alice (self)
Proof:      Signed by alice's own key
```

**Delegated creation (controller creates agent):**

```
Controller: did:aid:example.com:alice
Creates:    did:aid:example.com:alice-assistant
Proof:      Signed by alice's key (controller assertion)
```

#### 3.4.2 Read (Resolve)

DID Document resolution follows the process in Section 3.5.

#### 3.4.3 Update

To update an IDProva DID Document:

1. Retrieve the current DID Document.
2. Modify the desired fields.
3. Increment the `updated` timestamp.
4. The controller MUST sign a new `proof` over the updated document.
5. Submit the updated document to the registry.

**Key Rotation:** When rotating keys, the new key MUST be added to the document before the old key is removed. The update that adds the new key MUST be signed by the old key. This ensures continuity of control.

```
Step 1: Add new key (signed by old key)    → Document has [old-key, new-key]
Step 2: Remove old key (signed by new key) → Document has [new-key]
```

#### 3.4.4 Deactivate

To deactivate an IDProva DID:

1. Retrieve the current DID Document.
2. Remove all verification methods and service endpoints.
3. Add a `deactivated` property set to `true`.
4. Sign with the controller's key.
5. Submit to the registry.

A deactivated DID Document looks like:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://idprova.dev/v1"
  ],
  "id": "did:aid:example.com:retired-agent",
  "controller": "did:aid:example.com:alice",
  "deactivated": true,
  "updated": "2026-06-01T00:00:00Z"
}
```

Resolvers MUST check the `deactivated` flag. A deactivated DID MUST NOT be used for authentication, delegation, or signing.

### 3.5 Resolution

IDProva DID resolution follows a layered strategy:

**Resolution Order:**

1. **Local cache:** Check the local DID Document cache (respecting TTL).
2. **Well-known endpoint:** Attempt HTTPS resolution at `https://{authority}/.well-known/did/idprova/{agent-name}/did.json`.
3. **Registry lookup:** Query known registries for the DID.
4. **Universal resolver:** Fall back to a DID Universal Resolver if configured.

**Well-Known Endpoint Resolution:**

For `did:aid:example.com:kai-lead-agent`, the resolver makes an HTTPS GET request to:

```
https://example.com/.well-known/did/idprova/kai-lead-agent/did.json
```

The response MUST be a valid IDProva DID Document with `Content-Type: application/did+json`.

**Registry Resolution:**

For registry-based resolution, the resolver queries the registry API (Section 9.1):

```
GET /v1/identities/did:aid:example.com:kai-lead-agent
```

**Resolution Metadata:**

Resolvers MUST return resolution metadata alongside the DID Document:

```json
{
  "didDocument": { ... },
  "didResolutionMetadata": {
    "contentType": "application/did+json",
    "retrieved": "2026-02-24T12:00:00Z",
    "resolverVersion": "idprova-resolver/0.1.0"
  },
  "didDocumentMetadata": {
    "created": "2026-02-24T00:00:00Z",
    "updated": "2026-02-24T00:00:00Z",
    "deactivated": false,
    "versionId": "3",
    "nextUpdate": "2026-03-24T00:00:00Z"
  }
}
```

---

## 4. Cryptography

### 4.1 Hybrid Signature Scheme (Ed25519 + ML-DSA-65)

IDProva employs a **hybrid signature scheme** combining a classical algorithm (Ed25519) with a post-quantum algorithm (ML-DSA-65). This ensures security against both classical and quantum adversaries.

**Rationale:** NIST has standardised ML-DSA (formerly CRYSTALS-Dilithium) in FIPS 204. While ML-DSA is believed to be quantum-resistant, it has less cryptanalytic history than Ed25519. The hybrid approach provides defense in depth: an attacker must break *both* algorithms to forge a signature.

#### 4.1.1 Hybrid Signature Generation

Given a message `M` and key pairs `(sk_ed, pk_ed)` for Ed25519 and `(sk_ml, pk_ml)` for ML-DSA-65:

```
HybridSign(M, sk_ed, sk_ml):
  1. sig_ed  = Ed25519_Sign(sk_ed, M)
  2. sig_ml  = MLDSA65_Sign(sk_ml, M)
  3. sig_hybrid = CBOR_Encode({
       "ed25519": sig_ed,      // 64 bytes
       "mldsa65": sig_ml,      // 3309 bytes (ML-DSA-65 signature)
       "version": 1
     })
  4. return sig_hybrid
```

#### 4.1.2 Hybrid Signature Verification

```
HybridVerify(M, sig_hybrid, pk_ed, pk_ml):
  1. components = CBOR_Decode(sig_hybrid)
  2. valid_ed = Ed25519_Verify(pk_ed, M, components.ed25519)
  3. valid_ml = MLDSA65_Verify(pk_ml, M, components.mldsa65)
  4. return valid_ed AND valid_ml
```

**Both signatures MUST be valid for the hybrid verification to succeed.** A verifier MUST NOT accept a message where only one component is valid.

#### 4.1.3 Classical-Only Mode

For environments where post-quantum cryptography is not yet available or performance constraints are critical, implementations MAY operate in **classical-only mode** using Ed25519 signatures only. In this mode:

- The DID Document SHOULD still include an ML-DSA-65 key if available.
- Signatures use standard Ed25519 (64 bytes).
- The verifier MUST note the reduced security level in its trust assessment.
- Implementations operating in classical-only mode MUST NOT claim trust levels above L2.

#### 4.1.4 Signature Sizes

| Algorithm | Public Key | Signature | Security Level |
|-----------|-----------|-----------|---------------|
| Ed25519 | 32 bytes | 64 bytes | ~128-bit classical |
| ML-DSA-65 | 1952 bytes | 3309 bytes | NIST Level 3 (quantum) |
| Hybrid | 1984 bytes | ~3400 bytes (CBOR) | 128-bit classical + NIST Level 3 quantum |

### 4.2 Hashing (BLAKE3 / SHA-256)

**BLAKE3** is the primary hash function for IDProva:

- Action Receipt hash chains use BLAKE3.
- Config attestation hashes use BLAKE3 by default.
- Content-addressed storage uses BLAKE3.

**SHA-256** is the interoperability hash function:

- Systems that cannot support BLAKE3 MAY use SHA-256.
- When communicating hash values to external systems (e.g., blockchain anchors), SHA-256 SHOULD be used.

**Hash Representation:**

Hashes are represented as `algorithm:hex-digest`:

```
blake3:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890
sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 4.3 Key Encoding (Multibase)

All public keys in IDProva DID Documents are encoded using Multibase (base58btc) as specified in the W3C Data Integrity specification.

**Format:** `z` prefix (indicating base58btc) followed by the multicodec-prefixed public key bytes.

**Multicodec Prefixes:**

| Algorithm | Multicodec | Prefix Bytes |
|-----------|-----------|-------------|
| Ed25519 public key | `0xed` | `0xed 0x01` |
| ML-DSA-65 public key | `0x0d65` | `0x0d 0x65` |

**Example (Ed25519):**

```
Raw public key:    [32 bytes]
With multicodec:   0xed 0x01 [32 bytes] = [34 bytes]
Base58btc encoded: z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

**Example (ML-DSA-65):**

```
Raw public key:    [1952 bytes]
With multicodec:   0x0d 0x65 [1952 bytes] = [1954 bytes]
Base58btc encoded: z2Drjgb4TxNYuSiDBqd7pJAn5MfgF1YfNfsaHH3gZXQxqR7kW...
```

### 4.4 Key Management

#### 4.4.1 Key Generation

Implementations MUST generate keys using a cryptographically secure random number generator (CSPRNG) conforming to the requirements of the underlying algorithm specification.

- **Ed25519:** Keys MUST be generated per RFC 8032, Section 5.1.5.
- **ML-DSA-65:** Keys MUST be generated per FIPS 204, Section 6.

#### 4.4.2 Key Storage

Private keys MUST be stored securely. Recommended approaches, in order of preference:

1. **Hardware Security Module (HSM):** FIPS 140-2 Level 2+ certified.
2. **Trusted Platform Module (TPM):** For device-bound agents.
3. **Operating System Keychain:** macOS Keychain, Windows DPAPI, Linux Secret Service.
4. **Encrypted File:** AES-256-GCM encrypted file with key derived from a strong passphrase via Argon2id.

Private keys MUST NOT be:
- Stored in plain text.
- Included in DID Documents.
- Transmitted over the network in any form.
- Logged or included in error messages.

#### 4.4.3 Key Rotation

Key rotation is performed via DID Document updates (Section 3.4.3). Implementations SHOULD rotate keys:

- At least every 90 days for Ed25519 keys.
- At least every 180 days for ML-DSA-65 keys.
- Immediately upon suspected compromise.

During rotation, both old and new keys coexist in the DID Document. DATs issued by the old key remain valid until their expiry. New DATs MUST be signed by the new key.

#### 4.4.4 Key Revocation

Individual keys can be revoked by removing them from the DID Document via an update operation. Verifiers MUST re-resolve the DID Document when validating signatures to check for key revocation.

Implementations SHOULD cache DID Documents with a maximum TTL of 5 minutes to balance performance and revocation responsiveness.

### 4.5 Post-Quantum Migration Roadmap

IDProva anticipates a phased migration as post-quantum cryptography matures:

| Phase | Timeline | Action |
|-------|----------|--------|
| Phase 0 (Current) | 2026 | Hybrid Ed25519 + ML-DSA-65; classical-only fallback permitted |
| Phase 1 | 2027 | Classical-only mode deprecated (advisory); all new identities MUST include PQC keys |
| Phase 2 | 2028 | Classical-only mode deprecated (warning); verifiers SHOULD reject classical-only signatures |
| Phase 3 | 2029+ | Evaluate ML-DSA-87 as the default PQC algorithm; assess need for hybrid ML-KEM for key exchange |

---

## 5. Delegation Attestation Token (DAT)

### 5.1 Token Format (JWS)

A Delegation Attestation Token is a JSON Web Signature (JWS) in Compact Serialization format (RFC 7515, Section 3.1):

```
BASE64URL(Header) "." BASE64URL(Payload) "." BASE64URL(Signature)
```

For hybrid signatures, an additional JWS Unprotected Header carries the ML-DSA-65 signature. See Section 5.1.2.

#### 5.1.1 Header

```json
{
  "alg": "EdDSA",
  "typ": "idprova-dat+jwt",
  "kid": "did:aid:example.com:pratyush#key-ed25519-1",
  "pqalg": "MLDSA65",
  "pqkid": "did:aid:example.com:pratyush#key-mldsa65-1"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `alg` | Yes | MUST be `EdDSA` for Ed25519 signatures. |
| `typ` | Yes | MUST be `idprova-dat+jwt`. |
| `kid` | Yes | DID URL of the signing key (Ed25519). |
| `pqalg` | No | Post-quantum algorithm. MUST be `MLDSA65` when present. |
| `pqkid` | No | DID URL of the post-quantum signing key. |

#### 5.1.2 Hybrid Signature in JWS

When using hybrid signatures, the JWS Compact Serialization carries the Ed25519 signature in the standard signature position. The ML-DSA-65 signature is carried as a detached payload in a custom `pqsig` field appended after the third segment:

```
BASE64URL(Header) "." BASE64URL(Payload) "." BASE64URL(Ed25519Sig) "." BASE64URL(MLDSA65Sig)
```

This four-segment format is an IDProva extension to JWS Compact Serialization. Implementations that do not support ML-DSA-65 MAY validate only the first three segments as standard JWS, but MUST note the reduced assurance level.

### 5.2 Claims

The DAT payload contains the following claims:

```json
{
  "iss": "did:aid:example.com:pratyush",
  "sub": "did:aid:example.com:kai-lead-agent",
  "aud": "did:aid:example.com:target-service",
  "iat": 1708732800,
  "exp": 1708819200,
  "nbf": 1708732800,
  "jti": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
  "scope": [
    "mcp:tool:filesystem:read",
    "mcp:tool:filesystem:write",
    "mcp:resource:context:read",
    "idprova:agent:create"
  ],
  "constraints": {
    "maxCallsPerHour": 1000,
    "allowedIPs": ["10.0.0.0/8", "172.16.0.0/12"],
    "requiredTrustLevel": "L1",
    "maxDelegationDepth": 2,
    "geofence": ["AU", "NZ"]
  },
  "configAttestation": "blake3:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "delegationChain": [
    "dat_01HQ3M7JRAB6WF1CNKTS4E5D8S"
  ]
}
```

**Claim Definitions:**

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | DID string | Yes | The DID of the entity issuing (delegating) the token. |
| `sub` | DID string | Yes | The DID of the entity receiving the delegation. |
| `aud` | DID string | No | The intended recipient/verifier of the token. When present, the verifier MUST check that its own DID matches. |
| `iat` | NumericDate | Yes | Issued-at timestamp (seconds since Unix epoch). |
| `exp` | NumericDate | Yes | Expiration timestamp. MUST be greater than `iat`. Maximum lifetime: 86400 seconds (24 hours) for L0-L1 agents; 604800 seconds (7 days) for L2+ agents. |
| `nbf` | NumericDate | No | Not-before timestamp. If present, verifiers MUST reject the token before this time. |
| `jti` | string | Yes | Unique token identifier. MUST be globally unique. RECOMMENDED format: `dat_` prefix followed by a ULID or UUIDv7. |
| `scope` | array | Yes | Array of scope strings defining permitted actions. See Section 5.3. |
| `constraints` | object | No | Additional constraints on the delegation. See Section 5.4. |
| `configAttestation` | string | No | Expected config attestation hash of the subject agent. If present and the agent's current config attestation does not match, the verifier SHOULD reject the token. |
| `delegationChain` | array | No | Ordered array of `jti` values forming the delegation chain from the root principal. See Section 5.5. |

### 5.3 Scope Grammar

Scopes define what actions a delegated agent is permitted to perform. The scope grammar follows a hierarchical namespace model:

#### 5.3.1 Formal Grammar

```abnf
scope           = namespace ":" resource ":" action
namespace       = segment
resource        = segment *( ":" segment )
action          = segment / wildcard
segment         = 1*( ALPHA / DIGIT / "-" / "_" )
wildcard        = "*"

; Examples:
; mcp:tool:filesystem:read
; mcp:tool:filesystem:*
; mcp:resource:context:read
; idprova:agent:create
; idprova:delegation:issue
; a2a:task:execute
; custom:my-service:invoke
```

#### 5.3.2 Standard Namespaces

| Namespace | Description |
|-----------|-----------|
| `mcp` | Model Context Protocol operations |
| `idprova` | IDProva protocol operations |
| `a2a` | Agent-to-Agent protocol operations |
| `http` | HTTP endpoint access |
| `custom` | User-defined operations |

#### 5.3.3 Standard MCP Scopes

| Scope | Description |
|-------|-----------|
| `mcp:tool:*:*` | All tool operations |
| `mcp:tool:{name}:call` | Call a specific tool |
| `mcp:tool:{name}:read` | Read tool metadata |
| `mcp:resource:*:*` | All resource operations |
| `mcp:resource:{name}:read` | Read a specific resource |
| `mcp:resource:{name}:write` | Write a specific resource |
| `mcp:prompt:*:*` | All prompt operations |
| `mcp:prompt:{name}:use` | Use a specific prompt |

#### 5.3.4 Standard IDProva Scopes

| Scope | Description |
|-------|-----------|
| `idprova:agent:create` | Create new agent identities |
| `idprova:agent:update` | Update agent identity documents |
| `idprova:agent:deactivate` | Deactivate agent identities |
| `idprova:delegation:issue` | Issue new DATs |
| `idprova:delegation:revoke` | Revoke existing DATs |
| `idprova:receipt:create` | Create action receipts |
| `idprova:receipt:read` | Read action receipts |

#### 5.3.5 Wildcard Rules

- `*` as the action component matches any action: `mcp:tool:filesystem:*` grants read, write, delete, etc.
- `*` as a resource segment matches any resource: `mcp:tool:*:read` grants read on all tools.
- A scope of `*:*:*` grants all permissions. This MUST only be issued by L3+ principals and SHOULD be avoided.

#### 5.3.6 Scope Reduction Rule

When re-delegating (agent A delegates to agent B, who delegates to agent C), the child DAT's scopes MUST be a subset of or equal to the parent DAT's scopes. A delegatee MUST NOT escalate privileges.

**Formal rule:** For every scope `s` in the child DAT, there MUST exist a scope `p` in the parent DAT such that `p` covers `s`. Scope `p` covers scope `s` if:

1. `p` equals `s`, OR
2. `p` has a wildcard that matches the corresponding segment in `s`.

```
Parent scope: mcp:tool:filesystem:*
Child scope:  mcp:tool:filesystem:read   → VALID (covered by wildcard)
Child scope:  mcp:tool:database:read     → INVALID (different resource)
```

### 5.4 Constraints

The `constraints` object in a DAT provides additional restrictions beyond scopes:

```json
{
  "constraints": {
    "maxCallsPerHour": 1000,
    "maxCallsPerDay": 10000,
    "maxConcurrent": 5,
    "allowedIPs": ["10.0.0.0/8"],
    "deniedIPs": ["10.0.0.1/32"],
    "requiredTrustLevel": "L1",
    "maxDelegationDepth": 2,
    "geofence": ["AU", "NZ", "US"],
    "timeWindows": [
      {
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "startUTC": "00:00",
        "endUTC": "23:59"
      }
    ],
    "requiredConfigAttestation": true,
    "customConstraints": {
      "maxTokensPerRequest": 4096,
      "allowedModels": ["acme-ai/agent-v1", "acme-ai/agent-v2"]
    }
  }
}
```

**Standard Constraint Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `maxCallsPerHour` | integer | Maximum actions per clock hour. |
| `maxCallsPerDay` | integer | Maximum actions per calendar day (UTC). |
| `maxConcurrent` | integer | Maximum concurrent active operations. |
| `allowedIPs` | string[] | CIDR ranges from which the agent may operate. |
| `deniedIPs` | string[] | CIDR ranges explicitly blocked. Takes precedence over `allowedIPs`. |
| `requiredTrustLevel` | string | Minimum trust level the subject must maintain. |
| `maxDelegationDepth` | integer | Maximum further delegation depth allowed. 0 = no re-delegation. |
| `geofence` | string[] | ISO 3166-1 alpha-2 country codes where the agent may operate. |
| `timeWindows` | object[] | Time windows during which the delegation is active. |
| `requiredConfigAttestation` | boolean | If true, verifiers MUST check config attestation matches. |
| `customConstraints` | object | Implementation-specific constraints. |

**Constraint Inheritance:** When re-delegating, child constraints MUST be equal to or more restrictive than parent constraints. Specifically:

- Numeric limits: child value <= parent value.
- IP ranges: child set must be a subset of parent set.
- Trust level: child level >= parent level.
- Delegation depth: child depth < parent depth.
- Geofence: child set must be a subset of parent set.
- Time windows: child windows must be contained within parent windows.

### 5.5 Delegation Chains

Delegation chains trace the path of authority from a root principal to a leaf agent.

```
Root Principal (Human)
  └── DAT_1: delegates to Agent A
        └── DAT_2: Agent A delegates to Agent B
              └── DAT_3: Agent B delegates to Agent C
```

The `delegationChain` array in DAT_3 would be: `["dat_1_jti", "dat_2_jti"]`.

**Chain Validation Algorithm:**

```
ValidateChain(dat, resolver):
  1. current = dat
  2. chain = [current]
  3. while current.delegationChain is not empty:
       a. parent_jti = current.delegationChain[last]
       b. parent_dat = resolver.resolveDAT(parent_jti)
       c. if parent_dat is null: return INVALID("broken chain")
       d. if parent_dat.sub != current.iss: return INVALID("chain mismatch")
       e. if parent_dat.exp < now(): return INVALID("parent expired")
       f. if not ValidateScopes(current.scope, parent_dat.scope):
            return INVALID("scope escalation")
       g. if not ValidateConstraints(current.constraints, parent_dat.constraints):
            return INVALID("constraint escalation")
       h. chain.prepend(parent_dat)
       i. current = parent_dat
  4. root = chain[0]
  5. root_did = resolver.resolveDID(root.iss)
  6. if root_did is null: return INVALID("unknown root")
  7. if root_did.deactivated: return INVALID("deactivated root")
  8. return VALID(chain)
```

**Maximum Chain Depth:** The default maximum chain depth is 5. This can be restricted via the `maxDelegationDepth` constraint. Implementations MUST reject chains exceeding the maximum depth.

### 5.6 Revocation

DATs can be revoked before their expiry through two mechanisms:

#### 5.6.1 Revocation List

The issuer publishes a revocation list at their DID's service endpoint:

```json
{
  "id": "#idprova-revocation",
  "type": "IDProvaRevocationList",
  "serviceEndpoint": "https://example.com/.well-known/idprova/revocations.json"
}
```

The revocation list format:

```json
{
  "issuer": "did:aid:example.com:pratyush",
  "updated": "2026-02-24T12:00:00Z",
  "revocations": [
    {
      "jti": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
      "revokedAt": "2026-02-24T11:30:00Z",
      "reason": "key-compromise"
    }
  ]
}
```

**Revocation Reasons:**

| Reason | Description |
|--------|-----------|
| `key-compromise` | The signing key has been compromised. |
| `privilege-change` | The agent's permissions have changed. |
| `agent-deactivated` | The subject agent has been deactivated. |
| `policy-violation` | The agent violated its delegation policy. |
| `superseded` | A new DAT has replaced this one. |
| `unspecified` | No specific reason given. |

#### 5.6.2 Inline Revocation Check

For real-time revocation, verifiers MAY query the issuer's registry directly:

```
GET /v1/delegations/{jti}/status
```

Response:

```json
{
  "jti": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
  "active": false,
  "revokedAt": "2026-02-24T11:30:00Z",
  "reason": "privilege-change"
}
```

**Revocation Propagation:** When a parent DAT in a chain is revoked, all child DATs in that chain are implicitly revoked. Verifiers MUST check the validity of the entire chain, not just the leaf DAT.

---

## 6. Action Receipts

### 6.1 Receipt Structure

An Action Receipt is a signed record of an action performed by an agent. Receipts form a tamper-evident, hash-chained log.

```json
{
  "id": "rcpt_01HQ3P9LYCD8ZH3ENQWT6G7F0U",
  "version": "0.1.0",
  "timestamp": "2026-02-24T12:30:00.000Z",
  "agent": "did:aid:example.com:kai-lead-agent",
  "delegation": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
  "action": {
    "type": "mcp:tool:filesystem:read",
    "target": "/projects/idprova/README.md",
    "method": "readFile",
    "parameters": {
      "path": "/projects/idprova/README.md",
      "encoding": "utf-8"
    },
    "result": {
      "status": "success",
      "bytesRead": 4096,
      "contentHash": "blake3:f8c3..."
    }
  },
  "context": {
    "sessionId": "sess_01HQ3P2KABC...",
    "parentReceiptId": "rcpt_01HQ3P8KXBC...",
    "traceId": "trace_01HQ3P1JABC...",
    "environment": "production",
    "runtimeVersion": "openclaw/v2.1"
  },
  "chain": {
    "previousHash": "blake3:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
    "sequenceNumber": 42
  },
  "signature": {
    "algorithm": "hybrid-ed25519-mldsa65",
    "keyId": "did:aid:example.com:kai-lead-agent#key-ed25519-1",
    "value": "z4sK7qN2vR8wX1yT5uP3mJ6nB9cF0dA..."
  }
}
```

**Field Definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique receipt identifier. Format: `rcpt_` + ULID. |
| `version` | string | Yes | IDProva protocol version. |
| `timestamp` | ISO 8601 | Yes | When the action was performed. MUST include milliseconds. |
| `agent` | DID | Yes | DID of the agent that performed the action. |
| `delegation` | string | Yes | `jti` of the DAT that authorised this action. |
| `action` | object | Yes | Details of the action performed. See below. |
| `context` | object | No | Contextual information about the action. |
| `chain` | object | Yes | Hash chain linkage. |
| `signature` | object | Yes | Cryptographic signature over the receipt. |

**Action Object:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Scope string of the action (same grammar as DAT scopes). |
| `target` | string | Yes | The resource acted upon. |
| `method` | string | No | The specific method/function called. |
| `parameters` | object | No | Input parameters (sensitive values SHOULD be redacted). |
| `result` | object | Yes | Outcome of the action. |
| `result.status` | string | Yes | `success`, `failure`, or `error`. |

### 6.2 Hash Chain

Action Receipts form a hash chain for tamper detection. Each receipt includes the hash of the previous receipt and a monotonically increasing sequence number.

**Hash Chain Construction:**

```
Receipt[0]:
  chain.previousHash = blake3("GENESIS:" + agent_did)
  chain.sequenceNumber = 0

Receipt[n]:
  chain.previousHash = BLAKE3(CanonicalJSON(Receipt[n-1]))
  chain.sequenceNumber = n
```

**Canonical Serialization for Hashing:**

The input to the hash function is the receipt serialized using JSON Canonicalization Scheme (JCS, RFC 8785), with the `signature` field removed (since the signature is computed over the same content and would create a circular dependency).

```
HashInput(receipt):
  1. receipt_copy = DeepCopy(receipt)
  2. delete receipt_copy.signature
  3. canonical = JCS_Serialize(receipt_copy)
  4. return BLAKE3(canonical)
```

**Genesis Receipt:**

The first receipt in a chain uses a deterministic genesis hash:

```
genesisHash = BLAKE3("GENESIS:" + agent_did)
```

This allows verifiers to identify the start of a chain without requiring out-of-band information.

### 6.3 Integrity Verification

To verify the integrity of an action receipt chain:

```
VerifyChain(receipts[]):
  1. Sort receipts by sequenceNumber ascending
  2. if receipts[0].chain.sequenceNumber != 0:
       return INVALID("chain does not start at genesis")
  3. expected_prev = BLAKE3("GENESIS:" + receipts[0].agent)
  4. for each receipt in receipts:
       a. if receipt.chain.previousHash != expected_prev:
            return INVALID("hash chain break at seq " + receipt.chain.sequenceNumber)
       b. if receipt.chain.sequenceNumber != expected_seq:
            return INVALID("sequence gap at " + expected_seq)
       c. agent_did = resolver.resolveDID(receipt.agent)
       d. if not VerifySignature(receipt, agent_did):
            return INVALID("invalid signature at seq " + receipt.chain.sequenceNumber)
       e. expected_prev = HashInput(receipt)
       f. expected_seq = receipt.chain.sequenceNumber + 1
  5. return VALID(length=len(receipts))
```

**Partial Verification:** Verifiers MAY verify a subset of the chain by accepting a trusted checkpoint (a known-good receipt hash and sequence number) and verifying only from that point forward.

### 6.4 Compliance Mapping

Action Receipts are designed to satisfy common compliance framework controls:

#### 6.4.1 Australian ISM (Information Security Manual)

| ISM Control | Receipt Field | Description |
|------------|--------------|-------------|
| ISM-0585 | `agent`, `delegation` | Identification and authentication of processes |
| ISM-0988 | `action.type`, `action.target` | Logging of privileged actions |
| ISM-0580 | `chain.*`, `signature` | Integrity of audit logs |
| ISM-1405 | `timestamp`, `context.sessionId` | Centralised event logging |
| ISM-0859 | `context.environment` | System configuration logging |

#### 6.4.2 SOC 2 Trust Services Criteria

| SOC 2 Criteria | Receipt Field | Description |
|---------------|--------------|-------------|
| CC6.1 | `agent`, `delegation` | Logical access security — identity of actor |
| CC6.2 | `delegation`, `action.type` | Authorised scope of access |
| CC6.3 | `chain.*` | Integrity of audit trail |
| CC7.2 | `action.result.status` | Monitoring of system operations |
| CC8.1 | `context.runtimeVersion` | Change management tracking |

#### 6.4.3 NIST 800-53 Rev. 5

| NIST Control | Receipt Field | Description |
|-------------|--------------|-------------|
| AU-2 | `action.type` | Auditable events |
| AU-3 | All fields | Content of audit records |
| AU-8 | `timestamp` | Time stamps |
| AU-9 | `chain.*`, `signature` | Protection of audit information |
| AU-10 | `signature` | Non-repudiation |
| AU-12 | `agent`, `delegation` | Audit record generation |
| IA-2 | `agent`, `delegation` | Identification and authentication |
| AC-6 | `delegation.scope` | Least privilege |

---

## 7. Trust Framework

### 7.1 Trust Levels (L0-L4)

The IDProva Trust Framework defines five trust levels representing increasing degrees of identity verification:

| Level | Name | Verification | Assurance |
|-------|------|-------------|-----------|
| **L0** | Unverified | Self-declared identity only | The agent claims an identity but provides no external verification. Any agent can claim L0. |
| **L1** | Domain-Verified | DNS TXT record proves control of the authority domain | The agent's authority namespace is confirmed to be controlled by the same entity that controls the agent. |
| **L2** | Organisation-Verified | An Identity Provider (IdP) or directory service vouches for the agent | The agent is confirmed to belong to a specific organisation through an organisational identity system. |
| **L3** | Third-Party Attested | An independent auditor or certification body attests to the agent's identity and configuration | The agent has undergone external review. Attestation may reference specific standards (e.g., SOC 2, ISM). |
| **L4** | Continuously Monitored | Real-time monitoring confirms ongoing compliance with identity, configuration, and behaviour policies | The highest trust level. Requires active monitoring infrastructure and automated trust level demotion on policy violation. |

### 7.2 Verification Methods

Each trust level requires specific verification methods:

**L0 — Unverified:**
- The agent publishes a DID Document with valid cryptographic keys.
- No external verification is performed.
- Suitable for: development, testing, internal prototyping.

**L1 — Domain-Verified:**
- DNS TXT record verification (Section 7.3).
- Suitable for: production agents with domain ownership proof.

**L2 — Organisation-Verified:**
- OIDC/SAML assertion from an organisational IdP linking the agent DID to an organisational identity.
- LDAP/AD group membership attestation.
- X.509 certificate from an organisational CA with the agent DID in the Subject Alternative Name (SAN) extension.
- Suitable for: enterprise agents requiring organisational binding.

**L3 — Third-Party Attested:**
- Signed attestation from a recognised IDProva Attestation Provider.
- Reference to an external audit report (SOC 2, ISO 27001, ISM assessment).
- The attestation MUST include: attester DID, subject DID, attestation date, expiry, scope of attestation, and signature.
- Suitable for: cross-organisational trust, regulatory compliance.

**L4 — Continuously Monitored:**
- All L3 requirements, plus:
- Real-time config attestation monitoring (config hash checked on every interaction).
- Behavioural anomaly detection (e.g., unusual scope usage patterns).
- Automated trust demotion: if monitoring detects a policy violation, the agent's trust level is automatically reduced to L1 until the violation is resolved.
- Suitable for: high-security environments, financial systems, healthcare.

### 7.3 DNS Verification (L1)

To achieve L1 trust, the agent's controller MUST publish a DNS TXT record proving domain ownership:

**DNS TXT Record Format:**

```
_idprova.example.com.  IN  TXT  "idprova=1 did=did:aid:example.com:pratyush fingerprint=z6MkhaXgBZD..."
```

**Record Fields:**

| Field | Description |
|-------|-----------|
| `idprova` | Protocol version. MUST be `1`. |
| `did` | The controller DID for this domain namespace. |
| `fingerprint` | First 16 characters of the controller's primary public key (Multibase encoded). |

**Verification Algorithm:**

```
VerifyDNS(did):
  1. Parse authority from DID: did:aid:{authority}:{name} → authority
  2. Query DNS TXT records for _idprova.{authority}
  3. Parse the TXT record fields
  4. Resolve the controller DID from the record
  5. Verify the fingerprint matches the controller's public key
  6. Verify the DID Document's controller matches the DNS-declared controller
  7. If all checks pass: return L1_VERIFIED
  8. Otherwise: return L0_UNVERIFIED
```

**Multiple Agents Under One Domain:**

A single DNS TXT record covers all agents under that domain's authority. The `did` field points to the domain controller, not individual agents. Individual agents are verified by confirming their DID Document's `controller` field matches the DNS-declared controller DID.

### 7.4 Progressive Trust Elevation

Agents can elevate their trust level over time:

```
        ┌──────────┐
        │    L0    │  Self-declare identity
        └─────┬────┘
              │ Publish DNS TXT record
              ▼
        ┌──────────┐
        │    L1    │  Domain verified
        └─────┬────┘
              │ IdP vouches for agent
              ▼
        ┌──────────┐
        │    L2    │  Organisation verified
        └─────┬────┘
              │ External audit / attestation
              ▼
        ┌──────────┐
        │    L3    │  Third-party attested
        └─────┬────┘
              │ Enable continuous monitoring
              ▼
        ┌──────────┐
        │    L4    │  Continuously monitored
        └──────────┘
```

**Trust Demotion:** Trust levels can also decrease:

- **Automatic demotion:** L4 agents are demoted to L1 on monitoring failure. L3 agents are demoted to L2 on attestation expiry.
- **Manual demotion:** An administrator can reduce any agent's trust level via a DID Document update.
- **Revocation demotion:** If the controller DID is deactivated, all agents controlled by that DID are demoted to L0.

---

## 8. Protocol Bindings

### 8.1 MCP Authentication

IDProva integrates with the Model Context Protocol (MCP) to provide authenticated tool calls and resource access.

#### 8.1.1 MCP Session Establishment

When an MCP client connects to an MCP server, it MAY present an IDProva identity:

**Step 1: Client presents DAT in the `initialize` request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "idprova": {
        "version": "0.1.0",
        "dat": "eyJhbGciOi..."
      }
    },
    "clientInfo": {
      "name": "kai-lead-agent",
      "version": "2.1.0"
    }
  }
}
```

**Step 2: Server validates the DAT:**

1. Decode the JWS and verify the signature(s).
2. Resolve the issuer's DID Document.
3. Verify the delegation chain.
4. Check that the `sub` claim matches the connecting client's declared identity.
5. Extract scopes and constraints.

**Step 3: Server responds with acknowledgement:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2025-03-26",
    "capabilities": {
      "idprova": {
        "version": "0.1.0",
        "accepted": true,
        "effectiveScopes": [
          "mcp:tool:filesystem:read",
          "mcp:tool:filesystem:write"
        ],
        "trustLevel": "L1"
      }
    },
    "serverInfo": {
      "name": "secure-mcp-server",
      "version": "1.0.0"
    }
  }
}
```

#### 8.1.2 MCP Tool Call Authentication

Each tool call includes the DAT reference for per-call authorisation:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "readFile",
    "arguments": {
      "path": "/projects/idprova/README.md"
    },
    "_idprova": {
      "dat": "eyJhbGciOi...",
      "receiptRequested": true
    }
  }
}
```

The server validates:
1. The DAT grants `mcp:tool:filesystem:read` (or a covering scope).
2. Constraints are satisfied (rate limits, IP, time window).
3. If `receiptRequested` is true, generates an Action Receipt and returns it in the response.

**Tool Call Response with Receipt:**

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "# IDProva\n..."
      }
    ],
    "_idprova": {
      "receipt": {
        "id": "rcpt_01HQ3P9LYCD8ZH3ENQWT6G7F0U",
        "chain": {
          "previousHash": "blake3:7a8b...",
          "sequenceNumber": 42
        },
        "signature": "z4sK7q..."
      }
    }
  }
}
```

### 8.2 A2A Authentication

IDProva integrates with the Agent-to-Agent (A2A) protocol for authenticated agent communication.

#### 8.2.1 A2A Agent Card Extension

The A2A Agent Card is extended with IDProva identity information:

```json
{
  "name": "Kai Lead Agent",
  "description": "Primary orchestration agent",
  "url": "https://example.com/agents/kai",
  "capabilities": {
    "streaming": true,
    "pushNotifications": false
  },
  "authentication": {
    "schemes": ["idprova-dat"]
  },
  "idprova": {
    "did": "did:aid:example.com:kai-lead-agent",
    "trustLevel": "L1",
    "supportedAlgorithms": ["EdDSA", "MLDSA65"]
  }
}
```

#### 8.2.2 A2A Task Authentication

When sending a task to another agent via A2A, the sender includes its DAT:

```json
{
  "jsonrpc": "2.0",
  "id": "task-001",
  "method": "tasks/send",
  "params": {
    "id": "task-001",
    "message": {
      "role": "user",
      "parts": [
        {
          "type": "text",
          "text": "Analyse the security report."
        }
      ]
    },
    "metadata": {
      "idprova": {
        "senderDID": "did:aid:example.com:kai-lead-agent",
        "dat": "eyJhbGciOi...",
        "receiptRequested": true
      }
    }
  }
}
```

The receiving agent validates the DAT and checks that the `a2a:task:execute` scope (or more specific scope) is granted.

### 8.3 HTTP Transport

For direct HTTP-based interactions, IDProva uses standard HTTP headers:

#### 8.3.1 Request Headers

```http
POST /api/v1/action HTTP/1.1
Host: agent.example.com
Content-Type: application/json
Authorization: IDProva eyJhbGciOi...
X-IDProva-DID: did:aid:example.com:kai-lead-agent
X-IDProva-Receipt-Request: true
```

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `IDProva` scheme followed by the DAT (JWS compact). |
| `X-IDProva-DID` | Yes | The agent's DID. Must match the DAT's `sub` claim. |
| `X-IDProva-Receipt-Request` | No | If `true`, the server returns an Action Receipt in the response. |

#### 8.3.2 Response Headers

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-IDProva-Receipt: eyJpZCI6InJjcH...
X-IDProva-Trust-Level: L1
```

| Header | Description |
|--------|-----------|
| `X-IDProva-Receipt` | Base64url-encoded Action Receipt (if requested). |
| `X-IDProva-Trust-Level` | The server's assessed trust level of the requesting agent. |

#### 8.3.3 Error Responses

IDProva-specific HTTP error responses:

| Status | Code | Description |
|--------|------|-------------|
| 401 | `idprova:invalid-dat` | DAT is malformed, expired, or signature invalid. |
| 401 | `idprova:unknown-identity` | DID could not be resolved. |
| 403 | `idprova:insufficient-scope` | DAT does not grant required scope. |
| 403 | `idprova:constraint-violation` | A DAT constraint was violated (rate limit, IP, etc.). |
| 403 | `idprova:trust-level-insufficient` | Agent's trust level is below the required minimum. |
| 403 | `idprova:config-mismatch` | Agent's config attestation does not match expected value. |
| 403 | `idprova:delegation-revoked` | The DAT or a parent in its chain has been revoked. |

---

## 9. Registry

### 9.1 Registry API

The IDProva Registry provides storage and resolution of DID Documents, DATs, and Action Receipts. The API is RESTful over HTTPS.

**Base URL:** `https://{registry-host}/v1`

#### 9.1.1 Identity Operations

**Create Identity:**

```http
POST /v1/identities
Content-Type: application/did+json
Authorization: IDProva {controller-dat}

{DID Document}
```

Response: `201 Created` with the stored DID Document.

**Resolve Identity:**

```http
GET /v1/identities/{did}
Accept: application/did+json
```

Response: `200 OK` with the DID Document and resolution metadata.

**Update Identity:**

```http
PUT /v1/identities/{did}
Content-Type: application/did+json
Authorization: IDProva {controller-dat}

{Updated DID Document}
```

Response: `200 OK` with the updated DID Document.

**Deactivate Identity:**

```http
DELETE /v1/identities/{did}
Authorization: IDProva {controller-dat}
```

Response: `200 OK`. The DID Document is marked as deactivated (not physically deleted).

#### 9.1.2 Delegation Operations

**Store DAT:**

```http
POST /v1/delegations
Content-Type: application/json
Authorization: IDProva {issuer-dat}

{
  "token": "eyJhbGciOi...",
  "metadata": {
    "description": "Filesystem access for kai-lead-agent"
  }
}
```

**Resolve DAT:**

```http
GET /v1/delegations/{jti}
```

**Revoke DAT:**

```http
POST /v1/delegations/{jti}/revoke
Content-Type: application/json
Authorization: IDProva {issuer-dat}

{
  "reason": "privilege-change"
}
```

**Check DAT Status:**

```http
GET /v1/delegations/{jti}/status
```

#### 9.1.3 Receipt Operations

**Store Receipt:**

```http
POST /v1/receipts
Content-Type: application/json
Authorization: IDProva {agent-dat}

{Action Receipt}
```

**Query Receipts:**

```http
GET /v1/receipts?agent={did}&from={timestamp}&to={timestamp}&type={scope}&limit=100&offset=0
```

**Verify Receipt Chain:**

```http
POST /v1/receipts/verify
Content-Type: application/json

{
  "agent": "did:aid:example.com:kai-lead-agent",
  "fromSequence": 0,
  "toSequence": 100
}
```

Response:

```json
{
  "valid": true,
  "chainLength": 101,
  "firstSequence": 0,
  "lastSequence": 100,
  "genesisHash": "blake3:...",
  "headHash": "blake3:..."
}
```

### 9.2 Self-Hosted Registry

Organisations MAY operate their own IDProva registry. A self-hosted registry:

- MUST implement the full Registry API (Section 9.1).
- MUST serve DID Documents at the well-known endpoint (Section 3.5).
- MUST publish its own IDProva identity (`did:aid:{domain}:_registry`).
- SHOULD implement rate limiting and access controls.
- SHOULD persist data with appropriate backup and disaster recovery.

**Minimum self-hosted registry components:**

1. **HTTP server** implementing the Registry API.
2. **Storage backend** (PostgreSQL, SQLite, or similar) for DID Documents, DATs, and Receipts.
3. **Signature validation** library supporting Ed25519 and ML-DSA-65.
4. **DNS resolver** for L1 trust verification.

### 9.3 Managed Registry Service

Tech Blaze operates a managed registry service at `https://registry.idprova.dev`. The managed registry provides:

- High-availability DID Document resolution.
- Global DAT storage and revocation checking.
- Action Receipt storage with chain verification.
- Web dashboard for identity management.
- Webhook notifications for revocation events.

**Service Tiers:**

| Tier | DID Documents | DAT Storage | Receipt Storage | Resolution Latency |
|------|-------------|------------|----------------|-------------------|
| Free | 10 | 100 | 10,000 | Best-effort |
| Developer | 100 | 10,000 | 1,000,000 | < 100ms |
| Enterprise | Unlimited | Unlimited | Unlimited | < 50ms, SLA |

---

## 10. Security Considerations

### 10.1 Threat Model

IDProva assumes the following threat model:

**Trusted:**
- The cryptographic primitives (Ed25519, ML-DSA-65, BLAKE3, SHA-256) are correctly implemented and provide their stated security guarantees.
- The agent's local key storage is secure (per Section 4.4.2).

**Untrusted:**
- The network between any two entities.
- Registry operators (the protocol provides integrity even if a registry is compromised).
- Other agents (all claims are verified cryptographically).

**Threat Actors:**

| Actor | Capability | Motivation |
|-------|-----------|------------|
| Rogue Agent | Valid identity, acts outside policy | Data exfiltration, privilege escalation |
| External Attacker | Network access, no valid identity | Impersonation, man-in-the-middle |
| Compromised Registry | Control of registry infrastructure | Identity manipulation, revocation suppression |
| Quantum Adversary (Future) | Quantum computer capable of breaking classical crypto | Key recovery, signature forgery |

### 10.2 Key Compromise

**Detection:** Key compromise may be detected through:
- Unexpected action receipts in the chain.
- Config attestation mismatches.
- Anomalous behaviour detected by L4 monitoring.

**Response:**

1. **Immediate:** Deactivate the compromised agent's DID Document.
2. **Propagation:** Revoke all DATs issued by or to the compromised agent.
3. **Forensics:** Audit the action receipt chain to determine what actions the attacker performed.
4. **Recovery:** Generate new key pairs, create a new DID, and re-establish delegation chains.

**Mitigation:** The hybrid signature scheme ensures that compromising only the Ed25519 key is insufficient to forge signatures if the ML-DSA-65 key remains secure (and vice versa). An attacker must compromise both keys simultaneously.

### 10.3 Replay Attacks

**DAT Replay:** Prevented by:
- `exp` claim enforcing token expiry.
- `jti` claim providing a unique token ID for replay detection.
- `aud` claim binding the token to a specific verifier.
- Verifiers SHOULD maintain a `jti` cache for the token's lifetime to detect replays.

**Receipt Replay:** Prevented by:
- Monotonically increasing `sequenceNumber`.
- Hash chaining (`previousHash` links each receipt to its predecessor).
- Verifiers reject receipts with sequence numbers that have already been observed.

### 10.4 Delegation Chain Attacks

**Chain Fabrication:** An attacker cannot fabricate a delegation chain because:
- Each DAT in the chain is signed by its issuer.
- The chain validation algorithm (Section 5.5) verifies every link.
- The root of the chain must resolve to a valid, non-deactivated DID.

**Privilege Escalation:** Prevented by the scope reduction rule (Section 5.3.6):
- Child DAT scopes must be a subset of parent scopes.
- Verifiers MUST check this constraint during chain validation.

**Chain Length Attack:** An attacker might create very long delegation chains to exhaust verifier resources. Mitigated by:
- Default maximum chain depth of 5.
- `maxDelegationDepth` constraint in DATs.
- Verifiers MAY set their own maximum depth limits.

### 10.5 Config Attestation Privacy

The `configAttestation` field is a hash, not the configuration itself. However:

- Different configurations produce different hashes, which could be used to fingerprint agents.
- Configuration changes are observable through attestation changes.

**Mitigations:**
- Agents MAY omit the `configAttestation` field if privacy is a concern.
- The hash does not reveal the configuration contents.
- Implementations SHOULD NOT log or share config attestation hashes beyond what is necessary for verification.

---

## 11. Privacy Considerations

IDProva is designed with the following privacy principles:

**Data Minimisation:**
- DID Documents contain only the information necessary for identity verification and delegation.
- The `model` and `runtime` fields in agent metadata are OPTIONAL and can be omitted for privacy.
- Action Receipt parameters SHOULD be redacted to remove sensitive data before signing.

**Correlation Resistance:**
- Agents MAY use different DIDs for different relationships (pairwise DIDs) to prevent cross-service correlation.
- Registry operators can observe resolution patterns. Clients SHOULD use encrypted DNS (DoH/DoT) when resolving DID Documents via well-known endpoints.

**Right to Erasure:**
- DID deactivation (Section 3.4.4) removes all verification methods, rendering the identity unusable.
- Action Receipts, once signed and chained, cannot be individually deleted without breaking the chain. Implementations SHOULD implement retention policies that archive and eventually destroy old chains.
- Registry operators MUST comply with applicable data protection laws (GDPR, Privacy Act 1988) regarding the deletion of personal data.

**Cross-Border Data Flows:**
- The `geofence` constraint in DATs (Section 5.4) allows principals to restrict where agents operate.
- Registry operators SHOULD document data residency policies.
- Organisations operating under data sovereignty requirements SHOULD use self-hosted registries (Section 9.2).

**Agent Metadata Privacy:**
- The `model` field reveals the AI model vendor and version, which may be commercially sensitive.
- The `runtime` field reveals the deployment platform.
- Both fields are OPTIONAL. In high-privacy scenarios, agents SHOULD omit them or use generic values.

---

## 12. IANA Considerations

### 12.1 DID Method Registration

This specification registers the `did:aid:` method in the W3C DID Method Registry:

| Field | Value |
|-------|-------|
| Method Name | `idprova` |
| Method Specific Identifier | `authority:agent-name` |
| Authors | Tech Blaze Consulting Pty Ltd |
| Specification | https://idprova.dev/spec/v0.1 |
| Status | Provisional |

### 12.2 Media Type Registration

This specification defines the following media types:

**`application/idprova-dat+jwt`**

| Field | Value |
|-------|-------|
| Type name | application |
| Subtype name | idprova-dat+jwt |
| Required parameters | none |
| Optional parameters | none |
| Encoding | 7bit (JWS Compact Serialization) |
| Security considerations | See Section 10 |

**`application/idprova-receipt+json`**

| Field | Value |
|-------|-------|
| Type name | application |
| Subtype name | idprova-receipt+json |
| Required parameters | none |
| Optional parameters | none |
| Encoding | 8bit (JSON) |
| Security considerations | See Section 10 |

### 12.3 HTTP Header Registration

| Header | Description | Status |
|--------|-----------|--------|
| `X-IDProva-DID` | Agent's DID | Provisional |
| `X-IDProva-Receipt` | Action Receipt | Provisional |
| `X-IDProva-Receipt-Request` | Request receipt generation | Provisional |
| `X-IDProva-Trust-Level` | Assessed trust level | Provisional |

### 12.4 JSON Web Signature Header Parameter Registration

| Parameter | Description |
|-----------|-----------|
| `pqalg` | Post-quantum signature algorithm |
| `pqkid` | Post-quantum key identifier |

---

## Appendix A: Complete Examples

### A.1 Complete Agent Identity Document (AID)

The following is a complete, valid IDProva DID Document for a production agent:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://idprova.dev/v1"
  ],
  "id": "did:aid:techblaze.com.au:kai-lead-agent",
  "controller": "did:aid:techblaze.com.au:pratyush",
  "created": "2026-02-24T00:00:00Z",
  "updated": "2026-02-24T10:30:00Z",
  "verificationMethod": [
    {
      "id": "did:aid:techblaze.com.au:kai-lead-agent#key-ed25519-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:aid:techblaze.com.au:kai-lead-agent",
      "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    },
    {
      "id": "did:aid:techblaze.com.au:kai-lead-agent#key-mldsa65-1",
      "type": "MLDSA65VerificationKey2024",
      "controller": "did:aid:techblaze.com.au:kai-lead-agent",
      "publicKeyMultibase": "z2Drjgb4TxNYuSiDBqd7pJAn5MfgF1YfNfsaHH3gZXQxqR7kWvBcPmTq9sN8rY6jK3hL2dF7wX4eU1aR5oC0iV8bG9mJ6nH3pZ2tS5qA7yW4xD1fE8cB0uK9vL6gM3jI2rO5sT8nQ4wP1aZ7hX0dY6bC9eR3fG4kN2mJ8tV5uW7iA6oL1pS0qE3xD9yB2cF4gH8jK7lM5nO0rT6wU1vX3zA9bC2dE4fG7hI8jK0lM3nO6pQ1rS5tU9wV2xY4zA8bC0dE3fG6hI7jK1lM4nO9pQ2rS5tU8wV0xY3zA7bC1dE2fG5hI6jK4lM8nO0pQ3rS9tU1wV7xY2zA6bC4dE0fG3hI5jK9lM1nO7pQ8rS2tU4wV6xY0zA5bC3dE9fG1hI2jK8lM0nO4pQ7rS6tU3wV5xY9zA1bC8dE4fG0hI3jK7lM6nO5pQ2rS9tU1wV8xY4zA0bC7dE3fG6hI9jK2lM5nO8pQ1rS4tU7wV0xY3zA6bC9dE2fG5hI8jK1lM4nO7pQ0rS3tU6wV9xY2zA5bC8dE1fG4hI7jK0lM3nO6pQ9rS2tU5wV8x"
    }
  ],
  "authentication": [
    "did:aid:techblaze.com.au:kai-lead-agent#key-ed25519-1",
    "did:aid:techblaze.com.au:kai-lead-agent#key-mldsa65-1"
  ],
  "assertionMethod": [
    "did:aid:techblaze.com.au:kai-lead-agent#key-ed25519-1",
    "did:aid:techblaze.com.au:kai-lead-agent#key-mldsa65-1"
  ],
  "capabilityDelegation": [
    "did:aid:techblaze.com.au:kai-lead-agent#key-ed25519-1"
  ],
  "service": [
    {
      "id": "did:aid:techblaze.com.au:kai-lead-agent#idprova-metadata",
      "type": "IDProvaAgentMetadata",
      "serviceEndpoint": {
        "name": "Kai Lead Agent",
        "description": "Primary orchestration agent for Tech Blaze operations",
        "model": "acme-ai/agent-v2",
        "runtime": "openclaw/v2.1",
        "configAttestation": "blake3:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
        "trustLevel": "L1",
        "capabilities": [
          "mcp:tool-call",
          "mcp:resource-read",
          "mcp:resource-write",
          "idprova:delegate",
          "idprova:receipt-create",
          "a2a:task-execute"
        ],
        "maxDelegationDepth": 3,
        "organisationDID": "did:aid:techblaze.com.au:_root"
      }
    },
    {
      "id": "did:aid:techblaze.com.au:kai-lead-agent#idprova-revocation",
      "type": "IDProvaRevocationList",
      "serviceEndpoint": "https://techblaze.com.au/.well-known/idprova/revocations.json"
    }
  ],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-02-24T10:30:00Z",
    "verificationMethod": "did:aid:techblaze.com.au:pratyush#key-ed25519-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3FXQjecWg3dBGZBCY9KJTA1BgVPGHuS3RwQxMDwFkNUTxGgJdTLDNS7oS1i3yrA2A5UcHxG8FJvQyP1d9BCpWu3"
  }
}
```

### A.2 Complete Delegation Attestation Token (DAT)

**Header (decoded):**

```json
{
  "alg": "EdDSA",
  "typ": "idprova-dat+jwt",
  "kid": "did:aid:techblaze.com.au:pratyush#key-ed25519-1",
  "pqalg": "MLDSA65",
  "pqkid": "did:aid:techblaze.com.au:pratyush#key-mldsa65-1"
}
```

**Payload (decoded):**

```json
{
  "iss": "did:aid:techblaze.com.au:pratyush",
  "sub": "did:aid:techblaze.com.au:kai-lead-agent",
  "aud": "did:aid:techblaze.com.au:secure-mcp-server",
  "iat": 1708732800,
  "exp": 1708819200,
  "nbf": 1708732800,
  "jti": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
  "scope": [
    "mcp:tool:filesystem:read",
    "mcp:tool:filesystem:write",
    "mcp:tool:database:read",
    "mcp:resource:context:read",
    "mcp:resource:context:write",
    "idprova:agent:create",
    "idprova:delegation:issue",
    "idprova:receipt:create"
  ],
  "constraints": {
    "maxCallsPerHour": 5000,
    "maxCallsPerDay": 50000,
    "maxConcurrent": 10,
    "allowedIPs": ["10.0.0.0/8", "100.64.0.0/10"],
    "requiredTrustLevel": "L1",
    "maxDelegationDepth": 2,
    "geofence": ["AU"],
    "timeWindows": [
      {
        "days": ["Mon", "Tue", "Wed", "Thu", "Fri"],
        "startUTC": "21:00",
        "endUTC": "11:00"
      }
    ],
    "requiredConfigAttestation": true
  },
  "configAttestation": "blake3:a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
  "delegationChain": []
}
```

**Compact Serialization (illustrative, truncated):**

```
eyJhbGciOiJFZERTQSIsInR5cCI6ImFpZHNwZWMtZGF0K2p3dCIsImtpZCI6ImRpZDphc3BlYzp0
ZWNoYmxhemUuY29tLmF1OnByYXR5dXNoI2tleS1lZDI1NTE5LTEiLCJwcWFsZyI6Ik1MRFNBNjUi
LCJwcWtpZCI6ImRpZDphc3BlYzp0ZWNoYmxhemUuY29tLmF1OnByYXR5dXNoI2tleS1tbGRzYTY1
LTEifQ.eyJpc3MiOiJkaWQ6YXNwZWM6dGVjaGJsYXplLmNvbS5hdTpwcmF0eXVzaCIsInN1YiI6
ImRpZDphc3BlYzp0ZWNoYmxhemUuY29tLmF1OmthaS1sZWFkLWFnZW50Iiw...
.[Ed25519 signature].[ML-DSA-65 signature]
```

### A.3 Complete Action Receipt

```json
{
  "id": "rcpt_01HQ3P9LYCD8ZH3ENQWT6G7F0U",
  "version": "0.1.0",
  "timestamp": "2026-02-24T12:30:45.123Z",
  "agent": "did:aid:techblaze.com.au:kai-lead-agent",
  "delegation": "dat_01HQ3N8KXBC7YG2DMPVS5F6E9T",
  "action": {
    "type": "mcp:tool:filesystem:read",
    "target": "/projects/idprova/src/lib/resolver.ts",
    "method": "readFile",
    "parameters": {
      "path": "/projects/idprova/src/lib/resolver.ts",
      "encoding": "utf-8"
    },
    "result": {
      "status": "success",
      "bytesRead": 8192,
      "contentHash": "blake3:f8c3a1b29d4e7f068c5a2b31d4e7f068c5a2b31d4e7f068c5a2b31d4e7f068c"
    }
  },
  "context": {
    "sessionId": "sess_01HQ3P2KABCDEFG12345678",
    "parentReceiptId": "rcpt_01HQ3P8KXBCDEFG12345678",
    "traceId": "trace_01HQ3P1JABCDEFG12345678",
    "environment": "production",
    "runtimeVersion": "openclaw/v2.1"
  },
  "chain": {
    "previousHash": "blake3:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b",
    "sequenceNumber": 42
  },
  "signature": {
    "algorithm": "hybrid-ed25519-mldsa65",
    "keyId": "did:aid:techblaze.com.au:kai-lead-agent#key-ed25519-1",
    "value": "z4sK7qN2vR8wX1yT5uP3mJ6nB9cF0dA8eH2iL4kM7oQ1rS3tU6vW9xY0zA5bC8dE3fG6hI9jK2lM5nO8pQ1rS4tU7wV0xY3zA6bC9dE2fG5hI8jK1"
  }
}
```

### A.4 Delegation Chain Example

This example shows a three-level delegation chain:

**Level 0 — Human Principal creates root DAT:**

```
Issuer:  did:aid:techblaze.com.au:pratyush (human)
Subject: did:aid:techblaze.com.au:kai-lead-agent
JTI:     dat_ROOT_001
Scopes:  [mcp:tool:*:*, mcp:resource:*:*, idprova:*:*]
Chain:   []
```

**Level 1 — Lead agent delegates to sub-agent:**

```
Issuer:  did:aid:techblaze.com.au:kai-lead-agent
Subject: did:aid:techblaze.com.au:writer-agent
JTI:     dat_LEVEL1_001
Scopes:  [mcp:tool:filesystem:read, mcp:tool:filesystem:write, mcp:resource:context:read]
Chain:   [dat_ROOT_001]
```

**Level 2 — Sub-agent delegates to specialist:**

```
Issuer:  did:aid:techblaze.com.au:writer-agent
Subject: did:aid:techblaze.com.au:spellcheck-agent
JTI:     dat_LEVEL2_001
Scopes:  [mcp:tool:filesystem:read]
Chain:   [dat_ROOT_001, dat_LEVEL1_001]
```

Notice that at each level, the scopes are reduced. The spellcheck agent can only read files, not write them.

---

## Appendix B: Scope Grammar Reference

### B.1 Complete ABNF Grammar

```abnf
; IDProva Scope Grammar (ABNF, RFC 5234)

scope-list      = scope *( SP scope )
scope           = namespace ":" resource-path ":" action
namespace       = name-segment
resource-path   = name-segment *( ":" name-segment )
action          = name-segment / wildcard
name-segment    = name-char / wildcard
name-char       = 1*( ALPHA / DIGIT / "-" / "_" )
wildcard        = "*"

; Namespace registry
; "mcp"      - Model Context Protocol
; "idprova"  - IDProva Protocol
; "a2a"      - Agent-to-Agent Protocol
; "http"     - HTTP operations
; "custom"   - User-defined
```

### B.2 Scope Matching Algorithm

```
ScopeMatches(required, granted):
  1. Parse required into (req_ns, req_resource, req_action)
  2. Parse granted into (gnt_ns, gnt_resource, gnt_action)
  3. if not SegmentMatches(req_ns, gnt_ns): return false
  4. req_parts = Split(req_resource, ":")
  5. gnt_parts = Split(gnt_resource, ":")
  6. if len(gnt_parts) > len(req_parts): return false
  7. for i in range(len(gnt_parts)):
       if not SegmentMatches(req_parts[i], gnt_parts[i]): return false
  8. if not SegmentMatches(req_action, gnt_action): return false
  9. return true

SegmentMatches(required, granted):
  1. if granted == "*": return true
  2. return required == granted
```

### B.3 Common Scope Patterns

| Pattern | Description |
|---------|-----------|
| `mcp:tool:*:*` | Full access to all MCP tools |
| `mcp:tool:filesystem:read` | Read-only filesystem tool access |
| `mcp:tool:filesystem:*` | Full filesystem tool access |
| `mcp:resource:*:read` | Read any MCP resource |
| `idprova:agent:create` | Create new agent identities |
| `idprova:delegation:*` | Full delegation management |
| `a2a:task:*` | Full A2A task operations |
| `http:api:*` | Full HTTP API access |
| `custom:billing:read` | Read billing data (custom scope) |
| `*:*:*` | Unrestricted access (use with extreme caution) |

---

## Appendix C: Test Vectors

### C.1 DID Parsing Test Vectors

```
Input:  "did:aid:example.com:kai-lead-agent"
Method: "idprova"
Authority: "example.com"
AgentName: "kai-lead-agent"
Valid: true

Input:  "did:aid:my-org:agent-01"
Method: "idprova"
Authority: "my-org"
AgentName: "agent-01"
Valid: true

Input:  "did:aid:localhost:dev-agent"
Method: "idprova"
Authority: "localhost"
AgentName: "dev-agent"
Valid: true

Input:  "did:aid:example.com"
Valid: false (missing agent-name)

Input:  "did:aid::agent"
Valid: false (empty authority)

Input:  "did:web:example.com:agent"
Valid: false (wrong method)

Input:  "did:aid:example.com:Agent_With_Caps"
Valid: false (uppercase not allowed)

Input:  "did:aid:example.com:valid_agent-01"
Valid: true
```

### C.2 Scope Matching Test Vectors

```
Required: "mcp:tool:filesystem:read"
Granted:  "mcp:tool:filesystem:read"
Result:   MATCH

Required: "mcp:tool:filesystem:read"
Granted:  "mcp:tool:filesystem:*"
Result:   MATCH

Required: "mcp:tool:filesystem:read"
Granted:  "mcp:tool:*:*"
Result:   MATCH

Required: "mcp:tool:filesystem:read"
Granted:  "*:*:*"
Result:   MATCH

Required: "mcp:tool:filesystem:write"
Granted:  "mcp:tool:filesystem:read"
Result:   NO MATCH (action mismatch)

Required: "mcp:tool:database:read"
Granted:  "mcp:tool:filesystem:*"
Result:   NO MATCH (resource mismatch)

Required: "mcp:tool:filesystem:read"
Granted:  "a2a:tool:filesystem:read"
Result:   NO MATCH (namespace mismatch)

Required: "mcp:tool:filesystem:sub:read"
Granted:  "mcp:tool:filesystem:*"
Result:   NO MATCH (granted resource path shorter than required)

Required: "mcp:tool:filesystem:read"
Granted:  "mcp:tool:filesystem:sub:read"
Result:   NO MATCH (granted resource path longer than required)
```

### C.3 Hash Chain Test Vectors

**Genesis Hash:**

```
Agent DID: "did:aid:example.com:test-agent"
Input:     "GENESIS:did:aid:example.com:test-agent"
BLAKE3:    "blake3:b3a1d4f7e2c5b8a1d4f7e2c5b8a1d4f7e2c5b8a1d4f7e2c5b8a1d4f7e2c5b8a1"
```

Note: The above hash is illustrative. Implementations MUST compute the actual BLAKE3 hash of the UTF-8 encoded input string.

**Chain Verification:**

```
Receipt[0]:
  chain.previousHash = BLAKE3("GENESIS:did:aid:example.com:test-agent")
  chain.sequenceNumber = 0
  Compute: hash_0 = BLAKE3(JCS(Receipt[0] without signature))

Receipt[1]:
  chain.previousHash = hash_0
  chain.sequenceNumber = 1
  Verify: chain.previousHash == hash_0  → PASS
  Verify: chain.sequenceNumber == 1     → PASS
  Compute: hash_1 = BLAKE3(JCS(Receipt[1] without signature))

Receipt[2]:
  chain.previousHash = hash_1
  chain.sequenceNumber = 2
  Verify: chain.previousHash == hash_1  → PASS
  Verify: chain.sequenceNumber == 2     → PASS
```

### C.4 DAT Validation Test Vectors

**Valid DAT:**

```
Header:
  alg: "EdDSA"
  typ: "idprova-dat+jwt"
  kid: "did:aid:example.com:alice#key-ed25519-1"

Payload:
  iss: "did:aid:example.com:alice"
  sub: "did:aid:example.com:agent-01"
  iat: 1708732800 (2026-02-24T00:00:00Z)
  exp: 1708819200 (2026-02-25T00:00:00Z)
  jti: "dat_test_valid_001"
  scope: ["mcp:tool:filesystem:read"]
  constraints: {}
  delegationChain: []

Validation at 2026-02-24T12:00:00Z:
  ✓ Signature valid
  ✓ iat <= now
  ✓ exp > now
  ✓ iss resolves to valid DID
  ✓ sub resolves to valid DID
  Result: VALID
```

**Expired DAT:**

```
Same as above but:
  exp: 1708732860 (2026-02-24T00:01:00Z)

Validation at 2026-02-24T12:00:00Z:
  ✓ Signature valid
  ✓ iat <= now
  ✗ exp > now (expired)
  Result: INVALID (token expired)
```

**Scope Escalation in Chain:**

```
Parent DAT:
  scope: ["mcp:tool:filesystem:read"]

Child DAT:
  scope: ["mcp:tool:filesystem:write"]

Validation:
  ✗ Child scope "mcp:tool:filesystem:write" is not covered by parent scope "mcp:tool:filesystem:read"
  Result: INVALID (scope escalation)
```

**Constraint Escalation in Chain:**

```
Parent DAT:
  constraints.maxCallsPerHour: 100

Child DAT:
  constraints.maxCallsPerHour: 200

Validation:
  ✗ Child maxCallsPerHour (200) > Parent maxCallsPerHour (100)
  Result: INVALID (constraint escalation)
```

---

## Appendix D: Implementation Checklist

The following checklist is provided for implementers to track conformance:

### D.1 Core (REQUIRED)

- [ ] Parse and validate `did:aid:` DIDs
- [ ] Create and validate DID Documents with Ed25519 keys
- [ ] Generate and verify Ed25519 signatures
- [ ] Create DATs in JWS Compact Serialization
- [ ] Validate DAT claims (iss, sub, iat, exp, scope)
- [ ] Implement scope matching algorithm
- [ ] Create Action Receipts with hash chains
- [ ] Verify Action Receipt chain integrity
- [ ] Resolve DIDs via well-known endpoints
- [ ] Resolve DIDs via Registry API

### D.2 Post-Quantum (RECOMMENDED)

- [ ] Generate ML-DSA-65 key pairs
- [ ] Create and verify hybrid signatures
- [ ] Support four-segment hybrid JWS format
- [ ] Include ML-DSA-65 keys in DID Documents

### D.3 Delegation (REQUIRED for multi-agent systems)

- [ ] Validate delegation chains
- [ ] Enforce scope reduction rule
- [ ] Enforce constraint inheritance
- [ ] Check DAT revocation lists
- [ ] Enforce maxDelegationDepth

### D.4 Trust Framework (RECOMMENDED)

- [ ] Verify L1 trust via DNS TXT records
- [ ] Support L2 trust via IdP integration
- [ ] Check trust level requirements in DAT constraints
- [ ] Implement trust level demotion

### D.5 Protocol Bindings (at least one REQUIRED)

- [ ] MCP session establishment with IDProva
- [ ] MCP tool call authentication
- [ ] A2A Agent Card IDProva extension
- [ ] A2A task authentication
- [ ] HTTP Authorization header scheme
- [ ] HTTP receipt headers

### D.6 Registry (REQUIRED for production)

- [ ] Identity CRUD operations
- [ ] DAT storage and resolution
- [ ] DAT revocation
- [ ] Receipt storage and querying
- [ ] Receipt chain verification endpoint

---

## References

### Normative References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- **[RFC 7515]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Signature (JWS)", RFC 7515, May 2015.
- **[RFC 7517]** Jones, M., "JSON Web Key (JWK)", RFC 7517, May 2015.
- **[RFC 7519]** Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- **[RFC 8032]** Josefsson, S. and I. Liusvaara, "Edwards-Curve Digital Signature Algorithm (EdDSA)", RFC 8032, January 2017.
- **[RFC 8785]** Rundgren, A., Jordan, B., and S. Erdtman, "JSON Canonicalization Scheme (JCS)", RFC 8785, June 2020.
- **[FIPS 204]** National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard (ML-DSA)", FIPS 204, August 2024.
- **[W3C-DID]** Sporny, M., Guy, A., Sabadello, M., and D. Reed, "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation, July 2022.
- **[BLAKE3]** O'Connor, J., Aumasson, J-P., Neves, S., and Z. Wilcox-O'Hearn, "BLAKE3 — one function, fast everywhere", 2020.

### Informative References

- **[MCP]** Anthropic, "Model Context Protocol Specification", 2025.
- **[A2A]** Google, "Agent-to-Agent Protocol Specification", 2025.
- **[SPIFFE]** CNCF, "Secure Production Identity Framework for Everyone", 2024.
- **[ISM]** Australian Signals Directorate, "Australian Government Information Security Manual", 2025.
- **[NIST-800-53]** National Institute of Standards and Technology, "Security and Privacy Controls for Information Systems and Organizations", SP 800-53 Rev. 5, September 2020.
- **[SOC2]** AICPA, "SOC 2 — Trust Services Criteria", 2022.

---

*Copyright 2026 Tech Blaze Consulting Pty Ltd. Licensed under the Apache License, Version 2.0.*
