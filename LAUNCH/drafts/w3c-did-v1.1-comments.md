# W3C DIDs v1.1 — Comment Submission Draft

> **Submit at:** https://github.com/w3c/did/issues/new/choose
> **Alternative:** Email public-did-wg@w3.org with subject "[did-1.1]"
> **Deadline:** April 5, 2026
> **Spec:** https://www.w3.org/TR/2026/CR-did-1.1-20260305/

---

## Issue 1: Agent-Specific DID Method Considerations

**Title:** Consider guidance for non-human entity (AI agent) DID methods

**Body:**

Thank you for advancing DIDs to v1.1. As the author of an open-source protocol (IDProva, Apache 2.0) that uses DIDs for AI agent identity, I'd like to share implementation experience relevant to the specification.

### Context

AI agents represent a rapidly growing category of DID subjects. NIST's NCCoE published a concept paper in February 2026 specifically addressing "Software and AI Agent Identity and Authorization," and their AI Agent Standards Initiative (CAISI) is exploring how identity standards apply to autonomous AI systems.

IDProva implements a `did:aid:` method giving AI agents verifiable cryptographic identity with W3C DID Documents. Through this implementation, we've identified several areas where the v1.1 specification could benefit from explicit consideration of non-human entity (NHE) use cases.

### Observations

**1. Service Extensions for Agent Metadata**

AI agent DID Documents benefit from standardised service extensions carrying agent-specific metadata: model identifier, runtime platform, configuration attestation (a hash of the agent's active configuration), trust level, and declared capabilities. Currently, this is implementation-specific. Guidance on recommended service types for machine-to-machine or agent-to-agent use cases would improve interoperability across agent identity implementations.

**2. DID Document Resolution for Autonomous Entities**

Section 7 (Resolution) assumes a human or human-controlled process initiating resolution. Agent-to-agent resolution has different characteristics:
- High-frequency resolution (agents may resolve each other's DIDs on every interaction)
- Caching semantics are critical for performance (agents interact at machine speed)
- Trust decisions must be automated based on DID Document content (no human in the loop)

Guidance on resolution caching semantics (TTL recommendations, cache invalidation triggers) would benefit implementers building agent identity systems.

**3. Key Rotation in Autonomous Contexts**

Key rotation (Section 5) is well-specified for human-controlled identities. For autonomous agents, additional considerations apply:
- Agents may need to rotate keys without human intervention (scheduled rotation)
- Emergency rotation upon suspected compromise must be fast and automated
- Post-quantum algorithm transition (NIST FIPS 204 ML-DSA, mandatory by 2035) will require all DID implementations to support algorithm migration

The specification could acknowledge that key rotation for autonomous entities may follow different lifecycle patterns than human-controlled rotation.

### Recommendation

Consider adding a non-normative section or appendix discussing DID usage patterns for non-human entities (AI agents, autonomous software, IoT devices). This would:
- Acknowledge the growing use of DIDs beyond human identity
- Provide implementation guidance for agent-specific service extensions
- Address resolution performance considerations for machine-to-machine use cases
- Align with NIST's emerging work on AI agent identity standards

### References

- NIST NCCoE Concept Paper: [Accelerating the Adoption of Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf) (Feb 2026)
- NIST AI Agent Standards Initiative: [CAISI](https://www.nist.gov/caisi/ai-agent-standards-initiative) (Feb 2026)
- IETF WIMSE: [AI Agent Identity draft](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)
- IDProva Protocol: [idprova.dev](https://idprova.dev)

**Submitted by:**
Pratyush Sood — IRAP Assessor (ASD-endorsed), CISM, CISA
Tech Blaze Consulting Pty Ltd
techblaze.com.au

---

## Issue 2: Relative DID URLs for Delegation References

**Title:** Clarify relative DID URL usage for cross-document references in delegation chains

**Body:**

Section 3.2.1 (Relative DID URLs) would benefit from clarification on how relative DID URLs should be used when one DID Document references another — specifically in delegation or trust chain scenarios.

### Use Case

In agent delegation chains, a parent agent's DID Document may reference child agents it has delegated authority to. Similarly, a delegation token (external to the DID Document) references both the issuer's DID and the subject's DID. When both DIDs share the same authority (e.g., `did:aid:example.com:parent` and `did:aid:example.com:child`), relative references could simplify serialisation.

### Question

Is it conformant for a DID Document's service endpoint or metadata to reference another DID using a relative DID URL, or must cross-document references always use absolute DIDs? Section 3.2.1 discusses relative DID URLs within a single DID Document but doesn't explicitly address cross-document reference patterns.

Clarification here would help implementers building delegation and trust chain systems that rely on DID-to-DID references.
