# GDPR Compliance Mapping

**Status:** v0.1 — operator-facing mapping reference
**Audience:** EU enterprise procurement, DPOs, legal counsel
**Companion to:** [compliance.md](compliance.md) (NIST SP 800-207 + ISM), [controls.md](controls.md) (NIST 800-53 Rev 5)

---

## Purpose

This document maps how IDprova protocol primitives support compliance with the EU General Data Protection Regulation (Regulation (EU) 2016/679). It is a factual mapping — the cryptographic primitives produce the evidence specific GDPR articles require. It is **not** a legal opinion, attestation of compliance, or substitute for a Data Protection Officer's review.

GDPR distinguishes between:
- **Controller** (decides why and how personal data is processed)
- **Processor** (processes personal data on behalf of a controller)

When IDprova Cloud is offered as a hosted service, Tech Blaze acts as a **processor** for customer data. When self-hosted, the customer operates the registry themselves and is the controller. This mapping addresses both contexts.

A separate **Data Processing Agreement (DPA)** is required between Tech Blaze (processor) and any EU controller using IDprova Cloud. The DPA is published at idprova.com/dpa.

---

## Scope

What IDprova does NOT process:
- IDprova does not store the *content* of agent actions (the body of an email an agent sent, the contents of a file it modified). It stores the **metadata** of each action — who, what, when, under what authority — in receipts.
- IDprova does not process personal data of end users *unless* an end user's identity appears in an action receipt (e.g. a `user_principal` field naming the human delegating to the agent).

What IDprova DOES process:
- Agent identifiers (`did:aid:` strings — these are pseudonymous identifiers but may be linkable to organisations or natural persons)
- Public keys associated with agents
- Optional `controller` fields naming the operator of an agent (may be a natural person, may be an organisation)
- Action receipts (timestamps, actions taken, outcomes — may include user-identifying fields by configuration)
- Delegation chain metadata (who delegated to whom)

Where a controller chooses to embed personal data in optional receipt fields (e.g. `user_principal`, `decision_context`), that processing is governed by the controller's own GDPR posture; IDprova provides the cryptographic evidence and integrity guarantees.

---

## Article-by-article mapping

### Article 5 — Principles relating to processing of personal data

| Principle | IDprova mapping |
|---|---|
| **5(1)(a) Lawfulness, fairness, transparency** | DAT scope grammar makes the basis for each agent action explicit and verifiable post-hoc. Receipts produce a transparent audit trail of every processing operation. |
| **5(1)(b) Purpose limitation** | DAT `scope` field cryptographically bounds the purpose of each delegation. An agent issued a DAT with scope `mcp:tool:filesystem:read` cannot use it for any other purpose without a new DAT. |
| **5(1)(c) Data minimisation** | IDprova receipts capture metadata, not action content. Operators are not forced to log personal data; the system encourages minimal capture. |
| **5(1)(d) Accuracy** | Receipts are immutable and signed at creation; tampering breaks the BLAKE3 hash chain. Inaccurate records are detectable rather than silently corrupted. |
| **5(1)(e) Storage limitation** | Receipt log retention is operator-configured. IDprova does not impose retention; supports data lifecycle management policies. |
| **5(1)(f) Integrity and confidentiality** | Ed25519 signatures + BLAKE3 hash chain provide integrity; TLS 1.3 in transit; operator-controlled at-rest encryption. |
| **5(2) Accountability** | The entire receipt chain is a tamper-evident audit trail demonstrating compliance with each principle for every processing operation. |

### Article 6 — Lawfulness of processing

IDprova does not establish lawful basis (that is the controller's responsibility), but it provides **evidence of which basis was relied upon for each action**. Operators encode the basis in DAT metadata or receipt fields and the chain proves which basis applied at the moment of processing.

### Article 25 — Data protection by design and by default

| Requirement | IDprova mapping |
|---|---|
| Pseudonymisation | `did:aid:` identifiers are pseudonymous by default. The link to a natural person (controller) is held in operator records, not in the protocol. |
| Data minimisation by default | Receipt schema includes only essential metadata; optional fields require explicit opt-in. |
| Limit accessibility of personal data | DAT scopes are least-privilege by construction. Wildcard scopes are explicit and auditable. |
| Effective technical measures | Cryptographic primitives (Ed25519, BLAKE3) provide defence-in-depth that survives storage compromise. |

### Article 30 — Records of processing activities

This is one of the most operationally significant GDPR articles for IDprova mapping.

GDPR Article 30 requires controllers and processors to maintain records of processing activities including:

| Required record | IDprova mapping |
|---|---|
| **Name and contact of controller / processor / DPO** | Stored in IDprova Cloud account configuration; reflected in DAT issuer fields for cryptographic linkage |
| **Purposes of the processing** | DAT `scope` field encodes purpose at delegation time; receipt records purpose at action time |
| **Categories of data subjects and personal data** | Recorded in operator's DPIA (out of IDprova's protocol scope); receipt fields can reference categories where configured |
| **Categories of recipients** | Delegation chains in DATs explicitly record every party that received data via agent action |
| **Transfers to third countries** | Receipt `region` field plus `geofencing` constraint capture cross-border transfers; DAT scope can restrict to specific country codes |
| **Time limits for erasure** | DAT `exp` field; receipt log retention configuration |
| **General description of technical and organisational security measures** | Defined in operator's SSP; cryptographic measures attested to by the protocol |

In practice: an Article 30 register entry for an IDprova-instrumented system can reference the receipt log for "evidence of the technical measures applied to each processing operation" — a level of specificity that pre-IDprova systems generally cannot provide.

### Article 32 — Security of processing

The other most operationally significant article.

| 32(1) requirement | IDprova mapping |
|---|---|
| **(a) Pseudonymisation and encryption of personal data** | did:aid: identifiers are pseudonymous; Ed25519 + ML-DSA-65 hybrid signing; TLS 1.3 transport; operator-controlled at-rest encryption with key management per [key-rotation.md](key-rotation.md) |
| **(b) Ongoing confidentiality, integrity, availability, resilience** | Hash-chained receipts provide integrity; multi-region Cloud roadmap addresses availability and resilience; confidentiality through scope-limited DATs |
| **(c) Restore availability and access in timely manner** | Receipt log is append-only and replicable; supports operator backup and DR practices |
| **(d) Process for regular testing, assessing, evaluating effectiveness** | `ReceiptLog::verify_integrity()` provides continuous integrity verification; threat model published and updated; security advisory process |

### Article 33 — Notification of personal data breach to supervisory authority

GDPR requires breach notification within 72 hours of becoming aware. IDprova helps operators meet this in three ways:

1. **Detection:** receipt-pattern anomaly detection (IDprova Cloud Pro+ feature) surfaces suspect agent behaviour in near-real-time.
2. **Forensics:** the receipt chain provides immutable evidence of what was accessed, when, by which agent, under whose delegation. Supports a precise breach scope determination.
3. **Reporting:** [receipt forensics export feature](../../IDProva_Ecosystem_Plan_2026-05-05.md) (planned v1.0) generates legal-grade JSON/PDF export bundles suitable for supervisory authority submission.

### Article 35 — Data Protection Impact Assessment (DPIA)

For high-risk processing, controllers must conduct a DPIA. IDprova supports DPIA documentation by providing:

- Structured records of the **necessity and proportionality** of processing operations (DAT scope grammar makes this explicit)
- Evidence of **measures envisaged to address the risks** (receipt chain, scope limitations, revocation, audit)
- A reference architecture for **agent-based processing** that DPOs can use as the technical baseline of their DPIA

IDprova provides a DPIA template aligned with EDPB recommendations as part of the GDPR compliance pack (v1.0 launch deliverable).

### Articles 12-22 — Data subject rights

IDprova receipts contain the data necessary for a controller to respond to data subject access requests (DSARs):

| Right | IDprova support |
|---|---|
| **15 — Access** | Query receipts by `user_principal` field to surface all agent actions involving a data subject |
| **16 — Rectification** | Out of protocol scope (data correction is in the source system, not the receipt log) |
| **17 — Erasure** | Receipts are tamper-evident, so cannot be silently erased; legal-grade erasure of associated source data is operator's responsibility. The receipt itself remains as evidence the action occurred. |
| **18 — Restriction** | DAT revocation (`POST /v1/dat/revoke`) immediately restricts further processing under that delegation |
| **20 — Portability** | Receipt log export in machine-readable JSON; per-user receipt subsets exportable |
| **21 — Objection** | Operator implements; revocation of the DAT executing the objected-to processing is the immediate action |

### Article 44-50 — Transfers to third countries

For EU controllers transferring data to non-EU third countries:

- IDprova Cloud regional deployment ensures data **does not transit** out of the chosen region during normal operation.
- For controllers requiring no US-Cloud-Act exposure: deploy in EU Frankfurt region (planned v1.0 launch); self-hosted Enterprise Edition for full sovereign deployment.
- Receipt `region` field cryptographically witnesses where each action was processed — supports compliance with **Schrems II** Standard Contractual Clauses (SCCs) by providing audit evidence of where data was processed.
- Cross-border transfer to a country with adequate protection: documented in receipt metadata.

---

## Data Processing Agreement (DPA)

For IDprova Cloud customers in the EU/EEA/UK who require a DPA per Article 28:

- Standard DPA template available at idprova.com/dpa (v1.0 launch deliverable)
- Includes Standard Contractual Clauses for international data transfers (Schrems II compliant)
- Sub-processor list maintained at idprova.com/sub-processors (transparency obligation)
- 30-day notice period for sub-processor changes
- Customer audit rights specified
- Breach notification within 24 hours of detection (faster than GDPR's 72-hour requirement to controller)

For self-hosted Enterprise Edition, no DPA is required between Tech Blaze and the customer because no personal data is processed by Tech Blaze; the customer operates the registry themselves.

---

## What IDprova does NOT cover for GDPR

Operators retain responsibility for:

- Lawful basis determination (Article 6) — IDprova captures which basis was relied upon, but does not validate the legal correctness
- Privacy notice content (Article 13/14) — operator's own privacy policy
- Consent management — separate consent management platform (CMP) integration
- Joint controller agreements (Article 26) — when multiple parties share controllership of agent-processed data
- DPO appointment (Article 37-39) — operator's organisational responsibility
- Codes of conduct and certification (Articles 40-43) — operator's external commitments
- The substantive lawfulness of the processing operation itself

IDprova provides verifiable evidence of *what* happened. The lawfulness of *whether* it should have happened is the operator's question.

---

## EU AI Act considerations (Regulation (EU) 2024/1689)

The EU AI Act applies in addition to GDPR for AI-specific contexts. For IDprova-instrumented systems:

- **High-risk AI systems** (Art 6 + Annex III): IDprova receipts provide the **logging requirements** (Art 12) — automatic logging of agent operations throughout the system lifecycle
- **Transparency obligations** (Art 13 + 50): identity of the AI system (its `did:aid:`) is cryptographically verifiable
- **Human oversight** (Art 14): DAT revocation provides immediate intervention capability; receipt anomaly alerts support human review
- **Accuracy, robustness, cybersecurity** (Art 15): receipt chain integrity provides cybersecurity evidence; chain of authority supports accuracy attribution

The interaction between GDPR and the AI Act for AI agents is still being clarified by the European Data Protection Board. IDprova's evidence-producing posture is intended to support compliance with both regimes regardless of how the regulatory clarifications resolve.

---

## References

- Regulation (EU) 2016/679 (GDPR)
- Regulation (EU) 2024/1689 (AI Act)
- EDPB Guidelines 4/2019 on Article 25 (Data Protection by Design and by Default)
- EDPB Guidelines 9/2022 on Personal Data Breach Notification
- Schrems II — Court of Justice judgment in Case C-311/18 (2020)
- ICO Guidance on AI and data protection (UK)
- CNIL guidance on AI systems (FR)
- IDprova `compliance.md` (NIST SP 800-207 + ISM mapping)
- IDprova `controls.md` (NIST SP 800-53 Rev 5 mapping)
- IDprova `key-rotation.md` (key management procedures)
- IDprova `STRIDE-THREAT-MODEL.md`
