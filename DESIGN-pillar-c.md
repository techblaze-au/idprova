# Pillar C — `idprova-vc` Design Document

**Author:** Claude (orchestrator)
**Builder:** GLM (z.ai)
**Date:** 2026-06-25
**Status:** DESIGN-ONLY Skeleton

## 1. Mission & Positioning
The `idprova-vc` crate provides a W3C Verifiable Credentials (Data Model 2.0) interop layer on top of the existing Delegation Attestation Token (DAT) runtime. 

Its goal is to allow IDProva agents to participate in external identity and commerce rails—specifically **Google AP2 / Agent2Agent (A2A)** and **EUDI-style wallets**—without abandoning IDProva's deterministic-verify moat. 

**Core Philosophy:** DAT remains the execution-integrity primitive (handling capabilities and authorization). VC is strictly an **interop projection** (handling attestations and identity) mapped via a deterministic bridge. The LLM never touches cryptographic bytes.

## 2. Standards Alignment
- **W3C VC Data Model 2.0**: JSON-LD `@context` (`https://www.w3.org/ns/credentials/v2`), `type`, `issuer`, `validFrom`/`validUntil`, `credentialSubject`, `credentialStatus`.
- **Data Integrity Proofs**: 
  - Default: **`eddsa-jcs-2022`** (Ed25519 over RFC 8785 JCS). Reuses the workspace `serde_json_canonicalizer`. Avoids the URDNA2015 `@context` fragility documented in the TU-Berlin failure.
  - Opt-in (`rdfc-interop` feature): `eddsa-rdfc-2022` (RDF canonicalization).
  - Opt-in (`ecdsa-interop` feature): **`ecdsa-rdfc-2019`** (P-256). Required for AP2 compliance.
- **Revocation**: `credentialStatus` = **StatusList 2021 / Bitstring Status List**.
- **Presentation**: **DIF Presentation Exchange** (`presentation_definition`, `presentation_submission`).

## 3. Cryptosuite / Feature Matrix

| CryptoSuite | Features Required | Canonicalization | Signature Alg | Use Case |
|-------------|-------------------|------------------|---------------|----------|
| `EddsaJcs2022` | *(default)* | RFC 8785 (JCS) | Ed25519 | Standard IDProva interop (deterministic, safe) |
| `EddsaRdfc2022`| `rdfc-interop` | URDNA2015 | Ed25519 | Strict JSON-LD interop |
| `EcdsaRdfc2019`| `ecdsa-interop`, `rdfc-interop` | URDNA2015 | ECDSA P-256 | Google AP2 / Agent2Agent (A2A) rails |

## 4. DAT ↔ VC Mapping Table
The bridge maps IDProva runtime concepts into W3C VC attestations. This mapping is **lossy by design** because DAT encodes *authorization/capability* while VC encodes *identity/attestation*.

| IDProva (DAT) | W3C VC |
|---------------|--------|
| `DatClaims.iss` (Delegator DID) | `issuer` |
| `DatClaims.sub` (Agent DID) | `credentialSubject.id` |
| `DatClaims.scope` (Vec<String>) | `credentialSubject.scopes` |
| `DatClaims.constraints` | `credentialSubject.constraints` |
| `trust::level` | `credentialSubject.trustLevel` / `evidence` |
| `DatClaims.exp` | `validUntil` |
| `DatClaims.iat` | `validFrom` / `issuanceDate` |

**Reverse Mapping (`vc_to_dat_claims`):** Extracts `iss`, `sub`, `scope`, `constraints`, and `exp` from the VC if the schema matches the IDProva profile. Returns `None` if unmappable.

## 5. AP2 Intent Mandate Example
Google AP2 mandates are JSON-LD VCs signed with ECDSA P-256, transmitted over A2A.

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2", "https://schema.org/"],
  "type": ["VerifiableCredential", "IntentMandate"],
  "issuer": "did:web:agent.idprova.dev",
  "credentialSubject": {
    "id": "did:web:merchant.example",
    "intent": "purchase_checkout",
    "transactionId": "tx_12345"
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "ecdsa-rdfc-2019",
    "proofValue": "z3X... "
  }
}
```

## 6. DIF Presentation Exchange Example
```json
{
  "presentation_definition": {
    "id": "pd_ap2_intent",
    "input_descriptors": [{
      "id": "ap2_intent",
      "constraints": { "fields": [{ "path": ["$.type"], "filter": { "const": "IntentMandate" } }] }
    }]
  }
}
```

## 7. Test Matrix
- `test_issue_verify_roundtrip`: A VC issued by `VcIssuer` passes `VcVerifier::verify`.
- `test_tampered_vc_rejected`: Modifying `credentialSubject` invalidates the proof.
- `test_revoked_statuslist_rejected`: A VC with a revoked `credentialStatus` entry fails `verify`.
- `test_dat_to_vc_preserves_scope`: `dat_to_vc` correctly maps `ScopeSet` to `credentialSubject`.
- `test_ap2_intent_shape`: `to_ap2_mandate(Intent)` yields the correct VC profile shape.
