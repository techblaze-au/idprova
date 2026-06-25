# Pillar C — `idprova-vc` — SPEC (design intent for GLM codegen)

> **Author:** Claude (orchestrator/design). **Builder:** GLM (z.ai). **Scope this round:**
> DESIGN-ONLY — public API + types + doc comments + `todo!()` bodies + test stubs, `cargo check`
> clean. The whole point is **deterministic** VC handling (the TU-Berlin failure proves crypto must
> stay out of the LLM).

## 1. Mission & positioning
A **W3C Verifiable Credentials (Data Model 2.0) interop layer on top of DAT** — issue/verify VCs
(JSON-LD), a **DIF Presentation Exchange** adapter, and a **deterministic DAT↔VC mapping** so IDProva
plugs into **Google AP2 / Agent2Agent (A2A)** and EUDI-style rails **without abandoning the DAT
runtime**. DAT stays the execution-integrity primitive; VC is an **interop projection** over it. This
closes the gap-analysis "Critical" item (format/protocol mismatch + the *attestation* half of KYA)
while keeping IDProva's deterministic-verify moat.

## 2. Standards alignment (verified 2026-06-25 — build to these exactly)
- **W3C VC Data Model 2.0**: JSON-LD `@context` (`https://www.w3.org/ns/credentials/v2`), `type`,
  `issuer`, `validFrom`/`validUntil`, `credentialSubject`, `credentialStatus`.
- **Data Integrity proofs**: default **`eddsa-jcs-2022`** (Ed25519 over **RFC 8785 JCS** — matches
  IDProva's curve *and* the workspace's existing `serde_json_canonicalizer`, and sidesteps the
  URDNA2015 `@context`-resolution failures the TU-Berlin paper documented). Provide `eddsa-rdfc-2022`
  and **`ecdsa-rdfc-2019` (P-256)** behind a `rdfc-interop` / `ecdsa-interop` feature for strict
  JSON-LD + **AP2** interop (AP2 mandates sign ECDSA P-256).
- **Revocation:** `credentialStatus` = **StatusList 2021 / Bitstring Status List** — checked at
  verify time (closes gap #6: verify-time freshness baked into the SDK call).
- **DIF Presentation Exchange**: `presentation_definition` + `presentation_submission`.
- **Google AP2 Mandates** (Intent / Cart / Payment) are W3C VCs (JSON-LD, ECDSA P-256) carried over
  A2A/JSON-RPC — provide typed mandate builders so IDProva agents can participate in the 60+-partner
  rail.

## 3. Crate & placement
- New crate `crates/idprova-vc`; add to root `Cargo.toml` `members`.
- Reuse `idprova-core`: `dat::token::{Dat, DatClaims, DatHeader}`, `dat::scope::ScopeSet`,
  `dat::constraints::DatConstraints`, `aid` (issuer/subject DIDs), `crypto` (Ed25519), `trust::level`.
  Do not reimplement crypto or DAT.

## 4. Public API surface (modules → key items, `todo!()` bodies)
- `mod model` — `VerifiableCredential` (VC DM 2.0 fields), `VerifiablePresentation`,
  `DataIntegrityProof { type_, cryptosuite, created, verification_method, proof_purpose,
  proof_value }`, `CredentialStatus` (StatusList2021 entry), `enum CryptoSuite { EddsaJcs2022,
  EddsaRdfc2022, EcdsaRdfc2019 }`.
- `mod issue` — `VcIssuer { issuer_did, signing_key, suite }`;
  `fn issue(&self, subject, claims, valid_until, status) -> VerifiableCredential` — **deterministic**
  (canonicalize per suite → sign). Default suite EddsaJcs2022 via `serde_json_canonicalizer`.
- `mod verify` — `VcVerifier`; `trait IssuerResolver { fn verifying_key(issuer_did) -> Option<...> }`;
  `trait StatusResolver { fn is_revoked(status) -> bool }`;
  `fn verify(&self, vc, issuer_resolver, status_resolver, now) -> VcVerifyOutcome` — signature +
  validity window + **StatusList revocation** + issuer-trust hook. LLM never touches bytes.
- `mod presentation` — DIF Presentation Exchange: `PresentationDefinition`, `InputDescriptor`,
  `PresentationSubmission`; `fn build_submission(def, creds) -> (VerifiablePresentation, Submission)`;
  `fn evaluate(def, vp) -> EvalOutcome`.
- `mod dat_bridge` — **the crux**: `fn dat_to_vc(dat: &Dat, issuer_did) -> VerifiableCredential`
  (map `ScopeSet` + `DatConstraints` → `credentialSubject` capability claims; `trust::level` →
  evidence) and `fn vc_to_dat_claims(vc) -> Option<DatClaims>` (where mappable). Mapping is
  **lossy-by-design and documented** (DAT = capability/authorization; VC = attestation/identity).
- `mod ap2` — typed **AP2 mandate** builders: `IntentMandate`, `CartMandate`, `PaymentMandate` as VC
  profiles; `fn to_ap2_mandate(kind, ...) -> VerifiableCredential`. Forward bridge into AP2/A2A.

## 5. Dependencies
`idprova-core` (path), `serde`, `serde_json`, `serde_json_canonicalizer`, `ed25519-dalek`, `base64`,
`chrono`, `thiserror`. Optional behind features: `p256` (`ecdsa-interop`), an RDF canonicalizer
(`rdfc-interop`, may stay `todo!()` this round). Dev: `proptest`.

## 6. Design decisions to encode ("futuristic + definitely-work")
1. **`eddsa-jcs-2022` as default** — deterministic, Ed25519, reuses the workspace canonicalizer, and
   avoids JSON-LD URDNA2015 `@context` fragility (the exact failure TU-Berlin hit). Strict JSON-LD /
   AP2-ECDSA suites are opt-in features so we interop without taking on that fragility by default.
2. **DAT is the runtime; VC is a projection** — two-way bridge documented as lossy; we never replace
   the DAT verify path, we *expose* it as portable VCs for the rails.
3. **Verify-time revocation** — StatusList check is part of `verify`, not an afterthought.
4. **AP2-ready** — Intent/Cart/Payment mandate profiles so an IDProva agent can present into the
   60+-partner Google rail on day one of build.

## 7. What GLM must output
- `DESIGN-pillar-c.md`: architecture; a VC DM 2.0 example with an `eddsa-jcs-2022` proof; the
  cryptosuite/feature matrix; the **DAT↔VC mapping table** (scope/constraints/trust-level →
  credentialSubject, and the documented lossy reverse); the AP2 Intent-mandate example; a DIF PE
  example; test matrix.
- The `crates/idprova-vc` skeleton — all items above, doc comments, `todo!()` bodies, `cargo check`
  clean; `#[ignore]`d test stubs (issue→verify round trip; tampered VC rejected; revoked-via-StatusList
  rejected; `dat_to_vc` preserves scope; AP2 Intent shape).
- Edit root `Cargo.toml` to add the member.

## 8. Hard constraints
DESIGN-ONLY, deterministic (LLM-out-of-loop), no secrets, match workspace style, keep tight. RDF
canonicalization may remain `todo!()` behind a feature this round; JCS path is the real default.
