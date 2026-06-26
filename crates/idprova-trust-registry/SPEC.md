# Pillar B — `idprova-trust-registry` — SPEC (design intent for GLM codegen)

> **Author:** Claude (orchestrator/design). **Builder:** GLM (z.ai). **Scope this round:**
> DESIGN-ONLY — public API + types + doc comments + `todo!()` bodies + test stubs, `cargo check`
> clean. **Founder decision applied:** start with a **curated** trust-list AND ship the
> **federation spec** in parallel (skeleton + DESIGN section, not full impl).

## 1. Mission & positioning
The **neutral, vendor-neutral, chain-agnostic Issuer Trust Registry + cross-standard resolver** —
the verified whitespace: *"no vendor-neutral, multi-operator agent registry exists"* (Visa's
directory is Visa's; Cloudflare's is Cloudflare/IETF; Microsoft's is the Entra tenant). It answers the
**TU Berlin unsolved governance gap**: *"how trustworthy issuers are determined and their DIDs shared
among security domains."* Two jobs:
1. **Issuer trust authority** — a curated, signed, offline-verifiable list of *who may attest to /
   vouch for an agent* (sovereign/air-gapped friendly).
2. **Cross-standard resolver** — resolve one agent across **Web Bot Auth keyid**, **AP2 issuer DID**,
   **MCP OAuth client_id**, **Entra agent object**, all → a canonical `did:aid:`.

## 2. Standards & anchors (verified 2026-06-25)
- Trust-list model in the spirit of **ETSI TS 119 612 / EU LOTL** (curated, signed authority lists),
  re-cast for agent issuers, `did:aid:`-native.
- **Federation (the neutrality proof):** an **append-only, signed, mirrorable** trust log with
  **Merkle consistency proofs** (à la Certificate Transparency signed tree heads) so any operator can
  **mirror** without a central gatekeeper — this is what makes "neutral/decentralized" *provable*, not
  promised. Ship the **spec** now, implement later.
- Sovereign mode: the signed TrustList must verify fully **offline** (no network, no chain).

## 3. Crate & placement
- New service crate `crates/idprova-trust-registry` (axum), complements existing `idprova-registry`
  (which is the AID/revocation registry — do not duplicate it; this is the *issuer-trust* layer).
- Reuse `idprova-core`: `trust::level` (L0–L4), `crypto` (Ed25519 + BLAKE3 for Merkle), `aid`,
  `http::validate_registry_url`. Persistence via `rusqlite` + `r2d2` like `idprova-registry`.

## 4. Public API surface (modules → key items, `todo!()` bodies)
- `mod model` — `Issuer { did, name, jurisdiction, status: IssuerStatus (Active|Suspended|Revoked),
  trust_level: idprova_core::trust::level::TrustLevel, credential_types: Vec<String>, valid_from,
  valid_until }`; `TrustList { version, sequence, issued_at, entries: Vec<Issuer>, proof: Option<Proof> }`;
  `SignedTrustList { list, signature, signer_keyid }`.
- `mod store` — `trait TrustStore { upsert_issuer, get_issuer, list_issuers, may_attest(issuer_did,
  claim_type) -> bool }`; `struct SqliteTrustStore`.
- `mod authority` — **curated mode**: `TrustAuthority { signing_key }`;
  `fn publish(&self, store) -> SignedTrustList` — canonicalize via **RFC 8785 JCS**
  (`serde_json_canonicalizer`) then Ed25519-sign; `fn verify_signed_list(list, key) -> bool`
  (offline-verifiable).
- `mod federation` — **spec + skeleton**: `FederationPeer { url, pubkey }`; `SignedTreeHead { size,
  root_hash, sequence, signature }`; `fn append(entry) -> SignedTreeHead`;
  `fn prove_consistency(old_size, new_size) -> ConsistencyProof`; `fn verify_consistency(old_sth,
  new_sth, proof) -> bool`; `fn mirror(peer) -> Result<...>`. Bodies `todo!()`; the *protocol* is
  fully described in the DESIGN doc's FEDERATION-SPEC section.
- `mod resolver` — `enum AgentRef { DidAid(String), WebBotAuthKey { keyid, directory_url },
  Ap2Issuer(String), McpClient(String), EntraAgent(String) }`;
  `trait ResolverBackend { fn try_resolve(&self, AgentRef) -> Option<ResolvedAgent> }`;
  `struct CrossStandardResolver { backends }`; `ResolvedAgent { did_aid, attestations:
  Vec<Attestation>, trust_status }`. Outbound lookups use SSRF-safe http.
- `mod api` — axum router: `GET /trust-list` (signed, cacheable), `GET /issuers/:did`,
  `GET /issuers?claim_type=`, `POST /resolve` (AgentRef → ResolvedAgent), `GET /healthz`. Stub handlers.

## 5. Dependencies
`idprova-core` (path), `axum`, `tower`, `tower-http`, `serde`, `serde_json`,
`serde_json_canonicalizer`, `rusqlite`, `r2d2`, `r2d2_sqlite`, `ed25519-dalek`, `blake3`, `chrono`,
`thiserror`, `anyhow`. Dev: `proptest`, `tempfile`.

## 6. Design decisions to encode
1. **Curated-first, federation-ready** — one signed `TrustList` anyone can fetch and verify **offline**
   (sovereign/PROTECTED/air-gapped); the federation log is specced + skeletoned now so the neutrality
   claim is backed by a concrete protocol, switched on later without a re-architecture.
2. **`did:aid:` as the canonical key** — every external standard ref normalizes to it; this is the
   cross-standard "one identity, many envelopes" value the giants structurally can't offer.
3. **Deterministic, offline-verifiable** — no LLM, no mandatory chain; Merkle via BLAKE3 (already a
   core dep). Federation consistency = CT-style proofs.
4. **Separation from `idprova-registry`** — that crate is AID lifecycle/revocation; this is *issuer
   trust governance*. Clear boundary, documented.

## 7. What GLM must output
- `DESIGN-pillar-b.md`: architecture; the curated TrustList JSON example + signature flow; a full
  **FEDERATION-SPEC** section (append-only log, signed tree head, consistency + inclusion proofs,
  mirror handshake, threat model); the cross-standard resolver mapping table (WBA / AP2 / MCP / Entra →
  did:aid); API reference; test matrix.
- The `crates/idprova-trust-registry` skeleton — all items above, doc comments, `todo!()` bodies,
  `cargo check` clean; `#[ignore]`d test stubs (sign+verify list; may_attest; resolver normalize;
  consistency-proof placeholder).
- Edit root `Cargo.toml` to add the member.

## 8. Hard constraints
DESIGN-ONLY, deterministic, no secrets, match workspace style, keep tight. Federation = spec + stubs,
not a working log this round.
