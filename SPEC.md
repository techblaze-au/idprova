# Pillar A — `idprova-webbotauth` — SPEC (design intent for GLM codegen)

> **Author:** Claude (orchestrator/design). **Builder:** GLM (z.ai) — expand this into a
> DESIGN doc + a *compiling* Rust skeleton. **Scope this round:** DESIGN-ONLY — public API,
> types, doc comments, and `todo!()`/`unimplemented!()` bodies + `#[ignore]` test stubs.
> Everything must `cargo check` clean. No real network in the verify path.

## 1. Mission & positioning
Make an IDProva agent **speak the de-facto IETF agent-web-auth surface**: sign outbound HTTP
requests per **RFC 9421 (HTTP Message Signatures)** with **Ed25519**, publish a **key directory
(JWKS)** + **Signature Agent Card**, and **bind the signing key to a `did:aid:`**. Also verify
inbound signed requests deterministically. This is the "speak-the-protocol" posture: interop with
**Visa Trusted Agent Protocol (TAP)** and **Cloudflare Web Bot Auth** without ceding identity to an
operator-owned directory. `did:aid:` stays the canonical identity; Web Bot Auth is what we speak on
the wire.

## 2. Standards alignment (verified 2026-06-25 — build to these exactly)
- **RFC 9421** (published RFC). Signature base (§2.5) = ordered covered components, each on its own
  line `"<name>": <value>`, terminated by `"@signature-params": (...)`. Default covered set for an
  agent request: `@method`, `@authority`, `@path`, optional `@query`, plus any signed headers
  (e.g. `content-digest`). Params: `created`, `expires`, `keyid`, `alg="ed25519"`, optional `nonce`,
  `tag`. Output goes in two **RFC 8941 Structured Field** headers: `Signature-Input` (label →
  covered list + params) and `Signature` (label → byte-sequence signature).
- **Web Bot Auth** (`draft-meunier-web-bot-auth-architecture-05`, `…-directory-05`,
  `…-webbotauth-registry-01`): the **`Signature-Agent`** request header is a Structured **Dictionary**
  whose member value is a String Item URI pointing at the signer's directory. The **directory** is a
  **JWKS** served as media type `application/http-message-signatures-directory+json`. The
  **Signature Agent Card** is a JSON document advertising identity, purpose, contact, rate
  expectations, and keys.
- **Curve:** Ed25519 only (matches IDProva core + WBA + Visa TAP). 64-byte signatures, OKP/Ed25519 JWK.

## 3. Crate & placement
- New crate `crates/idprova-webbotauth`; add to root `Cargo.toml` `members`.
- Reuse `idprova-core`: `crypto` (Ed25519 sign/verify, BLAKE3), `aid` (did:aid + verification
  methods), `http::validate_registry_url` (SSRF-safe directory fetch). Do **not** reimplement crypto.

## 4. Public API surface (modules → key items, all `todo!()` bodies)
- `mod request` — `SignableRequest { method, authority, path, query, headers }` framework-agnostic
  abstraction (no hard tie to axum/reqwest). `trait IntoSignable`.
- `mod components` — `enum Component { Method, Authority, Path, Query, Header(String), SignatureParams }`;
  `fn build_signature_base(req, covered, params) -> String` (RFC 9421 §2.5, deterministic).
- `mod sfv` — thin RFC 8941 Structured Field ser/de for `Signature-Input` / `Signature` /
  `Signature-Agent`. **Decision:** use the `sfv` crate (add as dep) behind a small wrapper so the
  rest of the crate is parser-agnostic.
- `mod signer` — `HttpSigner { keyid, signing_key (ed25519_dalek::SigningKey via core::crypto), tag }`;
  `fn sign(&self, req: &SignableRequest, covered: &[Component], created, expires) -> SignatureHeaders`
  (returns the two header strings + the `Signature-Agent` value).
- `mod verifier` — `HttpVerifier`; `trait KeyResolver { fn resolve(keyid) -> Option<VerifyingKey> }`;
  `fn verify(&self, req, sig_input, sig, resolver, now) -> VerifyOutcome`. **Deterministic**: checks
  signature, `created`/`expires` window, covered-component completeness vs a required-set policy, and
  keyid→key binding. The LLM never touches bytes (this is the TU-Berlin anti-pattern fix, restated).
- `mod directory` — `KeyDirectory` (JWKS of Ed25519 JWKs) + `SignatureAgentCard { id: did:aid URI,
  purpose, contact, keys, rate }`; `fn to_jwks_json` / `fn media_type() -> "application/http-message-signatures-directory+json"`.
- `mod binding` — `fn bind_keyid_to_aid(keyid, aid: &Aid) -> KeyBinding` and the inverse; thumbprint
  the JWK (RFC 7638) for the keyid. Resolve a WBA keyid back to a `did:aid:`.

## 5. Dependencies (prefer `workspace = true`)
`idprova-core` (path), `ed25519-dalek`, `base64`, `serde`, `serde_json`, `chrono`, `thiserror`;
new: `sfv` (RFC 8941). Dev: `proptest`.

## 6. Design decisions to encode ("futuristic + definitely-work")
1. **Speak WBA on the wire, resolve to `did:aid:` internally** — we emit the exact artifacts the
   IETF WebBotAuth WG (standards-track, IESG target Apr 2026) defines, so when it lands we are already
   conformant, but identity remains neutral/sovereign, not Visa/Cloudflare-owned.
2. **Deterministic verify, optional directory fetch only** — any outbound directory fetch goes through
   `core::http::validate_registry_url`; verify itself is pure.
3. **Ed25519 reuse** — zero new crypto; `keyid` = RFC 7638 JWK thumbprint bound to the AID's
   verification method.
4. **Required-covered-set policy** — verify rejects signatures that omit `@method`/`@authority`/`@path`
   or whose `expires` is past; prevents downgrade/replay.

## 7. What GLM must output
- `DESIGN-pillar-a.md` at worktree root: architecture, the RFC 9421 signature-base worked example
  (Ed25519), the Web Bot Auth directory + agent-card JSON examples, the did:aid binding diagram, and a
  test matrix.
- The `crates/idprova-webbotauth` skeleton (Cargo.toml + src modules above) — every public item
  present with doc comments and `todo!()` bodies; **`cargo check` must pass**. Unit-test stubs (use
  the RFC 9421 Appendix-B Ed25519 vector as a `#[ignore]`d placeholder test).
- Edit root `Cargo.toml` to add the member.

## 8. Hard constraints
- DESIGN-ONLY: no real implementations beyond what's needed to compile. Prefer `todo!()`.
- Deterministic, LLM-out-of-loop. No secrets in code. Match workspace style (edition 2021, `thiserror`
  errors, `#![forbid(unsafe_code)]` if core does). Keep it tight.
