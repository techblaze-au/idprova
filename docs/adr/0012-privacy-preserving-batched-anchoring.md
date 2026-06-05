# 0012 — Privacy-preserving batched transparency anchoring

* **Status:** Proposed (design approved by Pratyush 2026-06-03; written ADR awaiting final sign-off)
* **Date:** 2026-06-04
* **Authors:** IDProva engineering
* **Related:** ADR 0011 (individual Rekor anchoring); `crates/idprova-core/src/receipt/commitment.rs`, `merkle.rs`, `batch.rs`, `guardrails.rs`; `crates/idprova-core/src/receipt/anchor.rs` (`TransparencyAnchor`, `TransparencyLog`)

---

## Context

ADR 0011 shipped **individual** anchoring: for each Action Receipt, `SHA-512(canonical signing payload)` is submitted to Sigstore Rekor as a `hashedrekord` (Ed25519ph). An adversarial review run **before** implementing the live-on-by-default flow surfaced two load-bearing flaws:

1. **Privacy.** A raw hash of a potentially low-entropy receipt payload, placed on a *permanent, public* append-only log, is brute-forceable: an observer who can guess the structure of an action (agent DID, tool, target, small input space) can confirm-by-hashing and correlate activity across time. On a permanent log this is irreversible — a deanonymisation/GDPR exposure that grows with adoption.
2. **Public-good abuse.** Anchoring *every* receipt turns the free, CI-sized public `rekor.sigstore.dev` into a per-action telemetry sink. At agent volumes this is both abusive of a shared public good and operationally fragile (rate limits, availability).

ADR 0011 anticipated the second point — its Alternatives #6 explicitly deferred "batched Merkle root" anchoring to a follow-up ADR. This is that ADR, and it additionally closes the privacy gap by anchoring an opaque commitment rather than a recoverable hash.

## Decision

Locked and founder-approved 2026-06-03.

**(a) Default OFF, opt-in.** `IDPROVA_ANCHOR_ENABLED=false` by default; both `AnchorConfig::default()` and `AnchorConfig::from_env()` produce a disabled config. When enabled, anchoring is opt-in per receipt (high-value actions only), never blanket-on-every-receipt. A kill-switch (`IDPROVA_ANCHOR_KILL_SWITCH`) hard-disables anchoring regardless of `enabled`.

**(b) Anchor a commitment, never the raw hash.** The leaf is

```
leaf = HMAC-SHA512(k, canonical_signing_payload)
k    = HKDF-SHA512(salt = nonce, ikm = tenant_key, info = "idprova/anchor/commitment/v1")
```

`nonce` is a fresh 32-byte random value stored with the receipt. `tenant_key` is a per-tenant secret held in the registry/KMS and **never logged** (no struct in this change stores or `Debug`-prints it; it is passed transiently to `commit()`). Because the key is per-tenant and the nonce is per-receipt, the value on the public log is an opaque commitment — the payload is unrecoverable even for low-entropy actions, and commitments are uncorrelatable without the tenant key.

**(c) Batch and anchor only the Merkle root.** Commitment leaves accumulate into an RFC-6962-style SHA-512 Merkle tree:

* leaf hash = `SHA512(0x00 || commitment)`
* node hash = `SHA512(0x01 || left || right)`
* an odd last node at any level is carried up unchanged (not duplicated).

The `0x00`/`0x01` domain tags give second-preimage resistance. The batch flushes on **whichever comes first: 256 leaves OR 60 seconds** (both configurable). Only the **root** is submitted to Rekor — one `hashedrekord` per batch. Each receipt stores its Merkle inclusion proof and the batch's Rekor `logIndex` (carried in `anchored_sha512` + `merkle_proof` on its `TransparencyAnchor`).

**(d) Offline verification.** Given `(payload, nonce, tenant_key)` and the stored anchor:

1. recompute `commitment = HMAC-SHA512(HKDF(tenant_key, nonce), payload)`;
2. verify the Merkle inclusion proof for that commitment against the anchored root (`merkle_proof.root == anchored_sha512`);
3. confirm the root itself is in the public log via Rekor's inclusion proof / SET at the `logIndex`.

Steps 1–2 are fully offline (`verify_commitment_anchor`); step 3 reuses the existing ADR-0011 Rekor verification path. A verifier without the tenant key cannot recompute the commitment — it can only confirm a presented `(payload, nonce)` is or isn't the committed one.

**(e) Release-blocking guardrails.** Live anchoring must be fire-and-forget (off the receipt hot path — an unreachable log leaves a valid, simply-unanchored receipt); guarded by a circuit-breaker with jittered exponential backoff, a kill-switch, and a per-minute rate budget; and instrumented with metrics counters. These are implemented as pure, clock-injected policy types (`CircuitBreaker`, `jittered_backoff_secs`, `RateBudget`, `AnchorMetrics`).

**(f) Trait unchanged.** The `TransparencyLog` trait from ADR 0011 is untouched — commitment derivation and batching sit *above* it. The self-hostable-log roadmap still holds. ADR 0012 changes **what** is submitted (a batch commitment-root) and **how often** (once per batch), not the `hashedrekord` crypto contract (still `sha512` + Ed25519ph, per ADR 0011's implementation findings).

## Implementation

* **New modules** (`crates/idprova-core/src/receipt/`):
  * `commitment.rs` — `commit`, `derive_commitment_key`, `generate_nonce`, `commit_hex` (HMAC-SHA512 + HKDF-SHA512, infallible).
  * `merkle.rs` — `MerkleTree`, `InclusionProof` (offline `verify`), `leaf_hash`/`node_hash`; RFC-6962 domain separation; verification is panic-free and constant-time on the root compare.
  * `batch.rs` — `AnchorConfig` (default-OFF, env-driven), `BatchAccumulator` (caller-driven clock, 256/60s policy), `attach_commitment_evidence`, `verify_commitment_anchor`.
  * `guardrails.rs` — `CircuitBreaker` (Closed/Open/HalfOpen), `jittered_backoff_secs`, `RateBudget` (per-minute token bucket), `AnchorMetrics`.
* **Seam.** `TransparencyAnchor` gains two optional, serde-skipped fields — `nonce: Option<String>` and `merkle_proof: Option<InclusionProof>`. There is **no new `Receipt` field**, so the SDK constructors (`sdks/python`, `sdks/typescript`) and the v0.1/v0.2 wire format are unchanged; raw-hash (ADR-0011) anchors serialise byte-identically. In commitment mode `anchored_sha512` holds the batch root and equals `merkle_proof.root`.
* **Dependencies.** Re-added RustCrypto `hmac = "=0.12.1"` and `hkdf = "=0.12.4"` (pinned exact per S6). This **reverses S7**, which had removed `hkdf` as an *unused* dependency; it is now load-bearing for a real cryptographic need.
* **Out of scope (deployment steps, intentionally not wired here):** the live root-submitter (async network submission of batch roots), the KMS fetch of tenant keys, per-tenant key rotation, and the production cutover (CT401 registry / Fly). This change lands the verifiable, fully unit-tested building blocks with anchoring default-OFF.
* **Verification.** `cargo fmt`, `cargo clippy --workspace -- -D warnings`, and `cargo test --workspace` all pass; the new logic is covered by unit tests including the offline commitment→root round-trip and wrong-key/wrong-payload rejection.

## Consequences

**Positive**
- Privacy: the public log holds only opaque commitments; payloads are unrecoverable and uncorrelatable without the tenant key.
- Abuse mitigation: one Rekor entry per batch (≤256 receipts / ≤60s), not one per action.
- Offline-verifiable: commitment→root is checkable with no network; root→log uses the existing Rekor path.
- Default-OFF + opt-in: zero behaviour change for existing adopters; no surprise telemetry.
- Wire-compatible seam: additive optional fields; existing receipts and SDKs unaffected.

**Negative / costs**
- More moving parts than ADR 0011's two-call-site wire: HMAC + HKDF + Merkle accumulator + inclusion proofs + guardrails.
- Tenant-key custody becomes a real requirement — a KMS/registry-held per-tenant secret, with rotation, that must never be logged.
- Verification now requires the `nonce` (stored) **and** the tenant key — third parties can verify a *presented* `(payload, nonce)` but cannot enumerate payloads.
- Batching adds up to ~60s latency before a receipt is anchorable (it becomes verifiable only once its batch root is anchored).

**Neutral / risk to validate at deployment**
- Live root-submission rate and availability against the public Rekor instance.
- KMS integration and the operational story for per-tenant key rotation (rotating a tenant key invalidates re-derivation for old receipts unless the historical key is retained for verification).

## Alternatives considered

1. **Status quo — per-receipt raw-hash (ADR 0011 as-shipped, on-by-default).** Rejected: the privacy and public-good-abuse flaws above.
2. **Salted hash instead of HMAC.** Rejected: `HMAC-SHA512` keyed by an `HKDF`-derived per-receipt key is a standard, well-analysed construction with clean key separation; an ad-hoc `H(salt || payload)` is weaker and easier to get wrong.
3. **Anchor every commitment individually (no batching), salted.** Rejected: fixes privacy but not public-good abuse — still one log entry per action.
4. **Encrypt payloads to the log.** Rejected: heavier, worse key management, and it is not the property we need — we want a tamper-evidence witness, not confidential storage.
5. **Blockchain / public-chain anchoring.** Rejected for the same reasons as ADR 0011 (cost, latency, throughput, operational/regulatory baggage; no verification property Rekor lacks).

## References

- ADR 0011 — Action Receipt transparency anchoring via Sigstore Rekor
- RFC 6962 — Certificate Transparency (Merkle tree leaf/node domain separation)
- RFC 5869 — HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- Sigstore Rekor — `hashedrekord` type, inclusion proofs, SET semantics
- ADR template: `docs/adr/README.md` (Michael Nygard format)
