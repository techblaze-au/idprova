# 0011 — Action Receipt transparency anchoring via Sigstore Rekor

* **Status:** Accepted (approved by Pratyush 2026-05-31; v0.3 targets public rekor.sigstore.dev)
* **Date:** 2026-05-31
* **Authors:** IDProva engineering
* **Related:** roadmap item "RFC 0011 / v0.3 transparency anchor"; `crates/idprova-core/src/receipt/entry.rs` (`Receipt`, `ChainLink`); `crates/idprova-core/src/receipt/log.rs` (`ReceiptLog::append`, `verify_integrity`); ADR 0003 (tenant boundary); IDProva Protocol Spec §Action Receipts

---

## Context

An IDProva **Action Receipt** records that an agent (identified by a `did:aid:`) performed an action under the authority of a DAT. Receipts are today, per `receipt/entry.rs` and `receipt/log.rs`:

1. **Hash-chained** — each `Receipt` carries a `ChainLink { previous_hash, sequence_number }`; `compute_hash()` is a BLAKE3 over the canonical signing payload (the receipt minus its signature, per the S3 fix).
2. **Signed** — each receipt carries an Ed25519 `signature` produced by the agent's key over that same payload.
3. **Integrity-checkable** — `ReceiptLog::verify_integrity_with_key()` walks the chain, checking sequence numbers, `previous_hash` linkage, and the per-entry signature.

This makes a receipt log **tamper-evident to a verifier who already holds the authentic log** — if someone mutates an entry, the chain hash and the signature break. It does **not** make the log tamper-evident **against the party that holds and serves the log**. The log holder (agent host, registry, or SaaS tenant) controls the agent key material in many deployment shapes, or can simply re-issue the whole chain. There is no independent, append-only witness that a given receipt existed at a given time. So the product claim "tamper-evident audit trail" is, today, only true *within a trust boundary we also control* — which is the weakest possible version of the claim and the one a serious adopter (or an auditor) will discount.

The forces in play:

1. **Trust must not terminate at the operator.** The differentiator is that a third party — a regulator, a counterparty agent, an insurer — can verify a receipt *without trusting IDProva or the agent host*. That requires an external witness.
2. **Privacy.** Receipts contain `did:aid:` identifiers, action types, target servers/tools, and input/output hashes. The witness must learn as little as possible — ideally only an opaque hash.
3. **Availability / offline operation.** Receipt creation must not hard-depend on a network call to a third-party log; agents run in air-gapped and intermittently-connected environments. Anchoring must degrade gracefully.
4. **Implementer surface.** `idprova-core` is the public protocol shipped to third-party SDKs. Anything mandatory here becomes a conformance burden for every implementer. Anchoring should be **optional and pluggable**, not a hard protocol requirement.
5. **Don't reinvent transparency.** Sigstore **Rekor** is a production-grade, widely-operated, append-only, Merkle-tree transparency log with signed checkpoints, signed entry timestamps (SETs), and inclusion proofs. Certificate Transparency, a bespoke Merkle service, or a blockchain are the alternatives (see below).

## Decision

Introduce an **optional transparency anchor** for Action Receipts that records, in an external append-only transparency log (**Sigstore Rekor**), a commitment to each receipt, and store the returned inclusion evidence on the receipt. Concretely:

1. **What is anchored.** The **SHA-512 of the canonical signed receipt payload** — i.e. SHA-512 over the exact bytes the Ed25519 `signature` already covers (`ReceiptSigningPayload`). The internal chain keeps BLAKE3; SHA-512 is computed *in addition*, only for Rekor. (Originally specified as SHA-256; the implementation spike — see Implementation findings — established that Rekor's Ed25519 `hashedrekord` path requires SHA-512.) **Only this hash leaves the trust boundary** — no DID, action, or payload content is transmitted to Rekor.

2. **Entry type & signer.** Submit a Rekor **`hashedrekord`** entry binding `{ data.hash = sha512, signature = a dedicated Ed25519ph signature, publicKey = the agent's Ed25519 public key }`. **No new operator key is introduced for v0.3** — the anchor signature is produced with the *agent's existing Ed25519 key*, but as a separate **Ed25519ph** (pre-hashed, SHA-512) signature over the payload — NOT the receipt's pure-Ed25519 `signature`, which Rekor's Ed25519 verifier rejects (see Implementation findings). `ed25519-dalek::sign_prehashed` produces this natively. The agent identity binding is preserved (same key); only the signature variant differs.

3. **Pluggable transport.** Define a `TransparencyLog` trait in `idprova-core` (e.g. `submit(entry) -> AnchorReceipt`, `verify(anchor, sha256) -> bool`). Ship one implementation, `RekorV1Client`, targeting the public good instance `https://rekor.sigstore.dev` for v0.3. The trait keeps a self-hosted Rekor, a Rekor v2 tile-backed instance, or a per-tenant log swappable without touching the receipt model or SDKs.

4. **Receipt model change (the seam).** Add an **optional** `anchor` field to `Receipt`:
   ```
   #[serde(skip_serializing_if = "Option::is_none")]
   pub anchor: Option<TransparencyAnchor>,
   // { log: "rekor", instance_url, log_index, entry_uuid,
   //   integrated_time, signed_entry_timestamp (SET), inclusion_proof,
   //   anchored_sha256 }
   ```
   `anchor` is **excluded from `ReceiptSigningPayload` and `compute_hash()`** — it is metadata recorded *after* the receipt is signed and chained, so including it would create a circular dependency identical to the S3 bug. The chain hash and signature are computed first; anchoring happens after.

5. **Best-effort, non-blocking anchoring.** `ReceiptLog::append()` MUST NOT block on the network. Anchoring is performed out-of-band (caller-driven `anchor_pending()` / background submit) so an unreachable Rekor leaves a valid, unanchored receipt rather than failing the action. Unanchored receipts are valid; `anchor` is simply `None`.

6. **Verification flow.** Independent verification of an anchored receipt:
   a. Recompute SHA-256 over the receipt's canonical signing payload; assert it equals `anchor.anchored_sha256`.
   b. Verify the Ed25519 `signature` over that payload with the receipt's agent key.
   c. Verify the Rekor **SET** against Rekor's published public key, and the **inclusion proof** against the log checkpoint, for `log_index`/`entry_uuid`.
   d. Conclude: *this agent signed this receipt no later than `integrated_time`, witnessed by an append-only log neither the agent nor IDProva controls.* This is verifiable **offline** given a cached Rekor public key + checkpoint — no live call to the operator required.

7. **Scope of v0.3.** Public-instance `hashedrekord` anchoring + the `anchor` field + an offline verifier + a live end-to-end test. Batching/Merkle-aggregation of many receipts into one entry, self-hosting, and Rekor v2 are explicitly **out of scope** for v0.3 (see Consequences / future work).

## Implementation findings (spike, 2026-05-31)

A Python spike submitted real entries to the public `rekor.sigstore.dev/api/v1/log/entries` to resolve the named primary risk *before* writing the Rust client. Results:

1. **SHA-256 is rejected for Ed25519.** `hashedrekord` with an Ed25519 key + `data.hash.algorithm = sha256` returns HTTP 400: `unsupported hash algorithm: "SHA-256" not in [SHA-512]`. → anchored hash MUST be **SHA-512**.
2. **Pure Ed25519 signatures are rejected.** With SHA-512, an ordinary Ed25519 signature (over the payload *or* over the digest bytes) returns HTTP 400 `ed25519: invalid signature`. Rekor's Ed25519 `hashedrekord` verifier expects **Ed25519ph** (RFC 8032 §5.1, SHA-512 prehash) — confirmed by the `[SHA-512]` supported-hash hint.
3. **Net design correction:** the anchor is a **dedicated Ed25519ph signature** over the payload, with `data.hash = SHA-512(payload)`. The receipt's existing pure-Ed25519 `signature` is unchanged and still covers the chain; the anchor signature is computed separately at anchor time. In Rust this is `signing_key.sign_prehashed(Sha512::new_with_prefix(payload), None)`; verification is `verifying_key.verify_prehashed(...)`. The 2a build's first integration test MUST round-trip a real public-Rekor entry (submit → fetch → verify inclusion proof + SET).

## Consequences

**Positive**
- The "tamper-evident" claim becomes true against the operator: a third party can verify a receipt without trusting IDProva or the agent host.
- Privacy-preserving: only a SHA-256 leaves the boundary; Rekor learns nothing about the agent, action, or data.
- Offline-verifiable after the fact; anchoring is decoupled from action latency.
- Optional + behind a trait → zero new conformance burden on SDK implementers; existing receipts remain valid.

**Negative / costs**
- Dual hashing (BLAKE3 for the chain + SHA-256 for Rekor) — negligible CPU, slight conceptual surface.
- A new optional `Receipt.anchor` field — additive, serde-skipped when absent, so wire-compatible with existing receipts and SDKs.
- Dependence on the availability/policy/rate-limits of the public `rekor.sigstore.dev` for v0.3. Mitigated by the swappable trait and best-effort semantics; a self-hosted instance is the production answer.

**Neutral / risk to validate in implementation (2a)**
- **Primary risk: Ed25519 acceptance by Rekor `hashedrekord`.** Rekor's PKI verifiers must accept a raw Ed25519 public key (PKIX/PEM) + signature for a `hashedrekord`. The 2a implementation MUST begin with a spike that submits one real entry to `rekor.sigstore.dev` and retrieves a verifiable inclusion proof. **If Ed25519 `hashedrekord` is rejected**, fall back, in order: (a) wrap the receipt in a **DSSE/in-toto** entry type; (b) re-encode the Ed25519 key in an accepted format (e.g. `ssh`/`minisign`); (c) stand up a self-hosted Rekor configured for Ed25519. The trait abstraction means this choice does not leak into the receipt model.

## Alternatives considered

1. **Status quo (no external anchor).** Rejected: leaves "tamper-evident" true only inside our own trust boundary — the weak claim that defeats the product's purpose.
2. **Self-hosted Rekor for v0.3.** Rejected *for v0.3* (kept as the production target): adds operational burden (a running tlog + checkpoint witness) before we've proven the receipt→anchor→verify path works end-to-end. Prove the path on the public instance first; self-host once the shape is locked.
3. **Bespoke Merkle transparency service.** Rejected: re-implements Rekor (gossip, checkpoints, monitors, inclusion/consistency proofs) — large surface, no ecosystem tooling, weaker trust story than a widely-operated public log.
4. **Certificate Transparency logs.** Rejected: CT is x509-certificate-shaped; coercing receipt hashes into CT is a poor fit and CT operators don't accept arbitrary entries.
5. **Blockchain / public-chain anchoring.** Rejected: cost, latency, throughput, and operational/regulatory baggage vastly exceed a transparency log; offers no verification property Rekor lacks.
6. **Anchor every receipt individually vs. batched Merkle root.** v0.3 anchors individually for simplicity and immediate verifiability. Batching many receipts under one periodic Rekor entry (anchor the root, ship per-receipt Merkle paths) is the **scale** answer and is deferred to a follow-up ADR once per-entry volume/rate-limits warrant it.

## References

- Sigstore Rekor — transparency log: https://docs.sigstore.dev/logging/overview/
- Rekor `hashedrekord` type and inclusion proofs / SET semantics.
- `crates/idprova-core/src/receipt/entry.rs` — `Receipt`, `ReceiptSigningPayload`, `compute_hash()` (S3 fix rationale).
- `crates/idprova-core/src/receipt/log.rs` — `ReceiptLog::append()`, `verify_integrity_with_key()`.
- ADR template: docs/adr/README.md (Michael Nygard format).
