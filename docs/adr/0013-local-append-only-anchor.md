# ADR 0013 — Local append-only anchoring

- **Status:** Accepted
- **Date:** 2026-06-17
- **Builds on:** ADR 0011 (Rekor transparency anchor), ADR 0012 (privacy-preserving batched anchoring)

## Context

ADR 0011/0012 anchor receipt evidence to the **public** Sigstore/Rekor transparency
log. That gives an independent third-party witness, but it requires network access to
public infrastructure that a data-residency-sensitive or air-gapped deployment may not
be able (or willing) to reach. Such deployments still want a **tamper-evident,
offline-verifiable** commitment that a given set and ordering of receipts existed —
without exporting anything off-site and without trusting a vendor.

The core verification guarantee (a signed, hash-chained receipt log verifiable with the
agent's public key) is already fully offline. What was missing was an offline way to
commit a *batch* of receipts to an append-only artifact that an auditor can later check.

## Decision

Add a **local, append-only, hash-chained anchor log** (`crates/idprova-core/src/receipt/local_anchor.rs`)
and two CLI subcommands (`idprova receipt anchor-local` / `verify-local`).

- Each `LocalAnchorRecord` commits a **Merkle root** (the existing ADR-0012 `MerkleTree`,
  RFC-6962 domain-separated over SHA-512) over a contiguous range of receipts.
  The Merkle leaf for a receipt is `SHA-512(receipt.signing_payload_bytes())`.
- Records are **hash-chained** with BLAKE3 (`previousHash` links the prior record's
  `recordHash`, genesis sentinel `"genesis"`), so the file is internally
  append-only-verifiable.
- Each record is optionally **Ed25519-signed** by the producer. The signature covers a
  payload that excludes the signature itself (mirrors the S3 receipt-signing fix).
- `verify_local_anchor` re-derives every record's root from the receipts, verifies the
  chain, and (given the producer public key) verifies every record signature — **fully
  offline, public key only**.

## Honesty boundary (load-bearing)

A local anchor is **producer-controlled — there is NO independent third-party witness.**
Therefore it **does NOT**:
- provide independent temporal attestation (the timestamp is producer-asserted), or
- prevent equivocation / split-view — a producer with full control of the file could
  rewrite its entire history.

What it **does** provide:
- a tamper-evident, append-only commitment — anyone holding *any* earlier copy of the
  file (or any earlier record hash) detects a later rewrite, reorder, or omission;
- proof of inclusion and ordering for the anchored receipts; and
- a network-free, self-hostable anchoring path for sovereign / air-gapped use.

For independent attestation, use the networked Rekor path (ADR 0011) or the
privacy-preserving batched path (ADR 0012). This local mode **complements**, and does
not replace, witnessed anchoring. A fully witnessed self-hostable log (with gossip /
external witnesses) remains a roadmap item.

## Consequences

- Backward compatible: no change to the `Receipt` wire format; the anchor log is a
  separate JSONL file. ADR-0011/0012 anchoring is untouched.
- Reuses the audited `MerkleTree` / `InclusionProof` primitives — no new crypto.
- The CLI surfaces the honesty boundary in `verify-local` output so an auditor reading
  the result cannot mistake it for a witnessed-log guarantee.
