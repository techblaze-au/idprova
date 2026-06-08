# IDProva vs. in-toto, SPIFFE/SPIRE, cosign/Sigstore, and PKI

**One question:** when an autonomous AI agent calls a tool, can you prove *which* agent
did it, that it was *authorized* to, and that the record *hasn't been tampered with* —
and can a third party verify all three without trusting you?

The existing identity and supply-chain tools each answer part of this. None of them was
built for the agent tool-call lifecycle, so each leaves a gap IDProva is designed to close.

## Capability comparison

| Technology | Primary purpose | Identity model | Scoped, time-boxed delegation | Per-action signed, tamper-evident receipts | Runtime tool-call enforcement | Transparency-log anchoring |
|---|---|---|---|---|---|---|
| **in-toto** | Supply-chain layout enforcement & link attestations | Key-pair bound to step roles in a layout | No — layout constrains step ordering, not delegation to an agent | Per-step signed link metadata, verified **post-hoc** | No — verification is an offline checker, not inline | No native log (relies on external storage) |
| **SPIFFE / SPIRE** | Workload identity issuance & federation (SVIDs) | SPIFFE ID (URI) in an X.509- or JWT-SVID, attested | Short SVID TTLs, but scoping needs an external policy engine (OPA, Envoy) | No — SVIDs authenticate workloads; no per-action receipt | Not natively — identity only; enforcement delegated to mesh/proxy | No |
| **cosign / Sigstore** | Artifact & container signing/verification | Keyless (OIDC → Fulcio cert) or key-pair; identity = cert subject | No — signs artifacts; no delegation-token model | Per-artifact signatures; **Rekor** gives a tamper-evident log | No — checked at admission/CI, not per tool call | **Yes** — Rekor is a public transparency log |
| **Traditional PKI / X.509** | Mutual-TLS authentication & identity assertion | Distinguished Name in a CA-issued cert | Revocation (CRL/OCSP), short-lived certs — but no native scoped-delegation primitive | No — certs authenticate; no per-action receipt | No — authenticates; authorization is external | No |
| **IDProva** | Verifiable identity + scoped delegation + signed receipts **for AI agents** | W3C DID per agent (`did:aid:…`, "AID"), Ed25519 keys, registry resolution | **Yes** — DAT with a 4-part scope grammar, expiry, and chaining (a child's issuer is the parent's subject; scopes only narrow; a child never outlives its parent) | **Yes** — BLAKE3 hash-chained, Ed25519-signed receipt log; `idprova receipt verify` checks chain integrity | **Yes** at the MCP middleware boundary (scope verified per call); first-party framework adapters (LangChain) landing for launch | **Yes** — opt-in (default-OFF) Sigstore Rekor anchoring (ADR 0011/0012) |

## What none of the four fully close (and IDProva targets)

- **No single system issues an agent a cryptographic identity *and* a scoped, time-boxed
  delegation token it can present downstream.** SPIFFE has the closest identity story but no
  delegation token; cosign and in-toto have no agent-identity model at all.
- **No system blocks an out-of-scope action at the moment of the call.** in-toto verifies
  after the fact; cosign/SPIFFE verify at admission or not at all — none gate an individual
  runtime tool call against a delegation scope.
- **No system emits a per-call signed receipt binding `identity → scope → tool → input → result`.**
  Rekor logs *signing* events; in-toto links *supply-chain steps* — neither is a per-action
  agent ledger.
- **None combine delegation scoping with runtime blocking *and* a verifiable receipt** in one
  handoff from intent → enforcement → proof.

## How to read this honestly

- **IDProva does not replace SPIFFE, cosign, or PKI** — it sits at a different layer (the agent
  tool-call), and it reuses the same proven primitives: Ed25519, BLAKE3, and **Sigstore Rekor**
  for the optional transparency anchor. Where you already run SPIFFE for workload identity, IDProva
  rides on top for *agent-action* accountability.
- **Anchoring is opt-in and default-OFF.** The crypto-credibility claim is "the receipt's existence,
  time, and agent signature are independently verifiable," **not** "the logged event is true."
- **Runtime enforcement** is shipped at the MCP middleware boundary today; the first-party
  **LangChain** adapter (enforce + audit) is the launch-flagship integration, with CrewAI and
  AutoGen following post-launch. Rows in the integrations matrix flip to "Shipped" only when an
  example runs in CI — we don't claim an integration before it's real.

---
*Sources: factual competitor capabilities drafted via research and verified against public project
docs; IDProva column grounded in the shipped CLI/core surface (`idprova {aid,dat,receipt}`,
`crates/idprova-core`). Last updated 2026-06-08.*
