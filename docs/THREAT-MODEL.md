# IDProva Threat Model

This document states plainly what IDProva protects, what it does **not**, and the trust
assumptions it rests on. It is deliberately conservative: a security primitive that overstates
its guarantees is worse than one that is honest about its edges.

## What IDProva protects

- **Agent identity authenticity.** Each agent has a W3C DID (an "AID", `did:aid:…`) bound to an
  Ed25519 keypair and resolvable through the registry. A verifier can confirm *which* agent
  produced a token or receipt — assuming that agent's private key has not been compromised.
- **Authorization scope.** A Delegation Attestation Token (DAT) is signed, scoped (4-part
  `namespace:protocol:resource:action` grammar), and time-boxed. A verifier checks a requested
  action against the granted scope and **denies out-of-scope requests**. Delegation chains are
  constrained: a child's issuer must be the parent's subject, child scopes must be a subset of
  the parent's, a child must not outlive its parent, and chain depth is bounded.
- **Tamper-evidence of the action log.** Receipts are BLAKE3 hash-chained (`previousHash`
  starting at `genesis`, monotonic `sequenceNumber`) and Ed25519-signed. Removing, reordering,
  or altering any entry breaks `idprova receipt verify`.
- **Independent verifiability of existence and time (optional).** With anchoring enabled, a
  third party can confirm a receipt *existed at a given time and carried a given agent
  signature* using the public Sigstore/Rekor log — without trusting the operator's server.

## What IDProva does NOT protect against

- **Truth of the logged event.** A receipt proves an action was *claimed and signed* — not that
  the tool's result is correct or that the agent behaved well. An anchor proves
  existence + time + signature, **not** event-truth.
- **Private-key compromise.** If an agent's (or issuer's) Ed25519 key is stolen, the attacker
  can mint valid DATs and receipts as that identity. IDProva offers registry revocation, but it
  cannot prevent misuse in the window before revocation.
- **A dishonest operator when anchoring is off.** Anchoring is **default-OFF**. Without it, an
  operator who controls both the receipt store and the signing keys could rebuild a consistent
  chain. The tamper-evidence guarantee then only holds for someone who already holds an earlier
  copy of the log. Anchoring is the mitigation for an untrusted operator.
- **Calls that bypass a guarded boundary.** Scope is enforced only where a verifier is wired in
  (the MCP middleware, and first-party framework adapters). An **audit-only** integration
  *records* but does not *block*. A tool call that never passes through the guarded path is
  invisible to IDProva.
- **Token theft / replay within validity.** A leaked DAT can be presented by another party until
  it expires or is revoked; single-use, session-bound enforcement is not yet a guarantee.
- **Confidentiality.** Receipts and DATs are integrity/authenticity primitives, not encryption.
  Inputs are hashed, not necessarily hidden.

## Trust assumptions

- **Key custody:** agents and issuers protect their Ed25519 private keys.
- **Registry integrity and availability:** identity resolution and revocation depend on the
  registry. It is both a trust anchor and an availability dependency — in the current deployment
  it is effectively a single point of failure.
- **Transport security:** registry and API calls run over TLS.
- **Honest verifier placement:** enforcement is only as strong as where the guard is installed.
- **Anchoring backend:** when enabled, you trust the Sigstore/Rekor transparency log.

## Cryptographic primitives

- **Ed25519** for DAT and receipt signatures (Ed25519ph in the anchoring path).
- **BLAKE3** for receipt hashing, emitted with an explicit `blake3:` prefix and hash-chained.
- **SHA-512 + Merkle** for batched anchoring (ADR 0012), with salted-HMAC leaves so per-action
  metadata is not exposed in the public log.
- *Limitations:* BLAKE3 is not FIPS-validated; key rotation is operator-managed.

## Transparency-log anchoring caveat

- **Opt-in, default-OFF.** ADR 0011 anchors a `hashedrekord` to `rekor.sigstore.dev`; ADR 0012
  adds a privacy-preserving batched scheme (salted HMAC leaf + Merkle root) so individual
  actions are not leaked publicly.
- **Guarantees:** existence, time, and agent signature are independently verifiable.
- **Does NOT guarantee:** event truth; completeness (an operator may choose not to anchor some
  receipts); or confidentiality of anchored content beyond what the batched/HMAC scheme provides.
- **Sovereignty note:** the default path uses public Sigstore infrastructure. A self-hostable
  log is a roadmap item for data-residency-sensitive deployments.

## Out of scope (current)

- SAML inbound (deferred to the v0.3 spec).
- Real-time, cross-node revocation propagation guarantees beyond the registry API.
- Device or hardware attestation of the agent runtime.
- Payload encryption / confidentiality.
- Defending a fully-compromised host from misusing in-memory keys.

---
*Grounded in the shipped surface (`idprova {aid,dat,receipt}`, `crates/idprova-core`,
ADR 0011/0012). Last updated 2026-06-08.*
