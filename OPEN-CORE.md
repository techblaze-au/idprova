# IDProva Open-Core Model

> **Status:** accepted 2026-06-27. This document is the canonical statement of *what is open and
> what is commercial* in IDProva. Dollar amounts live in pricing collateral (see
> [`product-truth.json`](https://github.com/techblaze-au/idprova-cloud) and idprova.com), **not here** —
> this file defines the capability line, which is stable; prices change.

## The governing rule

**The free/paid line is drawn at operation, governance, and scale — never at the protocol or the
verify path.** Paywalling the protocol or the ability to verify would break the "neutral / open"
claim that is the entire point of a cross-standard trust layer. So everything needed to *speak the
protocol* and *verify* is open source; what you pay for is having someone *operate and govern it at
scale* for you.

This mirrors how the credible neutral-infrastructure projects draw the line: Sigstore, SPIFFE/SPIRE,
and CT keep signing/verification open and monetise the *operated* service and the *enterprise
governance* around it; HashiCorp Vault, Keycloak/RH-SSO, and Ory keep the engine open and charge for
namespaces/governance/HA/support.

## What is OPEN (Apache-2.0, public — `github.com/techblaze-au/idprova`)

All three pillar **libraries**, in full:

| Pillar | Crate | Open capability |
|---|---|---|
| **A** | `idprova-webbotauth` | RFC 9421 HTTP Message Signatures sign **and** verify; RFC 7638 JWK-thumbprint ↔ `did:aid:` binding; JWKS / Signature-Agent directory model. |
| **C** | `idprova-vc` | W3C VC Data Model 2.0 issue **and** verify (`eddsa-jcs-2022`); DAT→VC bridge; AP2/A2A mandate types. |
| **B** | `idprova-trust-registry` | Issuer data model; single-authority **TrustList sign + offline verify**; SQLite issuer store + `may_attest`; cross-standard **resolver**; RFC 6962-style **Merkle log: inclusion + consistency proof generation AND verification, signed tree heads**. |

The federation **spec + proof verification** is open on purpose: it is what makes "neutral /
mirrorable / decentralised" *provable* rather than promised. Anyone can verify a signed trust list or
a tree head offline, with no network and no chain.

## What is COMMERCIAL

The open libraries give you the primitives; the commercial editions *operate and govern* them.

### Cloud (hosted SaaS — idprova.com)
Operating the hosted directory / trust-list / **transparency log** (uptime, monitoring), **HSM key
custody**, and **HA / replication** of the trust-anchor key. You could self-host the open library
instead; Cloud is "we run it, with custody and uptime guarantees."

### Enterprise Edition (self-host, commercial licence — separate component, NOT in the public repo)
The multi-operator / governance layer:
- multi-operator **federation management** & peer-admission orchestration;
- **governance**: issuer-admission approval workflow, tamper-evident audit of trust-list changes;
- **RBAC, SCIM**, compliance reporting, anomaly detection;
- SLA / support.

> ⚠️ **Naming:** "Enterprise **Edition**" (this self-host governance component) is distinct from any
> "Enterprise" *tier* of the hosted SaaS. They are different products. See the pricing collateral.

The open `idprova-trust-registry::federation::mirror()` is a documented boundary stub that returns an
"operator/enterprise edition" error — live multi-operator sync is the line where the commercial
component begins.

### Sovereign (paid licence)
Air-gapped / offline trust-list deployment + IRAP / Essential-Eight evidence packs, per-agency
licence. The open library already verifies fully offline; Sovereign is the packaged, supported,
accreditation-ready deployment for government / DISP / PROTECTED environments. **This is the
beachhead — a structural exclusion the global incumbents cannot occupy — not an afterthought.**

### Commercial / on-chain (paid — being validated)
On-chain (XRPL-first) KYA anchoring + a **KYA attestation API** (per-call) + issuer/registry
**membership**. This is the newest and least-de-risked surface, so it is **validated with a
"founding issuer" pilot before pricing is fixed** — it is deliberately *not* baked into the canonical
pricing file yet.

## Why open-source here is the entry ticket, not the moat

Open source buys credibility and auditability — necessary for a trust layer, but not sufficient as a
defence (walt.id, SPIRE, Keycloak are open and ahead). The defensible position is the **intersection
that no single incumbent can occupy at once**:

1. **Sovereign / air-gapped** — a structural exclusion of operator-owned directories (Visa TAP,
   Cloudflare Web Bot Auth, MS Entra Agent ID, Google AP2);
2. the **neutral cross-standard resolver / verifier** — the "Switzerland" layer an operator-owned
   directory will never build;
3. **standards citation** (Commonwealth / NIST / TRQP) as an influence moat.

Position: *the open, neutral, sovereign verify-resolve-reference layer* — **not** "the Visa of KYA."
