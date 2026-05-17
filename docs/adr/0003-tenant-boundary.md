# 0003 — Tenant boundary in registry, not core

* **Status:** Proposed (DRAFT — pending Pratyush approval in Night 2 morning gate)
* **Date:** 2026-05-18
* **Authors:** IDProva engineering (Night 2 architectural-seam batch)
* **Related:** Agent B spec audit §10 issue #1; RFC 0001 §5.3; backlog entry IDP-005;
  upcoming ADR 0004 (PQ hybrid signing, IDP-006); related backlog items
  IDP-020 (`idprova-identity-adapters` traits crate), IDP-040 (multi-tenant
  key resolution)

---

## Context

Agent B's spec audit (entry §10 issue #1) observed that `idprova-core`
contains the modules `aid/`, `crypto/`, `dat/`, `error.rs`, `http.rs`,
`policy/`, `receipt/`, and `trust/` — and **no `tenant/` module**. The same
review noted that RFC 0001 §5.3 ("Multi-tenancy") assumes a 1-to-1 mapping
between *one tenant* and *one configured IdP* at the overlay layer.

The question the audit raised is: should `idprova-core` introduce a first-
class tenant primitive (e.g. a `Tenant` newtype, a `TenantId` field threaded
through DAT-issuance and AID-binding APIs, perhaps a `tenant::isolation`
submodule), or should multi-tenancy live exclusively above the core, in the
registry crate (`idprova-registry`) and the identity adapter crates
(`idprova-identity-adapters` — see ADR 0001-style RFC 0001 §5.1, scaffolded
by backlog item IDP-020)?

Three forces are in tension:

1. **Open-protocol purity.** `idprova-core` is the public protocol surface
   shipped to third-party implementers (Python / TypeScript / Go SDKs and
   alternative server implementations). Anything the core leaks becomes
   part of the protocol contract. Adding a `Tenant` primitive to the core
   means every implementer must reason about multi-tenancy, including
   single-tenant on-prem deployments where multi-tenancy is meaningless.

2. **Deployment-shape diversity.** IDProva runs in (a) single-tenant on-prem,
   (b) multi-tenant SaaS, and (c) air-gapped / sovereign deployments where
   the registry may be replicated per tenant. The "right" tenant boundary
   differs per shape: in (a) there is no boundary, in (b) the boundary is
   the registry row, in (c) the boundary is the entire registry instance.
   A core-level primitive would have to be either the lowest common
   denominator (useless) or configurable to the point of leaking the
   deployment shape into the protocol surface (over-coupled).

3. **AID-binding and key custody.** Even though the *boundary* is not in
   core, the *primitives that get tenant-tagged* (DIDs, DATs, AIDs, keys)
   are. The decision below is therefore not "tenant is irrelevant to
   `idprova-core`" — it is "the tenant *boundary* and *isolation rules*
   live in registry / adapters; the *carry of tenant context* through DAT
   chains and receipts uses fields the core already has (`iss` / `aud` /
   `kid`) without a dedicated `tenant_id` field."

---

## Decision

**Multi-tenancy is a registry-layer and adapter-layer concern, not a core
concern.** The `idprova-core` crate will not gain a `tenant/` module, a
`TenantId` newtype, or any `tenant_id` field on `Aid`, `Dat`, or `Receipt`
structs. Tenant boundaries are enforced in:

1. **The registry layer** (`idprova-registry`), via the `AidBindingStore`
   trait (planned in IDP-003): bindings are keyed `(idp_issuer,
   idp_subject_hash)` and one binding row implicitly belongs to one tenant
   because one IdP issuer is bound to one tenant in any deployment. The
   registry's HTTP layer enforces tenant isolation by scoping admin DATs
   and ACLs to specific issuer prefixes.

2. **The identity-adapter layer** (`idprova-identity-adapters`, scaffolded
   in IDP-020), via per-adapter configuration that names exactly one
   issuer per adapter instance. A multi-tenant deployment runs N adapter
   instances, one per IdP, and the adapter never reasons across tenants.

3. **Per-tenant key custody and key resolution**: handled by
   `idprova-registry` (admin DATs + per-tenant signing keys) and by the
   future `idprova-keyresolver` crate (planned in IDP-040), which resolves
   `kid` values against a tenant-scoped key directory. The DID Document's
   `verificationMethod` already carries the public key per agent; the
   `controller` field carries the organisational binding. No new core field
   is needed for tenant key custody.

**What does *not* change:**

- `Aid`, `Dat`, and `Receipt` schemas remain stable. No breaking change to
  v0.1 / v0.2 wire formats.
- The `iss` claim on DATs and the `controller` field on AIDs continue to
  carry the organisational identity that downstream layers interpret as
  the tenant boundary.
- IRAP / DISP / sovereign-deployment claims remain unaffected — these are
  deployment-mode decisions, not protocol-level decisions.

---

## Consequences

### Positive

- **Protocol surface stays minimal.** Third-party implementers do not have
  to model multi-tenancy in their SDK or alt-server, which is a significant
  reduction in cognitive load. Single-tenant on-prem deployments never see
  the concept.
- **Deployment-shape flexibility preserved.** Per-registry-instance,
  per-row, and shared-registry models are all expressible without changing
  the core. The registry chooses the isolation mechanism per deployment.
- **No wire-format churn.** v0.1 → v0.2 transition does not need a
  multi-tenancy migration path on DAT / AID / receipt schemas.
- **Adapter port-and-adapter pattern is reinforced.** Each adapter instance
  represents exactly one IdP integration, mirroring the one-IdP-per-tenant
  rule in RFC 0001 §5.3.

### Negative

- **Tenant boundary enforcement is not protocol-guaranteed.** If a registry
  implementation has a bug that lets one tenant's admin DAT operate on
  another tenant's bindings, the core protocol cannot catch it — the
  registry's HTTP layer alone enforces isolation. This is the *intentional*
  trade-off, but it means registry implementations carry a security-
  critical responsibility that is documented but not type-checked.
- **Cross-tenant federation is a separate problem.** When two IDProva
  deployments need to federate (agent in tenant A calls a tool in tenant
  B), the federation layer must establish trust at the registry level, not
  via a core-level `tenant_id` field. This is consistent with the existing
  `did:aid:` resolution model (resolution is by DID, not by tenant) but
  requires explicit design for federation later.

### Neutral

- Multi-tenant key custody and per-tenant signing-key rotation are deferred
  to `idprova-keyresolver` (IDP-040). v0.2 does not block on this — it is a
  v0.3 expansion.
- Documentation update: the RFC 0001 §5.3 multi-tenancy section should be
  cross-referenced from this ADR so RFC readers know the boundary lives at
  the layer above core. Follow-up issue: add a one-line cross-reference in
  RFC 0001 §5.3 ("Implementation lives in registry + adapters per ADR
  0003").

---

## Alternatives considered

### Alternative 1 — introduce `idprova-core::tenant` module with `TenantId`

**Shape:** Add a `TenantId(String)` newtype in `idprova-core::tenant`; thread
it through `AidBinding`, `Dat::iss`-resolution, and `Receipt::context`. Each
SDK ships its own tenant-awareness.

**Rejected because:**
- Adds protocol surface that single-tenant deployments do not need.
- Forces every implementer to think about tenancy even when not relevant.
- Couples the protocol to a specific multi-tenancy model when in reality
  deployments span at least three (per-instance, per-row, per-cluster).
- Breaking change: v0.1 receipts and DATs would not carry `tenant_id` and
  would need a migration story to v0.2.

### Alternative 2 — accept the gap; document that tenant lives above core

**Shape:** Same as the chosen decision, but with no ADR — just an inline
comment in `idprova-core::lib.rs` saying "multi-tenancy lives above".

**Rejected because:**
- Without an explicit ADR, a future implementer is likely to re-litigate
  this question and may introduce ad-hoc tenant fields in the core. The
  ADR is the load-bearing artefact.

### Alternative 3 — introduce a per-tenant overlay crate (`idprova-tenant`)

**Shape:** New crate `idprova-tenant` between `core` and `registry`; it
defines tenant primitives that the registry and adapters consume.

**Rejected because:**
- Premature. The three current consumer crates (registry, future scim,
  future identity-adapters) already each know their own tenant binding via
  the IdP-issuer-prefix rule. A separate crate would add a layer without
  consolidating logic — the same tenant primitives would still be re-
  implemented in each consumer because the actual isolation enforcement is
  consumer-specific (HTTP middleware vs. SCIM endpoint scoping vs.
  webhook-verifier ownership).

### Alternative 4 — defer the decision until v0.3 and ship v0.2 ambiguous

**Rejected because:**
- IDP-005 is on the v0.2 path, and downstream items (IDP-020 traits crate,
  IDP-040 key-resolver) need the boundary defined to proceed. Leaving the
  question open in v0.2 risks the same drift Agent B already observed.

---

## References

- **RFC 0001** — IDProva Okta Bridge RFC v0.1 §5.3 (Multi-tenancy
  assumption), §6.1 (Flow 1 — OIDC bridge), §7.2 (binding table sketch).
- **Agent B spec audit** — entry §10 issue #1 (original observation of the
  missing `tenant/` module).
- **Backlog entry IDP-005** —
  `IDProva_Execution_Backlog_2026-05-12.md` (this ADR is the deliverable).
- **Related backlog items:** IDP-003 (`AidBinding` migration), IDP-020
  (identity-adapters traits crate), IDP-040 (multi-tenant key resolution).
- **Code references** — `idprova/crates/idprova-core/src/lib.rs` (no
  `tenant/` module; this ADR documents that absence is intentional);
  `idprova/crates/idprova-registry/src/store.rs` (registry-layer
  enforcement landing site).
