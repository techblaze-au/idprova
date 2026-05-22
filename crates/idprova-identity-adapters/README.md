# idprova-identity-adapters

Trait crate defining the **ports** between IDProva's core protocol and
the outside world's identity stack. Concrete adapters (Okta, Entra,
Auth0, Keycloak, SPIFFE, generic-OIDC, generic-SCIM, OpenTelemetry)
live in separate crates and bring their own runtime dependencies.

This crate is the architectural seam that closes the gap between
IDProva's three-pillar marketing story (portable receipts, sovereign
deployment, cross-stack continuity) and the actual code surface. It
defines **four traits** and the wire-format types they consume; it
ships **zero I/O** and **zero runtime dependencies** beyond
`idprova-core`, `serde`, `serde_json`, and `thiserror`.

## Port-and-adapter pattern

```
                  ┌────────────────────────────────┐
                  │       idprova-core             │
                  │  (DID • DAT • Receipt • Trust) │
                  └──────────────┬─────────────────┘
                                 │
                                 │   depends on traits only
                                 ▼
              ┌──────────────────────────────────────────────┐
              │      idprova-identity-adapters (THIS CRATE)  │
              │                                              │
              │   trait OidcIdpAdapter      ◀───── port A    │
              │   trait AttributeMapper     ◀───── port B    │
              │   trait ScimProvisioner     ◀───── port C    │
              │   trait AuditExporter       ◀───── port D    │
              └────┬───────────┬──────────────┬──────────────┘
                   │           │              │
       ┌───────────┘           │              └──────────────┐
       │                       │                             │
       ▼                       ▼                             ▼
┌──────────────┐      ┌──────────────────┐         ┌────────────────┐
│ idprova-     │      │ idprova-         │         │ idprova-       │
│ adapter-oidc-│      │ adapter-scim-    │         │ exporter-otel  │
│ generic      │      │ generic          │         │                │
│              │      │                  │         │  (OTLP / gRPC) │
│  (HTTP + JWKS│      │  (SQLite / Postgres │      │  → Splunk      │
│   cache)     │      │   + revocation)  │         │  → Datadog     │
└──────┬───────┘      └────────┬─────────┘         │  → Sentinel    │
       │                       │                   │  → Elastic     │
       ▼                       ▼                   └────────────────┘
   ┌────────┐              ┌────────┐
   │ Okta   │              │ Okta   │
   │ Entra  │              │ Entra  │
   │ Auth0  │              │ Auth0  │
   │ KCloak │              │ KCloak │
   └────────┘              └────────┘
```

Each adapter:

* implements **one** trait from this crate;
* configures itself for **one** IdP issuer (or one OTel collector
  endpoint) per instance — per ADR 0003, one adapter instance = one
  tenant in any deployment;
* depends on `idprova-identity-adapters` (this crate) and
  `idprova-core` (for the canonical types), plus whatever runtime
  bits it needs (HTTP client, SQL driver, OTLP shim).

Consumers of this crate (the registry, the SDKs, the middleware) hold
the adapter through its trait — they never name the concrete type.
This makes the system substitutable: swapping Okta for Entra, or
replacing the generic OIDC adapter with an Okta-specific one for a
single tenant, is a Cargo-feature-flag change in the bootstrap, not a
refactor.

## Traits at a glance

| Trait | Where it lives in the request flow |
|-------|-----------------------------------|
| `OidcIdpAdapter` | Inbound: verify the user's ID-token from Okta/Entra. |
| `AttributeMapper` | Inbound: map verified claims to IDProva trust level + scopes. |
| `ScimProvisioner` | Inbound: handle Okta/Entra SCIM PUT/DELETE for agent provisioning. |
| `AuditExporter` | Outbound: ship signed receipts to a SIEM via OTel. |

## What's *not* here

* **No HTTP client.** Adapters use `reqwest`/`hyper`/whatever they
  prefer. This crate stays runtime-agnostic.
* **No async runtime.** Trait methods use native `async fn`/RPITIT
  (Rust 1.85+). No `tokio` or `async-trait` Cargo dep.
* **No persistence.** SCIM impls bring their own store (SQLite,
  Postgres, in-memory, …).
* **No multi-tenancy primitive.** Per ADR 0003 multi-tenancy lives at
  the registry layer; each adapter instance is single-tenant by
  construction.

## References

* **RFC 0001** §5.1 — port-and-adapter pattern (the source of this
  crate's design).
* **Agent A Architecture Audit** headline recommendation — close the
  marketing-vs-reality gap by introducing this trait crate.
* **ADR 0003** — tenant boundary lives in registry + adapters, not
  in core.
* **Backlog entry IDP-020** — this crate is its deliverable.

## Versioning

The crate follows the workspace version (`0.1.x`). Trait signatures
will gain new methods in minor releases via default-method bodies
where possible; breaking changes wait for the next major release.
