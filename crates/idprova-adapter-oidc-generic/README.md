[![Crates.io](https://img.shields.io/crates/v/idprova-adapter-oidc-generic.svg)](https://crates.io/crates/idprova-adapter-oidc-generic)
[![Docs.rs](https://docs.rs/idprova-adapter-oidc-generic/badge.svg)](https://docs.rs/idprova-adapter-oidc-generic)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

# idprova-adapter-oidc-generic

Generic OIDC IdP adapter for [IDProva](https://github.com/techblaze-au/idprova). Implements `OidcIdpAdapter` and `AttributeMapper` from the [`idprova-identity-adapters`](../idprova-identity-adapters) trait crate.

## Overview

- OIDC ID-token verification with JWKS caching, RS256 + ES256 per [RFC 0001](../../docs/rfcs/IDProva_Okta_Bridge_RFC_v0.1.md) §4.3.
- Deterministic OIDC-claim → IDProva trust-level + scope mapping per [RFC 0001](../../docs/rfcs/IDProva_Okta_Bridge_RFC_v0.1.md) §6.3.
- Covers the claim shapes of **Okta**, **Microsoft Entra**, **Auth0**, and **Keycloak** via the `GroupClaimSource` enum.

## Architecture

```
+-------+      +-----------------------------+      +---------------+      +---------------+
| Agent | ---> | idprova-adapter-oidc-generic| ---> | IdP JWKS      | ---> | DAT issuance  |
|       |      |  (OidcIdpAdapter impl)      |      | (discovery +  |      | (downstream)  |
+-------+      +-----------------------------+      |  key fetch)   |      +---------------+
                                                    +---------------+
```

Port-and-adapter (hexagonal) pattern. Trait surface in `idprova-identity-adapters`; this crate is one concrete implementation.

## Quick start

```rust
use std::time::Duration;

use idprova_adapter_oidc_generic::{
    GenericAttributeMapper, GenericOidcAdapter, MappingConfig, OidcAdapterConfig,
};
use idprova_identity_adapters::{AttributeMapper, OidcIdpAdapter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Configure and create the adapter.
    let config = OidcAdapterConfig {
        issuer: "https://acme.okta.com".into(),
        jwks_cache_ttl: Duration::from_secs(3600),
    };
    let adapter = GenericOidcAdapter::new(config);

    // 2. Verify an ID token.
    let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...";
    let claims = adapter.verify_id_token(token, &["my-audience"]).await?;

    // 3. Map claims to trust level and scopes.
    let mapper = GenericAttributeMapper::new(MappingConfig::default());
    let trust_level = mapper.map_trust_level(&claims)?;
    let scopes = mapper.map_scopes(&claims)?;

    println!("trust={:?}  scopes={:?}", trust_level, scopes);
    Ok(())
}
```

## Per-vendor configuration

### Okta

`GroupClaimSource::Standard` — groups live in `claims.groups`.

### Microsoft Entra

`GroupClaimSource::EntraRoles` — app roles live in `claims.extra["roles"]` as a JSON array of strings.

### Auth0

`GroupClaimSource::Standard`. Auth0 namespaces custom claims under `https://<your-domain>/<key>` (per Auth0's rules / actions guidance); these flow through into `claims.extra`. Configure your Auth0 action to emit group membership under a namespaced key, then use `GroupClaimSource::Custom("https://<your-domain>/groups")`.

### Keycloak

`GroupClaimSource::Standard`. Keycloak nests realm roles inside a JSON object:

```json
{ "realm_access": { "roles": ["admin", "user"] } }
```

These land in `claims.extra["realm_access"]`. To map them, use `GroupClaimSource::Custom("realm_access")` and write a custom unpacking layer above this crate, or shape the IdP-side mapper to emit a flat string array under a dedicated claim.

## Trust level + scope mapping rules

[RFC 0001](../../docs/rfcs/IDProva_Okta_Bridge_RFC_v0.1.md) §6.3 defaults:

| Condition | Trust Level |
|---|---|
| `amr` contains `"phr"` (phishing-resistant) | L3 |
| `acr` ∈ `{urn:mace:incommon:iap:silver, loa2}` | L2 |
| Everything else | L1 |

Override per tenant via `MappingConfig`:

```rust
use std::collections::HashMap;
use idprova_adapter_oidc_generic::MappingConfig;
use idprova_core::trust::TrustLevel;

let mut acr_overrides = HashMap::new();
acr_overrides.insert("urn:example:acr:gold".to_string(), TrustLevel::L3);

let config = MappingConfig {
    acr_trust_overrides: acr_overrides,
    group_scope_map: HashMap::from([
        ("admin".to_string(), vec!["mcp:tool:*:*".into()]),
        ("viewer".to_string(), vec!["mcp:tool:*:read".into()]),
    ]),
    ..MappingConfig::default()
};
```

## Caching

Both discovery and JWKS responses are cached behind `tokio::sync::RwLock<Option<Cached<...>>>`. TTL configured via `OidcAdapterConfig.jwks_cache_ttl`. RFC 0001 §4.3 caps JWKS TTL at 24h; this crate honours whatever value the caller sets — production callers SHOULD enforce the cap externally.

## Limitations

- **No SAML inbound.** Deferred to v0.3 per RFC 0001 NG-3.
- **No DPoP.** Demonstrating Proof of Possession not implemented.
- **Synthetic JWKS in CI.** No live IdP smoke tests; integration tests use a wiremock-based synthetic server (`tests/integration.rs`).

## Status

v0.1 — port implementation. RFC 0001 §11 implementation phase Wk 6–12.

## License

Licensed under the [Apache License, Version 2.0](../../LICENSE).
