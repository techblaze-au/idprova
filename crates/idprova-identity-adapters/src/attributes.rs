//! `AttributeMapper` — port for deterministic OIDC-claims → IDProva
//! trust-level + scope mapping.
//!
//! Adapters implement this trait to translate IdP-side claims (`acr`,
//! `amr`, `groups`) into the IDProva trust framework (`TrustLevel`)
//! and 4-part scope prefixes. Per RFC 0001 §6.3 the mapping is
//! deterministic and per-tenant-overridable; a single tenant might
//! want stricter mapping than the default.

use crate::error::AdapterResult;
use crate::oidc::IdTokenClaims;
use idprova_core::trust::TrustLevel;

/// Deterministic OIDC → IDProva mapping.
///
/// Implementations MUST be pure functions of their inputs — the same
/// `IdTokenClaims` MUST produce the same outputs every time. Side
/// effects (HTTP, DB, randomness) are out of scope for this trait;
/// they belong to the [`OidcIdpAdapter`] step that produces the
/// claims.
///
/// [`OidcIdpAdapter`]: crate::oidc::OidcIdpAdapter
pub trait AttributeMapper: Send + Sync {
    /// Map an OIDC ID-token's `acr` / `amr` to an IDProva trust level.
    ///
    /// Default semantics (overrideable per tenant):
    /// * `amr` contains `"phr"` (phishing-resistant) → [`TrustLevel::L3`].
    /// * `acr` ∈ {`"urn:mace:incommon:iap:silver"`, `"loa2"`} → [`TrustLevel::L2`].
    /// * otherwise → [`TrustLevel::L1`] (organisation-bound but
    ///   single-factor session).
    fn map_trust_level(&self, claims: &IdTokenClaims) -> AdapterResult<TrustLevel>;

    /// Map group memberships to scope-grammar prefixes (4-part
    /// `namespace:protocol:resource:action`).
    ///
    /// Adapters typically pull groups from `claims.groups` (Okta) or
    /// `claims.extra["roles"]` (Entra). The mapping table is owned
    /// by the adapter — different tenants can have different rules.
    fn map_scopes(&self, claims: &IdTokenClaims) -> AdapterResult<Vec<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Reference mapper used in tests — demonstrates the default
    /// mapping rules described in the trait docstring.
    struct ReferenceMapper;

    impl AttributeMapper for ReferenceMapper {
        fn map_trust_level(&self, claims: &IdTokenClaims) -> AdapterResult<TrustLevel> {
            if claims.amr.iter().any(|m| m == "phr") {
                return Ok(TrustLevel::L3);
            }
            if let Some(acr) = claims.acr.as_deref() {
                if matches!(acr, "urn:mace:incommon:iap:silver" | "loa2") {
                    return Ok(TrustLevel::L2);
                }
            }
            Ok(TrustLevel::L1)
        }

        fn map_scopes(&self, claims: &IdTokenClaims) -> AdapterResult<Vec<String>> {
            Ok(claims
                .groups
                .iter()
                .filter_map(|g| match g.as_str() {
                    "agents" => Some("mcp:tool:*:read".to_string()),
                    "admins" => Some("mcp:tool:*:*".to_string()),
                    _ => None,
                })
                .collect())
        }
    }

    fn claims(acr: Option<&str>, amr: &[&str], groups: &[&str]) -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://example.com".to_string(),
            sub: "alice".to_string(),
            aud: "idprova".to_string(),
            exp: 0,
            iat: 0,
            nonce: None,
            acr: acr.map(|s| s.to_string()),
            amr: amr.iter().map(|s| s.to_string()).collect(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn phr_maps_to_l3() {
        let m = ReferenceMapper;
        assert_eq!(
            m.map_trust_level(&claims(None, &["phr"], &[])).unwrap(),
            TrustLevel::L3
        );
    }

    #[test]
    fn known_loa_maps_to_l2() {
        let m = ReferenceMapper;
        assert_eq!(
            m.map_trust_level(&claims(Some("loa2"), &[], &[])).unwrap(),
            TrustLevel::L2
        );
    }

    #[test]
    fn unknown_maps_to_l1() {
        let m = ReferenceMapper;
        assert_eq!(
            m.map_trust_level(&claims(None, &["pwd"], &[])).unwrap(),
            TrustLevel::L1
        );
    }

    #[test]
    fn group_maps_to_scope() {
        let m = ReferenceMapper;
        let s = m
            .map_scopes(&claims(None, &[], &["agents", "wheel"]))
            .unwrap();
        assert_eq!(s, vec!["mcp:tool:*:read".to_string()]);
    }
}
