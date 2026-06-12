//! Generic OIDC `AttributeMapper` with tenant-overridable trust and scope mapping.
//!
//! Implements [`AttributeMapper`] for IDProva. Default mapping follows
//! RFC 0001 §6.3:
//! * `amr` contains `"phr"` → [`TrustLevel::L3`]
//! * `acr` ∈ {`"urn:mace:incommon:iap:silver"`, `"loa2"`} → [`TrustLevel::L2`]
//! * otherwise → [`TrustLevel::L1`]
//!
//! Per-tenant overrides live in [`MappingConfig`]: the trust map can be
//! tightened or extended; group→scope translation is fully configurable;
//! the group claim source can be switched between vendor shapes (Okta's
//! `groups`, Entra's `extra["roles"]`, or a custom path).

use std::collections::HashMap;

use idprova_core::trust::TrustLevel;
use idprova_identity_adapters::{AdapterResult, AttributeMapper, IdTokenClaims};
use serde_json::Value;

/// Where to read group / role membership from in the OIDC claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupClaimSource {
    /// Standard OIDC `groups` claim (Okta, Auth0, Keycloak).
    Standard,
    /// Microsoft Entra `roles` claim (read from `claims.extra["roles"]`).
    EntraRoles,
    /// Any other key in `claims.extra`, e.g. `"my-roles"`.
    Custom(String),
}

/// Tenant-overridable mapping configuration.
#[derive(Debug, Clone)]
pub struct MappingConfig {
    /// ACR string → [`TrustLevel`] overrides. Applied after the `phr` AMR check.
    pub acr_trust_overrides: HashMap<String, TrustLevel>,
    /// Group name → scope strings to grant.
    pub group_scope_map: HashMap<String, Vec<String>>,
    /// Where to find the group claim.
    pub group_claim_source: GroupClaimSource,
}

impl Default for MappingConfig {
    fn default() -> Self {
        let mut acr_trust_overrides = HashMap::new();
        acr_trust_overrides.insert("urn:mace:incommon:iap:silver".to_string(), TrustLevel::L2);
        acr_trust_overrides.insert("loa2".to_string(), TrustLevel::L2);

        let mut group_scope_map = HashMap::new();
        group_scope_map.insert("agents".to_string(), vec!["mcp:tool:*:read".to_string()]);
        group_scope_map.insert("admins".to_string(), vec!["mcp:tool:*:*".to_string()]);

        Self {
            acr_trust_overrides,
            group_scope_map,
            group_claim_source: GroupClaimSource::Standard,
        }
    }
}

/// Generic OIDC attribute mapper driven by [`MappingConfig`].
pub struct GenericAttributeMapper {
    config: MappingConfig,
}

impl GenericAttributeMapper {
    /// Construct with the supplied per-tenant config.
    pub fn new(config: MappingConfig) -> Self {
        Self { config }
    }

    /// Returns the groups list for this claim, sourced per `config.group_claim_source`.
    fn extract_groups(&self, claims: &IdTokenClaims) -> Vec<String> {
        match &self.config.group_claim_source {
            GroupClaimSource::Standard => claims.groups.clone(),
            GroupClaimSource::EntraRoles => extract_string_array(&claims.extra, "roles"),
            GroupClaimSource::Custom(key) => extract_string_array(&claims.extra, key),
        }
    }
}

fn extract_string_array(
    extra: &std::collections::BTreeMap<String, Value>,
    key: &str,
) -> Vec<String> {
    match extra.get(key) {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

impl AttributeMapper for GenericAttributeMapper {
    fn map_trust_level(&self, claims: &IdTokenClaims) -> AdapterResult<TrustLevel> {
        // amr=phr takes precedence over acr.
        if claims.amr.iter().any(|m| m == "phr") {
            return Ok(TrustLevel::L3);
        }

        if let Some(acr) = claims.acr.as_deref() {
            if let Some(level) = self.config.acr_trust_overrides.get(acr) {
                return Ok(*level);
            }
        }

        Ok(TrustLevel::L1)
    }

    fn map_scopes(&self, claims: &IdTokenClaims) -> AdapterResult<Vec<String>> {
        let groups = self.extract_groups(claims);

        let mut scopes: Vec<String> = groups
            .iter()
            .filter_map(|g| self.config.group_scope_map.get(g))
            .flatten()
            .cloned()
            .collect();

        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn base_claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: "https://idp.example.com".into(),
            sub: "user1".into(),
            aud: "client1".into(),
            exp: 9_999_999_999,
            iat: 1_000_000_000,
            nonce: None,
            acr: None,
            amr: vec![],
            groups: vec![],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn phr_amr_maps_to_l3() {
        let mapper = GenericAttributeMapper::new(MappingConfig::default());
        let mut claims = base_claims();
        claims.amr = vec!["phr".into()];
        assert_eq!(mapper.map_trust_level(&claims).unwrap(), TrustLevel::L3);
    }

    #[test]
    fn loa2_acr_maps_to_l2() {
        let mapper = GenericAttributeMapper::new(MappingConfig::default());
        let mut claims = base_claims();
        claims.acr = Some("loa2".into());
        assert_eq!(mapper.map_trust_level(&claims).unwrap(), TrustLevel::L2);
    }

    #[test]
    fn urn_incommon_silver_maps_to_l2() {
        let mapper = GenericAttributeMapper::new(MappingConfig::default());
        let mut claims = base_claims();
        claims.acr = Some("urn:mace:incommon:iap:silver".into());
        assert_eq!(mapper.map_trust_level(&claims).unwrap(), TrustLevel::L2);
    }

    #[test]
    fn unknown_acr_no_phr_maps_to_l1() {
        let mapper = GenericAttributeMapper::new(MappingConfig::default());
        let mut claims = base_claims();
        claims.acr = Some("something-else".into());
        assert_eq!(mapper.map_trust_level(&claims).unwrap(), TrustLevel::L1);
    }

    #[test]
    fn standard_groups_source_maps_and_deduplicates() {
        let mut group_scope_map = HashMap::new();
        group_scope_map.insert(
            "agents".to_string(),
            vec!["mcp:tool:*:read".into(), "mcp:data:read".into()],
        );
        group_scope_map.insert(
            "admins".to_string(),
            // includes a duplicate "mcp:data:read" to verify dedup
            vec!["mcp:tool:*:*".into(), "mcp:data:read".into()],
        );
        let config = MappingConfig {
            group_scope_map,
            ..MappingConfig::default()
        };
        let mapper = GenericAttributeMapper::new(config);

        let mut claims = base_claims();
        claims.groups = vec!["agents".into(), "admins".into(), "unknown".into()];

        let scopes = mapper.map_scopes(&claims).unwrap();
        assert_eq!(
            scopes,
            vec![
                "mcp:data:read".to_string(),
                "mcp:tool:*:*".to_string(),
                "mcp:tool:*:read".to_string(),
            ]
        );
    }

    #[test]
    fn entra_roles_source_reads_extra_roles() {
        let mut group_scope_map = HashMap::new();
        group_scope_map.insert("Writer".to_string(), vec!["write:all".into()]);
        let config = MappingConfig {
            group_scope_map,
            group_claim_source: GroupClaimSource::EntraRoles,
            ..MappingConfig::default()
        };
        let mapper = GenericAttributeMapper::new(config);

        let mut claims = base_claims();
        claims
            .extra
            .insert("roles".to_string(), serde_json::json!(["Writer", "Reader"]));

        let scopes = mapper.map_scopes(&claims).unwrap();
        assert_eq!(scopes, vec!["write:all".to_string()]);
    }

    #[test]
    fn custom_group_source_reads_extra_key() {
        let mut group_scope_map = HashMap::new();
        group_scope_map.insert("devs".to_string(), vec!["code:push".into()]);
        let config = MappingConfig {
            group_scope_map,
            group_claim_source: GroupClaimSource::Custom("my-roles".into()),
            ..MappingConfig::default()
        };
        let mapper = GenericAttributeMapper::new(config);

        let mut claims = base_claims();
        claims
            .extra
            .insert("my-roles".to_string(), serde_json::json!(["devs", "ops"]));

        let scopes = mapper.map_scopes(&claims).unwrap();
        assert_eq!(scopes, vec!["code:push".to_string()]);
    }

    #[test]
    fn unknown_groups_are_dropped() {
        let mapper = GenericAttributeMapper::new(MappingConfig::default());
        let mut claims = base_claims();
        claims.groups = vec!["nonexistent".into(), "also-missing".into()];

        let scopes = mapper.map_scopes(&claims).unwrap();
        assert!(scopes.is_empty());
    }
}
