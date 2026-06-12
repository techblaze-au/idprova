//! Generic OIDC IdP adapter implementation for IDProva.
//!
//! Implements [`OidcIdpAdapter`] for any RFC-conformant OIDC IdP. Performs
//! discovery + JWKS fetch (cached with TTL), then verifies inbound ID-tokens
//! against the JWKS keyed by header `kid`. Algorithms RS256 + ES256 per
//! IDProva-RFC 0001 §4.3.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::Client;
use serde_json::Value;
use tokio::sync::RwLock;

use idprova_identity_adapters::error::{AdapterError, AdapterResult};
use idprova_identity_adapters::oidc::{IdTokenClaims, OidcDiscovery, OidcIdpAdapter};

/// Configuration for the generic OIDC adapter.
#[derive(Clone, Debug)]
pub struct OidcAdapterConfig {
    /// Issuer URL, e.g. `https://acme.okta.com`. MUST match the `iss` of any
    /// ID-token verified by this adapter.
    pub issuer: String,
    /// Cache TTL for both the discovery document and the JWKS. RFC 0001
    /// §4.3 caps this at 24h; recommended 1h.
    pub jwks_cache_ttl: Duration,
}

struct Cached<T> {
    value: T,
    fetched_at: Instant,
}

/// Generic OIDC adapter implementing [`OidcIdpAdapter`].
pub struct GenericOidcAdapter {
    config: OidcAdapterConfig,
    client: Client,
    discovery_cache: Arc<RwLock<Option<Cached<OidcDiscovery>>>>,
    jwks_cache: Arc<RwLock<Option<Cached<jsonwebtoken::jwk::JwkSet>>>>,
}

impl GenericOidcAdapter {
    /// Construct with a default reqwest client.
    pub fn new(config: OidcAdapterConfig) -> Self {
        Self::with_http(config, Client::new())
    }

    /// Construct with a caller-supplied reqwest client (for test injection
    /// or custom timeouts / proxies).
    pub fn with_http(config: OidcAdapterConfig, client: Client) -> Self {
        Self {
            config,
            client,
            discovery_cache: Arc::new(RwLock::new(None)),
            jwks_cache: Arc::new(RwLock::new(None)),
        }
    }

    async fn fetch_discovery(&self) -> AdapterResult<OidcDiscovery> {
        {
            let guard = self.discovery_cache.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < self.config.jwks_cache_ttl {
                    return Ok(cached.value.clone());
                }
            }
        }

        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AdapterError::Remote(e.to_string()))?
            .error_for_status()
            .map_err(|e| AdapterError::Remote(e.to_string()))?
            .json()
            .await
            .map_err(|e| AdapterError::Remote(e.to_string()))?;

        let mut guard = self.discovery_cache.write().await;
        *guard = Some(Cached {
            value: discovery.clone(),
            fetched_at: Instant::now(),
        });
        Ok(discovery)
    }

    async fn fetch_jwks(&self) -> AdapterResult<jsonwebtoken::jwk::JwkSet> {
        {
            let guard = self.jwks_cache.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.fetched_at.elapsed() < self.config.jwks_cache_ttl {
                    return Ok(cached.value.clone());
                }
            }
        }

        let discovery = self.fetch_discovery().await?;
        let jwks: jsonwebtoken::jwk::JwkSet = self
            .client
            .get(&discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| AdapterError::Remote(e.to_string()))?
            .error_for_status()
            .map_err(|e| AdapterError::Remote(e.to_string()))?
            .json()
            .await
            .map_err(|e| AdapterError::Remote(e.to_string()))?;

        let mut guard = self.jwks_cache.write().await;
        *guard = Some(Cached {
            value: jwks.clone(),
            fetched_at: Instant::now(),
        });
        Ok(jwks)
    }

    fn claims_from_payload(payload: Value) -> AdapterResult<IdTokenClaims> {
        let obj = payload
            .as_object()
            .ok_or_else(|| AdapterError::InvalidInput("claims payload is not an object".into()))?;

        let get_string = |key: &str| -> Option<String> {
            obj.get(key).and_then(|v| v.as_str()).map(String::from)
        };
        let get_required_string = |key: &str| -> AdapterResult<String> {
            get_string(key).ok_or_else(|| {
                AdapterError::InvalidInput(format!("missing or invalid required claim: {key}"))
            })
        };

        let iss = get_required_string("iss")?;
        let sub = get_required_string("sub")?;

        let aud = match obj.get("aud") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(arr)) => arr
                .first()
                .and_then(|v| v.as_str())
                .map(String::from)
                .ok_or_else(|| {
                    AdapterError::InvalidInput("aud array is empty or contains non-strings".into())
                })?,
            _ => {
                return Err(AdapterError::InvalidInput(
                    "missing or invalid aud claim".into(),
                ))
            }
        };

        let exp = obj
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AdapterError::InvalidInput("missing or invalid exp claim".into()))?;
        let iat = obj
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AdapterError::InvalidInput("missing or invalid iat claim".into()))?;

        let nonce = get_string("nonce");
        let acr = get_string("acr");

        let amr: Vec<String> = obj
            .get("amr")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let groups: Vec<String> = obj
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        const STANDARD_KEYS: &[&str] = &[
            "iss", "sub", "aud", "exp", "iat", "nonce", "acr", "amr", "groups",
        ];
        let extra: BTreeMap<String, Value> = obj
            .iter()
            .filter(|(k, _)| !STANDARD_KEYS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(IdTokenClaims {
            iss,
            sub,
            aud,
            exp,
            iat,
            nonce,
            acr,
            amr,
            groups,
            extra,
        })
    }
}

impl OidcIdpAdapter for GenericOidcAdapter {
    fn issuer(&self) -> &str {
        &self.config.issuer
    }

    async fn discover(&self) -> AdapterResult<OidcDiscovery> {
        self.fetch_discovery().await
    }

    async fn verify_id_token<'a>(
        &'a self,
        token: &'a str,
        expected_audiences: &'a [&'a str],
    ) -> AdapterResult<IdTokenClaims> {
        const ALLOWED_ALGORITHMS: &[Algorithm] = &[Algorithm::RS256, Algorithm::ES256];

        let header = decode_header(token)
            .map_err(|e| AdapterError::Verification(format!("decode_header: {e}")))?;
        if !ALLOWED_ALGORITHMS.contains(&header.alg) {
            return Err(AdapterError::Verification(format!(
                "unsupported JWT alg: {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AdapterError::Verification("JWT header missing kid".into()))?;

        let jwks = self.fetch_jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(&kid))
            .ok_or_else(|| AdapterError::Verification(format!("no matching JWK for kid: {kid}")))?;

        // Use explicit RSA/EC component extraction rather than DecodingKey::from_jwk:
        // from_jwk requires the JWK to carry a single `alg` and locks the key to it,
        // which breaks when validation.algorithms contains multiple algorithms
        // (RS256+ES256) — jsonwebtoken-9 returns InvalidAlgorithm even for valid
        // RS256-signed tokens. from_rsa_components / from_ec_components let
        // validation.algorithms drive the alg negotiation.
        let decoding_key = match &jwk.algorithm {
            AlgorithmParameters::RSA(rsa) => DecodingKey::from_rsa_components(&rsa.n, &rsa.e)
                .map_err(|e| {
                    AdapterError::Verification(format!("DecodingKey::from_rsa_components: {e}"))
                })?,
            AlgorithmParameters::EllipticCurve(ec) => DecodingKey::from_ec_components(&ec.x, &ec.y)
                .map_err(|e| {
                    AdapterError::Verification(format!("DecodingKey::from_ec_components: {e}"))
                })?,
            _ => {
                return Err(AdapterError::Verification(format!(
                    "unsupported JWK key type for kid: {kid}"
                )));
            }
        };

        // Validation::new(alg) sets algorithms = [alg]. jsonwebtoken-9 requires
        // every entry in validation.algorithms to be supported by the key, so we
        // can't pass [RS256, ES256] against an RSA-only key. The header.alg has
        // already been allowlisted above, so use it directly.
        let mut validation = Validation::new(header.alg);
        validation.set_audience(expected_audiences);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.leeway = 60;

        let token_data = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|e| AdapterError::Verification(format!("decode: {e}")))?;

        Self::claims_from_payload(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn claims_from_payload_extracts_standard_and_extra() {
        let payload = json!({
            "iss": "https://idp.example.com",
            "sub": "user123",
            "aud": "client1",
            "exp": 1700000000i64,
            "iat": 1699999000i64,
            "nonce": "n1",
            "acr": "urn:mace:incommon:iap:silver",
            "amr": ["pwd", "otp"],
            "groups": ["admin", "users"],
            "vendor_custom": 42
        });
        let claims = GenericOidcAdapter::claims_from_payload(payload).unwrap();
        assert_eq!(claims.iss, "https://idp.example.com");
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.aud, "client1");
        assert_eq!(claims.exp, 1700000000);
        assert_eq!(claims.iat, 1699999000);
        assert_eq!(claims.nonce.as_deref(), Some("n1"));
        assert_eq!(claims.acr.as_deref(), Some("urn:mace:incommon:iap:silver"));
        assert_eq!(claims.amr, vec!["pwd".to_string(), "otp".to_string()]);
        assert_eq!(
            claims.groups,
            vec!["admin".to_string(), "users".to_string()]
        );
        assert_eq!(claims.extra.get("vendor_custom"), Some(&json!(42)));
    }

    #[test]
    fn claims_from_payload_normalizes_aud_array() {
        let payload = json!({
            "iss": "https://idp.example.com",
            "sub": "user1",
            "aud": ["primary-aud", "secondary-aud"],
            "exp": 1700000000i64,
            "iat": 1699999000i64
        });
        let claims = GenericOidcAdapter::claims_from_payload(payload).unwrap();
        assert_eq!(claims.aud, "primary-aud");
    }

    #[test]
    fn claims_from_payload_rejects_missing_required() {
        // sub is missing
        let payload = json!({
            "iss": "https://idp.example.com",
            "aud": "client1",
            "exp": 1700000000i64,
            "iat": 1699999000i64
        });
        let result = GenericOidcAdapter::claims_from_payload(payload);
        assert!(matches!(result, Err(AdapterError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn verify_id_token_rejects_malformed_jwt() {
        let adapter = GenericOidcAdapter::new(OidcAdapterConfig {
            issuer: "https://idp.example.com".into(),
            jwks_cache_ttl: Duration::from_secs(3600),
        });
        let result = adapter.verify_id_token("not.a.jwt", &["client1"]).await;
        assert!(matches!(
            result,
            Err(AdapterError::Verification(_)) | Err(AdapterError::InvalidInput(_))
        ));
    }
}
