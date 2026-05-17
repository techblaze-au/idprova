//! `OidcIdpAdapter` — port for verifying inbound OIDC assertions.
//!
//! An adapter implementation owns the configuration of exactly one
//! Identity Provider (one issuer URL, one set of JWKS, one tenant per
//! ADR 0003). Implementations live in separate crates
//! (`idprova-adapter-oidc-generic`, vendor-specific shims) and depend
//! on this trait crate plus their HTTP client of choice.

use serde::{Deserialize, Serialize};

use crate::error::AdapterResult;

/// Parsed OIDC ID-token claim shape — the subset IDProva consumes
/// during the OIDC bridge flow (RFC 0001 §6.1, Flow 1).
///
/// Adapters MAY surface additional vendor-specific claims via
/// [`IdTokenClaims::extra`] when their IdP carries them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer URL (`iss`).
    pub iss: String,
    /// Subject — opaque IdP-side user identifier (`sub`).
    pub sub: String,
    /// Audience (`aud`). Adapters may return either a single audience
    /// or a list; this trait normalises to the first allowed value.
    pub aud: String,
    /// Expiry, seconds since Unix epoch (`exp`).
    pub exp: i64,
    /// Issued-at, seconds since Unix epoch (`iat`).
    pub iat: i64,
    /// Optional nonce echo (`nonce`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Authentication Context Class Reference (`acr`), if present.
    /// Mapped to IDProva trust levels by an [`AttributeMapper`]
    /// (see `attributes` module).
    ///
    /// [`AttributeMapper`]: crate::attributes::AttributeMapper
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication Methods Reference (`amr`), if present.
    /// `["phr"]` (phishing-resistant) is a strong L3 signal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub amr: Vec<String>,
    /// Group memberships, if present (vendor-specific claim name —
    /// Okta uses `groups`, Entra uses `roles`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Vendor-specific or unstandardised claims kept as raw JSON
    /// values so downstream code can opt in.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// OIDC discovery metadata — the v0.2 subset required by IDProva.
/// Sourced from the IdP's `/.well-known/openid-configuration` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    /// Issuer URL — MUST match the `iss` of any ID-token verified by
    /// this adapter.
    pub issuer: String,
    /// JWKS URI — `jwks_uri` from the discovery document.
    pub jwks_uri: String,
    /// Supported `acr` values (`acr_values_supported`), if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acr_values_supported: Vec<String>,
    /// Supported signing algorithms (`id_token_signing_alg_values_supported`).
    /// At minimum, adapters MUST support `"RS256"` and `"ES256"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// Verifies inbound OIDC ID-tokens for the bridge flow defined in
/// RFC 0001 §6.1 Flow 1.
///
/// **Lifecycle.** A typical adapter performs the following steps on
/// construction:
/// 1. Fetch and cache the [`OidcDiscovery`] document.
/// 2. Fetch and cache the JWKS, respecting `Cache-Control` (max 24 h
///    per RFC 0001).
///
/// On every [`verify_id_token`] call, the adapter validates the JWT
/// against the cached JWKS and surfaces the resulting [`IdTokenClaims`].
///
/// [`verify_id_token`]: Self::verify_id_token
pub trait OidcIdpAdapter: Send + Sync {
    /// Returns the configured issuer URL. Stable for the lifetime of
    /// the adapter (set at construction).
    fn issuer(&self) -> &str;

    /// Returns the (possibly cached) discovery document. Adapters MAY
    /// refresh transparently when the cache TTL expires.
    fn discover(&self) -> impl std::future::Future<Output = AdapterResult<OidcDiscovery>> + Send;

    /// Verifies an inbound ID-token against the cached JWKS and
    /// returns the parsed claims on success. Implementations MUST:
    ///
    /// * verify the JWT signature against the JWKS key matching the
    ///   token's `kid` header;
    /// * reject tokens whose `iss` does not match [`Self::issuer`];
    /// * reject tokens past their `exp` (allow ≤ 60 s clock skew);
    /// * reject tokens with `aud` outside `expected_audiences`.
    fn verify_id_token<'a>(
        &'a self,
        token: &'a str,
        expected_audiences: &'a [&'a str],
    ) -> impl std::future::Future<Output = AdapterResult<IdTokenClaims>> + Send + 'a;
}

#[cfg(test)]
pub mod testing {
    //! In-tree mock implementation for downstream-crate testing.
    //!
    //! Downstream crates that depend on this trait can use
    //! [`MockOidcIdpAdapter`] as a stand-in for a real OIDC adapter
    //! during unit tests.

    use super::*;

    /// A mock adapter that returns canned [`IdTokenClaims`] for any
    /// token string.
    ///
    /// Construct with [`MockOidcIdpAdapter::with_claims`] to control
    /// what `verify_id_token` returns. Construct with
    /// [`MockOidcIdpAdapter::reject_all`] to make every verification
    /// fail with an [`AdapterError::Verification`] error.
    ///
    /// [`AdapterError::Verification`]: crate::error::AdapterError::Verification
    pub struct MockOidcIdpAdapter {
        issuer: String,
        discovery: OidcDiscovery,
        outcome: Outcome,
    }

    enum Outcome {
        Accept(IdTokenClaims),
        Reject(String),
    }

    impl MockOidcIdpAdapter {
        /// Construct a mock that accepts every token and returns the
        /// supplied claims.
        pub fn with_claims(issuer: impl Into<String>, claims: IdTokenClaims) -> Self {
            let issuer = issuer.into();
            Self {
                discovery: OidcDiscovery {
                    issuer: issuer.clone(),
                    jwks_uri: format!("{issuer}/.well-known/jwks.json"),
                    acr_values_supported: vec![],
                    id_token_signing_alg_values_supported: vec!["RS256".to_string()],
                },
                issuer,
                outcome: Outcome::Accept(claims),
            }
        }

        /// Construct a mock that rejects every token with the supplied
        /// reason.
        pub fn reject_all(issuer: impl Into<String>, reason: impl Into<String>) -> Self {
            let issuer = issuer.into();
            Self {
                discovery: OidcDiscovery {
                    issuer: issuer.clone(),
                    jwks_uri: format!("{issuer}/.well-known/jwks.json"),
                    acr_values_supported: vec![],
                    id_token_signing_alg_values_supported: vec!["RS256".to_string()],
                },
                issuer,
                outcome: Outcome::Reject(reason.into()),
            }
        }
    }

    impl OidcIdpAdapter for MockOidcIdpAdapter {
        fn issuer(&self) -> &str {
            &self.issuer
        }

        async fn discover(&self) -> AdapterResult<OidcDiscovery> {
            Ok(self.discovery.clone())
        }

        async fn verify_id_token(
            &self,
            _token: &str,
            _expected_audiences: &[&str],
        ) -> AdapterResult<IdTokenClaims> {
            match &self.outcome {
                Outcome::Accept(claims) => Ok(claims.clone()),
                Outcome::Reject(reason) => Err(crate::error::AdapterError::Verification(
                    reason.clone(),
                )),
            }
        }
    }

    #[tokio::test]
    async fn mock_accepts_token_and_returns_claims() {
        let claims = IdTokenClaims {
            iss: "https://example.com".to_string(),
            sub: "alice".to_string(),
            aud: "idprova".to_string(),
            exp: 0,
            iat: 0,
            nonce: None,
            acr: Some("phr".to_string()),
            amr: vec!["phr".to_string()],
            groups: vec!["agents".to_string()],
            extra: Default::default(),
        };
        let adapter =
            MockOidcIdpAdapter::with_claims("https://example.com", claims.clone());
        let got = adapter
            .verify_id_token("any-token", &["idprova"])
            .await
            .expect("mock accepts");
        assert_eq!(got.sub, "alice");
        assert_eq!(adapter.issuer(), "https://example.com");
    }

    #[tokio::test]
    async fn mock_reject_returns_verification_error() {
        let adapter = MockOidcIdpAdapter::reject_all("https://example.com", "kid not found");
        let err = adapter
            .verify_id_token("any-token", &["idprova"])
            .await
            .unwrap_err();
        match err {
            crate::error::AdapterError::Verification(msg) => {
                assert!(msg.contains("kid not found"))
            }
            other => panic!("expected Verification error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mock_discovery_is_idempotent() {
        let claims = IdTokenClaims {
            iss: "https://example.com".to_string(),
            sub: "x".to_string(),
            aud: "idprova".to_string(),
            exp: 0,
            iat: 0,
            nonce: None,
            acr: None,
            amr: vec![],
            groups: vec![],
            extra: Default::default(),
        };
        let adapter = MockOidcIdpAdapter::with_claims("https://example.com", claims);
        let d1 = adapter.discover().await.unwrap();
        let d2 = adapter.discover().await.unwrap();
        assert_eq!(d1.issuer, d2.issuer);
        assert_eq!(d1.jwks_uri, d2.jwks_uri);
    }
}
