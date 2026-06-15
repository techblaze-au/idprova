//! Integration tests for `GenericOidcAdapter` — happy-path verification
//! against a synthetic JWKS server for the four target IdP claim shapes
//! (Okta, Microsoft Entra, Auth0, Keycloak).
//!
//! Uses `wiremock` to host both the OIDC discovery endpoint and the
//! JWKS endpoint, plus an ephemeral RSA-2048 keypair generated once per
//! test run. Production IdPs use RS256, so we exercise that path here.
//!
//! Per RFC 0001 §6.1 success criterion: "OIDC adapter passes integration
//! tests against synthetic JWKS for all four IdP shapes."

use std::sync::OnceLock;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use idprova_adapter_oidc_generic::{GenericOidcAdapter, OidcAdapterConfig};
use idprova_identity_adapters::{AdapterError, OidcIdpAdapter};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── Test RSA keypair ─────────────────────────────────────────────────────
//
// Generated at runtime (once per test binary, shared via `OnceLock`) so no
// key material — not even a throwaway test key — is ever committed to the
// repository (`.gitignore` forbids `*.pem`, and the repo policy is NEVER
// commit private keys).

const TEST_JWK_E: &str = "AQAB"; // standard 65537 (RsaPrivateKey::new default)

const TEST_KID: &str = "idprova-test-key-1";

struct TestKey {
    /// PKCS#8 PEM private key, accepted by `EncodingKey::from_rsa_pem`.
    private_pem: String,
    /// JWK `n` (modulus), base64url-no-pad — what a real JWKS endpoint serves.
    jwk_n: String,
}

fn test_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA-2048 key");
        let private_pem = key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("encode test key as PKCS#8 PEM")
            .to_string();
        let jwk_n = URL_SAFE_NO_PAD.encode(key.to_public_key().n().to_bytes_be());
        TestKey { private_pem, jwk_n }
    })
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn make_signed_jwt(payload: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let key = EncodingKey::from_rsa_pem(test_key().private_pem.as_bytes())
        .expect("test PEM parses as RSA private key");
    jsonwebtoken::encode(&header, &payload, &key).expect("JWT sign")
}

fn build_adapter(issuer: &str) -> GenericOidcAdapter {
    GenericOidcAdapter::new(OidcAdapterConfig {
        issuer: issuer.to_string(),
        jwks_cache_ttl: Duration::from_secs(60),
    })
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs() as i64
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn okta_shape_id_token_verifies_and_maps_claims() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    register_routes(&server).await;

    let now = now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "okta-user-id-abc",
        "aud": "idprova-client",
        "exp": now + 600,
        "iat": now,
        "amr": ["pwd", "mfa"],
        "groups": ["agents", "admins"],
    });
    let token = make_signed_jwt(payload);

    let adapter = build_adapter(&issuer);
    let claims = adapter
        .verify_id_token(&token, &["idprova-client"])
        .await
        .expect("Okta-shape JWT verifies");

    assert_eq!(claims.iss, issuer);
    assert_eq!(claims.sub, "okta-user-id-abc");
    assert_eq!(claims.aud, "idprova-client");
    assert_eq!(
        claims.groups,
        vec!["agents".to_string(), "admins".to_string()]
    );
    assert_eq!(claims.amr, vec!["pwd".to_string(), "mfa".to_string()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn entra_shape_id_token_with_roles_in_extra() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    register_routes(&server).await;

    let now = now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "entra-object-id-xyz",
        "aud": "idprova-client",
        "exp": now + 600,
        "iat": now,
        "roles": ["Writer", "Reader"],          // Entra app roles claim
        "tid": "00000000-0000-0000-0000-000000000001",
    });
    let token = make_signed_jwt(payload);

    let adapter = build_adapter(&issuer);
    let claims = adapter
        .verify_id_token(&token, &["idprova-client"])
        .await
        .expect("Entra-shape JWT verifies");

    assert_eq!(claims.sub, "entra-object-id-xyz");
    let roles = claims
        .extra
        .get("roles")
        .expect("roles claim ended up in extra");
    assert!(roles.is_array());
    let role_strs: Vec<&str> = roles
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(role_strs, vec!["Writer", "Reader"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn auth0_shape_id_token_with_custom_namespace_claim() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    register_routes(&server).await;

    let now = now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "auth0|abc123",
        "aud": "idprova-client",
        "exp": now + 600,
        "iat": now,
        "https://idprova.com/tier": "enterprise",  // Auth0 namespaced claim
        "groups": [],
    });
    let token = make_signed_jwt(payload);

    let adapter = build_adapter(&issuer);
    let claims = adapter
        .verify_id_token(&token, &["idprova-client"])
        .await
        .expect("Auth0-shape JWT verifies");

    let tier = claims
        .extra
        .get("https://idprova.com/tier")
        .expect("namespaced claim in extra");
    assert_eq!(tier.as_str(), Some("enterprise"));
}

#[tokio::test(flavor = "multi_thread")]
async fn keycloak_shape_id_token_with_realm_access() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    register_routes(&server).await;

    let now = now_secs();
    let payload = json!({
        "iss": issuer,
        "sub": "keycloak-user-uuid",
        "aud": "idprova-client",
        "exp": now + 600,
        "iat": now,
        "realm_access": { "roles": ["agent-role", "admin"] },
        "groups": [],
    });
    let token = make_signed_jwt(payload);

    let adapter = build_adapter(&issuer);
    let claims = adapter
        .verify_id_token(&token, &["idprova-client"])
        .await
        .expect("Keycloak-shape JWT verifies");

    let realm = claims
        .extra
        .get("realm_access")
        .expect("realm_access in extra");
    assert!(realm.is_object());
    let roles = realm
        .get("roles")
        .and_then(|v| v.as_array())
        .expect("realm_access.roles is array");
    let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(role_strs, vec!["agent-role", "admin"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_issuer_is_rejected() {
    let server = MockServer::start().await;
    let issuer = server.uri();
    register_routes(&server).await;

    let now = now_secs();
    // Token's iss claim does NOT match the adapter's configured issuer.
    let payload = json!({
        "iss": "https://other.example.com",
        "sub": "evil-actor",
        "aud": "idprova-client",
        "exp": now + 600,
        "iat": now,
    });
    let token = make_signed_jwt(payload);

    let adapter = build_adapter(&issuer); // configured for our mock server
    let result = adapter.verify_id_token(&token, &["idprova-client"]).await;

    assert!(
        matches!(result, Err(AdapterError::Verification(_))),
        "expected Verification error, got: {result:?}"
    );
}

// ─── Route helper ─────────────────────────────────────────────────────────

async fn register_routes(server: &MockServer) {
    let base = server.uri();
    let discovery_body = json!({
        "issuer": base,
        "jwks_uri": format!("{}/jwks.json", base),
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "acr_values_supported": ["loa2", "urn:mace:incommon:iap:silver"],
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery_body))
        .mount(server)
        .await;

    let jwks_body = json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": TEST_KID,
            "n": test_key().jwk_n,
            "e": TEST_JWK_E,
        }]
    });
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body))
        .mount(server)
        .await;
}
