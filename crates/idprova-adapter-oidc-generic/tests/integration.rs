//! Integration tests for `GenericOidcAdapter` — happy-path verification
//! against a synthetic JWKS server for the four target IdP claim shapes
//! (Okta, Microsoft Entra, Auth0, Keycloak).
//!
//! Uses `wiremock` to host both the OIDC discovery endpoint and the
//! JWKS endpoint, plus a hardcoded test RSA-2048 keypair. Production
//! IdPs use RS256, so we exercise that path here.
//!
//! Per RFC 0001 §6.1 success criterion: "OIDC adapter passes integration
//! tests against synthetic JWKS for all four IdP shapes."

use std::time::Duration;

use idprova_adapter_oidc_generic::{GenericOidcAdapter, OidcAdapterConfig};
use idprova_identity_adapters::{AdapterError, OidcIdpAdapter};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── Test RSA keypair ─────────────────────────────────────────────────────
//
// PKCS#8 PEM, RSA 2048, generated 2026-05-19 for testing only. NEVER use
// these keys outside tests — they are public in this source tree.
//
//   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
//       -out test_rsa_priv.pem -outform PEM
//   openssl rsa -in test_rsa_priv.pem -pubout -out test_rsa_pub.pem
//
// To inline-replace: run the commands above and paste the contents.
// The harness expects these to parse via `EncodingKey::from_rsa_pem` and
// the JWK n / e fields are derived from the public key (see jwk_for_kid).

const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!("test_keys/rsa_priv.pem");

/// Matching JWK public-key fields (modulus + exponent, base64url-no-pad).
/// Generated alongside the PEM above with:
///   openssl rsa -pubin -in test_rsa_pub.pem -RSAPublicKey_out -modulus
/// then base64url-encoded.
const TEST_JWK_N: &str = include_str!("test_keys/jwk_n.txt");
const TEST_JWK_E: &str = "AQAB"; // standard 65537

const TEST_KID: &str = "idprova-test-key-1";

// ─── Helpers ──────────────────────────────────────────────────────────────

fn make_signed_jwt(payload: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
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
            "n": TEST_JWK_N.trim(),
            "e": TEST_JWK_E,
        }]
    });
    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body))
        .mount(server)
        .await;
}
