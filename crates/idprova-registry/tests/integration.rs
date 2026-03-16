use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use idprova_core::aid::AidBuilder;
use idprova_core::crypto::KeyPair;
use idprova_registry::{build_app, store::AidStore, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

fn make_app() -> axum::Router {
    let store = AidStore::new_in_memory().unwrap();
    let state = AppState::new(store, None); // dev mode (no admin auth)
    build_app(state)
}

fn make_aid_json(kp: &KeyPair) -> Value {
    let doc = AidBuilder::new()
        .id("did:aid:example.com:test-agent")
        .controller("did:aid:example.com:alice")
        .name("Test Agent")
        .add_ed25519_key(kp)
        .build()
        .unwrap();
    serde_json::to_value(doc).unwrap()
}

async fn body_to_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ── 1. Health endpoint ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["protocol"], "idprova/0.1");
}

// ── 2. Register and resolve AID round-trip ──────────────────────────────────

#[tokio::test]
async fn test_register_and_resolve_aid() {
    let app = make_app();
    let kp = KeyPair::generate();
    let aid_json = make_aid_json(&kp);

    // PUT to register
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/aid/example.com:test-agent")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&aid_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET to resolve
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/aid/example.com:test-agent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["id"], "did:aid:example.com:test-agent");
}

// ── 3. Register invalid JSON ────────────────────────────────────────────────

#[tokio::test]
async fn test_register_invalid_json() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/aid/example.com:bad")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"not": "an aid document"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 4. Resolve nonexistent AID ──────────────────────────────────────────────

#[tokio::test]
async fn test_resolve_nonexistent() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/aid/example.com:nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── 5. Deactivate AID ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_deactivate_aid() {
    let app = make_app();
    let kp = KeyPair::generate();
    let aid_json = make_aid_json(&kp);

    // Register first
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/aid/example.com:test-agent")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&aid_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // DELETE to deactivate
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/aid/example.com:test-agent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["status"], "deactivated");

    // GET should now return 404
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/aid/example.com:test-agent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── 6. Revoke and check ────────────────────────────────────────────────────

#[tokio::test]
async fn test_revoke_and_check() {
    let app = make_app();

    // Revoke a JTI
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dat/revoke")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "jti": "dat_test123",
                        "reason": "compromised",
                        "revoked_by": "did:aid:example.com:alice"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["status"], "revoked");

    // Check revocation status
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/dat/revoked/dat_test123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_json(resp.into_body()).await;
    assert_eq!(body["revoked"], true);
}

// ── 7. Revoke empty JTI ────────────────────────────────────────────────────

#[tokio::test]
async fn test_revoke_empty_jti() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/dat/revoke")
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"jti": ""}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 8. Concurrent PUT/GET ──────────────────────────────────────────────────

#[tokio::test]
async fn test_concurrent_put_get() {
    let store = AidStore::new_in_memory().unwrap();
    let state = AppState::new(store, None);

    // Pre-register one AID
    let kp = KeyPair::generate();
    let aid_json = make_aid_json(&kp);
    state
        .store
        .put(
            "did:aid:example.com:test-agent",
            &serde_json::from_value(aid_json.clone()).unwrap(),
        )
        .unwrap();

    let app = build_app(state);

    let mut handles = Vec::new();
    for i in 0..20 {
        let app = app.clone();
        let aid_json = aid_json.clone();
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                // PUT
                let resp = app
                    .oneshot(
                        Request::builder()
                            .method("PUT")
                            .uri("/v1/aid/example.com:test-agent")
                            .header("Content-Type", "application/json")
                            .body(Body::from(serde_json::to_string(&aid_json).unwrap()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert!(
                    resp.status() == StatusCode::OK || resp.status() == StatusCode::CREATED,
                    "PUT failed with {}",
                    resp.status()
                );
            } else {
                // GET
                let resp = app
                    .oneshot(
                        Request::builder()
                            .uri("/v1/aid/example.com:test-agent")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ── 9. Security headers present ─────────────────────────────────────────────

#[tokio::test]
async fn test_security_headers_present() {
    let app = make_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("X-Content-Type-Options").unwrap(),
        "nosniff"
    );
    assert_eq!(resp.headers().get("X-Frame-Options").unwrap(), "DENY");
    assert!(resp
        .headers()
        .get("Strict-Transport-Security")
        .is_some());
    assert!(resp.headers().get("X-XSS-Protection").is_some());
}

// ── 10. Oversized body rejected ─────────────────────────────────────────────

#[tokio::test]
async fn test_oversized_body_rejected() {
    let app = make_app();
    let big_body = "x".repeat(2 * 1024 * 1024); // 2MB > 1MB limit
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/v1/aid/example.com:big")
                .header("Content-Type", "application/json")
                .body(Body::from(big_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
