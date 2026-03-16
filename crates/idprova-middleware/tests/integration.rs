use axum::{
    extract::Extension,
    http::StatusCode,
    middleware,
    response::Json,
    routing::get,
    Router,
};
use chrono::{Duration, Utc};
use idprova_core::crypto::KeyPair;
use idprova_core::dat::Dat;
use idprova_middleware::{dat_verification_middleware, DatVerificationConfig, VerifiedDat};
use serde_json::{json, Value};
use tokio::net::TcpListener;

fn make_config(kp: &KeyPair, scope: &str) -> DatVerificationConfig {
    DatVerificationConfig {
        public_key: kp.public_key_bytes(),
        required_scope: scope.to_string(),
    }
}

fn issue_token(kp: &KeyPair, scope: &str, valid: bool) -> String {
    let expires = if valid {
        Utc::now() + Duration::hours(24)
    } else {
        Utc::now() - Duration::hours(1)
    };
    let dat = Dat::issue(
        "did:aid:test:issuer",
        "did:aid:test:agent",
        vec![scope.to_string()],
        expires,
        None,
        None,
        kp,
    )
    .unwrap();
    dat.to_compact().unwrap()
}

fn build_test_app(config: DatVerificationConfig) -> Router {
    Router::new()
        .route(
            "/protected",
            get(|Extension(dat): Extension<VerifiedDat>| async move {
                Json(json!({
                    "subject": dat.subject_did,
                    "issuer": dat.issuer_did,
                    "scopes": dat.scopes,
                    "jti": dat.jti,
                }))
            }),
        )
        .layer(middleware::from_fn_with_state(
            config.clone(),
            dat_verification_middleware,
        ))
        .with_state(config)
}

async fn spawn_test_server(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn test_no_auth_header_returns_401() {
    let kp = KeyPair::generate();
    let app = build_test_app(make_config(&kp, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let resp = reqwest::get(format!("{base}/protected")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn test_empty_bearer_returns_401() {
    let kp = KeyPair::generate();
    let app = build_test_app(make_config(&kp, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", "Bearer ")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_malformed_token_returns_401() {
    let kp = KeyPair::generate();
    let app = build_test_app(make_config(&kp, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", "Bearer not.a.valid.token.at.all")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_valid_token_correct_scope_returns_200() {
    let kp = KeyPair::generate();
    let token = issue_token(&kp, "mcp:tool:echo:call", true);
    let app = build_test_app(make_config(&kp, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["subject"], "did:aid:test:agent");
    assert_eq!(body["issuer"], "did:aid:test:issuer");
}

#[tokio::test]
async fn test_valid_token_wrong_scope_returns_403() {
    let kp = KeyPair::generate();
    let token = issue_token(&kp, "mcp:tool:echo:call", true);
    let app = build_test_app(make_config(&kp, "mcp:tool:write:execute"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "forbidden");
}

#[tokio::test]
async fn test_expired_token_returns_401() {
    let kp = KeyPair::generate();
    let token = issue_token(&kp, "mcp:tool:echo:call", false); // expired
    let app = build_test_app(make_config(&kp, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_wrong_signing_key_returns_401() {
    let kp1 = KeyPair::generate();
    let kp2 = KeyPair::generate();
    let token = issue_token(&kp1, "mcp:tool:echo:call", true);
    // Config uses kp2's public key, but token signed with kp1
    let app = build_test_app(make_config(&kp2, "mcp:tool:echo:call"));
    let base = spawn_test_server(app).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{base}/protected"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
