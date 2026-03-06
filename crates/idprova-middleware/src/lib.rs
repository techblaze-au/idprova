//! # idprova-middleware
//!
//! Axum/Tower middleware for IDProva DAT bearer token verification.
//!
//! ## Usage
//!
//! Add [`DatVerificationLayer`] to your Axum router. On every request it:
//!
//! 1. Extracts the `Authorization: Bearer <compact-jws>` header
//! 2. Validates the URL-safe token is SSRF-safe (no private IPs in issuer DID)
//! 3. Verifies signature, timing, scope, and all constraint evaluators
//! 4. Injects a [`VerifiedDat`] extension into the request on success
//! 5. Returns `401 Unauthorized` or `403 Forbidden` with a JSON error body on failure
//!
//! ## Example
//!
//! ```rust,no_run
//! use axum::{Router, routing::get, Extension};
//! use idprova_middleware::{DatVerificationLayer, VerifiedDat};
//!
//! async fn protected_handler(Extension(verified): Extension<VerifiedDat>) -> String {
//!     format!("Hello, {}!", verified.subject_did)
//! }
//!
//! let pub_key = [0u8; 32]; // issuer's Ed25519 public key bytes
//! let app: Router = Router::new()
//!     .route("/api/action", get(protected_handler))
//!     .layer(DatVerificationLayer::new(pub_key, "mcp:tool:read"));
//! ```

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{HeaderMap, Request, Response, StatusCode},
};
use serde_json::json;
use tower::{Layer, Service};

use idprova_core::dat::{constraints::EvaluationContext, Dat};
use idprova_verify::verify_dat;

// ── VerifiedDat extension ─────────────────────────────────────────────────────

/// Request extension injected by [`DatVerificationLayer`] on successful verification.
///
/// Access via `Extension<VerifiedDat>` in Axum handlers.
#[derive(Debug, Clone)]
pub struct VerifiedDat {
    /// The verified DAT (all claims accessible).
    pub dat: Dat,
    /// Issuer DID (`iss` claim).
    pub issuer_did: String,
    /// Subject DID (`sub` claim) — the agent that holds this token.
    pub subject_did: String,
    /// Granted scopes from the token.
    pub scopes: Vec<String>,
}

// ── Layer ─────────────────────────────────────────────────────────────────────

/// Tower [`Layer`] that wraps a service with DAT bearer token verification.
///
/// Cloneable — safe to share across Axum routes.
#[derive(Clone)]
pub struct DatVerificationLayer {
    pub_key: [u8; 32],
    required_scope: String,
}

impl DatVerificationLayer {
    /// Create a new layer.
    ///
    /// - `pub_key`: Ed25519 public key bytes of the expected token issuer.
    /// - `required_scope`: Scope string the token must grant (e.g. `"mcp:tool:read"`).
    ///   Pass `""` to skip scope checking.
    pub fn new(pub_key: [u8; 32], required_scope: impl Into<String>) -> Self {
        Self {
            pub_key,
            required_scope: required_scope.into(),
        }
    }
}

impl<S> Layer<S> for DatVerificationLayer {
    type Service = DatVerificationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        DatVerificationService {
            inner,
            pub_key: self.pub_key,
            required_scope: self.required_scope.clone(),
        }
    }
}

// ── Service ───────────────────────────────────────────────────────────────────

/// The wrapped service produced by [`DatVerificationLayer`].
#[derive(Clone)]
pub struct DatVerificationService<S> {
    inner: S,
    pub_key: [u8; 32],
    required_scope: String,
}

impl<S> Service<Request<Body>> for DatVerificationService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let pub_key = self.pub_key;
        let required_scope = self.required_scope.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract bearer token
            let token = match extract_bearer_token(req.headers()) {
                Ok(t) => t,
                Err(resp) => return Ok(*resp),
            };

            // Build EvaluationContext from request headers
            let ctx = build_evaluation_context(req.headers());

            // Verify the DAT
            match verify_dat(&token, &pub_key, &required_scope, &ctx) {
                Ok(dat) => {
                    // Inject VerifiedDat extension
                    let verified = VerifiedDat {
                        issuer_did: dat.claims.iss.clone(),
                        subject_did: dat.claims.sub.clone(),
                        scopes: dat.claims.scope.clone(),
                        dat,
                    };
                    req.extensions_mut().insert(verified);
                    inner.call(req).await
                }
                Err(e) => {
                    let msg = e.to_string();
                    let status = if msg.contains("expired")
                        || msg.contains("not yet valid")
                        || msg.contains("signature verification failed")
                        || msg.contains("algorithm")
                        || msg.contains("malformed")
                        || msg.contains("compact JWS")
                        || msg.contains("decode")
                    {
                        StatusCode::UNAUTHORIZED
                    } else {
                        // scope denied, constraint violation
                        StatusCode::FORBIDDEN
                    };
                    Ok(error_response(status, &msg))
                }
            }
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Result<String, Box<Response<Body>>> {
    let auth = headers
        .get("Authorization")
        .ok_or_else(|| Box::new(error_response(StatusCode::UNAUTHORIZED, "missing Authorization header")))?;

    let auth_str = auth
        .to_str()
        .map_err(|_| Box::new(error_response(StatusCode::UNAUTHORIZED, "invalid Authorization header encoding")))?;

    if let Some(token) = auth_str.strip_prefix("Bearer ") {
        let token = token.trim();
        if token.is_empty() {
            return Err(Box::new(error_response(StatusCode::UNAUTHORIZED, "empty bearer token")));
        }
        Ok(token.to_string())
    } else {
        Err(Box::new(error_response(
            StatusCode::UNAUTHORIZED,
            "Authorization header must use Bearer scheme",
        )))
    }
}

/// Build an [`EvaluationContext`] from request headers.
///
/// - Client IP: extracted from `X-Forwarded-For` (first entry) or `X-Real-IP`
/// - All other fields default to zero/None
fn build_evaluation_context(headers: &HeaderMap) -> EvaluationContext {
    let request_ip = extract_client_ip(headers);

    EvaluationContext {
        request_ip,
        ..Default::default()
    }
}

/// Extract the real client IP from proxy headers.
///
/// Priority: `X-Forwarded-For` (first IP) → `X-Real-IP` → None
fn extract_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    // X-Forwarded-For: <client>, <proxy1>, <proxy2>
    if let Some(xff) = headers.get("X-Forwarded-For") {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // X-Real-IP (nginx convention)
    if let Some(xri) = headers.get("X-Real-IP") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    None
}

/// Build a JSON error response with the given status code.
fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let body = serde_json::to_string(&json!({ "error": message, "status": status.as_u16() }))
        .unwrap_or_else(|_| format!("{{\"error\":\"{message}\"}}"));

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::to_bytes, routing::get, Extension, Router};
    use chrono::{Duration, Utc};
    use idprova_core::{crypto::KeyPair, dat::Dat};
    use tower::ServiceExt;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn issue_token(kp: &KeyPair, scope: &str, valid: bool) -> String {
        let expires = if valid {
            Utc::now() + Duration::hours(24)
        } else {
            Utc::now() - Duration::hours(1)
        };
        let dat = Dat::issue(
            "did:idprova:test:issuer",
            "did:idprova:test:agent",
            vec![scope.to_string()],
            expires,
            None,
            None,
            kp,
        )
        .unwrap();
        dat.to_compact().unwrap()
    }

    fn test_router(pub_key: [u8; 32], required_scope: &str) -> Router {
        async fn handler(Extension(v): Extension<VerifiedDat>) -> String {
            format!("ok:{}", v.subject_did)
        }

        Router::new()
            .route("/protected", get(handler))
            .layer(DatVerificationLayer::new(pub_key, required_scope))
    }

    async fn get_with_auth(app: Router, token: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    async fn get_no_auth(app: Router) -> (StatusCode, String) {
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    // ── Integration tests ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_valid_token_passes() {
        let kp = KeyPair::generate();
        let token = issue_token(&kp, "mcp:tool:read", true);
        let app = test_router(kp.public_key_bytes(), "mcp:tool:read");

        let (status, body) = get_with_auth(app, &token).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("did:idprova:test:agent"), "body: {body}");
    }

    #[tokio::test]
    async fn test_missing_auth_header_returns_401() {
        let kp = KeyPair::generate();
        let app = test_router(kp.public_key_bytes(), "mcp:tool:read");

        let (status, body) = get_no_auth(app).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("Authorization"), "body: {body}");
    }

    #[tokio::test]
    async fn test_wrong_key_returns_401() {
        let kp = KeyPair::generate();
        let kp2 = KeyPair::generate(); // different key
        let token = issue_token(&kp, "mcp:tool:read", true);
        let app = test_router(kp2.public_key_bytes(), "mcp:tool:read");

        let (status, _) = get_with_auth(app, &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_expired_token_returns_401() {
        let kp = KeyPair::generate();
        let token = issue_token(&kp, "mcp:tool:read", false); // expired
        let app = test_router(kp.public_key_bytes(), "mcp:tool:read");

        let (status, body) = get_with_auth(app, &token).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("expired"), "body: {body}");
    }

    #[tokio::test]
    async fn test_wrong_scope_returns_403() {
        let kp = KeyPair::generate();
        let token = issue_token(&kp, "mcp:tool:read", true);
        let app = test_router(kp.public_key_bytes(), "mcp:tool:write"); // requires write

        let (status, body) = get_with_auth(app, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(body.contains("scope"), "body: {body}");
    }

    #[tokio::test]
    async fn test_wildcard_scope_passes() {
        let kp = KeyPair::generate();
        let token = issue_token(&kp, "mcp:*:*", true);
        let app = test_router(kp.public_key_bytes(), "mcp:tool:write");

        let (status, _) = get_with_auth(app, &token).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_malformed_token_returns_401() {
        let kp = KeyPair::generate();
        let app = test_router(kp.public_key_bytes(), "mcp:tool:read");

        let (status, _) = get_with_auth(app, "not.a.valid.token").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_bearer_scheme_required() {
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let kp = KeyPair::generate();
        let app = test_router(kp.public_key_bytes(), "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_extract_client_ip_from_xff() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "203.0.113.1, 10.0.0.1".parse().unwrap());
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_from_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "203.0.113.5".parse().unwrap());
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_xff_takes_priority() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "1.2.3.4".parse().unwrap());
        headers.insert("X-Real-IP", "5.6.7.8".parse().unwrap());
        let ip = extract_client_ip(&headers);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_extract_client_ip_none_when_absent() {
        let headers = HeaderMap::new();
        assert!(extract_client_ip(&headers).is_none());
    }

    #[test]
    fn test_extract_client_ip_invalid_value_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "not-an-ip".parse().unwrap());
        assert!(extract_client_ip(&headers).is_none());
    }
}
