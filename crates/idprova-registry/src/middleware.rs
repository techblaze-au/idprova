//! Axum middleware layers — security headers + per-IP rate limiting.

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use serde_json::json;
use std::net::SocketAddr;

use crate::state::SharedState;

/// Axum middleware that appends security headers to every response.
///
/// * `X-Content-Type-Options: nosniff`
/// * `X-Frame-Options: DENY`
/// * `X-XSS-Protection: 1; mode=block`
/// * `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
/// * `Strict-Transport-Security: max-age=31536000; includeSubDomains`
///   (only when `IDPROVA_TLS=true`)
pub async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    if std::env::var("IDPROVA_TLS").unwrap_or_default() == "true" {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    response
}

/// Per-IP rate limit: 120 requests / 60 s window. Source IP is taken
/// from `X-Forwarded-For` → `X-Real-IP` → peer socket address, in that
/// order, so the registry works correctly behind a trusted proxy.
pub async fn rate_limit_middleware(
    State(state): State<SharedState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Determine client IP: prefer proxy headers, fall back to peer
    // socket address.
    let ip = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            req.headers()
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .or_else(|| connect_info.map(|ci| ci.0.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let allowed = {
        let mut limiter = state.rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.check_and_record(&ip, 120)
    };

    if allowed {
        next.run(req).await
    } else {
        let body = serde_json::to_string(&json!({
            "error": "rate limit exceeded — max 120 requests per 60 seconds per IP"
        }))
        .unwrap_or_default();
        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "application/json")
            .header("Retry-After", "60")
            .body(Body::from(body))
            .unwrap()
    }
}
