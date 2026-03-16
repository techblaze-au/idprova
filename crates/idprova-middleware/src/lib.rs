//! # idprova-middleware
//!
//! Standalone Tower/Axum middleware for DAT bearer token verification.
//!
//! Provides a ready-to-use axum middleware function that:
//! - Extracts `Authorization: Bearer <token>` from requests
//! - Verifies the DAT signature, timing, scope, and constraints
//! - Injects [`VerifiedDat`] into request extensions on success
//! - Returns 401/403 JSON errors on failure
//!
//! ## Usage
//!
//! ```rust,ignore
//! use axum::{Router, routing::get, extract::Extension};
//! use idprova_middleware::{DatVerificationConfig, VerifiedDat, dat_verification_middleware};
//!
//! let config = DatVerificationConfig {
//!     public_key: [0u8; 32], // your Ed25519 public key
//!     required_scope: "mcp:tool:echo".to_string(),
//! };
//!
//! let app = Router::new()
//!     .route("/protected", get(|Extension(dat): Extension<VerifiedDat>| async move {
//!         format!("Hello, {}", dat.subject_did)
//!     }))
//!     .layer(axum::middleware::from_fn_with_state(
//!         config,
//!         dat_verification_middleware,
//!     ));
//! ```

pub mod error;

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use idprova_core::dat::constraints::EvaluationContext;
use idprova_core::dat::Dat;
use std::net::IpAddr;

pub use error::DatMiddlewareError;

/// Information from a successfully verified DAT, injected into request extensions.
#[derive(Debug, Clone)]
pub struct VerifiedDat {
    /// The decoded DAT.
    pub dat: Dat,
    /// Subject DID (the agent).
    pub subject_did: String,
    /// Issuer DID (the delegator).
    pub issuer_did: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// Token JTI.
    pub jti: String,
}

/// Configuration for the DAT verification middleware.
#[derive(Debug, Clone)]
pub struct DatVerificationConfig {
    /// Ed25519 public key bytes for signature verification.
    pub public_key: [u8; 32],
    /// Required scope to check. Empty string = skip scope check.
    pub required_scope: String,
}

/// Build an [`EvaluationContext`] from HTTP request headers.
///
/// Extracts source IP from `X-Forwarded-For`, `X-Real-IP`, or falls back to None.
fn build_eval_context(headers: &HeaderMap) -> EvaluationContext {
    let request_ip: Option<IpAddr> = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            headers
                .get("X-Real-IP")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .and_then(|s| s.parse().ok())
        });

    EvaluationContext {
        request_ip,
        current_timestamp: None,
        ..Default::default()
    }
}

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Result<&str, DatMiddlewareError> {
    let auth = headers
        .get("Authorization")
        .ok_or_else(|| DatMiddlewareError::unauthorized("Authorization header required"))?;

    let auth_str = auth
        .to_str()
        .map_err(|_| DatMiddlewareError::unauthorized("invalid Authorization header encoding"))?;

    let token = auth_str
        .strip_prefix("Bearer ")
        .unwrap_or("")
        .trim();

    if token.is_empty() {
        return Err(DatMiddlewareError::unauthorized(
            "Bearer token required",
        ));
    }

    Ok(token)
}

/// Axum middleware function for DAT verification.
///
/// Verifies the Bearer token against the configured public key and required scope.
/// On success, injects [`VerifiedDat`] into request extensions.
/// On failure, returns 401 (bad/missing token) or 403 (scope mismatch).
pub async fn dat_verification_middleware(
    State(config): State<DatVerificationConfig>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let headers = request.headers();

    // Extract bearer token
    let token = match extract_bearer_token(headers) {
        Ok(t) => t.to_string(),
        Err(e) => return e.into_response(),
    };

    // Build evaluation context from request
    let ctx = build_eval_context(headers);

    // Verify the DAT
    let dat = match idprova_verify::verify_dat(
        &token,
        &config.public_key,
        &config.required_scope,
        &ctx,
    ) {
        Ok(dat) => dat,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!("DAT verification failed: {msg}");

            // Scope failures → 403, everything else → 401
            let error = if msg.contains("scope") {
                DatMiddlewareError::forbidden(msg)
            } else {
                DatMiddlewareError::unauthorized(msg)
            };
            return error.into_response();
        }
    };

    // Build VerifiedDat and inject into extensions
    let verified = VerifiedDat {
        subject_did: dat.claims.sub.clone(),
        issuer_did: dat.claims.iss.clone(),
        scopes: dat.claims.scope.clone(),
        jti: dat.claims.jti.clone(),
        dat,
    };

    request.extensions_mut().insert(verified);

    next.run(request).await
}

/// Convenience function to create a middleware layer for a router.
///
/// Returns the config that can be used with `axum::middleware::from_fn_with_state`.
pub fn make_dat_config(public_key: [u8; 32], required_scope: &str) -> DatVerificationConfig {
    DatVerificationConfig {
        public_key,
        required_scope: required_scope.to_string(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_build_eval_context_with_forwarded_for() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "192.168.1.1, 10.0.0.1".parse().unwrap());
        let ctx = build_eval_context(&headers);
        assert_eq!(
            ctx.request_ip,
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_build_eval_context_with_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "10.0.0.5".parse().unwrap());
        let ctx = build_eval_context(&headers);
        assert_eq!(ctx.request_ip, Some("10.0.0.5".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_build_eval_context_no_ip() {
        let headers = HeaderMap::new();
        let ctx = build_eval_context(&headers);
        assert!(ctx.request_ip.is_none());
    }

    #[test]
    fn test_extract_bearer_missing_header() {
        let headers = HeaderMap::new();
        assert!(extract_bearer_token(&headers).is_err());
    }

    #[test]
    fn test_extract_bearer_empty_token() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer ".parse().unwrap());
        assert!(extract_bearer_token(&headers).is_err());
    }

    #[test]
    fn test_extract_bearer_no_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Basic abc123".parse().unwrap());
        assert!(extract_bearer_token(&headers).is_err());
    }

    #[test]
    fn test_extract_bearer_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", "Bearer my-token-here".parse().unwrap());
        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "my-token-here");
    }

    #[test]
    fn test_error_into_response_unauthorized() {
        let err = DatMiddlewareError::unauthorized("bad token");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_error_into_response_forbidden() {
        let err = DatMiddlewareError::forbidden("scope denied");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
