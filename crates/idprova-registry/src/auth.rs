//! Write-endpoint authorisation.
//!
//! Registry write endpoints (`PUT /v1/aid/:id`, `DELETE /v1/aid/:id`,
//! `POST /v1/dat/revoke`) require an admin DAT presented as a bearer
//! token in the `Authorization` header. When `AppState::admin_pubkey`
//! is `None` the registry is running in open (dev) mode and auth is
//! skipped — production deployments MUST set `REGISTRY_ADMIN_PUBKEY`.

use axum::http::StatusCode;
use axum::response::Json;
use serde_json::{json, Value};

use crate::state::AppState;

/// Returns `Ok(())` when the caller presents a valid admin DAT (or when
/// the registry is in open mode); otherwise returns a `(401, {error})`
/// JSON response ready to bubble up.
pub fn require_write_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<Value>)> {
    let pubkey = match state.admin_pubkey {
        Some(k) => k,
        None => return Ok(()),
    };

    let auth = headers.get("Authorization").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Authorization header required for write operations" })),
        )
    })?;

    let auth_str = auth.to_str().unwrap_or("");
    let token = auth_str.strip_prefix("Bearer ").unwrap_or("").trim();
    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Bearer token required" })),
        ));
    }

    let ctx = idprova_core::dat::constraints::EvaluationContext::default();
    idprova_verify::verify_dat(token, &pubkey, "registry:admin:*:write", &ctx).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": format!("invalid admin token: {e}") })),
        )
    })?;

    Ok(())
}
