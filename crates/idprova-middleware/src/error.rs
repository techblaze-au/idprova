use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;

/// Errors from DAT middleware verification.
#[derive(Debug)]
pub enum DatMiddlewareError {
    /// 401 — missing, empty, or invalid token.
    Unauthorized(String),
    /// 403 — valid token but insufficient scope.
    Forbidden(String),
}

impl DatMiddlewareError {
    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden(msg.into())
    }
}

impl IntoResponse for DatMiddlewareError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": msg, "code": "unauthorized" })),
            )
                .into_response(),
            Self::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": msg, "code": "forbidden" })),
            )
                .into_response(),
        }
    }
}
