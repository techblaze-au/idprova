use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use ulid::Ulid;

/// Structured JSON error response body.
///
/// All error responses from the registry use this shape:
/// ```json
/// {"error":"human readable message","code":"ERROR_CODE","request_id":"01JXXX..."}
/// ```
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: &'static str,
    pub request_id: String,
}

impl ApiError {
    /// Create an ApiError with a freshly generated ULID request_id.
    pub fn new(code: &'static str, error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code,
            request_id: Ulid::new().to_string(),
        }
    }

    pub fn bad_request(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::BAD_REQUEST, Json(Self::new("BAD_REQUEST", error)))
    }

    pub fn not_found(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::NOT_FOUND, Json(Self::new("NOT_FOUND", error)))
    }

    pub fn unauthorized(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (StatusCode::UNAUTHORIZED, Json(Self::new("UNAUTHORIZED", error)))
    }

    pub fn internal(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Self::new("INTERNAL_ERROR", error)),
        )
    }

    #[allow(dead_code)]
    pub fn too_many_requests(error: impl Into<String>) -> (StatusCode, Json<ApiError>) {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(Self::new("RATE_LIMITED", error)),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code {
            "BAD_REQUEST" => StatusCode::BAD_REQUEST,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}
