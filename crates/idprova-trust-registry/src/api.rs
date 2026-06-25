//! Axum API routes for the Trust Registry service.

use axum::{routing::get, Router};
use std::sync::Arc;

use crate::resolver::{AgentRef, CrossStandardResolver};
use crate::store::TrustStore;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn TrustStore>,
    pub resolver: Arc<CrossStandardResolver>,
}

/// Builds the main application router.
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/trust-list", get(get_trust_list))
        .route("/issuers/:did", get(get_issuer))
        .route("/issuers", get(list_issuers))
        .route("/resolve", axum::routing::post(resolve_agent))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn get_trust_list(
    axum::extract::State(_state): axum::extract::State<AppState>,
) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_IMPLEMENTED, "trust-list not implemented")
}

async fn get_issuer(
    axum::extract::State(_state): axum::extract::State<AppState>,
    axum::extract::Path(_did): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_IMPLEMENTED, "get issuer not implemented")
}

async fn list_issuers(
    axum::extract::State(_state): axum::extract::State<AppState>,
    axum::extract::Query(_params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_IMPLEMENTED, "list issuers not implemented")
}

async fn resolve_agent(
    axum::extract::State(_state): axum::extract::State<AppState>,
    axum::Json(_agent_ref): axum::Json<AgentRef>,
) -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_IMPLEMENTED, "resolve not implemented")
}
