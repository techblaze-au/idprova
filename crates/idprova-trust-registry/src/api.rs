//! Axum API routes for the Trust Registry service.
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::Path, extract::Query, extract::State, routing::get, Json, Router};
use std::collections::HashMap;
use std::sync::Arc;

use crate::authority::TrustAuthority;
use crate::resolver::{AgentRef, CrossStandardResolver};
use crate::store::TrustStore;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn TrustStore>,
    pub resolver: Arc<CrossStandardResolver>,
    pub authority: Arc<TrustAuthority>,
}

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

async fn get_trust_list(State(state): State<AppState>) -> impl IntoResponse {
    match state.authority.publish(&*state.store) {
        Ok(signed) => Json(signed).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_issuer(State(state): State<AppState>, Path(did): Path<String>) -> impl IntoResponse {
    match state.store.get_issuer(&did) {
        Ok(Some(i)) => Json(i).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn list_issuers(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let claim = params.get("claim_type").map(String::as_str);
    match state.store.list_issuers(claim) {
        Ok(v) => Json(v).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn resolve_agent(
    State(state): State<AppState>,
    Json(agent_ref): Json<AgentRef>,
) -> impl IntoResponse {
    match state.resolver.resolve(&agent_ref) {
        Some(r) => Json(r).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
