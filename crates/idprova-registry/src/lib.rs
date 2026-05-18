//! # idprova-registry
//!
//! HTTP registry server for AID resolution and management.
//!
//! Re-exports `build_app()` for integration testing.
//!
//! # Module layout
//!
//! | Module        | Responsibility                                       |
//! |---------------|------------------------------------------------------|
//! | [`store`]     | SQLite-backed AID + revocation persistence           |
//! | [`error`]     | Crate-level error type                               |
//! | [`state`]     | `AppState`, env loaders, shared-state alias          |
//! | [`ratelimit`] | Per-IP sliding-window rate limiter                   |
//! | [`middleware`]| Security headers + rate-limit axum middleware        |
//! | [`auth`]      | Write-endpoint admin-DAT authorisation               |
//! | [`routes`]    | Request handlers, grouped by resource                |
//!
//! The route table is defined in [`build_app`] below — call with an
//! in-memory store from integration tests to exercise the full pipeline.

pub mod auth;
pub mod error;
pub mod middleware;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod store;

use axum::http::Method;
use axum::middleware as axum_middleware;
use axum::routing::{delete, get, post, put};
use axum::Router;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

// ── Public surface (kept stable for downstream consumers) ────────────────────
pub use routes::dats::{DatVerifyRequest, DatVerifyResponse, RevokeRequest};
pub use state::{load_admin_pubkey, AppState, SharedState};

/// Build the registry router for the given state.
///
/// Exposed for integration testing — call with an in-memory store.
///
/// The route table is the *only* place the registry's public HTTP
/// surface is defined; it is asserted unchanged by the snapshot test in
/// `tests/route_snapshot.rs`.
pub fn build_app(state: AppState) -> Router {
    let shared: SharedState = Arc::new(state);

    // CORS: restrict write-method origins when CORS_ALLOWED_ORIGINS is
    // set. GET/HEAD/OPTIONS remain permissive for public reads.
    let cors = match state::load_cors_origins() {
        Some(origins) => CorsLayer::new()
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::OPTIONS,
                Method::POST,
                Method::PUT,
                Method::DELETE,
            ])
            .allow_headers(Any)
            .allow_origin(AllowOrigin::list(origins)),
        None => CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any),
    };

    Router::new()
        .route("/health", get(routes::meta::health))
        .route("/v1/meta", get(routes::meta::meta))
        .route("/v1/aids", get(routes::aids::list_aids))
        .route("/v1/aid/:id", put(routes::aids::register_aid))
        .route("/v1/aid/:id", get(routes::aids::resolve_aid))
        .route("/v1/aid/:id", delete(routes::aids::deactivate_aid))
        .route("/v1/aid/:id/key", get(routes::aids::get_public_key))
        .route("/v1/dat/verify", post(routes::dats::verify_dat))
        .route("/v1/dat/revoke", post(routes::dats::revoke_dat))
        .route("/v1/dat/revoked/:jti", get(routes::dats::check_revocation))
        .layer(axum_middleware::from_fn_with_state(
            shared.clone(),
            middleware::rate_limit_middleware,
        ))
        .layer(axum_middleware::from_fn(middleware::security_headers))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(cors)
        .with_state(shared)
}
