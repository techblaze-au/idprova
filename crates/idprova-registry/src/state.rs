//! Shared application state and registry-level configuration loaders.
//!
//! `AppState` owns the `AidStore` connection pool, the optional admin
//! verification key, and the per-IP rate limiter. It is cheap to clone
//! (everything inside is `Arc`-shared) so axum's `with_state` can hand
//! a copy to each request handler.

use axum::http::HeaderValue;
use std::sync::{Arc, Mutex};

use crate::ratelimit::RateLimiter;
use crate::store::AidStore;

/// Load the registry admin public key from the `REGISTRY_ADMIN_PUBKEY`
/// environment variable. Returns `None` when the variable is unset or
/// malformed — in that case the registry runs in *open* (dev) mode and
/// write endpoints are unauthenticated.
pub fn load_admin_pubkey() -> Option<[u8; 32]> {
    let hex_str = std::env::var("REGISTRY_ADMIN_PUBKEY").ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    bytes.try_into().ok()
}

/// Load CORS allowed origins from the `CORS_ALLOWED_ORIGINS` env var.
///
/// Format: comma-separated list of origins
/// (e.g. `"https://idprova.dev,https://app.idprova.dev"`). If unset or
/// empty, all origins are allowed (development mode).
pub fn load_cors_origins() -> Option<Vec<HeaderValue>> {
    let raw = std::env::var("CORS_ALLOWED_ORIGINS").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let origins: Vec<HeaderValue> = trimmed
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                HeaderValue::from_str(s).ok()
            }
        })
        .collect();
    if origins.is_empty() {
        None
    } else {
        Some(origins)
    }
}

/// Shared application state.
///
/// `AidStore` uses an r2d2 connection pool internally, so no Mutex is
/// needed for it.
#[derive(Clone)]
pub struct AppState {
    pub store: AidStore,
    /// Ed25519 public key for admin DAT verification. `None` = open
    /// (dev) mode — write endpoints skip auth.
    pub admin_pubkey: Option<[u8; 32]>,
    /// Per-IP rate limiter.
    pub(crate) rate_limiter: Arc<Mutex<RateLimiter>>,
}

impl AppState {
    pub fn new(store: AidStore, admin_pubkey: Option<[u8; 32]>) -> Self {
        Self {
            store,
            admin_pubkey,
            rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
        }
    }
}

/// `Arc<AppState>` alias used throughout the request-handler chain.
pub type SharedState = Arc<AppState>;
