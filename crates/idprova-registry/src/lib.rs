//! # idprova-registry
//!
//! HTTP registry server for AID resolution and management.
//!
//! Re-exports `build_app()` for integration testing.

pub mod store;

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use store::{AidListEntry, AidStore, RevocationRecord};

// ── Registry admin public key ─────────────────────────────────────────────────

/// Load the registry admin public key from the `REGISTRY_ADMIN_PUBKEY` environment variable.
pub fn load_admin_pubkey() -> Option<[u8; 32]> {
    let hex_str = std::env::var("REGISTRY_ADMIN_PUBKEY").ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    bytes.try_into().ok()
}

// ── Per-IP rate limiter ───────────────────────────────────────────────────────

/// Maximum number of unique IPs tracked by the rate limiter.
/// When exceeded, the oldest entries are evicted (LRU).
const RATE_LIMITER_MAX_ENTRIES: usize = 10_000;

#[derive(Default)]
struct RateLimiter {
    /// Per-IP request timestamps within the current window.
    windows: HashMap<String, Vec<Instant>>,
    /// Insertion-order queue for LRU eviction.
    order: VecDeque<String>,
}

impl RateLimiter {
    fn check_and_record(&mut self, ip: &str, limit: usize) -> bool {
        let now = Instant::now();

        // LRU eviction: if at capacity and this is a new IP, evict oldest entries
        if !self.windows.contains_key(ip) && self.windows.len() >= RATE_LIMITER_MAX_ENTRIES {
            // Evict 10% of oldest entries to amortize cleanup
            let evict_count = RATE_LIMITER_MAX_ENTRIES / 10;
            for _ in 0..evict_count {
                if let Some(old_ip) = self.order.pop_front() {
                    self.windows.remove(&old_ip);
                }
            }
        }

        let is_new = !self.windows.contains_key(ip);
        let window = self.windows.entry(ip.to_string()).or_default();
        window.retain(|t| now.duration_since(*t).as_secs() < 60);
        if window.len() >= limit {
            return false;
        }
        window.push(now);

        // Track insertion order for LRU
        if is_new {
            self.order.push_back(ip.to_string());
        }
        true
    }
}

/// Shared application state.
///
/// `AidStore` uses an r2d2 connection pool internally, so no Mutex is needed for it.
#[derive(Clone)]
pub struct AppState {
    pub store: AidStore,
    /// Ed25519 public key for admin DAT verification. None = open (dev mode).
    pub admin_pubkey: Option<[u8; 32]>,
    /// Per-IP rate limiter.
    rate_limiter: Arc<Mutex<RateLimiter>>,
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

type SharedState = Arc<AppState>;

/// Load CORS allowed origins from the `CORS_ALLOWED_ORIGINS` env var.
///
/// Format: comma-separated list of origins (e.g. "https://idprova.dev,https://app.idprova.dev").
/// If unset or empty, all origins are allowed (development mode).
fn load_cors_origins() -> Option<Vec<HeaderValue>> {
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

/// Build the registry router for the given state.
///
/// Exposed for integration testing — call with an in-memory store.
pub fn build_app(state: AppState) -> Router {
    let shared: SharedState = Arc::new(state);

    // CORS: restrict write-method origins when CORS_ALLOWED_ORIGINS is set.
    // GET/HEAD/OPTIONS remain permissive for public reads.
    let cors = match load_cors_origins() {
        Some(origins) => CorsLayer::new()
            .allow_methods([Method::GET, Method::HEAD, Method::OPTIONS,
                           Method::POST, Method::PUT, Method::DELETE])
            .allow_headers(Any)
            .allow_origin(AllowOrigin::list(origins)),
        None => CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any),
    };

    Router::new()
        .route("/health", get(health))
        .route("/v1/meta", get(meta))
        .route("/v1/aids", get(list_aids))
        .route("/v1/aid/:id", put(register_aid))
        .route("/v1/aid/:id", get(resolve_aid))
        .route("/v1/aid/:id", delete(deactivate_aid))
        .route("/v1/aid/:id/key", get(get_public_key))
        .route("/v1/dat/verify", post(verify_dat))
        .route("/v1/dat/revoke", post(revoke_dat))
        .route("/v1/dat/revoked/:jti", get(check_revocation))
        .layer(middleware::from_fn_with_state(
            shared.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn(security_headers))
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(cors)
        .with_state(shared)
}

/// Axum middleware that appends security headers to every response.
async fn security_headers(request: Request<Body>, next: Next) -> Response {
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

// ── Write authorization helper ────────────────────────────────────────────────

fn require_write_auth(
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

// ── Rate limiting middleware ───────────────────────────────────────────────────

async fn rate_limit_middleware(
    State(state): State<SharedState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Determine client IP: prefer proxy headers, fall back to peer socket address.
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
        let mut limiter = state
            .rate_limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "idprova/0.1"
    }))
}

async fn meta() -> Json<Value> {
    Json(json!({
        "protocolVersion": "0.1",
        "registryVersion": env!("CARGO_PKG_VERSION"),
        "didMethod": "did:aid",
        "supportedAlgorithms": ["EdDSA"],
        "supportedHashAlgorithms": ["blake3", "sha-256"]
    }))
}

async fn list_aids(
    State(state): State<SharedState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let entries: Vec<AidListEntry> = state.store.list_active().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("storage error: {e}") })),
        )
    })?;
    Ok(Json(json!({
        "total": entries.len(),
        "aids": entries
    })))
}

async fn register_aid(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_write_auth(&state, &headers)?;

    let did = format!("did:aid:{id}");

    let doc: idprova_core::aid::AidDocument = serde_json::from_value(body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid AID document: {e}") })),
        )
    })?;

    if let Err(e) = doc.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("AID validation failed: {e}") })),
        ));
    }

    let is_new = state.store.put(&did, &doc).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("storage error: {e}") })),
        )
    })?;

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((
        status,
        Json(json!({
            "id": did,
            "status": if is_new { "created" } else { "updated" }
        })),
    ))
}

async fn resolve_aid(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = format!("did:aid:{id}");

    match state.store.get(&did) {
        Ok(Some(doc)) => Ok(Json(serde_json::to_value(doc).unwrap())),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("AID not found: {did}") })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("storage error: {e}") })),
        )),
    }
}

async fn deactivate_aid(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_write_auth(&state, &headers)?;
    let did = format!("did:aid:{id}");

    match state.store.delete(&did) {
        Ok(true) => Ok(Json(json!({ "id": did, "status": "deactivated" }))),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("AID not found: {did}") })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("storage error: {e}") })),
        )),
    }
}

async fn get_public_key(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = format!("did:aid:{id}");

    match state.store.get(&did) {
        Ok(Some(doc)) => {
            let keys: Vec<Value> = doc
                .verification_method
                .iter()
                .map(|vm| {
                    json!({
                        "id": vm.id,
                        "type": vm.key_type,
                        "publicKeyMultibase": vm.public_key_multibase
                    })
                })
                .collect();
            Ok(Json(json!({ "id": did, "keys": keys })))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("AID not found: {did}") })),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("storage error: {e}") })),
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// POST /v1/dat/verify
// ────────────────────────────────────────────────────────────────────────────

/// Request body for DAT verification.
#[derive(Debug, Deserialize, Serialize)]
pub struct DatVerifyRequest {
    pub token: String,
    #[serde(default)]
    pub scope: String,
    pub request_ip: Option<String>,
    pub trust_level: Option<u8>,
    #[serde(default)]
    pub delegation_depth: u32,
    #[serde(default)]
    pub actions_in_window: u64,
    pub country_code: Option<String>,
    pub agent_config_hash: Option<String>,
}

/// Response from DAT verification.
#[derive(Debug, Serialize)]
pub struct DatVerifyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

async fn verify_dat(
    State(state): State<SharedState>,
    Json(req): Json<DatVerifyRequest>,
) -> Result<Json<DatVerifyResponse>, (StatusCode, Json<DatVerifyResponse>)> {
    use idprova_core::crypto::KeyPair;
    use idprova_core::dat::constraints::EvaluationContext;
    use idprova_core::dat::Dat;

    let err_resp = |msg: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(DatVerifyResponse {
                valid: false,
                issuer: None,
                subject: None,
                scopes: None,
                jti: None,
                error: Some(msg),
            }),
        )
    };

    // 1. Decode token (no sig check yet)
    let dat =
        Dat::from_compact(&req.token).map_err(|e| err_resp(format!("malformed token: {e}")))?;

    let issuer_did = dat.claims.iss.clone();
    let subject = dat.claims.sub.clone();
    let scopes = dat.claims.scope.clone();
    let jti = dat.claims.jti.clone();

    // 1b. Revocation check — fail fast before any crypto work
    match state.store.get_revocation(&jti) {
        Ok(Some(rev)) => {
            tracing::info!("Rejected revoked DAT jti={jti} reason={}", rev.reason);
            return Ok(Json(DatVerifyResponse {
                valid: false,
                issuer: Some(issuer_did),
                subject: Some(subject),
                scopes: Some(scopes),
                jti: Some(jti),
                error: Some(format!(
                    "DAT revoked at {} by {}: {}",
                    rev.revoked_at, rev.revoked_by, rev.reason
                )),
            }));
        }
        Ok(None) => {} // not revoked, continue
        Err(e) => return Err(err_resp(format!("revocation check error: {e}"))),
    }

    // 2. Extract DID from kid: "{did}#key-ed25519"
    let kid = &dat.header.kid;
    let issuer_from_kid = kid
        .split('#')
        .next()
        .ok_or_else(|| err_resp(format!("kid has unexpected format: {kid}")))?
        .to_string();

    // 3. Resolve AID from registry store
    let doc = state
        .store
        .get(&issuer_from_kid)
        .map_err(|e| err_resp(format!("store error: {e}")))?
        .ok_or_else(|| err_resp(format!("issuer AID not found: {issuer_from_kid}")))?;

    // 4. Find the verification key matching the kid
    let kid_fragment = kid.split('#').nth(1).unwrap_or("");
    let vm = doc
        .verification_method
        .iter()
        .find(|vm| {
            vm.id == *kid
                || vm.id == format!("{issuer_from_kid}#key-ed25519")
                || vm.id == format!("#{kid_fragment}")
        })
        .ok_or_else(|| err_resp(format!("key '{kid}' not found in issuer AID")))?;

    let pub_key_bytes = KeyPair::decode_multibase_pubkey(&vm.public_key_multibase)
        .map_err(|e| err_resp(format!("key decode error: {e}")))?;

    // 5. Build evaluation context from request fields
    let request_ip: Option<IpAddr> = req.request_ip.as_deref().and_then(|s| s.parse().ok());

    let ctx = EvaluationContext {
        actions_in_window: req.actions_in_window,
        request_ip,
        agent_trust_level: req.trust_level,
        delegation_depth: req.delegation_depth,
        country_code: req.country_code,
        current_timestamp: None,
        agent_config_hash: req.agent_config_hash,
    };

    // 6. Full verification pipeline
    match dat.verify(&pub_key_bytes, &req.scope, &ctx) {
        Ok(()) => Ok(Json(DatVerifyResponse {
            valid: true,
            issuer: Some(issuer_did),
            subject: Some(subject),
            scopes: Some(scopes),
            jti: Some(jti),
            error: None,
        })),
        Err(e) => {
            tracing::warn!("DAT verification failed for jti={jti}: {e}");
            Ok(Json(DatVerifyResponse {
                valid: false,
                issuer: Some(issuer_did),
                subject: Some(subject),
                scopes: Some(scopes),
                jti: Some(jti),
                error: Some(e.to_string()),
            }))
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// POST /v1/dat/revoke
// ────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub jti: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub revoked_by: String,
}

async fn revoke_dat(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_write_auth(&state, &headers)?;

    if req.jti.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "jti must not be empty" })),
        ));
    }
    if req.jti.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "jti exceeds maximum length of 128 characters" })),
        ));
    }
    if req.reason.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "reason exceeds maximum length of 512 characters" })),
        ));
    }
    if req.revoked_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "revoked_by exceeds maximum length of 256 characters" })),
        ));
    }

    match state.store.revoke(&req.jti, &req.reason, &req.revoked_by) {
        Ok(true) => {
            tracing::info!("Revoked DAT jti={} by={}", req.jti, req.revoked_by);
            Ok(Json(json!({
                "jti": req.jti,
                "status": "revoked",
                "reason": req.reason,
                "revoked_by": req.revoked_by
            })))
        }
        Ok(false) => Ok(Json(json!({
            "jti": req.jti,
            "status": "already_revoked"
        }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("store error: {e}") })),
        )),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// GET /v1/dat/revoked/:jti
// ────────────────────────────────────────────────────────────────────────────

async fn check_revocation(
    State(state): State<SharedState>,
    Path(jti): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match state.store.get_revocation(&jti) {
        Ok(Some(RevocationRecord {
            jti,
            reason,
            revoked_by,
            revoked_at,
        })) => Ok(Json(json!({
            "revoked": true,
            "jti": jti,
            "reason": reason,
            "revoked_by": revoked_by,
            "revoked_at": revoked_at
        }))),
        Ok(None) => Ok(Json(json!({ "revoked": false, "jti": jti }))),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("store error: {e}") })),
        )),
    }
}
