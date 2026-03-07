use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::EnvFilter;

mod error;
mod store;

use error::ApiError;
use store::{AidStore, RevocationRecord};

// ── Registry admin public key ─────────────────────────────────────────────────

/// Load the registry admin public key from the `REGISTRY_ADMIN_PUBKEY` environment variable.
///
/// The value must be a 64-character lowercase hex string (32 bytes Ed25519 public key).
/// If unset, write endpoints are **open** (development mode — warn loudly).
fn load_admin_pubkey() -> Option<[u8; 32]> {
    let hex_str = std::env::var("REGISTRY_ADMIN_PUBKEY").ok()?;
    let bytes = hex::decode(hex_str.trim()).ok()?;
    bytes.try_into().ok()
}

// ── Per-IP rate limiter ───────────────────────────────────────────────────────

/// Simple sliding-window rate limiter (per client IP, per minute).
#[derive(Default)]
struct RateLimiter {
    /// Map of IP → list of request timestamps in the last 60 seconds.
    windows: HashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    /// Returns `true` if the request should be allowed, `false` if rate-limited.
    ///
    /// Allows up to `limit` requests per 60-second sliding window per IP.
    fn check_and_record(&mut self, ip: &str, limit: usize) -> bool {
        let now = Instant::now();
        let window = self.windows.entry(ip.to_string()).or_default();
        // Prune entries older than 60 seconds
        window.retain(|t| now.duration_since(*t).as_secs() < 60);
        if window.len() >= limit {
            return false;
        }
        window.push(now);
        true
    }
}

/// Shared application state — uses std::sync::Mutex because rusqlite::Connection is !Sync.
#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<AidStore>>,
    /// Ed25519 public key for admin DAT verification. None = open (dev mode).
    admin_pubkey: Option<[u8; 32]>,
    /// Per-IP rate limiter.
    rate_limiter: Arc<Mutex<RateLimiter>>,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    tracing::info!("Starting IDProva Registry v{}", env!("CARGO_PKG_VERSION"));

    // Initialize the store and app state
    let store = AidStore::new("idprova_registry.db")?;
    let admin_pubkey = load_admin_pubkey();
    if admin_pubkey.is_none() {
        tracing::warn!(
            "REGISTRY_ADMIN_PUBKEY not set — write endpoints are OPEN (development mode only)"
        );
    }
    let state: SharedState = Arc::new(AppState {
        store: Arc::new(Mutex::new(store)),
        admin_pubkey,
        rate_limiter: Arc::new(Mutex::new(RateLimiter::default())),
    });

    // CORS — allow all origins/methods/headers (registry is a public read API)
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    // Build the router
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/meta", get(meta))
        .route("/v1/aid/:id", put(register_aid))
        .route("/v1/aid/:id", get(resolve_aid))
        .route("/v1/aid/:id", delete(deactivate_aid))
        .route("/v1/aid/:id/key", get(get_public_key))
        .route("/v1/dat/verify", post(verify_dat))
        .route("/v1/dat/revoke", post(revoke_dat))
        .route("/v1/dat/revoked/:jti", get(check_revocation))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_middleware))
        .layer(middleware::from_fn(security_headers))
        // 1 MB body limit on all requests
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("REGISTRY_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    let addr = format!("0.0.0.0:{port}");
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    response
}

// ── Write authorization helper ────────────────────────────────────────────────

/// Verify that the request carries a valid admin DAT Bearer token.
///
/// If `state.admin_pubkey` is `None` (dev mode), all writes are permitted.
/// Otherwise the `Authorization: Bearer <compact-jws>` header is required and
/// the token must be verifiable against the configured admin public key.
fn require_write_auth(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let pubkey = match state.admin_pubkey {
        Some(k) => k,
        None => return Ok(()), // dev mode — open writes
    };

    let auth = headers
        .get("Authorization")
        .ok_or_else(|| ApiError::unauthorized("Authorization header required for write operations"))?;

    let auth_str = auth.to_str().unwrap_or("");
    let token = auth_str.strip_prefix("Bearer ").unwrap_or("").trim();
    if token.is_empty() {
        return Err(ApiError::unauthorized("Bearer token required"));
    }

    let ctx = idprova_core::dat::constraints::EvaluationContext::default();
    idprova_verify::verify_dat(token, &pubkey, "", &ctx)
        .map_err(|e| ApiError::unauthorized(format!("invalid admin token: {e}")))?;

    Ok(())
}

// ── Rate limiting middleware ───────────────────────────────────────────────────

/// Per-IP rate limiting: 120 requests per 60-second window.
async fn rate_limit_middleware(
    State(state): State<SharedState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Extract client IP from X-Forwarded-For or X-Real-IP, fallback to "unknown"
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
        .unwrap_or_else(|| "unknown".to_string());

    let allowed = {
        let mut limiter = state.rate_limiter.lock().unwrap();
        limiter.check_and_record(&ip, 120)
    };

    if allowed {
        next.run(req).await
    } else {
        let err = ApiError::new(
            "RATE_LIMITED",
            "rate limit exceeded — max 120 requests per 60 seconds per IP",
        );
        let body = serde_json::to_string(&err).unwrap_or_default();
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

/// GET /ready — returns 200 if the SQLite store is reachable, 503 otherwise.
async fn ready(State(state): State<SharedState>) -> Response {
    let ok = state.store.lock().unwrap().ping().is_ok();
    if ok {
        (
            StatusCode::OK,
            Json(json!({ "status": "ready", "db": "ok" })),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "db": "error" })),
        )
            .into_response()
    }
}

async fn meta() -> Json<Value> {
    Json(json!({
        "protocolVersion": "0.1",
        "registryVersion": env!("CARGO_PKG_VERSION"),
        "didMethod": "did:idprova",
        "supportedAlgorithms": ["EdDSA"],
        "supportedHashAlgorithms": ["blake3", "sha-256"]
    }))
}

async fn register_aid(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiError>)> {
    // Require valid DAT for write operations
    require_write_auth(&state, &headers)?;

    let did = format!("did:idprova:{id}");

    // Validate the AID document
    let doc: idprova_core::aid::AidDocument = serde_json::from_value(body)
        .map_err(|e| ApiError::bad_request(format!("invalid AID document: {e}")))?;

    if let Err(e) = doc.validate() {
        return Err(ApiError::bad_request(format!("AID validation failed: {e}")));
    }

    let store = state.store.lock().unwrap();
    let is_new = store
        .put(&did, &doc)
        .map_err(|e| ApiError::internal(format!("storage error: {e}")))?;

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
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let did = format!("did:idprova:{id}");
    let store = state.store.lock().unwrap();

    match store.get(&did) {
        Ok(Some(doc)) => Ok(Json(serde_json::to_value(doc).unwrap())),
        Ok(None) => Err(ApiError::not_found(format!("AID not found: {did}"))),
        Err(e) => Err(ApiError::internal(format!("storage error: {e}"))),
    }
}

async fn deactivate_aid(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    require_write_auth(&state, &headers)?;
    let did = format!("did:idprova:{id}");
    let store = state.store.lock().unwrap();

    match store.delete(&did) {
        Ok(true) => Ok(Json(json!({ "id": did, "status": "deactivated" }))),
        Ok(false) => Err(ApiError::not_found(format!("AID not found: {did}"))),
        Err(e) => Err(ApiError::internal(format!("storage error: {e}"))),
    }
}

async fn get_public_key(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let did = format!("did:idprova:{id}");
    let store = state.store.lock().unwrap();

    match store.get(&did) {
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
        Ok(None) => Err(ApiError::not_found(format!("AID not found: {did}"))),
        Err(e) => Err(ApiError::internal(format!("storage error: {e}"))),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// POST /v1/dat/verify
// ────────────────────────────────────────────────────────────────────────────

/// Request body for DAT verification.
#[derive(Debug, Deserialize, Serialize)]
pub struct DatVerifyRequest {
    /// Compact JWS token (header.payload.signature).
    pub token: String,

    /// Required scope to check (e.g. "mcp:tool:read"). Empty string = skip scope check.
    #[serde(default)]
    pub scope: String,

    /// Request IP address (used for ip_allowlist / ip_denylist constraints).
    pub request_ip: Option<String>,

    /// Agent trust level (0–100, used for min_trust_level constraint).
    pub trust_level: Option<u8>,

    /// Delegation depth in the current chain (used for max_delegation_depth).
    #[serde(default)]
    pub delegation_depth: u32,

    /// Number of actions already taken in the current rate-limit window.
    #[serde(default)]
    pub actions_in_window: u64,

    /// ISO 3166-1 alpha-2 country code of the request origin.
    pub country_code: Option<String>,

    /// SHA-256 hex hash of the agent's current configuration.
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

/// Verify a DAT token against the issuer's registered public key.
///
/// Flow:
/// 1. Decode compact JWS
/// 2. Extract issuer DID from `kid` claim (`{did}#key-ed25519`)
/// 3. Look up the issuer's AID document in the registry store
/// 4. Decode the `publicKeyMultibase` Ed25519 public key
/// 5. Build `EvaluationContext` from request body
/// 6. Call `Dat::verify()` — full pipeline
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
    let dat = Dat::from_compact(&req.token)
        .map_err(|e| err_resp(format!("malformed token: {e}")))?;

    let issuer_did = dat.claims.iss.clone();
    let subject = dat.claims.sub.clone();
    let scopes = dat.claims.scope.clone();
    let jti = dat.claims.jti.clone();

    // 1b. Revocation check — fail fast before any crypto work
    {
        let store = state.store.lock().unwrap();
        match store.get_revocation(&jti) {
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
    }

    // 2. Extract DID from kid: "{did}#key-ed25519"
    let kid = &dat.header.kid;
    let issuer_from_kid = kid
        .split('#')
        .next()
        .ok_or_else(|| err_resp(format!("kid has unexpected format: {kid}")))?
        .to_string();

    // 3. Resolve AID from registry store
    let doc = {
        let store = state.store.lock().unwrap();
        store
            .get(&issuer_from_kid)
            .map_err(|e| err_resp(format!("store error: {e}")))?
            .ok_or_else(|| err_resp(format!("issuer AID not found: {issuer_from_kid}")))?
    };

    // 4. Find the verification key matching the kid
    let vm = doc
        .verification_method
        .iter()
        .find(|vm| vm.id == *kid || vm.id == format!("{issuer_from_kid}#key-ed25519"))
        .ok_or_else(|| err_resp(format!("key '{kid}' not found in issuer AID")))?;

    let pub_key_bytes = KeyPair::decode_multibase_pubkey(&vm.public_key_multibase)
        .map_err(|e| err_resp(format!("key decode error: {e}")))?;

    // 5. Build evaluation context from request fields
    let request_ip: Option<IpAddr> = req
        .request_ip
        .as_deref()
        .and_then(|s| s.parse().ok());

    let ctx = EvaluationContext {
        actions_in_window: req.actions_in_window,
        request_ip,
        agent_trust_level: req.trust_level,
        delegation_depth: req.delegation_depth,
        country_code: req.country_code,
        current_timestamp: None, // use Utc::now() inside evaluators
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
    /// Token JTI to revoke.
    pub jti: String,
    /// Human-readable revocation reason.
    #[serde(default)]
    pub reason: String,
    /// DID or identifier of the party performing the revocation.
    #[serde(default)]
    pub revoked_by: String,
}

async fn revoke_dat(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    require_write_auth(&state, &headers)?;

    if req.jti.is_empty() {
        return Err(ApiError::bad_request("jti must not be empty"));
    }
    if req.jti.len() > 128 {
        return Err(ApiError::bad_request("jti exceeds maximum length of 128 characters"));
    }
    if req.reason.len() > 512 {
        return Err(ApiError::bad_request("reason exceeds maximum length of 512 characters"));
    }
    if req.revoked_by.len() > 256 {
        return Err(ApiError::bad_request(
            "revoked_by exceeds maximum length of 256 characters",
        ));
    }

    let store = state.store.lock().unwrap();
    match store.revoke(&req.jti, &req.reason, &req.revoked_by) {
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
        Err(e) => Err(ApiError::internal(format!("store error: {e}"))),
    }
}

// ────────────────────────────────────────────────────────────────────────────
// GET /v1/dat/revoked/:jti
// ────────────────────────────────────────────────────────────────────────────

async fn check_revocation(
    State(state): State<SharedState>,
    Path(jti): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiError>)> {
    let store = state.store.lock().unwrap();

    match store.get_revocation(&jti) {
        Ok(Some(RevocationRecord { jti, reason, revoked_by, revoked_at })) => {
            Ok(Json(json!({
                "revoked": true,
                "jti": jti,
                "reason": reason,
                "revoked_by": revoked_by,
                "revoked_at": revoked_at
            })))
        }
        Ok(None) => Ok(Json(json!({ "revoked": false, "jti": jti }))),
        Err(e) => Err(ApiError::internal(format!("store error: {e}"))),
    }
}
