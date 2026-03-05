use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

mod store;

use store::{AidStore, RevocationRecord};

/// Shared application state — uses std::sync::Mutex because rusqlite::Connection is !Sync.
type SharedState = Arc<Mutex<AidStore>>;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    tracing::info!("Starting IDProva Registry v{}", env!("CARGO_PKG_VERSION"));

    // Initialize the store
    let store = AidStore::new("idprova_registry.db")?;
    let state: SharedState = Arc::new(Mutex::new(store));

    // Build the router
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/meta", get(meta))
        .route("/v1/aid/:id", put(register_aid))
        .route("/v1/aid/:id", get(resolve_aid))
        .route("/v1/aid/:id", delete(deactivate_aid))
        .route("/v1/aid/:id/key", get(get_public_key))
        .route("/v1/dat/verify", post(verify_dat))
        .route("/v1/dat/revoke", post(revoke_dat))
        .route("/v1/dat/revoked/:jti", get(check_revocation))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
        "didMethod": "did:idprova",
        "supportedAlgorithms": ["EdDSA"],
        "supportedHashAlgorithms": ["blake3", "sha-256"]
    }))
}

async fn register_aid(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let did = format!("did:idprova:{id}");

    // Validate the AID document
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

    let store = state.lock().unwrap();
    let is_new = store.put(&did, &doc).map_err(|e| {
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
    let did = format!("did:idprova:{id}");
    let store = state.lock().unwrap();

    match store.get(&did) {
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
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = format!("did:idprova:{id}");
    let store = state.lock().unwrap();

    match store.delete(&did) {
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
    let did = format!("did:idprova:{id}");
    let store = state.lock().unwrap();

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
        let store = state.lock().unwrap();
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
        let store = state.lock().unwrap();
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
    Json(req): Json<RevokeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if req.jti.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "jti must not be empty" })),
        ));
    }

    let store = state.lock().unwrap();
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
    let store = state.lock().unwrap();

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
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("store error: {e}") })),
        )),
    }
}
