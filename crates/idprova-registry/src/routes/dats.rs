//! Delegation Attestation Token (DAT) verification and revocation.
//!
//! * `POST /v1/dat/verify`        — full DAT verification (signature +
//!   scope + constraints).
//! * `POST /v1/dat/revoke`        — revoke a DAT by `jti`. **Auth.**
//! * `GET  /v1/dat/revoked/:jti`  — check revocation status.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::auth::require_write_auth;
use crate::state::SharedState;
use crate::store::RevocationRecord;

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

pub async fn verify_dat(
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

pub async fn revoke_dat(
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

pub async fn check_revocation(
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
