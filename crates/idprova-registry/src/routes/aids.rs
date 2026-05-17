//! Agent Identity Document (AID) CRUD endpoints.
//!
//! * `GET    /v1/aids`            — paginated list of active AIDs.
//! * `PUT    /v1/aid/:id`         — register (or update) an AID. **Auth.**
//! * `GET    /v1/aid/:id`         — resolve a single AID.
//! * `DELETE /v1/aid/:id`         — deactivate an AID. **Auth.**
//! * `GET    /v1/aid/:id/key`     — public-key material for an AID.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::require_write_auth;
use crate::state::SharedState;
use crate::store::AidListEntry;

#[derive(Deserialize)]
pub struct PaginationParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn list_aids(
    State(state): State<SharedState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let limit = params.limit.unwrap_or(100).clamp(1, 1000);
    let offset = params.offset.unwrap_or(0);
    let entries: Vec<AidListEntry> =
        state
            .store
            .list_active_paginated(limit, offset)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("storage error: {e}") })),
                )
            })?;
    Ok(Json(json!({
        "total": entries.len(),
        "limit": limit,
        "offset": offset,
        "aids": entries
    })))
}

pub async fn register_aid(
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

pub async fn resolve_aid(
    State(state): State<SharedState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let did = format!("did:aid:{id}");

    match state.store.get(&did) {
        Ok(Some(doc)) => serde_json::to_value(doc)
            .map(Json)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": format!("serialization error: {e}"), "code": "SERIALIZE_FAILED" })),
                )
            }),
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

pub async fn deactivate_aid(
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

pub async fn get_public_key(
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
