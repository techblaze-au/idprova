use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, put},
    Router,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;

mod store;

use store::AidStore;

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
