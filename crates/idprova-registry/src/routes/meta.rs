//! Protocol metadata endpoints — `/health` and `/v1/meta`.

use axum::response::Json;
use serde_json::{json, Value};

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": "idprova/0.1"
    }))
}

pub async fn meta() -> Json<Value> {
    Json(json!({
        "protocolVersion": "0.1",
        "registryVersion": env!("CARGO_PKG_VERSION"),
        "didMethod": "did:aid",
        "supportedAlgorithms": ["EdDSA"],
        "supportedHashAlgorithms": ["blake3", "sha-256"]
    }))
}
