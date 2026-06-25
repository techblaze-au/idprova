//! Binary entry point for the IDProva Trust Registry service.

use std::sync::Arc;

use idprova_trust_registry::api::{build_router, AppState};
use idprova_trust_registry::resolver::CrossStandardResolver;
use idprova_trust_registry::store::SqliteTrustStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // TODO: Load config
    let db_path = "trust_registry.db";
    let store = Arc::new(SqliteTrustStore::new(db_path)?);
    let resolver = Arc::new(CrossStandardResolver { backends: vec![] });

    let state = AppState { store, resolver };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Trust Registry listening on 0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
