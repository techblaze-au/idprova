use anyhow::Result;
use tracing_subscriber::EnvFilter;

use idprova_registry::{build_app, load_admin_pubkey, store::AidStore, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    tracing::info!("Starting IDProva Registry v{}", env!("CARGO_PKG_VERSION"));

    // Initialize the store and app state
    let db_path = std::env::var("IDPROVA_DB_PATH")
        .unwrap_or_else(|_| "idprova_registry.db".to_string());
    let store = AidStore::new(&db_path)?;
    let admin_pubkey = load_admin_pubkey();
    if admin_pubkey.is_none() {
        tracing::warn!(
            "REGISTRY_ADMIN_PUBKEY not set — write endpoints are OPEN (development mode only)"
        );
    }
    let state = AppState::new(store, admin_pubkey);
    let app = build_app(state);

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
