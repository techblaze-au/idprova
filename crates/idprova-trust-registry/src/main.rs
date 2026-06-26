//! Binary entry point for the IDProva Trust Registry service.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use idprova_trust_registry::api::{build_router, AppState};
use idprova_trust_registry::authority::TrustAuthority;
use idprova_trust_registry::resolver::{CrossStandardResolver, DidAidBackend};
use idprova_trust_registry::store::{SqliteTrustStore, TrustStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // TODO: load config / persistent signing key from a secret store.
    let db_path = "trust_registry.db";
    let store: Arc<dyn TrustStore> = Arc::new(SqliteTrustStore::new(db_path)?);

    // Single-authority open node: this node signs its own trust list. A persistent operator
    // would load the signing key from a secret manager; here we generate an ephemeral key.
    let signing_key = SigningKey::generate(&mut OsRng);
    let authority = Arc::new(TrustAuthority::new(signing_key));

    let resolver = Arc::new(CrossStandardResolver {
        backends: vec![Box::new(DidAidBackend {
            store: Arc::clone(&store),
        })],
    });

    let state = AppState {
        store,
        resolver,
        authority,
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    tracing::info!("Trust Registry listening on 0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
