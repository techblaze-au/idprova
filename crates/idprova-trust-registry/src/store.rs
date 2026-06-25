//! Persistence layer for the Issuer Trust Registry.

use anyhow::Result;
use std::sync::Arc;

use crate::model::{Issuer, IssuerStatus};

/// Abstraction over trust store backends.
pub trait TrustStore: Send + Sync {
    /// Inserts or updates an issuer.
    fn upsert_issuer(&self, issuer: &Issuer) -> Result<()>;
    
    /// Retrieves an issuer by their DID.
    fn get_issuer(&self, did: &str) -> Result<Option<Issuer>>;
    
    /// Lists all issuers, optionally filtered by credential type.
    fn list_issuers(&self, claim_type: Option<&str>) -> Result<Vec<Issuer>>;
    
    /// Checks if an issuer is allowed to attest to a specific claim type.
    /// Returns true only if the issuer exists, is `Active`, and is authorized for the claim.
    fn may_attest(&self, issuer_did: &str, claim_type: &str) -> bool {
        // Default implementation
        match self.get_issuer(issuer_did) {
            Ok(Some(issuer)) => {
                issuer.status == IssuerStatus::Active 
                    && issuer.credential_types.iter().any(|ct| ct == claim_type)
            }
            _ => false,
        }
    }
}

/// SQLite implementation of the `TrustStore`.
pub struct SqliteTrustStore {
    pool: Arc<r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>>,
}

impl SqliteTrustStore {
    /// Creates a new `SqliteTrustStore` from a database path.
    pub fn new(db_path: &str) -> Result<Self> {
        todo!("Implement SQLite pool initialization and schema creation")
    }
}

impl TrustStore for SqliteTrustStore {
    fn upsert_issuer(&self, issuer: &Issuer) -> Result<()> {
        todo!("Implement SQLite upsert for Issuer")
    }

    fn get_issuer(&self, did: &str) -> Result<Option<Issuer>> {
        todo!("Implement SQLite get for Issuer")
    }

    fn list_issuers(&self, claim_type: Option<&str>) -> Result<Vec<Issuer>> {
        todo!("Implement SQLite list for Issuers with optional claim_type filter")
    }
}
