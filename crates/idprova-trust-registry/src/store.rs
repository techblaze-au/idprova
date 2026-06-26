//! Persistence layer for the Issuer Trust Registry.
use anyhow::Result;
use std::sync::Arc;

use crate::model::{Issuer, IssuerStatus};
use chrono::Utc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;

pub trait TrustStore: Send + Sync {
    fn upsert_issuer(&self, issuer: &Issuer) -> Result<()>;
    fn get_issuer(&self, did: &str) -> Result<Option<Issuer>>;
    fn list_issuers(&self, claim_type: Option<&str>) -> Result<Vec<Issuer>>;
    /// Default impl: true iff issuer exists, Active, and authorized for claim.
    fn may_attest(&self, issuer_did: &str, claim_type: &str) -> bool {
        match self.get_issuer(issuer_did) {
            Ok(Some(issuer)) => {
                issuer.status == IssuerStatus::Active
                    && issuer.credential_types.iter().any(|ct| ct == claim_type)
            }
            _ => false,
        }
    }
}

pub struct SqliteTrustStore {
    pool: Arc<Pool<SqliteConnectionManager>>,
}

impl SqliteTrustStore {
    pub fn new(db_path: &str) -> Result<Self> {
        let manager = SqliteConnectionManager::file(db_path);
        let pool = Pool::builder().max_size(8).build(manager)?;
        let conn = pool.get()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS issuers (did TEXT PRIMARY KEY, document TEXT NOT NULL);",
        )?;
        Ok(SqliteTrustStore {
            pool: Arc::new(pool),
        })
    }

    pub fn new_in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;
        let conn = pool.get()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS issuers (did TEXT PRIMARY KEY, document TEXT NOT NULL);",
        )?;
        Ok(SqliteTrustStore {
            pool: Arc::new(pool),
        })
    }
}

impl TrustStore for SqliteTrustStore {
    fn upsert_issuer(&self, issuer: &Issuer) -> Result<()> {
        let doc = serde_json::to_string(issuer)?;
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT OR REPLACE INTO issuers (did, document) VALUES (?1, ?2)",
            params![&issuer.did, &doc],
        )?;
        Ok(())
    }

    fn get_issuer(&self, did: &str) -> Result<Option<Issuer>> {
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT document FROM issuers WHERE did = ?1",
            params![did],
            |row| {
                let doc: String = row.get(0)?;
                Ok(doc)
            },
        );

        match result {
            Ok(doc) => {
                let issuer = serde_json::from_str::<Issuer>(&doc)?;
                Ok(Some(issuer))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(anyhow::Error::from(e)),
        }
    }

    fn list_issuers(&self, claim_type: Option<&str>) -> Result<Vec<Issuer>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT document FROM issuers")?;
        let rows = stmt.query_map([], |row| {
            let doc: String = row.get(0)?;
            Ok(doc)
        })?;

        let mut vec = Vec::new();
        for row_result in rows {
            let doc = row_result?;
            let issuer = serde_json::from_str::<Issuer>(&doc)?;
            if let Some(ct) = claim_type {
                if issuer.credential_types.iter().any(|c| c == ct) {
                    vec.push(issuer);
                }
            } else {
                vec.push(issuer);
            }
        }

        Ok(vec)
    }

    fn may_attest(&self, issuer_did: &str, claim_type: &str) -> bool {
        match self.get_issuer(issuer_did) {
            Ok(Some(issuer)) => {
                let now = Utc::now();
                issuer.status == IssuerStatus::Active
                    && now >= issuer.valid_from
                    && now <= issuer.valid_until
                    && issuer.credential_types.iter().any(|ct| ct == claim_type)
            }
            _ => false,
        }
    }
}
