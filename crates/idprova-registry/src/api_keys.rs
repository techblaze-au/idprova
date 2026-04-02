//! API key generation, hashing, storage, and validation.
//!
//! Keys are 32 random bytes encoded as hex (64 chars). Only the BLAKE3 hash
//! is stored in SQLite — the raw key is returned once at creation time.

use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Serialize;

/// Prefix for all API keys (makes them easy to identify in logs / env vars).
const KEY_PREFIX: &str = "idp_";

/// Generate a random 32-byte API key, return it as `idp_<64 hex chars>`.
pub fn generate_api_key() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    format!("{}{}", KEY_PREFIX, hex::encode(buf))
}

/// BLAKE3-hash a raw API key string. The hash is stored in the DB.
pub fn hash_api_key(raw: &str) -> String {
    let hash = blake3::hash(raw.as_bytes());
    hash.to_hex().to_string()
}

/// Row returned when listing keys for an org.
#[derive(Debug, Clone, Serialize)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub org_id: String,
    pub key_hash: String,
    pub label: String,
    pub created_at: String,
    pub revoked: bool,
}

/// Manages API key storage in SQLite.
#[derive(Clone)]
pub struct ApiKeyStore {
    pool: Pool<SqliteConnectionManager>,
}

impl ApiKeyStore {
    /// Wrap an existing connection pool (shares the pool with AidStore).
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    /// Create the api_keys table if it doesn't exist.
    pub fn init_tables(&self) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS api_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id     TEXT NOT NULL,
                key_hash   TEXT NOT NULL UNIQUE,
                label      TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                revoked    INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id);
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
            ",
        )?;
        Ok(())
    }

    /// Store a new API key hash. Returns the row id.
    pub fn insert(&self, org_id: &str, key_hash: &str, label: &str) -> Result<i64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO api_keys (org_id, key_hash, label) VALUES (?1, ?2, ?3)",
            rusqlite::params![org_id, key_hash, label],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Validate a raw API key. Returns the org_id if valid and not revoked.
    pub fn validate(&self, raw_key: &str) -> Result<Option<String>> {
        let hash = hash_api_key(raw_key);
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT org_id FROM api_keys WHERE key_hash = ?1 AND revoked = 0",
            rusqlite::params![hash],
            |row| row.get::<_, String>(0),
        );
        match result {
            Ok(org_id) => Ok(Some(org_id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Revoke a key by its hash.
    pub fn revoke(&self, key_hash: &str) -> Result<bool> {
        let conn = self.pool.get()?;
        let rows = conn.execute(
            "UPDATE api_keys SET revoked = 1 WHERE key_hash = ?1 AND revoked = 0",
            rusqlite::params![key_hash],
        )?;
        Ok(rows > 0)
    }

    /// List all keys for an org.
    pub fn list_for_org(&self, org_id: &str) -> Result<Vec<ApiKeyRecord>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, org_id, key_hash, label, created_at, revoked
             FROM api_keys WHERE org_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![org_id], |row| {
                Ok(ApiKeyRecord {
                    id: row.get(0)?,
                    org_id: row.get(1)?,
                    key_hash: row.get(2)?,
                    label: row.get(3)?,
                    created_at: row.get(4)?,
                    revoked: row.get::<_, i64>(5)? != 0,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::memory();
        Pool::builder().max_size(1).build(manager).unwrap()
    }

    #[test]
    fn test_generate_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("idp_"), "key should start with idp_ prefix");
        // idp_ (4) + 64 hex chars = 68
        assert_eq!(key.len(), 68, "key should be 68 chars total");
        // The hex portion should be valid hex
        assert!(hex::decode(&key[4..]).is_ok(), "suffix should be valid hex");
    }

    #[test]
    fn test_hash_deterministic() {
        let key = "idp_aabbccdd";
        let h1 = hash_api_key(key);
        let h2 = hash_api_key(key);
        assert_eq!(h1, h2, "same input should produce same hash");

        let h3 = hash_api_key("idp_different");
        assert_ne!(h1, h3, "different input should produce different hash");
    }

    #[test]
    fn test_insert_validate_revoke() {
        let pool = test_pool();
        let store = ApiKeyStore::new(pool);
        store.init_tables().unwrap();

        let raw_key = generate_api_key();
        let hash = hash_api_key(&raw_key);

        // Insert
        let id = store.insert("org-1", &hash, "test key").unwrap();
        assert!(id > 0);

        // Validate
        let org = store.validate(&raw_key).unwrap();
        assert_eq!(org, Some("org-1".to_string()));

        // Revoke
        let revoked = store.revoke(&hash).unwrap();
        assert!(revoked);

        // Validate after revoke — should return None
        let org_after = store.validate(&raw_key).unwrap();
        assert_eq!(org_after, None);
    }

    #[test]
    fn test_validate_unknown_key() {
        let pool = test_pool();
        let store = ApiKeyStore::new(pool);
        store.init_tables().unwrap();

        let result = store.validate("idp_nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_list_for_org() {
        let pool = test_pool();
        let store = ApiKeyStore::new(pool);
        store.init_tables().unwrap();

        let k1 = generate_api_key();
        let k2 = generate_api_key();
        store.insert("org-a", &hash_api_key(&k1), "key 1").unwrap();
        store.insert("org-a", &hash_api_key(&k2), "key 2").unwrap();
        store
            .insert("org-b", &hash_api_key(&generate_api_key()), "other")
            .unwrap();

        let keys = store.list_for_org("org-a").unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.org_id == "org-a"));
    }
}
