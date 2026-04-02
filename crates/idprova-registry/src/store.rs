use anyhow::Result;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::Serialize;

use idprova_core::aid::AidDocument;

/// Summary entry returned by list_active().
#[derive(Debug, Clone, Serialize)]
pub struct AidListEntry {
    pub did: String,
    pub created_at: String,
    pub updated_at: String,
}

/// SQLite-backed store for AID documents and DAT revocations.
///
/// Uses an r2d2 connection pool for thread-safe concurrent access.
#[derive(Clone)]
pub struct AidStore {
    pool: Pool<SqliteConnectionManager>,
}

impl AidStore {
    /// Get a reference to the underlying connection pool.
    ///
    /// Used by other store modules (api_keys, usage, billing) to share the pool.
    pub fn pool(&self) -> &Pool<SqliteConnectionManager> {
        &self.pool
    }
}

/// A recorded DAT revocation.
#[derive(Debug, Clone, Serialize)]
pub struct RevocationRecord {
    pub jti: String,
    pub reason: String,
    pub revoked_by: String,
    pub revoked_at: String,
}

impl AidStore {
    /// Create or open the store database with a connection pool.
    pub fn new(path: &str) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder().max_size(8).build(manager)?;

        // Initialize schema on one connection
        let conn = pool.get()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS aids (
                did TEXT PRIMARY KEY,
                document TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_aids_active ON aids(active);

            CREATE TABLE IF NOT EXISTS dat_revocations (
                jti         TEXT PRIMARY KEY,
                reason      TEXT NOT NULL DEFAULT '',
                revoked_by  TEXT NOT NULL DEFAULT '',
                revoked_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

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

            CREATE TABLE IF NOT EXISTS orgs (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL DEFAULT '',
                email      TEXT NOT NULL DEFAULT '',
                tier       TEXT NOT NULL DEFAULT 'starter',
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS usage_records (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id     TEXT NOT NULL,
                endpoint   TEXT NOT NULL DEFAULT '',
                month      TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                UNIQUE(org_id, endpoint, month)
            );
            CREATE INDEX IF NOT EXISTS idx_usage_org_month ON usage_records(org_id, month);
            ",
        )?;

        Ok(Self { pool })
    }

    /// Open an in-memory database for testing.
    ///
    /// Uses max_size(1) to ensure all connections share the same in-memory DB.
    pub fn new_in_memory() -> Result<Self> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager)?;

        let conn = pool.get()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS aids (
                did TEXT PRIMARY KEY,
                document TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS dat_revocations (
                jti         TEXT PRIMARY KEY,
                reason      TEXT NOT NULL DEFAULT '',
                revoked_by  TEXT NOT NULL DEFAULT '',
                revoked_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id     TEXT NOT NULL,
                key_hash   TEXT NOT NULL UNIQUE,
                label      TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                revoked    INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS orgs (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL DEFAULT '',
                email      TEXT NOT NULL DEFAULT '',
                tier       TEXT NOT NULL DEFAULT 'starter',
                stripe_customer_id TEXT,
                stripe_subscription_id TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS usage_records (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id     TEXT NOT NULL,
                endpoint   TEXT NOT NULL DEFAULT '',
                month      TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                UNIQUE(org_id, endpoint, month)
            );
            ",
        )?;

        Ok(Self { pool })
    }

    // ── AID operations ───────────────────────────────────────────────────────

    /// Store or update an AID document. Returns true if this is a new entry.
    pub fn put(&self, did: &str, doc: &AidDocument) -> Result<bool> {
        let conn = self.pool.get()?;
        let json = serde_json::to_string(doc)?;

        let existing = conn.query_row("SELECT COUNT(*) FROM aids WHERE did = ?", [did], |row| {
            row.get::<_, i64>(0)
        })?;

        if existing > 0 {
            conn.execute(
                "UPDATE aids SET document = ?, updated_at = datetime('now'), active = 1 WHERE did = ?",
                rusqlite::params![json, did],
            )?;
            Ok(false)
        } else {
            conn.execute(
                "INSERT INTO aids (did, document) VALUES (?, ?)",
                rusqlite::params![did, json],
            )?;
            Ok(true)
        }
    }

    /// Retrieve an AID document by DID (active only).
    pub fn get(&self, did: &str) -> Result<Option<AidDocument>> {
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT document FROM aids WHERE did = ? AND active = 1",
            [did],
            |row| row.get::<_, String>(0),
        );

        match result {
            Ok(json) => {
                let doc: AidDocument = serde_json::from_str(&json)?;
                Ok(Some(doc))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Deactivate an AID. Returns true if found and deactivated.
    pub fn delete(&self, did: &str) -> Result<bool> {
        let conn = self.pool.get()?;
        let rows = conn.execute(
            "UPDATE aids SET active = 0, updated_at = datetime('now') WHERE did = ? AND active = 1",
            [did],
        )?;
        Ok(rows > 0)
    }

    // ── DAT revocation operations ────────────────────────────────────────────

    /// Record a DAT revocation by JTI.
    ///
    /// Idempotent — revoking an already-revoked JTI is a no-op (returns false).
    pub fn revoke(&self, jti: &str, reason: &str, revoked_by: &str) -> Result<bool> {
        let conn = self.pool.get()?;
        let rows = conn.execute(
            "INSERT OR IGNORE INTO dat_revocations (jti, reason, revoked_by) VALUES (?, ?, ?)",
            rusqlite::params![jti, reason, revoked_by],
        )?;
        Ok(rows > 0)
    }

    /// Return true if the given JTI has been revoked.
    #[allow(dead_code)]
    pub fn is_revoked(&self, jti: &str) -> Result<bool> {
        let conn = self.pool.get()?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM dat_revocations WHERE jti = ?",
            [jti],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Return all active AIDs (did + created_at + updated_at).
    pub fn list_active(&self) -> Result<Vec<AidListEntry>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT did, created_at, updated_at FROM aids WHERE active = 1 ORDER BY created_at DESC",
        )?;
        let entries = stmt
            .query_map([], |row| {
                Ok(AidListEntry {
                    did: row.get(0)?,
                    created_at: row.get(1)?,
                    updated_at: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(entries)
    }

    /// Return the revocation record for a JTI, if one exists.
    pub fn get_revocation(&self, jti: &str) -> Result<Option<RevocationRecord>> {
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT jti, reason, revoked_by, revoked_at FROM dat_revocations WHERE jti = ?",
            [jti],
            |row| {
                Ok(RevocationRecord {
                    jti: row.get(0)?,
                    reason: row.get(1)?,
                    revoked_by: row.get(2)?,
                    revoked_at: row.get(3)?,
                })
            },
        );

        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SQL injection payloads to verify parameterized queries are safe.
    const SQLI_PAYLOADS: &[&str] = &[
        "'; DROP TABLE aids; --",
        "\" OR 1=1",
        "1' OR '1'='1",
        "\0null_byte",
        "' UNION SELECT * FROM dat_revocations --",
        "'; INSERT INTO aids VALUES ('evil', '{}', datetime('now'), datetime('now'), 1); --",
    ];

    #[test]
    fn test_sqli_in_revoke_jti() {
        let store = AidStore::new_in_memory().unwrap();
        for payload in SQLI_PAYLOADS {
            // Should not panic or corrupt the DB — the payload is safely stored as-is
            let result = store.revoke(payload, "test", "tester");
            assert!(result.is_ok(), "revoke panicked on payload: {payload}");
            // Retrieve it back — confirms the payload was stored literally
            let found = store.is_revoked(payload).unwrap();
            assert!(found, "payload not stored as literal JTI: {payload}");
        }
    }

    #[test]
    fn test_sqli_in_revoke_reason() {
        let store = AidStore::new_in_memory().unwrap();
        for payload in SQLI_PAYLOADS {
            let result = store.revoke("test-jti-reason", payload, "tester");
            assert!(
                result.is_ok(),
                "revoke failed with SQL payload in reason: {payload}"
            );
        }
    }

    #[test]
    fn test_sqli_in_get_revocation() {
        let store = AidStore::new_in_memory().unwrap();
        for payload in SQLI_PAYLOADS {
            // Lookup with malicious JTI — should return None, not error or panic
            let result = store.get_revocation(payload);
            assert!(
                result.is_ok(),
                "get_revocation failed for payload: {payload}"
            );
            assert!(
                result.unwrap().is_none(),
                "unexpected row for payload: {payload}"
            );
        }
    }

    #[test]
    fn test_sqli_large_input_handled() {
        let store = AidStore::new_in_memory().unwrap();
        let large = "x".repeat(10_000);
        let result = store.revoke(&large, "reason", "tester");
        assert!(result.is_ok(), "large JTI should be handled safely");
    }

    #[test]
    fn test_unicode_in_fields() {
        let store = AidStore::new_in_memory().unwrap();
        let unicode_jti = "jtī-\u{1F600}-测试-\u{200B}";
        let result = store.revoke(unicode_jti, "测试 reason 🎉", "did:aid:测试");
        assert!(result.is_ok(), "unicode fields should be handled safely");
        let found = store.is_revoked(unicode_jti).unwrap();
        assert!(found, "unicode JTI not found after insert");
    }
}
