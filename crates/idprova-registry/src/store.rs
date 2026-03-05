use anyhow::Result;
use rusqlite::Connection;
use serde::Serialize;

use idprova_core::aid::AidDocument;

/// SQLite-backed store for AID documents and DAT revocations.
pub struct AidStore {
    conn: Connection,
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
    /// Create or open the store database.
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

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
            ",
        )?;

        Ok(Self { conn })
    }

    // ── AID operations ───────────────────────────────────────────────────────

    /// Store or update an AID document. Returns true if this is a new entry.
    pub fn put(&self, did: &str, doc: &AidDocument) -> Result<bool> {
        let json = serde_json::to_string(doc)?;

        let existing =
            self.conn
                .query_row("SELECT COUNT(*) FROM aids WHERE did = ?", [did], |row| {
                    row.get::<_, i64>(0)
                })?;

        if existing > 0 {
            self.conn.execute(
                "UPDATE aids SET document = ?, updated_at = datetime('now'), active = 1 WHERE did = ?",
                rusqlite::params![json, did],
            )?;
            Ok(false)
        } else {
            self.conn.execute(
                "INSERT INTO aids (did, document) VALUES (?, ?)",
                rusqlite::params![did, json],
            )?;
            Ok(true)
        }
    }

    /// Retrieve an AID document by DID (active only).
    pub fn get(&self, did: &str) -> Result<Option<AidDocument>> {
        let result = self.conn.query_row(
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
        let rows = self.conn.execute(
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
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO dat_revocations (jti, reason, revoked_by) VALUES (?, ?, ?)",
            rusqlite::params![jti, reason, revoked_by],
        )?;
        Ok(rows > 0)
    }

    /// Return true if the given JTI has been revoked.
    #[allow(dead_code)]
    pub fn is_revoked(&self, jti: &str) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM dat_revocations WHERE jti = ?",
            [jti],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Open an in-memory database for testing.
    #[cfg(test)]
    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
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
            ",
        )?;
        Ok(Self { conn })
    }

    /// Return the revocation record for a JTI, if one exists.
    pub fn get_revocation(&self, jti: &str) -> Result<Option<RevocationRecord>> {
        let result = self.conn.query_row(
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
            assert!(result.is_ok(), "revoke failed with SQL payload in reason: {payload}");
        }
    }

    #[test]
    fn test_sqli_in_get_revocation() {
        let store = AidStore::new_in_memory().unwrap();
        for payload in SQLI_PAYLOADS {
            // Lookup with malicious JTI — should return None, not error or panic
            let result = store.get_revocation(payload);
            assert!(result.is_ok(), "get_revocation failed for payload: {payload}");
            assert!(result.unwrap().is_none(), "unexpected row for payload: {payload}");
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
        let result = store.revoke(unicode_jti, "测试 reason 🎉", "did:idprova:测试");
        assert!(result.is_ok(), "unicode fields should be handled safely");
        let found = store.is_revoked(unicode_jti).unwrap();
        assert!(found, "unicode JTI not found after insert");
    }
}
