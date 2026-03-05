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
