use anyhow::Result;
use rusqlite::Connection;

use idprova_core::aid::AidDocument;

/// SQLite-backed store for AID documents.
pub struct AidStore {
    conn: Connection,
}

impl AidStore {
    /// Create or open the AID store database.
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
            ",
        )?;

        Ok(Self { conn })
    }

    /// Store or update an AID document. Returns true if this is a new entry.
    pub fn put(&self, did: &str, doc: &AidDocument) -> Result<bool> {
        let json = serde_json::to_string(doc)?;

        let existing = self.conn.query_row(
            "SELECT COUNT(*) FROM aids WHERE did = ?",
            [did],
            |row| row.get::<_, i64>(0),
        )?;

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

    /// Retrieve an AID document by DID.
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
}
