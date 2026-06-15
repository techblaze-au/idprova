//! AID-to-IdP binding storage, per RFC 0001 §6.1.
//!
//! Maintains the persistent link `(idp_issuer, idp_subject)` ↔ `did:aid:` AID
//! produced by Flow 1 (Identity bootstrap). `idp_subject` is stored alongside
//! a BLAKE3 hash for indexed lookup; per RFC §6.1.2 the raw `sub` is PII and
//! callers SHOULD redact it on outbound surfaces.
//!
//! Storage shape mirrors the existing `AidStore` in `crates/idprova-registry/
//! src/store.rs`: r2d2 + r2d2_sqlite pool, IDL applied on construction,
//! `anyhow::Result` from the public API.

use std::str::FromStr;

use anyhow::{Context, Result};
use rusqlite::params;
use serde::{Deserialize, Serialize};

// idprova-core exposes `crypto::blake3_hash(&[u8]) -> String` (hex digest).
use idprova_core::crypto::blake3_hash;

/// Custody of the AID signing key, per RFC 0001 §5.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyCustody {
    /// Overlay holds the key (HSM-backed for production).
    Overlay,
    /// The agent generated and holds its own keypair (L3+ requirement).
    Agent,
    /// Key resides in a customer HSM, accessed via PKCS#11 / KMIP.
    ExternalHsm,
}

impl KeyCustody {
    /// String representation matching the SQL column values.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyCustody::Overlay => "overlay",
            KeyCustody::Agent => "agent",
            KeyCustody::ExternalHsm => "external_hsm",
        }
    }
}

impl FromStr for KeyCustody {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "overlay" => Ok(KeyCustody::Overlay),
            "agent" => Ok(KeyCustody::Agent),
            "external_hsm" => Ok(KeyCustody::ExternalHsm),
            other => Err(format!("unknown key_custody variant: {other}")),
        }
    }
}

/// A row in the `aid_binding` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidBinding {
    /// `did:aid:{authority}:{name}` — primary key.
    pub did: String,
    /// OIDC `iss` claim of the upstream IdP.
    pub idp_issuer: String,
    /// OIDC `sub` claim. PII — redact on outbound surfaces per RFC §6.1.2.
    pub idp_subject: String,
    /// BLAKE3 hex digest of `idp_subject`. Index target.
    pub idp_subject_hash: String,
    /// Unix-seconds binding creation time.
    pub bound_at: i64,
    /// Unix-seconds last-refresh time (updated by `create_or_refresh`).
    pub last_refreshed_at: i64,
    /// Custody declaration for the AID signing key.
    pub key_custody: KeyCustody,
    /// Set when Flow-4 cascade deactivates this binding.
    pub deactivated_at: Option<i64>,
}

/// Lowercase-hex BLAKE3 of the UTF-8 subject string.
pub fn hash_subject(subject: &str) -> String {
    blake3_hash(subject.as_bytes())
}

const DDL: &str = "
CREATE TABLE IF NOT EXISTS aid_binding (
    did                  TEXT PRIMARY KEY,
    idp_issuer           TEXT NOT NULL,
    idp_subject          TEXT NOT NULL,
    idp_subject_hash     TEXT NOT NULL,
    bound_at             INTEGER NOT NULL,
    last_refreshed_at    INTEGER NOT NULL,
    key_custody          TEXT NOT NULL,
    deactivated_at       INTEGER,
    UNIQUE (idp_issuer, idp_subject_hash)
);
CREATE INDEX IF NOT EXISTS idx_aid_binding_issuer_hash
    ON aid_binding (idp_issuer, idp_subject_hash);
CREATE INDEX IF NOT EXISTS idx_aid_binding_active
    ON aid_binding (deactivated_at)
    WHERE deactivated_at IS NULL;
";

/// SQLite-backed `aid_binding` store.
#[derive(Clone)]
pub struct AidBindingStore {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
}

impl AidBindingStore {
    /// Open or create the database at `path`; applies the DDL.
    pub fn new(path: &str) -> Result<Self> {
        let manager = r2d2_sqlite::SqliteConnectionManager::file(path);
        let pool = r2d2::Pool::builder()
            .max_size(8)
            .build(manager)
            .context("building r2d2 pool for aid_binding")?;
        {
            let conn = pool.get().context("acquiring DDL connection")?;
            conn.execute_batch(DDL)
                .context("applying aid_binding DDL")?;
        }
        Ok(Self { pool })
    }

    /// Open an in-memory database (testing).
    pub fn new_in_memory() -> Result<Self> {
        let manager = r2d2_sqlite::SqliteConnectionManager::memory();
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .context("building in-memory r2d2 pool")?;
        {
            let conn = pool.get().context("acquiring DDL connection")?;
            conn.execute_batch(DDL)
                .context("applying aid_binding DDL")?;
        }
        Ok(Self { pool })
    }

    /// Insert a new binding or refresh an existing one (by `did`).
    /// Returns `true` if a new row was inserted, `false` on update.
    ///
    /// Uses an explicit existence check before INSERT/UPDATE so the
    /// insert/update distinction is reliable across SQLite versions
    /// (the SQLite `changes()` counter cannot distinguish UPSERT outcomes).
    pub fn create_or_refresh(&self, b: &AidBinding) -> Result<bool> {
        let conn = self.pool.get()?;
        let existing: i64 = conn.query_row(
            "SELECT COUNT(*) FROM aid_binding WHERE did = ?1",
            params![b.did],
            |row| row.get(0),
        )?;

        if existing > 0 {
            conn.execute(
                "UPDATE aid_binding SET
                    idp_issuer        = ?2,
                    idp_subject       = ?3,
                    idp_subject_hash  = ?4,
                    last_refreshed_at = ?5,
                    key_custody       = ?6
                 WHERE did = ?1",
                params![
                    b.did,
                    b.idp_issuer,
                    b.idp_subject,
                    b.idp_subject_hash,
                    b.last_refreshed_at,
                    b.key_custody.as_str(),
                ],
            )?;
            Ok(false)
        } else {
            conn.execute(
                "INSERT INTO aid_binding (
                    did, idp_issuer, idp_subject, idp_subject_hash,
                    bound_at, last_refreshed_at, key_custody, deactivated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    b.did,
                    b.idp_issuer,
                    b.idp_subject,
                    b.idp_subject_hash,
                    b.bound_at,
                    b.last_refreshed_at,
                    b.key_custody.as_str(),
                    b.deactivated_at,
                ],
            )?;
            Ok(true)
        }
    }

    /// Lookup by `did`.
    pub fn get_by_did(&self, did: &str) -> Result<Option<AidBinding>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT did, idp_issuer, idp_subject, idp_subject_hash,
                    bound_at, last_refreshed_at, key_custody, deactivated_at
             FROM aid_binding WHERE did = ?1",
        )?;
        let mut rows = stmt.query_map(params![did], row_to_binding)?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Lookup by (issuer, plaintext subject). The subject is hashed internally.
    pub fn get_by_idp_pair(&self, issuer: &str, subject: &str) -> Result<Option<AidBinding>> {
        let hash = hash_subject(subject);
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT did, idp_issuer, idp_subject, idp_subject_hash,
                    bound_at, last_refreshed_at, key_custody, deactivated_at
             FROM aid_binding
             WHERE idp_issuer = ?1 AND idp_subject_hash = ?2",
        )?;
        let mut rows = stmt.query_map(params![issuer, hash], row_to_binding)?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Set `deactivated_at`. Returns `true` if a row transitioned from active.
    pub fn deactivate(&self, did: &str, at: i64) -> Result<bool> {
        let conn = self.pool.get()?;
        let changed = conn.execute(
            "UPDATE aid_binding SET deactivated_at = ?1
             WHERE did = ?2 AND deactivated_at IS NULL",
            params![at, did],
        )?;
        Ok(changed > 0)
    }

    /// All bindings with `deactivated_at IS NULL`, ordered by `bound_at`.
    pub fn list_active(&self) -> Result<Vec<AidBinding>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT did, idp_issuer, idp_subject, idp_subject_hash,
                    bound_at, last_refreshed_at, key_custody, deactivated_at
             FROM aid_binding
             WHERE deactivated_at IS NULL
             ORDER BY bound_at",
        )?;
        let rows = stmt.query_map([], row_to_binding)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn row_to_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<AidBinding> {
    let custody_str: String = row.get(6)?;
    let custody = KeyCustody::from_str(&custody_str).map_err(|_| {
        rusqlite::Error::InvalidColumnType(6, "key_custody".into(), rusqlite::types::Type::Text)
    })?;
    Ok(AidBinding {
        did: row.get(0)?,
        idp_issuer: row.get(1)?,
        idp_subject: row.get(2)?,
        idp_subject_hash: row.get(3)?,
        bound_at: row.get(4)?,
        last_refreshed_at: row.get(5)?,
        key_custody: custody,
        deactivated_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(did: &str, subject: &str, bound_at: i64) -> AidBinding {
        AidBinding {
            did: did.to_string(),
            idp_issuer: "https://idp.example.com".to_string(),
            idp_subject: subject.to_string(),
            idp_subject_hash: hash_subject(subject),
            bound_at,
            last_refreshed_at: bound_at,
            key_custody: KeyCustody::Overlay,
            deactivated_at: None,
        }
    }

    #[test]
    fn new_binding_is_inserted_then_idempotent_refresh() {
        let store = AidBindingStore::new_in_memory().unwrap();
        let b = sample("did:aid:auth:name", "alice", 1000);
        assert!(
            store.create_or_refresh(&b).unwrap(),
            "first insert returns true"
        );
        assert!(
            !store.create_or_refresh(&b).unwrap(),
            "idempotent refresh returns false"
        );
    }

    #[test]
    fn get_by_did_roundtrips() {
        let store = AidBindingStore::new_in_memory().unwrap();
        let b = sample("did:aid:auth:round", "bob", 2000);
        store.create_or_refresh(&b).unwrap();
        let got = store.get_by_did(&b.did).unwrap().expect("row exists");
        assert_eq!(got.did, b.did);
        assert_eq!(got.idp_issuer, b.idp_issuer);
        assert_eq!(got.idp_subject, b.idp_subject);
        assert_eq!(got.idp_subject_hash, b.idp_subject_hash);
        assert_eq!(got.bound_at, b.bound_at);
        assert_eq!(got.last_refreshed_at, b.last_refreshed_at);
        assert_eq!(got.key_custody, b.key_custody);
        assert_eq!(got.deactivated_at, None);
    }

    #[test]
    fn get_by_idp_pair_hashes_subject() {
        let store = AidBindingStore::new_in_memory().unwrap();
        let b = sample("did:aid:auth:alice", "alice", 3000);
        store.create_or_refresh(&b).unwrap();
        let got = store
            .get_by_idp_pair("https://idp.example.com", "alice")
            .unwrap()
            .expect("found by idp pair");
        assert_eq!(got.did, "did:aid:auth:alice");
    }

    #[test]
    fn unique_constraint_on_issuer_subject_hash_rejects_second_did() {
        // Per RFC §6.1.4 + the UNIQUE constraint, a second DID for the same
        // (issuer, subject_hash) is a conflict that the caller must resolve
        // via §10.3 (manual reconciliation). The store surface returns an
        // error rather than silently aliasing.
        let store = AidBindingStore::new_in_memory().unwrap();
        let b1 = sample("did:aid:auth:v1", "carol", 4000);
        store.create_or_refresh(&b1).unwrap();

        let b2 = sample("did:aid:auth:v2", "carol", 5000);
        let result = store.create_or_refresh(&b2);
        assert!(
            result.is_err(),
            "second binding for same (issuer, subject_hash) must error per §6.1 UNIQUE"
        );
    }

    #[test]
    fn deactivate_marks_row_and_excludes_from_active_list() {
        let store = AidBindingStore::new_in_memory().unwrap();
        let b = sample("did:aid:auth:deact", "dave", 6000);
        store.create_or_refresh(&b).unwrap();
        assert!(store.deactivate(&b.did, 9999).unwrap());

        let got = store.get_by_did(&b.did).unwrap().expect("still queryable");
        assert_eq!(got.deactivated_at, Some(9999));

        // Second deactivate is a no-op (already deactivated).
        assert!(!store.deactivate(&b.did, 10000).unwrap());

        assert!(
            store.list_active().unwrap().is_empty(),
            "deactivated row excluded from list_active"
        );
    }

    #[test]
    fn list_active_orders_by_bound_at() {
        let store = AidBindingStore::new_in_memory().unwrap();
        store
            .create_or_refresh(&sample("did:aid:a:z", "zoe", 30))
            .unwrap();
        store
            .create_or_refresh(&sample("did:aid:a:a", "ann", 10))
            .unwrap();
        store
            .create_or_refresh(&sample("did:aid:a:m", "max", 20))
            .unwrap();

        let active = store.list_active().unwrap();
        assert_eq!(active.len(), 3);
        assert_eq!(active[0].did, "did:aid:a:a");
        assert_eq!(active[1].did, "did:aid:a:m");
        assert_eq!(active[2].did, "did:aid:a:z");
    }

    #[test]
    fn key_custody_roundtrips_all_three_variants() {
        let store = AidBindingStore::new_in_memory().unwrap();

        for (i, kc) in [
            KeyCustody::Overlay,
            KeyCustody::Agent,
            KeyCustody::ExternalHsm,
        ]
        .into_iter()
        .enumerate()
        {
            let did = format!("did:aid:auth:kc{i}");
            let mut b = sample(&did, &format!("user{i}"), 1000 + i as i64);
            b.key_custody = kc;
            store.create_or_refresh(&b).unwrap();
            let got = store.get_by_did(&did).unwrap().unwrap();
            assert_eq!(got.key_custody, kc);
        }

        // Also verify serde JSON round-trip.
        for kc in [
            KeyCustody::Overlay,
            KeyCustody::Agent,
            KeyCustody::ExternalHsm,
        ] {
            let json = serde_json::to_string(&kc).unwrap();
            let back: KeyCustody = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kc);
        }
    }

    #[test]
    fn refresh_updates_last_refreshed_at_but_preserves_bound_at() {
        let store = AidBindingStore::new_in_memory().unwrap();
        let mut b = sample("did:aid:auth:refresh", "ed", 1000);
        store.create_or_refresh(&b).unwrap();

        b.last_refreshed_at = 5000;
        store.create_or_refresh(&b).unwrap();

        let got = store.get_by_did(&b.did).unwrap().unwrap();
        assert_eq!(got.bound_at, 1000, "bound_at preserved across refresh");
        assert_eq!(got.last_refreshed_at, 5000, "last_refreshed_at updated");
    }
}
