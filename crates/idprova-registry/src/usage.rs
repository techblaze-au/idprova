//! Usage metering — per-org, per-endpoint, per-month counters with tier limits.

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Tier definitions with monthly AID resolution limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Starter,
    Developer,
    Team,
}

impl Tier {
    /// Monthly AID resolution limit for this tier.
    pub fn limit(&self) -> u64 {
        match self {
            Tier::Starter => 25,
            Tier::Developer => 250,
            Tier::Team => 2500,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Starter => "starter",
            Tier::Developer => "developer",
            Tier::Team => "team",
        }
    }
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Tier {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "starter" => Ok(Tier::Starter),
            "developer" => Ok(Tier::Developer),
            "team" => Ok(Tier::Team),
            _ => Err(anyhow::anyhow!("unknown tier: {s}")),
        }
    }
}

/// Usage record for a single org/endpoint/month combination.
#[derive(Debug, Clone, Serialize)]
pub struct UsageRecord {
    pub org_id: String,
    pub endpoint: String,
    pub month: String,
    pub count: u64,
}

/// Manages usage counting in SQLite.
#[derive(Clone)]
pub struct UsageStore {
    pool: Pool<SqliteConnectionManager>,
}

impl UsageStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    /// Increment the usage counter for an org/endpoint/month.
    /// Uses UPSERT (INSERT ... ON CONFLICT UPDATE).
    pub fn increment(&self, org_id: &str, endpoint: &str, month: &str) -> Result<u64> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO usage_records (org_id, endpoint, month, count)
             VALUES (?1, ?2, ?3, 1)
             ON CONFLICT(org_id, endpoint, month)
             DO UPDATE SET count = MIN(count + 1, 9223372036854775806)",
            rusqlite::params![org_id, endpoint, month],
        )?;
        let count: u64 = conn.query_row(
            "SELECT count FROM usage_records WHERE org_id = ?1 AND endpoint = ?2 AND month = ?3",
            rusqlite::params![org_id, endpoint, month],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get total usage across all endpoints for an org in a given month.
    pub fn get_total(&self, org_id: &str, month: &str) -> Result<u64> {
        let conn = self.pool.get()?;
        let total: u64 = conn.query_row(
            "SELECT COALESCE(SUM(count), 0) FROM usage_records WHERE org_id = ?1 AND month = ?2",
            rusqlite::params![org_id, month],
            |row| row.get(0),
        )?;
        Ok(total)
    }

    /// Get per-endpoint breakdown for an org in a given month.
    pub fn get_breakdown(&self, org_id: &str, month: &str) -> Result<Vec<UsageRecord>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT org_id, endpoint, month, count
             FROM usage_records WHERE org_id = ?1 AND month = ?2
             ORDER BY count DESC",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![org_id, month], |row| {
                Ok(UsageRecord {
                    org_id: row.get(0)?,
                    endpoint: row.get(1)?,
                    month: row.get(2)?,
                    count: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Check if an org has exceeded its tier limit for the current month.
    pub fn check_limit(&self, org_id: &str, month: &str, tier: Tier) -> Result<bool> {
        let total = self.get_total(org_id, month)?;
        Ok(total < tier.limit())
    }

    /// Get the org's tier from the orgs table.
    pub fn get_org_tier(&self, org_id: &str) -> Result<Tier> {
        let conn = self.pool.get()?;
        let tier_str: String = conn
            .query_row(
                "SELECT tier FROM orgs WHERE id = ?1",
                rusqlite::params![org_id],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "starter".to_string());
        tier_str.parse()
    }
}

/// Current month as YYYY-MM string.
pub fn current_month() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

/// GET /v1/usage — returns usage for the authenticated org.
///
/// Query params: month (optional, defaults to current month).
pub async fn get_usage(
    State(state): State<std::sync::Arc<crate::AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Extract API key from Authorization header
    let raw_key = extract_api_key(&headers)?;

    // Validate key and get org
    let key_store = crate::api_keys::ApiKeyStore::new(state.store.pool().clone());
    let org_id = key_store
        .validate(&raw_key)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("key validation error: {e}") })),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid or revoked API key" })),
            )
        })?;

    let usage_store = UsageStore::new(state.store.pool().clone());
    let month = current_month();
    let tier = usage_store.get_org_tier(&org_id).unwrap_or(Tier::Starter);
    let total = usage_store.get_total(&org_id, &month).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("usage query error: {e}") })),
        )
    })?;
    let breakdown = usage_store.get_breakdown(&org_id, &month).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("usage query error: {e}") })),
        )
    })?;

    Ok(Json(json!({
        "org_id": org_id,
        "month": month,
        "tier": tier.as_str(),
        "limit": tier.limit(),
        "total": total,
        "remaining": tier.limit().saturating_sub(total),
        "endpoints": breakdown
    })))
}

/// Extract API key from Authorization: Bearer <key> header.
pub fn extract_api_key(
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    let auth = headers
        .get("Authorization")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Authorization header required" })),
            )
        })?
        .to_str()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid Authorization header encoding" })),
            )
        })?;

    let key = auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Bearer token required" })),
            )
        })?
        .trim();

    if key.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "empty API key" })),
        ));
    }

    Ok(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pool() -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder().max_size(1).build(manager).unwrap();
        let conn = pool.get().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS usage_records (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id     TEXT NOT NULL,
                endpoint   TEXT NOT NULL DEFAULT '',
                month      TEXT NOT NULL,
                count      INTEGER NOT NULL DEFAULT 0,
                UNIQUE(org_id, endpoint, month)
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
            ",
        )
        .unwrap();
        pool
    }

    #[test]
    fn test_tier_limits() {
        assert_eq!(Tier::Starter.limit(), 25);
        assert_eq!(Tier::Developer.limit(), 250);
        assert_eq!(Tier::Team.limit(), 2500);
    }

    #[test]
    fn test_increment_and_total() {
        let pool = test_pool();
        let store = UsageStore::new(pool);

        let c1 = store.increment("org-1", "resolve", "2026-04").unwrap();
        assert_eq!(c1, 1);

        let c2 = store.increment("org-1", "resolve", "2026-04").unwrap();
        assert_eq!(c2, 2);

        // Different endpoint
        store.increment("org-1", "register", "2026-04").unwrap();

        let total = store.get_total("org-1", "2026-04").unwrap();
        assert_eq!(total, 3);
    }

    #[test]
    fn test_check_limit() {
        let pool = test_pool();
        let store = UsageStore::new(pool);

        // Starter tier limit = 25
        for _ in 0..24 {
            store.increment("org-limit", "resolve", "2026-04").unwrap();
        }
        assert!(store
            .check_limit("org-limit", "2026-04", Tier::Starter)
            .unwrap());

        // Hit the limit
        store
            .increment("org-limit", "resolve", "2026-04")
            .unwrap();
        assert!(!store
            .check_limit("org-limit", "2026-04", Tier::Starter)
            .unwrap());
    }

    #[test]
    fn test_breakdown() {
        let pool = test_pool();
        let store = UsageStore::new(pool);

        for _ in 0..5 {
            store
                .increment("org-brk", "resolve", "2026-04")
                .unwrap();
        }
        for _ in 0..3 {
            store
                .increment("org-brk", "register", "2026-04")
                .unwrap();
        }

        let breakdown = store.get_breakdown("org-brk", "2026-04").unwrap();
        assert_eq!(breakdown.len(), 2);
        // Ordered by count DESC
        assert_eq!(breakdown[0].endpoint, "resolve");
        assert_eq!(breakdown[0].count, 5);
        assert_eq!(breakdown[1].endpoint, "register");
        assert_eq!(breakdown[1].count, 3);
    }

    #[test]
    fn test_get_org_tier_default() {
        let pool = test_pool();
        let store = UsageStore::new(pool);

        // No org row — defaults to starter
        let tier = store.get_org_tier("nonexistent").unwrap();
        assert_eq!(tier, Tier::Starter);
    }

    #[test]
    fn test_different_months_isolated() {
        let pool = test_pool();
        let store = UsageStore::new(pool);

        store.increment("org-m", "resolve", "2026-03").unwrap();
        store.increment("org-m", "resolve", "2026-04").unwrap();
        store.increment("org-m", "resolve", "2026-04").unwrap();

        assert_eq!(store.get_total("org-m", "2026-03").unwrap(), 1);
        assert_eq!(store.get_total("org-m", "2026-04").unwrap(), 2);
    }
}
