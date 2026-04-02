//! Stripe billing integration — checkout sessions, webhooks, customer portal.

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use hmac::{Hmac, Mac};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ── Org store ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub email: String,
    pub tier: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone)]
pub struct OrgStore {
    pool: Pool<SqliteConnectionManager>,
}

impl OrgStore {
    pub fn new(pool: Pool<SqliteConnectionManager>) -> Self {
        Self { pool }
    }

    pub fn create(&self, id: &str, name: &str, email: &str, tier: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO orgs (id, name, email, tier) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![id, name, email, tier],
        )?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<Org>> {
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT id, name, email, tier, stripe_customer_id, stripe_subscription_id,
                    created_at, updated_at
             FROM orgs WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(Org {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    tier: row.get(3)?,
                    stripe_customer_id: row.get(4)?,
                    stripe_subscription_id: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        );
        match result {
            Ok(org) => Ok(Some(org)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_by_stripe_customer(&self, customer_id: &str) -> Result<Option<Org>> {
        let conn = self.pool.get()?;
        let result = conn.query_row(
            "SELECT id, name, email, tier, stripe_customer_id, stripe_subscription_id,
                    created_at, updated_at
             FROM orgs WHERE stripe_customer_id = ?1",
            rusqlite::params![customer_id],
            |row| {
                Ok(Org {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    email: row.get(2)?,
                    tier: row.get(3)?,
                    stripe_customer_id: row.get(4)?,
                    stripe_subscription_id: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        );
        match result {
            Ok(org) => Ok(Some(org)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_stripe_customer(&self, org_id: &str, customer_id: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE orgs SET stripe_customer_id = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![customer_id, org_id],
        )?;
        Ok(())
    }

    pub fn set_stripe_subscription(&self, org_id: &str, sub_id: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE orgs SET stripe_subscription_id = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![sub_id, org_id],
        )?;
        Ok(())
    }

    pub fn set_tier(&self, org_id: &str, tier: &str) -> Result<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE orgs SET tier = ?1, updated_at = datetime('now') WHERE id = ?2",
            rusqlite::params![tier, org_id],
        )?;
        Ok(())
    }
}

// ── Stripe client ────────────────────────────────────────────────────────────

/// Minimal Stripe API client using reqwest.
#[derive(Clone)]
pub struct StripeClient {
    secret_key: String,
    base_url: String,
}

impl StripeClient {
    pub fn from_env() -> Option<Self> {
        let key = std::env::var("STRIPE_SECRET_KEY").ok()?;
        Some(Self {
            secret_key: key,
            base_url: "https://api.stripe.com/v1".to_string(),
        })
    }

    /// Create with a custom base URL (for testing).
    #[cfg(test)]
    pub fn new(secret_key: &str, base_url: &str) -> Self {
        Self {
            secret_key: secret_key.to_string(),
            base_url: base_url.to_string(),
        }
    }

    /// Create a Stripe Checkout Session for a given price.
    pub async fn create_checkout_session(
        &self,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
        client_reference_id: &str,
    ) -> Result<Value> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/checkout/sessions", self.base_url))
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[
                ("mode", "subscription"),
                ("line_items[0][price]", price_id),
                ("line_items[0][quantity]", "1"),
                ("success_url", success_url),
                ("cancel_url", cancel_url),
                ("client_reference_id", client_reference_id),
            ])
            .send()
            .await?;
        let body: Value = resp.json().await?;
        Ok(body)
    }

    /// Create a customer portal session.
    pub async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &str,
    ) -> Result<Value> {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/billing_portal/sessions", self.base_url))
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&[("customer", customer_id), ("return_url", return_url)])
            .send()
            .await?;
        let body: Value = resp.json().await?;
        Ok(body)
    }
}

// ── Endpoint handlers ────────────────────────────────────────────────────────

/// Request body for POST /v1/billing/checkout
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    pub org_id: String,
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// POST /v1/billing/checkout — create a Stripe Checkout Session.
pub async fn create_checkout(
    State(state): State<std::sync::Arc<crate::AppState>>,
    Json(req): Json<CheckoutRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let stripe = StripeClient::from_env().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "Stripe not configured" })),
        )
    })?;

    // Validate URLs to prevent SSRF
    for url_str in [&req.success_url, &req.cancel_url] {
        if let Ok(parsed) = url::Url::parse(url_str) {
            if parsed.scheme() != "https" && parsed.scheme() != "http" {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "URLs must use http or https scheme" })),
                ));
            }
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid URL format" })),
            ));
        }
    }

    let org_store = OrgStore::new(state.store.pool().clone());

    // Create org if not exists (starter tier)
    if org_store.get(&req.org_id).map_err(internal_err)?.is_none() {
        org_store
            .create(&req.org_id, "", "", "starter")
            .map_err(internal_err)?;
    }

    let session = stripe
        .create_checkout_session(
            &req.price_id,
            &req.success_url,
            &req.cancel_url,
            &req.org_id,
        )
        .await
        .map_err(|e| {
            tracing::error!("Stripe checkout error: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "billing service unavailable" })),
            )
        })?;

    Ok(Json(json!({
        "checkout_url": session.get("url").and_then(|v| v.as_str()).unwrap_or(""),
        "session_id": session.get("id").and_then(|v| v.as_str()).unwrap_or("")
    })))
}

/// Verify Stripe webhook signature (HMAC-SHA256).
/// Header format: `t=1234567890,v1=abc123...`
fn verify_stripe_signature(body: &str, sig_header: &str, secret: &str) -> Result<(), String> {
    let mut timestamp = "";
    let mut signature = "";
    for part in sig_header.split(',') {
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t;
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = v;
        }
    }
    if timestamp.is_empty() || signature.is_empty() {
        return Err("missing timestamp or signature".into());
    }

    // Replay protection: reject events older than 5 minutes
    if let Ok(ts) = timestamp.parse::<i64>() {
        let now = chrono::Utc::now().timestamp();
        if (now - ts).abs() > 300 {
            return Err("timestamp too old (replay protection)".into());
        }
    } else {
        return Err("invalid timestamp".into());
    }

    // Compute expected signature: HMAC-SHA256(secret, "{timestamp}.{body}")
    let payload = format!("{timestamp}.{body}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| "invalid webhook secret".to_string())?;
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison (compare hex strings byte-by-byte)
    if expected.len() != signature.len() {
        return Err("signature mismatch".into());
    }
    let matches = expected
        .as_bytes()
        .iter()
        .zip(signature.as_bytes().iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if matches != 0 {
        return Err("signature mismatch".into());
    }
    Ok(())
}

/// POST /v1/billing/webhook — handle Stripe webhook events.
pub async fn handle_webhook(
    State(state): State<std::sync::Arc<crate::AppState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Verify Stripe webhook signature if secret is configured
    if let Ok(secret) = std::env::var("STRIPE_WEBHOOK_SECRET") {
        let sig_header = headers
            .get("stripe-signature")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "missing stripe-signature header" })),
                )
            })?;
        verify_stripe_signature(&body, sig_header, &secret).map_err(|e| {
            tracing::warn!("Webhook signature verification failed: {e}");
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid webhook signature" })),
            )
        })?;
    }

    let event: Value = serde_json::from_str(&body).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid event payload" })),
        )
    })?;

    let event_type = event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let org_store = OrgStore::new(state.store.pool().clone());

    match event_type {
        "checkout.session.completed" => {
            let session = event
                .get("data")
                .and_then(|d| d.get("object"))
                .ok_or_else(|| {
                    tracing::warn!("Webhook checkout.session.completed missing data.object");
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "malformed event: missing data.object" })),
                    )
                })?;

            let org_id = session
                .get("client_reference_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    tracing::warn!("Webhook missing client_reference_id");
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "missing client_reference_id" })),
                    )
                })?;

            let customer_id = session
                .get("customer")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    tracing::warn!("Webhook missing customer for org={org_id}");
                    (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "missing customer" })),
                    )
                })?;

            org_store
                .set_stripe_customer(org_id, customer_id)
                .map_err(internal_err)?;

            if let Some(sub_id) = session
                .get("subscription")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                org_store
                    .set_stripe_subscription(org_id, sub_id)
                    .map_err(internal_err)?;
            }

            org_store
                .set_tier(org_id, "developer")
                .map_err(internal_err)?;
            tracing::info!("Checkout completed for org={org_id} customer={customer_id}");
        }
        "customer.subscription.updated" => {
            let sub = event.get("data").and_then(|d| d.get("object"));
            if let Some(sub) = sub {
                let customer_id = sub.get("customer").and_then(|v| v.as_str()).unwrap_or("");
                let status = sub.get("status").and_then(|v| v.as_str()).unwrap_or("");

                if !customer_id.is_empty() {
                    if let Ok(Some(org)) = org_store.get_by_stripe_customer(customer_id) {
                        if status == "canceled" || status == "unpaid" {
                            let _ = org_store.set_tier(&org.id, "starter");
                            tracing::info!(
                                "Subscription {} for org={} — downgraded to starter",
                                status,
                                org.id
                            );
                        }
                    }
                }
            }
        }
        "customer.subscription.deleted" => {
            let sub = event.get("data").and_then(|d| d.get("object"));
            if let Some(sub) = sub {
                let customer_id = sub.get("customer").and_then(|v| v.as_str()).unwrap_or("");
                if !customer_id.is_empty() {
                    if let Ok(Some(org)) = org_store.get_by_stripe_customer(customer_id) {
                        let _ = org_store.set_tier(&org.id, "starter");
                        tracing::info!(
                            "Subscription deleted for org={} — downgraded to starter",
                            org.id
                        );
                    }
                }
            }
        }
        _ => {
            tracing::debug!("Ignoring webhook event: {event_type}");
        }
    }

    Ok(Json(json!({ "received": true })))
}

/// Request body for GET /v1/billing/portal
#[derive(Debug, Deserialize)]
pub struct PortalQuery {
    pub org_id: String,
    pub return_url: String,
}

/// GET /v1/billing/portal — redirect to Stripe Customer Portal.
pub async fn get_portal(
    State(state): State<std::sync::Arc<crate::AppState>>,
    axum::extract::Query(query): axum::extract::Query<PortalQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let stripe = StripeClient::from_env().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "Stripe not configured" })),
        )
    })?;

    let org_store = OrgStore::new(state.store.pool().clone());
    let org = org_store
        .get(&query.org_id)
        .map_err(internal_err)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "org not found" })),
            )
        })?;

    let customer_id = org.stripe_customer_id.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "org has no Stripe customer" })),
        )
    })?;

    let session = stripe
        .create_portal_session(&customer_id, &query.return_url)
        .await
        .map_err(|e| {
            tracing::error!("Stripe portal error: {e}");
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "billing service unavailable" })),
            )
        })?;

    Ok(Json(json!({
        "portal_url": session.get("url").and_then(|v| v.as_str()).unwrap_or("")
    })))
}

fn internal_err(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    tracing::error!("Internal billing error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "internal server error" })),
    )
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
    fn test_org_crud() {
        let pool = test_pool();
        let store = OrgStore::new(pool);

        store
            .create("org-1", "Test Org", "test@example.com", "starter")
            .unwrap();
        let org = store.get("org-1").unwrap().unwrap();
        assert_eq!(org.name, "Test Org");
        assert_eq!(org.tier, "starter");

        store.set_tier("org-1", "developer").unwrap();
        let org = store.get("org-1").unwrap().unwrap();
        assert_eq!(org.tier, "developer");
    }

    #[test]
    fn test_stripe_customer_link() {
        let pool = test_pool();
        let store = OrgStore::new(pool);

        store
            .create("org-s", "Stripe Org", "s@example.com", "starter")
            .unwrap();
        store.set_stripe_customer("org-s", "cus_test123").unwrap();

        let org = store
            .get_by_stripe_customer("cus_test123")
            .unwrap()
            .unwrap();
        assert_eq!(org.id, "org-s");

        store
            .set_stripe_subscription("org-s", "sub_test456")
            .unwrap();
        let org = store.get("org-s").unwrap().unwrap();
        assert_eq!(org.stripe_subscription_id, Some("sub_test456".to_string()));
    }

    #[test]
    fn test_webhook_checkout_completed() {
        // Test that the webhook handler parses checkout.session.completed events.
        // We test the OrgStore operations directly since the handler is async.
        let pool = test_pool();
        let store = OrgStore::new(pool);

        store
            .create("org-wh", "WH Org", "wh@example.com", "starter")
            .unwrap();

        // Simulate what the webhook handler does
        let org_id = "org-wh";
        let customer_id = "cus_webhook";
        let subscription_id = "sub_webhook";

        store.set_stripe_customer(org_id, customer_id).unwrap();
        store
            .set_stripe_subscription(org_id, subscription_id)
            .unwrap();
        store.set_tier(org_id, "developer").unwrap();

        let org = store.get("org-wh").unwrap().unwrap();
        assert_eq!(org.tier, "developer");
        assert_eq!(org.stripe_customer_id, Some("cus_webhook".to_string()));
    }

    #[test]
    fn test_get_nonexistent_org() {
        let pool = test_pool();
        let store = OrgStore::new(pool);
        assert!(store.get("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_get_by_stripe_customer_not_found() {
        let pool = test_pool();
        let store = OrgStore::new(pool);
        assert!(store
            .get_by_stripe_customer("cus_nonexistent")
            .unwrap()
            .is_none());
    }

    // ── Webhook signature verification tests ─────────────────────────────

    fn make_stripe_signature(body: &str, secret: &str, timestamp: i64) -> String {
        let payload = format!("{timestamp}.{body}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        format!("t={timestamp},v1={sig}")
    }

    #[test]
    fn test_webhook_sig_valid() {
        let body = r#"{"type":"test"}"#;
        let secret = "whsec_test123";
        let ts = chrono::Utc::now().timestamp();
        let header = make_stripe_signature(body, secret, ts);
        assert!(verify_stripe_signature(body, &header, secret).is_ok());
    }

    #[test]
    fn test_webhook_sig_invalid() {
        let body = r#"{"type":"test"}"#;
        let secret = "whsec_test123";
        let ts = chrono::Utc::now().timestamp();
        let header =
            format!("t={ts},v1=0000000000000000000000000000000000000000000000000000000000000000");
        assert!(verify_stripe_signature(body, &header, secret).is_err());
    }

    #[test]
    fn test_webhook_sig_missing_header() {
        assert!(verify_stripe_signature("body", "", "secret").is_err());
    }

    #[test]
    fn test_webhook_sig_expired_timestamp() {
        let body = r#"{"type":"test"}"#;
        let secret = "whsec_test123";
        let old_ts = chrono::Utc::now().timestamp() - 600; // 10 min ago
        let header = make_stripe_signature(body, secret, old_ts);
        let result = verify_stripe_signature(body, &header, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("replay"));
    }
}
