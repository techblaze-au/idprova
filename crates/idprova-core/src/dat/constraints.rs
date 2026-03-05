//! RBAC Policy Engine — DAT constraint evaluators.
//!
//! Each evaluator is pure (no I/O, no async). The caller provides an
//! [`EvaluationContext`] with all runtime values; evaluators return
//! `Ok(())` on pass or `Err(ConstraintViolated)` on fail.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{IdprovaError, Result};

// ────────────────────────────────────────────────────────────────────────────
// Extended DatConstraints (replaces the minimal version in token.rs)
// ────────────────────────────────────────────────────────────────────────────

/// Full constraint set that can be embedded in a DAT.
///
/// All fields are optional — absent means "no restriction on this axis".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatConstraints {
    // ── existing fields (preserved for backwards compat) ──────────────────

    /// Maximum total actions allowed under this DAT (lifetime cap).
    #[serde(rename = "maxActions", skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u64>,

    /// Allowed MCP server hostnames/patterns.
    #[serde(rename = "allowedServers", skip_serializing_if = "Option::is_none")]
    pub allowed_servers: Option<Vec<String>>,

    /// Whether every action MUST produce an Action Receipt.
    #[serde(rename = "requireReceipt", skip_serializing_if = "Option::is_none")]
    pub require_receipt: Option<bool>,

    // ── Phase 2: rate limiting ─────────────────────────────────────────────

    /// Sliding-window rate limit.
    #[serde(rename = "rateLimit", skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,

    // ── Phase 2: IP access control ─────────────────────────────────────────

    /// CIDR ranges that are allowed to present this DAT.
    /// If set, the request IP MUST match at least one entry.
    #[serde(rename = "ipAllowlist", skip_serializing_if = "Option::is_none")]
    pub ip_allowlist: Option<Vec<String>>,

    /// CIDR ranges that are explicitly denied.
    /// Evaluated AFTER allowlist — a deny always wins.
    #[serde(rename = "ipDenylist", skip_serializing_if = "Option::is_none")]
    pub ip_denylist: Option<Vec<String>>,

    // ── Phase 2: trust level ───────────────────────────────────────────────

    /// Minimum trust level the presenting agent must have (0–100 scale).
    #[serde(rename = "minTrustLevel", skip_serializing_if = "Option::is_none")]
    pub min_trust_level: Option<u8>,

    // ── Phase 2: delegation depth ──────────────────────────────────────────

    /// Maximum delegation chain depth allowed (0 = no re-delegation).
    #[serde(rename = "maxDelegationDepth", skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,

    // ── Phase 2: geofence ──────────────────────────────────────────────────

    /// ISO 3166-1 alpha-2 country codes that are allowed.
    /// If set, the request country MUST be in this list.
    #[serde(rename = "allowedCountries", skip_serializing_if = "Option::is_none")]
    pub allowed_countries: Option<Vec<String>>,

    // ── Phase 2: time windows ──────────────────────────────────────────────

    /// UTC time windows during which the DAT may be used.
    #[serde(rename = "timeWindows", skip_serializing_if = "Option::is_none")]
    pub time_windows: Option<Vec<TimeWindow>>,

    // ── Phase 2: config attestation ────────────────────────────────────────

    /// Required SHA-256 hex hash of the agent's config.
    /// Stored in DatClaims.config_attestation; evaluator checks it matches.
    #[serde(rename = "requiredConfigHash", skip_serializing_if = "Option::is_none")]
    pub required_config_hash: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Supporting types
// ────────────────────────────────────────────────────────────────────────────

/// Sliding-window rate limit specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum number of actions within the window.
    pub max_actions: u64,
    /// Window duration in seconds.
    pub window_secs: u64,
}

/// A UTC time window within which access is permitted.
///
/// `start_hour` / `end_hour` are in UTC (0–23, inclusive on both ends).
/// If `days_of_week` is set, only those days are permitted (0=Monday, 6=Sunday).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start hour (UTC, 0–23).
    pub start_hour: u8,
    /// End hour (UTC, 0–23, inclusive).
    pub end_hour: u8,
    /// Permitted days of week (0=Monday … 6=Sunday). None = every day.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_of_week: Option<Vec<u8>>,
}

// ────────────────────────────────────────────────────────────────────────────
// Evaluation context — supplied by the caller at verification time
// ────────────────────────────────────────────────────────────────────────────

/// Runtime values provided by the verifier when evaluating a DAT.
#[derive(Debug, Clone, Default)]
pub struct EvaluationContext {
    /// Number of actions already taken under this DAT in the current window.
    pub actions_in_window: u64,

    /// IP address of the agent presenting the DAT.
    pub request_ip: Option<IpAddr>,

    /// Trust level of the presenting agent (0–100).
    pub agent_trust_level: Option<u8>,

    /// Length of the delegation chain (0 = root token, 1 = one level deep, …).
    pub delegation_depth: u32,

    /// ISO 3166-1 alpha-2 country code of the request origin.
    pub country_code: Option<String>,

    /// Current UTC timestamp (seconds since Unix epoch).
    /// If `None`, `Utc::now()` is used.
    pub current_timestamp: Option<i64>,

    /// SHA-256 hex hash of the agent's current config.
    pub agent_config_hash: Option<String>,
}

// ────────────────────────────────────────────────────────────────────────────
// Evaluators
// ────────────────────────────────────────────────────────────────────────────

impl DatConstraints {
    /// Run all applicable evaluators against the provided context.
    ///
    /// Returns the first violation found, or `Ok(())` if everything passes.
    pub fn evaluate(&self, ctx: &EvaluationContext) -> Result<()> {
        self.eval_rate_limit(ctx)?;
        self.eval_ip_allowlist(ctx)?;
        self.eval_ip_denylist(ctx)?;
        self.eval_trust_level(ctx)?;
        self.eval_delegation_depth(ctx)?;
        self.eval_geofence(ctx)?;
        self.eval_time_windows(ctx)?;
        // config_attestation is checked against DatClaims separately — see
        // eval_config_attestation() which takes the token's stored hash.
        Ok(())
    }

    // ── 1. Rate limiting ────────────────────────────────────────────────────

    /// Checks that `ctx.actions_in_window` has not exceeded the rate limit.
    ///
    /// NOTE: This evaluator checks a snapshot supplied by the caller — it does
    /// NOT maintain state itself (state lives in the runtime/middleware layer).
    pub fn eval_rate_limit(&self, ctx: &EvaluationContext) -> Result<()> {
        if let Some(rl) = &self.rate_limit {
            if ctx.actions_in_window >= rl.max_actions {
                return Err(IdprovaError::ConstraintViolated(format!(
                    "rate limit exceeded: {} actions in {}s window (max {})",
                    ctx.actions_in_window, rl.window_secs, rl.max_actions
                )));
            }
        }
        Ok(())
    }

    // ── 2. IP allowlist ─────────────────────────────────────────────────────

    /// If `ip_allowlist` is set, the request IP must match at least one CIDR.
    pub fn eval_ip_allowlist(&self, ctx: &EvaluationContext) -> Result<()> {
        let allowlist = match &self.ip_allowlist {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(()), // no restriction
        };

        let ip = match ctx.request_ip {
            Some(ip) => ip,
            None => {
                return Err(IdprovaError::ConstraintViolated(
                    "ip_allowlist is set but no request IP was provided".into(),
                ))
            }
        };

        for cidr in allowlist {
            if cidr_contains(cidr, ip) {
                return Ok(());
            }
        }

        Err(IdprovaError::ConstraintViolated(format!(
            "request IP {} is not in the allowlist",
            ip
        )))
    }

    // ── 3. IP denylist ──────────────────────────────────────────────────────

    /// If the request IP matches any entry in `ip_denylist`, deny immediately.
    pub fn eval_ip_denylist(&self, ctx: &EvaluationContext) -> Result<()> {
        let denylist = match &self.ip_denylist {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(()),
        };

        let ip = match ctx.request_ip {
            Some(ip) => ip,
            None => return Ok(()), // no IP supplied → can't match denylist
        };

        for cidr in denylist {
            if cidr_contains(cidr, ip) {
                return Err(IdprovaError::ConstraintViolated(format!(
                    "request IP {} is in the denylist ({})",
                    ip, cidr
                )));
            }
        }

        Ok(())
    }

    // ── 4. Trust level ──────────────────────────────────────────────────────

    /// The agent's trust level must be >= `min_trust_level`.
    pub fn eval_trust_level(&self, ctx: &EvaluationContext) -> Result<()> {
        let min = match self.min_trust_level {
            Some(m) => m,
            None => return Ok(()),
        };

        let actual = match ctx.agent_trust_level {
            Some(t) => t,
            None => {
                return Err(IdprovaError::ConstraintViolated(format!(
                    "min_trust_level {} required but agent trust level was not provided",
                    min
                )))
            }
        };

        if actual < min {
            return Err(IdprovaError::ConstraintViolated(format!(
                "agent trust level {} is below required minimum {}",
                actual, min
            )));
        }

        Ok(())
    }

    // ── 5. Delegation depth ─────────────────────────────────────────────────

    /// The delegation chain depth must not exceed `max_delegation_depth`.
    pub fn eval_delegation_depth(&self, ctx: &EvaluationContext) -> Result<()> {
        let max = match self.max_delegation_depth {
            Some(m) => m,
            None => return Ok(()),
        };

        if ctx.delegation_depth > max {
            return Err(IdprovaError::ConstraintViolated(format!(
                "delegation depth {} exceeds maximum {}",
                ctx.delegation_depth, max
            )));
        }

        Ok(())
    }

    // ── 6. Geofence ─────────────────────────────────────────────────────────

    /// If `allowed_countries` is set, the request country code must be listed.
    pub fn eval_geofence(&self, ctx: &EvaluationContext) -> Result<()> {
        let allowed = match &self.allowed_countries {
            Some(list) if !list.is_empty() => list,
            _ => return Ok(()),
        };

        let country = match &ctx.country_code {
            Some(c) => c,
            None => {
                return Err(IdprovaError::ConstraintViolated(
                    "allowed_countries is set but no country code was provided".into(),
                ))
            }
        };

        let upper = country.to_uppercase();
        if allowed.iter().any(|a| a.to_uppercase() == upper) {
            return Ok(());
        }

        Err(IdprovaError::ConstraintViolated(format!(
            "country '{}' is not in the geofence allowlist",
            country
        )))
    }

    // ── 7. Time windows ─────────────────────────────────────────────────────

    /// If `time_windows` is set, the current time must fall within at least one
    /// window. Hours are evaluated in UTC.
    pub fn eval_time_windows(&self, ctx: &EvaluationContext) -> Result<()> {
        let windows = match &self.time_windows {
            Some(w) if !w.is_empty() => w,
            _ => return Ok(()),
        };

        let now_secs = ctx
            .current_timestamp
            .unwrap_or_else(|| chrono::Utc::now().timestamp());

        let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(now_secs, 0)
            .ok_or_else(|| IdprovaError::ConstraintViolated("invalid timestamp".into()))?;

        let hour = dt.hour() as u8;
        // chrono weekday: Mon=0 … Sun=6
        let dow = dt.weekday().num_days_from_monday() as u8;

        for w in windows {
            // Validate window configuration
            if w.start_hour > 23 || w.end_hour > 23 {
                return Err(IdprovaError::ConstraintViolated(
                    "time window hour out of range (0-23)".into(),
                ));
            }

            // Check day-of-week
            if let Some(days) = &w.days_of_week {
                if !days.contains(&dow) {
                    continue;
                }
            }

            // Check hour range (handles wrap-around e.g. 22–02 UTC)
            let in_range = if w.start_hour <= w.end_hour {
                hour >= w.start_hour && hour <= w.end_hour
            } else {
                // wrap: e.g. start=22, end=02
                hour >= w.start_hour || hour <= w.end_hour
            };

            if in_range {
                return Ok(());
            }
        }

        Err(IdprovaError::ConstraintViolated(format!(
            "current UTC hour {} is outside all permitted time windows",
            hour
        )))
    }

    // ── 8. Config attestation ───────────────────────────────────────────────

    /// Verify that the agent's current config hash matches the one required by
    /// the constraint AND the one recorded in the DAT claims.
    ///
    /// `token_config_hash` is the value from `DatClaims.config_attestation`.
    pub fn eval_config_attestation(
        &self,
        ctx: &EvaluationContext,
        token_config_hash: Option<&str>,
    ) -> Result<()> {
        let required = match &self.required_config_hash {
            Some(h) => h,
            None => return Ok(()),
        };

        // The token must carry a matching config_attestation claim.
        let token_hash = match token_config_hash {
            Some(h) => h,
            None => {
                return Err(IdprovaError::ConstraintViolated(
                    "required_config_hash constraint set but token carries no configAttestation claim"
                        .into(),
                ))
            }
        };

        if token_hash != required {
            return Err(IdprovaError::ConstraintViolated(format!(
                "token configAttestation '{}' does not match required hash '{}'",
                token_hash, required
            )));
        }

        // The agent's live config must also match.
        let live_hash = match &ctx.agent_config_hash {
            Some(h) => h,
            None => {
                return Err(IdprovaError::ConstraintViolated(
                    "required_config_hash constraint set but agent config hash was not provided"
                        .into(),
                ))
            }
        };

        if live_hash != required {
            return Err(IdprovaError::ConstraintViolated(format!(
                "agent live config hash '{}' does not match required '{}'",
                live_hash, required
            )));
        }

        Ok(())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// CIDR matching — pure stdlib, no external dependencies
// ────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `ip` falls within the CIDR block described by `cidr_str`.
///
/// Supports both IPv4 (`10.0.0.0/8`) and IPv6 (`::1/128`) CIDRs.
/// A plain IP address with no prefix length is treated as /32 (IPv4) or /128 (IPv6).
fn cidr_contains(cidr_str: &str, ip: IpAddr) -> bool {
    let (addr_str, prefix_len) = match cidr_str.split_once('/') {
        Some((a, p)) => (a, p.parse::<u32>().unwrap_or(128)),
        None => (cidr_str, if cidr_str.contains(':') { 128 } else { 32 }),
    };

    let Ok(network_addr) = addr_str.parse::<IpAddr>() else {
        return false;
    };

    match (network_addr, ip) {
        (IpAddr::V4(net), IpAddr::V4(req)) => {
            let prefix = prefix_len.min(32);
            if prefix == 0 {
                return true;
            }
            let shift = 32 - prefix;
            (u32::from(net) >> shift) == (u32::from(req) >> shift)
        }
        (IpAddr::V6(net), IpAddr::V6(req)) => {
            let prefix = prefix_len.min(128);
            if prefix == 0 {
                return true;
            }
            let net_bits = u128::from(net);
            let req_bits = u128::from(req);
            let shift = 128 - prefix;
            (net_bits >> shift) == (req_bits >> shift)
        }
        // IPv4 vs IPv6 mismatch → never matches
        _ => false,
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Use chrono's time accessors
// ────────────────────────────────────────────────────────────────────────────

use chrono::Timelike;
use chrono::Datelike;

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ctx() -> EvaluationContext {
        EvaluationContext::default()
    }

    // ── CIDR helper ─────────────────────────────────────────────────────────

    #[test]
    fn test_cidr_ipv4_exact() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5));
        assert!(cidr_contains("192.168.1.0/24", ip));
        assert!(!cidr_contains("10.0.0.0/8", ip));
    }

    #[test]
    fn test_cidr_ipv4_host() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(cidr_contains("1.2.3.4", ip));
        assert!(cidr_contains("1.2.3.4/32", ip));
        assert!(!cidr_contains("1.2.3.5/32", ip));
    }

    #[test]
    fn test_cidr_ipv4_slash0() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(cidr_contains("0.0.0.0/0", ip));
    }

    #[test]
    fn test_cidr_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(cidr_contains("::1/128", ip));
        assert!(!cidr_contains("fe80::/10", ip));
    }

    #[test]
    fn test_cidr_mismatch_family() {
        let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(!cidr_contains("::1/128", ipv4));
    }

    // ── 1. Rate limiting ────────────────────────────────────────────────────

    #[test]
    fn test_rate_limit_pass() {
        let c = DatConstraints {
            rate_limit: Some(RateLimit { max_actions: 10, window_secs: 60 }),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.actions_in_window = 9;
        assert!(c.eval_rate_limit(&cx).is_ok());
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let c = DatConstraints {
            rate_limit: Some(RateLimit { max_actions: 10, window_secs: 60 }),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.actions_in_window = 10;
        let err = c.eval_rate_limit(&cx).unwrap_err();
        assert!(err.to_string().contains("rate limit exceeded"));
    }

    #[test]
    fn test_rate_limit_none() {
        let c = DatConstraints::default();
        assert!(c.eval_rate_limit(&ctx()).is_ok());
    }

    // ── 2. IP allowlist ─────────────────────────────────────────────────────

    #[test]
    fn test_ip_allowlist_pass() {
        let c = DatConstraints {
            ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.request_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(c.eval_ip_allowlist(&cx).is_ok());
    }

    #[test]
    fn test_ip_allowlist_fail() {
        let c = DatConstraints {
            ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.request_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(c.eval_ip_allowlist(&cx).is_err());
    }

    #[test]
    fn test_ip_allowlist_no_ip_provided() {
        let c = DatConstraints {
            ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        };
        assert!(c.eval_ip_allowlist(&ctx()).is_err());
    }

    // ── 3. IP denylist ──────────────────────────────────────────────────────

    #[test]
    fn test_ip_denylist_blocked() {
        let c = DatConstraints {
            ip_denylist: Some(vec!["192.168.0.0/16".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.request_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 5, 10)));
        assert!(c.eval_ip_denylist(&cx).is_err());
    }

    #[test]
    fn test_ip_denylist_pass() {
        let c = DatConstraints {
            ip_denylist: Some(vec!["192.168.0.0/16".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.request_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(c.eval_ip_denylist(&cx).is_ok());
    }

    #[test]
    fn test_ip_denylist_no_ip_is_ok() {
        // No IP → can't match denylist → pass
        let c = DatConstraints {
            ip_denylist: Some(vec!["0.0.0.0/0".into()]),
            ..Default::default()
        };
        assert!(c.eval_ip_denylist(&ctx()).is_ok());
    }

    // ── 4. Trust level ──────────────────────────────────────────────────────

    #[test]
    fn test_trust_level_pass() {
        let c = DatConstraints {
            min_trust_level: Some(50),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_trust_level = Some(75);
        assert!(c.eval_trust_level(&cx).is_ok());
    }

    #[test]
    fn test_trust_level_equal_passes() {
        let c = DatConstraints {
            min_trust_level: Some(80),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_trust_level = Some(80);
        assert!(c.eval_trust_level(&cx).is_ok());
    }

    #[test]
    fn test_trust_level_fail() {
        let c = DatConstraints {
            min_trust_level: Some(80),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_trust_level = Some(40);
        assert!(c.eval_trust_level(&cx).is_err());
    }

    #[test]
    fn test_trust_level_not_provided() {
        let c = DatConstraints {
            min_trust_level: Some(1),
            ..Default::default()
        };
        assert!(c.eval_trust_level(&ctx()).is_err());
    }

    // ── 5. Delegation depth ─────────────────────────────────────────────────

    #[test]
    fn test_delegation_depth_pass() {
        let c = DatConstraints {
            max_delegation_depth: Some(3),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.delegation_depth = 2;
        assert!(c.eval_delegation_depth(&cx).is_ok());
    }

    #[test]
    fn test_delegation_depth_at_limit() {
        let c = DatConstraints {
            max_delegation_depth: Some(3),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.delegation_depth = 3;
        assert!(c.eval_delegation_depth(&cx).is_ok());
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let c = DatConstraints {
            max_delegation_depth: Some(2),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.delegation_depth = 3;
        assert!(c.eval_delegation_depth(&cx).is_err());
    }

    #[test]
    fn test_delegation_depth_zero_no_redelegate() {
        let c = DatConstraints {
            max_delegation_depth: Some(0),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.delegation_depth = 0;
        assert!(c.eval_delegation_depth(&cx).is_ok());
        cx.delegation_depth = 1;
        assert!(c.eval_delegation_depth(&cx).is_err());
    }

    // ── 6. Geofence ─────────────────────────────────────────────────────────

    #[test]
    fn test_geofence_pass() {
        let c = DatConstraints {
            allowed_countries: Some(vec!["AU".into(), "NZ".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.country_code = Some("AU".into());
        assert!(c.eval_geofence(&cx).is_ok());
    }

    #[test]
    fn test_geofence_case_insensitive() {
        let c = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.country_code = Some("au".into());
        assert!(c.eval_geofence(&cx).is_ok());
    }

    #[test]
    fn test_geofence_fail() {
        let c = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.country_code = Some("US".into());
        assert!(c.eval_geofence(&cx).is_err());
    }

    #[test]
    fn test_geofence_no_country_code() {
        let c = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        assert!(c.eval_geofence(&ctx()).is_err());
    }

    // ── 7. Time windows ─────────────────────────────────────────────────────

    #[test]
    fn test_time_window_pass() {
        // Timestamp: 2024-01-15 14:30 UTC = Monday (dow=0), hour=14
        let ts = 1705327800_i64; // 2024-01-15T14:30:00Z
        let c = DatConstraints {
            time_windows: Some(vec![TimeWindow {
                start_hour: 9,
                end_hour: 17,
                days_of_week: None,
            }]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.current_timestamp = Some(ts);
        assert!(c.eval_time_windows(&cx).is_ok());
    }

    #[test]
    fn test_time_window_fail_outside_hours() {
        // 2024-01-15T02:00:00Z — hour=2
        let ts = 1705276800_i64;
        let c = DatConstraints {
            time_windows: Some(vec![TimeWindow {
                start_hour: 9,
                end_hour: 17,
                days_of_week: None,
            }]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.current_timestamp = Some(ts);
        assert!(c.eval_time_windows(&cx).is_err());
    }

    #[test]
    fn test_time_window_day_of_week_pass() {
        // 2024-01-15T14:30:00Z = Monday = dow 0
        let ts = 1705327800_i64;
        let c = DatConstraints {
            time_windows: Some(vec![TimeWindow {
                start_hour: 9,
                end_hour: 17,
                days_of_week: Some(vec![0, 1, 2, 3, 4]), // Mon-Fri
            }]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.current_timestamp = Some(ts);
        assert!(c.eval_time_windows(&cx).is_ok());
    }

    #[test]
    fn test_time_window_day_of_week_fail() {
        // 2024-01-20T14:00:00Z = Saturday = dow 5
        let ts = 1705759200_i64;
        let c = DatConstraints {
            time_windows: Some(vec![TimeWindow {
                start_hour: 9,
                end_hour: 17,
                days_of_week: Some(vec![0, 1, 2, 3, 4]), // Mon-Fri only
            }]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.current_timestamp = Some(ts);
        assert!(c.eval_time_windows(&cx).is_err());
    }

    #[test]
    fn test_time_window_wraparound() {
        // Window 22–02 (overnight). Test at 23:00 UTC.
        // 2024-01-15T23:00:00Z
        let ts = 1705363200_i64;
        let c = DatConstraints {
            time_windows: Some(vec![TimeWindow {
                start_hour: 22,
                end_hour: 2,
                days_of_week: None,
            }]),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.current_timestamp = Some(ts);
        assert!(c.eval_time_windows(&cx).is_ok());
    }

    // ── 8. Config attestation ───────────────────────────────────────────────

    #[test]
    fn test_config_attestation_pass() {
        let hash = "abc123def456".to_string();
        let c = DatConstraints {
            required_config_hash: Some(hash.clone()),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_config_hash = Some(hash.clone());
        assert!(c.eval_config_attestation(&cx, Some(&hash)).is_ok());
    }

    #[test]
    fn test_config_attestation_token_mismatch() {
        let c = DatConstraints {
            required_config_hash: Some("required_hash".into()),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_config_hash = Some("required_hash".into());
        // token carries a different hash
        assert!(c.eval_config_attestation(&cx, Some("other_hash")).is_err());
    }

    #[test]
    fn test_config_attestation_live_mismatch() {
        let c = DatConstraints {
            required_config_hash: Some("required_hash".into()),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_config_hash = Some("different_hash".into());
        assert!(c.eval_config_attestation(&cx, Some("required_hash")).is_err());
    }

    #[test]
    fn test_config_attestation_no_token_claim() {
        let c = DatConstraints {
            required_config_hash: Some("required_hash".into()),
            ..Default::default()
        };
        let mut cx = ctx();
        cx.agent_config_hash = Some("required_hash".into());
        assert!(c.eval_config_attestation(&cx, None).is_err());
    }

    #[test]
    fn test_config_attestation_no_constraint() {
        let c = DatConstraints::default();
        assert!(c.eval_config_attestation(&ctx(), None).is_ok());
    }

    // ── evaluate() composite ────────────────────────────────────────────────

    #[test]
    fn test_evaluate_all_pass() {
        let c = DatConstraints {
            rate_limit: Some(RateLimit { max_actions: 100, window_secs: 60 }),
            ip_allowlist: Some(vec!["10.0.0.0/8".into()]),
            ip_denylist: Some(vec!["10.0.0.0/24".into()]), // deny narrow subnet
            min_trust_level: Some(50),
            max_delegation_depth: Some(3),
            allowed_countries: Some(vec!["AU".into()]),
            // time_windows: None → no time restriction
            ..Default::default()
        };
        let mut cx = ctx();
        cx.actions_in_window = 5;
        cx.request_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1))); // /8 yes, /24 no
        cx.agent_trust_level = Some(75);
        cx.delegation_depth = 2;
        cx.country_code = Some("AU".into());
        assert!(c.evaluate(&cx).is_ok());
    }

    #[test]
    fn test_evaluate_stops_at_first_violation() {
        let c = DatConstraints {
            rate_limit: Some(RateLimit { max_actions: 1, window_secs: 60 }),
            min_trust_level: Some(99), // would also fail
            ..Default::default()
        };
        let mut cx = ctx();
        cx.actions_in_window = 5; // rate limit fails first
        cx.agent_trust_level = Some(10);
        let err = c.evaluate(&cx).unwrap_err().to_string();
        assert!(err.contains("rate limit exceeded"));
    }
}
