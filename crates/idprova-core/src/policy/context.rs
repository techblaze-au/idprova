//! Evaluation context for policy decisions.
//!
//! `EvaluationContext` is a transport-agnostic struct that captures all information
//! needed to evaluate constraints against a request. It's constructed by middleware
//! (MCP, A2A, HTTP) and passed to the `PolicyEvaluator`.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::trust::level::TrustLevel;

/// Transport-agnostic context for evaluating policy constraints.
///
/// Constructed by protocol-specific middleware and passed to constraint evaluators.
/// All fields except `requested_scope` and `timestamp` are optional — evaluators
/// that need a missing field will skip their check (fail-open for missing context,
/// fail-closed for present-but-invalid context).
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// The scope being requested (e.g., "mcp:tool:filesystem:read").
    pub requested_scope: String,
    /// When this request is being evaluated.
    pub timestamp: DateTime<Utc>,
    /// Source IP address of the caller (if available from transport).
    pub source_ip: Option<IpAddr>,
    /// ISO 3166-1 alpha-2 country code derived from source IP (if geo-lookup available).
    pub source_country: Option<String>,
    /// Trust level of the calling agent (from AID document).
    pub caller_trust_level: Option<TrustLevel>,
    /// Number of actions by this agent in the current hour.
    pub actions_this_hour: u64,
    /// Number of actions by this agent in the current day.
    pub actions_this_day: u64,
    /// Number of currently active concurrent operations by this agent.
    pub active_concurrent: u64,
    /// Current delegation depth in the chain.
    pub delegation_depth: u32,
    /// Config attestation hash reported by the caller.
    pub caller_config_attestation: Option<String>,
    /// Arbitrary extension data for custom evaluators.
    pub extensions: HashMap<String, serde_json::Value>,
}

impl EvaluationContext {
    /// Create a new builder for constructing an `EvaluationContext`.
    pub fn builder(requested_scope: impl Into<String>) -> EvaluationContextBuilder {
        EvaluationContextBuilder {
            requested_scope: requested_scope.into(),
            timestamp: Utc::now(),
            source_ip: None,
            source_country: None,
            caller_trust_level: None,
            actions_this_hour: 0,
            actions_this_day: 0,
            active_concurrent: 0,
            delegation_depth: 0,
            caller_config_attestation: None,
            extensions: HashMap::new(),
        }
    }
}

/// Builder for `EvaluationContext`.
pub struct EvaluationContextBuilder {
    requested_scope: String,
    timestamp: DateTime<Utc>,
    source_ip: Option<IpAddr>,
    source_country: Option<String>,
    caller_trust_level: Option<TrustLevel>,
    actions_this_hour: u64,
    actions_this_day: u64,
    active_concurrent: u64,
    delegation_depth: u32,
    caller_config_attestation: Option<String>,
    extensions: HashMap<String, serde_json::Value>,
}

impl EvaluationContextBuilder {
    pub fn timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    pub fn source_country(mut self, country: impl Into<String>) -> Self {
        self.source_country = Some(country.into());
        self
    }

    pub fn caller_trust_level(mut self, level: TrustLevel) -> Self {
        self.caller_trust_level = Some(level);
        self
    }

    pub fn actions_this_hour(mut self, count: u64) -> Self {
        self.actions_this_hour = count;
        self
    }

    pub fn actions_this_day(mut self, count: u64) -> Self {
        self.actions_this_day = count;
        self
    }

    pub fn active_concurrent(mut self, count: u64) -> Self {
        self.active_concurrent = count;
        self
    }

    pub fn delegation_depth(mut self, depth: u32) -> Self {
        self.delegation_depth = depth;
        self
    }

    pub fn caller_config_attestation(mut self, hash: impl Into<String>) -> Self {
        self.caller_config_attestation = Some(hash.into());
        self
    }

    pub fn extension(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    pub fn build(self) -> EvaluationContext {
        EvaluationContext {
            requested_scope: self.requested_scope,
            timestamp: self.timestamp,
            source_ip: self.source_ip,
            source_country: self.source_country,
            caller_trust_level: self.caller_trust_level,
            actions_this_hour: self.actions_this_hour,
            actions_this_day: self.actions_this_day,
            active_concurrent: self.active_concurrent,
            delegation_depth: self.delegation_depth,
            caller_config_attestation: self.caller_config_attestation,
            extensions: self.extensions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read").build();
        assert_eq!(ctx.requested_scope, "mcp:tool:filesystem:read");
        assert!(ctx.source_ip.is_none());
        assert!(ctx.source_country.is_none());
        assert!(ctx.caller_trust_level.is_none());
        assert_eq!(ctx.actions_this_hour, 0);
        assert_eq!(ctx.actions_this_day, 0);
        assert_eq!(ctx.active_concurrent, 0);
        assert_eq!(ctx.delegation_depth, 0);
        assert!(ctx.caller_config_attestation.is_none());
        assert!(ctx.extensions.is_empty());
    }

    #[test]
    fn test_builder_full() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let ctx = EvaluationContext::builder("mcp:tool:*:*")
            .source_ip(ip)
            .source_country("AU")
            .caller_trust_level(TrustLevel::L2)
            .actions_this_hour(42)
            .actions_this_day(100)
            .active_concurrent(3)
            .delegation_depth(2)
            .caller_config_attestation("sha256:abc123")
            .extension("custom_field", serde_json::json!("value"))
            .build();

        assert_eq!(ctx.source_ip, Some(ip));
        assert_eq!(ctx.source_country.as_deref(), Some("AU"));
        assert_eq!(ctx.caller_trust_level, Some(TrustLevel::L2));
        assert_eq!(ctx.actions_this_hour, 42);
        assert_eq!(ctx.actions_this_day, 100);
        assert_eq!(ctx.active_concurrent, 3);
        assert_eq!(ctx.delegation_depth, 2);
        assert_eq!(
            ctx.caller_config_attestation.as_deref(),
            Some("sha256:abc123")
        );
        assert_eq!(
            ctx.extensions.get("custom_field"),
            Some(&serde_json::json!("value"))
        );
    }
}
