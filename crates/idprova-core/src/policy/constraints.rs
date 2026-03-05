//! Constraint evaluator trait and built-in evaluators.
//!
//! Each evaluator inspects a specific aspect of `DatConstraints` against the
//! `EvaluationContext` and returns a `PolicyDecision`. The `PolicyEvaluator`
//! (built in a later session) runs all evaluators and short-circuits on first denial.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::dat::token::DatConstraints;
use crate::trust::level::TrustLevel;

use super::context::EvaluationContext;
use super::decision::{DenialReason, PolicyDecision};

/// Trait for evaluating a specific constraint type.
///
/// Implementations should return `PolicyDecision::Allow` if:
/// - The constraint is not present in `DatConstraints` (skip check)
/// - The context satisfies the constraint
///
/// Return `PolicyDecision::Deny(reason)` if the constraint is violated.
pub trait ConstraintEvaluator: Send + Sync {
    /// Evaluate the constraint against the given context.
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision;

    /// Human-readable name of this evaluator (for logging/debugging).
    fn name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// Built-in evaluator stubs (Phase 2 sessions A-4 through A-6 will implement)
// ---------------------------------------------------------------------------

/// Evaluates `maxCallsPerHour`, `maxCallsPerDay`, `maxConcurrent` constraints.
pub struct RateLimitEvaluator;

impl ConstraintEvaluator for RateLimitEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        if let Some(limit) = constraints.max_calls_per_hour {
            if context.actions_this_hour >= limit {
                return PolicyDecision::Deny(DenialReason::RateLimitExceeded {
                    limit_type: "hourly".into(),
                    limit,
                    current: context.actions_this_hour,
                });
            }
        }
        if let Some(limit) = constraints.max_calls_per_day {
            if context.actions_this_day >= limit {
                return PolicyDecision::Deny(DenialReason::RateLimitExceeded {
                    limit_type: "daily".into(),
                    limit,
                    current: context.actions_this_day,
                });
            }
        }
        if let Some(limit) = constraints.max_concurrent {
            if context.active_concurrent >= limit {
                return PolicyDecision::Deny(DenialReason::RateLimitExceeded {
                    limit_type: "concurrent".into(),
                    limit,
                    current: context.active_concurrent,
                });
            }
        }
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

/// Evaluates `allowedIPs` and `deniedIPs` constraints using CIDR matching.
pub struct IpConstraintEvaluator;

impl IpConstraintEvaluator {
    /// Parse a list of CIDR/IP strings into IpNet, skipping unparseable entries.
    fn parse_nets(specs: &[String]) -> Vec<IpNet> {
        specs
            .iter()
            .filter_map(|s| {
                s.parse::<IpNet>()
                    .or_else(|_| s.parse::<IpAddr>().map(IpNet::from))
                    .ok()
            })
            .collect()
    }
}

impl ConstraintEvaluator for IpConstraintEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let ip = match context.source_ip {
            Some(ip) => ip,
            None => return PolicyDecision::Allow, // No IP in context — skip check
        };

        // Deny list takes priority
        if let Some(ref denied) = constraints.denied_ips {
            let nets = Self::parse_nets(denied);
            if nets.iter().any(|net| net.contains(&ip)) {
                return PolicyDecision::Deny(DenialReason::IpBlocked {
                    ip: ip.to_string(),
                    reason: "IP in denied list".into(),
                });
            }
        }

        // Allowed list: if present, IP must match at least one entry
        if let Some(ref allowed) = constraints.allowed_ips {
            let nets = Self::parse_nets(allowed);
            if !nets.is_empty() && !nets.iter().any(|net| net.contains(&ip)) {
                return PolicyDecision::Deny(DenialReason::IpBlocked {
                    ip: ip.to_string(),
                    reason: "IP not in allowed list".into(),
                });
            }
        }

        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "ip_constraint"
    }
}

/// Evaluates `requiredTrustLevel` constraint.
pub struct TrustLevelEvaluator;

impl ConstraintEvaluator for TrustLevelEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let required_str = match constraints.required_trust_level {
            Some(ref s) => s,
            None => return PolicyDecision::Allow, // No constraint — skip
        };

        let required = match TrustLevel::from_str_repr(required_str) {
            Some(level) => level,
            None => return PolicyDecision::Allow, // Invalid string — skip gracefully
        };

        match context.caller_trust_level {
            Some(caller) => {
                if caller.meets_minimum(required) {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny(DenialReason::InsufficientTrustLevel {
                        required: required.as_str().into(),
                        actual: caller.as_str().into(),
                    })
                }
            }
            None => PolicyDecision::Deny(DenialReason::InsufficientTrustLevel {
                required: required.as_str().into(),
                actual: "none".into(),
            }),
        }
    }

    fn name(&self) -> &'static str {
        "trust_level"
    }
}

/// Evaluates `maxDelegationDepth` constraint.
pub struct DelegationDepthEvaluator;

impl ConstraintEvaluator for DelegationDepthEvaluator {
    fn evaluate(
        &self,
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-5): Check delegation_depth against max_delegation_depth
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "delegation_depth"
    }
}

/// Evaluates `geofence` country-code constraint.
pub struct GeofenceEvaluator;

impl ConstraintEvaluator for GeofenceEvaluator {
    fn evaluate(
        &self,
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-5): Check source_country against allowed country list
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "geofence"
    }
}

/// Evaluates `timeWindows` day/time restriction constraint.
pub struct TimeWindowEvaluator;

impl ConstraintEvaluator for TimeWindowEvaluator {
    fn evaluate(
        &self,
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-5): Parse time windows, check timestamp against allowed windows
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "time_window"
    }
}

/// Evaluates `requiredConfigAttestation` constraint.
pub struct ConfigAttestationEvaluator;

impl ConstraintEvaluator for ConfigAttestationEvaluator {
    fn evaluate(
        &self,
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-5): Compare caller_config_attestation against required hash
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "config_attestation"
    }
}

/// Returns all built-in constraint evaluators.
pub fn default_evaluators() -> Vec<Box<dyn ConstraintEvaluator>> {
    vec![
        Box::new(RateLimitEvaluator),
        Box::new(IpConstraintEvaluator),
        Box::new(TrustLevelEvaluator),
        Box::new(DelegationDepthEvaluator),
        Box::new(GeofenceEvaluator),
        Box::new(TimeWindowEvaluator),
        Box::new(ConfigAttestationEvaluator),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_constraints() -> DatConstraints {
        DatConstraints::default()
    }

    fn minimal_context() -> EvaluationContext {
        EvaluationContext::builder("mcp:tool:filesystem:read").build()
    }

    #[test]
    fn test_all_stubs_return_allow() {
        let constraints = empty_constraints();
        let ctx = minimal_context();

        let evaluators = default_evaluators();
        assert_eq!(evaluators.len(), 7, "expected 7 built-in evaluators");

        for evaluator in &evaluators {
            let decision = evaluator.evaluate(&constraints, &ctx);
            assert!(
                decision.is_allowed(),
                "evaluator '{}' should return Allow for empty constraints",
                evaluator.name()
            );
        }
    }

    #[test]
    fn test_evaluator_names_are_unique() {
        let evaluators = default_evaluators();
        let names: Vec<&str> = evaluators.iter().map(|e| e.name()).collect();
        let mut unique = names.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(names.len(), unique.len(), "evaluator names must be unique");
    }

    // -----------------------------------------------------------------------
    // RateLimitEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rate_limit_hourly_exceeded() {
        let c = DatConstraints { max_calls_per_hour: Some(100), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").actions_this_hour(100).build();
        let d = RateLimitEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::RateLimitExceeded { limit_type, limit, current } => {
                assert_eq!(limit_type, "hourly");
                assert_eq!(*limit, 100);
                assert_eq!(*current, 100);
            }
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_daily_exceeded() {
        let c = DatConstraints { max_calls_per_day: Some(500), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").actions_this_day(501).build();
        let d = RateLimitEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::RateLimitExceeded { limit_type, .. } => assert_eq!(limit_type, "daily"),
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_concurrent_exceeded() {
        let c = DatConstraints { max_concurrent: Some(3), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").active_concurrent(5).build();
        let d = RateLimitEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::RateLimitExceeded { limit_type, .. } => assert_eq!(limit_type, "concurrent"),
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_within_limits() {
        let c = DatConstraints {
            max_calls_per_hour: Some(100),
            max_calls_per_day: Some(500),
            max_concurrent: Some(5),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .actions_this_hour(50)
            .actions_this_day(200)
            .active_concurrent(2)
            .build();
        assert!(RateLimitEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_rate_limit_no_constraints() {
        let c = empty_constraints();
        let ctx = EvaluationContext::builder("scope")
            .actions_this_hour(9999)
            .actions_this_day(9999)
            .active_concurrent(9999)
            .build();
        assert!(RateLimitEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    // -----------------------------------------------------------------------
    // IpConstraintEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ip_allowed() {
        let c = DatConstraints {
            allowed_ips: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .source_ip("10.1.2.3".parse().unwrap())
            .build();
        assert!(IpConstraintEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_ip_denied() {
        let c = DatConstraints {
            denied_ips: Some(vec!["192.168.1.0/24".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .source_ip("192.168.1.50".parse().unwrap())
            .build();
        let d = IpConstraintEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::IpBlocked { ip, reason } => {
                assert_eq!(ip, "192.168.1.50");
                assert!(reason.contains("denied"));
            }
            other => panic!("expected IpBlocked, got {other:?}"),
        }
    }

    #[test]
    fn test_ip_deny_wins_over_allow() {
        let c = DatConstraints {
            allowed_ips: Some(vec!["10.0.0.0/8".into()]),
            denied_ips: Some(vec!["10.0.0.99/32".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .source_ip("10.0.0.99".parse().unwrap())
            .build();
        assert!(IpConstraintEvaluator.evaluate(&c, &ctx).is_denied());
    }

    #[test]
    fn test_ip_not_in_allowed() {
        let c = DatConstraints {
            allowed_ips: Some(vec!["10.0.0.0/8".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .source_ip("172.16.0.1".parse().unwrap())
            .build();
        let d = IpConstraintEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::IpBlocked { reason, .. } => assert!(reason.contains("not in allowed")),
            other => panic!("expected IpBlocked, got {other:?}"),
        }
    }

    #[test]
    fn test_ip_no_source_ip_skips() {
        let c = DatConstraints {
            allowed_ips: Some(vec!["10.0.0.0/8".into()]),
            denied_ips: Some(vec!["0.0.0.0/0".into()]),
            ..Default::default()
        };
        let ctx = minimal_context(); // no source_ip
        assert!(IpConstraintEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    // -----------------------------------------------------------------------
    // TrustLevelEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trust_level_sufficient() {
        let c = DatConstraints {
            required_trust_level: Some("L2".into()),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .caller_trust_level(TrustLevel::L3)
            .build();
        assert!(TrustLevelEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_trust_level_exact_match() {
        let c = DatConstraints {
            required_trust_level: Some("L2".into()),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .caller_trust_level(TrustLevel::L2)
            .build();
        assert!(TrustLevelEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_trust_level_insufficient() {
        let c = DatConstraints {
            required_trust_level: Some("L2".into()),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .caller_trust_level(TrustLevel::L0)
            .build();
        let d = TrustLevelEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::InsufficientTrustLevel { required, actual } => {
                assert_eq!(required, "L2");
                assert_eq!(actual, "L0");
            }
            other => panic!("expected InsufficientTrustLevel, got {other:?}"),
        }
    }

    #[test]
    fn test_trust_level_no_constraint_skips() {
        let c = empty_constraints(); // no required_trust_level
        let ctx = EvaluationContext::builder("scope")
            .caller_trust_level(TrustLevel::L0)
            .build();
        assert!(TrustLevelEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_trust_level_missing_caller_level_denied() {
        let c = DatConstraints {
            required_trust_level: Some("L1".into()),
            ..Default::default()
        };
        let ctx = minimal_context(); // no caller_trust_level
        let d = TrustLevelEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::InsufficientTrustLevel { actual, .. } => assert_eq!(actual, "none"),
            other => panic!("expected InsufficientTrustLevel, got {other:?}"),
        }
    }
}
