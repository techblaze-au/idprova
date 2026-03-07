//! Constraint evaluator trait and built-in evaluators.
//!
//! Each evaluator inspects a specific aspect of `DatConstraints` against the
//! `EvaluationContext` and returns a `PolicyDecision`. The `PolicyEvaluator`
//! (built in a later session) runs all evaluators and short-circuits on first denial.

use std::net::IpAddr;

use chrono::{Datelike, Timelike};
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
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        if let Some(max) = constraints.max_delegation_depth {
            if context.delegation_depth > max {
                return PolicyDecision::Deny(DenialReason::DelegationDepthExceeded {
                    max_depth: max,
                    actual_depth: context.delegation_depth,
                });
            }
        }
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "delegation_depth"
    }
}

/// Evaluates `geofence` country-code constraint.
///
/// Fail-closed: if geofence is set but no country in context, deny.
pub struct GeofenceEvaluator;

impl ConstraintEvaluator for GeofenceEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let allowed = match constraints.geofence {
            Some(ref countries) if !countries.is_empty() => countries,
            _ => return PolicyDecision::Allow, // No constraint — skip
        };

        match context.source_country {
            Some(ref country) => {
                let upper = country.to_uppercase();
                if allowed.iter().any(|c| c.to_uppercase() == upper) {
                    PolicyDecision::Allow
                } else {
                    PolicyDecision::Deny(DenialReason::GeofenceViolation {
                        country: country.clone(),
                        allowed: allowed.clone(),
                    })
                }
            }
            None => PolicyDecision::Deny(DenialReason::GeofenceViolation {
                country: "unknown".into(),
                allowed: allowed.clone(),
            }),
        }
    }

    fn name(&self) -> &'static str {
        "geofence"
    }
}

/// Evaluates `timeWindows` day/time restriction constraint.
///
/// If any time window matches the current timestamp, allow. If windows are set
/// and none match, deny. Handles overnight windows (start_hour > end_hour wraps midnight).
pub struct TimeWindowEvaluator;

impl TimeWindowEvaluator {
    /// Check if a given hour falls within a time window, handling overnight wrap.
    fn hour_in_range(hour: u8, start: u8, end: u8) -> bool {
        if start <= end {
            // Normal range: e.g., 9-17
            hour >= start && hour <= end
        } else {
            // Overnight wrap: e.g., 22-6 means 22,23,0,1,2,3,4,5,6
            hour >= start || hour <= end
        }
    }
}

impl ConstraintEvaluator for TimeWindowEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let windows = match constraints.time_windows {
            Some(ref w) if !w.is_empty() => w,
            _ => return PolicyDecision::Allow, // No constraint — skip
        };

        let ts = context.timestamp;
        let hour = ts.hour() as u8;
        // chrono: weekday().num_days_from_monday() gives 0=Mon..6=Sun
        let day = ts.weekday().num_days_from_monday() as u8;

        for window in windows {
            let day_matches = window.days.is_empty() || window.days.contains(&day);
            let hour_matches = Self::hour_in_range(hour, window.start_hour, window.end_hour);
            if day_matches && hour_matches {
                return PolicyDecision::Allow;
            }
        }

        PolicyDecision::Deny(DenialReason::OutsideTimeWindow)
    }

    fn name(&self) -> &'static str {
        "time_window"
    }
}

/// Evaluates `requiredConfigAttestation` constraint.
///
/// Fail-closed: if constraint is set but caller provides no attestation, deny.
pub struct ConfigAttestationEvaluator;

impl ConstraintEvaluator for ConfigAttestationEvaluator {
    fn evaluate(
        &self,
        constraints: &DatConstraints,
        context: &EvaluationContext,
    ) -> PolicyDecision {
        let required = match constraints.required_config_attestation {
            Some(ref hash) => hash,
            None => return PolicyDecision::Allow, // No constraint — skip
        };

        match context.caller_config_attestation {
            Some(ref actual) if actual == required => PolicyDecision::Allow,
            Some(ref actual) => PolicyDecision::Deny(DenialReason::ConfigAttestationMismatch {
                expected: required.clone(),
                actual: Some(actual.clone()),
            }),
            None => PolicyDecision::Deny(DenialReason::ConfigAttestationMismatch {
                expected: required.clone(),
                actual: None,
            }),
        }
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
    use chrono::Utc;

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

    // -----------------------------------------------------------------------
    // DelegationDepthEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_delegation_depth_within_limit() {
        let c = DatConstraints { max_delegation_depth: Some(5), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").delegation_depth(3).build();
        assert!(DelegationDepthEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_delegation_depth_at_limit() {
        let c = DatConstraints { max_delegation_depth: Some(5), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").delegation_depth(5).build();
        assert!(DelegationDepthEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_delegation_depth_exceeded() {
        let c = DatConstraints { max_delegation_depth: Some(3), ..Default::default() };
        let ctx = EvaluationContext::builder("scope").delegation_depth(4).build();
        let d = DelegationDepthEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::DelegationDepthExceeded { max_depth, actual_depth } => {
                assert_eq!(*max_depth, 3);
                assert_eq!(*actual_depth, 4);
            }
            other => panic!("expected DelegationDepthExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_delegation_depth_no_constraint() {
        let c = empty_constraints();
        let ctx = EvaluationContext::builder("scope").delegation_depth(100).build();
        assert!(DelegationDepthEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_delegation_depth_zero_max() {
        let c = DatConstraints { max_delegation_depth: Some(0), ..Default::default() };
        // Depth 0 = direct delegation, should be allowed
        let ctx0 = EvaluationContext::builder("scope").delegation_depth(0).build();
        assert!(DelegationDepthEvaluator.evaluate(&c, &ctx0).is_allowed());
        // Depth 1 = one re-delegation, should be denied
        let ctx1 = EvaluationContext::builder("scope").delegation_depth(1).build();
        assert!(DelegationDepthEvaluator.evaluate(&c, &ctx1).is_denied());
    }

    // -----------------------------------------------------------------------
    // GeofenceEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_geofence_country_in_allowed() {
        let c = DatConstraints {
            geofence: Some(vec!["AU".into(), "NZ".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope").source_country("AU").build();
        assert!(GeofenceEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_geofence_country_not_in_allowed() {
        let c = DatConstraints {
            geofence: Some(vec!["AU".into(), "NZ".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope").source_country("US").build();
        let d = GeofenceEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::GeofenceViolation { country, allowed } => {
                assert_eq!(country, "US");
                assert_eq!(allowed, &vec!["AU".to_string(), "NZ".to_string()]);
            }
            other => panic!("expected GeofenceViolation, got {other:?}"),
        }
    }

    #[test]
    fn test_geofence_case_insensitive() {
        let c = DatConstraints {
            geofence: Some(vec!["au".into()]),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope").source_country("AU").build();
        assert!(GeofenceEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_geofence_no_country_fail_closed() {
        let c = DatConstraints {
            geofence: Some(vec!["AU".into()]),
            ..Default::default()
        };
        let ctx = minimal_context(); // no source_country
        assert!(GeofenceEvaluator.evaluate(&c, &ctx).is_denied());
    }

    #[test]
    fn test_geofence_no_constraint() {
        let c = empty_constraints();
        let ctx = minimal_context();
        assert!(GeofenceEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    // -----------------------------------------------------------------------
    // TimeWindowEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_time_window_inside() {
        use chrono::TimeZone;
        let c = DatConstraints {
            time_windows: Some(vec![crate::dat::token::TimeWindow {
                days: vec![0, 1, 2, 3, 4], // Mon-Fri
                start_hour: 9,
                end_hour: 17,
            }]),
            ..Default::default()
        };
        // 2026-03-05 is a Thursday (day=3), set hour to 12 UTC
        let ts = Utc.with_ymd_and_hms(2026, 3, 5, 12, 0, 0).unwrap();
        let ctx = EvaluationContext::builder("scope").timestamp(ts).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_time_window_outside_hour() {
        use chrono::TimeZone;
        let c = DatConstraints {
            time_windows: Some(vec![crate::dat::token::TimeWindow {
                days: vec![0, 1, 2, 3, 4],
                start_hour: 9,
                end_hour: 17,
            }]),
            ..Default::default()
        };
        // Thursday at 20:00 UTC — outside 9-17
        let ts = Utc.with_ymd_and_hms(2026, 3, 5, 20, 0, 0).unwrap();
        let ctx = EvaluationContext::builder("scope").timestamp(ts).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_denied());
    }

    #[test]
    fn test_time_window_outside_day() {
        use chrono::TimeZone;
        let c = DatConstraints {
            time_windows: Some(vec![crate::dat::token::TimeWindow {
                days: vec![0, 1, 2, 3, 4], // Mon-Fri only
                start_hour: 9,
                end_hour: 17,
            }]),
            ..Default::default()
        };
        // 2026-03-07 is a Saturday (day=5) at 12:00 — right hour, wrong day
        let ts = Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap();
        let ctx = EvaluationContext::builder("scope").timestamp(ts).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_denied());
    }

    #[test]
    fn test_time_window_overnight_wrap() {
        use chrono::TimeZone;
        let c = DatConstraints {
            time_windows: Some(vec![crate::dat::token::TimeWindow {
                days: vec![], // any day
                start_hour: 22,
                end_hour: 6, // overnight: 22-23, 0-6
            }]),
            ..Default::default()
        };
        // 2:00 AM should be inside the overnight window
        let ts = Utc.with_ymd_and_hms(2026, 3, 5, 2, 0, 0).unwrap();
        let ctx = EvaluationContext::builder("scope").timestamp(ts).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_allowed());

        // 12:00 PM should be outside
        let ts_noon = Utc.with_ymd_and_hms(2026, 3, 5, 12, 0, 0).unwrap();
        let ctx_noon = EvaluationContext::builder("scope").timestamp(ts_noon).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx_noon).is_denied());
    }

    #[test]
    fn test_time_window_multiple_windows() {
        use chrono::TimeZone;
        let c = DatConstraints {
            time_windows: Some(vec![
                crate::dat::token::TimeWindow {
                    days: vec![0, 1, 2, 3, 4], // weekdays
                    start_hour: 9,
                    end_hour: 17,
                },
                crate::dat::token::TimeWindow {
                    days: vec![5, 6], // weekends
                    start_hour: 10,
                    end_hour: 14,
                },
            ]),
            ..Default::default()
        };
        // Saturday at 12:00 — should match weekend window
        let ts = Utc.with_ymd_and_hms(2026, 3, 7, 12, 0, 0).unwrap();
        let ctx = EvaluationContext::builder("scope").timestamp(ts).build();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_time_window_no_constraint() {
        let c = empty_constraints();
        let ctx = minimal_context();
        assert!(TimeWindowEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    // -----------------------------------------------------------------------
    // ConfigAttestationEvaluator tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_attestation_match() {
        let hash = "sha256:abc123def456";
        let c = DatConstraints {
            required_config_attestation: Some(hash.into()),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .caller_config_attestation(hash)
            .build();
        assert!(ConfigAttestationEvaluator.evaluate(&c, &ctx).is_allowed());
    }

    #[test]
    fn test_config_attestation_mismatch() {
        let c = DatConstraints {
            required_config_attestation: Some("sha256:expected".into()),
            ..Default::default()
        };
        let ctx = EvaluationContext::builder("scope")
            .caller_config_attestation("sha256:different")
            .build();
        let d = ConfigAttestationEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::ConfigAttestationMismatch { expected, actual } => {
                assert_eq!(expected, "sha256:expected");
                assert_eq!(actual, &Some("sha256:different".to_string()));
            }
            other => panic!("expected ConfigAttestationMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_config_attestation_missing_caller_hash() {
        let c = DatConstraints {
            required_config_attestation: Some("sha256:required".into()),
            ..Default::default()
        };
        let ctx = minimal_context(); // no caller_config_attestation
        let d = ConfigAttestationEvaluator.evaluate(&c, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::ConfigAttestationMismatch { actual, .. } => assert_eq!(actual, &None),
            other => panic!("expected ConfigAttestationMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_config_attestation_no_constraint() {
        let c = empty_constraints();
        let ctx = EvaluationContext::builder("scope")
            .caller_config_attestation("sha256:anything")
            .build();
        assert!(ConfigAttestationEvaluator.evaluate(&c, &ctx).is_allowed());
    }
}
