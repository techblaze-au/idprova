//! Constraint evaluator trait and built-in evaluators.
//!
//! Each evaluator inspects a specific aspect of `DatConstraints` against the
//! `EvaluationContext` and returns a `PolicyDecision`. The `PolicyEvaluator`
//! (built in a later session) runs all evaluators and short-circuits on first denial.

use crate::dat::token::DatConstraints;

use super::context::EvaluationContext;
use super::decision::PolicyDecision;

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
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-4): Check rate counters from context against constraint limits
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "rate_limit"
    }
}

/// Evaluates `allowedIPs` and `deniedIPs` constraints using CIDR matching.
pub struct IpConstraintEvaluator;

impl ConstraintEvaluator for IpConstraintEvaluator {
    fn evaluate(
        &self,
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-4): Parse CIDR networks via ipnet, check source_ip
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
        _constraints: &DatConstraints,
        _context: &EvaluationContext,
    ) -> PolicyDecision {
        // TODO(A-4): Parse required trust level, compare with caller_trust_level
        PolicyDecision::Allow
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
}
