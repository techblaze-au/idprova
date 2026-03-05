//! Policy evaluation engine.
//!
//! `PolicyEvaluator` is the main entry point for evaluating whether a request
//! should be allowed under a given DAT. It runs scope checks, timing validation,
//! and all constraint evaluators in sequence, short-circuiting on the first denial.

use chrono::Utc;

use crate::dat::scope::{Scope, ScopeSet};
use crate::dat::token::Dat;

use super::constraints::{default_evaluators, ConstraintEvaluator};
use super::context::EvaluationContext;
use super::decision::{DenialReason, PolicyDecision};

/// Main policy evaluation engine.
///
/// Combines scope checking, timing validation, and pluggable constraint evaluators
/// into a single `evaluate()` call. Short-circuits on first denial.
pub struct PolicyEvaluator {
    evaluators: Vec<Box<dyn ConstraintEvaluator>>,
}

impl PolicyEvaluator {
    /// Create a new `PolicyEvaluator` with all default built-in evaluators.
    pub fn new() -> Self {
        Self {
            evaluators: default_evaluators(),
        }
    }

    /// Create a `PolicyEvaluator` with a custom set of evaluators.
    pub fn with_evaluators(evaluators: Vec<Box<dyn ConstraintEvaluator>>) -> Self {
        Self { evaluators }
    }

    /// Evaluate whether the request described by `context` is permitted under `dat`.
    ///
    /// Checks in order (short-circuits on first denial):
    /// 1. **Timing** — is the DAT currently valid (iat <= now <= exp, nbf <= now)?
    /// 2. **Scope** — does the DAT's scope set cover the requested scope?
    /// 3. **Constraints** — do all constraint evaluators allow the request?
    pub fn evaluate(&self, dat: &Dat, context: &EvaluationContext) -> PolicyDecision {
        // 1. Timing validation
        let now = Utc::now().timestamp();
        if now > dat.claims.exp {
            return PolicyDecision::Deny(DenialReason::Expired);
        }
        if now < dat.claims.nbf {
            return PolicyDecision::Deny(DenialReason::NotYetValid);
        }

        // 2. Scope check
        let scope_set = match ScopeSet::parse(&dat.claims.scope) {
            Ok(ss) => ss,
            Err(_) => {
                return PolicyDecision::Deny(DenialReason::ScopeNotCovered);
            }
        };
        let requested = match Scope::parse(&context.requested_scope) {
            Ok(s) => s,
            Err(_) => {
                return PolicyDecision::Deny(DenialReason::ScopeNotCovered);
            }
        };
        if !scope_set.permits(&requested) {
            return PolicyDecision::Deny(DenialReason::ScopeNotCovered);
        }

        // 3. Constraint evaluators
        if let Some(ref constraints) = dat.claims.constraints {
            for evaluator in &self.evaluators {
                let decision = evaluator.evaluate(constraints, context);
                if decision.is_denied() {
                    return decision;
                }
            }
        }

        PolicyDecision::Allow
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::KeyPair;
    use crate::dat::token::DatConstraints;
    use crate::trust::level::TrustLevel;
    use chrono::{Duration, Utc};

    fn issue_test_dat(scope: Vec<String>, constraints: Option<DatConstraints>) -> Dat {
        let issuer_kp = KeyPair::generate();
        let subject_kp = KeyPair::generate();
        let issuer_did = format!("did:idprova:test:{}", hex::encode(&issuer_kp.public_key_bytes()[..8]));
        let subject_did = format!("did:idprova:test:{}", hex::encode(&subject_kp.public_key_bytes()[..8]));
        let expires = Utc::now() + Duration::hours(24);

        Dat::issue(
            &issuer_did,
            &subject_did,
            scope,
            expires,
            constraints,
            None,
            &issuer_kp,
        )
        .expect("failed to issue test DAT")
    }

    #[test]
    fn test_policy_evaluator_allow() {
        let dat = issue_test_dat(vec!["mcp:tool:filesystem:read".into()], None);
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read").build();
        let pe = PolicyEvaluator::new();
        assert!(pe.evaluate(&dat, &ctx).is_allowed());
    }

    #[test]
    fn test_policy_evaluator_deny_scope() {
        let dat = issue_test_dat(vec!["mcp:tool:filesystem:read".into()], None);
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:write").build();
        let pe = PolicyEvaluator::new();
        let d = pe.evaluate(&dat, &ctx);
        assert!(d.is_denied());
        assert_eq!(d.denial_reason(), Some(&DenialReason::ScopeNotCovered));
    }

    #[test]
    fn test_policy_evaluator_deny_expired() {
        let issuer_kp = KeyPair::generate();
        let subject_kp = KeyPair::generate();
        let issuer_did = format!("did:idprova:test:{}", hex::encode(&issuer_kp.public_key_bytes()[..8]));
        let subject_did = format!("did:idprova:test:{}", hex::encode(&subject_kp.public_key_bytes()[..8]));
        // Already expired
        let expires = Utc::now() - Duration::hours(1);

        let dat = Dat::issue(
            &issuer_did,
            &subject_did,
            vec!["mcp:tool:filesystem:read".into()],
            expires,
            None,
            None,
            &issuer_kp,
        )
        .expect("failed to issue test DAT");

        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read").build();
        let pe = PolicyEvaluator::new();
        let d = pe.evaluate(&dat, &ctx);
        assert!(d.is_denied());
        assert_eq!(d.denial_reason(), Some(&DenialReason::Expired));
    }

    #[test]
    fn test_policy_evaluator_deny_constraint() {
        let constraints = DatConstraints {
            max_calls_per_hour: Some(10),
            ..Default::default()
        };
        let dat = issue_test_dat(
            vec!["mcp:tool:filesystem:read".into()],
            Some(constraints),
        );
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
            .actions_this_hour(10)
            .build();
        let pe = PolicyEvaluator::new();
        let d = pe.evaluate(&dat, &ctx);
        assert!(d.is_denied());
        match d.denial_reason().unwrap() {
            DenialReason::RateLimitExceeded { limit_type, .. } => assert_eq!(limit_type, "hourly"),
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_policy_evaluator_wildcard_scope() {
        let dat = issue_test_dat(vec!["mcp:*:*:*".into()], None);
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read").build();
        let pe = PolicyEvaluator::new();
        assert!(pe.evaluate(&dat, &ctx).is_allowed());
    }

    #[test]
    fn test_policy_evaluator_short_circuit() {
        // Both rate limit and trust level should fail, but we should get rate limit
        // (first evaluator) since it short-circuits.
        let constraints = DatConstraints {
            max_calls_per_hour: Some(5),
            required_trust_level: Some("L3".into()),
            ..Default::default()
        };
        let dat = issue_test_dat(
            vec!["mcp:tool:filesystem:read".into()],
            Some(constraints),
        );
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
            .actions_this_hour(10)
            .caller_trust_level(TrustLevel::L0)
            .build();
        let pe = PolicyEvaluator::new();
        let d = pe.evaluate(&dat, &ctx);
        assert!(d.is_denied());
        // Rate limit evaluator runs first in default_evaluators()
        match d.denial_reason().unwrap() {
            DenialReason::RateLimitExceeded { .. } => {} // expected
            other => panic!("expected RateLimitExceeded (short-circuit), got {other:?}"),
        }
    }

    #[test]
    fn test_policy_evaluator_empty_evaluators() {
        // With no evaluators, only timing + scope checks run
        let dat = issue_test_dat(
            vec!["mcp:tool:filesystem:read".into()],
            Some(DatConstraints {
                max_calls_per_hour: Some(1), // would fail with evaluators
                ..Default::default()
            }),
        );
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
            .actions_this_hour(999)
            .build();
        let pe = PolicyEvaluator::with_evaluators(vec![]); // no evaluators
        assert!(pe.evaluate(&dat, &ctx).is_allowed());
    }

    #[test]
    fn test_policy_evaluator_multiple_constraints_all_pass() {
        let constraints = DatConstraints {
            max_calls_per_hour: Some(100),
            required_trust_level: Some("L1".into()),
            geofence: Some(vec!["AU".into()]),
            max_delegation_depth: Some(5),
            ..Default::default()
        };
        let dat = issue_test_dat(
            vec!["mcp:tool:filesystem:read".into()],
            Some(constraints),
        );
        let ctx = EvaluationContext::builder("mcp:tool:filesystem:read")
            .actions_this_hour(50)
            .caller_trust_level(TrustLevel::L2)
            .source_country("AU")
            .delegation_depth(2)
            .build();
        let pe = PolicyEvaluator::new();
        assert!(pe.evaluate(&dat, &ctx).is_allowed());
    }
}
