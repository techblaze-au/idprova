//! Policy evaluation engine for IDProva.
//!
//! This module provides the RBAC policy evaluation framework:
//!
//! - [`PolicyEvaluator`] — main engine combining scope, timing, and constraint checks
//! - [`EvaluationContext`] — transport-agnostic request context
//! - [`PolicyDecision`] / [`DenialReason`] — evaluation outcomes
//! - [`ConstraintEvaluator`] — trait for pluggable constraint evaluators
//! - 7 built-in evaluators: rate limit, IP, trust level, delegation depth,
//!   geofence, time window, config attestation

pub mod constraints;
pub mod context;
pub mod decision;
pub mod evaluator;
pub mod inheritance;
pub mod rate;

pub use constraints::{
    ConfigAttestationEvaluator, ConstraintEvaluator, DelegationDepthEvaluator,
    GeofenceEvaluator, IpConstraintEvaluator, RateLimitEvaluator, TimeWindowEvaluator,
    TrustLevelEvaluator, default_evaluators,
};
pub use context::{EvaluationContext, EvaluationContextBuilder};
pub use decision::{DenialReason, PolicyDecision};
pub use evaluator::PolicyEvaluator;
pub use inheritance::validate_constraint_inheritance;
pub use rate::RateTracker;
