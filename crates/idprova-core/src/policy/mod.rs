//! Policy evaluation engine for IDProva.
//!
//! This module provides the RBAC policy evaluation framework:
//!
//! - [`EvaluationContext`] — transport-agnostic request context
//! - [`PolicyDecision`] / [`DenialReason`] — evaluation outcomes
//! - [`ConstraintEvaluator`] — trait for pluggable constraint evaluators
//! - 7 built-in evaluators: rate limit, IP, trust level, delegation depth,
//!   geofence, time window, config attestation
//!
//! Future sessions will add:
//! - `evaluator.rs` — `PolicyEvaluator` (main engine combining all evaluators)
//! - `rate.rs` — `RateTracker` (in-memory action counting)
//! - `revocation.rs` — `RevocationChecker` trait and types
//! - `inheritance.rs` — Constraint inheritance validation

pub mod constraints;
pub mod context;
pub mod decision;

pub use constraints::{
    ConfigAttestationEvaluator, ConstraintEvaluator, DelegationDepthEvaluator,
    GeofenceEvaluator, IpConstraintEvaluator, RateLimitEvaluator, TimeWindowEvaluator,
    TrustLevelEvaluator, default_evaluators,
};
pub use context::{EvaluationContext, EvaluationContextBuilder};
pub use decision::{DenialReason, PolicyDecision};
