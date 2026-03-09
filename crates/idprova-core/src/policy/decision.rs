//! Policy decision types.
//!
//! `PolicyDecision` is the output of constraint evaluation — either `Allow` or `Deny`
//! with a specific reason. `DenialReason` captures all possible constraint violations.

use std::fmt;

/// The result of evaluating a policy constraint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The request is permitted.
    Allow,
    /// The request is denied with a specific reason.
    Deny(DenialReason),
}

impl PolicyDecision {
    /// Returns `true` if this is an `Allow` decision.
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    /// Returns `true` if this is a `Deny` decision.
    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Deny(_))
    }

    /// Returns the denial reason if denied, `None` if allowed.
    pub fn denial_reason(&self) -> Option<&DenialReason> {
        match self {
            PolicyDecision::Deny(reason) => Some(reason),
            PolicyDecision::Allow => None,
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyDecision::Allow => write!(f, "ALLOW"),
            PolicyDecision::Deny(reason) => write!(f, "DENY: {reason}"),
        }
    }
}

/// Specific reasons why a policy evaluation denied a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    /// DAT has expired (past `exp` timestamp).
    Expired,
    /// DAT is not yet valid (before `nbf` timestamp).
    NotYetValid,
    /// The requested scope is not covered by the DAT's granted scopes.
    ScopeNotCovered,
    /// The DAT or a token in its delegation chain has been revoked.
    Revoked,
    /// Rate limit exceeded (hourly, daily, or concurrent).
    RateLimitExceeded {
        limit_type: String,
        limit: u64,
        current: u64,
    },
    /// Source IP is not in the allowed list or is in the denied list.
    IpBlocked { ip: String, reason: String },
    /// Caller's trust level does not meet the minimum requirement.
    InsufficientTrustLevel { required: String, actual: String },
    /// Delegation chain exceeds maximum allowed depth.
    DelegationDepthExceeded { max_depth: u32, actual_depth: u32 },
    /// Source country is not in the allowed geofence list.
    GeofenceViolation {
        country: String,
        allowed: Vec<String>,
    },
    /// Request is outside allowed time windows.
    OutsideTimeWindow,
    /// Caller's config attestation hash does not match the required value.
    ConfigAttestationMismatch {
        expected: String,
        actual: Option<String>,
    },
    /// Delegation chain validation failed (scope narrowing, issuer linkage, etc.).
    ChainValidationFailed(String),
    /// DAT signature is invalid.
    SignatureInvalid,
    /// Custom denial reason for extension evaluators.
    Custom(String),
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "DAT has expired"),
            Self::NotYetValid => write!(f, "DAT is not yet valid"),
            Self::ScopeNotCovered => write!(f, "requested scope not covered by DAT"),
            Self::Revoked => write!(f, "DAT or delegation chain member has been revoked"),
            Self::RateLimitExceeded {
                limit_type,
                limit,
                current,
            } => write!(
                f,
                "rate limit exceeded: {limit_type} limit {limit}, current {current}"
            ),
            Self::IpBlocked { ip, reason } => write!(f, "IP {ip} blocked: {reason}"),
            Self::InsufficientTrustLevel { required, actual } => {
                write!(f, "trust level {actual} does not meet required {required}")
            }
            Self::DelegationDepthExceeded {
                max_depth,
                actual_depth,
            } => write!(
                f,
                "delegation depth {actual_depth} exceeds maximum {max_depth}"
            ),
            Self::GeofenceViolation { country, allowed } => {
                write!(f, "country {country} not in allowed list: {allowed:?}")
            }
            Self::OutsideTimeWindow => write!(f, "request outside allowed time windows"),
            Self::ConfigAttestationMismatch { expected, actual } => write!(
                f,
                "config attestation mismatch: expected {expected}, got {actual:?}"
            ),
            Self::ChainValidationFailed(msg) => write!(f, "chain validation failed: {msg}"),
            Self::SignatureInvalid => write!(f, "DAT signature is invalid"),
            Self::Custom(msg) => write!(f, "{msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_allow() {
        let d = PolicyDecision::Allow;
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert!(d.denial_reason().is_none());
        assert_eq!(d.to_string(), "ALLOW");
    }

    #[test]
    fn test_policy_decision_deny() {
        let d = PolicyDecision::Deny(DenialReason::Expired);
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert_eq!(d.denial_reason(), Some(&DenialReason::Expired));
        assert_eq!(d.to_string(), "DENY: DAT has expired");
    }

    #[test]
    fn test_denial_reason_display() {
        assert_eq!(
            DenialReason::RateLimitExceeded {
                limit_type: "hourly".into(),
                limit: 100,
                current: 101,
            }
            .to_string(),
            "rate limit exceeded: hourly limit 100, current 101"
        );

        assert_eq!(
            DenialReason::InsufficientTrustLevel {
                required: "L2".into(),
                actual: "L0".into(),
            }
            .to_string(),
            "trust level L0 does not meet required L2"
        );

        assert_eq!(
            DenialReason::DelegationDepthExceeded {
                max_depth: 5,
                actual_depth: 7,
            }
            .to_string(),
            "delegation depth 7 exceeds maximum 5"
        );
    }
}
