//! Constraint inheritance validation for delegation chains.
//!
//! When a DAT delegates to a child, the child's constraints must be
//! **at least as restrictive** as the parent's. This module validates
//! that invariant for all constraint fields.

use crate::dat::constraints::DatConstraints;
use crate::{IdprovaError, Result};

/// Validate that child constraints are at least as restrictive as parent constraints.
///
/// Rules:
/// - Numeric limits: child <= parent (or child present when parent absent is fine)
/// - Trust level: child >= parent (higher minimum = more restrictive)
/// - IP lists: child allowed_ips ⊆ parent allowed_ips (narrower allowed set)
/// - Geofence: child ⊆ parent (fewer countries)
/// - Time windows: child ⊆ parent (fewer or narrower windows)
/// - Config attestation: child must match parent if parent is set
///
/// Returns `Ok(())` if inheritance is valid, or an error describing the violation.
pub fn validate_constraint_inheritance(
    parent: &DatConstraints,
    child: &DatConstraints,
) -> Result<()> {
    // Rate limit: child max_actions must be <= parent max_actions
    let parent_rl = parent.rate_limit.as_ref().map(|r| r.max_actions);
    let child_rl = child.rate_limit.as_ref().map(|r| r.max_actions);
    validate_numeric_le("rateLimit.maxActions", parent_rl, child_rl)?;

    // Delegation depth: child must be <= parent
    validate_numeric_le_u32(
        "maxDelegationDepth",
        parent.max_delegation_depth,
        child.max_delegation_depth,
    )?;

    // Trust level: child min_trust_level must be >= parent (more restrictive = higher ordinal)
    validate_trust_level(parent, child)?;

    // Geofence: child countries must be subset of parent countries
    validate_set_subset("allowedCountries", &parent.allowed_countries, &child.allowed_countries)?;

    // Config attestation: if parent requires it, child must require the same hash
    if let Some(ref parent_hash) = parent.required_config_hash {
        match child.required_config_hash {
            Some(ref child_hash) if child_hash == parent_hash => {} // OK
            Some(ref child_hash) => {
                return Err(IdprovaError::ConstraintViolated(format!(
                    "child config hash '{child_hash}' differs from parent '{parent_hash}'"
                )));
            }
            None => {
                return Err(IdprovaError::ConstraintViolated(
                    "child must require config hash when parent does".into(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_numeric_le(name: &str, parent: Option<u64>, child: Option<u64>) -> Result<()> {
    if let Some(p) = parent {
        match child {
            Some(c) if c <= p => Ok(()),
            Some(c) => Err(IdprovaError::ConstraintViolated(format!(
                "child {name} ({c}) exceeds parent ({p})"
            ))),
            // Child has no limit but parent does — child is less restrictive
            None => Err(IdprovaError::ConstraintViolated(format!(
                "child must set {name} when parent limits to {p}"
            ))),
        }
    } else {
        Ok(()) // Parent has no limit, child can do anything
    }
}

fn validate_numeric_le_u32(name: &str, parent: Option<u32>, child: Option<u32>) -> Result<()> {
    if let Some(p) = parent {
        match child {
            Some(c) if c <= p => Ok(()),
            Some(c) => Err(IdprovaError::ConstraintViolated(format!(
                "child {name} ({c}) exceeds parent ({p})"
            ))),
            None => Err(IdprovaError::ConstraintViolated(format!(
                "child must set {name} when parent limits to {p}"
            ))),
        }
    } else {
        Ok(())
    }
}

fn validate_trust_level(parent: &DatConstraints, child: &DatConstraints) -> Result<()> {
    if let Some(parent_min) = parent.min_trust_level {
        match child.min_trust_level {
            Some(child_min) if child_min >= parent_min => Ok(()),
            Some(child_min) => Err(IdprovaError::ConstraintViolated(format!(
                "child min_trust_level ({child_min}) is less restrictive than parent ({parent_min})"
            ))),
            None => Err(IdprovaError::ConstraintViolated(
                "child must set min_trust_level when parent does".into(),
            )),
        }
    } else {
        Ok(())
    }
}

fn validate_set_subset(
    name: &str,
    parent: &Option<Vec<String>>,
    child: &Option<Vec<String>>,
) -> Result<()> {
    if let Some(ref parent_set) = parent {
        match child {
            Some(ref child_set) => {
                let parent_upper: Vec<String> = parent_set.iter().map(|s| s.to_uppercase()).collect();
                for c in child_set {
                    if !parent_upper.contains(&c.to_uppercase()) {
                        return Err(IdprovaError::ConstraintViolated(format!(
                            "child {name} contains '{c}' which is not in parent set"
                        )));
                    }
                }
                Ok(())
            }
            // Child has no restriction but parent does — child is wider
            None => Err(IdprovaError::ConstraintViolated(format!(
                "child must set {name} when parent restricts it"
            ))),
        }
    } else {
        Ok(()) // Parent has no restriction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dat::constraints::RateLimit;

    fn empty() -> DatConstraints {
        DatConstraints::default()
    }

    fn rl(max: u64) -> Option<RateLimit> {
        Some(RateLimit { max_actions: max, window_secs: 3600 })
    }

    #[test]
    fn test_both_empty_is_valid() {
        assert!(validate_constraint_inheritance(&empty(), &empty()).is_ok());
    }

    #[test]
    fn test_child_narrower_rate_limit() {
        let parent = DatConstraints { rate_limit: rl(100), ..Default::default() };
        let child = DatConstraints { rate_limit: rl(50), ..Default::default() };
        assert!(validate_constraint_inheritance(&parent, &child).is_ok());
    }

    #[test]
    fn test_child_wider_rate_limit_rejected() {
        let parent = DatConstraints { rate_limit: rl(100), ..Default::default() };
        let child = DatConstraints { rate_limit: rl(200), ..Default::default() };
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_child_missing_rate_limit_rejected() {
        let parent = DatConstraints { rate_limit: rl(100), ..Default::default() };
        let child = empty();
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_child_narrower_delegation_depth() {
        let parent = DatConstraints { max_delegation_depth: Some(5), ..Default::default() };
        let child = DatConstraints { max_delegation_depth: Some(3), ..Default::default() };
        assert!(validate_constraint_inheritance(&parent, &child).is_ok());
    }

    #[test]
    fn test_child_wider_delegation_depth_rejected() {
        let parent = DatConstraints { max_delegation_depth: Some(3), ..Default::default() };
        let child = DatConstraints { max_delegation_depth: Some(5), ..Default::default() };
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_child_higher_trust_level_ok() {
        let parent = DatConstraints { min_trust_level: Some(1), ..Default::default() };
        let child = DatConstraints { min_trust_level: Some(3), ..Default::default() }; // more restrictive
        assert!(validate_constraint_inheritance(&parent, &child).is_ok());
    }

    #[test]
    fn test_child_lower_trust_level_rejected() {
        let parent = DatConstraints { min_trust_level: Some(2), ..Default::default() };
        let child = DatConstraints { min_trust_level: Some(0), ..Default::default() }; // less restrictive
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_child_missing_trust_level_rejected() {
        let parent = DatConstraints { min_trust_level: Some(1), ..Default::default() };
        let child = empty();
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_geofence_subset_ok() {
        let parent = DatConstraints {
            allowed_countries: Some(vec!["AU".into(), "NZ".into(), "US".into()]),
            ..Default::default()
        };
        let child = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        assert!(validate_constraint_inheritance(&parent, &child).is_ok());
    }

    #[test]
    fn test_geofence_superset_rejected() {
        let parent = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        let child = DatConstraints {
            allowed_countries: Some(vec!["AU".into(), "US".into()]),
            ..Default::default()
        };
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_geofence_missing_child_rejected() {
        let parent = DatConstraints {
            allowed_countries: Some(vec!["AU".into()]),
            ..Default::default()
        };
        let child = empty();
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_config_attestation_same_ok() {
        let parent = DatConstraints {
            required_config_hash: Some("sha256:abc".into()),
            ..Default::default()
        };
        let child = DatConstraints {
            required_config_hash: Some("sha256:abc".into()),
            ..Default::default()
        };
        assert!(validate_constraint_inheritance(&parent, &child).is_ok());
    }

    #[test]
    fn test_config_attestation_different_rejected() {
        let parent = DatConstraints {
            required_config_hash: Some("sha256:abc".into()),
            ..Default::default()
        };
        let child = DatConstraints {
            required_config_hash: Some("sha256:xyz".into()),
            ..Default::default()
        };
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_config_attestation_missing_child_rejected() {
        let parent = DatConstraints {
            required_config_hash: Some("sha256:abc".into()),
            ..Default::default()
        };
        let child = empty();
        assert!(validate_constraint_inheritance(&parent, &child).is_err());
    }

    #[test]
    fn test_parent_unrestricted_child_anything_ok() {
        let child = DatConstraints {
            rate_limit: rl(10),
            allowed_countries: Some(vec!["AU".into()]),
            min_trust_level: Some(3),
            ..Default::default()
        };
        assert!(validate_constraint_inheritance(&empty(), &child).is_ok());
    }
}
