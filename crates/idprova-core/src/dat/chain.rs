//! Delegation chain validation for multi-level delegation (v0.2+).
//!
//! In v0.1, only single-level delegation is supported (human → agent).
//! This module provides the foundation for future chain validation.

use super::scope::ScopeSet;
use super::token::Dat;
use crate::{IdprovaError, Result};

/// Configuration for delegation chain validation.
///
/// # SR-8: Maximum delegation depth
///
/// Without a depth limit, an attacker can construct arbitrarily deep delegation
/// chains, creating denial-of-service via quadratic chain validation cost and
/// enabling privilege confusion through deeply nested delegation.
#[derive(Debug, Clone)]
pub struct ChainValidationConfig {
    /// Maximum number of delegation hops allowed (default: 5, hard max: 10).
    ///
    /// A depth of 1 means the root (human) issuer → agent (no re-delegation).
    /// A depth of 2 means human → orchestrator → tool-agent.
    /// Values above 10 are clamped to 10.
    pub max_depth: u32,
}

impl Default for ChainValidationConfig {
    fn default() -> Self {
        Self { max_depth: 5 }
    }
}

impl ChainValidationConfig {
    /// The hard maximum depth — cannot be overridden.
    pub const HARD_MAX_DEPTH: u32 = 10;

    /// Create a config with a specific depth limit (clamped to `HARD_MAX_DEPTH`).
    pub fn with_max_depth(max_depth: u32) -> Self {
        Self {
            max_depth: max_depth.min(Self::HARD_MAX_DEPTH),
        }
    }
}

/// Validates that a delegation chain is valid using default configuration.
///
/// For production use, prefer `validate_chain_with_config()` to set explicit depth limits.
pub fn validate_chain(chain: &[Dat]) -> Result<()> {
    validate_chain_with_config(chain, &ChainValidationConfig::default())
}

/// Validates that a delegation chain is valid with explicit configuration.
///
/// Checks:
/// - Chain depth does not exceed `config.max_depth` (SR-8)
/// - Each DAT was issued by the subject of the previous DAT
/// - Scopes narrow (or stay equal) at each level
/// - No DAT in the chain expires after its parent
/// - Each DAT in the chain is temporally valid
pub fn validate_chain_with_config(chain: &[Dat], config: &ChainValidationConfig) -> Result<()> {
    if chain.is_empty() {
        return Ok(());
    }

    // SR-8: Enforce maximum delegation depth
    let depth = chain.len() as u32;
    let effective_max = config.max_depth.min(ChainValidationConfig::HARD_MAX_DEPTH);
    if depth > effective_max {
        return Err(IdprovaError::InvalidDelegationChain(format!(
            "delegation chain depth {} exceeds maximum allowed depth {}",
            depth, effective_max
        )));
    }

    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let child = &chain[i];

        // The child must have been issued by the parent's subject
        if child.claims.iss != parent.claims.sub {
            return Err(IdprovaError::InvalidDelegationChain(format!(
                "DAT {} was issued by {} but expected {}",
                child.claims.jti, child.claims.iss, parent.claims.sub
            )));
        }

        // Child scopes must be a subset of parent scopes
        let parent_scopes = ScopeSet::parse(&parent.claims.scope)?;
        let child_scopes = ScopeSet::parse(&child.claims.scope)?;
        if !child_scopes.is_subset_of(&parent_scopes) {
            return Err(IdprovaError::InvalidDelegationChain(format!(
                "DAT {} has scopes that exceed parent DAT {}",
                child.claims.jti, parent.claims.jti
            )));
        }

        // Child must not expire after parent
        if child.claims.exp > parent.claims.exp {
            return Err(IdprovaError::InvalidDelegationChain(format!(
                "DAT {} expires after parent DAT {}",
                child.claims.jti, parent.claims.jti
            )));
        }

        // Each DAT must be temporally valid
        child.validate_timing()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::dat::token::Dat;
    use chrono::{Duration, Utc};

    fn make_dat(issuer: &str, subject: &str, scopes: Vec<&str>, kp: &KeyPair) -> Dat {
        Dat::issue(
            issuer,
            subject,
            scopes.into_iter().map(String::from).collect(),
            Utc::now() + Duration::hours(24),
            None,
            None,
            kp,
        )
        .unwrap()
    }

    fn build_chain(depth: usize) -> Vec<Dat> {
        let kp = KeyPair::generate();
        let mut chain = Vec::new();
        let scopes = vec!["mcp:*:*:*"];

        // Root DAT: human → agent0
        chain.push(make_dat(
            "did:idprova:example.com:human",
            &format!("did:idprova:example.com:agent0"),
            scopes.clone(),
            &kp,
        ));

        // Re-delegations: agent_i → agent_{i+1}
        for i in 0..depth.saturating_sub(1) {
            let issuer = format!("did:idprova:example.com:agent{i}");
            let subject = format!("did:idprova:example.com:agent{}", i + 1);
            chain.push(make_dat(&issuer, &subject, scopes.clone(), &kp));
        }

        chain
    }

    #[test]
    fn test_chain_depth_5_passes_default_config() {
        let chain = build_chain(5);
        assert!(
            validate_chain(&chain).is_ok(),
            "chain of depth 5 must pass with default config (max_depth=5)"
        );
    }

    /// SR-8: Chain exceeding max_depth must be rejected.
    #[test]
    fn test_sr8_chain_depth_6_fails_default_config() {
        let chain = build_chain(6);
        assert!(
            validate_chain(&chain).is_err(),
            "chain of depth 6 must fail with default config (max_depth=5)"
        );
    }

    #[test]
    fn test_sr8_custom_depth_config() {
        let chain = build_chain(8);
        let config = ChainValidationConfig::with_max_depth(8);
        assert!(
            validate_chain_with_config(&chain, &config).is_ok(),
            "chain of depth 8 must pass with max_depth=8"
        );

        let chain9 = build_chain(9);
        assert!(
            validate_chain_with_config(&chain9, &config).is_err(),
            "chain of depth 9 must fail with max_depth=8"
        );
    }

    /// SR-8: Hard max of 10 cannot be bypassed by setting max_depth higher.
    #[test]
    fn test_sr8_hard_max_depth_10_cannot_be_exceeded() {
        // Config requesting 20 is clamped to 10
        let config = ChainValidationConfig::with_max_depth(20);
        assert_eq!(
            config.max_depth,
            ChainValidationConfig::HARD_MAX_DEPTH,
            "max_depth=20 must be clamped to HARD_MAX_DEPTH=10"
        );

        let chain11 = build_chain(11);
        assert!(
            validate_chain_with_config(&chain11, &config).is_err(),
            "chain of depth 11 must fail even with max_depth config of 20 (clamped to 10)"
        );
    }

    #[test]
    fn test_chain_depth_10_passes_hard_max() {
        let chain = build_chain(10);
        let config = ChainValidationConfig::with_max_depth(10);
        assert!(
            validate_chain_with_config(&chain, &config).is_ok(),
            "chain of depth 10 must pass with max_depth=10 (HARD_MAX)"
        );
    }
}
