//! Delegation chain validation for multi-level delegation (v0.2+).
//!
//! In v0.1, only single-level delegation is supported (human → agent).
//! This module provides the foundation for future chain validation.

use super::scope::ScopeSet;
use super::token::Dat;
use crate::{IdprovaError, Result};

/// Hard maximum delegation chain depth — cannot be overridden by any constraint.
pub const MAX_DELEGATION_DEPTH: u32 = 10;

/// Validates that a delegation chain is valid:
/// - Each DAT in the chain was issued by the subject of the previous DAT
/// - Scopes narrow (or stay equal) at each level
/// - No DAT in the chain is expired
/// - The chain is contiguous (no gaps)
/// - Chain length does not exceed [`MAX_DELEGATION_DEPTH`]
pub fn validate_chain(chain: &[Dat]) -> Result<()> {
    if chain.is_empty() {
        return Ok(());
    }

    if chain.len() as u32 > MAX_DELEGATION_DEPTH {
        return Err(IdprovaError::InvalidDelegationChain(format!(
            "delegation chain length {} exceeds hard maximum of {}",
            chain.len(),
            MAX_DELEGATION_DEPTH
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
    use chrono::{Duration, Utc};

    /// Issue a DAT from `issuer_kp` to `subject_did` with the given scope.
    fn make_dat(issuer_kp: &KeyPair, issuer_did: &str, subject_did: &str) -> Dat {
        let expires = Utc::now() + Duration::hours(1);
        Dat::issue(
            issuer_did,
            subject_did,
            vec!["mcp:tool:read".into()],
            expires,
            None,
            None,
            issuer_kp,
        )
        .expect("issue failed")
    }

    /// Build a delegation chain of `depth` links, returning the chain vec.
    fn build_chain(depth: usize) -> Vec<Dat> {
        // Generate one key pair per agent (depth+1 agents needed for depth links)
        let pairs: Vec<(KeyPair, String)> = (0..=depth)
            .map(|i| {
                let kp = KeyPair::generate();
                let did = format!("did:idprova:test:{}", hex::encode(&kp.public_key_bytes()[..6]));
                let _ = i; // suppress unused warning
                (kp, did)
            })
            .collect();

        (0..depth)
            .map(|i| make_dat(&pairs[i].0, &pairs[i].1, &pairs[i + 1].1))
            .collect()
    }

    #[test]
    fn test_max_depth_constant() {
        assert_eq!(MAX_DELEGATION_DEPTH, 10);
    }

    #[test]
    fn test_chain_of_11_fails() {
        let chain = build_chain(11);
        let result = validate_chain(&chain);
        assert!(result.is_err(), "chain of 11 should fail");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("exceeds hard maximum"), "unexpected error: {msg}");
    }

    #[test]
    fn test_chain_of_10_passes_length_check() {
        // Build a chain of 10 with valid topology & scopes
        let chain = build_chain(10);
        // Length check passes; topology validation runs. If timing is valid this passes.
        let result = validate_chain(&chain);
        assert!(result.is_ok(), "chain of 10 should pass: {:?}", result.err());
    }

    #[test]
    fn test_empty_chain_ok() {
        assert!(validate_chain(&[]).is_ok());
    }
}
