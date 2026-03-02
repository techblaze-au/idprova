//! Delegation chain validation for multi-level delegation (v0.2+).
//!
//! In v0.1, only single-level delegation is supported (human → agent).
//! This module provides the foundation for future chain validation.

use crate::{IdprovaError, Result};
use super::token::Dat;
use super::scope::ScopeSet;

/// Validates that a delegation chain is valid:
/// - Each DAT in the chain was issued by the subject of the previous DAT
/// - Scopes narrow (or stay equal) at each level
/// - No DAT in the chain is expired
/// - The chain is contiguous (no gaps)
pub fn validate_chain(chain: &[Dat]) -> Result<()> {
    if chain.is_empty() {
        return Ok(());
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
