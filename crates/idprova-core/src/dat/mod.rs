//! Delegation Attestation Tokens (DATs).
//!
//! A DAT is a JWS (JSON Web Signature) that grants an agent scoped,
//! time-bounded permissions on behalf of a human controller.

pub mod scope;
pub mod token;
pub mod chain;

pub use scope::{Scope, ScopeSet};
pub use token::{Dat, DatClaims, DatConstraints, DatHeader};
