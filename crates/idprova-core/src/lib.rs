//! # IDProva Core
//!
//! Core library for the IDProva protocol — AI agent identity, delegation, and audit.
//!
//! ## Modules
//!
//! - [`crypto`] — Ed25519 key generation, signing, verification, BLAKE3 hashing
//! - [`aid`] — Agent Identity Documents (W3C DID compatible)
//! - [`dat`] — Delegation Attestation Tokens (JWS-based)
//! - [`receipt`] — Hash-chained action receipts for audit
//! - [`trust`] — Trust level definitions (L0-L4)
//! - [`policy`] — RBAC policy engine (7 evaluators, constraint inheritance, rate tracking)

pub mod aid;
pub mod crypto;
pub mod dat;
pub mod error;
pub mod policy;
pub mod receipt;
pub mod trust;

pub use error::{IdprovaError, Result};
