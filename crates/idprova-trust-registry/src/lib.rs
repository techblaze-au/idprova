//! # IDProva Trust Registry
//!
//! The neutral, vendor-neutral, chain-agnostic Issuer Trust Registry + cross-standard resolver.
//!
//! ## Modules
//!
//! - [`model`] — Core data types (`Issuer`, `TrustList`, `SignedTrustList`).
//! - [`store`] — Persistence layer (`SqliteTrustStore`).
//! - [`authority`] — Curated list signing and verification (`TrustAuthority`).
//! - [`federation`] — Append-only log and Merkle proofs (Spec + Skeleton).
//! - [`resolver`] — Cross-standard agent resolution to `did:aid:`.

pub mod api;
pub mod authority;
pub mod federation;
pub mod model;
pub mod resolver;
pub mod store;

pub use model::{Issuer, IssuerStatus, SignedTrustList, TrustList};
pub use store::{SqliteTrustStore, TrustStore};
