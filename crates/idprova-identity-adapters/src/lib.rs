//! # idprova-identity-adapters
//!
//! Trait crate defining the four ports between the IDProva core and
//! the outside world's identity stack:
//!
//! | Trait                                          | Job                                 |
//! |------------------------------------------------|-------------------------------------|
//! | [`OidcIdpAdapter`](oidc::OidcIdpAdapter)       | Verify inbound OIDC ID-tokens.      |
//! | [`AttributeMapper`](attributes::AttributeMapper) | Map OIDC claims → trust + scope.   |
//! | [`ScimProvisioner`](scim::ScimProvisioner)     | SCIM 2.0 user/group lifecycle.      |
//! | [`AuditExporter`](audit::AuditExporter)        | Ship receipts to external SIEMs.    |
//!
//! This crate **only** defines the traits and their wire-format types
//! (`IdTokenClaims`, `OidcDiscovery`, `ScimUser`, `ScimGroup`, …).
//! Concrete implementations live in separate crates
//! (`idprova-adapter-oidc-generic`, `idprova-exporter-otel`, …) and
//! bring their own runtime dependencies. The trait crate itself
//! depends only on `idprova-core`, `serde`, `serde_json`, and
//! `thiserror` — no async runtime, no HTTP client, no I/O.
//!
//! See the README for the port-and-adapter pattern this crate
//! implements (per Agent A's Architecture Audit headline
//! recommendation and RFC 0001 §5.1).

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod attributes;
pub mod audit;
pub mod error;
pub mod oidc;
pub mod scim;

// Convenience re-exports of the most commonly used items.
pub use attributes::AttributeMapper;
pub use audit::AuditExporter;
pub use error::{AdapterError, AdapterResult};
pub use oidc::{IdTokenClaims, OidcDiscovery, OidcIdpAdapter};
pub use scim::{
    ScimAgentExtension, ScimEmail, ScimGroup, ScimGroupMember, ScimProvisioner, ScimUser,
};
