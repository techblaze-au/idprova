//! # idprova-adapter-oidc-generic
//!
//! Generic OIDC IdP adapter for IDProva. Implements the [`OidcIdpAdapter`]
//! and [`AttributeMapper`] traits from `idprova-identity-adapters` against
//! any RFC 5785 / OIDC Discovery 1.0 conformant IdP — Okta, Microsoft Entra,
//! Auth0, Keycloak.
//!
//! Per IDProva-RFC 0001 §5.1 the implementation lives in a separate crate
//! from the trait definitions (port-and-adapter pattern). The crate brings
//! its own HTTP and JWT dependencies; the trait crate carries none.
//!
//! [`OidcIdpAdapter`]: idprova_identity_adapters::OidcIdpAdapter
//! [`AttributeMapper`]: idprova_identity_adapters::AttributeMapper

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod adapter;
mod mapper;

pub use adapter::{GenericOidcAdapter, OidcAdapterConfig};
pub use mapper::{GenericAttributeMapper, GroupClaimSource, MappingConfig};
