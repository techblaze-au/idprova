//! Agent Identity Documents (AIDs) — W3C DID compatible.
//!
//! An AID is a DID Document with IDProva-specific extensions for agent metadata,
//! config attestation, and trust level information.

pub mod builder;
pub mod document;

pub use builder::AidBuilder;
pub use document::{AgentMetadata, AidDocument, AidIdentifier, VerificationMethod};
