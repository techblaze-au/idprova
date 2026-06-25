//! Core data models for the Issuer Trust Registry.

use chrono::{DateTime, Utc};
use idprova_core::trust::level::TrustLevel;
use serde::{Deserialize, Serialize};

/// Represents an entity authorized to attest to agent identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issuer {
    /// The canonical DID of the issuer (must be `did:aid:`).
    pub did: String,
    /// Human-readable name of the issuing authority.
    pub name: String,
    /// Jurisdiction code (e.g., ISO 3166-1 alpha-2).
    pub jurisdiction: String,
    /// Current status of the issuer.
    pub status: IssuerStatus,
    /// The trust level assigned to this issuer (L0-L4).
    pub trust_level: TrustLevel,
    /// The types of credentials this issuer is authorized to issue.
    pub credential_types: Vec<String>,
    /// When the issuer's validity begins.
    pub valid_from: DateTime<Utc>,
    /// When the issuer's validity expires.
    pub valid_until: DateTime<Utc>,
}

/// The lifecycle status of an issuer within the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssuerStatus {
    Active,
    Suspended,
    Revoked,
}

/// A curated list of trusted issuers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustList {
    pub version: String,
    pub sequence: u64,
    pub issued_at: DateTime<Utc>,
    pub entries: Vec<Issuer>,
    /// Optional cryptographic proof (e.g., Merkle root of entries for federation).
    pub proof: Option<Proof>,
}

impl TrustList {
    /// Sorts entries deterministically by DID to ensure canonical representation.
    pub fn canonicalize(&mut self) {
        self.entries.sort_by(|a, b| a.did.cmp(&b.did));
    }
}

/// A TrustList signed by the TrustAuthority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTrustList {
    /// The unsigned (but canonically sorted) trust list payload.
    #[serde(flatten)]
    pub list: TrustList,
    /// The Ed25519 signature over the RFC 8785 canonicalized `TrustList`.
    pub signature: Vec<u8>,
    /// The Key ID identifying the public key used to sign this list.
    pub signer_keyid: String,
}

/// Generic proof structure for tree heads and inclusion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub proof_type: String,
    pub data: Vec<u8>,
}
