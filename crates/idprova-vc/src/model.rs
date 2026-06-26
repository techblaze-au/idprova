//! W3C VC Data Model 2.0 core types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Supported Data Integrity cryptographic suites.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoSuite {
    /// Ed25519 over RFC 8785 JCS (Default).
    EddsaJcs2022,
    /// Ed25519 over URDNA2015 RDF canonicalization.
    EddsaRdfc2022,
    /// ECDSA P-256 over URDNA2015 RDF canonicalization (Required for AP2).
    EcdsaRdfc2019,
}

/// A Data Integrity Proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub type_: String,
    pub cryptosuite: CryptoSuite,
    pub created: DateTime<Utc>,
    pub verification_method: String,
    pub proof_purpose: String,
    pub proof_value: String, // Multibase encoded signature
}

/// StatusList 2021 entry for `credentialStatus`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialStatus {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub status_purpose: String,
    pub status_list_index: String,
}

/// A W3C Verifiable Credential (Data Model 2.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub id: String,
    pub issuer: String,
    pub valid_from: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub credential_subject: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
    pub proof: DataIntegrityProof,
}

/// A W3C Verifiable Presentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub proof: DataIntegrityProof,
}
