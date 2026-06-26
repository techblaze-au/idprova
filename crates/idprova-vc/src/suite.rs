//! Shared cryptosuite primitives.
//!
//! The [`jcs_hash`] function is the single source of truth for the
//! `eddsa-jcs-2022` hashing transformation, used identically by both the
//! issuer ([`crate::issue`]) and the verifier ([`crate::verify`]) so that the
//! signed bytes always match the verified bytes.

use crate::model::VerifiableCredential;
use sha2::{Digest, Sha256};

/// Errors produced while computing the `eddsa-jcs-2022` hash.
#[derive(Debug, thiserror::Error)]
pub enum SuiteError {
    /// The VC or its proof could not be serialized to JSON.
    #[error("failed to serialize document: {0}")]
    Serialize(#[from] serde_json::Error),
    /// JCS (RFC 8785) canonicalization failed.
    #[error("JCS canonicalization failed: {0}")]
    Canonicalize(String),
}

/// Computes the `eddsa-jcs-2022` hash input per the W3C `vc-di-eddsa` spec:
///
/// `SHA-256(JCS(proofConfig)) || SHA-256(JCS(unsecuredDocument))`
///
/// where:
/// * the *unsecured document* is the VC serialized to JSON with the `proof`
///   member removed, and
/// * the *proof config* is the proof serialized to JSON with the `proof_value`
///   (`proofValue`) member removed.
///
/// The `proofConfig` hash is concatenated **first**, matching the spec.
pub(crate) fn jcs_hash(vc: &VerifiableCredential) -> Result<Vec<u8>, SuiteError> {
    // 1. Unsecured document = the VC JSON, sans `proof`.
    let mut doc = serde_json::to_value(vc)?;
    if let serde_json::Value::Object(ref mut m) = doc {
        m.remove("proof");
    }

    // 2. Proof config = the proof JSON, sans `proof_value`.
    let mut cfg = serde_json::to_value(&vc.proof)?;
    if let serde_json::Value::Object(ref mut m) = cfg {
        m.remove("proof_value");
    }

    let canon_cfg = serde_json_canonicalizer::to_vec(&cfg)
        .map_err(|e| SuiteError::Canonicalize(e.to_string()))?;
    let canon_doc = serde_json_canonicalizer::to_vec(&doc)
        .map_err(|e| SuiteError::Canonicalize(e.to_string()))?;

    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(Sha256::digest(&canon_cfg).as_slice());
    h.extend_from_slice(Sha256::digest(&canon_doc).as_slice());
    Ok(h)
}
