//! Google AP2 / Agent2Agent (A2A) typed mandate builders.

use crate::model::{DataIntegrityProof, VerifiableCredential};

/// Enumerates the AP2 mandate profiles.
pub enum Ap2Kind {
    Intent,
    Cart,
    Payment,
}

/// Builds an AP2 compliant Verifiable Credential.
///
/// Note: AP2 mandates strictly require P-256 (ECDSA) signatures carried over A2A.
pub fn to_ap2_mandate(
    kind: Ap2Kind,
    issuer_did: &str,
    subject_did: &str,
    payload: serde_json::Value,
    proof: DataIntegrityProof,
) -> VerifiableCredential {
    let type_str = match kind {
        Ap2Kind::Intent => "IntentMandate",
        Ap2Kind::Cart => "CartMandate",
        Ap2Kind::Payment => "PaymentMandate",
    };

    let mut subject_map = serde_json::Map::new();
    subject_map.insert(
        "id".to_string(),
        serde_json::Value::String(subject_did.to_string()),
    );
    if let serde_json::Value::Object(obj) = payload {
        for (k, v) in obj {
            subject_map.insert(k, v);
        }
    }

    VerifiableCredential {
        context: vec![
            "https://www.w3.org/ns/credentials/v2".to_string(),
            "https://schema.org/".to_string(),
            "https://google.com/Ap2Mandates/v1".to_string(),
        ],
        types: vec!["VerifiableCredential".to_string(), type_str.to_string()],
        id: format!("urn:uuid:ap2_{}", chrono::Utc::now().timestamp()),
        issuer: issuer_did.to_string(),
        valid_from: chrono::Utc::now(),
        valid_until: None,
        credential_subject: serde_json::Value::Object(subject_map),
        credential_status: None,
        proof,
    }
}
