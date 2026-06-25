//! The deterministic DAT to VC bridge.

use crate::model::{CryptoSuite, VerifiableCredential};
use chrono::TimeZone;
use idprova_core::dat::token::DatClaims;

/// Converts a DAT into a Verifiable Credential format.
///
/// This mapping is **lossy by design**.
/// DAT encodes *authorization/capability* while VC encodes *identity/attestation*.
pub fn dat_to_vc(
    dat_claims: &DatClaims,
    proof: crate::model::DataIntegrityProof,
) -> VerifiableCredential {
    let subject = serde_json::json!({
        "id": dat_claims.sub,
        "scopes": dat_claims.scope,
        "constraints": dat_claims.constraints,
        "config_attestation": dat_claims.config_attestation
    });

    VerifiableCredential {
        context: vec![
            "https://www.w3.org/ns/credentials/v2".to_string(),
            "https://www.idprova.dev/contexts/dat-bridge/v1.json".to_string(),
        ],
        types: vec![
            "VerifiableCredential".to_string(),
            "IDProvaDelegatedCapability".to_string(),
        ],
        id: format!("urn:dat:{}", dat_claims.jti),
        issuer: dat_claims.iss.clone(),
        valid_from: chrono::Utc.timestamp_opt(dat_claims.iat, 0).unwrap(),
        valid_until: Some(chrono::Utc.timestamp_opt(dat_claims.exp, 0).unwrap()),
        credential_subject: subject,
        credential_status: None,
        proof,
    }
}

/// Attempts to extract DAT claims from a mapped VC.
///
/// Returns `None` if the VC does not represent an IDProva delegated capability.
pub fn vc_to_dat_claims(vc: &VerifiableCredential) -> Option<DatClaims> {
    if !vc.types.contains(&"IDProvaDelegatedCapability".to_string()) {
        return None;
    }

    let sub = vc.credential_subject.get("id")?.as_str()?.to_string();
    let scopes = vc.credential_subject.get("scopes")?.as_array()?;
    let scope_strings: Vec<String> = scopes
        .iter()
        .filter_map(|s| s.as_str().map(String::from))
        .collect();

    Some(DatClaims {
        iss: vc.issuer.clone(),
        sub,
        iat: vc.valid_from.timestamp(),
        exp: vc.valid_until?.timestamp(),
        nbf: vc.valid_from.timestamp(),
        jti: vc.id.strip_prefix("urn:dat:")?.to_string(),
        scope: scope_strings,
        constraints: None, // TODO: reverse map constraints
        config_attestation: None,
        delegation_chain: Some(vec![]),
    })
}
