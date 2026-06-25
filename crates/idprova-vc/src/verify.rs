//! VC Verification logic.

use crate::model::{CredentialStatus, VerifiableCredential};
use base64::Engine as _;
use chrono::{DateTime, Utc};

/// Resolves the verifying key for an issuer DID.
pub trait IssuerResolver {
    fn verifying_key(&self, issuer_did: &str) -> Option<[u8; 32]>;
}

/// Checks if a credential is revoked via its StatusList.
pub trait StatusResolver {
    fn is_revoked(&self, status: &CredentialStatus) -> bool;
}

/// The outcome of a VC verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcVerifyOutcome {
    Valid,
    InvalidSignature,
    Expired,
    NotYetValid,
    Revoked,
    UntrustedIssuer,
}

/// Verifier for Verifiable Credentials.
pub struct VcVerifier;

impl VcVerifier {
    pub fn new() -> Self {
        Self
    }

    /// Verifies a Verifiable Credential.
    ///
    /// Checks:
    /// 1. Validity window (valid_from / valid_until)
    /// 2. Issuer trust (via IssuerResolver)
    /// 3. Revocation status (via StatusResolver)
    /// 4. Data Integrity Proof signature
    pub fn verify<I: IssuerResolver, S: StatusResolver>(
        &self,
        vc: &VerifiableCredential,
        issuer_resolver: &I,
        status_resolver: &S,
        now: DateTime<Utc>,
    ) -> VcVerifyOutcome {
        // 1. Validity Window
        if now < vc.valid_from {
            return VcVerifyOutcome::NotYetValid;
        }
        if let Some(until) = vc.valid_until {
            if now > until {
                return VcVerifyOutcome::Expired;
            }
        }

        // 2. Issuer Resolution
        let pub_key = match issuer_resolver.verifying_key(&vc.issuer) {
            Some(k) => k,
            None => return VcVerifyOutcome::UntrustedIssuer,
        };

        // 3. Status Check
        if let Some(status) = &vc.credential_status {
            if status_resolver.is_revoked(status) {
                return VcVerifyOutcome::Revoked;
            }
        }

        // 4. Signature Verification
        if self.verify_signature(vc, &pub_key) {
            VcVerifyOutcome::Valid
        } else {
            VcVerifyOutcome::InvalidSignature
        }
    }

    fn verify_signature(&self, vc: &VerifiableCredential, pub_key: &[u8; 32]) -> bool {
        let payload = self.construct_verify_payload(vc);

        match vc.proof.cryptosuite {
            crate::model::CryptoSuite::EddsaJcs2022 => {
                let canonical = match serde_json_canonicalizer::to_vec(&payload) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                let sig = match vc.proof.proof_value.strip_prefix('z') {
                    Some(b64) => match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64)
                    {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    },
                    None => return false,
                };
                idprova_core::crypto::KeyPair::verify(pub_key, &canonical, &sig).is_ok()
            }
            _ => todo!("RDF canonicalization verification"),
        }
    }

    fn construct_verify_payload(&self, vc: &VerifiableCredential) -> serde_json::Value {
        // Reconstruct the unsigned VC payload for canonicalization
        let mut map = serde_json::Map::new();
        map.insert(
            "@context".to_string(),
            serde_json::Value::Array(
                vc.context
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "type".to_string(),
            serde_json::Value::Array(
                vc.types
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "issuer".to_string(),
            serde_json::Value::String(vc.issuer.clone()),
        );
        map.insert(
            "validFrom".to_string(),
            serde_json::Value::String(vc.valid_from.to_rfc3339()),
        );
        map.insert(
            "credentialSubject".to_string(),
            vc.credential_subject.clone(),
        );
        serde_json::Value::Object(map)
    }
}
