//! VC Verification logic.

use crate::model::{CredentialStatus, VerifiableCredential};
use crate::suite::jcs_hash;
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
        match vc.proof.cryptosuite {
            crate::model::CryptoSuite::EddsaJcs2022 => {
                // Recompute the EXACT hash the issuer signed.
                let hash = match jcs_hash(vc) {
                    Ok(h) => h,
                    Err(_) => return false,
                };
                // proof_value is multibase (base58btc, 'z'-prefixed).
                let (_base, sig) = match multibase::decode(&vc.proof.proof_value) {
                    Ok(t) => t,
                    Err(_) => return false,
                };
                idprova_core::crypto::KeyPair::verify(pub_key, &hash, &sig).is_ok()
            }
            _ => todo!("RDF canonicalization verification"),
        }
    }
}

impl Default for VcVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ap2::{to_ap2_mandate, Ap2Kind};
    use crate::dat_bridge::{dat_to_vc, vc_to_dat_claims};
    use crate::issue::VcIssuer;
    use crate::model::{CredentialStatus, CryptoSuite, DataIntegrityProof};
    use chrono::{Duration, Utc};
    use idprova_core::crypto::KeyPair;
    use idprova_core::dat::token::DatClaims;

    const ISSUER_DID: &str = "did:aid:issuer-test";
    const SUBJECT_DID: &str = "did:aid:subject-test";

    /// Resolver that always returns the given key for any issuer.
    struct FixedResolver([u8; 32]);
    impl IssuerResolver for FixedResolver {
        fn verifying_key(&self, _issuer_did: &str) -> Option<[u8; 32]> {
            Some(self.0)
        }
    }

    /// Resolver that reports a constant revocation state.
    struct FixedStatus(bool);
    impl StatusResolver for FixedStatus {
        fn is_revoked(&self, _status: &CredentialStatus) -> bool {
            self.0
        }
    }

    fn issuer(kp: KeyPair) -> VcIssuer {
        VcIssuer {
            issuer_did: ISSUER_DID.to_string(),
            signing_key: kp,
            suite: CryptoSuite::EddsaJcs2022,
        }
    }

    fn dummy_proof() -> DataIntegrityProof {
        DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: CryptoSuite::EddsaJcs2022,
            created: Utc::now(),
            verification_method: format!("{ISSUER_DID}#key-1"),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "z".to_string(),
        }
    }

    #[test]
    fn round_trip_valid() {
        let kp = KeyPair::generate();
        let pubkey = kp.public_key_bytes();
        let iss = issuer(kp);

        let vc = iss.issue(
            SUBJECT_DID,
            serde_json::json!({ "role": "agent", "tier": "gold" }),
            Duration::days(1),
            None,
        );

        let outcome =
            VcVerifier::new().verify(&vc, &FixedResolver(pubkey), &FixedStatus(false), Utc::now());
        assert_eq!(outcome, VcVerifyOutcome::Valid);
    }

    #[test]
    fn tampered_invalid() {
        let kp = KeyPair::generate();
        let pubkey = kp.public_key_bytes();
        let iss = issuer(kp);

        let mut vc = iss.issue(
            SUBJECT_DID,
            serde_json::json!({ "role": "agent" }),
            Duration::days(1),
            None,
        );

        // Flip a claim value AFTER signing.
        if let serde_json::Value::Object(ref mut m) = vc.credential_subject {
            m.insert("role".to_string(), serde_json::json!("admin"));
        }

        let outcome =
            VcVerifier::new().verify(&vc, &FixedResolver(pubkey), &FixedStatus(false), Utc::now());
        assert_eq!(outcome, VcVerifyOutcome::InvalidSignature);
    }

    #[test]
    fn revoked() {
        let kp = KeyPair::generate();
        let pubkey = kp.public_key_bytes();
        let iss = issuer(kp);

        let status = CredentialStatus {
            type_: "StatusList2021Entry".to_string(),
            id: "https://status.idprova.dev/1#5".to_string(),
            status_purpose: "revocation".to_string(),
            status_list_index: "5".to_string(),
        };

        let vc = iss.issue(
            SUBJECT_DID,
            serde_json::json!({ "role": "agent" }),
            Duration::days(1),
            Some(status),
        );

        let outcome =
            VcVerifier::new().verify(&vc, &FixedResolver(pubkey), &FixedStatus(true), Utc::now());
        assert_eq!(outcome, VcVerifyOutcome::Revoked);
    }

    #[test]
    fn expired() {
        let kp = KeyPair::generate();
        let pubkey = kp.public_key_bytes();
        let iss = issuer(kp);

        let vc = iss.issue(
            SUBJECT_DID,
            serde_json::json!({ "role": "agent" }),
            Duration::days(1),
            None,
        );

        let after_expiry = vc.valid_until.unwrap() + Duration::seconds(1);
        let outcome = VcVerifier::new().verify(
            &vc,
            &FixedResolver(pubkey),
            &FixedStatus(false),
            after_expiry,
        );
        assert_eq!(outcome, VcVerifyOutcome::Expired);
    }

    #[test]
    fn dat_to_vc_preserves_scope() {
        let scope = vec!["mcp:tool:fs:read".to_string()];
        let now = Utc::now().timestamp();
        let claims = DatClaims {
            iss: ISSUER_DID.to_string(),
            sub: SUBJECT_DID.to_string(),
            iat: now,
            exp: now + 3600,
            nbf: now,
            jti: "dat-123".to_string(),
            scope: scope.clone(),
            constraints: None,
            config_attestation: None,
            delegation_chain: None,
        };

        let vc = dat_to_vc(&claims, dummy_proof());
        assert!(vc.types.contains(&"IDProvaDelegatedCapability".to_string()));

        let back = vc_to_dat_claims(&vc).expect("should round-trip to DatClaims");
        assert_eq!(back.scope, scope);
    }

    #[test]
    fn ap2_intent_shape() {
        let vc = to_ap2_mandate(
            Ap2Kind::Intent,
            ISSUER_DID,
            SUBJECT_DID,
            serde_json::json!({ "merchant": "acme", "max_amount": "100.00" }),
            dummy_proof(),
        );

        // An AP2 Intent mandate is a VerifiableCredential typed IntentMandate.
        assert!(vc.types.contains(&"VerifiableCredential".to_string()));
        assert!(vc.types.contains(&"IntentMandate".to_string()));
    }
}
