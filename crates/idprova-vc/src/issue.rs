//! VC Issuance logic.

use crate::model::{CryptoSuite, DataIntegrityProof, VerifiableCredential};
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use idprova_core::crypto::KeyPair;

/// Issues Verifiable Credentials deterministically.
pub struct VcIssuer {
    pub issuer_did: String,
    pub signing_key: KeyPair,
    pub suite: CryptoSuite,
}

impl VcIssuer {
    pub fn new(issuer_did: String, signing_key: KeyPair, suite: CryptoSuite) -> Self {
        Self {
            issuer_did,
            signing_key,
            suite,
        }
    }

    /// Issues a Verifiable Credential.
    ///
    /// Canonicalizes the VC data per the selected suite and signs it deterministically.
    pub fn issue(
        &self,
        subject_did: &str,
        claims: serde_json::Value,
        valid_for: Duration,
        status: Option<crate::model::CredentialStatus>,
    ) -> VerifiableCredential {
        let now = Utc::now();

        let mut vc_map = serde_json::Map::new();
        vc_map.insert(
            "@context".to_string(),
            serde_json::json!([
                "https://www.w3.org/ns/credentials/v2",
                "https://www.idprova.dev/contexts/v1.json"
            ]),
        );
        vc_map.insert(
            "type".to_string(),
            serde_json::json!(["VerifiableCredential"]),
        );
        vc_map.insert(
            "issuer".to_string(),
            serde_json::Value::String(self.issuer_did.clone()),
        );
        vc_map.insert(
            "validFrom".to_string(),
            serde_json::Value::String(now.to_rfc3339()),
        );
        vc_map.insert(
            "validUntil".to_string(),
            serde_json::Value::String((now + valid_for).to_rfc3339()),
        );

        let mut subject_map = serde_json::Map::new();
        subject_map.insert(
            "id".to_string(),
            serde_json::Value::String(subject_did.to_string()),
        );
        if let serde_json::Value::Object(obj) = claims {
            for (k, v) in obj {
                subject_map.insert(k, v);
            }
        }
        vc_map.insert(
            "credentialSubject".to_string(),
            serde_json::Value::Object(subject_map),
        );

        // Sign the canonicalized VC data
        let proof_value = self.sign_payload(&serde_json::Value::Object(vc_map.clone()));

        let proof = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: self.suite.clone(),
            created: now,
            verification_method: format!("{}#key-1", self.issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        };

        VerifiableCredential {
            context: vec!["https://www.w3.org/ns/credentials/v2".to_string()],
            types: vec!["VerifiableCredential".to_string()],
            id: format!("urn:uuid:{}", uuid_like()),
            issuer: self.issuer_did.clone(),
            valid_from: now,
            valid_until: Some(now + valid_for),
            credential_subject: vc_map.get("credentialSubject").cloned().unwrap_or_default(),
            credential_status: status,
            proof,
        }
    }

    fn sign_payload(&self, payload: &serde_json::Value) -> String {
        match self.suite {
            CryptoSuite::EddsaJcs2022 => {
                let canonical =
                    serde_json_canonicalizer::to_vec(payload).expect("JCS canonicalization failed");
                let sig = self.signing_key.sign(&canonical);
                format!(
                    "z{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
                )
            }
            CryptoSuite::EddsaRdfc2022 | CryptoSuite::EcdsaRdfc2019 => {
                todo!("RDF canonicalization signing (requires rdfc-interop)")
            }
        }
    }
}

fn uuid_like() -> String {
    // Todo: use ulid or uuid crate if strictly required, otherwise rely on core's generation if exposed
    chrono::Utc::now().timestamp().to_string()
}
