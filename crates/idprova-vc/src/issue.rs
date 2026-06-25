//! VC Issuance logic.

use crate::model::{CryptoSuite, DataIntegrityProof, VerifiableCredential};
use crate::suite::jcs_hash;
use chrono::{Duration, Utc};
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
    /// Canonicalizes the *serialized typed VC* per the selected suite and signs
    /// it deterministically. The same canonicalization is used on the verify
    /// path (see [`crate::suite::jcs_hash`]), so issue → verify always matches.
    pub fn issue(
        &self,
        subject_did: &str,
        claims: serde_json::Value,
        valid_for: Duration,
        status: Option<crate::model::CredentialStatus>,
    ) -> VerifiableCredential {
        let now = Utc::now();

        // Build the credential subject: { "id": subject_did, ...claims }.
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

        // The proof is built with an EMPTY proof_value; `jcs_hash` strips
        // proof_value before hashing, so the placeholder is irrelevant to the
        // signed bytes but keeps the proof config (type, cryptosuite, created,
        // verificationMethod, proofPurpose) inside the signature.
        let proof = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: self.suite.clone(),
            created: now,
            verification_method: format!("{}#key-1", self.issuer_did),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: String::new(),
        };

        let mut vc = VerifiableCredential {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".to_string(),
                "https://www.idprova.dev/contexts/v1.json".to_string(),
            ],
            types: vec!["VerifiableCredential".to_string()],
            id: format!("urn:uuid:{}", uuid_like()),
            issuer: self.issuer_did.clone(),
            valid_from: now,
            valid_until: Some(now + valid_for),
            credential_subject: serde_json::Value::Object(subject_map),
            credential_status: status,
            proof,
        };

        match self.suite {
            CryptoSuite::EddsaJcs2022 => {
                let hash = jcs_hash(&vc).expect("eddsa-jcs-2022 hashing failed");
                let sig = self.signing_key.sign(&hash);
                // Multibase base58btc ('z'-prefixed) per W3C Data Integrity.
                vc.proof.proof_value = multibase::encode(multibase::Base::Base58Btc, sig);
            }
            CryptoSuite::EddsaRdfc2022 | CryptoSuite::EcdsaRdfc2019 => {
                todo!("RDF canonicalization signing (requires rdfc-interop)")
            }
        }

        vc
    }
}

fn uuid_like() -> String {
    // Todo: use ulid or uuid crate if strictly required, otherwise rely on core's generation if exposed
    chrono::Utc::now().timestamp().to_string()
}
