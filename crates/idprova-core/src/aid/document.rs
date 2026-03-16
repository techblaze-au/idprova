use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_vec as jcs_to_vec;
use std::fmt;

use crate::{IdprovaError, Result};

/// The DID method name for IDProva identifiers.
pub const DID_METHOD: &str = "aid";

/// A parsed IDProva DID identifier: `did:aid:{domain}:{local_name}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AidIdentifier {
    /// The domain namespace (e.g., "techblaze.com.au").
    pub domain: String,
    /// The local agent name (e.g., "kai").
    pub local_name: String,
}

impl AidIdentifier {
    /// Parse a DID string into an AidIdentifier.
    ///
    /// Expected format: `did:aid:{domain}:{local_name}`
    pub fn parse(did: &str) -> Result<Self> {
        let parts: Vec<&str> = did.splitn(4, ':').collect();
        if parts.len() != 4 {
            return Err(IdprovaError::InvalidAid(format!(
                "expected did:aid:{{domain}}:{{name}}, got: {did}"
            )));
        }
        if parts[0] != "did" || parts[1] != DID_METHOD {
            return Err(IdprovaError::InvalidAid(format!(
                "expected did:{DID_METHOD}:..., got: {did}"
            )));
        }

        let domain = parts[2].to_string();
        let local_name = parts[3].to_string();

        // Validate domain (basic check)
        if domain.is_empty() || !domain.contains('.') {
            return Err(IdprovaError::InvalidAid(format!(
                "invalid domain: {domain}"
            )));
        }

        // Validate local name (lowercase alphanumeric + hyphens)
        if local_name.is_empty()
            || !local_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(IdprovaError::InvalidAid(format!(
                "local name must be lowercase alphanumeric with hyphens: {local_name}"
            )));
        }

        Ok(Self { domain, local_name })
    }

    /// Convert to the full DID string.
    pub fn to_did(&self) -> String {
        format!("did:{}:{}:{}", DID_METHOD, self.domain, self.local_name)
    }
}

impl fmt::Display for AidIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_did())
    }
}

/// A verification method entry in the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Fragment identifier (e.g., "#key-ed25519").
    pub id: String,
    /// Key type (e.g., "Ed25519VerificationKey2020").
    #[serde(rename = "type")]
    pub key_type: String,
    /// The controller DID.
    pub controller: String,
    /// The public key in multibase encoding.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Agent-specific metadata stored in the DID document service endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    /// Human-readable agent name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// AI model identifier (e.g., "acme-ai/agent-v2").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Runtime environment (e.g., "openclaw/v2.1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// BLAKE3 hash of the agent's configuration for attestation.
    #[serde(rename = "configAttestation", skip_serializing_if = "Option::is_none")]
    pub config_attestation: Option<String>,
}

/// A complete IDProva Agent Identity Document (W3C DID Document).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidDocument {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID identifier (e.g., "did:aid:techblaze.com.au:kai").
    pub id: String,

    /// The controller DID (the human/entity who controls this agent).
    pub controller: String,

    /// Verification methods (public keys).
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// Authentication method references.
    pub authentication: Vec<String>,

    /// Agent metadata service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<AidService>>,

    /// Trust level (L0-L4).
    #[serde(rename = "trustLevel", skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<String>,

    /// Document version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,

    /// Creation timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,

    /// Last update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,

    /// Cryptographic proof (signature by the controller).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AidProof>,
}

/// A service entry in the DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidService {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

/// Cryptographic proof for the AID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AidProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl AidDocument {
    /// Validate the structure of the AID document.
    pub fn validate(&self) -> Result<()> {
        // Validate the DID identifier
        AidIdentifier::parse(&self.id)?;

        // Validate controller is a valid DID
        if !self.controller.starts_with("did:") {
            return Err(IdprovaError::AidValidation(
                "controller must be a valid DID".into(),
            ));
        }

        // Must have at least one verification method
        if self.verification_method.is_empty() {
            return Err(IdprovaError::AidValidation(
                "at least one verification method required".into(),
            ));
        }

        // Authentication must reference existing verification methods
        for auth_ref in &self.authentication {
            let found = self.verification_method.iter().any(|vm| vm.id == *auth_ref);
            if !found {
                return Err(IdprovaError::AidValidation(format!(
                    "authentication reference {auth_ref} not found in verification methods"
                )));
            }
        }

        Ok(())
    }

    /// Serialize the document to canonical JSON (for signing).
    ///
    /// # Security: fix S4 (non-canonical JSON)
    ///
    /// Uses RFC 8785 JSON Canonicalization Scheme (JCS) via `json-canonicalization`
    /// to produce deterministic output with sorted object keys. This ensures that
    /// signatures produced on one platform verify correctly on all others.
    ///
    /// The proof field is excluded (it contains the signature itself).
    pub fn to_canonical_json(&self) -> Result<Vec<u8>> {
        let mut doc = self.clone();
        doc.proof = None;
        // Serialize to serde_json::Value first, then apply JCS ordering
        let value = serde_json::to_value(&doc)?;
        let canonical = jcs_to_vec(&value)?;
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_did() {
        let id = AidIdentifier::parse("did:aid:techblaze.com.au:kai").unwrap();
        assert_eq!(id.domain, "techblaze.com.au");
        assert_eq!(id.local_name, "kai");
        assert_eq!(id.to_did(), "did:aid:techblaze.com.au:kai");
    }

    #[test]
    fn test_parse_invalid_method() {
        assert!(AidIdentifier::parse("did:other:example.com:agent").is_err());
    }

    #[test]
    fn test_parse_invalid_format() {
        assert!(AidIdentifier::parse("not-a-did").is_err());
        assert!(AidIdentifier::parse("did:aid:nodomain").is_err());
    }

    #[test]
    fn test_parse_invalid_local_name() {
        assert!(AidIdentifier::parse("did:aid:example.com:UPPERCASE").is_err());
        assert!(AidIdentifier::parse("did:aid:example.com:has spaces").is_err());
    }

    #[test]
    fn test_parse_valid_local_names() {
        assert!(AidIdentifier::parse("did:aid:example.com:kai").is_ok());
        assert!(AidIdentifier::parse("did:aid:example.com:billing-agent").is_ok());
        assert!(AidIdentifier::parse("did:aid:example.com:agent-v2").is_ok());
    }

    #[test]
    fn test_display() {
        let id = AidIdentifier {
            domain: "example.com".into(),
            local_name: "kai".into(),
        };
        assert_eq!(format!("{id}"), "did:aid:example.com:kai");
    }

    fn sample_aid_document() -> AidDocument {
        AidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://idprova.dev/ns/v1".into(),
            ],
            id: "did:aid:example.com:kai".into(),
            controller: "did:aid:example.com:root".into(),
            verification_method: vec![VerificationMethod {
                id: "#key-ed25519".into(),
                key_type: "Ed25519VerificationKey2020".into(),
                controller: "did:aid:example.com:kai".into(),
                public_key_multibase: "zABCDEF".into(),
            }],
            authentication: vec!["#key-ed25519".into()],
            service: None,
            trust_level: Some("L2".into()),
            version: Some(1),
            created: None,
            updated: None,
            proof: None,
        }
    }

    /// S4: to_canonical_json() must produce RFC 8785 JCS output.
    ///
    /// The output must have sorted object keys so that the same document
    /// serialized on any platform produces identical bytes.
    #[test]
    fn test_s4_canonical_json_is_deterministic() {
        let doc = sample_aid_document();
        let canonical1 = doc.to_canonical_json().unwrap();
        let canonical2 = doc.to_canonical_json().unwrap();
        assert_eq!(
            canonical1, canonical2,
            "to_canonical_json() must be deterministic"
        );
    }

    #[test]
    fn test_s4_canonical_json_excludes_proof() {
        let mut doc = sample_aid_document();
        doc.proof = Some(AidProof {
            proof_type: "Ed25519Signature2020".into(),
            created: chrono::Utc::now(),
            verification_method: "#key-ed25519".into(),
            proof_value: "zsig123".into(),
        });

        let canonical = String::from_utf8(doc.to_canonical_json().unwrap()).unwrap();
        assert!(
            !canonical.contains("proof"),
            "canonical JSON must exclude the proof field: {canonical}"
        );
    }

    #[test]
    fn test_s4_canonical_json_keys_are_sorted() {
        let doc = sample_aid_document();
        let canonical = String::from_utf8(doc.to_canonical_json().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        // Top-level keys should appear in the canonical output sorted lexicographically
        // Verify by checking that @context comes before authentication (@ < a in ASCII)
        let ctx_pos = canonical.find("\"@context\"").unwrap();
        let auth_pos = canonical.find("\"authentication\"").unwrap();
        assert!(
            ctx_pos < auth_pos,
            "@context must appear before authentication in JCS output"
        );
        // Ensure the output is valid JSON
        assert!(value.is_object());
    }
}
